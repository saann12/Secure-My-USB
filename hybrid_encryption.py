"""Hybrid Encryption Module.

This module implements hybrid encryption:
- Each file is encrypted with AES-256-GCM using a random key and nonce
- The AES key is wrapped (encrypted) using the recipient's public key (RSA-OAEP or ECC)
- Per-file envelope metadata stores: algorithm, wrapped key, nonce, auth tag

This provides:
- Efficient encryption for large files (AES is fast)
- Secure key distribution (asymmetric encryption for key exchange)
- Authentication and tampering detection (AES-GCM auth tag)
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509

from key_manager import KeyManager

# Envelope metadata file suffix
ENVELOPE_SUFFIX = ".envelope.json"


class HybridEncryption:
    """Manages hybrid encryption using AES-256-GCM + RSA-OAEP/ECC key wrapping."""

    def __init__(self, key_manager: KeyManager):
        """Initialize HybridEncryption with a KeyManager instance."""
        self.key_manager = key_manager

    def _iter_files(self, root: Path):
        """Yield all file paths under root, excluding metadata and envelope files."""
        exclude = {".usb_secure_meta.json", ".usb_manifest.json", ".usb_manifest.sig"}
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                file_path = Path(dirpath) / name
                # Skip metadata files and envelope files
                if file_path.name in exclude or file_path.name.endswith(ENVELOPE_SUFFIX):
                    continue
                yield file_path

    def encrypt_file_for(
        self,
        file_path: Path,
        recipient_cert: x509.Certificate,
        recipient_fingerprint: str,
    ) -> None:
        """
        Encrypt a file using hybrid encryption for a specific recipient.

        Process:
        1. Generate a random 256-bit AES key
        2. Generate a random 96-bit nonce (for GCM)
        3. Encrypt file content with AES-256-GCM
        4. Wrap (encrypt) the AES key with recipient's public key
        5. Store envelope metadata (algorithm, wrapped key, nonce, auth tag)

        Args:
            file_path: Path to the file to encrypt
            recipient_cert: Recipient's X.509 certificate
            recipient_fingerprint: Fingerprint of recipient's certificate (for metadata)
        """
        # Read plaintext
        plaintext = file_path.read_bytes()

        # Generate random AES-256 key and 96-bit nonce for GCM
        aes_key = os.urandom(32)  # 256 bits
        nonce = os.urandom(12)  # 96 bits for GCM

        # Encrypt with AES-256-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        auth_tag = encryptor.tag  # 16 bytes

        # Wrap AES key using recipient's public key
        public_key = recipient_cert.public_key()

        if isinstance(public_key, rsa.RSAPublicKey):
            # RSA-OAEP wrapping
            wrapped_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            algorithm = "RSA-OAEP-SHA256"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # ECC key wrapping using ECDH + KDF
            # For simplicity, we'll use ECIES-like approach: generate ephemeral key pair
            # and derive shared secret, then encrypt AES key with derived key
            # Note: This is a simplified version. Production would use proper ECIES.
            ephemeral_private = ec.generate_private_key(public_key.curve)
            ephemeral_public = ephemeral_private.public_key()

            # Perform ECDH
            shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

            # Derive key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"SecureMyUSB-KeyWrap",
            ).derive(shared_secret)

            # Encrypt AES key with derived key using AES-GCM
            wrap_nonce = os.urandom(12)
            wrap_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(wrap_nonce))
            wrap_encryptor = wrap_cipher.encryptor()
            wrapped_aes_key = wrap_encryptor.update(aes_key) + wrap_encryptor.finalize()
            wrapped_key_tag = wrap_encryptor.tag

            # Store ephemeral public key and wrap metadata
            ephemeral_pub_bytes = ephemeral_public.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )

            algorithm = "ECDH-HKDF-AES256-GCM"
            # Store wrapped key as: ephemeral_pub || wrapped_key || tag || wrap_nonce
            wrapped_key = ephemeral_pub_bytes + wrapped_aes_key + wrapped_key_tag + wrap_nonce
        else:
            raise ValueError(f"Unsupported public key type: {type(public_key)}")

        # Create envelope metadata
        envelope = {
            "algorithm": algorithm,
            "recipient_fingerprint": recipient_fingerprint,
            "wrapped_key": base64.b64encode(wrapped_key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "auth_tag": base64.b64encode(auth_tag).decode("utf-8"),
        }

        # Write encrypted file and envelope
        file_path.write_bytes(ciphertext)
        envelope_path = file_path.with_suffix(file_path.suffix + ENVELOPE_SUFFIX)
        envelope_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

    def decrypt_file(
        self,
        file_path: Path,
        password: str,
        key_id: Optional[str] = None,
    ) -> None:
        """
        Decrypt a file that was encrypted with hybrid encryption.

        Process:
        1. Load envelope metadata
        2. Load private key (using password)
        3. Unwrap AES key using private key
        4. Decrypt file content with AES-256-GCM
        5. Verify auth tag (detects tampering)

        Args:
            file_path: Path to the encrypted file
            password: Password to unlock private key
            key_id: Optional key ID (uses active key if not specified)

        Raises:
            ValueError: If decryption fails (wrong key, tampered data, etc.)
        """
        # Find envelope file
        envelope_path = file_path.with_suffix(file_path.suffix + ENVELOPE_SUFFIX)
        if not envelope_path.exists():
            raise ValueError(f"Envelope file not found for: {file_path}")

        # Load envelope
        try:
            envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"Failed to load envelope: {exc}") from exc

        algorithm = envelope["algorithm"]
        wrapped_key_b64 = envelope["wrapped_key"]
        nonce_b64 = envelope["nonce"]
        auth_tag_b64 = envelope["auth_tag"]

        wrapped_key = base64.b64decode(wrapped_key_b64)
        nonce = base64.b64decode(nonce_b64)
        auth_tag = base64.b64decode(auth_tag_b64)

        # Load private key
        private_key, _ = self.key_manager.load_private_key(password, key_id)

        # Unwrap AES key
        if algorithm == "RSA-OAEP-SHA256":
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("Private key type mismatch: expected RSA")
            try:
                aes_key = private_key.decrypt(
                    wrapped_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            except Exception as exc:
                raise ValueError("Failed to unwrap key (wrong private key?)") from exc

        elif algorithm == "ECDH-HKDF-AES256-GCM":
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ValueError("Private key type mismatch: expected ECC")

            # Extract ephemeral public key, wrapped key, tag, and wrap nonce
            # Format: ephemeral_pub (65 bytes for P-256) || wrapped_key (32 bytes) || tag (16 bytes) || wrap_nonce (12 bytes)
            curve_size = 65  # Uncompressed point size for P-256
            ephemeral_pub_bytes = wrapped_key[:curve_size]
            wrapped_aes_key = wrapped_key[curve_size:-28]  # 32 bytes key + 16 bytes tag + 12 bytes nonce
            wrap_tag = wrapped_key[-28:-12]  # 16 bytes tag
            wrap_nonce_bytes = wrapped_key[-12:]  # 12 bytes nonce

            # Load ephemeral public key
            ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                private_key.curve, ephemeral_pub_bytes
            )

            # Perform ECDH
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)

            # Derive key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"SecureMyUSB-KeyWrap",
            ).derive(shared_secret)

            # Decrypt AES key
            wrap_cipher = Cipher(algorithms.AES(derived_key), modes.GCM(wrap_nonce_bytes, wrap_tag))
            wrap_decryptor = wrap_cipher.decryptor()
            try:
                aes_key = wrap_decryptor.update(wrapped_aes_key) + wrap_decryptor.finalize()
            except InvalidTag:
                raise ValueError("Failed to unwrap key (wrong private key or tampered data)")

        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        # Decrypt file content
        ciphertext = file_path.read_bytes()
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, auth_tag))
        decryptor = cipher.decryptor()

        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise ValueError("Decryption failed: file may be tampered or corrupted")

        # Write decrypted file
        file_path.write_bytes(plaintext)
        # Remove envelope file after successful decryption
        envelope_path.unlink()

    def encrypt_for(
        self,
        path: str,
        recipient_fingerprint: str,
    ) -> None:
        """
        Encrypt all files in a path for a specific recipient.

        Args:
            path: Root path to encrypt
            recipient_fingerprint: Fingerprint of recipient's certificate
        """
        root = Path(path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Path does not exist or is not a directory: {root}")

        # Get recipient's certificate
        recipient_cert = self.key_manager.get_trusted_certificate(recipient_fingerprint)
        if recipient_cert is None:
            raise ValueError(
                f"Recipient certificate not found: {recipient_fingerprint}. "
                "Import it first using 'import-cert'."
            )

        count = 0
        for file_path in self._iter_files(root):
            try:
                self.encrypt_file_for(file_path, recipient_cert, recipient_fingerprint)
                count += 1
                print(f"[+] Encrypted: {file_path}")
            except Exception as exc:
                print(f"[!] Failed to encrypt {file_path}: {exc}")

        print(f"[i] Total files encrypted: {count}")

    def decrypt(
        self,
        path: str,
        password: str,
        key_id: Optional[str] = None,
    ) -> None:
        """
        Decrypt all files in a path that were encrypted with hybrid encryption.

        Args:
            path: Root path to decrypt
            password: Password to unlock private key
            key_id: Optional key ID (uses active key if not specified)
        """
        root = Path(path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Path does not exist or is not a directory: {root}")

        count = 0
        failed = 0

        for file_path in self._iter_files(root):
            # Check if envelope exists (file is encrypted)
            envelope_path = file_path.with_suffix(file_path.suffix + ENVELOPE_SUFFIX)
            if not envelope_path.exists():
                continue  # Skip files without envelopes

            try:
                self.decrypt_file(file_path, password, key_id)
                count += 1
                print(f"[+] Decrypted: {file_path}")
            except ValueError as exc:
                failed += 1
                print(f"[!] Failed to decrypt {file_path}: {exc}")
            except Exception as exc:
                failed += 1
                print(f"[!] Error processing {file_path}: {exc}")

        print(f"[i] Total files decrypted: {count}")
        if failed > 0:
            print(f"[!] Failed to decrypt: {failed} file(s)")

