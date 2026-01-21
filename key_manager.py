"""Key and Certificate Management Module.

This module handles:
- RSA/ECC key pair generation
- Encrypted private key storage using scrypt
- Key versioning and rotation
- Certificate creation and management
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography import x509
from cryptography.x509.oid import NameOID

# Default key storage directory (user's home directory)
DEFAULT_KEY_DIR = Path.home() / ".secure_usb_keys"
KEY_STORAGE_FILE = "keys.json"
CERT_STORAGE_FILE = "certificates.json"
TRUSTED_CERTS_FILE = "trusted_certs.json"

# Key versioning
CURRENT_KEY_VERSION = 1


class KeyManager:
    """Manages cryptographic keys and certificates for Secure My USB."""

    def __init__(self, key_dir: Optional[Path] = None):
        """Initialize KeyManager with a key storage directory."""
        self.key_dir = Path(key_dir) if key_dir else DEFAULT_KEY_DIR
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.keys_file = self.key_dir / KEY_STORAGE_FILE
        self.certs_file = self.key_dir / CERT_STORAGE_FILE
        self.trusted_certs_file = self.key_dir / TRUSTED_CERTS_FILE

    def _derive_key_encryption_key(self, password: str, salt: bytes) -> bytes:
        """Derive a key for encrypting private keys using scrypt."""
        # Scrypt parameters: n=2^14 (16384), r=8, p=1 (memory-hard KDF)
        # Equivalent to ~64MB memory cost, provides strong security
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=16384,  # CPU/memory cost parameter (2^14)
            r=8,      # Block size parameter
            p=1,      # Parallelization parameter
        )
        return kdf.derive(password.encode("utf-8"))

    def generate_keypair(
        self, password: str, key_type: str = "RSA", key_size: int = 3072
    ) -> tuple[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, x509.Certificate]:
        """
        Generate a new key pair and self-signed certificate.

        Args:
            password: Password to encrypt the private key
            key_type: "RSA" or "ECC" (default: "RSA")
            key_size: For RSA, key size in bits (default: 3072). Ignored for ECC.

        Returns:
            Tuple of (private_key, certificate)
        """
        # Generate key pair
        if key_type.upper() == "RSA":
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=key_size
            )
        elif key_type.upper() == "ECC":
            private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        public_key = private_key.public_key()

        # Create self-signed certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Secure"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "USB"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure My USB"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Secure My USB User"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365 * 10))  # 10 years
            .sign(private_key, hashes.SHA256())
        )

        # Encrypt and store private key
        salt = os.urandom(16)
        kek = self._derive_key_encryption_key(password, salt)

        # Serialize private key
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(kek),
        )

        # Load existing keys or create new structure
        keys_data = {}
        if self.keys_file.exists():
            try:
                keys_data = json.loads(self.keys_file.read_text(encoding="utf-8"))
            except Exception:
                keys_data = {}

        # Store key with versioning (include microseconds to ensure uniqueness)
        now = datetime.utcnow()
        timestamp = int(now.timestamp() * 1_000_000)  # Include microseconds
        key_id = f"key_{CURRENT_KEY_VERSION}_{timestamp}"
        keys_data[key_id] = {
            "version": CURRENT_KEY_VERSION,
            "key_type": key_type.upper(),
            "key_size": key_size if key_type.upper() == "RSA" else 256,
            "salt": base64.b64encode(salt).decode("utf-8"),
            "private_key_encrypted": base64.b64encode(private_key_pem).decode("utf-8"),
            "created_at": datetime.utcnow().isoformat(),
            "active": True,
        }

        # Mark old keys as inactive
        for k in keys_data:
            if k != key_id:
                keys_data[k]["active"] = False

        self.keys_file.write_text(json.dumps(keys_data, indent=2), encoding="utf-8")

        # Store certificate
        certs_data = {}
        if self.certs_file.exists():
            try:
                certs_data = json.loads(self.certs_file.read_text(encoding="utf-8"))
            except Exception:
                certs_data = {}

        cert_pem = cert.public_bytes(Encoding.PEM)
        certs_data[key_id] = {
            "certificate": base64.b64encode(cert_pem).decode("utf-8"),
            "fingerprint": self._get_certificate_fingerprint(cert),
            "created_at": datetime.utcnow().isoformat(),
        }

        self.certs_file.write_text(json.dumps(certs_data, indent=2), encoding="utf-8")

        print(f"[+] Key pair generated: {key_id}")
        print(f"[+] Certificate fingerprint: {certs_data[key_id]['fingerprint']}")

        return private_key, cert

    def load_private_key(self, password: str, key_id: Optional[str] = None) -> tuple[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, str]:
        """
        Load the active private key (or a specific key by ID).

        Args:
            password: Password to decrypt the private key
            key_id: Optional key ID. If None, loads the active key.

        Returns:
            Tuple of (private_key, key_id)
        """
        if not self.keys_file.exists():
            raise FileNotFoundError("No keys found. Run 'keygen' first.")

        keys_data = json.loads(self.keys_file.read_text(encoding="utf-8"))

        # Find active key or specified key
        if key_id:
            if key_id not in keys_data:
                raise ValueError(f"Key ID not found: {key_id}")
            key_entry = keys_data[key_id]
        else:
            # Find active key
            active_keys = [k for k, v in keys_data.items() if v.get("active", False)]
            if not active_keys:
                raise ValueError("No active key found. Run 'keygen' first.")
            key_id = active_keys[0]
            key_entry = keys_data[key_id]

        # Decrypt private key
        salt = base64.b64decode(key_entry["salt"])
        kek = self._derive_key_encryption_key(password, salt)

        encrypted_key_data = base64.b64decode(key_entry["private_key_encrypted"])

        try:
            private_key = serialization.load_pem_private_key(
                encrypted_key_data, password=kek
            )
        except Exception as exc:
            raise ValueError("Wrong password or corrupted key.") from exc

        return private_key, key_id

    def load_certificate(self, key_id: Optional[str] = None) -> tuple[x509.Certificate, str]:
        """
        Load certificate for a key ID (or active key).

        Args:
            key_id: Optional key ID. If None, loads certificate for active key.

        Returns:
            Tuple of (certificate, key_id)
        """
        if not self.certs_file.exists():
            raise FileNotFoundError("No certificates found. Run 'keygen' first.")

        certs_data = json.loads(self.certs_file.read_text(encoding="utf-8"))

        if key_id:
            if key_id not in certs_data:
                raise ValueError(f"Certificate not found for key ID: {key_id}")
        else:
            # Find active key
            if not self.keys_file.exists():
                raise FileNotFoundError("No keys found.")
            keys_data = json.loads(self.keys_file.read_text(encoding="utf-8"))
            active_keys = [k for k, v in keys_data.items() if v.get("active", False)]
            if not active_keys:
                raise ValueError("No active key found.")
            key_id = active_keys[0]

        cert_pem = base64.b64decode(certs_data[key_id]["certificate"])
        cert = x509.load_pem_x509_certificate(cert_pem)

        return cert, key_id

    def export_certificate(self, output_path: str, key_id: Optional[str] = None) -> None:
        """Export certificate to a PEM file."""
        cert, _ = self.load_certificate(key_id)
        cert_pem = cert.public_bytes(Encoding.PEM)
        Path(output_path).write_bytes(cert_pem)
        fingerprint = self._get_certificate_fingerprint(cert)
        print(f"[+] Certificate exported to: {output_path}")
        print(f"[+] Fingerprint: {fingerprint}")

    def import_certificate(self, cert_path: str, owner_name: str = "Unknown") -> str:
        """
        Import a certificate and add it to trusted certificates.

        Args:
            cert_path: Path to certificate PEM file
            owner_name: Name/identifier for the certificate owner

        Returns:
            Certificate fingerprint
        """
        cert_pem = Path(cert_path).read_bytes()
        cert = x509.load_pem_x509_certificate(cert_pem)
        fingerprint = self._get_certificate_fingerprint(cert)

        # Load trusted certificates
        trusted = {}
        if self.trusted_certs_file.exists():
            try:
                trusted = json.loads(self.trusted_certs_file.read_text(encoding="utf-8"))
            except Exception:
                trusted = {}

        # Trust-on-first-use: if fingerprint exists, verify it matches
        if fingerprint in trusted:
            existing_name = trusted[fingerprint].get("owner_name", "Unknown")
            if existing_name != owner_name:
                print(f"[!] Warning: Certificate fingerprint already exists with owner: {existing_name}")
                response = input("Do you want to update it? (y/N): ")
                if response.lower() != "y":
                    print("[-] Import cancelled.")
                    return fingerprint

        trusted[fingerprint] = {
            "certificate": base64.b64encode(cert_pem).decode("utf-8"),
            "owner_name": owner_name,
            "imported_at": datetime.utcnow().isoformat(),
        }

        self.trusted_certs_file.write_text(json.dumps(trusted, indent=2), encoding="utf-8")
        print(f"[+] Certificate imported: {owner_name}")
        print(f"[+] Fingerprint: {fingerprint}")

        return fingerprint

    def list_certificates(self) -> None:
        """List all trusted certificates."""
        if not self.trusted_certs_file.exists():
            print("[-] No trusted certificates found.")
            return

        trusted = json.loads(self.trusted_certs_file.read_text(encoding="utf-8"))
        if not trusted:
            print("[-] No trusted certificates found.")
            return

        print("\n[+] Trusted Certificates:")
        for fingerprint, data in trusted.items():
            print(f"  Owner: {data.get('owner_name', 'Unknown')}")
            print(f"  Fingerprint: {fingerprint}")
            print(f"  Imported: {data.get('imported_at', 'Unknown')}")
            print()

    def get_trusted_certificate(self, fingerprint: str) -> Optional[x509.Certificate]:
        """Get a trusted certificate by fingerprint."""
        if not self.trusted_certs_file.exists():
            return None

        trusted = json.loads(self.trusted_certs_file.read_text(encoding="utf-8"))
        if fingerprint not in trusted:
            return None

        cert_pem = base64.b64decode(trusted[fingerprint]["certificate"])
        return x509.load_pem_x509_certificate(cert_pem)

    def _get_certificate_fingerprint(self, cert: x509.Certificate) -> str:
        """Calculate SHA-256 fingerprint of a certificate."""
        fingerprint_bytes = cert.fingerprint(hashes.SHA256())
        return ":".join(f"{b:02x}" for b in fingerprint_bytes)

    def list_keys(self) -> None:
        """List all key pairs."""
        if not self.keys_file.exists():
            print("[-] No keys found.")
            return

        keys_data = json.loads(self.keys_file.read_text(encoding="utf-8"))
        if not keys_data:
            print("[-] No keys found.")
            return

        print("\n[+] Key Pairs:")
        for key_id, data in keys_data.items():
            status = "ACTIVE" if data.get("active", False) else "INACTIVE"
            print(f"  ID: {key_id}")
            print(f"  Type: {data.get('key_type', 'Unknown')}")
            print(f"  Size: {data.get('key_size', 'Unknown')} bits")
            print(f"  Status: {status}")
            print(f"  Created: {data.get('created_at', 'Unknown')}")
            print()

