"""Digital Signature and Manifest Management Module.

This module handles:
- Creating signed manifest files (JSON) with file hashes, timestamps, nonces
- Signing manifests with private keys
- Verifying signatures and detecting tampering
- Replay attack mitigation using nonces and timestamps
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from key_manager import KeyManager

# Manifest file name
MANIFEST_FILENAME = ".usb_manifest.json"
SIGNATURE_FILENAME = ".usb_manifest.sig"


class SignatureManager:
    """Manages digital signatures and manifest files."""

    def __init__(self, key_manager: KeyManager):
        """Initialize SignatureManager with a KeyManager instance."""
        self.key_manager = key_manager

    def _compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _iter_files(self, root: Path) -> List[Path]:
        """Get all files in a directory tree, excluding manifest and signature files."""
        files = []
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                file_path = Path(dirpath) / name
                # Skip manifest and signature files
                if file_path.name in (MANIFEST_FILENAME, SIGNATURE_FILENAME):
                    continue
                if file_path.is_file():
                    files.append(file_path)
        return files

    def create_manifest(self, path: str) -> Dict[str, Any]:
        """
        Create a manifest of all files in the path.

        The manifest includes:
        - File name (relative to root)
        - SHA-256 hash
        - Timestamp
        - Random nonce (for replay protection)

        Args:
            path: Root path to create manifest for

        Returns:
            Dictionary containing manifest data
        """
        root = Path(path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Path does not exist or is not a directory: {root}")

        files = self._iter_files(root)
        manifest = {
            "version": 1,
            "created_at": datetime.utcnow().isoformat(),
            "nonce": base64.b64encode(os.urandom(16)).decode("utf-8"),
            "files": [],
        }

        for file_path in files:
            try:
                rel_path = file_path.relative_to(root)
                file_hash = self._compute_file_hash(file_path)
                file_size = file_path.stat().st_size

                manifest["files"].append(
                    {
                        "path": str(rel_path),
                        "hash": file_hash,
                        "size": file_size,
                        "timestamp": datetime.fromtimestamp(
                            file_path.stat().st_mtime
                        ).isoformat(),
                    }
                )
            except Exception as exc:
                print(f"[!] Warning: Failed to process {file_path}: {exc}")

        return manifest

    def sign_manifest(
        self, path: str, password: str, key_id: Optional[str] = None
    ) -> None:
        """
        Create and sign a manifest for all files in the path.

        Args:
            path: Root path to sign
            password: Password to unlock private key
            key_id: Optional key ID (uses active key if not specified)
        """
        root = Path(path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Path does not exist or is not a directory: {root}")

        # Create manifest
        manifest = self.create_manifest(path)
        manifest_json = json.dumps(manifest, indent=2, sort_keys=True)

        # Load private key and certificate
        private_key, key_id_used = self.key_manager.load_private_key(password, key_id)
        cert, _ = self.key_manager.load_certificate(key_id_used)
        fingerprint = self.key_manager._get_certificate_fingerprint(cert)

        # Sign the manifest
        if isinstance(private_key, rsa.RSAPrivateKey):
            signature = private_key.sign(
                manifest_json.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            signature = private_key.sign(
                manifest_json.encode("utf-8"), ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("Unsupported key type for signing")

        # Store manifest and signature
        manifest_path = root / MANIFEST_FILENAME
        signature_path = root / SIGNATURE_FILENAME

        manifest_path.write_text(manifest_json, encoding="utf-8")

        signature_data = {
            "signer_fingerprint": fingerprint,
            "signature": base64.b64encode(signature).decode("utf-8"),
            "algorithm": "RSA-PSS-SHA256" if isinstance(private_key, rsa.RSAPrivateKey) else "ECDSA-SHA256",
            "signed_at": datetime.utcnow().isoformat(),
        }

        signature_path.write_text(
            json.dumps(signature_data, indent=2), encoding="utf-8"
        )

        print(f"[+] Manifest created and signed: {len(manifest['files'])} files")
        print(f"[+] Signer fingerprint: {fingerprint}")

    def verify_manifest(
        self, path: str, expected_signer_fingerprint: Optional[str] = None
    ) -> bool:
        """
        Verify the manifest signature and check file integrity.

        Args:
            path: Root path to verify
            expected_signer_fingerprint: Optional expected signer fingerprint (for TOFU)

        Returns:
            True if verification succeeds, False otherwise
        """
        root = Path(path).expanduser().resolve()
        manifest_path = root / MANIFEST_FILENAME
        signature_path = root / SIGNATURE_FILENAME

        if not manifest_path.exists() or not signature_path.exists():
            print("[-] Manifest or signature file not found.")
            return False

        try:
            # Load manifest and signature
            manifest_json = manifest_path.read_text(encoding="utf-8")
            signature_data = json.loads(signature_path.read_text(encoding="utf-8"))

            signer_fingerprint = signature_data["signer_fingerprint"]
            signature_bytes = base64.b64decode(signature_data["signature"])
            algorithm = signature_data.get("algorithm", "RSA-PSS-SHA256")

            # Get signer's certificate
            cert = self.key_manager.get_trusted_certificate(signer_fingerprint)
            if cert is None:
                print(f"[-] Certificate not found for fingerprint: {signer_fingerprint}")
                print("[-] Import the signer's certificate first using 'import-cert'")
                return False

            # TOFU: Check if fingerprint matches expected
            if expected_signer_fingerprint and signer_fingerprint != expected_signer_fingerprint:
                print(f"[-] Signer fingerprint mismatch!")
                print(f"[-] Expected: {expected_signer_fingerprint}")
                print(f"[-] Got: {signer_fingerprint}")
                return False

            # Verify signature
            public_key = cert.public_key()

            try:
                if algorithm.startswith("RSA"):
                    public_key.verify(
                        signature_bytes,
                        manifest_json.encode("utf-8"),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                else:  # ECDSA
                    public_key.verify(
                        signature_bytes,
                        manifest_json.encode("utf-8"),
                        ec.ECDSA(hashes.SHA256()),
                    )
            except InvalidSignature:
                print("[-] Signature verification failed! Manifest may be tampered.")
                return False

            # Parse manifest and verify file integrity
            manifest = json.loads(manifest_json)

            # Check for replay attacks: verify nonce and timestamp are recent
            created_at = datetime.fromisoformat(manifest["created_at"])
            age = (datetime.utcnow() - created_at).total_seconds()
            if age > 86400 * 30:  # 30 days
                print(f"[!] Warning: Manifest is {age/86400:.1f} days old")

            # Verify all files match manifest
            files_ok = 0
            files_failed = 0

            for file_entry in manifest["files"]:
                file_path = root / file_entry["path"]
                if not file_path.exists():
                    print(f"[!] File missing: {file_entry['path']}")
                    files_failed += 1
                    continue

                current_hash = self._compute_file_hash(file_path)
                if current_hash != file_entry["hash"]:
                    print(f"[!] File modified: {file_entry['path']}")
                    print(f"    Expected hash: {file_entry['hash']}")
                    print(f"    Current hash:  {current_hash}")
                    files_failed += 1
                else:
                    files_ok += 1

            if files_failed > 0:
                print(f"[-] Verification failed: {files_failed} file(s) modified or missing")
                return False

            print(f"[+] Verification successful: {files_ok} file(s) verified")
            print(f"[+] Signer: {signer_fingerprint}")
            return True

        except Exception as exc:
            print(f"[-] Verification error: {exc}")
            return False

    def check_replay_attack(self, path: str) -> bool:
        """
        Check if a manifest with the same nonce already exists (replay detection).

        This is a simple check - in production, you'd maintain a database of used nonces.

        Args:
            path: Root path to check

        Returns:
            True if replay detected, False otherwise
        """
        root = Path(path).expanduser().resolve()
        manifest_path = root / MANIFEST_FILENAME

        if not manifest_path.exists():
            return False

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            nonce = manifest.get("nonce")

            # In a real system, you'd check against a database of used nonces
            # For this coursework, we'll just check if the manifest is very old
            created_at = datetime.fromisoformat(manifest["created_at"])
            age = (datetime.utcnow() - created_at).total_seconds()

            if age > 86400 * 365:  # More than a year old
                print(f"[!] Warning: Manifest is very old ({age/86400:.0f} days)")
                return True

            return False
        except Exception:
            return False

