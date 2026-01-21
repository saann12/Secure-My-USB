"""Secure My USB - Advanced Cryptographic Tool for USB/Folder Protection.

This tool provides:
- Password-based encryption (legacy Fernet mode)
- Hybrid encryption with public key cryptography (AES-256-GCM + RSA-OAEP/ECC)
- Digital signatures with manifest verification
- Key and certificate management
- Cross-platform support (Windows, Linux, macOS)

New commands (cryptography coursework features):
- keygen: Generate RSA/ECC key pair and self-signed certificate
- export-cert: Export certificate to PEM file
- import-cert: Import and trust a certificate
- encrypt-for: Encrypt files for a recipient using hybrid encryption
- decrypt: Decrypt files using private key (hybrid encryption)
- sign: Create and sign a manifest of files
- verify: Verify manifest signature and file integrity

Legacy commands (backward compatibility):
- init: Initialize path with password-based encryption
- encrypt: Encrypt files with password (Fernet)
- decrypt: Decrypt files with password (Fernet)
- status: Show path status
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Import new modules
from key_manager import KeyManager
from signature_manager import SignatureManager
from hybrid_encryption import HybridEncryption

# Metadata file name stored in the target root (legacy).
META_FILENAME = ".usb_secure_meta.json"
# Constant marker used to validate the password for a given path.
TEST_MARKER = b"USB-OK"


# ============================================================================
# Legacy password-based encryption functions (backward compatibility)
# ============================================================================


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit Fernet key from password + salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = kdf.derive(password.encode("utf-8"))
    # Fernet expects a urlsafe base64-encoded 32-byte key.
    return base64.urlsafe_b64encode(key)


def init_usb(path: str, password: str) -> None:
    """Initialize the target path by generating salt + metadata (legacy)."""
    root = Path(path).expanduser().resolve()
    meta_path = root / META_FILENAME

    if not root.exists():
        print(f"[-] Path does not exist: {root}")
        return
    if not root.is_dir():
        print(f"[-] Path is not a directory: {root}")
        return
    if meta_path.exists():
        print("[i] Already initialized. No action taken.")
        return

    try:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        test_token = fernet.encrypt(TEST_MARKER).decode("utf-8")

        metadata = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "test_token": test_token,
        }
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        print("[+] USB initialized.")
    except OSError as exc:
        print(f"[-] Failed to write metadata: {exc}")


def load_key(path: str, password: str) -> Fernet:
    """Load Fernet key after validating password; raises on errors."""
    root = Path(path).expanduser().resolve()
    meta_path = root / META_FILENAME
    if not meta_path.exists():
        raise FileNotFoundError("Not initialized. Run init first.")

    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        salt_b64 = data["salt"]
        test_token = data["test_token"]
        salt = base64.b64decode(salt_b64)
    except Exception as exc:
        raise ValueError("Metadata file is corrupted or unreadable.") from exc

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        marker = fernet.decrypt(test_token.encode("utf-8"))
    except InvalidToken as exc:
        raise ValueError("Wrong password.") from exc

    if marker != TEST_MARKER:
        raise ValueError("Wrong password.")
    return fernet


def _iter_files(root: Path):
    """Yield all file paths under root, skipping the metadata file."""
    exclude = {META_FILENAME, ".usb_manifest.json", ".usb_manifest.sig"}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            file_path = Path(dirpath) / name
            if file_path.name in exclude or file_path.name.endswith(".envelope.json"):
                continue
            yield file_path


def encrypt_usb(path: str, password: str) -> None:
    """Encrypt all files under the path using the provided password (legacy Fernet)."""
    root = Path(path).expanduser().resolve()
    try:
        fernet = load_key(str(root), password)
    except Exception as exc:
        print(f"[-] {exc}")
        return

    count = 0
    for file_path in _iter_files(root):
        try:
            data = file_path.read_bytes()
            encrypted = fernet.encrypt(data)
            file_path.write_bytes(encrypted)
            count += 1
            print(f"[+] Encrypted: {file_path}")
        except Exception as exc:
            print(f"[!] Failed to encrypt {file_path}: {exc}")
    print(f"[i] Total files encrypted: {count}")


def decrypt_usb(path: str, password: str) -> None:
    """Decrypt all files under the path using the provided password (legacy Fernet)."""
    root = Path(path).expanduser().resolve()
    try:
        fernet = load_key(str(root), password)
    except Exception as exc:
        print(f"[-] {exc}")
        return

    count = 0
    for file_path in _iter_files(root):
        try:
            data = file_path.read_bytes()
            plaintext = fernet.decrypt(data)
            file_path.write_bytes(plaintext)
            count += 1
            print(f"[+] Decrypted: {file_path}")
        except InvalidToken:
            print(f"[!] Failed to decrypt (corrupted or not encrypted): {file_path}")
        except Exception as exc:
            print(f"[!] Failed to process {file_path}: {exc}")
    print(f"[i] Total files decrypted: {count}")


def usb_status(path: str) -> None:
    """Print whether the path is initialized and basic stats."""
    root = Path(path).expanduser().resolve()
    meta_path = root / META_FILENAME

    if not root.exists():
        print(f"[-] Path does not exist: {root}")
        return
    if not root.is_dir():
        print(f"[-] Path is not a directory: {root}")
        return

    # Check for legacy initialization
    legacy_init = meta_path.exists()
    
    # Check for manifest (new signature system)
    manifest_path = root / ".usb_manifest.json"
    has_manifest = manifest_path.exists()

    # Check for hybrid encryption envelopes
    has_envelopes = any(f.name.endswith(".envelope.json") for f in root.rglob("*.envelope.json"))

    print(f"[+] Path: {root}")
    if legacy_init:
        print("[+] Legacy password-based encryption: initialized")
    if has_manifest:
        print("[+] Digital signature: manifest found")
    if has_envelopes:
        print("[+] Hybrid encryption: encrypted files found")

    if not legacy_init and not has_manifest and not has_envelopes:
        print("[-] Path is NOT initialized (no encryption or signatures found).")
        return

    file_count = 0
    total_size = 0
    for file_path in _iter_files(root):
        try:
            file_count += 1
            total_size += file_path.stat().st_size
        except OSError:
            continue
    print(f"[i] Files found: {file_count}")
    print(f"[i] Total size: {total_size} bytes")


# ============================================================================
# New cryptography coursework commands
# ============================================================================


def cmd_keygen(key_type: str = "RSA", key_size: int = 3072) -> None:
    """Generate a new key pair and self-signed certificate."""
    password = getpass.getpass("Enter password to encrypt private key: ")
    if not password:
        print("[-] Password cannot be empty.")
        return

    try:
        key_manager = KeyManager()
        private_key, cert = key_manager.generate_keypair(password, key_type, key_size)
        print("[+] Key generation successful!")
        print("[i] Use 'export-cert' to share your certificate with others.")
    except Exception as exc:
        print(f"[-] Key generation failed: {exc}")
        sys.exit(1)


def cmd_export_cert(output_path: str, key_id: Optional[str] = None) -> None:
    """Export certificate to a PEM file."""
    try:
        key_manager = KeyManager()
        key_manager.export_certificate(output_path, key_id)
    except Exception as exc:
        print(f"[-] Export failed: {exc}")
        sys.exit(1)


def cmd_import_cert(cert_path: str, owner_name: str = "Unknown") -> None:
    """Import and trust a certificate."""
    try:
        key_manager = KeyManager()
        fingerprint = key_manager.import_certificate(cert_path, owner_name)
        print(f"[+] Certificate imported successfully!")
        print(f"[i] Fingerprint: {fingerprint}")
        print("[i] You can now encrypt files for this recipient using 'encrypt-for'.")
    except Exception as exc:
        print(f"[-] Import failed: {exc}")
        sys.exit(1)


def cmd_list_certs() -> None:
    """List all trusted certificates."""
    try:
        key_manager = KeyManager()
        key_manager.list_certificates()
    except Exception as exc:
        print(f"[-] Failed to list certificates: {exc}")
        sys.exit(1)


def cmd_list_keys() -> None:
    """List all key pairs."""
    try:
        key_manager = KeyManager()
        key_manager.list_keys()
    except Exception as exc:
        print(f"[-] Failed to list keys: {exc}")
        sys.exit(1)


def cmd_encrypt_for(path: str, recipient_fingerprint: str) -> None:
    """Encrypt all files in path for a recipient using hybrid encryption."""
    root = Path(path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"[-] Path does not exist or is not a directory: {root}")
        sys.exit(1)

    try:
        key_manager = KeyManager()
        hybrid = HybridEncryption(key_manager)
        hybrid.encrypt_for(str(root), recipient_fingerprint)
        print("[+] Encryption completed!")
    except Exception as exc:
        print(f"[-] Encryption failed: {exc}")
        sys.exit(1)


def cmd_decrypt(path: str, key_id: Optional[str] = None) -> None:
    """Decrypt files encrypted with hybrid encryption."""
    password = getpass.getpass("Enter password to unlock private key: ")
    if not password:
        print("[-] Password cannot be empty.")
        sys.exit(1)

    try:
        key_manager = KeyManager()
        hybrid = HybridEncryption(key_manager)
        hybrid.decrypt(str(path), password, key_id)
        print("[+] Decryption completed!")
    except Exception as exc:
        print(f"[-] Decryption failed: {exc}")
        sys.exit(1)


def cmd_sign(path: str, key_id: Optional[str] = None) -> None:
    """Create and sign a manifest of all files in the path."""
    password = getpass.getpass("Enter password to unlock private key: ")
    if not password:
        print("[-] Password cannot be empty.")
        sys.exit(1)

    try:
        key_manager = KeyManager()
        sig_manager = SignatureManager(key_manager)
        sig_manager.sign_manifest(str(path), password, key_id)
        print("[+] Manifest signed successfully!")
    except Exception as exc:
        print(f"[-] Signing failed: {exc}")
        sys.exit(1)


def cmd_verify(path: str, expected_signer: Optional[str] = None) -> None:
    """Verify manifest signature and file integrity."""
    try:
        key_manager = KeyManager()
        sig_manager = SignatureManager(key_manager)
        success = sig_manager.verify_manifest(str(path), expected_signer)
        if success:
            print("[+] Verification successful!")
            sys.exit(0)
        else:
            print("[-] Verification failed!")
            sys.exit(1)
    except Exception as exc:
        print(f"[-] Verification error: {exc}")
        sys.exit(1)


# ============================================================================
# CLI Argument Parsing
# ============================================================================


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Secure My USB - Advanced Cryptographic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Key management
  %(prog)s keygen                    # Generate RSA-3072 key pair
  %(prog)s keygen --key-type ECC     # Generate ECC P-256 key pair
  %(prog)s export-cert cert.pem      # Export certificate
  %(prog)s import-cert cert.pem "Alice"  # Import and trust certificate
  %(prog)s list-certs                # List trusted certificates

  # Hybrid encryption
  %(prog)s encrypt-for /path/to/usb <fingerprint>  # Encrypt for recipient
  %(prog)s decrypt /path/to/usb                    # Decrypt with private key

  # Digital signatures
  %(prog)s sign /path/to/usb         # Sign manifest
  %(prog)s verify /path/to/usb      # Verify manifest

  # Legacy password-based encryption
  %(prog)s init /path/to/usb        # Initialize with password
  %(prog)s encrypt /path/to/usb    # Encrypt with password
  %(prog)s decrypt /path/to/usb    # Decrypt with password
  %(prog)s status /path/to/usb     # Show status
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Key management commands
    keygen_parser = subparsers.add_parser("keygen", help="Generate key pair and certificate")
    keygen_parser.add_argument(
        "--key-type",
        choices=["RSA", "ECC"],
        default="RSA",
        help="Key type: RSA or ECC (default: RSA)",
    )
    keygen_parser.add_argument(
        "--key-size",
        type=int,
        default=3072,
        help="RSA key size in bits (default: 3072, ignored for ECC)",
    )

    export_parser = subparsers.add_parser("export-cert", help="Export certificate to PEM file")
    export_parser.add_argument("output", help="Output PEM file path")
    export_parser.add_argument("--key-id", help="Key ID (uses active key if not specified)")

    import_parser = subparsers.add_parser("import-cert", help="Import and trust a certificate")
    import_parser.add_argument("cert_path", help="Path to certificate PEM file")
    import_parser.add_argument(
        "--owner",
        default="Unknown",
        help="Owner name/identifier (default: Unknown)",
    )

    subparsers.add_parser("list-certs", help="List all trusted certificates")
    subparsers.add_parser("list-keys", help="List all key pairs")

    # Hybrid encryption commands
    encrypt_for_parser = subparsers.add_parser(
        "encrypt-for", help="Encrypt files for a recipient (hybrid encryption)"
    )
    encrypt_for_parser.add_argument("path", help="Path to encrypt")
    encrypt_for_parser.add_argument(
        "recipient",
        help="Recipient certificate fingerprint",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt files (hybrid encryption or legacy password-based)"
    )
    decrypt_parser.add_argument("path", help="Path to decrypt")
    decrypt_parser.add_argument("--key-id", help="Key ID (uses active key if not specified)")
    decrypt_parser.add_argument(
        "--password-mode",
        action="store_true",
        help="Use legacy password-based decryption",
    )

    # Digital signature commands
    sign_parser = subparsers.add_parser("sign", help="Sign manifest of files")
    sign_parser.add_argument("path", help="Path to sign")
    sign_parser.add_argument("--key-id", help="Key ID (uses active key if not specified)")

    verify_parser = subparsers.add_parser("verify", help="Verify manifest signature")
    verify_parser.add_argument("path", help="Path to verify")
    verify_parser.add_argument(
        "--expected-signer",
        help="Expected signer fingerprint (for TOFU)",
    )

    # Legacy commands
    init_parser = subparsers.add_parser("init", help="Initialize path (legacy password-based)")
    init_parser.add_argument("path", help="Path to initialize")

    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt files (legacy password-based)"
    )
    encrypt_parser.add_argument("path", help="Path to encrypt")

    decrypt_legacy_parser = subparsers.add_parser(
        "decrypt-legacy", help="Decrypt files (legacy password-based, alias for decrypt --password-mode)"
    )
    decrypt_legacy_parser.add_argument("path", help="Path to decrypt")

    status_parser = subparsers.add_parser("status", help="Show path status")
    status_parser.add_argument("path", help="Path to check")

    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if not args.command:
        # No command provided, show help
        parse_args().parser.print_help()
        sys.exit(1)

    try:
        # New cryptography coursework commands
        if args.command == "keygen":
            cmd_keygen(args.key_type, args.key_size)
        elif args.command == "export-cert":
            cmd_export_cert(args.output, getattr(args, "key_id", None))
        elif args.command == "import-cert":
            cmd_import_cert(args.cert_path, getattr(args, "owner", "Unknown"))
        elif args.command == "list-certs":
            cmd_list_certs()
        elif args.command == "list-keys":
            cmd_list_keys()
        elif args.command == "encrypt-for":
            cmd_encrypt_for(args.path, args.recipient)
        elif args.command == "decrypt":
            if getattr(args, "password_mode", False):
                # Legacy password-based decryption
                password = getpass.getpass("Enter password: ")
                decrypt_usb(args.path, password)
            else:
                # Hybrid encryption decryption
                cmd_decrypt(args.path, getattr(args, "key_id", None))
        elif args.command == "sign":
            cmd_sign(args.path, getattr(args, "key_id", None))
        elif args.command == "verify":
            cmd_verify(args.path, getattr(args, "expected_signer", None))
        # Legacy commands
        elif args.command == "init":
            password = getpass.getpass("Enter password: ")
            init_usb(args.path, password)
        elif args.command == "encrypt":
            password = getpass.getpass("Enter password: ")
            encrypt_usb(args.path, password)
        elif args.command == "decrypt-legacy":
            password = getpass.getpass("Enter password: ")
            decrypt_usb(args.path, password)
        elif args.command == "status":
            usb_status(args.path)
        else:
            print(f"[-] Unknown command: {args.command}")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] Operation cancelled by user.")
        sys.exit(1)
    except Exception as exc:
        print(f"[-] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
