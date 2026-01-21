# Secure My USB

A comprehensive **CLI-only** cryptographic tool for securing files on USB drives and folders. It provides password-based encryption, hybrid encryption with public key cryptography, and digital signatures for file integrity verification. No GUI is required; all operations run via `python secure_usb.py ...`.

## Features

- **Key Management**: Generate RSA-3072 or ECC P-256 key pairs with self-signed X.509 certificates
- **Hybrid Encryption**: Encrypt files using AES-256-GCM with RSA-OAEP or ECC key wrapping
- **Digital Signatures**: Create and verify signed manifests for file integrity
- **Password-based Encryption**: Legacy Fernet-based encryption for backward compatibility
- **Cross-platform**: Works on Windows, Linux, and macOS

## Installation

### Prerequisites

- Python 3.10 or higher
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

### Setup

1. Clone or download this repository.
2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install runtime dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. (Optional) Install test tools:
   ```bash
   pip install pytest
   ```

## Quick Start

### 1. Generate Your Key Pair

First, generate a key pair and certificate:

```bash
python secure_usb.py keygen
# Or for ECC:
python secure_usb.py keygen --key-type ECC
```

You'll be prompted for a password to encrypt your private key. **Remember this password!**

### 2. Export Your Certificate

Share your certificate with others so they can encrypt files for you:

```bash
python secure_usb.py export-cert my_certificate.pem
```

### 3. Import Trusted Certificates

Import certificates from people you trust:

```bash
python secure_usb.py import-cert alice_cert.pem --owner "Alice"
python secure_usb.py list-certs  # View all trusted certificates
```

### 4. Encrypt Files for a Recipient

Encrypt all files in a folder/USB for a specific recipient:

```bash
python secure_usb.py encrypt-for /path/to/usb <recipient_fingerprint>
```

The recipient fingerprint can be found using `list-certs` or when importing a certificate.

### 5. Decrypt Files

Decrypt files that were encrypted for you:

```bash
python secure_usb.py decrypt /path/to/usb
```

You'll be prompted for your private key password.

### 6. Sign and Verify Files

Create a signed manifest of all files:

```bash
python secure_usb.py sign /path/to/usb
```

Verify the signature and file integrity:

```bash
python secure_usb.py verify /path/to/usb
```

## Command Reference (CLI)

### Key Management

- `keygen [--key-type RSA|ECC] [--key-size 3072]` - Generate key pair and certificate
- `export-cert <output.pem> [--key-id <id>]` - Export certificate to PEM file
- `import-cert <cert.pem> [--owner <name>]` - Import and trust a certificate
- `list-certs` - List all trusted certificates
- `list-keys` - List all key pairs

### Hybrid Encryption

- `encrypt-for <path> <recipient_fingerprint>` - Encrypt files for a recipient
- `decrypt <path> [--key-id <id>]` - Decrypt files using private key

### Digital Signatures

- `sign <path> [--key-id <id>]` - Create and sign a manifest
- `verify <path> [--expected-signer <fingerprint>]` - Verify manifest signature

### Legacy Commands (Password-based)

- `init <path>` - Initialize path with password-based encryption
- `encrypt <path>` - Encrypt files with password (Fernet)
- `decrypt <path> --password-mode` - Decrypt files with password (Fernet)
- `status <path>` - Show path status

## Usage Examples

### Example 1: Encrypting Files for Alice

```bash
# 1. Alice generates her key pair
python secure_usb.py keygen
python secure_usb.py export-cert alice_cert.pem

# 2. You import Alice's certificate
python secure_usb.py import-cert alice_cert.pem --owner "Alice"

# 3. Get Alice's fingerprint
python secure_usb.py list-certs
# Output shows: Fingerprint: aa:bb:cc:dd:...

# 4. Encrypt files for Alice
python secure_usb.py encrypt-for /media/usb aa:bb:cc:dd:...
```

### Example 2: Signing Files Before Sharing

```bash
# 1. Sign all files in the USB
python secure_usb.py sign /media/usb

# 2. Share the USB with recipient

# 3. Recipient verifies integrity
python secure_usb.py verify /media/usb
```

### Example 3: Complete Workflow

```bash
# Setup
python secure_usb.py keygen --key-type RSA
python secure_usb.py export-cert my_cert.pem

# Encrypt for recipient
python secure_usb.py encrypt-for ./secure_folder <recipient_fingerprint>

# Sign for integrity
python secure_usb.py sign ./secure_folder

# On recipient side: verify and decrypt
python secure_usb.py verify ./secure_folder
python secure_usb.py decrypt ./secure_folder
```

## Testing

Manual testing steps:
1. Generate keys: `python secure_usb.py keygen`
2. Export cert: `python secure_usb.py export-cert my_cert.pem`
3. Import recipient cert: `python secure_usb.py import-cert recipient.pem --owner "Recipient"`
4. Encrypt: `python secure_usb.py encrypt-for <path> <recipient_fingerprint>`
5. Decrypt: `python secure_usb.py decrypt <path>`
6. Sign: `python secure_usb.py sign <path>`
7. Verify: `python secure_usb.py verify <path>`

## Security Considerations

- **Private Keys**: Private keys are encrypted at rest using scrypt (memory-hard KDF)
- **Key Storage**: Keys are stored in `~/.secure_usb_keys/` (configurable)
- **Certificate Pinning**: Trust-on-first-use (TOFU) prevents MITM attacks
- **Replay Protection**: Manifests include nonces and timestamps
- **Tampering Detection**: AES-GCM authentication tags detect modifications

## File Structure (CLI only)

```
Secure-My-USB/
├── secure_usb.py          # Main CLI application
├── key_manager.py         # Key and certificate management
├── signature_manager.py   # Digital signature functionality
├── hybrid_encryption.py   # Hybrid encryption (AES-GCM + RSA/ECC)
├── hardware_key_storage.py# Conceptual hardware-backed key interface (future work)
├── QUICK_START.md         # Command examples
├── TESTING.md             # Testing guide
├── README.md              # This file
├── DOCS.md                # Detailed cryptographic documentation
├── LICENSE                # MIT License
└── requirements.txt       # Runtime dependencies
```

## Troubleshooting

### "Certificate not found" error

Make sure you've imported the recipient's certificate using `import-cert` before encrypting.

### "Wrong password" error

Double-check your private key password. If forgotten, you'll need to generate a new key pair.

### "Verification failed" error

This means files or the manifest have been modified. Check:
- Files haven't been tampered with
- Manifest signature file is intact
- Certificate is trusted

## License

MIT License - see LICENSE file for details.

## Author

This is a solo academic project for cryptography coursework.

## Acknowledgments

Built using the Python `cryptography` library, which provides secure implementations of cryptographic primitives.






