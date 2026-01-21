# Testing Guide for Secure My USB

This guide shows you how to test all features of Secure My USB.

## Quick Test: Run Automated Tests

```bash
# Run all tests
pytest test_secure_usb.py -v

# Run specific test classes
pytest test_secure_usb.py::TestKeyManagement -v
pytest test_secure_usb.py::TestHybridEncryption -v
pytest test_secure_usb.py::TestDigitalSignatures -v
```

## Manual Testing: Step-by-Step Workflow

### 1. Setup Test Environment

```bash
# Create a test directory
mkdir test_workflow
cd test_workflow

# Create some test files
echo "Hello, this is a test file!" > file1.txt
echo "Secret data here" > file2.txt
echo "More content" > file3.txt
```

### 2. Test Key Generation

```bash
# Generate RSA key pair
python secure_usb.py keygen

# Generate ECC key pair (alternative)
python secure_usb.py keygen --key-type ECC

# List your keys
python secure_usb.py list-keys
```

**Expected output**: Key pair generated, certificate fingerprint shown.

### 3. Test Certificate Export/Import

```bash
# Export your certificate
python secure_usb.py export-cert my_cert.pem

# Import it back (simulating receiving someone else's cert)
python secure_usb.py import-cert my_cert.pem --owner "Test User"

# List trusted certificates
python secure_usb.py list-certs
```

**Expected output**: Certificate exported, then imported successfully.

### 4. Test Hybrid Encryption

```bash
# Get your certificate fingerprint (from list-certs output)
# It looks like: aa:bb:cc:dd:ee:ff:...

# Encrypt files for yourself (using your own fingerprint)
python secure_usb.py encrypt-for . <your_fingerprint>

# Verify files are encrypted (check for .envelope.json files)
ls -la *.envelope.json

# Decrypt the files
python secure_usb.py decrypt .
```

**Expected output**: Files encrypted, then decrypted successfully. Original content restored.

### 5. Test Digital Signatures

```bash
# Sign all files in the directory
python secure_usb.py sign .

# Verify the signature
python secure_usb.py verify .

# Modify a file to test tampering detection
echo "TAMPERED" >> file1.txt

# Verify again (should fail)
python secure_usb.py verify .
```

**Expected output**: First verify succeeds, second fails with tampering detected.

### 6. Test Legacy Password-Based Encryption

```bash
# Create a new test directory
mkdir test_legacy
cd test_legacy
echo "Legacy test" > test.txt

# Initialize with password
python secure_usb.py init .

# Encrypt files
python secure_usb.py encrypt .

# Decrypt files
python secure_usb.py decrypt-legacy .

# Check status
python secure_usb.py status .
```

**Expected output**: Files encrypted and decrypted successfully.

## Complete End-to-End Test Script

Save this as `test_complete.sh`:

```bash
#!/bin/bash
set -e

echo "=== Secure My USB Complete Test ==="

# Create test directory
TEST_DIR="test_complete_$(date +%s)"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Create test files
echo "File 1 content" > file1.txt
echo "File 2 content" > file2.txt
mkdir subdir
echo "File 3 content" > subdir/file3.txt

echo "1. Testing key generation..."
python ../secure_usb.py keygen --key-type RSA

echo "2. Testing certificate export..."
python ../secure_usb.py export-cert test_cert.pem

echo "3. Testing certificate import..."
python ../secure_usb.py import-cert test_cert.pem --owner "Test User"

echo "4. Getting certificate fingerprint..."
FINGERPRINT=$(python ../secure_usb.py list-certs | grep -A1 "Test User" | grep "Fingerprint" | awk '{print $2}')
echo "Fingerprint: $FINGERPRINT"

echo "5. Testing hybrid encryption..."
python ../secure_usb.py encrypt-for . "$FINGERPRINT"

echo "6. Verifying encryption (checking for envelope files)..."
if ls *.envelope.json 1> /dev/null 2>&1; then
    echo "✓ Encryption successful"
else
    echo "✗ Encryption failed"
    exit 1
fi

echo "7. Testing decryption..."
python ../secure_usb.py decrypt .

echo "8. Verifying decryption..."
if diff file1.txt <(echo "File 1 content") > /dev/null; then
    echo "✓ Decryption successful"
else
    echo "✗ Decryption failed"
    exit 1
fi

echo "9. Testing digital signatures..."
python ../secure_usb.py sign .

echo "10. Testing signature verification..."
if python ../secure_usb.py verify .; then
    echo "✓ Signature verification successful"
else
    echo "✗ Signature verification failed"
    exit 1
fi

echo "11. Testing tampering detection..."
echo "TAMPERED" >> file1.txt
if ! python ../secure_usb.py verify . 2>/dev/null; then
    echo "✓ Tampering detection works"
else
    echo "✗ Tampering detection failed"
    exit 1
fi

echo ""
echo "=== All tests passed! ==="
cd ..
rm -rf "$TEST_DIR"
```

Make it executable and run:
```bash
chmod +x test_complete.sh
./test_complete.sh
```

## Testing Specific Scenarios

### Test Wrong Password

```bash
python secure_usb.py keygen
# Enter password: correct123

# Try to load with wrong password
python secure_usb.py decrypt .
# Enter password: wrong123
# Expected: Error "Wrong password"
```

### Test Wrong Private Key

```bash
# Generate two key pairs
python secure_usb.py keygen
python secure_usb.py keygen  # Creates second key

# Export both certificates
python secure_usb.py export-cert cert1.pem
python secure_usb.py export-cert cert2.pem

# Import both
python secure_usb.py import-cert cert1.pem --owner "User1"
python secure_usb.py import-cert cert2.pem --owner "User2"

# Encrypt with cert1 fingerprint
python secure_usb.py encrypt-for . <cert1_fingerprint>

# Try to decrypt with password for cert2 (should fail)
python secure_usb.py decrypt .
# Expected: Error "Failed to unwrap key"
```

### Test Tampered Ciphertext

```bash
# Encrypt a file
python secure_usb.py encrypt-for . <fingerprint>

# Manually tamper with encrypted file
python3 -c "
import sys
data = open('file1.txt', 'rb').read()
data = bytearray(data)
data[0] ^= 0xFF  # Flip a bit
open('file1.txt', 'wb').write(bytes(data))
"

# Try to decrypt (should fail)
python secure_usb.py decrypt .
# Expected: Error about tampering/corruption
```

### Test Missing Files in Manifest

```bash
# Sign files
python secure_usb.py sign .

# Delete a file
rm file1.txt

# Verify (should fail)
python secure_usb.py verify .
# Expected: Error "File missing"
```

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError`:
```bash
# Make sure you're in the project directory
cd /path/to/Secure-My-USB

# Activate virtual environment if using one
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows
```

### Certificate Not Found

If encryption fails with "certificate not found":
```bash
# Make sure you imported the certificate first
python secure_usb.py import-cert <cert.pem> --owner "Name"

# Get the fingerprint
python secure_usb.py list-certs
```

### Tests Fail

If pytest tests fail:
```bash
# Install pytest if not installed
pip install pytest

# Run with more verbose output
pytest test_secure_usb.py -v -s

# Run a specific test
pytest test_secure_usb.py::TestHybridEncryption::test_encrypt_decrypt_rsa_success -v
```

## Expected Test Results

When everything works correctly:

✅ **Key Generation**: Creates key pair and certificate  
✅ **Certificate Export**: Saves PEM file  
✅ **Certificate Import**: Adds to trusted store  
✅ **Hybrid Encryption**: Files encrypted with .envelope.json created  
✅ **Decryption**: Files restored to original content  
✅ **Signing**: Manifest and signature files created  
✅ **Verification**: Signature verified successfully  
✅ **Tampering Detection**: Modified files detected  
✅ **Wrong Password**: Properly rejected  
✅ **Wrong Key**: Decryption fails correctly  

## Quick Verification Checklist

- [ ] `python secure_usb.py --help` shows all commands
- [ ] `pytest test_secure_usb.py -v` passes all tests
- [ ] Key generation works (RSA and ECC)
- [ ] Certificate export/import works
- [ ] Hybrid encryption/decryption works
- [ ] Digital signatures work
- [ ] Tampering is detected
- [ ] Wrong passwords are rejected
- [ ] Status command shows correct information





