# Quick Start Guide - Command Examples

## Step-by-Step: How to Use the Commands

### 1. Generate Your Key Pair

```bash
python secure_usb.py keygen
# Enter password when prompted (e.g., "mypassword123")
```

**Output example:**
```
[+] Key pair generated: key_1_1768093337199217
[+] Certificate fingerprint: aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00
```

**Copy that fingerprint!** You'll need it later.

---

### 2. Export Your Certificate (to share with others)

```bash
python secure_usb.py export-cert my_certificate.pem
```

This creates `my_certificate.pem` file that you can share with others.

---

### 3. Import Someone Else's Certificate

If Alice sends you her certificate file (`alice_cert.pem`):

```bash
python secure_usb.py import-cert alice_cert.pem --owner "Alice"
```

**Output:**
```
[+] Certificate imported: Alice
[+] Fingerprint: 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:...
```

**Copy Alice's fingerprint!** You'll need it to encrypt files for her.

---

### 4. List Trusted Certificates (to find fingerprints)

```bash
python secure_usb.py list-certs
```

**Output example:**
```
[+] Trusted Certificates:
  Owner: Alice
  Fingerprint: 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff
  Imported: 2024-01-15T10:30:00

  Owner: Bob
  Fingerprint: ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00
  Imported: 2024-01-15T11:00:00
```

**Copy the fingerprint** (the long string with colons) of the person you want to encrypt for.

---

### 5. Encrypt Files for a Recipient

**What is `/path`?**
- This is the **directory path** where your files are located
- Can be a folder on your computer or a USB drive

**What is `fingerprint`?**
- This is the **certificate fingerprint** of the recipient (from step 3 or 4)
- It's that long string with colons like: `11:22:33:44:55:66:77:88:...`

**Examples:**

```bash
# Encrypt files in current directory for Alice
python secure_usb.py encrypt-for . 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff

# Encrypt files in a specific folder
python secure_usb.py encrypt-for /home/user/my_files 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff

# Encrypt files on USB drive (Linux/Mac)
python secure_usb.py encrypt-for /media/user/USB 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff

# Encrypt files on USB drive (Windows)
python secure_usb.py encrypt-for E:\\ 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff
```

**Real example with a test folder:**
```bash
# Create test files
mkdir test_folder
echo "Secret message" > test_folder/secret.txt
echo "Important data" > test_folder/data.txt

# Get Alice's fingerprint first
python secure_usb.py list-certs

# Copy the fingerprint, then encrypt (replace with actual fingerprint)
python secure_usb.py encrypt-for test_folder 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff
```

**Expected output:**
```
[+] Encrypted: test_folder/secret.txt
[+] Encrypted: test_folder/data.txt
[i] Total files encrypted: 2
```

---

### 6. Decrypt Files

When you receive encrypted files (that were encrypted for you):

```bash
# Decrypt files in current directory
python secure_usb.py decrypt .

# Decrypt files in a specific folder
python secure_usb.py decrypt /home/user/my_files

# Decrypt files on USB drive
python secure_usb.py decrypt /media/user/USB
```

You'll be prompted for your password (the one from step 1).

---

### Complete Workflow Example

```bash
# 1. Generate your keys
python secure_usb.py keygen
# Password: mypassword123
# Fingerprint: aa:bb:cc:dd:ee:ff:... (save this!)

# 2. Export your certificate to share
python secure_usb.py export-cert my_cert.pem

# 3. Import Alice's certificate (she sent you alice_cert.pem)
python secure_usb.py import-cert alice_cert.pem --owner "Alice"

# 4. Get Alice's fingerprint
python secure_usb.py list-certs
# Copy Alice's fingerprint: 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff

# 5. Create files to encrypt
mkdir secret_files
echo "Top secret!" > secret_files/file1.txt
echo "Confidential" > secret_files/file2.txt

# 6. Encrypt files for Alice (use her actual fingerprint)
python secure_usb.py encrypt-for secret_files 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff

# 7. Sign the files (optional, for integrity)
python secure_usb.py sign secret_files
# Password: mypassword123

# 8. Send secret_files to Alice
# (via USB, email, etc.)

# On Alice's side:
# 9. She imports your certificate
python secure_usb.py import-cert my_cert.pem --owner "You"

# 10. She decrypts the files
python secure_usb.py decrypt secret_files
# Password: alice_password

# 11. She verifies signature (optional)
python secure_usb.py verify secret_files
```

---

## Path Examples

**Current directory:**
```bash
python secure_usb.py encrypt-for . fingerprint
# "." means current directory
```

**Specific folder:**
```bash
python secure_usb.py encrypt-for /home/user/documents fingerprint
python secure_usb.py encrypt-for ./my_folder fingerprint
python secure_usb.py encrypt-for ~/Documents fingerprint
```

**USB drive (Linux/Mac):**
```bash
python secure_usb.py encrypt-for /media/user/USB fingerprint
python secure_usb.py encrypt-for /Volumes/USB fingerprint  # Mac
```

**USB drive (Windows):**
```bash
python secure_usb.py encrypt-for E:\ fingerprint
python secure_usb.py encrypt-for "E:\My Files" fingerprint
```

---

## Fingerprint Format

Fingerprints look like this (64 hex characters, 31 colons, 95 characters total):
```
aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00
```

**Important:** Copy the ENTIRE fingerprint exactly as shown, including all colons.

---

## Quick Reference

| Command | What to provide |
|---------|----------------|
| `encrypt-for <path> <fingerprint>` | `<path>` = folder with files, `<fingerprint>` = recipient's cert fingerprint |
| `decrypt <path>` | `<path>` = folder with encrypted files (uses your password) |
| `sign <path>` | `<path>` = folder with files to sign (uses your password) |
| `verify <path>` | `<path>` = folder with signed files |
| `list-certs` | Nothing (shows all trusted certificates with fingerprints) |

---

**Tip:** Always use `list-certs` to find the exact fingerprint you need!




