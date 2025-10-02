
 PassFort - Cryptographic Password Manager

PassFort is a secure password manager built with Python that uses hybrid encryption (AES + RSA) to protect your passwords. It features a unique "Honey Vault" that shows decoy passwords if an attacker uses the wrong decryption key.

## Features

- **Hybrid Encryption**: Passwords encrypted with AES-256, keys encrypted with RSA-2048
- **Integrity Verification**: SHA-256 hashes verify password integrity
- **Honey Vault**: Shows realistic fake passwords if wrong key is used (security deception)
- **Strong Password Generator**: Auto-generates secure random passwords
- **Simple GUI**: User-friendly Tkinter interface
- **Secure Storage**: Encrypted vault files with PEM key format

## Security Architecture

1. **Password Storage**:
   - Each password is encrypted with a unique AES key (Fernet/AES-256)
   - The AES key is encrypted with your RSA public key
   - SHA-256 hash created for integrity verification

2. **Honey Vault**:
   - If wrong RSA key is used, shows fake decoy passwords
   - Appears legitimate to deceive attackers
   - Protects real vault from detection

## Installation

### Dependencies

```bash
pip install cryptography
```

Tkinter is included with Python by default.

## Usage

### 1. Run PassFort

```bash
python main.py
```

### 2. Generate RSA Keys

Click **"Generate RSA Keys"** to create a new key pair:
- `private_key.pem` - Keep this secret!
- `public_key.pem` - Used for encryption

### 3. Add Passwords

Click **"Add Password"**:
- Enter service name (e.g., "Gmail", "Facebook")
- Enter password or leave empty to auto-generate
- Password is encrypted and saved

### 4. Unlock Vault

Click **"Unlock Vault"**:
- Select your private key file
- If correct key: real vault unlocked
- If wrong key: honey vault (decoy) shown

### 5. View Passwords

Click **"View Passwords"** to see decrypted passwords with integrity status.

### 6. Generate Strong Password

Click **"Generate Strong Password"** to create a random secure password.

## File Structure

```


## Security Notes

 **Important**:
- Keep `private_key.pem` secure - anyone with it can decrypt your passwords
- The honey vault provides security through deception but is not foolproof
- Backup your private key in a secure location
- Use strong master passwords if you add password protection to the key

 How Honey Vault Works

When you unlock with the **wrong private key**:
1. App appears to decrypt successfully
2. Shows fake passwords for common services
3. Attacker doesn't know they have wrong data
4. Real vault remains hidden

When you unlock with the **correct private key**:
1. App verifies integrity with SHA-256 hashes
2. Shows real passwords with integrity status
3. Log indicates "Real vault accessible"

## Technical Details

- **Encryption**: AES-256 (Fernet) for passwords, RSA-2048 for AES keys
- **Hashing**: SHA-256 for integrity verification
- **Padding**: OAEP with SHA-256 for RSA encryption
- **Random Generation**: Uses `secrets` module for cryptographically secure randomness

## License

MIT License - Use responsibly and at your own risk.

## Disclaimer

This is an educational project demonstrating cryptographic concepts. For production use, consider established password managers with security audits.
