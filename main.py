from flask import Flask, render_template, request, jsonify, session
import json
import os
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

class VaultManager:
    def __init__(self):
        self.vault_file = "vault.json"
        self.honey_vault_file = "honey_vault.json"
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.is_unlocked = False
        self.is_honey_vault = False

    def generate_rsa_keypair(self, bits=2048):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_aes_key(self):
        """Generate AES key using Fernet"""
        return Fernet.generate_key()

    def encrypt_password(self, password, aes_key):
        """Encrypt password with AES (Fernet)"""
        f = Fernet(aes_key)
        encrypted = f.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_password(self, encrypted, aes_key):
        """Decrypt password with AES"""
        try:
            f = Fernet(aes_key)
            encrypted_bytes = base64.b64decode(encrypted.encode())
            decrypted = f.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def encrypt_aes_key_rsa(self, aes_key, public_key):
        """Encrypt AES key with RSA public key"""
        encrypted = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    def decrypt_aes_key_rsa(self, encrypted_key, private_key):
        """Decrypt AES key with RSA private key"""
        encrypted_bytes = base64.b64decode(encrypted_key.encode())
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

    def hash_password(self, service, password):
        """Create SHA-256 hash for integrity check"""
        data = f"{service}{password}".encode()
        return hashlib.sha256(data).hexdigest()

    def save_entry(self, entry, vault_type="real"):
        """Save entry to vault file"""
        file = self.vault_file if vault_type == "real" else self.honey_vault_file
        entries = self.load_entries(vault_type)
        entries.append(entry)
        with open(file, 'w') as f:
            json.dump(entries, f, indent=2)

    def load_entries(self, vault_type="real"):
        """Load entries from vault file"""
        file = self.vault_file if vault_type == "real" else self.honey_vault_file
        if os.path.exists(file):
            with open(file, 'r') as f:
                return json.load(f)
        return []

    def generate_strong_password(self, length=16):
        """Generate a strong random password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password

    def create_honey_vault(self):
        """Create decoy honey vault with fake passwords"""
        if os.path.exists(self.honey_vault_file):
            return

        fake_services = [
            "Gmail", "Facebook", "Netflix", "Amazon", "Twitter", 
            "Instagram", "LinkedIn", "GitHub", "Dropbox", "Spotify"
        ]

        honey_entries = []
        for service in fake_services:
            fake_password = self.generate_strong_password(12)
            aes_key = self.generate_aes_key()
            encrypted_password = self.encrypt_password(fake_password, aes_key)
            encrypted_aes_key = self.encrypt_aes_key_rsa(aes_key, self.rsa_public_key)
            password_hash = self.hash_password(service, fake_password)

            entry = {
                "service": service,
                "encrypted_password": encrypted_password,
                "encrypted_aes_key": encrypted_aes_key,
                "hash": password_hash
            }
            honey_entries.append(entry)

        with open(self.honey_vault_file, 'w') as f:
            json.dump(honey_entries, f, indent=2)

    def add_password(self, service, password=None):
        """Add a new password entry"""
        if not self.rsa_public_key:
            raise Exception("No RSA key pair loaded. Generate or import keys first.")

        if not password:
            password = self.generate_strong_password()

        aes_key = self.generate_aes_key()
        encrypted_password = self.encrypt_password(password, aes_key)
        encrypted_aes_key = self.encrypt_aes_key_rsa(aes_key, self.rsa_public_key)
        password_hash = self.hash_password(service, password)

        entry = {
            "service": service,
            "encrypted_password": encrypted_password,
            "encrypted_aes_key": encrypted_aes_key,
            "hash": password_hash
        }

        self.save_entry(entry, "real")
        return password

    def unlock_vault(self, private_key):
        """Unlock vault with RSA private key"""
        self.rsa_private_key = private_key
        self.is_unlocked = True

        # Test if this is the correct key
        entries = self.load_entries("real")
        if entries:
            try:
                test_entry = entries[0]
                aes_key = self.decrypt_aes_key_rsa(test_entry["encrypted_aes_key"], private_key)
                password = self.decrypt_password(test_entry["encrypted_password"], aes_key)
                expected_hash = self.hash_password(test_entry["service"], password)

                if expected_hash == test_entry["hash"]:
                    self.is_honey_vault = False
                    return True
                else:
                    raise Exception("Hash mismatch")
            except:
                # Wrong key - switch to honey vault
                self.is_honey_vault = True
                return True
        return True

    def view_passwords(self):
        """View all passwords"""
        if not self.is_unlocked:
            raise Exception("Vault is locked. Unlock first.")

        vault_type = "honey" if self.is_honey_vault else "real"
        entries = self.load_entries(vault_type)
        results = []

        for entry in entries:
            try:
                aes_key = self.decrypt_aes_key_rsa(entry["encrypted_aes_key"], self.rsa_private_key)
                password = self.decrypt_password(entry["encrypted_password"], aes_key)
                expected_hash = self.hash_password(entry["service"], password)

                integrity = "✓ OK" if expected_hash == entry["hash"] else "✗ FAILED"
                results.append({
                    "service": entry["service"],
                    "password": password,
                    "integrity": integrity
                })
            except Exception as e:
                results.append({
                    "service": entry["service"],
                    "password": "[DECRYPTION ERROR]",
                    "integrity": "✗ FAILED"
                })

        return results

# Initialize vault manager
vault = VaultManager()

# Check for existing keys on startup
if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
    try:
        with open("private_key.pem", "rb") as f:
            vault.rsa_private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            vault.rsa_public_key = serialization.load_pem_public_key(f.read())
    except:
        pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def status():
    return jsonify({
        'has_keys': vault.rsa_public_key is not None,
        'is_unlocked': vault.is_unlocked,
        'is_honey_vault': vault.is_honey_vault
    })

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    try:
        private_key, public_key = vault.generate_rsa_keypair(2048)
        vault.rsa_private_key = private_key
        vault.rsa_public_key = public_key

        # Save keys to files
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("private_key.pem", "wb") as f:
            f.write(private_pem)
        with open("public_key.pem", "wb") as f:
            f.write(public_pem)

        vault.create_honey_vault()

        return jsonify({
            'success': True,
            'message': 'RSA keys generated successfully',
            'private_key': private_pem.decode(),
            'public_key': public_pem.decode()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/import-keys', methods=['POST'])
def import_keys():
    try:
        data = request.json
        private_pem = data.get('private_key')

        if not private_pem:
            return jsonify({'success': False, 'error': 'Private key is required'}), 400

        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        public_key = private_key.public_key()

        vault.rsa_private_key = private_key
        vault.rsa_public_key = public_key
        vault.create_honey_vault()

        return jsonify({'success': True, 'message': 'Keys imported successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/add-password', methods=['POST'])
def add_password():
    try:
        data = request.json
        service = data.get('service')
        password = data.get('password')

        if not service:
            return jsonify({'success': False, 'error': 'Service name is required'}), 400

        saved_password = vault.add_password(service, password if password else None)

        return jsonify({
            'success': True,
            'message': f'Password for {service} saved successfully',
            'password': saved_password if not password else None
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/unlock-vault', methods=['POST'])
def unlock_vault():
    try:
        data = request.json
        private_pem = data.get('private_key')

        if not private_pem:
            return jsonify({'success': False, 'error': 'Private key is required'}), 400

        private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        vault.unlock_vault(private_key)

        return jsonify({
            'success': True,
            'is_honey_vault': vault.is_honey_vault,
            'message': 'Vault unlocked successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/view-passwords')
def view_passwords():
    try:
        results = vault.view_passwords()
        return jsonify({
            'success': True,
            'passwords': results,
            'is_honey_vault': vault.is_honey_vault
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/generate-password')
def generate_password():
    try:
        password = vault.generate_strong_password(16)
        return jsonify({'success': True, 'password': password})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)