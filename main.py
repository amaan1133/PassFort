from flask import Flask, render_template, request, jsonify
import sqlite3
import hashlib
import secrets
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Database initialization
def init_db():
    conn = sqlite3.connect('passfort.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  service TEXT NOT NULL,
                  password_hash TEXT NOT NULL,
                  encrypted_password TEXT NOT NULL,
                  encrypted_aes_key TEXT NOT NULL,
                  rsa_key_name TEXT NOT NULL,
                  private_key_pem TEXT NOT NULL,
                  public_key_pem TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

class PasswordManager:
    def __init__(self):
        self.db_name = 'passfort.db'

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

    def hash_password(self, password):
        """Hash password with SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

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

    def generate_strong_password(self, length=16):
        """Generate a strong random password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password

    def save_password(self, service, password):
        """Save password with unique RSA key"""
        # Generate unique RSA key pair for this password
        private_key, public_key = self.generate_rsa_keypair(2048)

        # Generate AES key for password encryption
        aes_key = self.generate_aes_key()

        # Hash the password
        password_hash = self.hash_password(password)

        # Encrypt password with AES
        encrypted_password = self.encrypt_password(password, aes_key)

        # Encrypt AES key with RSA
        encrypted_aes_key = self.encrypt_aes_key_rsa(aes_key, public_key)

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # RSA key name format: "Password for [service]"
        rsa_key_name = f"Password for {service}"

        # Save to database
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('''INSERT INTO passwords 
                     (service, password_hash, encrypted_password, encrypted_aes_key, 
                      rsa_key_name, private_key_pem, public_key_pem)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (service, password_hash, encrypted_password, encrypted_aes_key,
                   rsa_key_name, private_pem, public_pem))
        conn.commit()
        conn.close()

        return {
            'rsa_key_name': rsa_key_name,
            'private_key': private_pem,
            'public_key': public_pem
        }

    def get_all_services(self):
        """Get list of all services with their RSA key names, keys, and hashes"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('''SELECT id, service, rsa_key_name, created_at, 
                     private_key_pem, public_key_pem, password_hash 
                     FROM passwords ORDER BY created_at DESC''')
        results = c.fetchall()
        conn.close()

        services = []
        for row in results:
            services.append({
                'id': row[0],
                'service': row[1],
                'rsa_key_name': row[2],
                'created_at': row[3],
                'private_key': row[4],
                'public_key': row[5],
                'password_hash': row[6]
            })
        return services

    def unlock_password(self, password_id, private_key_pem):
        """Unlock specific password with its RSA private key"""
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )

            # Get password from database
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute('''SELECT service, password_hash, encrypted_password, encrypted_aes_key 
                        FROM passwords WHERE id = ?''', (password_id,))
            result = c.fetchone()
            conn.close()

            if not result:
                raise Exception("Password not found")

            service, password_hash, encrypted_password, encrypted_aes_key = result

            # Decrypt AES key with RSA private key
            aes_key = self.decrypt_aes_key_rsa(encrypted_aes_key, private_key)

            # Decrypt password with AES key
            password = self.decrypt_password(encrypted_password, aes_key)

            # Verify hash
            if self.hash_password(password) != password_hash:
                raise Exception("Password integrity check failed")

            return {
                'service': service,
                'password': password,
                'hash': password_hash
            }
        except Exception as e:
            raise Exception(f"Failed to unlock password: {str(e)}")

    def delete_password(self, password_id):
        """Delete a password entry"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        conn.commit()
        conn.close()

# Initialize password manager
pm = PasswordManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/services')
def get_services():
    """Get all saved services"""
    try:
        services = pm.get_all_services()
        return jsonify({'success': True, 'services': services})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/save-password', methods=['POST'])
def save_password():
    """Save new password"""
    try:
        data = request.json
        service = data.get('service')
        password = data.get('password')

        if not service:
            return jsonify({'success': False, 'error': 'Service name is required'}), 400

        if not password:
            password = pm.generate_strong_password()

        result = pm.save_password(service, password)

        return jsonify({
            'success': True,
            'message': f'Password saved for {service}',
            'generated_password': password if not data.get('password') else None,
            'rsa_key_name': result['rsa_key_name'],
            'private_key': result['private_key'],
            'public_key': result['public_key']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/unlock-password', methods=['POST'])
def unlock_password():
    """Unlock specific password with RSA key"""
    try:
        data = request.json
        password_id = data.get('password_id')
        private_key = data.get('private_key')

        if not password_id or not private_key:
            return jsonify({'success': False, 'error': 'Password ID and private key are required'}), 400

        result = pm.unlock_password(password_id, private_key)

        return jsonify({
            'success': True,
            'service': result['service'],
            'password': result['password'],
            'hash': result['hash']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/delete-password/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    """Delete a password entry"""
    try:
        pm.delete_password(password_id)
        return jsonify({'success': True, 'message': 'Password deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/generate-password')
def generate_password():
    """Generate strong password"""
    try:
        password = pm.generate_strong_password(16)
        return jsonify({'success': True, 'password': password})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)