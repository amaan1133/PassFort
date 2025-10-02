from flask import Flask, render_template, request, jsonify
import sqlite3
import hashlib
import secrets
import base64
import re
import json
from urllib.parse import urlparse
from difflib import SequenceMatcher
from datetime import datetime
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
    
    # Phishing database
    c.execute('''CREATE TABLE IF NOT EXISTS phishing_urls
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT NOT NULL UNIQUE,
                  domain TEXT NOT NULL,
                  threat_type TEXT NOT NULL,
                  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Trusted domains/certificates
    c.execute('''CREATE TABLE IF NOT EXISTS trusted_domains
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  domain TEXT NOT NULL UNIQUE,
                  legitimate_url TEXT NOT NULL,
                  reputation_score INTEGER DEFAULT 100,
                  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

init_db()

class PhishingDetector:
    def __init__(self):
        self.db_name = 'passfort.db'
        self.common_phishing_patterns = [
            r'(paypal|amazon|google|microsoft|apple|bank|secure|login|verify|update|account)',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # IP addresses
            r'(bit\.ly|tinyurl|short|redirect)',
            r'(free|prize|winner|claim|urgent|suspended)'
        ]
        self.initialize_trusted_domains()
    
    def initialize_trusted_domains(self):
        """Initialize database with common trusted domains"""
        trusted = [
            ('google.com', 'https://google.com', 100),
            ('facebook.com', 'https://facebook.com', 100),
            ('amazon.com', 'https://amazon.com', 100),
            ('paypal.com', 'https://paypal.com', 100),
            ('microsoft.com', 'https://microsoft.com', 100),
            ('apple.com', 'https://apple.com', 100),
            ('github.com', 'https://github.com', 100),
            ('twitter.com', 'https://twitter.com', 100),
            ('linkedin.com', 'https://linkedin.com', 100),
            ('netflix.com', 'https://netflix.com', 100)
        ]
        
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        for domain, url, score in trusted:
            c.execute('''INSERT OR IGNORE INTO trusted_domains (domain, legitimate_url, reputation_score)
                        VALUES (?, ?, ?)''', (domain, url, score))
        conn.commit()
        conn.close()
    
    def extract_domain(self, url):
        """Extract domain from URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    
    def calculate_similarity(self, str1, str2):
        """Calculate similarity ratio between two strings"""
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
    
    def check_url_similarity(self, check_url):
        """Check if URL is similar to known legitimate domains"""
        check_domain = self.extract_domain(check_url)
        
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('SELECT domain, legitimate_url FROM trusted_domains')
        trusted_domains = c.fetchall()
        conn.close()
        
        similar_domains = []
        for trusted_domain, legitimate_url in trusted_domains:
            similarity = self.calculate_similarity(check_domain, trusted_domain)
            
            # Check for typosquatting (high similarity but not exact match)
            if 0.7 < similarity < 1.0:
                similar_domains.append({
                    'legitimate_domain': trusted_domain,
                    'legitimate_url': legitimate_url,
                    'similarity': round(similarity * 100, 2),
                    'warning': f'Possible typosquatting of {trusted_domain}'
                })
        
        return similar_domains
    
    def check_phishing_patterns(self, url):
        """Check URL against phishing patterns"""
        url_lower = url.lower()
        detected_patterns = []
        
        for pattern in self.common_phishing_patterns:
            if re.search(pattern, url_lower):
                detected_patterns.append(pattern)
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
        for tld in suspicious_tlds:
            if url_lower.endswith(tld):
                detected_patterns.append(f'Suspicious TLD: {tld}')
        
        return detected_patterns
    
    def check_phishing_database(self, url):
        """Check if URL is in local phishing database"""
        domain = self.extract_domain(url)
        
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('SELECT threat_type, added_at FROM phishing_urls WHERE url = ? OR domain = ?', 
                  (url, domain))
        result = c.fetchone()
        conn.close()
        
        if result:
            return {
                'is_phishing': True,
                'threat_type': result[0],
                'added_at': result[1]
            }
        return {'is_phishing': False}
    
    def calculate_domain_reputation(self, url):
        """Calculate domain reputation score (0-100)"""
        domain = self.extract_domain(url)
        score = 50  # Start with neutral score
        
        # Check if in trusted domains
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('SELECT reputation_score FROM trusted_domains WHERE domain = ?', (domain,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return result[0]
        
        # Scoring based on various factors
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        
        # HTTPS bonus
        if parsed.scheme == 'https':
            score += 20
        
        # Domain length penalty (very long domains are suspicious)
        if len(domain) > 30:
            score -= 15
        
        # Subdomain penalty
        subdomain_count = domain.count('.')
        if subdomain_count > 2:
            score -= 10 * (subdomain_count - 2)
        
        # Numbers in domain penalty
        if any(char.isdigit() for char in domain):
            score -= 10
        
        # Hyphens penalty (common in phishing)
        hyphen_count = domain.count('-')
        if hyphen_count > 1:
            score -= 5 * hyphen_count
        
        return max(0, min(100, score))
    
    def validate_certificate(self, url):
        """Simulate certificate validation (in real app, would check SSL cert)"""
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        
        # Basic checks
        checks = {
            'uses_https': parsed.scheme == 'https',
            'valid_certificate': parsed.scheme == 'https',  # Simplified
            'certificate_issuer': 'Let\'s Encrypt' if parsed.scheme == 'https' else None,
            'certificate_expiry': 'Valid' if parsed.scheme == 'https' else 'N/A'
        }
        
        return checks
    
    def analyze_url(self, url):
        """Comprehensive URL analysis"""
        # Check phishing database first
        phishing_check = self.check_phishing_database(url)
        
        # Calculate reputation
        reputation_score = self.calculate_domain_reputation(url)
        
        # Check similarity to legitimate domains
        similar_domains = self.check_url_similarity(url)
        
        # Check phishing patterns
        phishing_patterns = self.check_phishing_patterns(url)
        
        # Validate certificate
        cert_info = self.validate_certificate(url)
        
        # Determine threat level
        threat_level = 'safe'
        if phishing_check['is_phishing']:
            threat_level = 'critical'
        elif len(similar_domains) > 0 or len(phishing_patterns) > 2:
            threat_level = 'high'
        elif reputation_score < 30 or len(phishing_patterns) > 0:
            threat_level = 'medium'
        elif reputation_score < 60:
            threat_level = 'low'
        
        return {
            'url': url,
            'domain': self.extract_domain(url),
            'threat_level': threat_level,
            'reputation_score': reputation_score,
            'is_in_phishing_db': phishing_check['is_phishing'],
            'phishing_threat_type': phishing_check.get('threat_type'),
            'similar_to_legitimate': similar_domains,
            'suspicious_patterns': phishing_patterns,
            'certificate_validation': cert_info,
            'safe_to_autofill': threat_level == 'safe' and cert_info['uses_https']
        }
    
    def add_phishing_url(self, url, threat_type='phishing'):
        """Add URL to phishing database"""
        domain = self.extract_domain(url)
        
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('''INSERT OR IGNORE INTO phishing_urls (url, domain, threat_type)
                    VALUES (?, ?, ?)''', (url, domain, threat_type))
        conn.commit()
        conn.close()
    
    def get_phishing_database(self):
        """Get all phishing URLs"""
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()
        c.execute('SELECT id, url, domain, threat_type, added_at FROM phishing_urls ORDER BY added_at DESC')
        results = c.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'url': row[1],
                'domain': row[2],
                'threat_type': row[3],
                'added_at': row[4]
            }
            for row in results
        ]

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

# Initialize password manager and phishing detector
pm = PasswordManager()
phishing_detector = PhishingDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check-url', methods=['POST'])
def check_url():
    """Check URL for phishing"""
    try:
        data = request.json
        url = data.get('url')
        
        if not url:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        analysis = phishing_detector.analyze_url(url)
        
        return jsonify({
            'success': True,
            'analysis': analysis
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/add-phishing-url', methods=['POST'])
def add_phishing_url():
    """Add URL to phishing database"""
    try:
        data = request.json
        url = data.get('url')
        threat_type = data.get('threat_type', 'phishing')
        
        if not url:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        phishing_detector.add_phishing_url(url, threat_type)
        
        return jsonify({
            'success': True,
            'message': f'Added {url} to phishing database'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/phishing-database')
def get_phishing_database():
    """Get phishing database"""
    try:
        db = phishing_detector.get_phishing_database()
        return jsonify({'success': True, 'phishing_urls': db})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/delete-phishing-url/<int:url_id>', methods=['DELETE'])
def delete_phishing_url(url_id):
    """Delete phishing URL from database"""
    try:
        conn = sqlite3.connect('passfort.db')
        c = conn.cursor()
        c.execute('DELETE FROM phishing_urls WHERE id = ?', (url_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Phishing URL deleted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

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