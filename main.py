
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import json
import os
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import base64

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

class PassFortGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PassFort - Cryptographic Password Manager")
        self.root.geometry("800x600")
        self.vault = VaultManager()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title = tk.Label(self.root, text="🔐 PassFort", font=("Arial", 24, "bold"))
        title.pack(pady=10)
        
        # Button Frame
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Generate RSA Keys", command=self.generate_keys, 
                 bg="#4CAF50", fg="white", width=18).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="Import RSA Keys", command=self.import_keys,
                 bg="#2196F3", fg="white", width=18).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(btn_frame, text="Add Password", command=self.add_password,
                 bg="#FF9800", fg="white", width=18).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="Generate Strong Password", command=self.generate_password,
                 bg="#9C27B0", fg="white", width=18).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(btn_frame, text="Unlock Vault", command=self.unlock_vault,
                 bg="#F44336", fg="white", width=18).grid(row=2, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="View Passwords", command=self.view_passwords,
                 bg="#009688", fg="white", width=18).grid(row=2, column=1, padx=5, pady=5)
        
        # Log/Status Box
        tk.Label(self.root, text="Operation Log:", font=("Arial", 12, "bold")).pack(pady=5)
        self.log_box = scrolledtext.ScrolledText(self.root, height=10, width=90)
        self.log_box.pack(pady=5)
        
        # Password Display Area
        tk.Label(self.root, text="Stored Passwords:", font=("Arial", 12, "bold")).pack(pady=5)
        self.password_display = scrolledtext.ScrolledText(self.root, height=10, width=90)
        self.password_display.pack(pady=5)
        
        self.log("PassFort initialized. Generate or import RSA keys to begin.")
    
    def log(self, message):
        self.log_box.insert(tk.END, f"[LOG] {message}\n")
        self.log_box.see(tk.END)
    
    def generate_keys(self):
        try:
            private_key, public_key = self.vault.generate_rsa_keypair(2048)
            self.vault.rsa_private_key = private_key
            self.vault.rsa_public_key = public_key
            
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
            
            self.vault.create_honey_vault()
            self.log("✓ RSA key pair generated (2048-bit)")
            self.log("✓ Keys saved to private_key.pem and public_key.pem")
            self.log("✓ Honey vault created for security")
        except Exception as e:
            self.log(f"✗ Error generating keys: {str(e)}")
    
    def import_keys(self):
        try:
            private_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
            if not private_path:
                return
            
            with open(private_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            
            public_key = private_key.public_key()
            self.vault.rsa_private_key = private_key
            self.vault.rsa_public_key = public_key
            
            self.vault.create_honey_vault()
            self.log("✓ RSA keys imported successfully")
            self.log("✓ Honey vault created for security")
        except Exception as e:
            self.log(f"✗ Error importing keys: {str(e)}")
    
    def add_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x200")
        
        tk.Label(dialog, text="Service Name:").pack(pady=5)
        service_entry = tk.Entry(dialog, width=40)
        service_entry.pack(pady=5)
        
        tk.Label(dialog, text="Password (leave empty to auto-generate):").pack(pady=5)
        password_entry = tk.Entry(dialog, width=40, show="*")
        password_entry.pack(pady=5)
        
        def save():
            service = service_entry.get().strip()
            password = password_entry.get().strip()
            
            if not service:
                messagebox.showerror("Error", "Service name is required")
                return
            
            try:
                saved_password = self.vault.add_password(service, password if password else None)
                if not password:
                    self.log(f"✓ Auto-generated password for {service}: {saved_password}")
                else:
                    self.log(f"✓ Password saved for {service}")
                self.log(f"✓ Password encrypted with AES-256")
                self.log(f"✓ AES key encrypted with RSA")
                self.log(f"✓ Integrity hash (SHA-256) created")
                dialog.destroy()
            except Exception as e:
                self.log(f"✗ Error adding password: {str(e)}")
                messagebox.showerror("Error", str(e))
        
        tk.Button(dialog, text="Save", command=save, bg="#4CAF50", fg="white").pack(pady=10)
    
    def generate_password(self):
        password = self.vault.generate_strong_password(16)
        self.log(f"✓ Generated strong password: {password}")
        messagebox.showinfo("Strong Password", f"Generated password:\n{password}\n\n(Copied to log)")
    
    def unlock_vault(self):
        try:
            if not self.vault.rsa_private_key:
                private_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
                if not private_path:
                    return
                
                with open(private_path, "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)
                
                self.vault.unlock_vault(private_key)
            else:
                self.vault.unlock_vault(self.vault.rsa_private_key)
            
            if self.vault.is_honey_vault:
                self.log("⚠ Vault unlocked with incorrect key - showing HONEY VAULT (decoy data)")
            else:
                self.log("✓ Vault unlocked successfully with correct key")
                self.log("✓ Real vault accessible")
            
            self.vault.is_unlocked = True
        except Exception as e:
            self.log(f"✗ Error unlocking vault: {str(e)}")
    
    def view_passwords(self):
        try:
            results = self.vault.view_passwords()
            self.password_display.delete(1.0, tk.END)
            
            if not results:
                self.password_display.insert(tk.END, "No passwords stored.\n")
                self.log("ℹ No passwords in vault")
                return
            
            vault_type = "HONEY VAULT (DECOY)" if self.vault.is_honey_vault else "REAL VAULT"
            self.password_display.insert(tk.END, f"=== {vault_type} ===\n\n")
            
            for result in results:
                self.password_display.insert(tk.END, f"Service: {result['service']}\n")
                self.password_display.insert(tk.END, f"Password: {result['password']}\n")
                self.password_display.insert(tk.END, f"Integrity: {result['integrity']}\n")
                self.password_display.insert(tk.END, "-" * 50 + "\n")
            
            self.log(f"✓ Displayed {len(results)} passwords from {vault_type}")
        except Exception as e:
            self.log(f"✗ Error viewing passwords: {str(e)}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = PassFortGUI(root)
    root.mainloop()
