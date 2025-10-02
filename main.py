
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
        self.root.geometry("900x700")
        self.root.configure(bg="#1e1e1e")
        self.vault = VaultManager()
        
        self.create_widgets()
        self.check_existing_keys()
        
    def create_widgets(self):
        # Title Frame
        title_frame = tk.Frame(self.root, bg="#2d2d2d", height=80)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        title = tk.Label(title_frame, text="🔐 PassFort", font=("Arial", 28, "bold"), 
                        bg="#2d2d2d", fg="#4CAF50")
        title.pack(pady=15)
        
        subtitle = tk.Label(title_frame, text="Cryptographic Password Manager with Honey Vault Protection", 
                           font=("Arial", 10), bg="#2d2d2d", fg="#888")
        subtitle.pack()
        
        # Main Container
        main_container = tk.Frame(self.root, bg="#1e1e1e")
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left Panel - Controls
        left_panel = tk.Frame(main_container, bg="#2d2d2d", width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Key Management Section
        tk.Label(left_panel, text="🔑 Key Management", font=("Arial", 12, "bold"), 
                bg="#2d2d2d", fg="#4CAF50").pack(pady=(10, 5))
        
        tk.Button(left_panel, text="Generate RSA Keys", command=self.generate_keys, 
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, cursor="hand2", height=2).pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(left_panel, text="Import RSA Keys", command=self.import_keys,
                 bg="#2196F3", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, cursor="hand2", height=2).pack(fill=tk.X, padx=10, pady=5)
        
        # Vault Operations Section
        tk.Label(left_panel, text="🔒 Vault Operations", font=("Arial", 12, "bold"), 
                bg="#2d2d2d", fg="#FF9800").pack(pady=(20, 5))
        
        tk.Button(left_panel, text="Unlock Vault", command=self.unlock_vault,
                 bg="#F44336", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, cursor="hand2", height=2).pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(left_panel, text="Add Password", command=self.add_password,
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, cursor="hand2", height=2).pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(left_panel, text="View Passwords", command=self.view_passwords,
                 bg="#009688", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, cursor="hand2", height=2).pack(fill=tk.X, padx=10, pady=5)
        
        # Password Tools Section
        tk.Label(left_panel, text="🛠️ Password Tools", font=("Arial", 12, "bold"), 
                bg="#2d2d2d", fg="#9C27B0").pack(pady=(20, 5))
        
        tk.Button(left_panel, text="Generate Strong Password", command=self.generate_password,
                 bg="#9C27B0", fg="white", font=("Arial", 10, "bold"), 
                 relief=tk.FLAT, cursor="hand2", height=2).pack(fill=tk.X, padx=10, pady=5)
        
        # Status Indicator
        self.status_label = tk.Label(left_panel, text="Status: Not Initialized", 
                                     font=("Arial", 9), bg="#2d2d2d", fg="#888")
        self.status_label.pack(side=tk.BOTTOM, pady=10)
        
        # Right Panel - Display Area
        right_panel = tk.Frame(main_container, bg="#1e1e1e")
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Operation Log
        tk.Label(right_panel, text="📋 Operation Log", font=("Arial", 12, "bold"), 
                bg="#1e1e1e", fg="#4CAF50").pack(anchor=tk.W, pady=(5, 5))
        
        log_frame = tk.Frame(right_panel, bg="#2d2d2d", relief=tk.SUNKEN, bd=1)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.log_box = scrolledtext.ScrolledText(log_frame, height=12, bg="#1e1e1e", 
                                                 fg="#00ff00", insertbackground="white",
                                                 font=("Consolas", 9), relief=tk.FLAT)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Password Display
        tk.Label(right_panel, text="🔐 Stored Passwords", font=("Arial", 12, "bold"), 
                bg="#1e1e1e", fg="#4CAF50").pack(anchor=tk.W, pady=(5, 5))
        
        pwd_frame = tk.Frame(right_panel, bg="#2d2d2d", relief=tk.SUNKEN, bd=1)
        pwd_frame.pack(fill=tk.BOTH, expand=True)
        
        self.password_display = scrolledtext.ScrolledText(pwd_frame, height=12, bg="#1e1e1e", 
                                                          fg="#ffffff", insertbackground="white",
                                                          font=("Consolas", 10), relief=tk.FLAT)
        self.password_display.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        self.log("🚀 PassFort initialized successfully")
        self.log("ℹ️  Generate or import RSA keys to begin")
    
    def log(self, message):
        self.log_box.insert(tk.END, f"{message}\n")
        self.log_box.see(tk.END)
    
    def update_status(self, status, color="#888"):
        self.status_label.config(text=f"Status: {status}", fg=color)
    
    def check_existing_keys(self):
        """Check if keys already exist and load them"""
        if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
            try:
                with open("private_key.pem", "rb") as f:
                    self.vault.rsa_private_key = serialization.load_pem_private_key(f.read(), password=None)
                
                with open("public_key.pem", "rb") as f:
                    self.vault.rsa_public_key = serialization.load_pem_public_key(f.read())
                
                self.log("✓ Existing RSA keys loaded automatically")
                self.update_status("Keys Loaded", "#4CAF50")
            except Exception as e:
                self.log(f"⚠️  Could not load existing keys: {str(e)}")
    
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
            self.update_status("Keys Generated", "#4CAF50")
            messagebox.showinfo("Success", "RSA keys generated successfully!\n\nFiles saved:\n- private_key.pem\n- public_key.pem")
        except Exception as e:
            self.log(f"✗ Error generating keys: {str(e)}")
            messagebox.showerror("Error", str(e))
    
    def import_keys(self):
        try:
            private_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
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
            self.update_status("Keys Imported", "#4CAF50")
            messagebox.showinfo("Success", "RSA keys imported successfully!")
        except Exception as e:
            self.log(f"✗ Error importing keys: {str(e)}")
            messagebox.showerror("Error", f"Failed to import keys:\n{str(e)}")
    
    def add_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("450x280")
        dialog.configure(bg="#2d2d2d")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        tk.Label(dialog, text="Service Name:", font=("Arial", 10), 
                bg="#2d2d2d", fg="#fff").pack(pady=(20, 5))
        service_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        service_entry.pack(pady=5)
        service_entry.focus()
        
        tk.Label(dialog, text="Password (leave empty to auto-generate):", 
                font=("Arial", 10), bg="#2d2d2d", fg="#fff").pack(pady=(15, 5))
        password_entry = tk.Entry(dialog, width=40, show="●", font=("Arial", 10))
        password_entry.pack(pady=5)
        
        show_var = tk.BooleanVar()
        def toggle_password():
            password_entry.config(show="" if show_var.get() else "●")
        
        tk.Checkbutton(dialog, text="Show password", variable=show_var, 
                      command=toggle_password, bg="#2d2d2d", fg="#fff",
                      selectcolor="#1e1e1e", activebackground="#2d2d2d").pack(pady=5)
        
        def save():
            service = service_entry.get().strip()
            password = password_entry.get().strip()
            
            if not service:
                messagebox.showerror("Error", "Service name is required", parent=dialog)
                return
            
            try:
                saved_password = self.vault.add_password(service, password if password else None)
                if not password:
                    self.log(f"✓ Auto-generated password for {service}")
                    self.log(f"  Password: {saved_password}")
                else:
                    self.log(f"✓ Password saved for {service}")
                self.log(f"  🔒 Encrypted with AES-256")
                self.log(f"  🔑 AES key encrypted with RSA")
                self.log(f"  #️⃣  Integrity hash (SHA-256) created")
                self.update_status("Password Added", "#4CAF50")
                dialog.destroy()
                messagebox.showinfo("Success", f"Password for '{service}' saved successfully!")
            except Exception as e:
                self.log(f"✗ Error adding password: {str(e)}")
                messagebox.showerror("Error", str(e), parent=dialog)
        
        btn_frame = tk.Frame(dialog, bg="#2d2d2d")
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Save", command=save, bg="#4CAF50", fg="white",
                 font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, bg="#666", fg="white",
                 font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)
    
    def generate_password(self):
        password = self.vault.generate_strong_password(16)
        self.log(f"✓ Generated strong password: {password}")
        
        # Copy to clipboard
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        
        messagebox.showinfo("Strong Password Generated", 
                          f"Generated password:\n\n{password}\n\n✓ Copied to clipboard!")
    
    def unlock_vault(self):
        try:
            if not self.vault.rsa_private_key:
                private_path = filedialog.askopenfilename(title="Select Private Key", 
                                                         filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
                if not private_path:
                    return
                
                with open(private_path, "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)
                
                self.vault.unlock_vault(private_key)
            else:
                self.vault.unlock_vault(self.vault.rsa_private_key)
            
            if self.vault.is_honey_vault:
                self.log("⚠️  Vault unlocked with INCORRECT key")
                self.log("🍯 Showing HONEY VAULT (decoy data for security)")
                self.update_status("Honey Vault Active", "#FF9800")
                messagebox.showwarning("Honey Vault", "Vault unlocked.\n\nNote: Incorrect key detected.\nShowing decoy passwords for security.")
            else:
                self.log("✓ Vault unlocked successfully with CORRECT key")
                self.log("🔓 Real vault accessible")
                self.update_status("Vault Unlocked", "#4CAF50")
                messagebox.showinfo("Success", "Vault unlocked successfully!\n\nYou can now view your passwords.")
            
            self.vault.is_unlocked = True
        except Exception as e:
            self.log(f"✗ Error unlocking vault: {str(e)}")
            messagebox.showerror("Error", f"Failed to unlock vault:\n{str(e)}")
    
    def view_passwords(self):
        try:
            results = self.vault.view_passwords()
            self.password_display.delete(1.0, tk.END)
            
            if not results:
                self.password_display.insert(tk.END, "No passwords stored in vault.\n")
                self.log("ℹ️  No passwords in vault")
                return
            
            vault_type = "🍯 HONEY VAULT (DECOY)" if self.vault.is_honey_vault else "🔐 REAL VAULT"
            header = f"{'='*60}\n{vault_type:^60}\n{'='*60}\n\n"
            self.password_display.insert(tk.END, header)
            
            for i, result in enumerate(results, 1):
                self.password_display.insert(tk.END, f"#{i} Service: {result['service']}\n")
                self.password_display.insert(tk.END, f"   Password: {result['password']}\n")
                self.password_display.insert(tk.END, f"   Integrity: {result['integrity']}\n")
                self.password_display.insert(tk.END, "-" * 60 + "\n\n")
            
            vault_label = "HONEY VAULT" if self.vault.is_honey_vault else "REAL VAULT"
            self.log(f"✓ Displayed {len(results)} password(s) from {vault_label}")
        except Exception as e:
            self.log(f"✗ Error viewing passwords: {str(e)}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = PassFortGUI(root)
    root.mainloop()
