import os
import base64
import sqlite3
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


class PasswordManager:
    def __init__(self):
        self.salt = os.urandom(16)  # Random salt for key derivation
        self.key = None  # AES encryption key
        self.init_db()  # Initialize database
        self.init_ui()  # Initialize user interface

    def derive_key(self, master_password: str):
        """Derives a 32-byte AES encryption key from the master password."""
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000
        )
        self.key = kdf.derive(master_password.encode())  # Key must be bytes

    def encrypt_password(self, plaintext: str) -> str:
        """Encrypts a plaintext password using AES-CBC."""
        if not self.key:
            raise ValueError("Encryption key not set. Set the master password first.")

        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Pad plaintext to match AES block size
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()  # Return as a base64-encoded string

    def decrypt_password(self, ciphertext: str) -> str:
        """Decrypts an AES-CBC encrypted password."""
        if not self.key:
            raise ValueError("Decryption key not set. Set the master password first.")

        data = base64.b64decode(ciphertext)
        iv, ciphertext = data[:16], data[16:]  # Extract IV and ciphertext

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def init_db(self):
        """Initializes the SQLite database to store passwords."""
        conn = sqlite3.connect("passwords.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )''')
        conn.commit()
        conn.close()

    def save_password(self, service: str, username: str, password: str):
        """Saves an encrypted password to the database."""
        conn = sqlite3.connect("passwords.db")
        c = conn.cursor()
        c.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)",
                  (service, username, password))
        conn.commit()
        conn.close()

    def retrieve_passwords(self):
        """Retrieves all saved passwords from the database."""
        conn = sqlite3.connect("passwords.db")
        c = conn.cursor()
        c.execute("SELECT service, username, password FROM passwords")
        rows = c.fetchall()
        conn.close()
        return rows

    def export_database(self):
        """Exports the database to a user-specified location."""
        file_path = filedialog.asksaveasfilename(defaultextension=".db",
                                                 filetypes=[("SQLite Database", "*.db")])
        if file_path:
            try:
                with open("passwords.db", "rb") as src, open(file_path, "wb") as dst:
                    dst.write(src.read())
                messagebox.showinfo("Export", "Database exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export database: {e}")

    def import_database(self):
        """Imports a database from a user-specified location."""
        file_path = filedialog.askopenfilename(filetypes=[("SQLite Database", "*.db")])
        if file_path:
            try:
                with open(file_path, "rb") as src, open("passwords.db", "wb") as dst:
                    dst.write(src.read())
                messagebox.showinfo("Import", "Database imported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import database: {e}")

    def add_password(self):
        """Handles adding a new password."""
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not self.key:
            messagebox.showwarning("Error", "Set the master password first!")
            return

        if not service or not username or not password:
            messagebox.showwarning("Error", "All fields are required!")
            return

        encrypted_password = self.encrypt_password(password)
        self.save_password(service, username, encrypted_password)
        messagebox.showinfo("Success", "Password saved!")

    def view_passwords(self):
        """Displays all saved passwords."""
        if not self.key:
            messagebox.showwarning("Error", "Set the master password first!")
            return

        passwords = self.retrieve_passwords()
        if not passwords:
            messagebox.showinfo("Stored Passwords", "No passwords saved.")
            return

        result = ""
        for service, username, encrypted_password in passwords:
            try:
                decrypted_password = self.decrypt_password(encrypted_password).decode()
                result += f"Service: {service}, Username: {username}, Password: {decrypted_password}\n"
            except Exception as e:
                result += f"Service: {service}, Username: {username}, Password: [Error decrypting: {e}]\n"

        messagebox.showinfo("Stored Passwords", result)

    def init_ui(self):
        """Initializes the tkinter GUI."""
        root = tk.Tk()
        root.title("Password Manager")

        tk.Label(root, text="Master Password:").grid(row=0, column=0, sticky="e")
        self.master_password_entry = tk.Entry(root, show="*")
        self.master_password_entry.grid(row=0, column=1)
        tk.Button(root, text="Set Master Password", command=self.set_master_password).grid(row=0, column=2)

        tk.Label(root, text="Service:").grid(row=1, column=0, sticky="e")
        self.service_entry = tk.Entry(root)
        self.service_entry.grid(row=1, column=1)

        tk.Label(root, text="Username:").grid(row=2, column=0, sticky="e")
        self.username_entry = tk.Entry(root)
        self.username_entry.grid(row=2, column=1)

        tk.Label(root, text="Password:").grid(row=3, column=0, sticky="e")
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.grid(row=3, column=1)

        tk.Button(root, text="Add Password", command=self.add_password).grid(row=4, column=0, columnspan=2)
        tk.Button(root, text="View Passwords", command=self.view_passwords).grid(row=4, column=2)
        tk.Button(root, text="Export Database", command=self.export_database).grid(row=5, column=0, columnspan=2)
        tk.Button(root, text="Import Database", command=self.import_database).grid(row=5, column=2)

        root.mainloop()

    def set_master_password(self):
        """Handles setting the master password."""
        master_password = self.master_password_entry.get()
        if master_password:
            self.derive_key(master_password)
            messagebox.showinfo("Success", "Master password set!")
        else:
            messagebox.showwarning("Error", "Master password cannot be empty!")


if __name__ == "__main__":
    PasswordManager()
