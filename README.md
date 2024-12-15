🔒 SecPass

Secure your digital world with Password Manager – a simple yet powerful tool designed to safely store, encrypt, and manage your passwords using AES-256 encryption. Say goodbye to password chaos and hello to streamlined security!


🚀 Features

End-to-End Security: Protect your passwords with robust AES-256 encryption.

User-Friendly Interface: Intuitive and easy-to-use GUI built with Tkinter.

Master Password: One master password to rule them all!

Password Strength Checker: Get insights into the strength of your passwords.

Import/Export Database: Backup and restore your encrypted password database effortlessly.



🛠️ Technologies Used

Programming Language: Python

Encryption: Cryptography library (AES-256, PBKDF2-HMAC)

Database: SQLite for secure local storage

GUI: Tkinter for a seamless user experience

Packaging: PyInstaller for creating an executable



📖 How It Works

1. Set a Master Password: Start by setting a strong master password. This password is used to derive the encryption key.


2. Add Passwords: Save service credentials (e.g., email, bank accounts) securely.


3. Encrypt & Decrypt: Passwords are encrypted on save and decrypted only when you need them.


4. View Saved Passwords: Access your stored passwords with a single click.


5. Export/Import Database: Safeguard your data by exporting or importing the database securely.



📦 Installation

Prerequisites:

Python 3.10+

Required libraries (install via pip):

pip install cryptography tkinter


Steps to Run:

1. Clone the repository:

git clone https://github.com/Patil-Nitish/SecPass.git
cd Password-Manager


2. Run the script:

python main.py


3. (Optional) Create an executable:

pyinstaller --noconfirm --onefile --windowed main.py



🔐 Security Practices

Local Storage Only: Your passwords never leave your device.

Strong Encryption: Industry-standard AES-256 ensures top-notch protection.

Master Password: Encrypts all your data; without it, the data remains inaccessible.



🌟 Why Use This Password Manager?

Open Source: Fully customizable and transparent code.

Lightweight: Minimal resource usage without sacrificing security.

Offline: No internet connection required, ensuring complete control.



🛡️ Disclaimer

This tool is designed for personal use. Use it responsibly, and always keep your master password secure.


🤝 Contributing

Contributions are welcome! Feel free to fork the repository, raise issues, or submit pull requests.

🌐 Connect

📫 Email: nitishp2030@gmail.com
💼 LinkedIn: Nitish Patil
