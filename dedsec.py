#!/data/data/com.termux/files/usr/bin/python

import os
import subprocess
import tarfile
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Define the path to the internal storage and backup file
INTERNAL_STORAGE_PATH = '/data/data/com.termux/files/home/termux_backup'
BACKUP_FILE = os.path.join(INTERNAL_STORAGE_PATH, 'dedsec.tar.gz')

def ensure_internal_storage_path():
    if not os.path.exists(INTERNAL_STORAGE_PATH):
        os.makedirs(INTERNAL_STORAGE_PATH)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(os.urandom(12)), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = encryptor.update(data) + encryptor.finalize()
    with open(file_path, 'wb') as f:
        f.write(salt + cipher.nonce + encryptor.tag + encrypted_data)

def decrypt_file(file_path: str, password: str):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        nonce = f.read(12)
        tag = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    with open(file_path, 'wb') as f:
        f.write(decrypted_data)

def backup_termux(password: str):
    ensure_internal_storage_path()
    with tarfile.open(BACKUP_FILE, 'w:gz') as tar:
        tar.add('/data/data/com.termux/files', arcname='termux')
    encrypt_file(BACKUP_FILE, password)
    print(f"Backup completed: {BACKUP_FILE}")

def restore_termux(password: str):
    if os.path.exists(BACKUP_FILE):
        try:
            decrypt_file(BACKUP_FILE, password)
            with tarfile.open(BACKUP_FILE, 'r:gz') as tar:
                tar.extractall(path='/')
            print("Restore completed")
        except Exception as e:
            print("Failed to restore backup:", str(e))
    else:
        print("Backup file not found in the internal storage.")

def install_dependencies():
    # Install basic Termux packages
    subprocess.run(['pkg', 'install', '-y', 'python', 'git', 'curl', 'wget', 'openssl', 'tar', 'zip'], check=True)
    # Upgrade pip
    subprocess.run(['pip', 'install', '--upgrade', 'pip'], check=True)
    # Install cryptography library
    subprocess.run(['pip', 'install', 'cryptography'], check=True)
    # Setup storage access
    subprocess.run(['termux-setup-storage'], check=True)

def menu():
    while True:
        print("\nDedSec - Termux Backup & Restore")
        print("1) Backup Now")
        print("2) Restore Backup")
        print("3) Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            password = getpass.getpass("Enter an 8-digit password to encrypt the backup: ")
            if len(password) == 8 and password.isdigit():
                backup_termux(password)
            else:
                print("Invalid password. Please enter exactly 8 digits.")
        elif choice == '2':
            password = getpass.getpass("Enter the 8-digit password to decrypt the backup: ")
            if len(password) == 8 and password.isdigit():
                restore_termux(password)
            else:
                print("Invalid password. Please enter exactly 8 digits.")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    # Install dependencies if not already installed
    install_dependencies()
    # Run the menu
    menu()