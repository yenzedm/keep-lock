#!/usr/bin/env python3

#or

#!usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "cryptography",
#     "pyperclip"
# ]
# ///


import os
import json
import base64
import argparse
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
from typing import Dict

# Constants
DATA_FILE = "passwords.enc"
DEFAULT_ITERATIONS = 600_000
SALT_SIZE = 16  # Salt size in bytes (128 бит)

class KeepLock:
    def __init__(self):
        pass

    def _get_cipher(self, password: str) -> Fernet:
        """Generates or loads salt and creates an encryption object"""
        # Read or create salt
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "rb") as f:
                salt = f.read(SALT_SIZE)
        else:
            salt = os.urandom(SALT_SIZE)
            with open(DATA_FILE, "wb") as f:
                f.write(salt)  # We write down only the salt, we will add the data later

        # Generating a key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=DEFAULT_ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def _load_data(self, cipher: Fernet) -> Dict[str, str]:
        """Loads and decrypts data"""
        try:
            with open(DATA_FILE, "rb") as f:
                f.read(SALT_SIZE)  # Skip the salt
                encrypted_data = f.read()
                
                if not encrypted_data:
                    return {}
                    
                return json.loads(cipher.decrypt(encrypted_data).decode())
        except Exception:
            print("Error: Invalid password or corrupted data")
            exit(1)

    def _save_data(self, cipher: Fernet, data: Dict[str, str]):
        """Encrypts and saves data (salt is already in the file)"""
        with open(DATA_FILE, "r+b") as f:
            f.seek(SALT_SIZE)  # Moving on after the salt
            encrypted_data = cipher.encrypt(json.dumps(data).encode())
            f.write(encrypted_data)
            f.truncate()  # cut off the excess if the new data is shorter than the old ones

    def add_password(self, service: str, password: str):
        """Adds a new password"""
        master_password = getpass("Enter master password: ")
        cipher = self._get_cipher(master_password)
        passwords = self._load_data(cipher)
        passwords[service] = password
        self._save_data(cipher, passwords)
        print(f"✓ Password for '{service}' saved")

    def get_password(self, service: str, to_clipboard: bool = False):
        """Gets the password"""
        master_password = getpass("Enter master password: ")
        cipher = self._get_cipher(master_password)
        passwords = self._load_data(cipher)
        
        if service not in passwords:
            print(f"✗ Service '{service}' not found")
            return
            
        if to_clipboard:
            pyperclip.copy(passwords[service])
            print("✓ The password has been copied to the clipboard")
        else:
            print(f"Password for '{service}': {passwords[service]}")

    def delete_password(self, service: str):
        """Removes the password"""
        master_password = getpass("Enter master password: ")
        cipher = self._get_cipher(master_password)
        passwords = self._load_data(cipher)
        
        if service not in passwords:
            print(f"✗ Service '{service}' not found")
            return
            
        del passwords[service]
        self._save_data(cipher, passwords)
        print(f"✓ Password for '{service}' deleted")

    def list_services(self):
        """Displays a list of all services"""
        master_password = getpass("Enter master password: ")
        cipher = self._get_cipher(master_password)
        passwords = self._load_data(cipher)
        
        if not passwords:
            print("✗ No saved passwords")
            return
            
        print("Saved services:")
        for service in sorted(passwords.keys()):
            print(f"• {service}")

def main():
    parser = argparse.ArgumentParser(
        description="🔐 Encrypted password manager",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Help for add a password
    add_parser = subparsers.add_parser("add", help="Add password")
    add_parser.add_argument("service", help="Service name (for example: github)")
    add_parser.add_argument("password", help="Password (if not specified, will be requested)", 
                          nargs="?", default=None)

    # Help for get password
    get_parser = subparsers.add_parser("get", help="Get password")
    get_parser.add_argument("service", help="Service name")
    get_parser.add_argument("-c", "--clipboard", action="store_true",
                          help="Copy to clipboard")

    # Help for delete password
    del_parser = subparsers.add_parser("delete", help="Remove password")
    del_parser.add_argument("service", help="Service name")

    # Help for list of services
    list_parser = subparsers.add_parser("list", help="Show all services")

    args = parser.parse_args()
    pm = KeepLock()

    try:
        if args.command == "add":
            password = args.password if args.password else getpass("Enter the password for the service: ")
            pm.add_password(args.service, password)
        elif args.command == "get":
            pm.get_password(args.service, args.clipboard)
        elif args.command == "delete":
            pm.delete_password(args.service)
        elif args.command == "list":
            pm.list_services()
    except KeyboardInterrupt:
        print("\nCanceled by user")
    except Exception as e:
        print(f"⚠️ Error: {str(e)}")

if __name__ == "__main__":
    main()