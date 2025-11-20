#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "cryptography>=43.0.0",
#   "pyperclip"
# ]
# ///

import argparse
import json
import os
import threading
from getpass import getpass
from pathlib import Path
from typing import Dict

import pyperclip
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

DATA_FILE = Path("passwords.enc")
SALT_SIZE = 16
ITERATIONS = 800_000
CLIPBOARD_TIMEOUT = 20


class AuthenticationError(Exception):
    pass


class KeepLock:
    def __init__(self):
        self._clipboard_cleared = threading.Event()
        self._timer: threading.Timer | None = None

    def _clear_clipboard(self):
        if not self._clipboard_cleared.is_set():
            pyperclip.copy("")
            self._clipboard_cleared.set()

    def _start_clear_timer(self):
        self._timer = threading.Timer(CLIPBOARD_TIMEOUT, self._clear_clipboard)
        self._timer.start()

    def _cancel_timer(self):
        if self._timer and self._timer.is_alive():
            self._timer.cancel()
        self._timer = None

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def _get_cipher_from_password(self, password: str):
        if not DATA_FILE.exists():
            raise FileNotFoundError("No database found")
        raw = DATA_FILE.read_bytes()
        if len(raw) < SALT_SIZE:
            raise ValueError("Database corrupted")
        salt = raw[:SALT_SIZE]
        return Fernet(self._derive_key(password, salt))

    def _load_data(self, cipher: Fernet) -> Dict[str, str]:
        raw = DATA_FILE.read_bytes()[SALT_SIZE:]
        if not raw:
            return {}
        try:
            return json.loads(cipher.decrypt(raw).decode())
        except InvalidToken:
            raise AuthenticationError("Wrong master password.")

    def _save_data(self, data: Dict[str, str], password: str, new_salt: bytes | None = None):
        salt = new_salt or os.urandom(SALT_SIZE)
        cipher = Fernet(self._derive_key(password, salt))
        encrypted = cipher.encrypt(json.dumps(data, ensure_ascii=False, indent=2).encode())
        tmp = DATA_FILE.with_suffix(".tmp")
        try:
            tmp.write_bytes(salt + encrypted)
            tmp.replace(DATA_FILE)
            DATA_FILE.chmod(0o600)
        finally:
            tmp.unlink(missing_ok=True)

    def add(self, service: str):
        pwd = getpass("Service password (empty = generate 32 chars): ").strip()
        if not pwd:
            import secrets, string
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+="
            pwd = ''.join(secrets.choice(alphabet) for _ in range(32))
            print("Generated strong password")

        master = getpass("Master password: ")

        # Try to load existing data — will fail cleanly if wrong password
        current: Dict[str, str] = {}
        if DATA_FILE.exists():
            try:
                cipher = self._get_cipher_from_password(master)
                current = self._load_data(cipher)
            except AuthenticationError:
                print("Error: Wrong master password.")
                return
            except Exception:
                print("Error: Cannot read database (corrupted or wrong password).")
                return

        current[service.lower()] = pwd
        self._save_data(current, master)
        print(f"Password for '{service}' saved")

    def get(self, service: str):
        self._clipboard_cleared.clear()
        self._cancel_timer()

        try:
            master = getpass("Master password: ")
            cipher = self._get_cipher_from_password(master)
            data = self._load_data(cipher)

            svc = service.lower()
            if svc not in data:
                print(f"Service '{service}' not found")
                return

            pyperclip.copy(data[svc])
            print(f"Password for '{service}' copied to clipboard")
            print(f"Will auto-clear in {CLIPBOARD_TIMEOUT} seconds (press Enter or Ctrl+C)")

            self._start_clear_timer()

            try:
                input("Press Enter to clear now, or wait... ")
                self._clear_clipboard()
            except KeyboardInterrupt:
                print("\nCancelled")
                self._clear_clipboard()

        except AuthenticationError:
            print("Error: Wrong master password.")
            self._clear_clipboard()
        except FileNotFoundError:
            print("Error: No database found. Use 'add' first.")
        except Exception as e:
            print(f"Error: {e}")
            self._clear_clipboard()
        finally:
            self._cancel_timer()

    def delete(self, service: str):
        master = getpass("Master password: ")
        try:
            cipher = self._get_cipher_from_password(master)
            data = self._load_data(cipher)
            svc = service.lower()
            if svc not in data:
                print(f"Service '{service}' not found")
                return
            del data[svc]
            self._save_data(data, master)
            print(f"Password for '{service}' deleted")
        except AuthenticationError:
            print("Error: Wrong master password.")
        except FileNotFoundError:
            print("Error: No database found.")
        except Exception as e:
            print(f"Error: {e}")

    def list(self):
        master = getpass("Master password: ")
        try:
            cipher = self._get_cipher_from_password(master)
            data = self._load_data(cipher)
            if not data:
                print("No passwords stored")
                return
            print("Stored services:")
            for s in sorted(data.keys()):
                print(f"  • {s}")
        except AuthenticationError:
            print("Error: Wrong master password.")
        except FileNotFoundError:
            print("Error: No database found.")
        except Exception as e:
            print(f"Error: {e}")

    def change_password(self):
        if not DATA_FILE.exists():
            print("Error: No database found.")
            return

        old = getpass("Current master password: ")
        try:
            cipher = self._get_cipher_from_password(old)
            data = self._load_data(cipher)
        except AuthenticationError:
            print("Error: Wrong current master password.")
            return
        except Exception as e:
            print(f"Error: {e}")
            return

        new1 = getpass("New master password: ")
        new2 = getpass("Confirm new master password: ")
        if new1 != new2:
            print("Error: Passwords do not match")
            return
        if not new1:
            print("Error: Master password cannot be empty")
            return

        self._save_data(data, new1, new_salt=os.urandom(SALT_SIZE))
        print("Master password changed successfully")


def main():
    parser = argparse.ArgumentParser(description="KeepLock — ultra-secure password manager")
    sub = parser.add_subparsers(dest="cmd", required=True)

    add = sub.add_parser("add", help="Add a password")
    add.add_argument("service")

    get = sub.add_parser("get", help="Copy password to clipboard (never shown)")
    get.add_argument("service")

    delete = sub.add_parser("delete", help="Delete a password")
    delete.add_argument("service")

    sub.add_parser("list", help="List services")
    sub.add_parser("change-password", help="Change master password")

    args = parser.parse_args()
    kl = KeepLock()

    try:
        {
            "add": lambda: kl.add(args.service),
            "get": lambda: kl.get(args.service),
            "delete": lambda: kl.delete(args.service),
            "list": kl.list,
            "change-password": kl.change_password,
        }[args.cmd]()
    except KeyboardInterrupt:
        print("\nCancelled")


if __name__ == "__main__":
    main()
