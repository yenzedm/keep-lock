#!/usr/bin/env python3
from cryptography.fernet import Fernet
from sys import argv, exit
import pyperclip
import json
import os


KEY_FILE = "secret.key"

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

cipher = load_key()

DATA_FILE = "passwords.json"

def load_passwords():
    try:
        if not os.path.exists(DATA_FILE):
            return {}
        with open(DATA_FILE, "r") as f:
            encrypted_data = f.read()
            if not encrypted_data:
                return {}
            decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()
            return json.loads(decrypted_data)
    except:
        print("Try again")
        exit(1)
        

def save_passwords(passwords):
    encrypted_data = cipher.encrypt(json.dumps(passwords).encode())
    with open(DATA_FILE, "w") as f:
        f.write(encrypted_data.decode())

def add_password(service, password):
    passwords = load_passwords()
    passwords[service] = password
    save_passwords(passwords)
    print(f"Info: password for {service} saved.")

def get_password(service):
    passwords = load_passwords()
    if service in passwords:
        print(f"Info: password for {service}: {passwords[service]}")
    else:
        print("Err: service not found")

def delete_password(service):
    passwords = load_passwords()
    if service in passwords:
        del passwords[service]
        save_passwords(passwords)
        print(f"Info: password for {service} deleted")
    else:
        print("Err: service not found")

def get_password_clipboard(service):
    passwords = load_passwords()
    if service in passwords:
        pyperclip.copy(passwords[service])
        print(f"Info: password copied to the clipboard")
    else:
        print("Err: service not found")

def get_all_service():
    passwords = load_passwords()
    for service_name in passwords:
        print(service_name)

if __name__ == "__main__":
    func = argv[1] if len(argv) > 1 else None
    service = argv[2] if len(argv) > 2 else None
    password = argv[3] if len(argv) > 3 else None
    if func == "get":
        tmp = input("clipboard(cb) or output(out)? Enter cb or out: ")
        if tmp == "cb":
            get_password_clipboard(service)
        elif tmp == "out":
            get_password(service)
    elif func == "delete":
        delete_password(service)
    elif func == "add":
        add_password(service, password)
    elif func == "all":
        get_all_service()
    else:
        print("use ./kp.py add service pass - add service and password")
        print("use ./kp.py get service - get specified service")
        print("use ./kp.py all - view all services")
        print("use ./kp.py delete service - delete specified service")      
