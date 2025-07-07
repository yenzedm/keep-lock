# 🔒 Secure Password Manager

A secure command-line password manager that encrypts data using AES-256 (Fernet) with PBKDF2 key derivation. All passwords are protected by a master password and never stored in plaintext.

## Features

- 🔐 Military-grade encryption (AES-256)
- 🛡 Master password protection
- 📋 Copy to clipboard functionality
- 📁 Single encrypted vault file

## Installation

1. Ensure you have Python 3.8+ installed
2. Install required packages:

```bash
pip install cryptography pyperclip
