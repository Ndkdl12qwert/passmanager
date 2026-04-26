#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import os
import subprocess
import sys

CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{};:,.<>/?\\|"


def pbkdf2_hash(password: str, salt: str, iterations: int = 10000) -> str:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations, dklen=32)
    return key.hex()


def pbkdf2_derive(password: str, salt: str, iterations: int = 10000) -> str:
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations, dklen=32)
    return base64.b64encode(key).decode()


def encrypt(plaintext: str, key_b64: str) -> str:
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError('invalid key length')
    iv = os.urandom(16)
    proc = subprocess.run([
        'openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-e', '-K', key.hex(), '-iv', iv.hex()
    ], input=plaintext.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode().strip())
    return base64.b64encode(iv + proc.stdout).decode()


def decrypt(ciphertext_b64: str, key_b64: str) -> str:
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError('invalid key length')
    payload = base64.b64decode(ciphertext_b64)
    if len(payload) < 16:
        raise ValueError('invalid ciphertext')
    iv = payload[:16]
    ciphertext = payload[16:]
    proc = subprocess.run([
        'openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-d', '-K', key.hex(), '-iv', iv.hex()
    ], input=ciphertext, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode().strip())
    return proc.stdout.decode('utf-8', errors='ignore')


def generate(length: int = 12) -> str:
    if length <= 0:
        length = 12
    data = os.urandom(length)
    return ''.join(CHARSET[b % len(CHARSET)] for b in data)


def strength(password: str) -> int:
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    return score


def main():
    parser = argparse.ArgumentParser(description='Module4 Python crypto backend')
    parser.add_argument('command', help='command to run')
    parser.add_argument('arg1', nargs='?', help='first argument')
    parser.add_argument('arg2', nargs='?', help='second argument')
    args = parser.parse_args()

    try:
        if args.command == 'hash' and args.arg1 and args.arg2:
            print(pbkdf2_hash(args.arg1, args.arg2))
        elif args.command == 'derive' and args.arg1 and args.arg2:
            print(pbkdf2_derive(args.arg1, args.arg2))
        elif args.command == 'encrypt' and args.arg1 and args.arg2:
            print(encrypt(args.arg1, args.arg2))
        elif args.command == 'decrypt' and args.arg1 and args.arg2:
            print(decrypt(args.arg1, args.arg2))
        elif args.command == 'generate':
            length = int(args.arg1) if args.arg1 and args.arg1.isdigit() else 12
            print(generate(length))
        elif args.command == 'strength' and args.arg1:
            print(strength(args.arg1))
        else:
            parser.print_help()
            sys.exit(1)
    except Exception as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
