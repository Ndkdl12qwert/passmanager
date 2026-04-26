# Architecture

This project demonstrates a multi-language password manager built as a single platform with a shared Bash UI and backend implementations in several languages.

## Layers

- `scripts/pass.bash`
  - Primary command-line interface and user interaction layer.
  - Handles master password setup, password file management, backups, export/import and backend selection.

- `bin/module1`, `bin/module2`, `bin/module3`, `bin/module4`
  - Backend executables for C++, Go, Node.js, and Python.
  - Each backend implements the same cryptographic contract:
    - `hash <password> <salt>`
    - `derive <password> <salt>`
    - `encrypt <plaintext> <key>`
    - `decrypt <ciphertext> <key>`
    - `generate <length>`
    - `strength <password>`

- `bin/pass`
  - Convenience wrapper for launching the Bash tool from the project root.

## Crypto flow

1. User enters the master password.
2. The selected backend uses PBKDF2 with a stored salt to derive a master hash and encryption key.
3. Password entries are encrypted with AES-256-CBC and stored as base64 payloads.
4. The Bash layer keeps only encrypted data on disk and never stores plaintext passwords.

## Backend selection

- `scripts/pass.bash` automatically selects the first available backend from:
  - `bin/module2`
  - `bin/module3`
  - `bin/module4`
  - `bin/module1`
- `BACKEND` environment variable can override the selected backend path.

## Data storage

- Password records are stored in `~/.pass_manager/passwords.txt`.
- A separate salt file and master hash file keep master authentication state.
- Backups are stored in `~/.pass_manager/backups/` as compressed archives.
