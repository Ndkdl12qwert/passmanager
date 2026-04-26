# Backend Matrix

| Backend | Language | Runtime | Crypto | Notes |
|---|---|---|---|---|
| `bin/module1` | C++ | g++ / OpenSSL | PBKDF2 + AES-256-CBC | Native OpenSSL implementation.
| `bin/module2` | Go | go | PBKDF2 + AES-256-CBC | Standard library crypto.
| `bin/module3` | Node.js | node | PBKDF2 + AES-256-CBC | Built-in `crypto` support.
| `bin/module4` | Python | python3 + openssl | PBKDF2 + AES-256-CBC | Uses `hashlib` and OpenSSL subprocess for AES.
| `bin/module5` | x86_64 ASM + C | gcc / OpenSSL | PBKDF2 + XOR stream cipher | Demo backend with assembly encryption core.

## Notes

- The Bash CLI is intentionally backend-agnostic.
- Each backend exposes the same command interface so the tool can switch languages transparently.
- New backend implementations can be added by providing a compatible executable in `bin/` and updating the selection order.
