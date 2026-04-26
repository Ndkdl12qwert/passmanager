# A project entirely completed by AI
# Passmanager

A secure password manager written in Go with a command-line interface.

[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/passman)](https://goreportcard.com/report/github.com/yourusername/passman)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Master password protection with PBKDF2
- AES-256-CTR encryption
- Secure password generation
- JSON export/import
- Automatic backups
- Cross-platform (Linux, macOS, Windows)

## Installation

### From source

```bash
git clone https://github.com/yourusername/passman.git
cd passman
./build_all.sh
```

### Using go install

```bash
go install github.com/yourusername/passman/cmd/passman@latest
```

## Usage

```bash
./bin/passman help
./bin/passman add github
./bin/passman show github
./bin/passman gen github 24
./bin/passman list
./bin/passman export passwords.json
./bin/passman import passwords.json
```

## Commands

- `help` - Show help
- `list` - List saved services
- `show <service>` - Display a password
- `add <service>` - Add or update a password
- `gen <service> [length]` - Generate and save a password
- `delete <service>` - Delete an entry
- `export <file>` - Export entries to JSON
- `import <file>` - Import entries from JSON
- `backup` - Create a backup archive
- `menu` - Interactive menu

## Security

Passwords are encrypted using AES-256-CTR with a key derived from your master password using PBKDF2 with 10,000 iterations. The master password is never stored.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

- `import <file>` - Import entries from JSON
- `backup` - Create a backup archive
- `menu` - Interactive menu

## Data storage

Passwords are stored encrypted in `~/.pass_manager/passwords.txt`.
Backups are created in `~/.pass_manager/backups/`.

## Legacy backends

Multi-language backend implementations are available in `backends/legacy/` for educational purposes.
