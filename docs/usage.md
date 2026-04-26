# Usage

## Build

From the project root:

```bash
cd /home/onico/fr
./build_all.sh
chmod +x scripts/pass.bash
```

## Start the tool

```bash
./bin/passman help
```

You can also use the compatibility wrapper:

```bash
./bin/pass help
```

Or run the Bash CLI directly:

```bash
./scripts/pass.bash help
```

## Available commands

- `help`
- `list`
- `show <service>`
- `add <service>`
- `gen <service> [length]`
- `delete <service>`
- `export <file>`
- `import <file>`
- `backup`
- `backend`
- `menu`

## Examples

```bash
./bin/pass list
./bin/pass add github
./bin/pass gen github 20
./bin/pass show github
./bin/pass export backup.json
./bin/pass import backup.json
./bin/pass backup
```

## Force a backend

Use `BACKEND` to choose a specific backend executable:

```bash
BACKEND=bin/module3 ./bin/pass list
```

## Test the repository

```bash
make test
./tests/run_tests.sh
```
