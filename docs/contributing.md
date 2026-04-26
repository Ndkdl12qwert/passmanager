# Contributing

Welcome to the multi-language password manager project.

## How to contribute

- Add new backend implementations in `src/`.
- Keep the backend command interface consistent with the existing modules.
- Add docs to `docs/` for new features or architecture changes.
- Add tests to `tests/` for new functionality.

## Recommended workflow

1. Clone the repository.
2. Run `./build_all.sh`.
3. Add or edit code.
4. Run `make test` and `./tests/run_tests.sh`.
5. Update `README.md`, `docs/usage.md`, or `docs/architecture.md` as needed.

## Backend contract

All backend executables should support these commands:

- `hash <password> <salt>`
- `derive <password> <salt>`
- `encrypt <plaintext> <key>`
- `decrypt <ciphertext> <key>`
- `generate <length>`
- `strength <password>`

## Patches

Use standard Git workflows. Please include meaningful commit messages and keep changes focused.
