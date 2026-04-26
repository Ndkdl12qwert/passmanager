#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Running shell syntax check..."
bash -n scripts/pass.bash

echo "Running Go tests..."
go test ./pkg/...

echo "Checking Go CLI..."
./bin/passman help >/dev/null

echo "Checking project docs..."
for doc in README.md docs/*.md; do
    [[ -f "$doc" ]] || { echo "Missing documentation file: $doc"; exit 1; }
done

echo "All tests passed."
