#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Running integration tests..."

rm -f /tmp/passman_test_* && mkdir -p /tmp/passman_test
export HOME="/tmp/passman_test"

./build_all.sh
chmod +x scripts/pass.bash
./scripts/pass.bash help >/dev/null
./scripts/pass.bash list >/dev/null

# Create a fake password store and test export/import
mkdir -p "$HOME/.pass_manager"
cat > "$HOME/.pass_manager/passwords.txt" <<'EOF'
github:ZmFrZWNpcGhlcnRleHQ=
EOF
chmod 600 "$HOME/.pass_manager/passwords.txt"

./scripts/pass.bash export "$HOME/export.json" >/dev/null
[[ -f "$HOME/export.json" ]]

rm -f "$HOME/.pass_manager/passwords.txt"
./scripts/pass.bash import "$HOME/export.json" >/dev/null
[[ -f "$HOME/.pass_manager/passwords.txt" ]]

echo "Integration tests passed."
