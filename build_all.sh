#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

mkdir -p bin

echo "Building Go CLI passman..."
go build -o bin/passman ./cmd/passman

echo "Creating pass wrapper..."
cat > bin/pass <<'EOF2'
#!/usr/bin/env bash
cd "$(cd "$(dirname "$0")/.." && pwd)"
exec ./bin/passman "$@"
EOF2
chmod +x bin/pass

echo "Build complete. Use ./bin/passman for the CLI."
