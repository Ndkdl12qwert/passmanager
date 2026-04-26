#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

./build_all.sh

for backend in bin/module1 bin/module2 bin/module3 bin/module4 bin/module5; do
    if [[ -x "$backend" ]]; then
        echo "Testing $backend"
        derived=$("$backend" derive testpassword testsalt)
        if [[ -z "$derived" ]]; then
            echo "Backend $backend failed derive"
            exit 1
        fi
        cipher=$("$backend" encrypt hello "$derived")
        if [[ -z "$cipher" ]]; then
            echo "Backend $backend failed encrypt"
            exit 1
        fi
        plain=$("$backend" decrypt "$cipher" "$derived")
        if [[ "$plain" != "hello" ]]; then
            echo "Backend $backend returned wrong plaintext"
            exit 1
        fi
    fi
done

echo "Backend smoke tests passed."
