#!/bin/bash
set -o pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
YELLOW='\033[0;33m'

PASS_DIR="${HOME}/.pass_manager"
PASS_FILE="${PASS_DIR}/passwords.txt"
SALT_FILE="${PASS_DIR}/salt"
MASTER_FILE="${PASS_DIR}/master"
BACKUP_DIR="${PASS_DIR}/backups"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_PATH="${BACKEND:-${SCRIPT_DIR}/../bin/module2}"

if [[ ! -x "$MODULE_PATH" ]]; then
    for candidate in module2 module3 module4 module1; do
        if [[ -x "${SCRIPT_DIR}/../bin/$candidate" ]]; then
            MODULE_PATH="${SCRIPT_DIR}/../bin/$candidate"
            break
        fi
    done
fi

if [[ ! -x "$MODULE_PATH" ]]; then
    echo -e "${RED}Error: no backend found in ${SCRIPT_DIR}/../bin. Run ./build_all.sh first.${NC}"
    exit 1
fi

mkdir -p "$PASS_DIR" "$BACKUP_DIR"
chmod 700 "$PASS_DIR" "$BACKUP_DIR"

if [[ ! -f "$SALT_FILE" ]]; then
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 > "$SALT_FILE"
    elif [[ -r /dev/urandom ]]; then
        head -c 32 /dev/urandom | openssl base64 -e > "$SALT_FILE"
    else
        echo "$(date +%s%N)$RANDOM$RANDOM" | sha256sum | awk '{print $1}' > "$SALT_FILE"
    fi
    chmod 600 "$SALT_FILE"
fi
SALT=$(cat "$SALT_FILE")

pbkdf2_hash() {
    "$MODULE_PATH" hash "$1" "$2" 2>/dev/null
}

derive_key() {
    "$MODULE_PATH" derive "$1" "$2" 2>/dev/null
}

encrypt_password() {
    "$MODULE_PATH" encrypt "$1" "$2" 2>/dev/null
}

decrypt_password() {
    "$MODULE_PATH" decrypt "$1" "$2" 2>/dev/null
}

declare -A passwords
load_passwords() {
    passwords=()
    [[ -f "$PASS_FILE" ]] || return 0
    while IFS=':' read -r svc enc; do
        [[ -z "$svc" ]] && continue
        passwords["$svc"]="$enc"
    done < "$PASS_FILE"
}

save_passwords() {
    : > "$PASS_FILE"
    for svc in "${!passwords[@]}"; do
        echo "$svc:${passwords[$svc]}" >> "$PASS_FILE"
    done
    chmod 600 "$PASS_FILE"
}

backup_all() {
    local bf="${BACKUP_DIR}/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$bf" -C "$PASS_DIR" . 2>/dev/null && chmod 600 "$bf" && echo -e "${GREEN}Backup: $bf${NC}"
}

export_passwords() {
    local dest="$1"
    if [[ -z "$dest" ]]; then
        echo -e "${RED}Usage: $0 export <path>${NC}"
        return 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}Python3 required for export${NC}"
        return 1
    fi
    python3 - "${PASS_FILE}" "$dest" <<'PY'
import json, sys
source = sys.argv[1]
dest = sys.argv[2]
entries = []
with open(source, 'r', encoding='utf-8') as f:
    for line in f:
        line=line.strip()
        if not line or ':' not in line:
            continue
        svc, enc = line.split(':', 1)
        entries.append({'service': svc, 'encrypted': enc})
with open(dest, 'w', encoding='utf-8') as f:
    json.dump({'entries': entries}, f, indent=2)
print(dest)
PY
}

import_passwords() {
    local source="$1"
    if [[ -z "$source" ]]; then
        echo -e "${RED}Usage: $0 import <path>${NC}"
        return 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}Python3 required for import${NC}"
        return 1
    fi
    if [[ ! -f "$source" ]]; then
        echo -e "${RED}Import file not found: $source${NC}"
        return 1
    fi
    local result
    result=$(python3 - "${source}" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    data = json.load(f)
entries = data.get('entries', [])
for entry in entries:
    svc = entry.get('service')
    enc = entry.get('encrypted')
    if svc and enc:
        print(f"{svc}:{enc}")
PY
)
    if [[ -z "$result" ]]; then
        echo -e "${RED}No valid entries in import file${NC}"
        return 1
    fi
    load_passwords
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        svc=${line%%:*}
        enc=${line#*:}
        passwords["$svc"]="$enc"
    done <<< "$result"
    save_passwords
    backup_all
    echo -e "${GREEN}Imported $(wc -l <<< "$result" | tr -d ' ') entries${NC}"
}

list_services() {
    load_passwords
    if [[ ${#passwords[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No saved services${NC}"
        return
    fi
    echo -e "${GREEN}Saved services:${NC}"
    for svc in "${!passwords[@]}"; do
        echo "- $svc"
    done | sort
}

password_exists() {
    [[ -n "${passwords[$1]:-}" ]]
}

verify_password_for() {
    local svc="$1"
    local tkey
    tkey=$(verify_master) || return 1
    load_passwords
    if [[ -z "${passwords[$svc]}" ]]; then
        echo -e "${RED}Service not found${NC}"
        return 1
    fi
    local pw
    if ! pw=$(decrypt_password "${passwords[$svc]}" "$tkey"); then
        echo -e "${RED}Decrypt failed${NC}"
        return 1
    fi
    submenu "$svc" "$pw"
}

delete_service() {
    local svc="$1"
    if [[ -z "$svc" ]]; then
        echo -e "${RED}Usage: $0 delete <service>${NC}"
        return 1
    fi
    load_passwords
    if [[ -z "${passwords[$svc]}" ]]; then
        echo -e "${RED}Service not found${NC}"
        return 1
    fi
    unset passwords["$svc"]
    save_passwords
    backup_all
    echo -e "${GREEN}Deleted $svc${NC}"
}

show_usage() {
    cat <<EOF
Usage: $0 [command] [args]
Commands:
  help                 Show this help message
  list                 List saved services
  show <service>       Show and copy a password for a service
  add <service>        Add or update a password interactively
  gen <service> [len]  Generate and save a secure password
  delete <service>     Delete an entry
  export <file>        Export passwords metadata to JSON
  import <file>        Import passwords from JSON
  backup               Create an encrypted password backup
  backend              Print the current backend path
  menu                 Enter interactive menu mode
If no command is given, the interactive menu starts.
EOF
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        help|-h|--help)
            show_usage
            exit 0
            ;;
        list)
            list_services
            exit 0
            ;;
        show)
            shift
            verify_password_for "$1"
            exit $?
            ;;
        add)
            set_new_password
            exit $?
            ;;
        gen)
            shift
            if [[ -z "$1" ]]; then
                echo -e "${RED}Usage: $0 gen <service> [length]${NC}"
                exit 1
            fi
            local svc="$1"
            shift
            generate_and_set "$svc" "$1"
            exit $?
            ;;
        delete)
            shift
            delete_service "$1"
            exit $?
            ;;
        export)
            shift
            export_passwords "$1"
            exit $?
            ;;
        import)
            shift
            import_passwords "$1"
            exit $?
            ;;
        backup)
            backup_all
            exit 0
            ;;
        backend)
            echo "$MODULE_PATH"
            exit 0
            ;;
        menu)
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
fi

setup_master() {
    if [[ ! -f "$MASTER_FILE" ]]; then
        read -s -p "Set master password: " master; echo
        read -s -p "Confirm: " confirm; echo
        [[ "$master" != "$confirm" ]] && echo -e "${RED}Mismatch${NC}" && exit 1
        local hash
        hash=$(pbkdf2_hash "$master" "$SALT")
        if [[ -z "$hash" ]]; then
            echo -e "${RED}Failed to derive master hash${NC}" && exit 1
        fi
        echo "$hash" > "$MASTER_FILE"
        chmod 600 "$MASTER_FILE"
        echo -e "${GREEN}Master set.${NC}"
        unset master confirm hash
    fi
}

verify_master() {
    local stored
    stored=$(<"$MASTER_FILE")
    read -s -p "Master password: " master; echo
    local hash
    hash=$(pbkdf2_hash "$master" "$SALT")
    if [[ "$hash" != "$stored" ]]; then
        echo -e "${RED}Invalid${NC}" && unset master hash && exit 1
    fi
    local key
    key=$(derive_key "$master" "$SALT")
    if [[ -z "$key" ]]; then
        echo -e "${RED}Key derivation failed${NC}" && unset master hash key && exit 1
    fi
    unset master hash
    echo "$key"
}

check_password_strength() {
    "$MODULE_PATH" strength "$1" 2>/dev/null
}

generate_password() {
    local len=${1:-12}
    "$MODULE_PATH" generate "$len" 2>/dev/null
}

verify_password() {
    local tkey
    tkey=$(verify_master)
    load_passwords
    echo "Services: ${!passwords[*]}"
    read -p "Service: " svc
    if [[ -z "${passwords[$svc]}" ]]; then
        echo -e "${RED}Not found${NC}" && unset tkey && return
    fi
    local pw
    if ! pw=$(decrypt_password "${passwords[$svc]}" "$tkey"); then
        echo -e "${RED}Decrypt failed${NC}" && unset tkey && return
    fi
    submenu "$svc" "$pw"
    unset pw tkey
}

submenu() {
    local svc=$1 pw=$2
    while true; do
        echo -e "${YELLOW}$svc:${NC} 1.View 2.Copy 3.Back"
        read -p "> " ch
        case $ch in
            1) echo -e "${GREEN}Password: $pw${NC}" ;;
            2)
                if command -v xclip &>/dev/null; then
                    echo -n "$pw" | xclip -selection clipboard
                    echo -e "${GREEN}Copied (clears in 30s)${NC}"
                    (sleep 30; echo -n "" | xclip -selection clipboard) &
                elif command -v pbcopy &>/dev/null; then
                    echo -n "$pw" | pbcopy
                    echo -e "${GREEN}Copied (clears in 30s)${NC}"
                    (sleep 30; echo -n "" | pbcopy) &
                else
                    echo -e "${RED}No clipboard tool${NC}"
                fi
                ;;
            3) break ;;
            *) echo -e "${RED}Invalid${NC}" ;;
        esac
    done
    unset pw
}

set_new_password() {
    local tkey
    tkey=$(verify_master)
    load_passwords
    read -p "Service: " svc
    read -s -p "New password: " pw1; echo
    read -s -p "Confirm: " pw2; echo
    [[ "$pw1" != "$pw2" ]] && echo -e "${RED}Mismatch${NC}" && unset tkey pw1 pw2 && return
    local strength
    strength=$(check_password_strength "$pw1")
    (( strength < 3 )) && echo -e "${YELLOW}Weak password (${strength}/5)${NC}"
    local enc
    if ! enc=$(encrypt_password "$pw1" "$tkey"); then
        echo -e "${RED}Encryption failed${NC}" && unset tkey pw1 pw2 && return
    fi
    passwords["$svc"]="$enc"
    save_passwords
    backup_all
    echo -e "${GREEN}Saved${NC}"
    unset pw1 pw2 enc tkey
}

generate_and_set() {
    local svc="$1"
    local len="$2"
    local tkey
    tkey=$(verify_master)
    load_passwords
    if [[ -z "$svc" ]]; then
        read -p "Service: " svc
    fi
    if [[ -z "$len" ]]; then
        read -p "Length (default 12): " len
    fi
    len=${len:-12}
    local pw
    pw=$(generate_password "$len")
    if [[ -z "$pw" ]]; then
        echo -e "${RED}Password generation failed${NC}" && unset tkey && return
    fi
    local enc
    if ! enc=$(encrypt_password "$pw" "$tkey"); then
        echo -e "${RED}Encryption failed${NC}" && unset pw tkey && return
    fi
    passwords["$svc"]="$enc"
    save_passwords
    backup_all
    echo -e "${GREEN}Generated: $pw${NC}"
    unset pw enc tkey
}

setup_master
load_passwords

while true; do
    echo -e "${YELLOW}Menu:${NC} 1.Access 2.Set 3.Generate 4.Exit"
    read -p "> " opt
    case $opt in
        1) verify_password ;;
        2) set_new_password ;;
        3) generate_and_set ;;
        4) break ;;
        *) echo -e "${RED}Invalid${NC}" ;;
    esac
    echo

done
