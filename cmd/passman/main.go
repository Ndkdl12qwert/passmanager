package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"passman/pkg/crypto"
	"passman/pkg/storage"
)

func main() {
	flag.Usage = func() {
		fmt.Println("Usage: passman <command> [args]")
		fmt.Println("Commands:")
		fmt.Println("  help                 Show help")
		fmt.Println("  list                 List saved services")
		fmt.Println("  show <service>       Display a password")
		fmt.Println("  add <service>        Add or update a password")
		fmt.Println("  gen <service> [len]  Generate and save a password")
		fmt.Println("  delete <service>     Delete an entry")
		fmt.Println("  export <file>        Export entries to JSON")
		fmt.Println("  import <file>        Import entries from JSON")
		fmt.Println("  backup               Create a backup archive")
		fmt.Println("  backend              Print the active backend")
		fmt.Println("  menu                 Interactive menu")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		flag.Usage()
		return
	}

	store, err := storage.New()
	if err != nil {
		fatal(err)
	}
	if err := store.Ensure(); err != nil {
		fatal(err)
	}

	switch args[0] {
	case "list":
		listCommand(store)
	case "backend":
		fmt.Println("built-in Go crypto")
	case "show":
		if len(args) < 2 {
			fatal(errors.New("show requires service name"))
		}
		showCommand(store, args[1])
	case "add":
		if len(args) < 2 {
			fatal(errors.New("add requires service name"))
		}
		addCommand(store, args[1])
	case "gen":
		if len(args) < 2 {
			fatal(errors.New("gen requires service name"))
		}
		length := 12
		if len(args) >= 3 {
			length, err = strconv.Atoi(args[2])
			if err != nil || length <= 0 {
				fatal(errors.New("invalid length"))
			}
		}
		genCommand(store, args[1], length)
	case "delete":
		if len(args) < 2 {
			fatal(errors.New("delete requires service name"))
		}
		deleteCommand(store, args[1])
	case "export":
		if len(args) < 2 {
			fatal(errors.New("export requires file path"))
		}
		exportCommand(store, args[1])
	case "import":
		if len(args) < 2 {
			fatal(errors.New("import requires file path"))
		}
		importCommand(store, args[1])
	case "backup":
		backupCommand(store)
	case "menu":
		menuCommand(store)
	default:
		fatal(errors.New("unknown command"))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func loadPasswords(store *storage.Store) (map[string]string, error) {
	return store.LoadPasswords()
}

func listCommand(store *storage.Store) {
	entries, err := loadPasswords(store)
	if err != nil {
		fatal(err)
	}
	if len(entries) == 0 {
		fmt.Println("No saved services")
		return
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, svc := range keys {
		fmt.Println(svc)
	}
}

func promptHidden(prompt string) string {
	fmt.Print(prompt)
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	_ = off.Run()
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	on := exec.Command("stty", "echo")
	on.Stdin = os.Stdin
	_ = on.Run()
	fmt.Println()
	if err != nil {
		fatal(err)
	}
	return strings.TrimSpace(text)
}

func promptLine(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		fatal(err)
	}
	return strings.TrimSpace(text)
}

func setupMaster(store *storage.Store) error {
	if _, err := os.Stat(store.MasterFile); os.IsNotExist(err) {
		password := promptHidden("Set master password: ")
		confirm := promptHidden("Confirm: ")
		if password != confirm {
			return errors.New("passwords do not match")
		}
		salt, err := store.Salt()
		if err != nil {
			return err
		}
		hash, err := crypto.HashPassword(password, salt)
		if err != nil {
			return err
		}
		return os.WriteFile(store.MasterFile, []byte(hash), 0o600)
	}
	return nil
}

func verifyMaster(store *storage.Store) (string, error) {
	data, err := os.ReadFile(store.MasterFile)
	if err != nil {
		return "", err
	}
	saved := strings.TrimSpace(string(data))
	password := promptHidden("Master password: ")
	salt, err := store.Salt()
	if err != nil {
		return "", err
	}
	hash, err := crypto.HashPassword(password, salt)
	if err != nil {
		return "", err
	}
	if hash != saved {
		return "", errors.New("invalid master password")
	}
	return crypto.DeriveKey(password, salt)
}

func showCommand(store *storage.Store, service string) {
	if err := setupMaster(store); err != nil {
		fatal(err)
	}
	key, err := verifyMaster(store)
	if err != nil {
		fatal(err)
	}
	entries, err := loadPasswords(store)
	if err != nil {
		fatal(err)
	}
	ciphertext, ok := entries[service]
	if !ok {
		fatal(errors.New("service not found"))
	}
	password, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("%s\n", password)
}

func addCommand(store *storage.Store, service string) {
	if err := setupMaster(store); err != nil {
		fatal(err)
	}
	key, err := verifyMaster(store)
	if err != nil {
		fatal(err)
	}
	password := promptHidden("New password: ")
	confirm := promptHidden("Confirm: ")
	if password != confirm {
		fatal(errors.New("passwords do not match"))
	}
	ciphertext, err := crypto.Encrypt(password, key)
	if err != nil {
		fatal(err)
	}
	entries, err := loadPasswords(store)
	if err != nil {
		fatal(err)
	}
	entries[service] = ciphertext
	if err := store.SavePasswords(entries); err != nil {
		fatal(err)
	}
	if _, err := store.Backup(); err != nil {
		fatal(err)
	}
	fmt.Println("Saved")
}

func genCommand(store *storage.Store, service string, length int) {
	if err := setupMaster(store); err != nil {
		fatal(err)
	}
	key, err := verifyMaster(store)
	if err != nil {
		fatal(err)
	}
	password, err := crypto.GeneratePassword(length)
	if err != nil {
		fatal(err)
	}
	ciphertext, err := crypto.Encrypt(password, key)
	if err != nil {
		fatal(err)
	}
	entries, err := loadPasswords(store)
	if err != nil {
		fatal(err)
	}
	entries[service] = ciphertext
	if err := store.SavePasswords(entries); err != nil {
		fatal(err)
	}
	if _, err := store.Backup(); err != nil {
		fatal(err)
	}
	fmt.Printf("Generated: %s\n", password)
}

func deleteCommand(store *storage.Store, service string) {
	entries, err := loadPasswords(store)
	if err != nil {
		fatal(err)
	}
	if _, ok := entries[service]; !ok {
		fatal(errors.New("service not found"))
	}
	delete(entries, service)
	if err := store.SavePasswords(entries); err != nil {
		fatal(err)
	}
	if _, err := store.Backup(); err != nil {
		fatal(err)
	}
	fmt.Println("Deleted")
}

func exportCommand(store *storage.Store, path string) {
	entries, err := loadPasswords(store)
	if err != nil {
		fatal(err)
	}
	records := make([]map[string]string, 0, len(entries))
	for svc, enc := range entries {
		records = append(records, map[string]string{"service": svc, "encrypted": enc})
	}
	body := map[string]interface{}{"entries": records}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fatal(err)
	}
	fmt.Println(path)
}

func importCommand(store *storage.Store, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	var body struct {
		Entries []struct {
			Service   string `json:"service"`
			Encrypted string `json:"encrypted"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		fatal(err)
	}
	entries, err := loadPasswords(store)
	if err != nil {
		fatal(err)
	}
	for _, entry := range body.Entries {
		if entry.Service == "" || entry.Encrypted == "" {
			continue
		}
		entries[entry.Service] = entry.Encrypted
	}
	if err := store.SavePasswords(entries); err != nil {
		fatal(err)
	}
	if _, err := store.Backup(); err != nil {
		fatal(err)
	}
	fmt.Printf("Imported %d entries\n", len(body.Entries))
}

func backupCommand(store *storage.Store) {
	path, err := store.Backup()
	if err != nil {
		fatal(err)
	}
	fmt.Println(path)
}

func menuCommand(store *storage.Store) {
	if err := setupMaster(store); err != nil {
		fatal(err)
	}
	for {
		fmt.Println("Menu: 1.Access 2.Set 3.Generate 4.List 5.Delete 6.Export 7.Import 8.Backup 9.Exit")
		choice := promptLine("> ")
		switch choice {
		case "1":
			service := promptLine("Service: ")
			showCommand(store, service)
		case "2":
			service := promptLine("Service: ")
			addCommand(store, service)
		case "3":
			service := promptLine("Service: ")
			lengthStr := promptLine("Length (default 12): ")
			length := 12
			if lengthStr != "" {
				n, err := strconv.Atoi(lengthStr)
				if err == nil && n > 0 {
					length = n
				}
			}
			genCommand(store, service, length)
		case "4":
			listCommand(store)
		case "5":
			service := promptLine("Service: ")
			deleteCommand(store, service)
		case "6":
			path := promptLine("Export path: ")
			exportCommand(store, path)
		case "7":
			path := promptLine("Import path: ")
			importCommand(store, path)
		case "8":
			backupCommand(store)
		case "9":
			return
		default:
			fmt.Println("Unknown option")
		}
		fmt.Println()
	}
}
