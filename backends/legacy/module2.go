package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{};:,.<>/?\\|"

func usage() {
	fmt.Println("Usage: module2 <command> [args...]")
	fmt.Println("Commands:")
	fmt.Println("  hash <password> <salt>")
	fmt.Println("  derive <password> <salt>")
	fmt.Println("  encrypt <plaintext> <base64key>")
	fmt.Println("  decrypt <ciphertext> <base64key>")
	fmt.Println("  generate [length]")
	fmt.Println("  strength <password>")
}

func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)

	for block := 1; block <= numBlocks; block++ {
		T := pbkdf2F(password, salt, iter, block)
		dk = append(dk, T...)
	}

	return dk[:keyLen]
}

func pbkdf2F(password, salt []byte, iter, blockIndex int) []byte {
	hmacFunc := func(data []byte) []byte {
		h := hmac.New(sha256.New, password)
		h.Write(data)
		return h.Sum(nil)
	}

	U := make([]byte, len(salt)+4)
	copy(U, salt)
	U[len(salt)+0] = byte(blockIndex >> 24)
	U[len(salt)+1] = byte(blockIndex >> 16)
	U[len(salt)+2] = byte(blockIndex >> 8)
	U[len(salt)+3] = byte(blockIndex)

	ui := hmacFunc(U)
	t := make([]byte, len(ui))
	copy(t, ui)

	for i := 1; i < iter; i++ {
		ui = hmacFunc(ui)
		for j := range t {
			t[j] ^= ui[j]
		}
	}

	return t
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytesRepeat(byte(padding), padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid padding")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, errors.New("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}

func bytesRepeat(b byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = b
	}
	return result
}

func randomPassword(length int) (string, error) {
	if length <= 0 {
		length = 12
	}

	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}

	password := make([]byte, length)
	for i := 0; i < length; i++ {
		password[i] = charset[bytes[i]%byte(len(charset))]
	}
	return string(password), nil
}

func strength(password string) int {
	count := 0
	if len(password) >= 8 {
		count++
	}
	if strings.IndexAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") >= 0 {
		count++
	}
	if strings.IndexAny(password, "abcdefghijklmnopqrstuvwxyz") >= 0 {
		count++
	}
	if strings.IndexAny(password, "0123456789") >= 0 {
		count++
	}
	if strings.IndexAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != len(password) {
		count++
	}
	return count
}

func encrypt(plaintext, keyB64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", errors.New("invalid key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	output := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(output), nil
}

func decrypt(ciphertextB64, keyB64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", errors.New("invalid key length")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("invalid ciphertext")
	}

	iv := ciphertext[:aes.BlockSize]
	encrypted := ciphertext[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plain := make([]byte, len(encrypted))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plain, encrypted)

	unpad, err := pkcs7Unpad(plain)
	if err != nil {
		return "", err
	}
	return string(unpad), nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "hash":
		if len(os.Args) != 4 {
			usage()
			os.Exit(1)
		}
		result := pbkdf2([]byte(os.Args[2]), []byte(os.Args[3]), 10000, 32)
		fmt.Println(hex.EncodeToString(result))
	case "derive":
		if len(os.Args) != 4 {
			usage()
			os.Exit(1)
		}
		result := pbkdf2([]byte(os.Args[2]), []byte(os.Args[3]), 10000, 32)
		fmt.Println(base64.StdEncoding.EncodeToString(result))
	case "encrypt":
		if len(os.Args) != 4 {
			usage()
			os.Exit(1)
		}
		out, err := encrypt(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		fmt.Print(out)
	case "decrypt":
		if len(os.Args) != 4 {
			usage()
			os.Exit(1)
		}
		out, err := decrypt(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		fmt.Print(out)
	case "generate":
		length := 12
		if len(os.Args) == 3 {
			parsed, err := strconv.Atoi(os.Args[2])
			if err == nil && parsed > 0 {
				length = parsed
			}
		}
		password, err := randomPassword(length)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			os.Exit(1)
		}
		fmt.Print(password)
	case "strength":
		if len(os.Args) != 3 {
			usage()
			os.Exit(1)
		}
		fmt.Print(strength(os.Args[2]))
	default:
		usage()
		os.Exit(1)
	}
}
