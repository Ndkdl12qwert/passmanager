package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const (
	KeyLen    = 32
	SaltLen   = 32
	IterCount = 10000
	IVLen     = 16
)

func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := sha256.New
	hLen := prf().Size()
	if keyLen > (1<<32-1)*hLen {
		panic("keyLen too large")
	}
	l := (keyLen + hLen - 1) / hLen
	result := make([]byte, l*hLen)
	for i := 1; i <= l; i++ {
		u := make([]byte, hLen)
		copy(u, salt)
		u = append(u, byte(i>>24), byte(i>>16), byte(i>>8), byte(i))
		for j := 0; j < iter; j++ {
			u = prf().Sum(u[:len(salt)+4])
		}
		copy(result[(i-1)*hLen:], u)
	}
	return result[:keyLen]
}

func DeriveKey(password, salt string) (string, error) {
	key := pbkdf2([]byte(password), []byte(salt), IterCount, KeyLen)
	return base64.StdEncoding.EncodeToString(key), nil
}

func HashPassword(password, salt string) (string, error) {
	hash := pbkdf2([]byte(password), []byte(salt), IterCount, KeyLen)
	return base64.StdEncoding.EncodeToString(hash), nil
}

func Encrypt(plaintext, keyBase64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}
	if len(key) != KeyLen {
		return "", errors.New("invalid key length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, IVLen)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, []byte(plaintext))

	combined := append(iv, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

func Decrypt(ciphertextBase64, keyBase64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return "", err
	}
	if len(key) != KeyLen {
		return "", errors.New("invalid key length")
	}

	combined, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}
	if len(combined) < IVLen {
		return "", errors.New("invalid ciphertext")
	}

	iv := combined[:IVLen]
	ciphertext := combined[IVLen:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return string(plaintext), nil
}

func GeneratePassword(length int) (string, error) {
	if length <= 0 {
		length = 12
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	charsetLen := len(charset)
	password := make([]byte, length)
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	for i := 0; i < length; i++ {
		password[i] = charset[randomBytes[i]%byte(charsetLen)]
	}
	return string(password), nil
}

func CheckStrength(password string) int {
	score := 0
	hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
	hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasDigit := strings.ContainsAny(password, "0123456789")
	hasSymbol := strings.ContainsAny(password, "!@#$%^&*()-_=+")
	score += boolToInt(hasLower) + boolToInt(hasUpper) + boolToInt(hasDigit) + boolToInt(hasSymbol)
	if len(password) >= 12 {
		score++
	}
	return score
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
