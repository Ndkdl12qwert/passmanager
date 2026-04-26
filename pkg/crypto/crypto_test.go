package crypto

import (
	"testing"
)

func TestDeriveKey(t *testing.T) {
	key, err := DeriveKey("password", "salt")
	if err != nil {
		t.Fatal(err)
	}
	if key == "" {
		t.Error("key is empty")
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("password", "salt")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Error("hash is empty")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, err := DeriveKey("password", "salt")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "hello world"
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %s, got %s", plaintext, decrypted)
	}
}

func TestGeneratePassword(t *testing.T) {
	pw, err := GeneratePassword(12)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 12 {
		t.Errorf("expected length 12, got %d", len(pw))
	}
}

func TestCheckStrength(t *testing.T) {
	score := CheckStrength("Test123!")
	if score < 3 {
		t.Errorf("expected score >= 3, got %d", score)
	}
}
