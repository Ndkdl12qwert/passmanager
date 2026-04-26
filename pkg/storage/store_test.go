package storage

import (
	"os"
	"testing"
)

func TestNew(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if store.Dir == "" {
		t.Error("store dir is empty")
	}
}

func TestEnsure(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatal(err)
	}
	err = store.Ensure()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.SaltFile); os.IsNotExist(err) {
		t.Error("salt file not created")
	}
}

func TestLoadSavePasswords(t *testing.T) {
	store, err := New()
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{
		"github": "encrypted1",
		"gitlab": "encrypted2",
	}
	err = store.SavePasswords(entries)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadPasswords()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2 entries, got %d", len(loaded))
	}
}
