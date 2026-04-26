package storage

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Store struct {
	Dir        string
	PassFile   string
	SaltFile   string
	MasterFile string
	BackupDir  string
}

func New() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".pass_manager")
	return &Store{
		Dir:        dir,
		PassFile:   filepath.Join(dir, "passwords.txt"),
		SaltFile:   filepath.Join(dir, "salt"),
		MasterFile: filepath.Join(dir, "master"),
		BackupDir:  filepath.Join(dir, "backups"),
	}, nil
}

func (s *Store) Ensure() error {
	if err := os.MkdirAll(s.BackupDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.SaltFile); os.IsNotExist(err) {
		data := make([]byte, 32)
		if _, err := rand.Read(data); err != nil {
			return err
		}
		if err := os.WriteFile(s.SaltFile, []byte(base64.StdEncoding.EncodeToString(data)), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Salt() (string, error) {
	data, err := os.ReadFile(s.SaltFile)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *Store) LoadPasswords() (map[string]string, error) {
	entries := map[string]string{}
	file, err := os.Open(s.PassFile)
	if os.IsNotExist(err) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		entries[parts[0]] = parts[1]
	}
	return entries, scanner.Err()
}

func (s *Store) SavePasswords(entries map[string]string) error {
	file, err := os.OpenFile(s.PassFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for svc, enc := range entries {
		if _, err := fmt.Fprintf(writer, "%s:%s\n", svc, enc); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func (s *Store) Backup() (string, error) {
	ts := time.Now().Format("20060102_150405")
	outPath := filepath.Join(s.BackupDir, fmt.Sprintf("backup_%s.tar.gz", ts))
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	gw := gzip.NewWriter(out)
	defer gw.Close()
	if err := archiveDirectory(gw, s.Dir); err != nil {
		return "", err
	}
	return outPath, nil
}

func archiveDirectory(w io.Writer, root string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tw, file)
		return err
	})
}
