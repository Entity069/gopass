package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Vault struct {
	aead cipher.AEAD
	id   string
}

func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("cli-login/key-id/v1:"), key...))
	return &Vault{aead: aead, id: hex.EncodeToString(digest[:])}, nil
}

func (v *Vault) ID() string { return v.id }

// seal binds secrets to owner or purpose via AEAD and uses a fresh random 96 bit nonce
func (v *Vault) Seal(plaintext []byte, purpose string) []byte {
	return v.aead.Seal(nil, nil, plaintext, []byte(purpose))
}

func (v *Vault) Open(ciphertext []byte, purpose string) ([]byte, error) {
	return v.aead.Open(nil, nil, ciphertext, []byte(purpose))
}

// PrivateDir refuses shared directories instead of silently changing permissions on an existing user owned location
func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("data directory %q must be a real directory with mode 0700", path)
	}
	return nil
}

// LoadKey atomically publishes keys via hard link and existing DBs are not replaced
func LoadKey(path string, allowCreate bool) ([]byte, error) {
	key, err := readKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !allowCreate {
		return nil, errors.New("encryption key is missing for an existing database; restore its original key")
	}
	if err := PrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	defer clear(key)
	f, err := os.CreateTemp(filepath.Dir(path), ".key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(f.Name(), path); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	// persists the key entry before DB creation
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return nil, err
	}
	return readKey(path)
}

func readKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return nil, errors.New("key file must be a regular, private (0600 or 0400) file containing exactly 32 raw bytes")
	}
	return os.ReadFile(path)
}
