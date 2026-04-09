package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// StoreError represents secret storage errors.
type StoreError struct {
	Kind    string
	Message string
}

func (e *StoreError) Error() string {
	return e.Message
}

var (
	ErrSecretNotFound = &StoreError{Kind: "secretNotFound", Message: "secret not found"}
	ErrCorruptedData  = &StoreError{Kind: "corruptedData", Message: "corrupted secret data"}
)

// SecretStore manages encrypted secret storage.
type SecretStore struct {
	DB              *SecretDatabase
	keychain        KeychainProvider
	KeychainService string
	KeychainAccount string
}

type StoreOption func(*SecretStore)

func WithKeychainService(service string) StoreOption {
	return func(s *SecretStore) { s.KeychainService = service }
}

func NewSecretStore(db *SecretDatabase, keychain KeychainProvider, opts ...StoreOption) *SecretStore {
	s := &SecretStore{
		DB:              db,
		keychain:        keychain,
		KeychainService: "secret-box",
		KeychainAccount: "__master-key__",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *SecretStore) Write(name string, data []byte) error {
	key, err := s.getOrCreateKey()
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return &StoreError{Kind: "storageError", Message: "encryption failed"}
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return &StoreError{Kind: "storageError", Message: "encryption failed"}
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return &StoreError{Kind: "storageError", Message: "encryption failed"}
	}

	// combined = nonce || ciphertext || tag (matches CryptoKit format)
	combined := gcm.Seal(nonce, nonce, data, nil)

	conn, err := s.DB.Connection()
	if err != nil {
		return &StoreError{Kind: "storageError", Message: err.Error()}
	}

	_, err = conn.Exec(
		`INSERT OR REPLACE INTO secrets (name, encrypted_data) VALUES (?, ?)`,
		name, combined,
	)
	if err != nil {
		return &StoreError{Kind: "storageError", Message: err.Error()}
	}
	return nil
}

func (s *SecretStore) Read(name string) ([]byte, error) {
	key, err := s.getOrCreateKey()
	if err != nil {
		return nil, err
	}

	conn, err := s.DB.Connection()
	if err != nil {
		return nil, &StoreError{Kind: "storageError", Message: err.Error()}
	}

	var combined []byte
	err = conn.QueryRow(`SELECT encrypted_data FROM secrets WHERE name = ?`, name).Scan(&combined)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, &StoreError{Kind: "storageError", Message: err.Error()}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCorruptedData
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCorruptedData
	}

	nonceSize := gcm.NonceSize()
	if len(combined) < nonceSize {
		return nil, ErrCorruptedData
	}

	nonce := combined[:nonceSize]
	ciphertext := combined[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrCorruptedData
	}
	return plaintext, nil
}

func (s *SecretStore) Exists(name string) bool {
	conn, err := s.DB.Connection()
	if err != nil {
		return false
	}

	var count int
	err = conn.QueryRow(`SELECT COUNT(*) FROM secrets WHERE name = ?`, name).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (s *SecretStore) Delete(name string) error {
	conn, err := s.DB.Connection()
	if err != nil {
		return &StoreError{Kind: "storageError", Message: err.Error()}
	}

	_, err = conn.Exec(`DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		return &StoreError{Kind: "storageError", Message: err.Error()}
	}
	return nil
}

func (s *SecretStore) List() []string {
	conn, err := s.DB.Connection()
	if err != nil {
		return nil
	}

	rows, err := conn.Query(`SELECT name FROM secrets ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil
		}
		names = append(names, name)
	}
	return names
}

func (s *SecretStore) ResetAll() error {
	s.DB.CloseConnection()

	if _, err := os.Stat(s.DB.BaseDir()); err == nil {
		if err := os.RemoveAll(s.DB.BaseDir()); err != nil {
			return fmt.Errorf("failed to remove data directory: %w", err)
		}
	}

	s.keychain.Delete(s.KeychainService, s.KeychainAccount)
	return nil
}

// AuthKey derives the HMAC key for auth cache from the master key using HKDF-SHA256.
func (s *SecretStore) AuthKey() ([]byte, error) {
	masterKey, err := s.getOrCreateKey()
	if err != nil {
		return nil, err
	}

	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte("secret-box-auth-cache"))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derived); err != nil {
		return nil, err
	}
	return derived, nil
}

func (s *SecretStore) getOrCreateKey() ([]byte, error) {
	if data := s.keychain.Get(s.KeychainService, s.KeychainAccount); data != nil {
		return data, nil
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, &StoreError{Kind: "keychainError", Message: "failed to generate key"}
	}

	if err := s.keychain.Set(key, s.KeychainService, s.KeychainAccount); err != nil {
		return nil, &StoreError{Kind: "keychainError", Message: fmt.Sprintf("Failed to store key: %s", err)}
	}

	return key, nil
}
