package secretbox

import (
	"testing"
)

// MockKeychain provides an in-memory keychain for testing.
type MockKeychain struct {
	Storage map[string][]byte
}

func NewMockKeychain() *MockKeychain {
	return &MockKeychain{Storage: make(map[string][]byte)}
}

func (k *MockKeychain) Get(service, account string) []byte {
	return k.Storage[service+":"+account]
}

func (k *MockKeychain) Set(data []byte, service, account string) error {
	k.Storage[service+":"+account] = data
	return nil
}

func (k *MockKeychain) Delete(service, account string) {
	delete(k.Storage, service+":"+account)
}

// MockBiometricAuth provides controllable biometric auth for testing.
type MockBiometricAuth struct {
	ShouldSucceed      bool
	AuthenticateCalled bool
	LastReason         string
}

func (m *MockBiometricAuth) Authenticate(reason string) error {
	m.AuthenticateCalled = true
	m.LastReason = reason
	if !m.ShouldSucceed {
		return &TouchIDError{Message: "Mock auth failed"}
	}
	return nil
}

// TestEnvironment bundles all test dependencies.
type TestEnvironment struct {
	Store     *SecretStore
	Cache     *AuthCache
	DB        *SecretDatabase
	Keychain  *MockKeychain
	Biometric *MockBiometricAuth
	Ops       *Operations
	TmpDir    string
}

func makeTestEnvironment(t *testing.T, opts ...interface{}) *TestEnvironment {
	t.Helper()
	tmpDir := t.TempDir()
	db := NewSecretDatabase(tmpDir)
	keychain := NewMockKeychain()
	store := NewSecretStore(db, keychain)

	var cacheOpts []CacheOption
	for _, opt := range opts {
		if co, ok := opt.(CacheOption); ok {
			cacheOpts = append(cacheOpts, co)
		}
	}
	cache := NewAuthCache(db, store.AuthKey, cacheOpts...)
	bio := &MockBiometricAuth{ShouldSucceed: true}
	ops := &Operations{
		Store:     store,
		Cache:     cache,
		Biometric: bio,
		GetCaller: func() CallerIdentity {
			return CallerIdentity{ID: "test-caller", DisplayName: "TestApp"}
		},
	}

	return &TestEnvironment{
		Store:     store,
		Cache:     cache,
		DB:        db,
		Keychain:  keychain,
		Biometric: bio,
		Ops:       ops,
		TmpDir:    tmpDir,
	}
}
