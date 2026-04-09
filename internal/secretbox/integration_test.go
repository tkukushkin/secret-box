package secretbox

import (
	"bytes"
	"testing"
)

func TestIntegration_SecretLifecycle(t *testing.T) {
	env := makeTestEnvironment(t)

	// Write
	if err := env.Store.Write("my-secret", []byte("my-value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Exists
	if !env.Store.Exists("my-secret") {
		t.Error("secret should exist after write")
	}

	// List
	names := env.Store.List()
	if len(names) != 1 || names[0] != "my-secret" {
		t.Errorf("List() = %v, want [my-secret]", names)
	}

	// Read
	data, err := env.Store.Read("my-secret")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(data) != "my-value" {
		t.Errorf("Read() = %q, want %q", data, "my-value")
	}

	// Delete
	if err := env.Store.Delete("my-secret"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if env.Store.Exists("my-secret") {
		t.Error("secret should not exist after delete")
	}
	if len(env.Store.List()) != 0 {
		t.Error("List() should be empty after delete")
	}
}

func TestIntegration_MultipleSecrets(t *testing.T) {
	env := makeTestEnvironment(t)

	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if err := env.Store.Write(name, []byte(name[:1])); err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}

	names := env.Store.List()
	expected := []string{"alpha", "bravo", "charlie"}
	if len(names) != len(expected) {
		t.Fatalf("List() returned %d names, want %d", len(names), len(expected))
	}
	for i := range names {
		if names[i] != expected[i] {
			t.Errorf("List()[%d] = %s, want %s", i, names[i], expected[i])
		}
	}

	// Delete middle one
	if err := env.Store.Delete("bravo"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	names = env.Store.List()
	if len(names) != 2 || names[0] != "alpha" || names[1] != "charlie" {
		t.Errorf("after delete, List() = %v, want [alpha charlie]", names)
	}

	// Remaining secrets are still readable
	a, err := env.Store.Read("alpha")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(a, []byte("a")) {
		t.Errorf("Read(alpha) = %q, want %q", a, "a")
	}
	c, err := env.Store.Read("charlie")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(c, []byte("c")) {
		t.Errorf("Read(charlie) = %q, want %q", c, "c")
	}
}

func TestIntegration_AuthCacheFlow(t *testing.T) {
	env := makeTestEnvironment(t)
	callerID := "test-caller"

	// Force DB init
	if _, err := env.DB.Connection(); err != nil {
		t.Fatalf("Connection error: %v", err)
	}

	// Not cached initially
	if env.Cache.IsValid(callerID, "secret-1") {
		t.Error("cache should not be valid initially")
	}

	// After update, cache is valid
	env.Cache.Update(callerID, "secret-1")
	if !env.Cache.IsValid(callerID, "secret-1") {
		t.Error("cache should be valid after update")
	}

	// After invalidation, cache is no longer valid
	env.Cache.Invalidate("secret-1")
	if env.Cache.IsValid(callerID, "secret-1") {
		t.Error("cache should not be valid after invalidation")
	}
}

func TestIntegration_WriteInvalidatesCache(t *testing.T) {
	env := makeTestEnvironment(t)
	callerID := "test-caller"

	// Write a secret and cache auth
	if err := env.Store.Write("my-secret", []byte("old")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	env.Cache.Update(callerID, "my-secret")
	if !env.Cache.IsValid(callerID, "my-secret") {
		t.Error("cache should be valid")
	}

	// Overwrite the secret and invalidate cache (as the CLI does)
	if err := env.Store.Write("my-secret", []byte("new")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	env.Cache.Invalidate("my-secret")

	if env.Cache.IsValid(callerID, "my-secret") {
		t.Error("cache should not be valid after write+invalidate")
	}
	data, err := env.Store.Read("my-secret")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(data, []byte("new")) {
		t.Errorf("Read() = %q, want %q", data, "new")
	}
}

func TestIntegration_ResetClearsAll(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Store.Write("s1", []byte("v1")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := env.Store.Write("s2", []byte("v2")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	env.Cache.Update("caller", "s1")

	if err := env.Store.ResetAll(); err != nil {
		t.Fatalf("ResetAll error: %v", err)
	}

	// Keychain is cleared
	if len(env.Keychain.Storage) != 0 {
		t.Error("keychain should be empty after reset")
	}
}

func TestIntegration_CacheWithTime(t *testing.T) {
	var currentTime int64 = 10_000
	env := makeTestEnvironment(t,
		WithCacheDuration(60),
		WithTimeProvider(func() int64 { return currentTime }),
	)

	if err := env.Store.Write("secret", []byte("val")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// First access - not cached
	if env.Cache.IsValid("caller", "secret") {
		t.Error("should not be cached initially")
	}

	// Authenticate and cache
	env.Cache.Update("caller", "secret")
	if !env.Cache.IsValid("caller", "secret") {
		t.Error("should be cached after update")
	}

	// 30 seconds later - still valid
	currentTime = 10_030
	if !env.Cache.IsValid("caller", "secret") {
		t.Error("should still be valid at 30s")
	}

	// 61 seconds later - expired
	currentTime = 10_061
	if env.Cache.IsValid("caller", "secret") {
		t.Error("should be expired at 61s")
	}

	// Re-authenticate
	env.Cache.Update("caller", "secret")
	if !env.Cache.IsValid("caller", "secret") {
		t.Error("should be valid after re-auth")
	}
}

func TestIntegration_MultipleCallersSameSecret(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Store.Write("shared-secret", []byte("value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Caller A authenticates
	env.Cache.Update("caller-A", "shared-secret")

	if !env.Cache.IsValid("caller-A", "shared-secret") {
		t.Error("caller-A should be cached")
	}
	if env.Cache.IsValid("caller-B", "shared-secret") {
		t.Error("caller-B should not be cached")
	}

	// Caller B authenticates
	env.Cache.Update("caller-B", "shared-secret")

	if !env.Cache.IsValid("caller-A", "shared-secret") {
		t.Error("caller-A should still be cached")
	}
	if !env.Cache.IsValid("caller-B", "shared-secret") {
		t.Error("caller-B should now be cached")
	}

	// Invalidating clears both
	env.Cache.Invalidate("shared-secret")
	if env.Cache.IsValid("caller-A", "shared-secret") {
		t.Error("caller-A should not be cached after invalidation")
	}
	if env.Cache.IsValid("caller-B", "shared-secret") {
		t.Error("caller-B should not be cached after invalidation")
	}
}

func TestIntegration_UniqueNonces(t *testing.T) {
	env := makeTestEnvironment(t)

	data := []byte("same data")
	if err := env.Store.Write("s1", data); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := env.Store.Write("s2", data); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	conn, err := env.DB.Connection()
	if err != nil {
		t.Fatalf("Connection error: %v", err)
	}

	var blob1, blob2 []byte
	if err := conn.QueryRow(`SELECT encrypted_data FROM secrets WHERE name = ?`, "s1").Scan(&blob1); err != nil {
		t.Fatalf("QueryRow error: %v", err)
	}
	if err := conn.QueryRow(`SELECT encrypted_data FROM secrets WHERE name = ?`, "s2").Scan(&blob2); err != nil {
		t.Fatalf("QueryRow error: %v", err)
	}

	if bytes.Equal(blob1, blob2) {
		t.Error("encrypted blobs should be different (different nonces)")
	}

	// But decrypted values should be the same
	d1, _ := env.Store.Read("s1")
	d2, _ := env.Store.Read("s2")
	if !bytes.Equal(d1, d2) {
		t.Error("decrypted values should be equal")
	}
}

func TestIntegration_KeychainIsolation(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	keychain := NewMockKeychain()
	db1 := NewSecretDatabase(tmpDir1)
	db2 := NewSecretDatabase(tmpDir2)
	store1 := NewSecretStore(db1, keychain, WithKeychainService("svc1"))
	store2 := NewSecretStore(db2, keychain, WithKeychainService("svc2"))

	if err := store1.Write("secret", []byte("from-store-1")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := store2.Write("secret", []byte("from-store-2")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	d1, err := store1.Read("secret")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	d2, err := store2.Read("secret")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	if !bytes.Equal(d1, []byte("from-store-1")) {
		t.Errorf("store1 got %q, want %q", d1, "from-store-1")
	}
	if !bytes.Equal(d2, []byte("from-store-2")) {
		t.Errorf("store2 got %q, want %q", d2, "from-store-2")
	}
}

func TestIntegration_MockBiometricAuth(t *testing.T) {
	mock := &MockBiometricAuth{ShouldSucceed: true}

	// Success case
	if err := mock.Authenticate("test reason"); err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if !mock.AuthenticateCalled {
		t.Error("AuthenticateCalled should be true")
	}
	if mock.LastReason != "test reason" {
		t.Errorf("LastReason = %q, want %q", mock.LastReason, "test reason")
	}

	// Failure case
	mock.ShouldSucceed = false
	err := mock.Authenticate("fail")
	if err == nil {
		t.Fatal("expected error on failed auth")
	}
	if _, ok := err.(*TouchIDError); !ok {
		t.Errorf("expected *TouchIDError, got %T", err)
	}
}
