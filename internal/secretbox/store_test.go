package secretbox

import (
	"bytes"
	"testing"
)

func TestStore_WriteAndRead(t *testing.T) {
	env := makeTestEnvironment(t)
	data := []byte("hello world")
	if err := env.Store.Write("test-secret", data); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	result, err := env.Store.Read("test-secret")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("got %q, want %q", result, data)
	}
}

func TestStore_WriteAndReadBinary(t *testing.T) {
	env := makeTestEnvironment(t)
	data := []byte{0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F}
	if err := env.Store.Write("binary-secret", data); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	result, err := env.Store.Read("binary-secret")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Errorf("got %x, want %x", result, data)
	}
}

func TestStore_Overwrite(t *testing.T) {
	env := makeTestEnvironment(t)
	if err := env.Store.Write("s", []byte("old")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := env.Store.Write("s", []byte("new")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	result, err := env.Store.Read("s")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(result, []byte("new")) {
		t.Errorf("got %q, want %q", result, "new")
	}
}

func TestStore_ReadNonExistent(t *testing.T) {
	env := makeTestEnvironment(t)
	// Force DB init
	if _, err := env.DB.Connection(); err != nil {
		t.Fatalf("Connection error: %v", err)
	}
	_, err := env.Store.Read("no-such-secret")
	if err == nil {
		t.Fatal("expected error for non-existent secret")
	}
}

func TestStore_ExistsTrue(t *testing.T) {
	env := makeTestEnvironment(t)
	if err := env.Store.Write("present", []byte("v")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if !env.Store.Exists("present") {
		t.Error("Exists should return true for existing secret")
	}
}

func TestStore_ExistsFalse(t *testing.T) {
	env := makeTestEnvironment(t)
	if _, err := env.DB.Connection(); err != nil {
		t.Fatalf("Connection error: %v", err)
	}
	if env.Store.Exists("absent") {
		t.Error("Exists should return false for non-existing secret")
	}
}

func TestStore_Delete(t *testing.T) {
	env := makeTestEnvironment(t)
	if err := env.Store.Write("to-delete", []byte("v")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if !env.Store.Exists("to-delete") {
		t.Fatal("secret should exist before delete")
	}
	if err := env.Store.Delete("to-delete"); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if env.Store.Exists("to-delete") {
		t.Error("secret should not exist after delete")
	}
}

func TestStore_ListSorted(t *testing.T) {
	env := makeTestEnvironment(t)
	for _, name := range []string{"charlie", "alpha", "bravo"} {
		if err := env.Store.Write(name, []byte(name[:1])); err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}

	names := env.Store.List()
	expected := []string{"alpha", "bravo", "charlie"}
	if len(names) != len(expected) {
		t.Fatalf("List() returned %d names, want %d", len(names), len(expected))
	}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("List()[%d] = %s, want %s", i, name, expected[i])
		}
	}
}

func TestStore_ListEmpty(t *testing.T) {
	env := makeTestEnvironment(t)
	if _, err := env.DB.Connection(); err != nil {
		t.Fatalf("Connection error: %v", err)
	}
	names := env.Store.List()
	if len(names) != 0 {
		t.Errorf("List() should return empty for empty store, got %v", names)
	}
}

func TestStore_ResetAll(t *testing.T) {
	env := makeTestEnvironment(t)
	if err := env.Store.Write("s1", []byte("v")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := env.Store.Write("s2", []byte("v")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	if err := env.Store.ResetAll(); err != nil {
		t.Fatalf("ResetAll error: %v", err)
	}

	// Keychain entry should be deleted
	if len(env.Keychain.Storage) != 0 {
		t.Error("keychain should be empty after reset")
	}
}

func TestStore_AuthKeyConsistent(t *testing.T) {
	env := makeTestEnvironment(t)
	key1, err := env.Store.AuthKey()
	if err != nil {
		t.Fatalf("AuthKey error: %v", err)
	}
	key2, err := env.Store.AuthKey()
	if err != nil {
		t.Fatalf("AuthKey error: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("AuthKey should return consistent derived key")
	}
}

func TestStore_LargeData(t *testing.T) {
	env := makeTestEnvironment(t)
	data := bytes.Repeat([]byte{0x42}, 100_000)
	if err := env.Store.Write("large", data); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	result, err := env.Store.Read("large")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("large data should round-trip correctly")
	}
}

func TestStore_MultipleSecretsIndependent(t *testing.T) {
	env := makeTestEnvironment(t)
	if err := env.Store.Write("a", []byte("value-a")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if err := env.Store.Write("b", []byte("value-b")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	a, err := env.Store.Read("a")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	b, err := env.Store.Read("b")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if !bytes.Equal(a, []byte("value-a")) {
		t.Errorf("got %q, want %q", a, "value-a")
	}
	if !bytes.Equal(b, []byte("value-b")) {
		t.Errorf("got %q, want %q", b, "value-b")
	}
}
