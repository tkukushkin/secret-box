package secretbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDatabase_CreatesDirectoryAndFile(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewSecretDatabase(tmpDir)
	_, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "db.sqlite3")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file should exist")
	}
}

func TestDatabase_DirectoryPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewSecretDatabase(tmpDir)
	_, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}

	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("directory permissions = %o, want %o", perm, 0700)
	}
}

func TestDatabase_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewSecretDatabase(tmpDir)
	_, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "db.sqlite3")
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want %o", perm, 0600)
	}
}

func TestDatabase_ConnectionReuse(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewSecretDatabase(tmpDir)

	conn1, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}
	conn2, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}
	if conn1 != conn2 {
		t.Error("Connection() should return the same instance")
	}
}

func TestDatabase_CloseAndReconnect(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewSecretDatabase(tmpDir)

	conn1, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}
	db.CloseConnection()

	conn2, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}
	if conn1 == conn2 {
		t.Error("after CloseConnection, Connection() should return a new instance")
	}
}

func TestDatabase_CreatesSchema(t *testing.T) {
	tmpDir := t.TempDir()
	db := NewSecretDatabase(tmpDir)

	conn, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}

	rows, err := conn.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatalf("Query error: %v", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Scan error: %v", err)
		}
		tables = append(tables, name)
	}

	hasSecrets := false
	hasAuthCache := false
	for _, table := range tables {
		if table == "secrets" {
			hasSecrets = true
		}
		if table == "auth_cache" {
			hasAuthCache = true
		}
	}
	if !hasSecrets {
		t.Error("'secrets' table should exist")
	}
	if !hasAuthCache {
		t.Error("'auth_cache' table should exist")
	}
}

func TestDatabase_CreatesBaseDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "nested", "deep")

	db := NewSecretDatabase(nestedDir)
	_, err := db.Connection()
	if err != nil {
		t.Fatalf("Connection() error: %v", err)
	}

	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("nested directory should be created")
	}
}
