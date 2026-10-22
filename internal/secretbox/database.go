package secretbox

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

// SecretDatabase manages the SQLite database connection and schema.
type SecretDatabase struct {
	baseDir string
	conn    *sql.DB
	mu      sync.Mutex
}

func NewSecretDatabase(baseDir string) *SecretDatabase {
	return &SecretDatabase{baseDir: baseDir}
}

func (db *SecretDatabase) BaseDir() string {
	return db.baseDir
}

func (db *SecretDatabase) Connection() (*sql.DB, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.conn != nil {
		return db.conn, nil
	}

	conn, err := db.setup()
	if err != nil {
		return nil, err
	}
	db.conn = conn
	return conn, nil
}

func (db *SecretDatabase) CloseConnection() {
	db.mu.Lock()
	defer db.mu.Unlock()

	if db.conn != nil {
		db.conn.Close()
		db.conn = nil
	}
}

func (db *SecretDatabase) setup() (*sql.DB, error) {
	if err := os.MkdirAll(db.baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}
	if err := os.Chmod(db.baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to set directory permissions: %w", err)
	}

	dbPath := filepath.Join(db.baseDir, "db.sqlite3")
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Force file creation
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := os.Chmod(dbPath, 0600); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set file permissions: %w", err)
	}

	if _, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			name TEXT PRIMARY KEY,
			encrypted_data BLOB NOT NULL
		)
	`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create secrets table: %w", err)
	}

	if _, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS auth_cache (
			secret_name TEXT NOT NULL,
			caller_id TEXT NOT NULL,
			timestamp INTEGER NOT NULL,
			expires_at INTEGER NOT NULL DEFAULT 0,
			hmac BLOB NOT NULL,
			PRIMARY KEY (secret_name, caller_id)
		)
	`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create auth_cache table: %w", err)
	}

	if err := migrateAuthCacheExpiresAt(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to migrate auth_cache table: %w", err)
	}

	if _, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS access_log (
			id INTEGER PRIMARY KEY,
			timestamp INTEGER NOT NULL,
			secret_name TEXT NOT NULL,
			caller_id TEXT NOT NULL,
			caller_name TEXT NOT NULL,
			auth TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)
	`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create access_log table: %w", err)
	}

	return conn, nil
}

// migrateAuthCacheExpiresAt adds the expires_at column to auth_cache tables created before it existed.
func migrateAuthCacheExpiresAt(conn *sql.DB) error {
	var count int
	if err := conn.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('auth_cache') WHERE name = 'expires_at'`,
	).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := conn.Exec(`ALTER TABLE auth_cache ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`)
	return err
}
