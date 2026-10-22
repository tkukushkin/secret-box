package secretbox

import (
	"time"
)

// AuthMethod tells how a secret read was authorized.
type AuthMethod string

const (
	AuthTouchID AuthMethod = "touch_id"
	AuthCached  AuthMethod = "cached"
)

// AccessLogEntry is a single recorded secret read.
type AccessLogEntry struct {
	Timestamp  int64
	SecretName string
	Caller     CallerIdentity
	Auth       AuthMethod
	// ExpiresAt is when the authorization used for the read expires; 0 means it was not cached.
	ExpiresAt int64
}

// AccessLog records secret reads.
type AccessLog struct {
	db           *SecretDatabase
	TimeProvider func() int64
}

type AccessLogOption func(*AccessLog)

func WithAccessLogTimeProvider(tp func() int64) AccessLogOption {
	return func(l *AccessLog) { l.TimeProvider = tp }
}

func NewAccessLog(db *SecretDatabase, opts ...AccessLogOption) *AccessLog {
	l := &AccessLog{
		db:           db,
		TimeProvider: func() int64 { return time.Now().Unix() },
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Record stores entries with the current time as their timestamp.
func (l *AccessLog) Record(entries ...AccessLogEntry) error {
	conn, err := l.db.Connection()
	if err != nil {
		return err
	}

	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := l.TimeProvider()
	for _, e := range entries {
		if _, err := tx.Exec(
			`INSERT INTO access_log (timestamp, secret_name, caller_id, caller_name, auth, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			now, e.SecretName, e.Caller.ID, e.Caller.DisplayName, string(e.Auth), e.ExpiresAt,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// List returns up to limit entries, newest first. An empty secretName matches all secrets;
// a non-positive limit returns all entries.
func (l *AccessLog) List(secretName string, limit int) ([]AccessLogEntry, error) {
	conn, err := l.db.Connection()
	if err != nil {
		return nil, err
	}

	query := `SELECT timestamp, secret_name, caller_id, caller_name, auth, expires_at FROM access_log`
	var args []any
	if secretName != "" {
		query += ` WHERE secret_name = ?`
		args = append(args, secretName)
	}
	query += ` ORDER BY id DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}

	rows, err := conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AccessLogEntry
	for rows.Next() {
		var e AccessLogEntry
		var auth string
		if err := rows.Scan(&e.Timestamp, &e.SecretName, &e.Caller.ID, &e.Caller.DisplayName, &auth, &e.ExpiresAt); err != nil {
			return nil, err
		}
		e.Auth = AuthMethod(auth)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
