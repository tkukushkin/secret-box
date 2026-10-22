package secretbox

import (
	"encoding/binary"
	"time"
)

const DefaultAuthDuration = 10 * time.Minute

// AuthCache provides per-app, per-secret authentication caching with HMAC integrity.
type AuthCache struct {
	db              *SecretDatabase
	authKeyProvider func() ([]byte, error)
	TimeProvider    func() int64
}

type CacheOption func(*AuthCache)

func WithTimeProvider(tp func() int64) CacheOption {
	return func(c *AuthCache) { c.TimeProvider = tp }
}

func NewAuthCache(db *SecretDatabase, authKeyProvider func() ([]byte, error), opts ...CacheOption) *AuthCache {
	c := &AuthCache{
		db:              db,
		authKeyProvider: authKeyProvider,
		TimeProvider:    func() int64 { return time.Now().Unix() },
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *AuthCache) IsValid(callerID, secretName string) bool {
	_, ok := c.Lookup(callerID, secretName)
	return ok
}

// Lookup returns the expiry of a valid cached authentication.
func (c *AuthCache) Lookup(callerID, secretName string) (expiresAt int64, ok bool) {
	key, err := c.authKeyProvider()
	if err != nil {
		return 0, false
	}

	conn, err := c.db.Connection()
	if err != nil {
		return 0, false
	}

	var timestamp int64
	var storedHMAC []byte
	err = conn.QueryRow(
		`SELECT timestamp, expires_at, hmac FROM auth_cache WHERE secret_name = ? AND caller_id = ?`,
		secretName, callerID,
	).Scan(&timestamp, &expiresAt, &storedHMAC)
	if err != nil {
		return 0, false
	}

	now := c.TimeProvider()
	if now > expiresAt || timestamp > now {
		return 0, false
	}

	message := BuildMessage(timestamp, expiresAt, callerID, secretName)
	expectedHMAC := HMACSHA256(key, message)

	if !ConstantTimeEqual(expectedHMAC, storedHMAC) {
		return 0, false
	}
	return expiresAt, true
}

// Update records a successful authentication that stays valid for the given duration.
// It returns the expiry of the stored entry, or 0 if nothing was stored.
func (c *AuthCache) Update(callerID, secretName string, duration time.Duration) int64 {
	key, err := c.authKeyProvider()
	if err != nil {
		return 0
	}

	conn, err := c.db.Connection()
	if err != nil {
		return 0
	}

	timestamp := c.TimeProvider()
	expiresAt := timestamp + int64(duration/time.Second)

	message := BuildMessage(timestamp, expiresAt, callerID, secretName)
	hmacValue := HMACSHA256(key, message)

	if _, err := conn.Exec(
		`INSERT OR REPLACE INTO auth_cache (secret_name, caller_id, timestamp, expires_at, hmac) VALUES (?, ?, ?, ?, ?)`,
		secretName, callerID, timestamp, expiresAt, hmacValue,
	); err != nil {
		return 0
	}
	return expiresAt
}

func (c *AuthCache) Invalidate(secretName string) {
	conn, err := c.db.Connection()
	if err != nil {
		return
	}
	_, _ = conn.Exec(`DELETE FROM auth_cache WHERE secret_name = ?`, secretName)
}

// InvalidateAll removes all entries from the auth cache.
func (c *AuthCache) InvalidateAll() error {
	conn, err := c.db.Connection()
	if err != nil {
		return err
	}
	_, err = conn.Exec(`DELETE FROM auth_cache`)
	return err
}

// BuildMessage constructs the HMAC message for cache validation.
// Format: timestamp (8 bytes LE) || expires_at (8 bytes LE) || caller_length (4 bytes BE) || caller_id || secret_name
func BuildMessage(timestamp, expiresAt int64, callerID, secretName string) []byte {
	callerData := []byte(callerID)
	nameData := []byte(secretName)

	message := make([]byte, 0, 8+8+4+len(callerData)+len(nameData))
	message = binary.LittleEndian.AppendUint64(message, uint64(timestamp))
	message = binary.LittleEndian.AppendUint64(message, uint64(expiresAt))
	message = binary.BigEndian.AppendUint32(message, uint32(len(callerData)))
	message = append(message, callerData...)
	message = append(message, nameData...)

	return message
}
