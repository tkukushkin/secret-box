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
	key, err := c.authKeyProvider()
	if err != nil {
		return false
	}

	conn, err := c.db.Connection()
	if err != nil {
		return false
	}

	var timestamp, expiresAt int64
	var storedHMAC []byte
	err = conn.QueryRow(
		`SELECT timestamp, expires_at, hmac FROM auth_cache WHERE secret_name = ? AND caller_id = ?`,
		secretName, callerID,
	).Scan(&timestamp, &expiresAt, &storedHMAC)
	if err != nil {
		return false
	}

	now := c.TimeProvider()
	if now > expiresAt || timestamp > now {
		return false
	}

	message := BuildMessage(timestamp, expiresAt, callerID, secretName)
	expectedHMAC := HMACSHA256(key, message)

	return ConstantTimeEqual(expectedHMAC, storedHMAC)
}

// Update records a successful authentication that stays valid for the given duration.
func (c *AuthCache) Update(callerID, secretName string, duration time.Duration) {
	key, err := c.authKeyProvider()
	if err != nil {
		return
	}

	conn, err := c.db.Connection()
	if err != nil {
		return
	}

	timestamp := c.TimeProvider()
	expiresAt := timestamp + int64(duration/time.Second)

	message := BuildMessage(timestamp, expiresAt, callerID, secretName)
	hmacValue := HMACSHA256(key, message)

	_, _ = conn.Exec(
		`INSERT OR REPLACE INTO auth_cache (secret_name, caller_id, timestamp, expires_at, hmac) VALUES (?, ?, ?, ?, ?)`,
		secretName, callerID, timestamp, expiresAt, hmacValue,
	)
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
