package secretbox

import (
	"encoding/binary"
	"time"
)

const DefaultCacheDuration int64 = 600

// AuthCache provides per-app, per-secret authentication caching with HMAC integrity.
type AuthCache struct {
	db              *SecretDatabase
	authKeyProvider func() ([]byte, error)
	cacheDuration   int64
	TimeProvider    func() int64
}

type CacheOption func(*AuthCache)

func WithCacheDuration(d int64) CacheOption {
	return func(c *AuthCache) { c.cacheDuration = d }
}

func WithTimeProvider(tp func() int64) CacheOption {
	return func(c *AuthCache) { c.TimeProvider = tp }
}

func NewAuthCache(db *SecretDatabase, authKeyProvider func() ([]byte, error), opts ...CacheOption) *AuthCache {
	c := &AuthCache{
		db:              db,
		authKeyProvider: authKeyProvider,
		cacheDuration:   DefaultCacheDuration,
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

	var timestamp int64
	var storedHMAC []byte
	err = conn.QueryRow(
		`SELECT timestamp, hmac FROM auth_cache WHERE secret_name = ? AND caller_id = ?`,
		secretName, callerID,
	).Scan(&timestamp, &storedHMAC)
	if err != nil {
		return false
	}

	now := c.TimeProvider()
	if now-timestamp > c.cacheDuration || timestamp > now {
		return false
	}

	timestampData := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampData, uint64(timestamp))

	message := BuildMessage(timestampData, callerID, secretName)
	expectedHMAC := HMACSHA256(key, message)

	return ConstantTimeEqual(expectedHMAC, storedHMAC)
}

func (c *AuthCache) Update(callerID, secretName string) {
	key, err := c.authKeyProvider()
	if err != nil {
		return
	}

	conn, err := c.db.Connection()
	if err != nil {
		return
	}

	timestamp := c.TimeProvider()
	timestampData := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestampData, uint64(timestamp))

	message := BuildMessage(timestampData, callerID, secretName)
	hmacValue := HMACSHA256(key, message)

	_, _ = conn.Exec(
		`INSERT OR REPLACE INTO auth_cache (secret_name, caller_id, timestamp, hmac) VALUES (?, ?, ?, ?)`,
		secretName, callerID, timestamp, hmacValue,
	)
}

func (c *AuthCache) Invalidate(secretName string) {
	conn, err := c.db.Connection()
	if err != nil {
		return
	}
	_, _ = conn.Exec(`DELETE FROM auth_cache WHERE secret_name = ?`, secretName)
}

// BuildMessage constructs the HMAC message for cache validation.
// Format: timestamp (8 bytes LE) || caller_length (4 bytes BE) || caller_id || secret_name
func BuildMessage(timestampData []byte, callerID, secretName string) []byte {
	callerData := []byte(callerID)
	nameData := []byte(secretName)

	callerLen := make([]byte, 4)
	binary.BigEndian.PutUint32(callerLen, uint32(len(callerData)))

	message := make([]byte, 0, len(timestampData)+4+len(callerData)+len(nameData))
	message = append(message, timestampData...)
	message = append(message, callerLen...)
	message = append(message, callerData...)
	message = append(message, nameData...)

	return message
}
