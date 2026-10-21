package secretbox

import (
	"bytes"
	"testing"
	"time"
)

func TestAuthCache_UpdateThenValid(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-1", "secret-1", DefaultAuthDuration)
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid after update")
	}
}

func TestAuthCache_NonExistent(t *testing.T) {
	env := makeTestEnvironment(t)
	if _, err := env.DB.Connection(); err != nil {
		t.Fatalf("Connection error: %v", err)
	}
	if env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("non-existent cache entry should not be valid")
	}
}

func TestAuthCache_Expired(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t,
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1", 600*time.Second)
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid immediately after update")
	}

	currentTime = 1601
	if env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be expired after duration")
	}
}

func TestAuthCache_AtExactDuration(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t,
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1", 600*time.Second)

	currentTime = 1600
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid at exactly the duration boundary")
	}
}

func TestAuthCache_DifferentCallers(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-A", "secret-1", DefaultAuthDuration)

	if !env.Cache.IsValid("caller-A", "secret-1") {
		t.Error("caller-A should be valid")
	}
	if env.Cache.IsValid("caller-B", "secret-1") {
		t.Error("caller-B should not be valid")
	}
}

func TestAuthCache_DifferentSecrets(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-1", "secret-A", DefaultAuthDuration)

	if !env.Cache.IsValid("caller-1", "secret-A") {
		t.Error("secret-A should be valid")
	}
	if env.Cache.IsValid("caller-1", "secret-B") {
		t.Error("secret-B should not be valid")
	}
}

func TestAuthCache_Invalidate(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-1", "secret-1", DefaultAuthDuration)
	env.Cache.Update("caller-2", "secret-1", DefaultAuthDuration)

	env.Cache.Invalidate("secret-1")

	if env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("caller-1 should not be valid after invalidation")
	}
	if env.Cache.IsValid("caller-2", "secret-1") {
		t.Error("caller-2 should not be valid after invalidation")
	}
}

func TestAuthCache_InvalidateIsolated(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-1", "secret-1", DefaultAuthDuration)
	env.Cache.Update("caller-1", "secret-2", DefaultAuthDuration)

	env.Cache.Invalidate("secret-1")

	if env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("secret-1 should not be valid after invalidation")
	}
	if !env.Cache.IsValid("caller-1", "secret-2") {
		t.Error("secret-2 should still be valid")
	}
}

func TestAuthCache_UpdateRefreshes(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t,
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1", 600*time.Second)

	currentTime = 1500
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid near expiry")
	}

	// Refresh the cache
	env.Cache.Update("caller-1", "secret-1", 600*time.Second)

	// Past original expiry but within new window
	currentTime = 2000
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid after refresh")
	}
}

func TestAuthCache_FutureTimestamp(t *testing.T) {
	var currentTime int64 = 2000
	env := makeTestEnvironment(t,
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1", 600*time.Second)

	// Time goes backwards (clock skew)
	currentTime = 1999
	if env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("future timestamp should be rejected")
	}
}

func TestAuthCache_PerEntryDuration(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t,
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "short", 60*time.Second)
	env.Cache.Update("caller-1", "long", time.Hour)

	currentTime = 1061
	if env.Cache.IsValid("caller-1", "short") {
		t.Error("short entry should be expired")
	}
	if !env.Cache.IsValid("caller-1", "long") {
		t.Error("long entry should still be valid")
	}
}

func TestAuthCache_TamperedExpiry(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t,
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1", 60*time.Second)

	conn, err := env.DB.Connection()
	if err != nil {
		t.Fatalf("Connection error: %v", err)
	}
	if _, err := conn.Exec(`UPDATE auth_cache SET expires_at = expires_at + 3600`); err != nil {
		t.Fatalf("Exec error: %v", err)
	}

	if env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("entry with tampered expires_at should be rejected")
	}
}

func TestAuthCache_BuildMessageDeterministic(t *testing.T) {
	msg1 := BuildMessage(1, 2, "caller", "secret")
	msg2 := BuildMessage(1, 2, "caller", "secret")
	if !bytes.Equal(msg1, msg2) {
		t.Error("BuildMessage should be deterministic")
	}
}

func TestAuthCache_BuildMessageFormat(t *testing.T) {
	msg := BuildMessage(1, 2, "AB", "XY")

	// 8 bytes timestamp + 8 bytes expires_at + 4 bytes caller length + 2 bytes "AB" + 2 bytes "XY" = 24
	if len(msg) != 24 {
		t.Errorf("message length = %d, want 24", len(msg))
	}

	if !bytes.Equal(msg[0:8], []byte{1, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("timestamp bytes = %v", msg[0:8])
	}
	if !bytes.Equal(msg[8:16], []byte{2, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("expires_at bytes = %v", msg[8:16])
	}

	// Caller length should be 2 in big endian
	callerLen := msg[16:20]
	expected := []byte{0, 0, 0, 2}
	if !bytes.Equal(callerLen, expected) {
		t.Errorf("caller length bytes = %v, want %v", callerLen, expected)
	}
}

func TestAuthCache_BuildMessageDifferentCallers(t *testing.T) {
	msg1 := BuildMessage(0, 0, "AB", "XY")
	msg2 := BuildMessage(0, 0, "A", "BXY")
	if bytes.Equal(msg1, msg2) {
		t.Error("messages with different caller/secret split should differ")
	}
}
