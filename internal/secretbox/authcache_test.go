package secretbox

import (
	"bytes"
	"testing"
)

func TestAuthCache_UpdateThenValid(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-1", "secret-1")
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
		WithCacheDuration(600),
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1")
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
		WithCacheDuration(600),
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1")

	currentTime = 1600
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid at exactly the duration boundary")
	}
}

func TestAuthCache_DifferentCallers(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-A", "secret-1")

	if !env.Cache.IsValid("caller-A", "secret-1") {
		t.Error("caller-A should be valid")
	}
	if env.Cache.IsValid("caller-B", "secret-1") {
		t.Error("caller-B should not be valid")
	}
}

func TestAuthCache_DifferentSecrets(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-1", "secret-A")

	if !env.Cache.IsValid("caller-1", "secret-A") {
		t.Error("secret-A should be valid")
	}
	if env.Cache.IsValid("caller-1", "secret-B") {
		t.Error("secret-B should not be valid")
	}
}

func TestAuthCache_Invalidate(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Cache.Update("caller-1", "secret-1")
	env.Cache.Update("caller-2", "secret-1")

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
	env.Cache.Update("caller-1", "secret-1")
	env.Cache.Update("caller-1", "secret-2")

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
		WithCacheDuration(600),
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1")

	currentTime = 1500
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid near expiry")
	}

	// Refresh the cache
	env.Cache.Update("caller-1", "secret-1")

	// Past original expiry but within new window
	currentTime = 2000
	if !env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("cache should be valid after refresh")
	}
}

func TestAuthCache_FutureTimestamp(t *testing.T) {
	var currentTime int64 = 2000
	env := makeTestEnvironment(t,
		WithCacheDuration(600),
		WithTimeProvider(func() int64 { return currentTime }),
	)

	env.Cache.Update("caller-1", "secret-1")

	// Time goes backwards (clock skew)
	currentTime = 1999
	if env.Cache.IsValid("caller-1", "secret-1") {
		t.Error("future timestamp should be rejected")
	}
}

func TestAuthCache_BuildMessageDeterministic(t *testing.T) {
	ts := bytes.Repeat([]byte{0x01}, 8)
	msg1 := BuildMessage(ts, "caller", "secret")
	msg2 := BuildMessage(ts, "caller", "secret")
	if !bytes.Equal(msg1, msg2) {
		t.Error("BuildMessage should be deterministic")
	}
}

func TestAuthCache_BuildMessageFormat(t *testing.T) {
	ts := make([]byte, 8)
	msg := BuildMessage(ts, "AB", "XY")

	// 8 bytes timestamp + 4 bytes caller length + 2 bytes "AB" + 2 bytes "XY" = 16
	if len(msg) != 16 {
		t.Errorf("message length = %d, want 16", len(msg))
	}

	// Caller length should be 2 in big endian
	callerLen := msg[8:12]
	expected := []byte{0, 0, 0, 2}
	if !bytes.Equal(callerLen, expected) {
		t.Errorf("caller length bytes = %v, want %v", callerLen, expected)
	}
}

func TestAuthCache_BuildMessageDifferentCallers(t *testing.T) {
	ts := make([]byte, 8)
	msg1 := BuildMessage(ts, "AB", "XY")
	msg2 := BuildMessage(ts, "A", "BXY")
	if bytes.Equal(msg1, msg2) {
		t.Error("messages with different caller/secret split should differ")
	}
}
