package secretbox

import (
	"reflect"
	"testing"
	"time"
)

func TestAccessLog_RecordAndList(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t, WithTimeProvider(func() int64 { return currentTime }))

	caller := CallerIdentity{ID: "caller-1", DisplayName: "App1"}
	if err := env.Log.Record(AccessLogEntry{SecretName: "a", Caller: caller, Auth: AuthTouchID, ExpiresAt: 1600}); err != nil {
		t.Fatalf("Record error: %v", err)
	}
	currentTime = 1100
	if err := env.Log.Record(
		AccessLogEntry{SecretName: "b", Caller: caller, Auth: AuthCached, ExpiresAt: 1600},
		AccessLogEntry{SecretName: "a", Caller: caller, Auth: AuthTouchID},
	); err != nil {
		t.Fatalf("Record error: %v", err)
	}

	entries, err := env.Log.List("", 0)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	want := []AccessLogEntry{
		{Timestamp: 1100, SecretName: "a", Caller: caller, Auth: AuthTouchID},
		{Timestamp: 1100, SecretName: "b", Caller: caller, Auth: AuthCached, ExpiresAt: 1600},
		{Timestamp: 1000, SecretName: "a", Caller: caller, Auth: AuthTouchID, ExpiresAt: 1600},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("List() = %+v, want %+v", entries, want)
	}
}

func TestAccessLog_ListFilterAndLimit(t *testing.T) {
	env := makeTestEnvironment(t)

	for _, name := range []string{"a", "b", "a", "a"} {
		if err := env.Log.Record(AccessLogEntry{SecretName: name, Auth: AuthCached}); err != nil {
			t.Fatalf("Record error: %v", err)
		}
	}

	entries, err := env.Log.List("a", 0)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("List(a) returned %d entries, want 3", len(entries))
	}

	entries, err = env.Log.List("", 2)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("List with limit 2 returned %d entries, want 2", len(entries))
	}
}

func TestAccessLog_ListEmpty(t *testing.T) {
	env := makeTestEnvironment(t)

	entries, err := env.Log.List("", 0)
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List() = %+v, want none", entries)
	}
}

func TestAccessLog_ReadSecret(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t, WithTimeProvider(func() int64 { return currentTime }))
	caller := CallerIdentity{ID: "test-caller", DisplayName: "TestApp"}

	if err := env.Store.Write("key", []byte("value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	if _, err := env.Ops.ReadSecret("key", DefaultAuthDuration); err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	currentTime = 1100
	if _, err := env.Ops.ReadSecret("key", 0); err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	if err := env.Ops.ClearAuthCache(); err != nil {
		t.Fatalf("ClearAuthCache error: %v", err)
	}
	currentTime = 1200
	if _, err := env.Ops.ReadSecret("key", 0); err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}

	entries, err := env.Ops.AccessLog("", 0)
	if err != nil {
		t.Fatalf("AccessLog error: %v", err)
	}
	want := []AccessLogEntry{
		{Timestamp: 1200, SecretName: "key", Caller: caller, Auth: AuthTouchID},
		{Timestamp: 1100, SecretName: "key", Caller: caller, Auth: AuthCached, ExpiresAt: 1600},
		{Timestamp: 1000, SecretName: "key", Caller: caller, Auth: AuthTouchID, ExpiresAt: 1600},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("AccessLog() = %+v, want %+v", entries, want)
	}
}

func TestAccessLog_ReadSecretNotRecordedOnFailure(t *testing.T) {
	env := makeTestEnvironment(t)

	if _, err := env.Ops.ReadSecret("missing", DefaultAuthDuration); err == nil {
		t.Fatal("expected error for missing secret")
	}

	if err := env.Store.Write("key", []byte("value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	env.Biometric.ShouldSucceed = false
	if _, err := env.Ops.ReadSecret("key", DefaultAuthDuration); err == nil {
		t.Fatal("expected error when biometric fails")
	}

	entries, err := env.Ops.AccessLog("", 0)
	if err != nil {
		t.Fatalf("AccessLog error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("AccessLog() = %+v, want none", entries)
	}
}

func TestAccessLog_PrepareExec(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t, WithTimeProvider(func() int64 { return currentTime }))
	caller := CallerIdentity{ID: "test-caller", DisplayName: "TestApp"}

	for _, name := range []string{"s1", "s2"} {
		if err := env.Store.Write(name, []byte("v")); err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}
	env.Cache.Update("test-caller", "s1", DefaultAuthDuration)

	currentTime = 1100
	if _, err := env.Ops.PrepareExec([]string{"A=$(s1)", "B=$(s2)"}, []string{"cmd"}, 0); err != nil {
		t.Fatalf("PrepareExec error: %v", err)
	}

	entries, err := env.Ops.AccessLog("", 0)
	if err != nil {
		t.Fatalf("AccessLog error: %v", err)
	}
	want := []AccessLogEntry{
		{Timestamp: 1100, SecretName: "s2", Caller: caller, Auth: AuthTouchID},
		{Timestamp: 1100, SecretName: "s1", Caller: caller, Auth: AuthCached, ExpiresAt: 1600},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("AccessLog() = %+v, want %+v", entries, want)
	}
}

func TestAccessLog_PrepareExecCachesTouchID(t *testing.T) {
	var currentTime int64 = 1000
	env := makeTestEnvironment(t, WithTimeProvider(func() int64 { return currentTime }))
	caller := CallerIdentity{ID: "test-caller", DisplayName: "TestApp"}

	for _, name := range []string{"s1", "s2", "s3"} {
		if err := env.Store.Write(name, []byte("v")); err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}
	env.Cache.Update("test-caller", "s2", DefaultAuthDuration)

	currentTime = 1100
	if _, err := env.Ops.PrepareExec([]string{"A=$(s1)", "B=$(s2)", "C=$(s3)"}, []string{"cmd"}, time.Hour); err != nil {
		t.Fatalf("PrepareExec error: %v", err)
	}

	entries, err := env.Ops.AccessLog("", 0)
	if err != nil {
		t.Fatalf("AccessLog error: %v", err)
	}
	want := []AccessLogEntry{
		{Timestamp: 1100, SecretName: "s3", Caller: caller, Auth: AuthTouchID, ExpiresAt: 4700},
		{Timestamp: 1100, SecretName: "s2", Caller: caller, Auth: AuthCached, ExpiresAt: 1600},
		{Timestamp: 1100, SecretName: "s1", Caller: caller, Auth: AuthTouchID, ExpiresAt: 4700},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Errorf("AccessLog() = %+v, want %+v", entries, want)
	}
}
