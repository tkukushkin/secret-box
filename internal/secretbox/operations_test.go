package secretbox

import (
	"errors"
	"testing"
)

func TestWriteSecret(t *testing.T) {
	env := makeTestEnvironment(t)

	// Write a secret
	if err := env.Ops.WriteSecret("key", []byte("value")); err != nil {
		t.Fatalf("WriteSecret error: %v", err)
	}

	// Verify it was stored
	data, err := env.Store.Read("key")
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(data) != "value" {
		t.Errorf("Read() = %q, want %q", data, "value")
	}
}

func TestWriteSecret_InvalidatesCache(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Ops.WriteSecret("key", []byte("v1")); err != nil {
		t.Fatalf("WriteSecret error: %v", err)
	}

	// Cache auth for this secret
	env.Cache.Update("test-caller", "key")
	if !env.Cache.IsValid("test-caller", "key") {
		t.Fatal("cache should be valid after Update")
	}

	// Overwrite secret — cache should be invalidated
	if err := env.Ops.WriteSecret("key", []byte("v2")); err != nil {
		t.Fatalf("WriteSecret error: %v", err)
	}
	if env.Cache.IsValid("test-caller", "key") {
		t.Error("cache should be invalidated after WriteSecret")
	}
}

func TestReadSecret_NotFound(t *testing.T) {
	env := makeTestEnvironment(t)

	_, err := env.Ops.ReadSecret("missing", false)
	if !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got %v", err)
	}
	if env.Biometric.AuthenticateCalled {
		t.Error("biometric should not be called for missing secret")
	}
}

func TestReadSecret_BiometricSuccess(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Store.Write("key", []byte("value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	data, err := env.Ops.ReadSecret("key", false)
	if err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	if string(data) != "value" {
		t.Errorf("ReadSecret() = %q, want %q", data, "value")
	}
	if !env.Biometric.AuthenticateCalled {
		t.Error("biometric should have been called")
	}
	if env.Biometric.LastReason != `"TestApp" wants to access "key"` {
		t.Errorf("reason = %q, want %q", env.Biometric.LastReason, `"TestApp" wants to access "key"`)
	}

	// Auth should be cached now
	if !env.Cache.IsValid("test-caller", "key") {
		t.Error("cache should be valid after successful read")
	}
}

func TestReadSecret_Cached(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Store.Write("key", []byte("value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	env.Cache.Update("test-caller", "key")

	data, err := env.Ops.ReadSecret("key", false)
	if err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	if string(data) != "value" {
		t.Errorf("ReadSecret() = %q, want %q", data, "value")
	}
	if env.Biometric.AuthenticateCalled {
		t.Error("biometric should not be called when cached")
	}
}

func TestReadSecret_Once(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Store.Write("key", []byte("value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	data, err := env.Ops.ReadSecret("key", true)
	if err != nil {
		t.Fatalf("ReadSecret error: %v", err)
	}
	if string(data) != "value" {
		t.Errorf("ReadSecret() = %q, want %q", data, "value")
	}
	if !env.Biometric.AuthenticateCalled {
		t.Error("biometric should have been called")
	}

	// Auth should NOT be cached with once=true
	if env.Cache.IsValid("test-caller", "key") {
		t.Error("cache should not be valid with once=true")
	}
}

func TestReadSecret_BiometricFails(t *testing.T) {
	env := makeTestEnvironment(t)
	env.Biometric.ShouldSucceed = false

	if err := env.Store.Write("key", []byte("value")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	_, err := env.Ops.ReadSecret("key", false)
	if err == nil {
		t.Fatal("expected error when biometric fails")
	}
	if _, ok := err.(*TouchIDError); !ok {
		t.Errorf("expected *TouchIDError, got %T", err)
	}
}

func TestListSecrets(t *testing.T) {
	env := makeTestEnvironment(t)

	for _, name := range []string{"charlie", "alpha", "bravo"} {
		if err := env.Store.Write(name, []byte("x")); err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}

	names := env.Ops.ListSecrets()
	expected := []string{"alpha", "bravo", "charlie"}
	if len(names) != len(expected) {
		t.Fatalf("ListSecrets() returned %d names, want %d", len(names), len(expected))
	}
	for i := range names {
		if names[i] != expected[i] {
			t.Errorf("ListSecrets()[%d] = %s, want %s", i, names[i], expected[i])
		}
	}
}

func TestDeleteSecrets(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Store.Write("exists", []byte("v")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	env.Cache.Update("test-caller", "exists")

	results := env.Ops.DeleteSecrets([]string{"exists", "missing"})

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	// First: deleted successfully
	if results[0].Name != "exists" || results[0].Error != nil {
		t.Errorf("results[0] = %+v, want deleted", results[0])
	}
	if env.Store.Exists("exists") {
		t.Error("secret should be deleted")
	}
	if env.Cache.IsValid("test-caller", "exists") {
		t.Error("cache should be invalidated after delete")
	}

	// Second: not found
	if results[1].Name != "missing" || !errors.Is(results[1].Error, ErrSecretNotFound) {
		t.Errorf("results[1] = %+v, want ErrSecretNotFound", results[1])
	}
}

func TestResetAll(t *testing.T) {
	env := makeTestEnvironment(t)

	if err := env.Store.Write("s1", []byte("v1")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	if err := env.Ops.ResetAll(); err != nil {
		t.Fatalf("ResetAll error: %v", err)
	}

	if len(env.Keychain.Storage) != 0 {
		t.Error("keychain should be empty after reset")
	}
}

func TestParseEnvMappings(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		mappings, err := ParseEnvMappings([]string{"DB_PASS=db-password", "API_KEY=api-key"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if len(mappings) != 2 {
			t.Fatalf("got %d mappings, want 2", len(mappings))
		}
		if mappings[0].VarName != "DB_PASS" || mappings[0].SecretName != "db-password" {
			t.Errorf("mappings[0] = %+v", mappings[0])
		}
		if mappings[1].VarName != "API_KEY" || mappings[1].SecretName != "api-key" {
			t.Errorf("mappings[1] = %+v", mappings[1])
		}
	})

	t.Run("value with equals", func(t *testing.T) {
		mappings, err := ParseEnvMappings([]string{"VAR=name=with=equals"})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if mappings[0].SecretName != "name=with=equals" {
			t.Errorf("SecretName = %q, want %q", mappings[0].SecretName, "name=with=equals")
		}
	})

	t.Run("empty", func(t *testing.T) {
		_, err := ParseEnvMappings(nil)
		if err == nil {
			t.Fatal("expected error for empty entries")
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := ParseEnvMappings([]string{"no-equals"})
		if err == nil {
			t.Fatal("expected error for invalid format")
		}
	})
}

func TestPrepareExec(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		env := makeTestEnvironment(t)
		if err := env.Store.Write("db-pass", []byte("s3cret")); err != nil {
			t.Fatalf("Write error: %v", err)
		}

		params, err := env.Ops.PrepareExec(
			[]EnvMapping{{VarName: "DB_PASS", SecretName: "db-pass"}},
			[]string{"psql", "--password=$(DB_PASS)"},
		)
		if err != nil {
			t.Fatalf("PrepareExec error: %v", err)
		}

		if params.Env["DB_PASS"] != "s3cret" {
			t.Errorf("Env[DB_PASS] = %q, want %q", params.Env["DB_PASS"], "s3cret")
		}
		if len(params.Command) != 2 || params.Command[1] != "--password=s3cret" {
			t.Errorf("Command = %v, want [psql --password=s3cret]", params.Command)
		}
		if !env.Biometric.AuthenticateCalled {
			t.Error("biometric should have been called")
		}
	})

	t.Run("secret not found", func(t *testing.T) {
		env := makeTestEnvironment(t)

		_, err := env.Ops.PrepareExec(
			[]EnvMapping{{VarName: "X", SecretName: "missing"}},
			[]string{"cmd"},
		)
		if err == nil {
			t.Fatal("expected error for missing secret")
		}
	})

	t.Run("all cached", func(t *testing.T) {
		env := makeTestEnvironment(t)
		if err := env.Store.Write("key", []byte("val")); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		env.Cache.Update("test-caller", "key")

		params, err := env.Ops.PrepareExec(
			[]EnvMapping{{VarName: "K", SecretName: "key"}},
			[]string{"cmd"},
		)
		if err != nil {
			t.Fatalf("PrepareExec error: %v", err)
		}
		if env.Biometric.AuthenticateCalled {
			t.Error("biometric should not be called when all cached")
		}
		if params.Env["K"] != "val" {
			t.Errorf("Env[K] = %q, want %q", params.Env["K"], "val")
		}
	})

	t.Run("biometric fails", func(t *testing.T) {
		env := makeTestEnvironment(t)
		env.Biometric.ShouldSucceed = false
		if err := env.Store.Write("key", []byte("val")); err != nil {
			t.Fatalf("Write error: %v", err)
		}

		_, err := env.Ops.PrepareExec(
			[]EnvMapping{{VarName: "K", SecretName: "key"}},
			[]string{"cmd"},
		)
		if err == nil {
			t.Fatal("expected error when biometric fails")
		}
	})

	t.Run("null bytes", func(t *testing.T) {
		env := makeTestEnvironment(t)
		if err := env.Store.Write("bin", []byte("a\x00b")); err != nil {
			t.Fatalf("Write error: %v", err)
		}

		_, err := env.Ops.PrepareExec(
			[]EnvMapping{{VarName: "B", SecretName: "bin"}},
			[]string{"cmd"},
		)
		if err == nil {
			t.Fatal("expected error for null bytes")
		}
	})

	t.Run("multiple secrets partial cache", func(t *testing.T) {
		env := makeTestEnvironment(t)
		if err := env.Store.Write("s1", []byte("v1")); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		if err := env.Store.Write("s2", []byte("v2")); err != nil {
			t.Fatalf("Write error: %v", err)
		}
		// Only cache s1
		env.Cache.Update("test-caller", "s1")

		params, err := env.Ops.PrepareExec(
			[]EnvMapping{
				{VarName: "A", SecretName: "s1"},
				{VarName: "B", SecretName: "s2"},
			},
			[]string{"cmd"},
		)
		if err != nil {
			t.Fatalf("PrepareExec error: %v", err)
		}
		if !env.Biometric.AuthenticateCalled {
			t.Error("biometric should be called for uncached s2")
		}
		if params.Env["A"] != "v1" || params.Env["B"] != "v2" {
			t.Errorf("Env = %v", params.Env)
		}
	})
}
