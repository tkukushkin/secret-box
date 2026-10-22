package secretbox

import (
	"fmt"
	"strings"
	"time"
)

// Operations provides high-level secret management operations.
type Operations struct {
	Store     *SecretStore
	Cache     *AuthCache
	Log       *AccessLog
	Biometric BiometricAuth
	GetCaller func() CallerIdentity
}

// WriteSecret writes a secret and invalidates its auth cache.
func (o *Operations) WriteSecret(name string, data []byte) error {
	if err := o.Store.Write(name, data); err != nil {
		return err
	}
	o.Cache.Invalidate(name)
	return nil
}

// ReadSecret reads a secret, authenticating via biometrics if not cached.
// A successful authentication is cached for authDuration; zero disables caching.
func (o *Operations) ReadSecret(name string, authDuration time.Duration) ([]byte, error) {
	if !o.Store.Exists(name) {
		return nil, ErrSecretNotFound
	}

	caller := o.GetCaller()

	entry := AccessLogEntry{SecretName: name, Caller: caller, Auth: AuthCached}
	if expiresAt, ok := o.Cache.Lookup(caller.ID, name); ok {
		entry.ExpiresAt = expiresAt
	} else {
		reason := fmt.Sprintf(`"%s" wants to access "%s"`, caller.DisplayName, name)
		if err := o.Biometric.Authenticate(reason); err != nil {
			return nil, err
		}
		entry.Auth = AuthTouchID
		if authDuration > 0 {
			entry.ExpiresAt = o.Cache.Update(caller.ID, name, authDuration)
		}
	}

	data, err := o.Store.Read(name)
	if err != nil {
		return nil, err
	}
	if err := o.Log.Record(entry); err != nil {
		return nil, fmt.Errorf("failed to write access log: %w", err)
	}
	return data, nil
}

// AccessLog returns up to limit recorded secret reads, newest first.
// An empty secretName matches all secrets; a non-positive limit returns all entries.
func (o *Operations) AccessLog(secretName string, limit int) ([]AccessLogEntry, error) {
	return o.Log.List(secretName, limit)
}

// ListSecrets returns all secret names sorted alphabetically.
func (o *Operations) ListSecrets() []string {
	return o.Store.List()
}

// DeleteResult holds the outcome of deleting a single secret.
type DeleteResult struct {
	Name  string
	Error error
}

// DeleteSecrets deletes the named secrets, returning per-name results.
func (o *Operations) DeleteSecrets(names []string) []DeleteResult {
	results := make([]DeleteResult, len(names))
	for i, name := range names {
		results[i].Name = name
		if !o.Store.Exists(name) {
			results[i].Error = ErrSecretNotFound
			continue
		}
		if err := o.Store.Delete(name); err != nil {
			results[i].Error = err
			continue
		}
		o.Cache.Invalidate(name)
	}
	return results
}

// ResetAll removes all secrets, auth cache, and the master key.
func (o *Operations) ResetAll() error {
	return o.Store.ResetAll()
}

// ClearAuthCache removes all auth cache entries.
func (o *Operations) ClearAuthCache() error {
	return o.Cache.InvalidateAll()
}

// ExecParams holds the prepared parameters for exec.
type ExecParams struct {
	Env     map[string]string
	Command []string
}

// PrepareExec scans environ and command for $(secret-name) references,
// resolves the secrets (authenticating via biometrics if needed),
// and returns the modified environment variables and expanded command.
// A successful authentication is cached for authDuration; zero disables caching.
func (o *Operations) PrepareExec(environ []string, command []string, authDuration time.Duration) (*ExecParams, error) {
	// Parse environment into keys and values
	envKeys := make([]string, 0, len(environ))
	envValues := make([]string, 0, len(environ))
	for _, entry := range environ {
		if k, v, ok := strings.Cut(entry, "="); ok {
			envKeys = append(envKeys, k)
			envValues = append(envValues, v)
		}
	}

	// Find all $(secret-name) references in env values and command args
	allStrings := make([]string, 0, len(envValues)+len(command))
	allStrings = append(allStrings, envValues...)
	allStrings = append(allStrings, command...)
	secretNames := FindSecretRefs(allStrings)

	if len(secretNames) == 0 {
		return nil, fmt.Errorf("no secret references found (use $(secret-name) syntax in environment variables or command arguments)")
	}

	// Verify all secrets exist
	for _, name := range secretNames {
		if !o.Store.Exists(name) {
			return nil, fmt.Errorf("secret '%s' not found", name)
		}
	}

	// Check auth cache, collect uncached secrets
	caller := o.GetCaller()
	logEntries := make([]AccessLogEntry, len(secretNames))
	var uncachedSecrets []int
	for i, name := range secretNames {
		logEntries[i] = AccessLogEntry{SecretName: name, Caller: caller, Auth: AuthCached}
		if expiresAt, ok := o.Cache.Lookup(caller.ID, name); ok {
			logEntries[i].ExpiresAt = expiresAt
		} else {
			logEntries[i].Auth = AuthTouchID
			uncachedSecrets = append(uncachedSecrets, i)
		}
	}

	// Single biometric prompt for all uncached secrets
	if len(uncachedSecrets) > 0 {
		quoted := make([]string, len(uncachedSecrets))
		for i, idx := range uncachedSecrets {
			quoted[i] = fmt.Sprintf(`"%s"`, secretNames[idx])
		}
		reason := fmt.Sprintf(`"%s" wants to access %s`, caller.DisplayName, strings.Join(quoted, ", "))
		if err := o.Biometric.Authenticate(reason); err != nil {
			return nil, err
		}
		if authDuration > 0 {
			for _, idx := range uncachedSecrets {
				logEntries[idx].ExpiresAt = o.Cache.Update(caller.ID, secretNames[idx], authDuration)
			}
		}
	}

	// Read secrets
	secrets := make(map[string]string)
	for _, name := range secretNames {
		data, err := o.Store.Read(name)
		if err != nil {
			return nil, err
		}
		for _, b := range data {
			if b == 0 {
				return nil, fmt.Errorf("secret '%s' contains null bytes and cannot be used as environment variable", name)
			}
		}
		secrets[name] = string(data)
	}
	if err := o.Log.Record(logEntries...); err != nil {
		return nil, fmt.Errorf("failed to write access log: %w", err)
	}

	// Expand secret references in env values, collect only modified vars
	expandedValues := ExpandVariables(envValues, secrets)
	env := make(map[string]string)
	for i, val := range expandedValues {
		if val != envValues[i] {
			env[envKeys[i]] = val
		}
	}

	// Expand secret references in command args
	expandedCommand := ExpandVariables(command, secrets)

	return &ExecParams{
		Env:     env,
		Command: expandedCommand,
	}, nil
}
