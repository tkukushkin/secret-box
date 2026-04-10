package secretbox

import (
	"fmt"
	"strings"
)

// Operations provides high-level secret management operations.
type Operations struct {
	Store     *SecretStore
	Cache     *AuthCache
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
// If once is true, successful authentication is not cached.
func (o *Operations) ReadSecret(name string, once bool) ([]byte, error) {
	if !o.Store.Exists(name) {
		return nil, ErrSecretNotFound
	}

	caller := o.GetCaller()

	if !o.Cache.IsValid(caller.ID, name) {
		reason := fmt.Sprintf(`"%s" wants to access "%s"`, caller.DisplayName, name)
		if err := o.Biometric.Authenticate(reason); err != nil {
			return nil, err
		}
		if !once {
			o.Cache.Update(caller.ID, name)
		}
	}

	return o.Store.Read(name)
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

// EnvMapping maps an environment variable name to a secret name.
type EnvMapping struct {
	VarName    string
	SecretName string
}

// ParseEnvMappings parses "ENV_VAR=secret-name" strings into EnvMapping values.
func ParseEnvMappings(entries []string) ([]EnvMapping, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("at least one env mapping is required")
	}
	mappings := make([]EnvMapping, len(entries))
	for i, entry := range entries {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env mapping '%s': expected format ENV_VAR=secret-name", entry)
		}
		mappings[i] = EnvMapping{VarName: parts[0], SecretName: parts[1]}
	}
	return mappings, nil
}

// ExecParams holds the prepared parameters for exec.
type ExecParams struct {
	Env     map[string]string
	Command []string
}

// PrepareExec reads secrets, handles authentication, and prepares environment
// variables and command arguments for exec.
func (o *Operations) PrepareExec(mappings []EnvMapping, command []string) (*ExecParams, error) {
	// Verify all secrets exist
	for _, m := range mappings {
		if !o.Store.Exists(m.SecretName) {
			return nil, fmt.Errorf("secret '%s' not found", m.SecretName)
		}
	}

	// Check auth cache, collect uncached secrets
	caller := o.GetCaller()
	var uncachedSecrets []string
	for _, m := range mappings {
		if !o.Cache.IsValid(caller.ID, m.SecretName) {
			uncachedSecrets = append(uncachedSecrets, m.SecretName)
		}
	}

	// Single biometric prompt for all uncached secrets
	if len(uncachedSecrets) > 0 {
		quoted := make([]string, len(uncachedSecrets))
		for i, s := range uncachedSecrets {
			quoted[i] = fmt.Sprintf(`"%s"`, s)
		}
		reason := fmt.Sprintf(`"%s" wants to access %s`, caller.DisplayName, strings.Join(quoted, ", "))
		if err := o.Biometric.Authenticate(reason); err != nil {
			return nil, err
		}
		for _, secretName := range uncachedSecrets {
			o.Cache.Update(caller.ID, secretName)
		}
	}

	// Read secrets
	resolved := make(map[string]string)
	for _, m := range mappings {
		data, err := o.Store.Read(m.SecretName)
		if err != nil {
			return nil, err
		}
		for _, b := range data {
			if b == 0 {
				return nil, fmt.Errorf("secret '%s' contains null bytes and cannot be used as environment variable", m.SecretName)
			}
		}
		resolved[m.VarName] = string(data)
	}

	// Expand variables in command arguments
	expandedCommand := ExpandVariables(command, resolved)

	return &ExecParams{
		Env:     resolved,
		Command: expandedCommand,
	}, nil
}
