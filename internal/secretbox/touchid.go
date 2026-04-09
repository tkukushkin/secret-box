//go:build darwin

package secretbox

import (
	"fmt"

	touchid "github.com/lox/go-touchid"
)

// TouchIDError represents a biometric authentication failure.
type TouchIDError struct {
	Message string
}

func (e *TouchIDError) Error() string {
	return fmt.Sprintf("Touch ID: %s", e.Message)
}

// BiometricAuth abstracts biometric authentication.
type BiometricAuth interface {
	Authenticate(reason string) error
}

// SystemBiometricAuth provides real Touch ID authentication.
type SystemBiometricAuth struct{}

func (s SystemBiometricAuth) Authenticate(reason string) error {
	ok, err := touchid.Authenticate(reason)
	if err != nil {
		return &TouchIDError{Message: err.Error()}
	}
	if !ok {
		return &TouchIDError{Message: "Authentication failed"}
	}
	return nil
}
