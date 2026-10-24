//go:build darwin

package secretbox

/*
#cgo LDFLAGS: -framework Cocoa -framework LocalAuthentication -framework LocalAuthenticationEmbeddedUI -framework CoreGraphics
#include <stdlib.h>
#include "prompt.h"
*/
import "C"

import (
	"fmt"
	"os"
	"strings"
	"unsafe"
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
	Authenticate(caller CallerIdentity, secrets []string) error
}

// SystemBiometricAuth shows the native Touch ID window naming the caller and secrets,
// returning nil only on a successful biometric.
type SystemBiometricAuth struct{}

func (s SystemBiometricAuth) Authenticate(caller CallerIdentity, secrets []string) error {
	iconPath := caller.IconPath
	if iconPath == "" {
		iconPath, _ = os.Executable()
	}
	action := "wants to access secret"
	if len(secrets) > 1 {
		action = "wants to access secrets"
	}
	subject := strings.Join(secrets, "\n")
	quoted := make([]string, len(secrets))
	for i, name := range secrets {
		quoted[i] = fmt.Sprintf(`"%s"`, name)
	}
	reason := fmt.Sprintf(`"%s" wants to access %s`, caller.DisplayName, strings.Join(quoted, ", "))

	cName := C.CString(caller.DisplayName)
	cIcon := C.CString(iconPath)
	cAction := C.CString(action)
	cSubject := C.CString(subject)
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cName))
	defer C.free(unsafe.Pointer(cIcon))
	defer C.free(unsafe.Pointer(cAction))
	defer C.free(unsafe.Pointer(cSubject))
	defer C.free(unsafe.Pointer(cReason))

	res := C.ShowTouchIDPrompt(cName, cIcon, cAction, cSubject, cReason)

	switch res.verdict {
	case C.PROMPT_ALLOWED:
		return nil
	case C.PROMPT_CANCELLED:
		return &TouchIDError{Message: "authentication cancelled"}
	case C.PROMPT_TIMEDOUT:
		return &TouchIDError{Message: "authentication timed out"}
	case C.PROMPT_NO_WINDOW_SERVER:
		return &TouchIDError{Message: "no window server (cannot display Touch ID prompt)"}
	case C.PROMPT_NO_GLYPH:
		return &TouchIDError{Message: "could not embed Touch ID view"}
	default:
		return &TouchIDError{Message: fmt.Sprintf("authentication failed (LAError %d)", int(res.code))}
	}
}
