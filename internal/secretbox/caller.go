//go:build darwin

package secretbox

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <libproc.h>
#include <sys/sysctl.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static int get_path_for_pid(int pid, char *buf, int bufsize) {
	return proc_pidpath(pid, buf, (uint32_t)bufsize);
}

static int get_parent_pid(int pid) {
	struct kinfo_proc info;
	size_t length = sizeof(info);
	int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
	if (sysctl(mib, 4, &info, &length, NULL, 0) != 0 || length == 0) {
		return 0;
	}
	return info.kp_eproc.e_ppid;
}

static int get_signing_identity(const char *path, char *team_id, int team_id_size, char *signing_id, int signing_id_size) {
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8*)path, strlen(path), false);
	if (!url) return -1;

	SecStaticCodeRef staticCode = NULL;
	OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
	CFRelease(url);
	if (status != errSecSuccess || !staticCode) return -1;

	CFDictionaryRef info = NULL;
	status = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &info);
	CFRelease(staticCode);
	if (status != errSecSuccess || !info) return -1;

	CFStringRef teamRef = (CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
	if (teamRef && CFGetTypeID(teamRef) == CFStringGetTypeID()) {
		CFStringGetCString(teamRef, team_id, team_id_size, kCFStringEncodingUTF8);
	} else {
		team_id[0] = '\0';
	}

	CFStringRef idRef = (CFStringRef)CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
	if (idRef && CFGetTypeID(idRef) == CFStringGetTypeID()) {
		CFStringGetCString(idRef, signing_id, signing_id_size, kCFStringEncodingUTF8);
	} else {
		signing_id[0] = '\0';
	}

	CFRelease(info);
	return 0;
}
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

func getPathForPid(pid int32) string {
	buf := make([]byte, 4096)
	ret := C.get_path_for_pid(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if ret <= 0 {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
}

func getParentPid(pid int32) int32 {
	return int32(C.get_parent_pid(C.int(pid)))
}

// ExtractAppBundle extracts the .app bundle path from a full executable path.
func ExtractAppBundle(path string) string {
	idx := strings.Index(path, ".app/")
	if idx >= 0 {
		return path[:idx] + ".app"
	}
	if strings.HasSuffix(path, ".app") {
		return path
	}
	return ""
}

func findResponsibleAppPath() string {
	pid := int32(os.Getppid())

	for pid > 1 {
		path := getPathForPid(pid)
		if path != "" {
			if bundle := ExtractAppBundle(path); bundle != "" {
				return bundle
			}
		}
		pid = getParentPid(pid)
	}

	return getPathForPid(int32(os.Getppid()))
}

func getSigningIdentity(path string) string {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	teamID := make([]byte, 256)
	signingID := make([]byte, 256)

	ret := C.get_signing_identity(
		cPath,
		(*C.char)(unsafe.Pointer(&teamID[0])), C.int(len(teamID)),
		(*C.char)(unsafe.Pointer(&signingID[0])), C.int(len(signingID)),
	)
	if ret != 0 {
		return ""
	}

	team := C.GoString((*C.char)(unsafe.Pointer(&teamID[0])))
	signing := C.GoString((*C.char)(unsafe.Pointer(&signingID[0])))

	if signing == "" {
		return ""
	}
	if team != "" {
		return fmt.Sprintf("signed:%s:%s", team, signing)
	}
	return fmt.Sprintf("signed::%s", signing)
}

// CallerIdentity identifies the calling application.
type CallerIdentity struct {
	ID          string
	DisplayName string
}

// CurrentCallerIdentity walks the process tree to identify the responsible app.
func CurrentCallerIdentity() CallerIdentity {
	appPath := findResponsibleAppPath()

	var displayName string
	if appPath != "" {
		if bundle := ExtractAppBundle(appPath); bundle != "" {
			base := filepath.Base(bundle)
			displayName = strings.TrimSuffix(base, ".app")
		} else {
			displayName = filepath.Base(appPath)
		}
	} else {
		displayName = "Unknown app"
	}

	var callerID string
	if appPath != "" {
		bundle := ExtractAppBundle(appPath)
		if bundle != "" {
			if sigID := getSigningIdentity(bundle); sigID != "" {
				callerID = sigID
			} else if sigID := getSigningIdentity(appPath); sigID != "" {
				callerID = sigID
			} else {
				callerID = "path:" + SHA256Hex(appPath)
			}
		} else {
			if sigID := getSigningIdentity(appPath); sigID != "" {
				callerID = sigID
			} else {
				callerID = "path:" + SHA256Hex(appPath)
			}
		}
	} else {
		callerID = "unknown"
	}

	return CallerIdentity{ID: callerID, DisplayName: displayName}
}
