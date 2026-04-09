package secretbox

import "testing"

func TestCaller_ExtractAppBundleFromAppSlash(t *testing.T) {
	path := "/Applications/iTerm.app/Contents/MacOS/iTerm2"
	result := ExtractAppBundle(path)
	if result != "/Applications/iTerm.app" {
		t.Errorf("got %q, want %q", result, "/Applications/iTerm.app")
	}
}

func TestCaller_ExtractAppBundleFromAppSuffix(t *testing.T) {
	path := "/Applications/Safari.app"
	result := ExtractAppBundle(path)
	if result != "/Applications/Safari.app" {
		t.Errorf("got %q, want %q", result, "/Applications/Safari.app")
	}
}

func TestCaller_ExtractAppBundleFromNonAppPath(t *testing.T) {
	path := "/usr/bin/ssh"
	result := ExtractAppBundle(path)
	if result != "" {
		t.Errorf("got %q, want empty string", result)
	}
}

func TestCaller_ExtractAppBundleFromNestedApps(t *testing.T) {
	path := "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app/Contents/MacOS/Simulator"
	result := ExtractAppBundle(path)
	if result != "/Applications/Xcode.app" {
		t.Errorf("got %q, want %q", result, "/Applications/Xcode.app")
	}
}

func TestCaller_CurrentIdentity(t *testing.T) {
	identity := CurrentCallerIdentity()
	if identity.ID == "" {
		t.Error("ID should not be empty")
	}
	if identity.DisplayName == "" {
		t.Error("DisplayName should not be empty")
	}
}
