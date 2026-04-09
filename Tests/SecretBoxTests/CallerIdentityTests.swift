import Foundation
import Testing
@testable import SecretBoxLib

@Suite("CallerIdentity")
struct CallerIdentityTests {
    @Test("extractAppBundle from path containing .app/")
    func extractFromAppSlash() {
        let path = "/Applications/iTerm.app/Contents/MacOS/iTerm2"
        #expect(extractAppBundle(from: path) == "/Applications/iTerm.app")
    }

    @Test("extractAppBundle from path ending with .app")
    func extractFromAppSuffix() {
        let path = "/Applications/Safari.app"
        #expect(extractAppBundle(from: path) == "/Applications/Safari.app")
    }

    @Test("extractAppBundle returns nil for non-app path")
    func extractFromNonAppPath() {
        let path = "/usr/bin/ssh"
        #expect(extractAppBundle(from: path) == nil)
    }

    @Test("extractAppBundle picks first .app in nested path")
    func extractFromNestedApps() {
        let path = "/Applications/Xcode.app/Contents/Developer/Applications/Simulator.app/Contents/MacOS/Simulator"
        #expect(extractAppBundle(from: path) == "/Applications/Xcode.app")
    }

    @Test("CallerIdentity.current() returns non-empty values")
    func currentIdentity() {
        let identity = CallerIdentity.current()
        #expect(!identity.id.isEmpty)
        #expect(!identity.displayName.isEmpty)
    }
}
