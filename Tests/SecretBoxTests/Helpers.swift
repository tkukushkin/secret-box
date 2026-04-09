import CryptoKit
import Foundation
@testable import SecretBoxLib

class MockKeychain: KeychainProvider {
    var storage: [String: Data] = [:]

    func get(service: String, account: String) -> Data? {
        storage["\(service):\(account)"]
    }

    func set(_ data: Data, service: String, account: String) throws {
        storage["\(service):\(account)"] = data
    }

    func delete(service: String, account: String) {
        storage.removeValue(forKey: "\(service):\(account)")
    }
}

class MockBiometricAuth: BiometricAuth {
    var shouldSucceed = true
    var authenticateCalled = false
    var lastReason: String?

    func authenticate(reason: String) throws {
        authenticateCalled = true
        lastReason = reason
        if !shouldSucceed {
            throw TouchIDError.authFailed("Mock auth failed")
        }
    }
}

/// Creates a temporary directory for test isolation and returns its URL.
func makeTempDir() -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("secret-box-tests-\(UUID().uuidString)")
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

/// Creates a fully wired test environment with mock keychain.
func makeTestEnvironment(
    cacheDuration: Int64 = AuthCache.defaultCacheDuration,
    timeProvider: @escaping () -> Int64 = { Int64(time(nil)) }
) -> (store: SecretStore, cache: AuthCache, db: SecretDatabase, keychain: MockKeychain, tmpDir: URL) {
    let tmpDir = makeTempDir()
    let db = SecretDatabase(baseDir: tmpDir)
    let keychain = MockKeychain()
    let store = SecretStore(db: db, keychain: keychain)
    let cache = AuthCache(
        db: db,
        authKeyProvider: store.authKey,
        cacheDuration: cacheDuration,
        timeProvider: timeProvider
    )
    return (store, cache, db, keychain, tmpDir)
}

/// Removes a temporary directory.
func cleanupTempDir(_ url: URL) {
    try? FileManager.default.removeItem(at: url)
}
