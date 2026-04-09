import CryptoKit
import Foundation
import SQLite
import Testing
@testable import SecretBoxLib

@Suite("Integration")
struct IntegrationTests {
    @Test("Full secret lifecycle: write, exists, list, read, delete")
    func secretLifecycle() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        // Write
        try env.store.write(name: "my-secret", data: Data("my-value".utf8))

        // Exists
        #expect(env.store.exists(name: "my-secret"))

        // List
        #expect(env.store.list() == ["my-secret"])

        // Read
        let data = try env.store.read(name: "my-secret")
        #expect(String(data: data, encoding: .utf8) == "my-value")

        // Delete
        try env.store.delete(name: "my-secret")
        #expect(!env.store.exists(name: "my-secret"))
        #expect(env.store.list() == [])
    }

    @Test("Multiple secrets management")
    func multipleSecrets() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "alpha", data: Data("a".utf8))
        try env.store.write(name: "bravo", data: Data("b".utf8))
        try env.store.write(name: "charlie", data: Data("c".utf8))

        #expect(env.store.list() == ["alpha", "bravo", "charlie"])

        // Delete middle one
        try env.store.delete(name: "bravo")
        #expect(env.store.list() == ["alpha", "charlie"])

        // Remaining secrets are still readable
        #expect(try env.store.read(name: "alpha") == Data("a".utf8))
        #expect(try env.store.read(name: "charlie") == Data("c".utf8))
    }

    @Test("Auth cache flow: first access, cached access, invalidate")
    func authCacheFlow() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        let callerID = "test-caller"

        // Not cached initially
        _ = try env.db.connection
        #expect(!env.cache.isValid(for: callerID, secretName: "secret-1"))

        // After update, cache is valid
        env.cache.update(for: callerID, secretName: "secret-1")
        #expect(env.cache.isValid(for: callerID, secretName: "secret-1"))

        // After invalidation, cache is no longer valid
        env.cache.invalidate(secretName: "secret-1")
        #expect(!env.cache.isValid(for: callerID, secretName: "secret-1"))
    }

    @Test("Write invalidates auth cache for that secret")
    func writeInvalidatesCache() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        let callerID = "test-caller"

        // Write a secret and cache auth
        try env.store.write(name: "my-secret", data: Data("old".utf8))
        env.cache.update(for: callerID, secretName: "my-secret")
        #expect(env.cache.isValid(for: callerID, secretName: "my-secret"))

        // Overwrite the secret and invalidate cache (as the CLI does)
        try env.store.write(name: "my-secret", data: Data("new".utf8))
        env.cache.invalidate(secretName: "my-secret")

        #expect(!env.cache.isValid(for: callerID, secretName: "my-secret"))
        #expect(try env.store.read(name: "my-secret") == Data("new".utf8))
    }

    @Test("Reset clears everything including cache")
    func resetClearsAll() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        // Populate store and cache
        try env.store.write(name: "s1", data: Data("v1".utf8))
        try env.store.write(name: "s2", data: Data("v2".utf8))
        env.cache.update(for: "caller", secretName: "s1")

        // Reset
        try env.store.resetAll()

        // DB directory is gone
        #expect(!FileManager.default.fileExists(atPath: env.tmpDir.path))
        // Keychain is cleared
        #expect(env.keychain.storage.isEmpty)
    }

    @Test("Auth cache with time progression")
    func cacheWithTime() throws {
        var currentTime: Int64 = 10_000
        let env = makeTestEnvironment(
            cacheDuration: 60,
            timeProvider: { currentTime }
        )
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "secret", data: Data("val".utf8))

        // First access - not cached
        #expect(!env.cache.isValid(for: "caller", secretName: "secret"))

        // Authenticate and cache
        env.cache.update(for: "caller", secretName: "secret")
        #expect(env.cache.isValid(for: "caller", secretName: "secret"))

        // 30 seconds later - still valid
        currentTime = 10_030
        #expect(env.cache.isValid(for: "caller", secretName: "secret"))

        // 61 seconds later - expired
        currentTime = 10_061
        #expect(!env.cache.isValid(for: "caller", secretName: "secret"))

        // Re-authenticate
        env.cache.update(for: "caller", secretName: "secret")
        #expect(env.cache.isValid(for: "caller", secretName: "secret"))
    }

    @Test("Multiple callers accessing same secret")
    func multipleCallersSameSecret() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "shared-secret", data: Data("value".utf8))

        // Caller A authenticates
        env.cache.update(for: "caller-A", secretName: "shared-secret")

        // Caller A is cached, caller B is not
        #expect(env.cache.isValid(for: "caller-A", secretName: "shared-secret"))
        #expect(!env.cache.isValid(for: "caller-B", secretName: "shared-secret"))

        // Caller B authenticates
        env.cache.update(for: "caller-B", secretName: "shared-secret")

        // Both are cached now
        #expect(env.cache.isValid(for: "caller-A", secretName: "shared-secret"))
        #expect(env.cache.isValid(for: "caller-B", secretName: "shared-secret"))

        // Invalidating the secret clears cache for both
        env.cache.invalidate(secretName: "shared-secret")
        #expect(!env.cache.isValid(for: "caller-A", secretName: "shared-secret"))
        #expect(!env.cache.isValid(for: "caller-B", secretName: "shared-secret"))
    }

    @Test("Secret encryption uses unique nonces")
    func uniqueNonces() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        // Write same data under two names - encrypted blobs should differ
        let data = Data("same data".utf8)
        try env.store.write(name: "s1", data: data)
        try env.store.write(name: "s2", data: data)

        let conn = try env.db.connection
        let table = Table("secrets")
        let nameCol = Expression<String>("name")
        let encryptedCol = Expression<Data>("encrypted_data")

        let row1 = try conn.pluck(table.filter(nameCol == "s1"))!
        let row2 = try conn.pluck(table.filter(nameCol == "s2"))!

        // Encrypted blobs should be different (different nonces)
        #expect(row1[encryptedCol] != row2[encryptedCol])

        // But decrypted values should be the same
        #expect(try env.store.read(name: "s1") == data)
        #expect(try env.store.read(name: "s2") == data)
    }

    @Test("MockKeychain isolation between stores")
    func keychainIsolation() throws {
        let tmpDir1 = makeTempDir()
        let tmpDir2 = makeTempDir()
        defer {
            cleanupTempDir(tmpDir1)
            cleanupTempDir(tmpDir2)
        }

        let keychain = MockKeychain()
        let db1 = SecretDatabase(baseDir: tmpDir1)
        let db2 = SecretDatabase(baseDir: tmpDir2)
        let store1 = SecretStore(db: db1, keychain: keychain, keychainService: "svc1")
        let store2 = SecretStore(db: db2, keychain: keychain, keychainService: "svc2")

        try store1.write(name: "secret", data: Data("from-store-1".utf8))
        try store2.write(name: "secret", data: Data("from-store-2".utf8))

        // Each store uses its own encryption key
        #expect(try store1.read(name: "secret") == Data("from-store-1".utf8))
        #expect(try store2.read(name: "secret") == Data("from-store-2".utf8))
    }

    @Test("MockBiometricAuth tracks calls")
    func mockBiometricAuth() throws {
        let mock = MockBiometricAuth()

        // Success case
        try mock.authenticate(reason: "test reason")
        #expect(mock.authenticateCalled)
        #expect(mock.lastReason == "test reason")

        // Failure case
        mock.shouldSucceed = false
        #expect(throws: TouchIDError.self) {
            try mock.authenticate(reason: "fail")
        }
    }
}
