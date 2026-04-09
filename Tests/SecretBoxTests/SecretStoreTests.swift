import Foundation
import Testing
@testable import SecretBoxLib

@Suite("SecretStore")
struct SecretStoreTests {
    @Test("Write and read back a text secret")
    func writeAndRead() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        let data = Data("hello world".utf8)
        try env.store.write(name: "test-secret", data: data)
        let result = try env.store.read(name: "test-secret")
        #expect(result == data)
    }

    @Test("Write and read back binary data")
    func writeAndReadBinary() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        let data = Data([0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F])
        try env.store.write(name: "binary-secret", data: data)
        let result = try env.store.read(name: "binary-secret")
        #expect(result == data)
    }

    @Test("Overwrite replaces secret value")
    func overwrite() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "s", data: Data("old".utf8))
        try env.store.write(name: "s", data: Data("new".utf8))
        let result = try env.store.read(name: "s")
        #expect(result == Data("new".utf8))
    }

    @Test("Read non-existent secret throws secretNotFound")
    func readNonExistent() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        #expect(throws: StoreError.self) {
            try env.store.read(name: "no-such-secret")
        }
    }

    @Test("exists returns true for existing secret")
    func existsTrue() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "present", data: Data("v".utf8))
        #expect(env.store.exists(name: "present"))
    }

    @Test("exists returns false for non-existing secret")
    func existsFalse() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        // Force DB initialization
        _ = try env.db.connection
        #expect(!env.store.exists(name: "absent"))
    }

    @Test("Delete removes secret")
    func deleteSecret() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "to-delete", data: Data("v".utf8))
        #expect(env.store.exists(name: "to-delete"))

        try env.store.delete(name: "to-delete")
        #expect(!env.store.exists(name: "to-delete"))
    }

    @Test("List returns sorted names")
    func listSorted() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "charlie", data: Data("c".utf8))
        try env.store.write(name: "alpha", data: Data("a".utf8))
        try env.store.write(name: "bravo", data: Data("b".utf8))

        #expect(env.store.list() == ["alpha", "bravo", "charlie"])
    }

    @Test("List returns empty for empty store")
    func listEmpty() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        // Force DB initialization
        _ = try env.db.connection
        #expect(env.store.list() == [])
    }

    @Test("resetAll clears secrets and keychain")
    func resetAll() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "s1", data: Data("v".utf8))
        try env.store.write(name: "s2", data: Data("v".utf8))

        try env.store.resetAll()

        // DB directory should be removed
        #expect(!FileManager.default.fileExists(atPath: env.tmpDir.path))
        // Keychain entry should be deleted
        #expect(env.keychain.storage.isEmpty)
    }

    @Test("authKey returns consistent derived key")
    func authKeyConsistent() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        let key1 = try env.store.authKey()
        let key2 = try env.store.authKey()
        let data1 = key1.withUnsafeBytes { Data($0) }
        let data2 = key2.withUnsafeBytes { Data($0) }
        #expect(data1 == data2)
    }

    @Test("Write and read large data")
    func largeData() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        let data = Data(repeating: 0x42, count: 100_000)
        try env.store.write(name: "large", data: data)
        let result = try env.store.read(name: "large")
        #expect(result == data)
    }

    @Test("Multiple secrets are independent")
    func multipleSecrets() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        try env.store.write(name: "a", data: Data("value-a".utf8))
        try env.store.write(name: "b", data: Data("value-b".utf8))

        #expect(try env.store.read(name: "a") == Data("value-a".utf8))
        #expect(try env.store.read(name: "b") == Data("value-b".utf8))
    }
}
