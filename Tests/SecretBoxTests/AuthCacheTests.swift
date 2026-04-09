import CryptoKit
import Foundation
import Testing
@testable import SecretBoxLib

@Suite("AuthCache")
struct AuthCacheTests {
    @Test("Update and isValid returns true")
    func updateThenValid() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-1")
        #expect(env.cache.isValid(for: "caller-1", secretName: "secret-1"))
    }

    @Test("isValid returns false for non-existent cache entry")
    func nonExistent() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        // Force DB init
        _ = try env.db.connection
        #expect(!env.cache.isValid(for: "caller-1", secretName: "secret-1"))
    }

    @Test("isValid returns false after cache expiry")
    func expired() throws {
        var currentTime: Int64 = 1000
        let env = makeTestEnvironment(
            cacheDuration: 600,
            timeProvider: { currentTime }
        )
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-1")
        #expect(env.cache.isValid(for: "caller-1", secretName: "secret-1"))

        // Advance time past the cache duration
        currentTime = 1601
        #expect(!env.cache.isValid(for: "caller-1", secretName: "secret-1"))
    }

    @Test("isValid still valid at exactly cache duration")
    func atExactDuration() throws {
        var currentTime: Int64 = 1000
        let env = makeTestEnvironment(
            cacheDuration: 600,
            timeProvider: { currentTime }
        )
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-1")

        // Exactly at the boundary (now - timestamp == 600)
        currentTime = 1600
        #expect(env.cache.isValid(for: "caller-1", secretName: "secret-1"))
    }

    @Test("Different callers don't share cache")
    func differentCallers() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-A", secretName: "secret-1")

        #expect(env.cache.isValid(for: "caller-A", secretName: "secret-1"))
        #expect(!env.cache.isValid(for: "caller-B", secretName: "secret-1"))
    }

    @Test("Different secrets don't share cache")
    func differentSecrets() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-A")

        #expect(env.cache.isValid(for: "caller-1", secretName: "secret-A"))
        #expect(!env.cache.isValid(for: "caller-1", secretName: "secret-B"))
    }

    @Test("Invalidate removes cache for all callers of that secret")
    func invalidate() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-1")
        env.cache.update(for: "caller-2", secretName: "secret-1")

        env.cache.invalidate(secretName: "secret-1")

        #expect(!env.cache.isValid(for: "caller-1", secretName: "secret-1"))
        #expect(!env.cache.isValid(for: "caller-2", secretName: "secret-1"))
    }

    @Test("Invalidate does not affect other secrets")
    func invalidateIsolated() throws {
        let env = makeTestEnvironment()
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-1")
        env.cache.update(for: "caller-1", secretName: "secret-2")

        env.cache.invalidate(secretName: "secret-1")

        #expect(!env.cache.isValid(for: "caller-1", secretName: "secret-1"))
        #expect(env.cache.isValid(for: "caller-1", secretName: "secret-2"))
    }

    @Test("Update refreshes cache timestamp")
    func updateRefreshes() throws {
        var currentTime: Int64 = 1000
        let env = makeTestEnvironment(
            cacheDuration: 600,
            timeProvider: { currentTime }
        )
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-1")

        // Advance to near expiry
        currentTime = 1500
        #expect(env.cache.isValid(for: "caller-1", secretName: "secret-1"))

        // Refresh the cache
        env.cache.update(for: "caller-1", secretName: "secret-1")

        // Advance past original expiry but within new window
        currentTime = 2000
        #expect(env.cache.isValid(for: "caller-1", secretName: "secret-1"))
    }

    @Test("isValid rejects future timestamp")
    func futureTimestamp() throws {
        var currentTime: Int64 = 2000
        let env = makeTestEnvironment(
            cacheDuration: 600,
            timeProvider: { currentTime }
        )
        defer { cleanupTempDir(env.tmpDir) }

        env.cache.update(for: "caller-1", secretName: "secret-1")

        // Time goes backwards (clock skew)
        currentTime = 1999
        #expect(!env.cache.isValid(for: "caller-1", secretName: "secret-1"))
    }

    @Test("buildMessage produces deterministic output")
    func buildMessageDeterministic() {
        let ts = Data(repeating: 0x01, count: 8)
        let msg1 = AuthCache.buildMessage(timestampData: ts, callerID: "caller", secretName: "secret")
        let msg2 = AuthCache.buildMessage(timestampData: ts, callerID: "caller", secretName: "secret")
        #expect(msg1 == msg2)
    }

    @Test("buildMessage includes caller length prefix")
    func buildMessageFormat() {
        let ts = Data(repeating: 0x00, count: 8)
        let msg = AuthCache.buildMessage(timestampData: ts, callerID: "AB", secretName: "XY")

        // 8 bytes timestamp + 4 bytes caller length (big endian) + 2 bytes "AB" + 2 bytes "XY" = 16
        #expect(msg.count == 16)

        // Caller length should be 2 in big endian
        let callerLen = msg.subdata(in: 8..<12)
        #expect(callerLen == Data([0, 0, 0, 2]))
    }

    @Test("buildMessage differs for different callers with same total length")
    func buildMessageDifferentCallers() {
        let ts = Data(repeating: 0x00, count: 8)
        // "AB" + "XY" vs "A" + "BXY" - same total bytes but different split
        let msg1 = AuthCache.buildMessage(timestampData: ts, callerID: "AB", secretName: "XY")
        let msg2 = AuthCache.buildMessage(timestampData: ts, callerID: "A", secretName: "BXY")
        #expect(msg1 != msg2)
    }
}
