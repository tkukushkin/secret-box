import CryptoKit
import Foundation
import Testing
@testable import SecretBoxLib

@Suite("Crypto")
struct CryptoTests {
    @Test("sha256Hex produces correct hash")
    func sha256HexKnownValue() {
        // SHA-256 of "hello" is well-known
        let result = sha256Hex("hello")
        #expect(result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    @Test("sha256Hex of empty string")
    func sha256HexEmpty() {
        let result = sha256Hex("")
        #expect(result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("hmacSHA256 produces deterministic output")
    func hmacDeterministic() {
        let key = SymmetricKey(data: Data(repeating: 0xAB, count: 32))
        let data = Data("test message".utf8)
        let mac1 = hmacSHA256(key: key, data: data)
        let mac2 = hmacSHA256(key: key, data: data)
        #expect(mac1 == mac2)
    }

    @Test("hmacSHA256 differs with different keys")
    func hmacDifferentKeys() {
        let key1 = SymmetricKey(data: Data(repeating: 0xAA, count: 32))
        let key2 = SymmetricKey(data: Data(repeating: 0xBB, count: 32))
        let data = Data("test".utf8)
        #expect(hmacSHA256(key: key1, data: data) != hmacSHA256(key: key2, data: data))
    }

    @Test("hmacSHA256 differs with different data")
    func hmacDifferentData() {
        let key = SymmetricKey(data: Data(repeating: 0xAA, count: 32))
        let mac1 = hmacSHA256(key: key, data: Data("hello".utf8))
        let mac2 = hmacSHA256(key: key, data: Data("world".utf8))
        #expect(mac1 != mac2)
    }

    @Test("constantTimeEqual returns true for equal data")
    func equalData() {
        let a = Data([1, 2, 3, 4, 5])
        #expect(constantTimeEqual(a, a))
    }

    @Test("constantTimeEqual returns false for different data")
    func differentData() {
        let a = Data([1, 2, 3, 4, 5])
        let b = Data([1, 2, 3, 4, 6])
        #expect(!constantTimeEqual(a, b))
    }

    @Test("constantTimeEqual returns false for different lengths")
    func differentLengths() {
        let a = Data([1, 2, 3])
        let b = Data([1, 2, 3, 4])
        #expect(!constantTimeEqual(a, b))
    }

    @Test("constantTimeEqual with empty data")
    func emptyData() {
        #expect(constantTimeEqual(Data(), Data()))
    }
}
