import CryptoKit
import Foundation

public func sha256Hex(_ input: String) -> String {
    let digest = SHA256.hash(data: Data(input.utf8))
    return digest.map { String(format: "%02x", $0) }.joined()
}

public func hmacSHA256(key: SymmetricKey, data: Data) -> Data {
    let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
    return Data(mac)
}

public func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    let aBytes = [UInt8](a)
    let bBytes = [UInt8](b)
    var diff: UInt8 = 0
    for i in 0..<aBytes.count {
        diff |= aBytes[i] ^ bBytes[i]
    }
    return diff == 0
}
