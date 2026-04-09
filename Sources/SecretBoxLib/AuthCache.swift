import CryptoKit
import Foundation
import SQLite

public class AuthCache {
    public static let defaultCacheDuration: Int64 = 600

    private let db: SecretDatabase
    private let authKeyProvider: () throws -> SymmetricKey
    private let cacheDuration: Int64
    let timeProvider: () -> Int64

    // SQLite column definitions
    private let cacheTable = Table("auth_cache")
    private let secretNameCol = SQLite.Expression<String>("secret_name")
    private let callerIdCol = SQLite.Expression<String>("caller_id")
    private let timestampCol = SQLite.Expression<Int64>("timestamp")
    private let hmacCol = SQLite.Expression<Data>("hmac")

    public init(
        db: SecretDatabase,
        authKeyProvider: @escaping () throws -> SymmetricKey,
        cacheDuration: Int64 = defaultCacheDuration,
        timeProvider: @escaping () -> Int64 = { Int64(time(nil)) }
    ) {
        self.db = db
        self.authKeyProvider = authKeyProvider
        self.cacheDuration = cacheDuration
        self.timeProvider = timeProvider
    }

    public func isValid(for callerID: String, secretName: String) -> Bool {
        guard let key = try? authKeyProvider(),
              let conn = try? db.connection else { return false }

        guard let row = try? conn.pluck(
            cacheTable.filter(secretNameCol == secretName && callerIdCol == callerID)
        ) else { return false }

        let timestamp = row[timestampCol]
        let storedHmac = row[hmacCol]

        let now = timeProvider()
        guard now - timestamp <= cacheDuration, timestamp <= now else { return false }

        var ts = timestamp.littleEndian
        let timestampData = Data(bytes: &ts, count: MemoryLayout<Int64>.size)
        let message = Self.buildMessage(timestampData: timestampData, callerID: callerID, secretName: secretName)
        let expectedHmac = hmacSHA256(key: key, data: message)

        return constantTimeEqual(expectedHmac, storedHmac)
    }

    public func update(for callerID: String, secretName: String) {
        guard let key = try? authKeyProvider(),
              let conn = try? db.connection else { return }

        let timestamp = timeProvider()
        var ts = timestamp.littleEndian
        let timestampData = Data(bytes: &ts, count: MemoryLayout<Int64>.size)

        let message = Self.buildMessage(timestampData: timestampData, callerID: callerID, secretName: secretName)
        let hmac = hmacSHA256(key: key, data: message)

        _ = try? conn.run(cacheTable.insert(or: .replace,
            secretNameCol <- secretName,
            callerIdCol <- callerID,
            timestampCol <- timestamp,
            hmacCol <- hmac
        ))
    }

    public func invalidate(secretName: String) {
        guard let conn = try? db.connection else { return }
        _ = try? conn.run(cacheTable.filter(secretNameCol == secretName).delete())
    }

    static func buildMessage(timestampData: Data, callerID: String, secretName: String) -> Data {
        var message = timestampData
        let callerData = Data(callerID.utf8)
        let nameData = Data(secretName.utf8)
        var callerLen = UInt32(callerData.count).bigEndian
        message.append(Data(bytes: &callerLen, count: 4))
        message.append(callerData)
        message.append(nameData)
        return message
    }
}
