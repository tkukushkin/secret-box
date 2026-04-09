import CryptoKit
import Foundation
import SQLite

enum AuthCache {
    private static let cacheDuration: Int64 = 600 // seconds

    // MARK: - SQLite column definitions

    private static let cacheTable = Table("auth_cache")
    private static let secretNameCol = SQLite.Expression<String>("secret_name")
    private static let callerIdCol = SQLite.Expression<String>("caller_id")
    private static let timestampCol = SQLite.Expression<Int64>("timestamp")
    private static let hmacCol = SQLite.Expression<Data>("hmac")

    // MARK: - Public API

    static func isValid(for callerID: String, secretName: String) -> Bool {
        guard let key = try? SecretStore.authKey(),
              let db = try? Database.connection else { return false }

        guard let row = try? db.pluck(
            cacheTable.filter(secretNameCol == secretName && callerIdCol == callerID)
        ) else { return false }

        let timestamp = row[timestampCol]
        let storedHmac = row[hmacCol]

        let now = Int64(time(nil))
        guard now - timestamp <= cacheDuration, timestamp <= now else { return false }

        var ts = timestamp.littleEndian
        let timestampData = Data(bytes: &ts, count: MemoryLayout<Int64>.size)

        let message = buildMessage(timestampData: timestampData, callerID: callerID, secretName: secretName)
        let expectedHmac = hmacSHA256(key: key, data: message)

        return constantTimeEqual(expectedHmac, storedHmac)
    }

    static func update(for callerID: String, secretName: String) {
        guard let key = try? SecretStore.authKey(),
              let db = try? Database.connection else { return }

        let timestamp = Int64(time(nil))
        var ts = timestamp.littleEndian
        let timestampData = Data(bytes: &ts, count: MemoryLayout<Int64>.size)

        let message = buildMessage(timestampData: timestampData, callerID: callerID, secretName: secretName)
        let hmac = hmacSHA256(key: key, data: message)

        _ = try? db.run(cacheTable.insert(or: .replace,
            secretNameCol <- secretName,
            callerIdCol <- callerID,
            timestampCol <- timestamp,
            hmacCol <- hmac
        ))
    }

    static func invalidate(secretName: String) {
        guard let db = try? Database.connection else { return }
        _ = try? db.run(cacheTable.filter(secretNameCol == secretName).delete())
    }

    // MARK: - Private

    private static func buildMessage(timestampData: Data, callerID: String, secretName: String) -> Data {
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
