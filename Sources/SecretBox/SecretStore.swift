import CryptoKit
import Foundation
import Security
import SQLite

enum StoreError: Error, CustomStringConvertible {
    case secretNotFound
    case corruptedData
    case storageError(String)
    case keychainError(String)

    var description: String {
        switch self {
        case .secretNotFound: return "secret not found"
        case .corruptedData: return "corrupted secret data"
        case .storageError(let msg): return msg
        case .keychainError(let msg): return msg
        }
    }
}

enum SecretStore {
    private static let keychainService = "secret-box"
    private static let keychainAccount = "__master-key__"

    private static var baseDir: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("secret-box")
    }

    // MARK: - SQLite column definitions

    private static let secretsTable = Table("secrets")
    private static let nameCol = SQLite.Expression<String>("name")
    private static let encryptedDataCol = SQLite.Expression<Data>("encrypted_data")

    // MARK: - CRUD

    static func write(name: String, data: Data) throws {
        let key = try getOrCreateKey()

        let sealed = try AES.GCM.seal(data, using: key)
        guard let combined = sealed.combined else {
            throw StoreError.storageError("encryption failed")
        }

        let db = try Database.connection
        try db.run(secretsTable.insert(or: .replace,
            nameCol <- name,
            encryptedDataCol <- combined
        ))
    }

    static func read(name: String) throws -> Data {
        let key = try getOrCreateKey()
        let db = try Database.connection

        guard let row = try db.pluck(secretsTable.filter(nameCol == name)) else {
            throw StoreError.secretNotFound
        }

        let combined = row[encryptedDataCol]
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    static func exists(name: String) -> Bool {
        guard let db = try? Database.connection else { return false }
        guard let count = try? db.scalar(secretsTable.filter(nameCol == name).count) else {
            return false
        }
        return count > 0
    }

    static func delete(name: String) throws {
        let db = try Database.connection
        try db.run(secretsTable.filter(nameCol == name).delete())
    }

    static func list() -> [String] {
        guard let db = try? Database.connection else { return [] }
        guard let rows = try? db.prepare(secretsTable.select(nameCol).order(nameCol)) else {
            return []
        }
        return rows.map { $0[nameCol] }
    }

    static func resetAll() throws {
        Database.closeConnection()

        if FileManager.default.fileExists(atPath: baseDir.path) {
            try FileManager.default.removeItem(at: baseDir)
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Key management

    static func authKey() throws -> SymmetricKey {
        let master = try getOrCreateKey()
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            info: Data("secret-box-auth-cache".utf8),
            outputByteCount: 32
        )
    }

    private static func getOrCreateKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess, let data = result as? Data {
            return SymmetricKey(data: data)
        }

        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess {
            let msg = SecCopyErrorMessageString(addStatus, nil) as String? ?? "Unknown error"
            throw StoreError.keychainError("Failed to store master key: \(msg)")
        }

        return key
    }
}
