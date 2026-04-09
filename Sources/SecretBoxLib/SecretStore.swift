import CryptoKit
import Foundation
import SQLite

public enum StoreError: Error, CustomStringConvertible {
    case secretNotFound
    case corruptedData
    case storageError(String)
    case keychainError(String)

    public var description: String {
        switch self {
        case .secretNotFound: return "secret not found"
        case .corruptedData: return "corrupted secret data"
        case .storageError(let msg): return msg
        case .keychainError(let msg): return msg
        }
    }
}

public class SecretStore {
    public let db: SecretDatabase
    private let keychain: KeychainProvider
    public let keychainService: String
    public let keychainAccount: String

    // SQLite column definitions
    private let secretsTable = Table("secrets")
    private let nameCol = SQLite.Expression<String>("name")
    private let encryptedDataCol = SQLite.Expression<Data>("encrypted_data")

    public init(
        db: SecretDatabase,
        keychain: KeychainProvider,
        keychainService: String = "secret-box",
        keychainAccount: String = "__master-key__"
    ) {
        self.db = db
        self.keychain = keychain
        self.keychainService = keychainService
        self.keychainAccount = keychainAccount
    }

    public func write(name: String, data: Data) throws {
        let key = try getOrCreateKey()
        let sealed = try AES.GCM.seal(data, using: key)
        guard let combined = sealed.combined else {
            throw StoreError.storageError("encryption failed")
        }
        let conn = try db.connection
        try conn.run(secretsTable.insert(or: .replace,
            nameCol <- name,
            encryptedDataCol <- combined
        ))
    }

    public func read(name: String) throws -> Data {
        let key = try getOrCreateKey()
        let conn = try db.connection

        guard let row = try conn.pluck(secretsTable.filter(nameCol == name)) else {
            throw StoreError.secretNotFound
        }

        let combined = row[encryptedDataCol]
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    public func exists(name: String) -> Bool {
        guard let conn = try? db.connection else { return false }
        guard let count = try? conn.scalar(secretsTable.filter(nameCol == name).count) else {
            return false
        }
        return count > 0
    }

    public func delete(name: String) throws {
        let conn = try db.connection
        try conn.run(secretsTable.filter(nameCol == name).delete())
    }

    public func list() -> [String] {
        guard let conn = try? db.connection else { return [] }
        guard let rows = try? conn.prepare(secretsTable.select(nameCol).order(nameCol)) else {
            return []
        }
        return rows.map { $0[nameCol] }
    }

    public func resetAll() throws {
        db.closeConnection()
        let baseDir = db.baseDir
        if FileManager.default.fileExists(atPath: baseDir.path) {
            try FileManager.default.removeItem(at: baseDir)
        }
        keychain.delete(service: keychainService, account: keychainAccount)
    }

    // MARK: - Key management

    public func authKey() throws -> SymmetricKey {
        let master = try getOrCreateKey()
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            info: Data("secret-box-auth-cache".utf8),
            outputByteCount: 32
        )
    }

    private func getOrCreateKey() throws -> SymmetricKey {
        if let data = keychain.get(service: keychainService, account: keychainAccount) {
            return SymmetricKey(data: data)
        }

        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        try keychain.set(keyData, service: keychainService, account: keychainAccount)
        return key
    }
}
