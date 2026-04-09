import Foundation
import SQLite

public class SecretDatabase {
    private var _connection: Connection?
    public let baseDir: URL

    public init(baseDir: URL) {
        self.baseDir = baseDir
    }

    public var connection: Connection {
        get throws {
            if let conn = _connection { return conn }
            let conn = try setup()
            _connection = conn
            return conn
        }
    }

    public func closeConnection() {
        _connection = nil
    }

    private func setup() throws -> Connection {
        if !FileManager.default.fileExists(atPath: baseDir.path) {
            try FileManager.default.createDirectory(
                at: baseDir, withIntermediateDirectories: true
            )
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: baseDir.path
        )

        let dbPath = baseDir.appendingPathComponent("db.sqlite3").path
        let conn = try Connection(dbPath)

        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: dbPath
        )

        try conn.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                name TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL
            )
        """)

        try conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_cache (
                secret_name TEXT NOT NULL,
                caller_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                hmac BLOB NOT NULL,
                PRIMARY KEY (secret_name, caller_id)
            )
        """)

        return conn
    }
}
