import Foundation
import Testing
@testable import SecretBoxLib

@Suite("Database")
struct DatabaseTests {
    @Test("Creates directory and database file")
    func createsDirectoryAndFile() throws {
        let tmpDir = makeTempDir()
        defer { cleanupTempDir(tmpDir) }

        let db = SecretDatabase(baseDir: tmpDir)
        _ = try db.connection

        let dbPath = tmpDir.appendingPathComponent("db.sqlite3").path
        #expect(FileManager.default.fileExists(atPath: dbPath))
    }

    @Test("Sets restrictive directory permissions")
    func directoryPermissions() throws {
        let tmpDir = makeTempDir()
        defer { cleanupTempDir(tmpDir) }

        let db = SecretDatabase(baseDir: tmpDir)
        _ = try db.connection

        let attrs = try FileManager.default.attributesOfItem(atPath: tmpDir.path)
        let perms = attrs[.posixPermissions] as! Int
        #expect(perms == 0o700)
    }

    @Test("Sets restrictive database file permissions")
    func filePermissions() throws {
        let tmpDir = makeTempDir()
        defer { cleanupTempDir(tmpDir) }

        let db = SecretDatabase(baseDir: tmpDir)
        _ = try db.connection

        let dbPath = tmpDir.appendingPathComponent("db.sqlite3").path
        let attrs = try FileManager.default.attributesOfItem(atPath: dbPath)
        let perms = attrs[.posixPermissions] as! Int
        #expect(perms == 0o600)
    }

    @Test("Connection is reusable")
    func connectionReuse() throws {
        let tmpDir = makeTempDir()
        defer { cleanupTempDir(tmpDir) }

        let db = SecretDatabase(baseDir: tmpDir)
        let conn1 = try db.connection
        let conn2 = try db.connection
        #expect(conn1 === conn2)
    }

    @Test("closeConnection allows reconnection")
    func closeAndReconnect() throws {
        let tmpDir = makeTempDir()
        defer { cleanupTempDir(tmpDir) }

        let db = SecretDatabase(baseDir: tmpDir)
        let conn1 = try db.connection
        db.closeConnection()
        let conn2 = try db.connection
        #expect(conn1 !== conn2)
    }

    @Test("Creates tables on first connection")
    func createsSchema() throws {
        let tmpDir = makeTempDir()
        defer { cleanupTempDir(tmpDir) }

        let db = SecretDatabase(baseDir: tmpDir)
        let conn = try db.connection

        // Query sqlite_master to verify tables exist
        let tables = try conn.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .map { $0[0] as! String }
        #expect(tables.contains("secrets"))
        #expect(tables.contains("auth_cache"))
    }

    @Test("Creates base directory if it does not exist")
    func createsBaseDirectory() throws {
        let tmpDir = makeTempDir()
        let nestedDir = tmpDir.appendingPathComponent("nested/deep")
        defer { cleanupTempDir(tmpDir) }

        let db = SecretDatabase(baseDir: nestedDir)
        _ = try db.connection

        #expect(FileManager.default.fileExists(atPath: nestedDir.path))
    }
}
