import Foundation
import Testing
@testable import SecretBoxLib

@Suite("ExpandVariables")
struct ExpandVariablesTests {
    @Test("Expands single variable")
    func singleVar() {
        let result = expandVariables(
            in: ["--password=$(DB_PASS)"],
            with: ["DB_PASS": "secret123"]
        )
        #expect(result == ["--password=secret123"])
    }

    @Test("Expands multiple variables in same argument")
    func multipleVarsInArg() {
        let result = expandVariables(
            in: ["$(USER):$(PASS)"],
            with: ["USER": "admin", "PASS": "s3cret"]
        )
        #expect(result == ["admin:s3cret"])
    }

    @Test("Expands variables across multiple arguments")
    func multipleArgs() {
        let result = expandVariables(
            in: ["--user=$(USER)", "--pass=$(PASS)"],
            with: ["USER": "admin", "PASS": "s3cret"]
        )
        #expect(result == ["--user=admin", "--pass=s3cret"])
    }

    @Test("Leaves unmatched variables untouched")
    func unmatchedVar() {
        let result = expandVariables(
            in: ["$(UNKNOWN)"],
            with: ["KNOWN": "value"]
        )
        #expect(result == ["$(UNKNOWN)"])
    }

    @Test("No variables - passthrough")
    func noVariables() {
        let result = expandVariables(
            in: ["echo", "hello"],
            with: ["VAR": "value"]
        )
        #expect(result == ["echo", "hello"])
    }

    @Test("Empty values map")
    func emptyValues() {
        let result = expandVariables(
            in: ["$(VAR)"],
            with: [:]
        )
        #expect(result == ["$(VAR)"])
    }

    @Test("Empty arguments list")
    func emptyArgs() {
        let result = expandVariables(
            in: [],
            with: ["VAR": "value"]
        )
        #expect(result == [])
    }

    @Test("Variable value containing special characters")
    func specialChars() {
        let result = expandVariables(
            in: ["$(PASS)"],
            with: ["PASS": "p@ss w0rd!\"'$"]
        )
        #expect(result == ["p@ss w0rd!\"'$"])
    }
}
