import ArgumentParser
import Foundation

struct SecretBox: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "secret-box",
        abstract: "Secure secret storage with Touch ID authentication.",
        subcommands: [Write.self, Read.self, List.self, Delete.self, Reset.self, Exec.self]
    )
}

extension SecretBox {
    struct Write: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Save a secret. Value is read from stdin if not provided as argument.",
            discussion: """
                Examples:
                  secret-box write my-secret "some value"
                  echo -n "some value" | secret-box write my-secret
                  cat file.bin | secret-box write my-binary-secret
                """
        )

        @Argument(help: "Secret name.")
        var name: String

        @Argument(help: "Secret value (read from stdin if omitted).")
        var value: String?

        mutating func run() throws {
            let data: Data
            if let value {
                data = Data(value.utf8)
            } else {
                data = FileHandle.standardInput.readDataToEndOfFile()
                guard !data.isEmpty else {
                    throw ValidationError("no value provided (pass as argument or pipe to stdin)")
                }
            }
            try SecretStore.write(name: name, data: data)
            AuthCache.invalidate(secretName: name)
            print("Secret saved.")
        }
    }

    struct Read: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Read a secret (Touch ID required)."
        )

        @Argument(help: "Secret name.")
        var name: String

        @Flag(help: "Authenticate with Touch ID but don't cache the session.")
        var once = false

        mutating func run() throws {
            guard SecretStore.exists(name: name) else {
                fputs("Error: secret not found\n", stderr)
                throw ExitCode.failure
            }

            let caller = CallerIdentity.current()

            if !AuthCache.isValid(for: caller.id, secretName: name) {
                try TouchID.authenticate(
                    reason: "\"\(caller.displayName)\" wants to access \"\(name)\""
                )
                if !once {
                    AuthCache.update(for: caller.id, secretName: name)
                }
            }

            let data = try SecretStore.read(name: name)
            FileHandle.standardOutput.write(data)
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List secret names."
        )

        mutating func run() {
            for name in SecretStore.list() {
                print(name)
            }
        }
    }

    struct Delete: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Delete one or more secrets."
        )

        @Argument(help: "Secret names.")
        var names: [String]

        mutating func run() {
            for name in names {
                if !SecretStore.exists(name: name) {
                    print("\(name): not found")
                    continue
                }
                do {
                    try SecretStore.delete(name: name)
                    AuthCache.invalidate(secretName: name)
                    print("\(name): deleted")
                } catch {
                    fputs("\(name): \(error)\n", stderr)
                }
            }
        }
    }
    struct Reset: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Delete all secrets, auth cache, and the master key."
        )

        @Flag(name: .shortAndLong, help: "Skip confirmation prompt.")
        var yes = false

        mutating func run() throws {
            if !yes {
                print("This will permanently delete all secrets and the master key.")
                print("Type 'yes' to confirm: ", terminator: "")
                guard readLine()?.lowercased() == "yes" else {
                    print("Aborted.")
                    throw ExitCode.failure
                }
            }

            try SecretStore.resetAll()
            print("All data has been removed.")
        }
    }
}

extension SecretBox {
    struct Exec: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Run a command with secrets in environment variables.",
            discussion: """
                Secrets are set as environment variables. Use $(VAR) in command \
                arguments to substitute the secret value inline.

                Examples:
                  secret-box exec -e DB_PASSWORD=db-pass -- psql
                  secret-box exec -e DB_PASSWORD=db-pass -- psql '--password=$(DB_PASSWORD)'
                  secret-box exec -e DB_PASSWORD=db-pass -e API_KEY=api-key -- myapp
                """
        )

        @Option(name: .shortAndLong, help: "Map secret to env var (format: ENV_VAR=secret-name).")
        var env: [String]

        @Argument(help: "Command to execute.")
        var command: [String]

        func validate() throws {
            guard !env.isEmpty else {
                throw ValidationError("at least one -e/--env mapping is required")
            }
            for mapping in env {
                guard mapping.contains("=") else {
                    throw ValidationError("invalid env mapping '\(mapping)': expected format ENV_VAR=secret-name")
                }
            }
            guard !command.isEmpty else {
                throw ValidationError("no command specified")
            }
        }

        mutating func run() throws {
            // Parse mappings
            let mappings = env.map { entry -> (varName: String, secretName: String) in
                let parts = entry.split(separator: "=", maxSplits: 1)
                return (String(parts[0]), String(parts[1]))
            }

            // Verify all secrets exist
            for (_, secretName) in mappings {
                guard SecretStore.exists(name: secretName) else {
                    fputs("Error: secret '\(secretName)' not found\n", stderr)
                    throw ExitCode.failure
                }
            }

            // Check auth cache, collect uncached secrets
            let caller = CallerIdentity.current()
            let uncachedSecrets = mappings
                .map { $0.secretName }
                .filter { !AuthCache.isValid(for: caller.id, secretName: $0) }

            // Single Touch ID prompt for all uncached secrets
            if !uncachedSecrets.isEmpty {
                let quoted = uncachedSecrets.map { "\"\($0)\"" }.joined(separator: ", ")
                try TouchID.authenticate(
                    reason: "\"\(caller.displayName)\" wants to access \(quoted)"
                )
                for secretName in uncachedSecrets {
                    AuthCache.update(for: caller.id, secretName: secretName)
                }
            }

            // Read secrets and set env vars
            var resolved = [String: String]()
            for (varName, secretName) in mappings {
                let data = try SecretStore.read(name: secretName)
                guard let value = String(data: data, encoding: .utf8) else {
                    fputs("Error: secret '\(secretName)' is not valid UTF-8\n", stderr)
                    throw ExitCode.failure
                }
                resolved[varName] = value
                setenv(varName, value, 1)
            }

            // Substitute $(VAR) in command arguments
            let expandedCommand = command.map { arg in
                var result = arg
                for (varName, value) in resolved {
                    result = result.replacingOccurrences(of: "$(\(varName))", with: value)
                }
                return result
            }

            // execvp
            let argv = expandedCommand.map { strdup($0) } + [nil]
            execvp(argv[0], argv)

            // execvp only returns on error
            let err = String(cString: strerror(errno))
            fputs("Error: exec '\(command[0])': \(err)\n", stderr)
            throw ExitCode(127)
        }
    }
}

SecretBox.main()
