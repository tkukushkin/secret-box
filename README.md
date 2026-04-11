# secret-box

[![Test](https://github.com/tkukushkin/secret-box/actions/workflows/test.yml/badge.svg)](https://github.com/tkukushkin/secret-box/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/tkukushkin/secret-box/graph/badge.svg)](https://codecov.io/gh/tkukushkin/secret-box)

A macOS CLI tool for secure secret storage with Touch ID authentication.

## Features

- **Touch ID protection** — reading a secret requires biometric confirmation
- **Per-app authorization** — access is granted per-app per-secret and cached for 10 minutes
- **AES-256-GCM encryption** — all secrets encrypted at rest
- **macOS Keychain integration** — master key stored in the system keychain
- **Binary data support** — store any data via stdin
- **Environment variable injection** — run commands with secrets as env vars

## Installation

```bash
curl -fsSL https://github.com/tkukushkin/secret-box/releases/latest/download/secret-box -o ~/.local/bin/secret-box
chmod +x ~/.local/bin/secret-box
```

### Install with Go

```bash
go install github.com/tkukushkin/secret-box@latest
```

### Build from source

```bash
go build -o secret-box
cp secret-box ~/.local/bin/
```

## Usage

### Save a secret

```bash
secret-box write my-secret "some value"
```

From stdin (text or binary):

```bash
echo -n "some value" | secret-box write my-secret
cat cert.pem | secret-box write my-cert
```

### Read a secret

```bash
# Touch ID required
secret-box read my-secret

# Authenticate but don't cache the session
secret-box read --once my-secret

# Output to a file
secret-box read my-cert > cert.pem
```

### List secrets

```bash
secret-box list
```

### Delete secrets

```bash
secret-box delete my-secret my-cert
```

### Reset all data

```bash
# Delete all secrets, auth cache, and the master key
secret-box reset

# Skip confirmation
secret-box reset --yes
```

### Run a command with secrets

Environment variables and command arguments containing `$(secret-name)` references
are resolved and replaced with actual secret values.

```bash
DB_PASSWORD='$(db-pass)' secret-box exec -- psql
DB_PASSWORD='$(db-pass)' secret-box exec -- psql '--password=$(db-pass)'
DB_PASSWORD='$(db-pass)' API_KEY='$(api-key)' secret-box exec -- myapp
DATABASE_URL='postgres://$(db-user):$(db-pass)@localhost/mydb' secret-box exec -- myapp
```

## Data storage

- Master key is stored in macOS Keychain
- Secrets and auth cache are stored in `~/Library/Application Support/secret-box/db.sqlite3`
- `secret-box reset` removes all data including the master key

## Requirements

- macOS 13+
- Touch ID
- Go 1.23+

## License

[MIT](LICENSE)
