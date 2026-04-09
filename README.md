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
curl -fsSL https://github.com/tkukushkin/secret-box/releases/latest/download/secret-box -o /usr/local/bin/secret-box
chmod +x /usr/local/bin/secret-box
```

### Build from source

```bash
swift build -c release
cp .build/release/secret-box /usr/local/bin/
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

```bash
secret-box exec -e DB_PASSWORD=db-pass -- psql
secret-box exec -e DB_PASSWORD=db-pass -- psql '--password=$(DB_PASSWORD)'
secret-box exec -e DB_PASSWORD=db-pass -e API_KEY=api-key -- myapp
```

## Data storage

- Master key is stored in macOS Keychain
- Secrets and auth cache are stored in `~/Library/Application Support/secret-box/db.sqlite3`
- `secret-box reset` removes all data including the master key

## Requirements

- macOS 13+
- Touch ID
- Swift 5.9+

## License

[MIT](LICENSE)
