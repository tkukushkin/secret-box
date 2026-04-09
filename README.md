# secret-box

A macOS CLI tool for secure secret storage with Touch ID authentication.

## Features

- Reading a secret requires Touch ID confirmation
- Authorization is granted per-app per-secret and cached for 10 minutes
- Binary data supported via stdin

## Installation

```
swift build -c release
cp .build/release/secret-box /usr/local/bin/
```

## Usage

```
# Save a secret
secret-box write my-secret "some-value"

# Save from stdin (text or binary data)
echo -n "some-value" | secret-box write my-secret
cat cert.pem | secret-box write my-cert

# Read a secret (Touch ID required)
secret-box read my-secret

# Read without caching the session
secret-box read --once my-secret

# Output to a file
secret-box read my-cert > cert.pem

# List secrets
secret-box list

# Delete secrets
secret-box delete my-secret my-cert

# Delete all data and the master key
secret-box reset
secret-box reset --yes  # skip confirmation
```

## Data storage

- Master key is stored in macOS Keychain
- Secrets and auth cache are stored in `~/Library/Application Support/secret-box/db.sqlite3`
- `secret-box reset` removes all data including the master key

## Requirements

- macOS 13+
- Touch ID
- Swift 5.9+
