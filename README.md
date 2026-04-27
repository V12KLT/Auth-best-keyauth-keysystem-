JOIN OUR DISCORD FOR ALL NEW VERSIONS & INFO -> https://discord.gg/x2P52WwqWf

[HOW TO USE.md](https://github.com/user-attachments/files/24622491/HOW.TO.USE.md)

# Auth Key System Documentation

Welcome to the **Auth Key System**. This documentation covers how to connect, authenticate, and manage users using our secure TCP/TLS socket protocol.

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Features](#features)
4. [Client Implementation (Languages)](#client-implementation)
    - [Python](#python)
    - [C#](#c-sharp)
    - [C++](#c-plus-plus)
    - [JavaScript (Node.js)](#javascript)
    - [Go](#go)
    - [Java](#java)
    - [PHP](#php)
    - [Ruby](#ruby)
    - [Rust](#rust)
5. [Advanced Features](#advanced-features)
    - [Secure File Delivery](#secure-file-delivery)
    - [Signed Webhooks](#signed-webhooks)
    - [App Integrity Hash](#app-integrity-hash)
    - [Cloud Variables](#cloud-variables)

---

## Overview

The Auth Key System uses a **secure socket connection (SSL/TLS)** to validate license keys. It supports:
- **HWID Locking**: Keys are locked to the user's hardware ID after first use.
- **Challenge-Response Security**: Prevents replay attacks by issuing a cryptographic challenge that the client must sign.
- **Encrypted Traffic**: All communication is encrypted via TLS 1.2/1.3.
- **Secure File Delivery**: Encrypted files delivered in-memory only after successful authentication.
- **Signed Webhooks**: Server-side HMAC-signed proxy requests that crackers cannot forge.
- **App Integrity Hash**: Reject tampered or cracked executables before they can authenticate.

**Server Address**: `socket.keyauth.shop`
**Port**: `3389`

---

## Prerequisites

Before implementing the client, you need your **Project ID**.
1. Log in to the management tool (`auth.py`).
2. Go to **Project Settings**.
3. Copy your `Project ID` (it will look like a 32-character hex string, e.g., `e0bc069afb6a0e4de767700dab2e8b90`).

You will replace `ENTER_PROJECT_ID_HERE` with this ID in the code examples below.

---

## Features

- **License Key Login**: Users log in with a single license key.
- **Hardware Locking**: The system automatically grabs the user's HWID (UUID) and locks the key to it.
- **Expiration Management**: Keys can have durations (1 day, 1 week, etc.) or be permanent.
- **Session Security**: The server issues a random challenge. The client must HMAC-SHA256 hash this challenge with the Key to prove ownership without sending the key in plaintext again (Double Verification).
- **Secure File Delivery** *(new)*: Upload a DLL, EXE, script, or any payload to the server. It is only decrypted and delivered in-memory to clients that pass authentication. A cracker who bypasses the auth check receives nothing.
- **Signed Webhooks** *(new)*: The auth server acts as a trusted proxy between your client and your private server. Every forwarded request carries an HMAC-SHA256 signature only the auth server can produce — your server rejects anything unsigned.
- **App Integrity Hash** *(new)*: Register the SHA-256 hash of your compiled executable. Any client whose binary hash does not match a registered hash is rejected at the authentication stage, preventing cracked/modified copies from connecting.
- **Cloud Variables**: Store configuration strings, offsets, API keys, or any critical data on the server. Clients fetch them only after authentication — if auth is bypassed, the variable is never returned and the program has nothing to work with.

---

## Client Implementation

Usage for all languages follows this flow:

1. Connect to `socket.keyauth.shop:3389`.
2. Send byte `"2"` to initiate handshake.
3. Wait 200ms.
4. Send `PROJECT_ID|KEY|HWID` (optionally `PROJECT_ID|KEY|HWID|APP_HASH` if app integrity is enabled).
5. If server returns `CHALLENGE|ID|NONCE`, calculate `HMAC_SHA256(Key, NONCE)` and send back `RESPONSE|ID|SIGNATURE`.
6. If server returns `ACCESS|...`, login is successful.

### Python
Requires: `pip install cryptography`

```python
from Templates.Python import authenticate, start_session, download_file, call_webhook

PROJECT_ID = "ENTER_PROJECT_ID_HERE"
key = input("Enter your license key: ")

if authenticate(PROJECT_ID, key, send_app_hash=True):
    start_session(PROJECT_ID, key)
    print("Authenticated.")

    payload = download_file(PROJECT_ID, key, "payload.dll")
    if payload is None:
        sys.exit(1)

    result = call_webhook(PROJECT_ID, key, "my-webhook", {"action": "get_config"})
else:
    sys.exit(1)
```

### C#
Requires: `.NET Framework 4.7.2+` or `.NET Core`

```csharp
// See Templates/csharp.cs for full code
using System.Net.Sockets;
using System.Net.Security;

public class KeyAuth {
    public static bool Authenticate(string key) {
        // ... (implementation details)
    }
}
```

### C++
Requires: `OpenSSL` libraries linked.

```cpp
// See Templates/cpp.cpp for full code
#include <openssl/ssl.h>
#include <openssl/hmac.h>

bool authenticate(const std::string& key) {
    // ... (implementation details)
}
```

### JavaScript
Requires: Node.js

```javascript
// See Templates/js.js for full code
const tls = require('tls');
const crypto = require('crypto');

function authenticate(key) {
    // ... (implementation details)
}
```

### Go
No external dependencies.

```go
// See Templates/go.go for full code
import (
    "crypto/hmac"
    "crypto/tls"
    // ...
)

func authenticate(key string) bool {
    // ...
}
```

### Java
Standard Java Library (JDK 8+)

```java
// See Templates/java.java for full code
import javax.net.ssl.*;

public class KeyAuth {
    public static boolean authenticate(String key) {
        // ...
    }
}
```

### PHP
Requires: `openssl` extension enabled.

```php
// See Templates/php.php for full code
<?php
function authenticate($key) {
    // ...
}
?>
```

### Ruby
Standard Library.

```ruby
# See Templates/ruby.rb for full code
require 'socket'
require 'openssl'

def authenticate(key)
    # ...
end
```

### Rust
Requires: `native-tls`, `hmac`, `sha2`, `hex` crates.

```rust
// See Templates/rust.rs for full code
use native_tls::TlsConnector;
use hmac::{Hmac, Mac};

fn authenticate(key: &str) -> Result<bool, Box<dyn std::error::Error>> {
    // ...
}
```

---

## Advanced Features

### Secure File Delivery

Upload a file (DLL, EXE, script, config, etc.) to your project from the management dashboard. After a client authenticates, it can request the file by name. The server:

1. Re-encrypts the file using **AES-256-GCM** with a per-request key derived from the client's license key.
2. Sends the encrypted bytes over the TLS connection.
3. The client decrypts entirely **in memory** — the file is never written to disk.

If a cracker patches the `authenticate()` call to return `True`, they still get nothing from `download_file()` because the decryption key is derived from the real license key, which they do not have.

**Dashboard commands (management tool):**
| Command | Description |
|---|---|
| `upload_file\|name\|description\|base64data` | Upload or replace a file |
| `list_files` | List all files for the project |
| `delete_file\|name` | Delete a file |
| `toggle_file\|name` | Enable or disable a file |

**Python client usage:**
```python
payload_bytes = download_file(PROJECT_ID, key, "payload.dll")
if payload_bytes is None:
    sys.exit(1)
```

**Protocol:** `6` — send `PROJECT_ID|KEY|HWID|FILE_NAME`, receive length-prefixed AES-256-GCM encrypted bytes.

---

### Signed Webhooks

Register a webhook URL (must be `https://`) in the management dashboard. When a client calls `call_webhook()`, the auth server:

1. Validates the client's key.
2. POSTs the payload to your private server with these headers:

| Header | Value |
|---|---|
| `X-KeySystem-Signature` | `sha256=HMAC-SHA256(secret, timestamp.payload)` |
| `X-KeySystem-Timestamp` | Unix timestamp |
| `X-KeySystem-Project` | Project ID |
| `X-KeySystem-Key-Hash` | First 16 chars of the key hash |

Your server verifies the `X-KeySystem-Signature` using the webhook secret shown once when you create the webhook. Crackers cannot forge this signature because only the auth server knows the secret.

**Dashboard commands (management tool):**
| Command | Description |
|---|---|
| `add_webhook\|name\|https://your-url/hook` | Create a webhook (returns secret once) |
| `list_webhooks` | List all webhooks with their secrets |
| `delete_webhook\|name` | Delete a webhook |
| `toggle_webhook\|name` | Enable or disable a webhook |

**Python client usage:**
```python
status, body = call_webhook(PROJECT_ID, key, "my-webhook", {"user": "abc"})
```

**Verifying the signature on your server (Python example):**
```python
import hmac, hashlib

def verify_webhook(request):
    secret = "YOUR_WEBHOOK_SECRET"
    timestamp = request.headers["X-KeySystem-Timestamp"]
    payload = request.body.decode()
    expected = "sha256=" + hmac.new(
        secret.encode(), f"{timestamp}.{payload}".encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(request.headers["X-KeySystem-Signature"], expected)
```

**Protocol:** `7` — send `PROJECT_ID|KEY|HWID|WEBHOOK_NAME|JSON_PAYLOAD`, receive `OK|STATUS_CODE|RESPONSE_BODY`.

---

### App Integrity Hash

Register the SHA-256 hash of your compiled executable in the management dashboard. Once at least one hash is registered for a project, authentication is strict:

- Clients **must** send their binary hash as a 4th field: `PROJECT_ID|KEY|HWID|APP_HASH`.
- If the hash does not match any registered hash → authentication is rejected with `App integrity check failed`.
- A cracker who modifies your `.exe` produces a different SHA-256 and is blocked before the challenge-response even begins.
- When you release a new version, add its hash to the dashboard. Old hashes can be toggled off at any time.

**Dashboard commands (management tool):**
| Command | Description |
|---|---|
| `add_app_hash\|sha256hex\|description` | Register an allowed binary hash |
| `list_app_hashes` | List all registered hashes |
| `delete_app_hash\|sha256hex` | Remove a hash |
| `toggle_app_hash\|sha256hex` | Enable or disable a hash |

**Python client usage:**
```python
if authenticate(PROJECT_ID, key, send_app_hash=True):
    start_session(PROJECT_ID, key)
```

The `send_app_hash=True` flag automatically hashes `sys.executable` (the compiled `.exe`) and appends it to the authentication packet.

---

### Cloud Variables

Store any string value (offsets, API keys, decryption keys, config) on the server. Clients fetch them only after successful authentication.

```python
rows = get_table_rows(PROJECT_ID, key, "config")
vital_offset = rows[0]["data"]["offset"]
```

If a cracker bypasses `authenticate()`, `get_table_rows()` still re-validates the key server-side and returns nothing. The program has no data to run with.

---

## Security Recommendations

To get the most out of this system:

1. **Enable App Integrity Hash** — register your `.exe` hash so cracked copies are blocked at the server.
2. **Use Secure File Delivery** for any payload your application needs to function. Never ship it inside the executable.
3. **Store critical config in Cloud Variables** — don't hardcode offsets, keys, or API URLs in your binary.
4. **Use Signed Webhooks** for any calls to your private server — never let clients call your server directly.
5. **Obfuscate your binary** with a packer (PyInstaller + PyArmor, VMProtect, Themida) — the combination of server-side security and client-side obfuscation is what makes cracking practically infeasible.

---

## Support
For issues, ensure your **Project ID** is correct and your firewall allows outbound connections to port `3389`.

Join our Discord for support and updates: https://discord.gg/x2P52WwqWf
