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

---

## Overview

The Auth Key System uses a **secure socket connection (SSL/TLS)** to validate license keys. It supports:
- **HWID Locking**: Keys are locked to the user's hardware ID after first use.
- **Challenge-Response Security**: Prevents replay attacks by issuing a cryptographic challenge that the client must sign.
- **Encrypted Traffic**: All communication is encrypted via TLS 1.2/1.3.

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
- **Session Security**: The server issues a random challenge. The client must HMAC-SHA256 hash this challenge with the Key to prove ownership without sending the key securely again (Double Verification).

---

## Client Implementation

Usage for all languages follows this flow:
1. Connect to `socket.keyauth.shop:3389`.
2. Send byte "2" to initiate handshake.
3. Wait 200ms.
4. Send `PROJECT_ID|KEY|HWID`.
5. If server returns `CHALLENGE|ID|NONCE`, calculate `HMAC_SHA256(Key, NONCE)` and send back `RESPONSE|ID|SIGNATURE`.
6. If server returns `ACCESS|...`, login is successful.

### Python
Requires: `pip install wmi` (Windows)

```python
# See Templates/Python.py for full code
import ssl, wmi, hashlib, sys, time, hmac
from socket import socket, AF_INET, SOCK_STREAM

def authenticate(PROJECT_ID, key):
    # ... (implementation details)
    # 1. Connect SSL Socket
    # 2. Send handshake
    # 3. Handle ChallengeResponse
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
// See Templates/ruby.rb for full code
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

## Support
For issues, ensure your **Project ID** is correct and your firewall allows connections to port `3389`.
