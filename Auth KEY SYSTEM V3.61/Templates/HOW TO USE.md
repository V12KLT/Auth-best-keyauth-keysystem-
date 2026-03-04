# Auth Key System Documentation

Welcome to the **Auth Key System**. This documentation covers how to connect, authenticate, and manage users using our secure TCP/TLS socket protocol.

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Features](#features)
4. [Security Features](#security-features)
5. [Client Implementation (Languages)](#client-implementation)

---

## Overview

The Auth Key System uses a **secure socket connection (SSL/TLS)** to validate license keys. It supports:
- **HWID Locking**: Keys are locked to the user's hardware ID after first use.
- **Challenge-Response Security**: Prevents replay attacks by issuing a cryptographic challenge that the client must sign.
- **Encrypted Traffic**: All communication is encrypted via TLS 1.2/1.3.

**Server Address**: Obfuscated in templates (XOR-encrypted at rest)
**Port**: `3389`

---

## Prerequisites

Before implementing the client, you need your **Project ID**.
1. Log in to the management tool (`auth.py`).
2. Go to **Project Settings**.
3. Copy your `Project ID` (it will look like a 32-character hex string, e.g., `e0bc069afb6a0e4de767700dab2e8b90`).

You will replace `ENTER_PROJECT_ID_HERE` with this ID in the code.

---

## Features

- **License Key Login**: Users log in with a single license key.
- **Hardware Locking**: The system automatically grabs the user's HWID (UUID) and locks the key to it.
- **Expiration Management**: Keys can have durations (1 day, 1 week, etc.) or be permanent.
- **Session Security**: The server issues a random challenge. The client must HMAC-SHA256 hash this challenge with the Key to prove ownership (Double Verification).

---

## Security Features

Every template now includes production-grade security:

| Feature | Description |
|---------|-------------|
| **XOR String Obfuscation** | Server host/port are XOR-encrypted at rest, decoded only at runtime |
| **Encrypted Token Storage** | Auth tokens stored XOR-encrypted in memory with FNV-1a integrity canary |
| **Anti-Debug** | Detects debuggers (IsDebuggerPresent, JDWP, xdebug, etc.) |
| **Anti-Process** | Scans for known reverse engineering tools (x64dbg, IDA, Wireshark, dnSpy, etc.) |
| **Session Validation** | Background thread re-verifies session every 60 seconds |
| **Stealth Exit** | Exits silently without error messages on tampering detection |
| **Token Integrity** | FNV-1a canary detects memory tampering of stored tokens |
| **No Info Leakage** | Generic error messages, no details about what failed |

### C++ Exclusive Features
- Compile-time string obfuscation (strings never appear in plaintext in the binary)
- Hidden API resolution via PE export hash (APIs don't show in import table)
- Native Windows TLS via SSPI/SChannel (no OpenSSL dependency)
- Thread hiding from debuggers via NtSetInformationThread
- Stealth process termination via resolved TerminateProcess

---

## Client Implementation

Usage for all languages follows this flow:
1. Connect to the server on port `3389` via TLS.
2. Send byte "2" to initiate handshake.
3. Wait 200ms.
4. Send `PROJECT_ID|KEY|HWID`.
5. If server returns `CHALLENGE|ID|NONCE`, calculate `HMAC_SHA256(Key, NONCE)` and send back `RESPONSE|ID|SIGNATURE`.
6. If server returns `ACCESS|...`, login is successful. Token is stored encrypted.
7. Session validation thread starts automatically.

### Python
Requires: `pip install colorama` (optional)

### C# (.NET)
Requires: `.NET Framework 4.7.2+` or `.NET Core`

### C++ (Windows)
Requires: C++17 compiler, links against `ws2_32.lib`, `secur32.lib`, `bcrypt.lib`, `crypt32.lib`, `advapi32.lib`
No external dependencies (uses Windows-native SSPI/SChannel for TLS).
Define `KEYAUTH_HEADER_ONLY` to use as a header-only library.

### JavaScript (Node.js)
Requires: Node.js (uses built-in `tls`, `crypto` modules)

### Go
No external dependencies.

### Java
Standard Java Library (JDK 8+)

### PHP
Requires: `openssl` extension enabled.

### Ruby
Standard Library (OpenSSL).

### Rust
Requires: `native-tls`, `hmac`, `sha2`, `hex` crates.

---

## Support
For issues, ensure your **Project ID** is correct and your firewall allows connections to port `3389`.
