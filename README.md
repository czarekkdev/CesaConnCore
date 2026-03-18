# CesaConn

<div align="center">
  <img src="https://your-logo-url.png" alt="CesaConn Logo" width="200"/>
  
  ### Ready. Set. Connect.
  
  *CesaConn — connecting all your devices together securely.*

  ![Status](https://img.shields.io/badge/status-in%20development-yellow)
  ![License](https://img.shields.io/badge/license-GPL%203.0-blue)
  ![Language](https://img.shields.io/badge/language-Rust-orange)
  ![Coming](https://img.shields.io/badge/coming-2026%2F2027-gold)
</div>

---

## What is CesaConn?

CesaConn is a **secure, serverless, cross-platform device synchronization application** built by [CesaSec](https://cesasec.com).

Sync your files, clipboard, notifications, and more — across all your devices — without any central server ever seeing your data. Your data stays yours.

---

## Why CesaConn?

Most sync solutions force you to trust a third party with your data. CesaConn is different:

- **No central server** — data travels directly between your devices
- **End-to-end encrypted** — nobody can read your data, not even us
- **You are in full control** — every feature can be turned on or off
- **Zero data collection** — we don't know who you are, and we don't want to

---

## Security Architecture

CesaConn is built with a military-grade security stack:

| Layer | Technology | Purpose |
|---|---|---|
| Key Exchange | X25519 ECDH | Secure shared secret — never transmitted |
| Encryption | AES-256-GCM | Authenticated encryption with integrity |
| Key Derivation | Argon2 | Password → cryptographic key |
| Salt Generation | OS Entropy (SysRng) | Cryptographically secure randomness |
| Signing | Ed25519 | Device authorization |
| Memory Safety | Zeroize | Keys wiped from RAM after use |

### How it works

```
Device A                          Device B
   │                                 │
   │──── ECDH Public Key ──────────►│
   │◄─── ECDH Public Key ───────────│
   │                                 │
   │  Both compute shared secret     │
   │  locally — never transmitted    │
   │                                 │
   │◄══════ AES-256-GCM ════════════►│
```

The encryption key is **never sent over the network**. Both devices independently derive the same key using ECDH mathematics. This is the same principle used by Signal, WhatsApp, and WireGuard.

---

## Features

### Planned for v1.0
- [ ] File synchronization
- [ ] Clipboard sync
- [ ] Notification mirroring
- [ ] End-to-end encryption
- [ ] Zero Trust device authorization
- [ ] Full offline / serverless operation

### Transport Support
- [ ] WiFi / LAN (TCP + UDP)
- [ ] WiFi Hotspot
- [ ] Bluetooth LE

### Platform Support
- [ ] Windows
- [ ] Linux
- [ ] Android
- [ ] macOS *(planned)*
- [ ] iOS *(under consideration)*

---

## Philosophy

> Every feature is **off by default** after updates. You decide what to enable. We don't decide for you.

CesaConn is built on the belief that software should serve the user — not the developer. No forced features. No hidden telemetry. No dark patterns.

---

## Repository Structure

```
CesaConn/
├── cesa_conn_core/         # Core cryptography library (LGPL 3.0)
│   ├── src/
│   │   ├── aes.rs          # AES-256-GCM encryption/decryption
│   │   ├── salt.rs         # Secure salt generation
│   │   ├── pswd_manager.rs # Argon2 key derivation
│   │   └── lib.rs
│   └── Cargo.toml
│
└── cesa_conn_networker/    # Networking layer
    ├── src/
    │   ├── udp_networker.rs # Device discovery (UDP broadcast)
    │   ├── tcp_networker.rs # Data transfer (TCP)
    │   └── lib.rs
    └── Cargo.toml
```

---

## Building from Source

### Requirements
- Rust 1.75+
- Cargo

### Build

```bash
git clone https://github.com/czarekkdev/CesaConnCore
cd CesaConnCore
cargo build --release
```

### Run Tests

```bash
cargo test
```

---

## Privacy

CesaConn is designed with privacy as a core principle, not an afterthought:

- **No account required** to use the application
- **No telemetry** — we don't collect usage data
- **No analytics** — we don't track you
- **No servers** — there is nothing to breach
- **Open source core** — verify our claims yourself

---

## License

- `cesa_conn_core` — [LGPL 3.0](LICENSE)
- `cesa_conn_networker` — [GPL 3.0](LICENSE)
- CesaConn application — Proprietary (CesaSec)

---

## About CesaSec

**CesaSec** — *Where Innovation Meets Security.*

CesaConn is a product of CesaSec, an independent security-focused software company.

- Website: [cesasec.com](https://cesasec.com)
- Coming: 2026 / 2027

---

<div align="center">
  <i>Built with ❤️ and Rust 🦀</i>
</div>