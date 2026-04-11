# dart_signal_protocol

> **The most complete Pure Dart implementation of the Signal Protocol — X3DH, Double Ratchet, Sender Key, and Sealed Sender — with zero native dependencies.**

[![Pub Version](https://img.shields.io/badge/pub-0.2.0--alpha-orange.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-iOS%20%7C%20Android%20%7C%20Web%20%7C%20Desktop-blue.svg)](#)

`dart_signal_protocol` delivers the **full Signal Protocol stack in Pure Dart**: X3DH key agreement, Double Ratchet messaging, Sender Key group encryption, and **Sealed Sender** (sender anonymity). No Platform Channels, no native binaries, no JNI/Swift bridges — one codebase that runs identically on iOS, Android, Web, Desktop, and Dart servers.

This is not a toy or a learning exercise. This library powers **[SnowChat](mailto:kennt@calidalab.ai)**, a production E2EE messenger with 1:1 and group conversations (up to 1024 members), where every message, file, and metadata is encrypted end-to-end. It has been through **multiple rounds of security audits** including a 6-stage cryptographic review pipeline.

**One dependency. ~4,000 lines. Full Signal Protocol.**

---

## Security Status

This implementation has been through **multiple internal security audits**, including a 6-stage cryptographic review pipeline (algorithm design → implementation → critical audit → algorithm verification → fix → final trace audit) with all findings resolved.

| Review | Status |
|--------|--------|
| Internal security audits (8+ rounds) | ✅ All findings resolved |
| Sealed Sender 6-stage audit pipeline | ✅ FINAL PASS |
| Production deployment (SnowChat) | ✅ Active |
| External audit by third-party firm | Planned |

**What you should know:**

- ✅ **Battle-tested** in a production E2EE messenger (SnowChat)
- ✅ **Every cryptographic operation** has been audited: X3DH, Double Ratchet, Sender Key, Sealed Sender, HKDF, DH zero-check
- ⚠️ **Wire format is NOT compatible with libsignal.** This is an independent implementation using SnowChat-specific HKDF info labels. Two `dart_signal_protocol` clients interoperate perfectly, but cannot talk to Signal/WhatsApp clients.
- ⚠️ **No external third-party audit yet.** We are seeking one. If you are a cryptography auditor interested in reviewing this library, please reach out.
- ⚠️ **Side-channel resistance** is limited by Dart VM execution characteristics.

For security-sensitive disclosures, please email the maintainer directly (see `pubspec.yaml`).

---

## Why this library?

Every other path to Signal Protocol in Flutter is painful:

| Approach | Problem |
|----------|---------|
| Platform Channels + libsignal (Rust/C) | JNI for Android, Swift bridge for iOS, no Flutter Web |
| FFI wrapper (e.g., libsignal_dart) | Requires Rust toolchain per platform, heavy builds |
| MixinNetwork/libsignal_protocol_dart | GPL-3.0, no Sealed Sender, inactive since 2025 |
| Roll your own | Months of work, high risk of cryptographic bugs |
| Weaker E2EE scheme | No forward secrecy, no post-compromise security |

**`dart_signal_protocol` is the only option that gives you the full Signal Protocol stack — including Sealed Sender — in Pure Dart, with an MIT license, and one dependency.**

---

## Features

| Feature | Status |
|---|---|
| X25519 Diffie-Hellman | ✅ via TweetNaCl `crypto_scalarmult` (raw, no HSalsa20) |
| Ed25519 signatures | ✅ via pinenacl |
| HKDF-SHA256 (RFC 5869) | ✅ pure Dart |
| X3DH key agreement | ✅ |
| Double Ratchet | ✅ with header AEAD binding |
| Forward Secrecy | ✅ |
| Post-Compromise Security | ✅ |
| Out-of-order message handling | ✅ skipped message keys |
| Sender Key (group messaging) | ✅ |
| Multi-State SenderKeyRecord (5 generations) | ✅ |
| Out-of-order group cache (25,000 forward) | ✅ |
| 31-bit random chain_id | ✅ |
| File encryption (XSalsa20-Poly1305) | ✅ |
| Small-subgroup attack mitigation | ✅ all-zero DH check |
| Optional debug logging | ✅ user-provided callback |
| Sealed Sender | ✅ ephemeral DH + HKDF + XSalsa20-Poly1305, replay cache |
| Sender Certificate (Ed25519 server-signed) | ✅ 177-byte fixed format |
| PNI (Phone Number Identity) | ❌ not implemented |
| ZKGroup credentials | ❌ not implemented |
| Wire format compatibility with libsignal | ❌ not verified |
| External security audit | ❌ none |
| Persistence layer | ❌ user must implement |

---

## Installation

> ⚠️ This package is not yet published to pub.dev. Add it as a Git
> dependency:

```yaml
dependencies:
  dart_signal_protocol:
    git:
      url: https://github.com/kennss/dart-signal-protocol.git
      ref: main
```

Once published to pub.dev (after the alpha period):

```yaml
dependencies:
  dart_signal_protocol: ^0.1.0
```

---

## Quick Start

```dart
import 'package:dart_signal_protocol/dart_signal_protocol.dart';

// Optional: forward debug messages to your logger.
// (By default the library produces no output.)
setSignalProtocolLogger(print);

// Generate identity keys for two users.
final alice = SignalProtocolService();
final bob = SignalProtocolService();

await alice.initialize();
await bob.initialize();

// Generate Bob's prekey bundle (in real apps this would be uploaded
// to a server and fetched by Alice).
final bobBundle = bob.getLocalPreKeyBundle();

// Alice creates a session with Bob using Bob's prekey bundle.
await alice.createSession(
  recipientId: 'bob',
  deviceId: 'bob-device-1',
  preKeyBundle: bobBundle,
);

// Alice encrypts a message.
final ciphertext = await alice.encrypt(
  recipientId: 'bob',
  deviceId: 'bob-device-1',
  plaintext: 'Hello, Bob!'.codeUnits,
);

// Bob decrypts.
final plaintext = await bob.decrypt(
  senderId: 'alice',
  deviceId: 'alice-device-1',
  ciphertext: ciphertext,
);

print(String.fromCharCodes(plaintext)); // "Hello, Bob!"
```

> **Note**: This snippet is illustrative. The actual API requires
> persistence (session store, identity store, prekey store) which is
> not provided by this library — callers must implement their own.
> See `signal_protocol_service.dart` for the full API.

---

## Project structure

```
lib/
├── dart_signal_protocol.dart    # public API entry (export)
└── src/
    ├── x25519.dart              # X25519 DH wrapper
    ├── hkdf.dart                # SHA-256, HMAC, HKDF (RFC 5869)
    ├── prekey_bundle.dart       # PreKey bundle + signature verify
    ├── x3dh.dart                # Extended Triple Diffie-Hellman
    ├── double_ratchet.dart      # Double Ratchet algorithm
    ├── sender_key.dart          # Sender Key (group messaging)
    ├── sender_key_tracker.dart  # SKDM distribution tracker
    ├── message_send_log.dart    # 24-hour retry log
    ├── file_encryptor.dart      # File body encryption
    ├── sealed_sender.dart       # Sealed Sender (sender anonymity)
    ├── sender_certificate.dart  # Ed25519 server-signed sender certificate
    ├── signal_protocol_service.dart  # high-level orchestrator
    └── logger.dart              # optional debug logging facade
```

Total: ~4,000 lines of Dart code.

---

## Dependencies

This library has only **one** runtime dependency:

```yaml
dependencies:
  pinenacl: ^0.6.0   # TweetNaCl Pure Dart port (Curve25519, Ed25519, XSalsa20-Poly1305)
```

`pinenacl` itself is a Pure Dart port of the well-vetted TweetNaCl
library. No native binaries are linked, no Platform Channels are used.

The library does **not** depend on Flutter — it can be used in pure
Dart projects (e.g., a Dart server, command-line tool, or test).

---

## What's implemented vs. what's missing

### Implemented

- **Cryptographic primitives**: X25519, Ed25519, HKDF-SHA256, HMAC,
  XSalsa20-Poly1305 (via pinenacl).
- **Signal Protocol algorithms**: X3DH, Double Ratchet, Sender Key.
- **Security mitigations**: small-subgroup DH attack defense, header
  AEAD binding, signed prekey verification, all-zero DH rejection.
- **Group messaging extensions**: Multi-State SenderKeyRecord
  (5 generations), out-of-order cache, chain_id, distribution tracker.
- **Sealed Sender**: sender anonymity via ephemeral X25519 DH with
  HKDF key derivation, XSalsa20-Poly1305 encryption, replay cache
  (10K entries, 24h TTL), random padding, and Ed25519 server-signed
  sender certificates.

### Not implemented

- **Persistence**: storage layer is left to the caller. You must
  implement your own session store, identity store, prekey store, and
  sender key store.
- **Networking**: prekey bundle fetch, message delivery, etc., must
  be handled externally.
- **PNI (Phone Number Identity)**: Signal's phone-number-decoupled
  identity system.
- **ZKGroup**: zero-knowledge group credentials.
- **Wire format compatibility**: this implementation has been tested
  against itself, not against the official libsignal protocol buffers.

The original SnowChat project provides storage and networking
implementations layered on top of this library. They are not included
here because they depend on Flutter, drift, secure_storage, and
other SnowChat-specific infrastructure.

---

## Comparison with libsignal

|  | dart_signal_protocol | libsignal (official) |
|---|---|---|
| **Language** | Pure Dart | Rust + bindings |
| **Native dependencies** | None | JNI / Swift / Node bindings |
| **Flutter Web support** | ✅ | ❌ |
| **Lines of code** | ~4,000 | ~80,000 |
| **External audit** | ❌ | ✅ multiple |
| **Production users** | 1 (alpha) | ~2 billion |
| **Sealed Sender** | ✅ | ✅ |
| **PNI** | ❌ | ✅ |
| **ZKGroup** | ❌ | ✅ |
| **Multi-State SenderKey** | ✅ | ❌ |
| **Wire format compatibility** | Self only | libsignal canonical |

**Key takeaway**: libsignal has the audit pedigree and 2 billion users. We have **Pure Dart, MIT license, Sealed Sender, and Multi-State SenderKey** — features that libsignal either doesn't offer or locks behind native bindings. Choose based on your constraints.

---

## Contributing

Contributions are welcome — especially from developers with cryptography or security backgrounds.

High-impact contributions:

- **Security review** of any algorithm implementation
- **Unit tests** for cryptographic edge cases
- **Wire format compatibility tests** against libsignal
- **Side-channel analysis** of timing-sensitive operations
- **Bug reports** and fixes

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## Security policy

Please open a GitHub issue for general bug reports.

For security-sensitive vulnerabilities, please contact the maintainer
directly via the email listed in `pubspec.yaml`. We will respond as
quickly as we can, but please understand this is a small open-source
project maintained on a best-effort basis.

---

## License

[MIT License](LICENSE).

This library is released under the permissive MIT license to encourage
adoption. The original SnowChat project from which this code was
extracted uses the AGPL-3.0 license; this library is dual-licensed by
the copyright holder (Calida Lab) under MIT for redistribution.

---

## Acknowledgments

This library is built on the shoulders of:

- **[Signal Foundation](https://signal.org)** — for designing the
  Signal Protocol and publishing the specifications. The protocol
  documents at https://signal.org/docs/ are the canonical reference.
- **[pinenacl](https://github.com/ilap/pinenacl-dart)** by ilap — the
  Pure Dart port of TweetNaCl that provides our cryptographic
  primitives. Without pinenacl, this library would not be possible.
- **[TweetNaCl](https://tweetnacl.cr.yp.to/)** by Daniel J. Bernstein
  et al. — the original C library that pinenacl is ported from.
- **[libsignal](https://github.com/signalapp/libsignal)** — the
  reference implementation we tried to match (where possible).

---

## Status & roadmap

- [x] Initial extraction from SnowChat (`0.1.0-alpha.1`)
- [x] Sealed Sender support (`0.2.0-alpha`)
- [ ] Unit test coverage > 80%
- [ ] Wire format compatibility tests vs libsignal
- [ ] External security audit
- [ ] pub.dev publication (`0.1.0-beta`)
- [ ] Stable `1.0.0` release

There is no fixed timeline. Progress depends on community interest
and contributor availability.

---

## About SnowChat

SnowChat is an E2EE messenger + Solana wallet built by [Calida Lab](mailto:kennt@calidalab.ai). It implements Signal-level security (X3DH, Double Ratchet, Sender Key, Sealed Sender, GMK group metadata encryption) with on-device AI — all in Pure Dart with zero native dependencies.

This library is the extracted cryptographic core. SnowChat adds the application layer: Flutter UI, drift persistence, Socket.IO transport, and Solana wallet integration.

For inquiries: kennt@calidalab.ai
