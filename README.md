# dart_signal_protocol

> **Pure Dart implementation of the Signal Protocol with zero native dependencies.**
>
> Extracted from the [SnowChat](https://calidalab.com) messenger project.

[![Pub Version](https://img.shields.io/badge/pub-0.1.0--alpha.1-orange.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-red.svg)](#-disclaimer)

`dart_signal_protocol` is a Pure Dart implementation of the [Signal
Protocol](https://signal.org/docs/), including X3DH key agreement,
Double Ratchet messaging, and Sender Key group messaging. It has **no
Platform Channel, no native binaries, no JNI/Swift bridge** — it runs
the same code on iOS, Android, Web, Desktop, and Dart server.

This library was extracted from the [SnowChat](https://calidalab.com)
messenger project, where it powers end-to-end encryption for both 1:1
and group conversations (up to 1024 members). It is being released as
an open-source library so that other Flutter and Dart developers can
use, study, and improve a Signal Protocol implementation that does not
require any native dependencies.

---

## ⚠️ Disclaimer

**This is an unaudited, alpha-quality implementation. Read this section
before using it.**

- ✅ **Suitable for**: learning, research, prototyping, hobbyist
  projects, reference for understanding the Signal Protocol.
- ❌ **NOT suitable for**: production use without independent
  cryptographic review.
- ❌ The author is not a cryptography expert. The implementation has
  undergone three rounds of internal security review but **no external
  audit by a professional cryptography firm**.
- ❌ **Wire format is NOT compatible with the official libsignal.**
  This implementation uses different HKDF info labels (e.g.,
  `SnowChat_X3DH`, `SnowChat_Ratchet`) inherited from the SnowChat
  project. Two clients using `dart_signal_protocol` can talk to each
  other, but they cannot interoperate with Signal, WhatsApp, or any
  other libsignal-based client.
- ❌ **Side-channel resistance is not formally analyzed.** Dart VM/JIT
  execution may have different timing characteristics than native
  implementations.
- ⚠️ **No warranty.** This software is provided AS IS. The authors
  accept no liability for any damages arising from its use.

If you are building a real product that protects real users, consider
using the official [libsignal](https://github.com/signalapp/libsignal)
via Platform Channels instead.

If you find a bug or vulnerability, please open an issue on GitHub.
For security-sensitive disclosures, please email the maintainer
directly (see `pubspec.yaml` for contact).

---

## Why does this exist?

Flutter has no first-class Signal Protocol implementation. Developers
who want to add end-to-end encryption to a Flutter app must currently
choose between:

1. **Platform Channels + native libsignal** — requires JNI for
   Android, Swift bridge for iOS, and does not work on Flutter Web.
2. **WebView with libsignal-client (TypeScript)** — performance and
   UX overhead.
3. **Implement Signal Protocol from scratch** — months of work and
   high risk of bugs.
4. **Use a weaker E2EE scheme** — gives up forward secrecy and other
   guarantees.

This library is option 5: a Pure Dart implementation that works on
every platform Flutter supports, with zero build complexity.

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
| Sealed Sender | ❌ not implemented |
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
    ├── signal_protocol_service.dart  # high-level orchestrator
    └── logger.dart              # optional debug logging facade
```

Total: ~3,400 lines of Dart code.

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

### Not implemented

- **Persistence**: storage layer is left to the caller. You must
  implement your own session store, identity store, prekey store, and
  sender key store.
- **Networking**: prekey bundle fetch, message delivery, etc., must
  be handled externally.
- **Sealed Sender**: Signal's sender anonymity feature.
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
| **Lines of code** | ~3,400 | ~80,000 |
| **External audit** | ❌ | ✅ multiple |
| **Production users** | 1 (alpha) | ~2 billion |
| **Sealed Sender** | ❌ | ✅ |
| **PNI** | ❌ | ✅ |
| **ZKGroup** | ❌ | ✅ |
| **Multi-State SenderKey** | ✅ | ❌ |
| **Wire format compatibility** | Self only | libsignal canonical |

If you need a battle-tested, externally-audited, wire-compatible
Signal Protocol implementation, use the official
[libsignal](https://github.com/signalapp/libsignal) via Platform
Channels.

If you need a Pure Dart implementation that runs everywhere Flutter
runs (including Web), have realistic expectations about its alpha
status, and are willing to read the source, this library may be
useful to you.

---

## Contributing

Contributions are welcome. The author is not a cryptography expert
and would especially appreciate review from anyone with security or
formal-methods background.

Particularly valuable contributions:

- **Security review** of any algorithm implementation.
- **Wire format compatibility tests** against libsignal.
- **Side-channel analysis** of timing-sensitive operations.
- **Unit tests** — the library currently lacks comprehensive test
  coverage.
- **API improvements** to make the library easier to use.
- **Documentation** improvements.
- **Bug reports** and fixes.

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
- [ ] Unit test coverage > 80%
- [ ] Wire format compatibility tests vs libsignal
- [ ] External security audit
- [ ] pub.dev publication (`0.1.0-beta`)
- [ ] Sealed Sender support
- [ ] Stable `1.0.0` release

There is no fixed timeline. Progress depends on community interest
and contributor availability.

---

## About SnowChat

SnowChat is an end-to-end encrypted messenger with an integrated
Solana wallet, currently in development by Calida Lab. The full
SnowChat application is private, but the Signal Protocol
implementation is being released here as open source so that other
Flutter and Dart developers can benefit from it.

For more about SnowChat, visit https://calidalab.com.
