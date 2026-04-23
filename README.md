# dart_signal_protocol

> **The most complete Pure Dart implementation of the Signal Protocol — X3DH, Double Ratchet, Sender Key, and Sealed Sender — with zero native dependencies.**

[![Pub Version](https://img.shields.io/badge/pub-0.2.0--alpha.1-orange.svg)](#)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-iOS%20%7C%20Android%20%7C%20Desktop%20%7C%20Dart%20VM-blue.svg)](#)

`dart_signal_protocol` delivers the **full Signal Protocol stack in Pure Dart**: X3DH key agreement, Double Ratchet messaging, Sender Key group encryption, and **Sealed Sender** (sender anonymity). No Platform Channels, no native binaries, no JNI/Swift bridges — one codebase that runs identically on iOS, Android, Desktop, and Dart VM targets.

This library is the extracted cryptographic core of **[SnowChat](mailto:kennt@calidalab.ai)**, an E2EE messenger with 1:1 and group conversations (up to 1024 members). SnowChat has been running the hardened service-layer version of this code in production. The public package (`0.2.0-alpha.1`) contains the backport of those hardenings plus documentation of the residual risks — please read [`§ Known Risks Before You Use`](#known-risks-before-you-use) before adopting.

**One dependency. ~4,000 lines. Full Signal Protocol.**

---

## Security Status

| Review | Status |
|--------|--------|
| Internal security audits (multiple rounds, 2026-03 ~ 2026-04) | Multiple findings resolved; residual risks documented below |
| Sealed Sender 6-stage internal audit pipeline | Resolved within scope; replay-cache persistence tracked as open limitation |
| Production deployment — **SnowChat application** (service-layer code) | ✅ Active |
| Production deployment — **this pub package**, directly consumed | ❌ None verified |
| External third-party firm audit | Planned, no timeline |

### What this means in plain language

- ✅ The cryptographic primitives (X25519 DH, Ed25519, HKDF, XSalsa20-Poly1305) are sound and audited.
- ✅ X3DH, Double Ratchet, Sender Key, and Sealed Sender have been internally reviewed end-to-end.
- ⚠️ The **service layer** (`SignalProtocolService`) is what was battle-tested inside SnowChat. The lower-level classes (`DoubleRatchetSession`, `SenderKeyManager`, `SealedSenderService`) have known caller-responsibility contracts — see [`§ Known Risks`](#known-risks-before-you-use).
- ⚠️ **No external third-party audit** has been conducted. Do not deploy to high-stakes adversaries without additional review.
- ⚠️ The wire format uses `SnowChat_*` HKDF info labels and is **not compatible with libsignal**.
- ⚠️ Dart VM timing is not constant-time guaranteed; side-channel attacks on hostile multi-tenant environments are out of scope.

For security-sensitive disclosures, please email the maintainer directly (see [`SECURITY.md`](SECURITY.md)).

---

## Known Risks Before You Use

This library ships with a set of **caller-responsibility contracts** that you must honour to get the security guarantees advertised. Most of these are not enforceable at compile time; ignoring them will silently weaken your deployment.

### 1. Direct `DoubleRatchetSession.decrypt()` callers MUST implement snapshot/restore

[`DoubleRatchetSession.decrypt`](lib/src/double_ratchet.dart) advances ratchet state **before** the AEAD check succeeds. A forged message with a valid serialised header but a tampered ciphertext will roll `receivingChainKey` (and, in the DH-ratchet branch, `rootKey` + the whole receiving chain) forward, then throw on the Poly1305 check. A **single adversarial message can permanently desynchronise the chain** if the caller does nothing else.

The reference mitigation is implemented in [`SignalProtocolService._trialDecrypt`](lib/src/signal_protocol_service.dart): snapshot the session via `toJson()` before calling `decrypt()`, deserialise the snapshot back on exception. Archived sessions (1-hour TTL) extend the same defense to in-flight messages after session reset. **If you use `SignalProtocolService` you are covered.** If you call `DoubleRatchetSession.decrypt()` directly, you must implement the equivalent:

```dart
final snapshot = session.toJson();
try {
  return session.decrypt(message);
} catch (_) {
  restoreFromSnapshot(session, snapshot); // or replace with DoubleRatchetSession.fromJson(snapshot)
  rethrow;
}
```

The class-level docstring on `DoubleRatchetSession` carries this same warning.

### 2. Sealed Sender replay cache is in-memory only

`SealedSenderService._ReplayCache` is a process-local `Map`. On app restart the cache is cleared; an attacker who captured a sealed envelope earlier can re-deliver it during the 24-hour timestamp window and the unseal will succeed. **Whether this produces user-visible impact depends on what you layer below the Sealed Sender stage:**

- If the inner payload is a Double Ratchet ciphertext and the DR ratchet has advanced past that message number, DR rejects the replay (trial-decrypt rollback — see §1).
- If the inner payload is a Sender Key group ciphertext, the backported `cachedMessageKeys` (kept for drift-retry safety) **will return plaintext**. Your application must deduplicate (e.g. via `UNIQUE(sender, timestamp, conversation)` at the storage layer).
- If the inner payload is VoIP signalling, application-level state machines naturally reject stale signalling.

A persistent replay cache (spanning process restart) is on the roadmap but **not** in this release.

### 3. TOFU identity pinning is **opt-in**

`SignalProtocolService` accepts an optional `IdentityPinStore` in its constructor. If you do not inject one, `_tofuPinCheck` is a no-op — the library will accept **any** Ed25519 identity key the remote peer presents, on every session establishment.

```dart
// Unprotected: no pin store injected
final service = SignalProtocolService();

// Protected: TOFU enforcement active
final service = SignalProtocolService(
  identityPinStore: MyIdentityPinStore(), // your IdentityPinStore implementation
);
```

An `IdentityPinStore` implementation must be backed by platform-secure storage (iOS Keychain, Android Keystore, encrypted SQLite, etc.) — the library does not ship one to avoid prescribing a persistence layer.

Without this pin store wired up, a compromised server can silently swap a peer's identity key between sessions and the library will not raise `IdentityKeyChangedException`.

### 4. `SignalProtocolService` imports `dart:io`; Flutter Web builds WILL fail

`SignalProtocolService.saveSessionStore` / `loadSessionStore` use `dart:io`'s `File` class. This means:

- ✅ iOS, Android, macOS, Windows, Linux, Dart VM — full support.
- ❌ Flutter Web — `dart:io` is unavailable; build fails.

A platform-agnostic session-store adapter is on the roadmap. If you need Web today, you can use the lower-level classes (`DoubleRatchetSession`, `SenderKeyManager`, `SealedSenderService`, `X3DH`, `PreKeyGenerator`) directly and implement persistence yourself — those modules do not import `dart:io`. The `Platform` badge above reflects this reality (previous badges incorrectly listed Web as supported).

### 5. HKDF `info` labels are hardcoded to `SnowChat_*`

All domain-separation labels are constants:

```dart
_x3dhInfo        = "SnowChat_X3DH"
_rkInfo          = "SnowChat_Ratchet"
_sealedSenderInfo = "SnowChat_SealedSender_v1"
```

If you use this library as the cryptographic core of a non-SnowChat product, your keys are derived under SnowChat's domain separation. Two consequences:

1. Forensically your keys are traceable to this library's brand — acceptable for most use cases, but note it.
2. A future version may accept these labels via a config object; that would be a **wire-breaking** change. Track the [`CHANGELOG`](CHANGELOG.md) before upgrading.

---

## Why this library?

Every other path to Signal Protocol in Flutter is painful:

| Approach | Problem |
|----------|---------|
| Platform Channels + libsignal (Rust/C) | JNI for Android, Swift bridge for iOS, no Flutter Web |
| FFI wrapper (e.g., `libsignal_dart`) | Requires Rust toolchain per platform, heavy builds |
| `libsignal_protocol_dart` (MixinNetwork) | No Sealed Sender, inactive since 2025 |
| Roll your own | Months of work, high risk of cryptographic bugs |
| Weaker E2EE scheme | No forward secrecy, no post-compromise security |

**`dart_signal_protocol` is the only option that gives you the full Signal Protocol stack — including Sealed Sender — in Pure Dart, with one dependency.**

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
| Sealed Sender (ephemeral DH + HKDF + XSalsa20-Poly1305) | ✅ |
| Sender Certificate (Ed25519 server-signed) | ✅ 177-byte fixed format |
| TOFU identity pinning (optional, see §3) | ✅ interface; caller provides storage backend |
| Trial-decrypt with snapshot/restore (service layer) | ✅ `SignalProtocolService` |
| Archived sessions with TTL | ✅ 1h TTL for in-flight replays |
| Optional debug logging | ✅ user-provided callback |
| Sealed Sender persistent replay cache | ❌ in-memory only (see §2) |
| Flutter Web support | ❌ `SignalProtocolService` imports `dart:io` (see §4) |
| Configurable HKDF info labels | ❌ hardcoded `SnowChat_*` (see §5) |
| PNI (Phone Number Identity) | ❌ not implemented |
| ZKGroup credentials | ❌ not implemented |
| Wire format compatibility with libsignal | ❌ independent implementation |
| External security audit | ❌ none |
| Bundled persistence layer | ❌ caller implements |

---

## Installation

> ⚠️ This package is not yet published to pub.dev. Add it as a Git dependency:

```yaml
dependencies:
  dart_signal_protocol:
    git:
      url: https://github.com/kennss/dart-signal-protocol.git
      ref: main
```

pub.dev publication is deferred until after an external audit and the items tracked in [`§ Known Risks`](#known-risks-before-you-use) are addressed. See [`§ Status & roadmap`](#status--roadmap).

---

## Quick Start

```dart
import 'package:dart_signal_protocol/dart_signal_protocol.dart';

// Optional: forward debug messages to your logger.
// (By default the library produces no output.)
setSignalProtocolLogger(print);

// Generate identity keys for two users.
// SECURITY: inject an IdentityPinStore (see §3) before deploying.
final alice = SignalProtocolService();
final bob = SignalProtocolService();

await alice.generateIdentityKeyPair();
await alice.generateSignedPreKey(1);
await alice.generateOneTimePreKeys(100, 5);

await bob.generateIdentityKeyPair();
await bob.generateSignedPreKey(1);
await bob.generateOneTimePreKeys(200, 5);

final bobBundle = await bob.getPreKeyBundle();

// Alice creates a session with Bob using Bob's prekey bundle.
await alice.createSession(
  recipientId: 'bob',
  deviceId: 'bob-device-1',
  preKeyBundle: bobBundle,
);

// Alice encrypts a message.
final enc = await alice.encryptMessage(
  recipientId: 'bob',
  deviceId: 'bob-device-1',
  plaintext: Uint8List.fromList('Hello, Bob!'.codeUnits),
);

// Bob decrypts. Note: on prekey messages, supply the sender's Ed25519
// verify key so receive-side TOFU can run before installing the session.
final plaintext = await bob.decryptMessage(
  senderId: 'alice',
  deviceId: 'alice-device-1',
  ciphertext: enc['ciphertext'] as Uint8List,
  messageType: enc['messageType'] as int,
  senderIdentityKeyEd25519: alice.verifyKey,
);

print(String.fromCharCodes(plaintext)); // "Hello, Bob!"
```

> **Note**: Prekey bundle distribution, session storage encryption key derivation, and identity-pin-store implementation are your responsibility. See `signal_protocol_service.dart` for the full API.

---

## Project structure

```
lib/
├── dart_signal_protocol.dart               # public API entry (export)
└── src/
    ├── x25519.dart                         # X25519 DH wrapper
    ├── hkdf.dart                           # SHA-256, HMAC, HKDF (RFC 5869)
    ├── prekey_bundle.dart                  # PreKey bundle + signature verify
    ├── x3dh.dart                           # Extended Triple Diffie-Hellman
    ├── double_ratchet.dart                 # Double Ratchet (see §1 on direct use)
    ├── sender_key.dart                     # Sender Key (group messaging)
    ├── sender_key_tracker.dart             # SKDM distribution tracker
    ├── message_send_log.dart               # 24-hour retry log
    ├── file_encryptor.dart                 # File body encryption
    ├── sealed_sender.dart                  # Sealed Sender (see §2 on replay)
    ├── sender_certificate.dart             # Ed25519 server-signed sender certificate
    ├── identity_pin_store.dart             # TOFU pin interface (see §3)
    ├── identity_key_changed_exception.dart # typed TOFU mismatch exception
    ├── signal_protocol_service.dart        # high-level orchestrator (Flutter-free but dart:io)
    └── logger.dart                         # optional debug logging facade
```

Total: ~4,500 lines of Dart code.

---

## Dependencies

This library has only **one** runtime dependency:

```yaml
dependencies:
  pinenacl: ^0.6.0   # TweetNaCl Pure Dart port (Curve25519, Ed25519, XSalsa20-Poly1305)
```

`pinenacl` itself is a Pure Dart port of the well-vetted TweetNaCl library. No native binaries are linked, no Platform Channels are used.

The library does **not** depend on Flutter. `SignalProtocolService` imports `dart:io` for session-store persistence — see [`§ Known Risks #4`](#4-signalprotocolservice-imports-dartio-flutter-web-builds-will-fail).

---

## What's implemented vs. what's missing

### Implemented

- **Cryptographic primitives**: X25519, Ed25519, HKDF-SHA256, HMAC, XSalsa20-Poly1305 (via pinenacl).
- **Signal Protocol algorithms**: X3DH, Double Ratchet, Sender Key.
- **Security mitigations**: small-subgroup DH attack defense, header AEAD binding, signed prekey verification, all-zero DH rejection, fail-closed on missing sender Ed25519 verify key.
- **Group messaging extensions**: Multi-State SenderKeyRecord (5 generations), out-of-order cache, chain_id wire field, distribution tracker, origin SKDM cache, corrupt-recovery removal.
- **Sealed Sender**: sender anonymity via ephemeral X25519 DH with HKDF key derivation, XSalsa20-Poly1305 encryption, in-memory replay cache (10K entries, 24h TTL), random padding, and Ed25519 server-signed sender certificates.
- **Service-layer hardenings** (backported from SnowChat v0.2.0-alpha.1): multi-session storage per peer, archived sessions with TTL, snapshot/restore trial-decrypt, TOFU identity pin interface, plaintext-save refusal.

### Not implemented

- **Persistence back-ends**: session store encryption key derivation, identity pin store, prekey store implementations are left to the caller.
- **Networking**: prekey bundle fetch, message delivery, etc., must be handled externally.
- **PNI (Phone Number Identity)**: Signal's phone-number-decoupled identity system.
- **ZKGroup**: zero-knowledge group credentials.
- **Wire format compatibility with libsignal**: this implementation has been tested against itself.
- **Persistent Sealed Sender replay cache** (see [`§ Known Risks #2`](#2-sealed-sender-replay-cache-is-in-memory-only)).
- **Flutter Web support** (see [`§ Known Risks #4`](#4-signalprotocolservice-imports-dartio-flutter-web-builds-will-fail)).
- **Configurable HKDF info labels** (see [`§ Known Risks #5`](#5-hkdf-info-labels-are-hardcoded-to-snowchat_)).

The original SnowChat project provides storage, networking, and pin-store implementations layered on top of this library. They are not included here because they depend on Flutter, drift, secure_storage, and other SnowChat-specific infrastructure.

---

## Comparison with libsignal

|  | dart_signal_protocol | libsignal (official) |
|---|---|---|
| **Language** | Pure Dart | Rust + bindings |
| **Native dependencies** | None | JNI / Swift / Node bindings |
| **Flutter Web support** | ❌ (see §4) | ❌ |
| **Lines of code** | ~4,500 | ~80,000 |
| **External audit** | ❌ | ✅ multiple |
| **Production users (direct consumption)** | 0 (alpha) | ~2 billion (via Signal) |
| **Sealed Sender** | ✅ | ✅ |
| **PNI** | ❌ | ✅ |
| **ZKGroup** | ❌ | ✅ |
| **Wire format** | self-compatible | libsignal canonical |

**Key takeaway**: libsignal has the audit pedigree, 2 billion users, and features (PNI, ZKGroup) we do not offer. We provide **Pure Dart portability and Sealed Sender support without native bindings**. Choose based on your platform constraints and threat model. Both libraries are AGPL-3.0.

---

## Contributing

Contributions are welcome — especially from developers with cryptography or security backgrounds.

High-impact contributions:

- **Security review** of any algorithm implementation
- **Unit tests** for cryptographic edge cases (tampered headers, out-of-order bursts, state-rollback proofs)
- **Wire format compatibility tests** against libsignal
- **Side-channel analysis** of timing-sensitive operations
- **Persistent replay cache** implementation (addresses `§ Known Risks #2`)
- **Platform-agnostic session-store adapter** (addresses `§ Known Risks #4`)
- **Configurable HKDF info labels** (addresses `§ Known Risks #5`)
- **Bug reports** and fixes

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

---

## Security policy

Please open a GitHub issue for general bug reports.

For security-sensitive vulnerabilities, please follow [`SECURITY.md`](SECURITY.md).

---

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

Copyright (C) 2026 Kennt Kim, Calida Lab.

This library is released under the AGPL-3.0 — the same license used by Signal's reference implementation (`libsignal`). The license applies the standard copyleft obligations of GPL-3.0, and additionally requires that users interacting with a modified version over a network be offered the corresponding source code (§13).

If AGPL-3.0 is incompatible with your project, contact the copyright holder (kennt@calidalab.ai) about a commercial license.

---

## Acknowledgments

This library is built on the shoulders of:

- **[Signal Foundation](https://signal.org)** — for designing the Signal Protocol and publishing the specifications. The protocol documents at https://signal.org/docs/ are the canonical reference.
- **[pinenacl](https://github.com/ilap/pinenacl-dart)** by ilap — the Pure Dart port of TweetNaCl that provides our cryptographic primitives. Without pinenacl, this library would not be possible.
- **[TweetNaCl](https://tweetnacl.cr.yp.to/)** by Daniel J. Bernstein et al. — the original C library that pinenacl is ported from.
- **[libsignal](https://github.com/signalapp/libsignal)** — the reference implementation we tried to match (where possible).

---

## Status & roadmap

- [x] Initial extraction from SnowChat (`0.1.0-alpha.1`)
- [x] Sealed Sender support (`0.2.0-alpha`)
- [x] Service-layer hardenings backport (`0.2.0-alpha.1`) — archived sessions, trial-decrypt, TOFU pin interface, plaintext-save refusal
- [x] Public disclosure of residual risks (this README update)
- [ ] Persistent Sealed Sender replay cache
- [ ] Platform-agnostic session-store adapter (Flutter Web unblock)
- [ ] Configurable HKDF info labels
- [ ] External third-party security audit
- [ ] Unit test coverage > 80%
- [ ] Wire format compatibility tests vs libsignal
- [ ] pub.dev publication (`0.1.0-beta`)
- [ ] Stable `1.0.0` release

There is no fixed timeline. Progress depends on community interest and contributor availability.

---

## About SnowChat

SnowChat is an E2EE messenger + Solana wallet built by [Calida Lab](mailto:kennt@calidalab.ai). It implements Signal-level security (X3DH, Double Ratchet, Sender Key, Sealed Sender, GMK group metadata encryption) with on-device AI — all in Pure Dart with zero native dependencies.

This library is the extracted cryptographic core. SnowChat adds the application layer: Flutter UI, drift persistence, Socket.IO transport, and Solana wallet integration. Where this library's caller-responsibility contracts require storage-layer decisions (replay dedup, pin store, session-store encryption), SnowChat's application layer supplies them.

For inquiries: kennt@calidalab.ai
