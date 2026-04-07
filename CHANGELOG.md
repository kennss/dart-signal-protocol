# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.1] - 2026-04-07

### Added

- Initial alpha release extracted from the SnowChat messenger project.
- Pure Dart implementation of the Signal Protocol with zero native
  dependencies.

#### Cryptographic primitives
- `x25519.dart` — X25519 Diffie-Hellman key exchange via TweetNaCl's
  `crypto_scalarmult` (raw, no HSalsa20). Includes Ed25519 ↔ X25519 key
  conversion via TweetNaClExt.
- `hkdf.dart` — Pure Dart SHA-256, HMAC-SHA256, and HKDF (RFC 5869)
  implementations.

#### Signal Protocol — 1:1 messaging
- `prekey_bundle.dart` — PreKey bundle data class with Ed25519 signature
  verification.
- `x3dh.dart` — Extended Triple Diffie-Hellman key agreement
  (Signal X3DH specification).
- `double_ratchet.dart` — Double Ratchet algorithm with header AEAD
  binding, forward secrecy, post-compromise security, and
  out-of-order message handling via skipped message keys.

#### Signal Protocol — group messaging
- `sender_key.dart` — Sender Key implementation for group messaging.
  Supports Multi-State SenderKeyRecord (5 generations), out-of-order
  cache (up to 25,000 messages forward), and 31-bit random chain_id
  for generation identification.
- `sender_key_tracker.dart` — Distribution tracker that records which
  members have received the current sender key, enabling O(K) instead
  of O(N) SKDM redistribution.
- `message_send_log.dart` — 24-hour message log infrastructure for
  retry-request handling.

#### File encryption
- `file_encryptor.dart` — XSalsa20-Poly1305 file body encryption with
  per-file keys derived via HKDF.

#### Service layer
- `signal_protocol_service.dart` — High-level orchestrator combining
  X3DH session establishment, Double Ratchet messaging, and Sender Key
  group messaging.

#### Logging
- `logger.dart` — Optional debug logging facade. By default the library
  produces no log output. Users can register a callback via
  `setSignalProtocolLogger()` to receive internal debug messages.

### Security audit history (inherited from SnowChat)

This implementation has undergone three rounds of internal security
review prior to extraction:

- Round 1: 7 issues found (C-1, C-2, C-3, H-1 ~ H-4) — all resolved.
- Round 2: 4 additional issues — all resolved.
- Round 3: 2 actionable issues (N-5, N-7) — resolved.

Notable security fixes:
- Use raw `crypto_scalarmult` instead of `Box.sharedKey` (the latter
  applies HSalsa20 on top, which is incompatible with Signal Protocol).
- Reject all-zero X25519 DH outputs to prevent small-subgroup attacks.
- Header AEAD binding in Double Ratchet to prevent message reordering
  across rachet steps.
- 64-bit big-endian SHA-256 length encoding (FIPS 180-4 compliance).
- Explicit Ed25519 signature verification on signed prekeys.

### Known limitations

- **No external security audit.** This is an alpha-quality library
  extracted from an in-development project. Do not use in production
  without independent cryptographic review.
- **Wire format compatibility with libsignal not verified.** This
  implementation has been tested against itself only. Do not assume
  it can interoperate with other Signal Protocol implementations.
- **No Sealed Sender, PNI, or ZKGroup.** These features are not
  implemented.
- **No persistence layer.** Storage interfaces are not provided —
  callers must implement their own session/identity stores.
- **Side-channel resistance.** Dart VM/JIT execution may exhibit
  timing characteristics that differ from native implementations.
  No formal side-channel analysis has been performed.

### Notes

- Extracted from the SnowChat messenger project (private repository).
- The original codebase contains additional integration code
  (storage, networking, UI, business logic) that is not part of this
  library.
