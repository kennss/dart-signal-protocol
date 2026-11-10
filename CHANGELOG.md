# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0-alpha.1] - 2026-11-10

Second backport from the reference SnowChat deployment. These fixes had been
running in the SnowChat app since May–August 2026 but were only present in
the app's copy of the crypto code; this release brings the published library
back in line with it. Each fix is covered by a new regression test in
`test/signal_protocol_service_test.dart`.

### ⚠️ Breaking

- **X3DH HKDF info is now domain-separated by path** (SnowChat `ddfbe6d`).
  The unified `SnowChat_X3DH` info string is replaced by
  `SnowChat_X3DH_4DH` (no one-time prekey) and `SnowChat_X3DH_5DH` (with a
  one-time prekey). A silent mismatch between initiator and responder on
  whether an OPK was used now fails on the first AEAD check instead of
  deriving a quietly wrong shared secret. **0.2.x and 0.3.x peers cannot
  establish NEW sessions with each other.** Existing Double Ratchet sessions
  are unaffected (the ratchet never re-runs X3DH HKDF). Upgrade all peers
  together.
- **`saveSessionStore` returns `Future<bool>`** (was `Future<void>`) — see
  Changed. Callers that ignore the result keep compiling.

### Fixed

- **First-contact Sealed Sender messages were lost** (SnowChat `c062a09`).
  Sealed Sender hides the inner Signal message type from the transport, so a
  receiver that took `messageType` from the transport (defaulting to 1)
  misrouted the first prekey message from a new contact as a normal message;
  the X3DH responder branch never ran and the message could never be
  decrypted. New `SignalProtocolService.resolveSealedMessageType(drCiphertext,
  certIdentityKey)` derives the type from the self-describing DR ciphertext
  (prekey messages carry `identityKey` + `ephemeralKey`; normal messages
  never do). Non-JSON input degrades to type 1.
- **Receive-first bootstrap failed if the first PreKey message was lost**
  (SnowChat `dc71736`). `encryptMessage` used to clear the pending-PreKey
  state after the first send, so every later message was type-1 and a peer
  that never received the first one could not build the inbound session.
  The initiator now keeps emitting PreKey (type-2) messages until it
  successfully decrypts an inbound message on that specific session
  (libsignal behavior). The retire is per-session, never per-peer, so
  concurrent-initiation (glare) sessions are not flipped to type-1
  prematurely. The pending state is persisted in the session store.
- **Re-sent PreKey message after a reset was undecryptable** (SnowChat
  `dc71736`). A type-2 message whose one-time prekey was already consumed
  now falls back to archived sessions (as type-1 messages already did)
  before failing. `IdentityKeyChangedException` still propagates untouched.
- **Missing one-time prekey silently downgraded X3DH to 4-DH** (SnowChat
  `ddfbe6d`). When a PreKey message names a one-time prekey that is not in
  the local store, `decryptMessage` now throws `SignalProtocolException`
  instead of deriving a mismatched shared secret and installing a
  permanently broken session.
- **Torn session-store writes** (SnowChat `591d0b9`). `saveSessionStore`
  now writes to a uniquely-named temp file and renames it over the target,
  so a crash mid-write or two concurrent saves can no longer leave a
  corrupt ciphertext that loses every session on the next load.

### Added

- **Sealed Sender Step 9 identity cross-check** (SnowChat `c062a09`).
  `resolveSealedMessageType` rejects a prekey message whose X3DH identity
  key does not equal the identity in the server-signed sender certificate
  (constant-time compare, opaque `StateError('Sealed message rejected')`).
  This check was documented in `sealed_sender.dart` but never implemented
  before.
- **Signed-prekey self-heal accessors** (SnowChat `591d0b9`):
  `signedPreKeyPublicKey(keyId)` and `hasAnySignedPreKey`. They let the
  caller detect that the signed prekey its server advertises is not held
  locally (which makes every receive-first X3DH fail with "Signed prekey N
  not found") and re-arm it. The reconcile policy itself (when to rotate,
  server comparison, counters) stays in the application, because it needs
  the caller's server API and secure storage.
- **`MessageSendLog.addAlias(primaryId, aliasId)`** (SnowChat `faf645d`).
  Registers a second lookup key (typically the server-assigned message id)
  for an existing entry so retry requests that reference the server id can
  be answered.

### Changed

- **`saveSessionStore` returns whether bytes reached disk.** `false` when no
  store encryption key is set or the write failed. Callers that upload
  prekeys should persist first and refuse to upload on `false`
  (persist-before-advertise).

### Not included

- The SnowChat app's TOFU identity-pin keying and Safety Number computation
  are being reworked separately and are not part of this release.
- App-only orchestration from the same SnowChat commits (session-manager
  signed-prekey reconcile, prekey upload mutex, message-queue placeholders,
  server-side atomic OPK consume / replace) is application or server logic
  and is intentionally not in this library.

## [0.2.0-alpha.1] - 2026-04-20

Backport of hardening work done on the reference SnowChat deployment
(`~/Developments/SnowChat-voip`) that was previously only applied at the
application layer.

### Added

- **`SignalProtocolService` — archived sessions.** Superseded sessions are
  kept for a 1-hour TTL instead of being hard-deleted so that in-flight
  messages encrypted under an old ratchet remain decryptable. New methods:
  `archiveSession()`, `archiveDecryptDirty` getter, `_tryDecryptFromArchive`
  (internal), TTL-aware persistence via `saveSessionStore` /
  `loadSessionStore`.
- **`SignalProtocolService` — multi-session per peer.** Each peer now holds
  a `List<DoubleRatchetSession>` (MRU at tail, LRU-evicted beyond 5) to
  handle X3DH concurrent initiation. Encrypt picks `list.last`; decrypt
  trial-decrypts all sessions newest-first.
- **`SignalProtocolService` — trial-decrypt with snapshot/restore.** Every
  decrypt attempt snapshots the session via `DoubleRatchetSession.toJson`
  before calling `decrypt` and restores it on failure. This is the primary
  defense against forged messages corrupting ratchet state (see the security
  note on `DoubleRatchetSession`). Direct callers of
  `DoubleRatchetSession.decrypt` must implement equivalent semantics.
- **`SignalProtocolService` — TOFU identity pinning.** New optional
  constructor parameter `identityPinStore: IdentityPinStore?`. When
  supplied, a peer's Ed25519 verify key is pinned on first encounter and
  constant-time compared on subsequent encounters. Mismatches raise
  `IdentityKeyChangedException` so the caller can run their Safety Number
  workflow. Runs on both send-side (`createSession`) and receive-side
  (`_receiveSession` / prekey envelope decrypt), fail-closed when the
  sender's Ed25519 key is missing from the envelope.
- **`SignalProtocolService` — remote identity key cache.** Learned X25519
  identity keys are cached in `_remoteIdentityKeys` and persisted inside
  the session store so `SealedSenderService.seal()` has them available
  without re-fetching the prekey bundle.
- **`SignalProtocolService` — `hasStoreEncryptionKey` getter.** Allows
  callers to short-circuit key-derivation setup once the key is installed.
- **`SignalProtocolService` — session key PII masking.** Log and exception
  messages mask session keys to `first8...last4` so full identifiers do
  not leak into stack traces, crash reports, or device logs.
- **`IdentityPinStore`** (new) — abstract TOFU pin interface. The library
  does not prescribe persistence; callers supply an implementation backed
  by platform-secure storage (Keychain, Keystore, etc.).
- **`IdentityKeyChangedException`** (new) — typed exception for TOFU
  mismatches, with expected/actual keys exposed.
- **`SenderKeyDistributionMessage.chainId`** (new field, backward-compat).
  Receivers can now align state generation to the wire chainId when the
  sender rotates keys. Legacy SKDMs (without the field) deserialize as
  `chainId = 0`.
- **`SenderKeyManager` — origin SKDM cache.** `createSenderKey()` caches
  the iter=0 SKDM in `_originSKDMs` so that `getExistingSKDM()` returns a
  decryptable SKDM covering all past messages in the current generation.
  Persisted inside the session store.
- **`SenderKeyManager.removeSenderKeyForMember()`** — escape hatch to
  break out of permanent decrypt failure loops caused by stale / corrupt
  remote sender key state.
- **`SenderKeyManager.needsResave` flag** — `fromJson()` drops malformed
  legacy `"<groupId>:"` entries and sets this flag so the caller can
  immediately persist a clean store.
- **`MessageSendLog` — 1:1 + group retry.** Redesigned API:
  `record(messageId, plaintext, {conversationId, isGroup})`. Retention
  raised to 500 entries / 24 hours. `fromJson` is backward-compatible
  with the legacy `groupId`-only schema.
- **`generateOneTimePreKeysIsolateWorker`** (new top-level) — isolate-safe
  worker for `PreKeyGenerator.generateOneTimePreKeys`. Compatible with
  both Flutter's `compute()` and pure-Dart `Isolate.run()`. The bundled
  `SignalProtocolService.generateOneTimePreKeys` now uses `Isolate.run()`
  automatically so ~7.9s X25519 batches no longer block the calling
  isolate.

### Changed

- **`SenderKeyManager.processSenderKey()` — chainId-aware replay.** Same
  chainId drops duplicate SKDMs. Different chainId triggers state
  replacement (rotation or legacy-0 migration). Legacy `chainId = 0`
  records are cleared on first real SKDM arrival so they don't waste
  decrypt-loop cycles.
- **`SenderKeyManager.decryptGroupMessage` — drift-retry safety.** Caches
  the current message key BEFORE ratcheting so a caller's durable INSERT
  failing after `decrypt` returned can re-fetch the key on retry instead
  of hitting "no cached key".
- **`SenderKeyManager` — empty senderId / myId rejected at the producer.**
  `createSenderKey`, `getExistingSKDM`, `encryptGroupMessage`,
  `rotateSenderKey` now throw `ArgumentError` rather than silently
  creating state at map key `"<groupId>:"`.
- **`SignalProtocolService.saveSessionStore` — plaintext fallback
  removed.** If no encryption key has been installed via
  `setStoreEncryptionKey`, the save is **skipped entirely** rather than
  writing identity + ratchet material to disk in the clear. Tamper
  protection (refusing plaintext fallback once a store was ever
  encrypted) was already present; this change closes the first-save
  window.
- **`SignalProtocolService.decryptMessage`** now accepts an optional
  `senderIdentityKeyEd25519` parameter for receive-side TOFU on prekey
  envelopes. Ignored for `messageType == 1` and for prekey envelopes
  that match an already-existing session.

### Documentation

- **`DoubleRatchetSession`** — class-level security note added explaining
  that `decrypt()` mutates state before the AEAD check and that direct
  callers must implement snapshot/restore. Links to
  `SignalProtocolService._trialDecrypt` as the reference pattern.

### Migration notes

- **Wire format**: `SenderKeyDistributionMessage` gains a `chainId` field
  but remains byte-compatible with 0.1.x peers — missing field
  deserializes as `0`. Mixed-version group conversations continue to
  work as long as at least one SKDM round trip happens after 0.2.0
  rolls out.
- **Session store**: new `archivedSessions` and `remoteIdentityKeys`
  keys are written on save. Legacy stores load cleanly (missing keys
  treated as empty).

### Known limitations / deliberate non-changes

- `DoubleRatchetSession.decrypt` itself is **not** changed in this
  release. The state-mutation-before-AEAD behaviour is documented and
  defended at the service layer via `_trialDecrypt`, which is how the
  SnowChat production deployment handles it. Direct callers of
  `DoubleRatchetSession` must mirror that pattern.
- No external third-party audit has been performed. The `SECURITY.md`
  audit history reflects internal reviews only.

## [0.2.0-alpha] - 2026-04-12

### Added

#### Sealed Sender (sender anonymity)
- `sealed_sender.dart` -- Core Sealed Sender cryptographic service.
  - `SealedSenderService.seal()`: Wraps a DR/SK ciphertext in an anonymous
    envelope using ephemeral X25519 DH with the recipient's identity key,
    HKDF key derivation, and XSalsa20-Poly1305 AEAD encryption. Includes
    random padding (64-byte aligned, 512-byte minimum) to resist traffic
    analysis.
  - `SealedSenderService.unseal()`: Decrypts the envelope, verifies the
    sender certificate (Ed25519 signature + expiry), performs replay
    detection (EK_seal-based LRU cache, 10K entries, 24h TTL), and
    validates timestamp window (24h).
  - `UnsealedMessage`: Result data class containing sender identity,
    message context, timestamp, and inner DR ciphertext.
  - Defense-in-depth: ephemeral private keys zeroed after use, DH results
    zeroed after HKDF derivation, OKM zeroed after key extraction.

- `sender_certificate.dart` -- Server-signed sender certificate.
  - `SenderCertificate`: 177-byte fixed-size binary format binding
    SnowChat ID, device UUID, X25519 identity key, and expiry with an
    Ed25519 server signature.
  - `SenderCertificate.toBytes()` / `SenderCertificate.fromBytes()`:
    Deterministic serialization/deserialization.
  - `SenderCertificate.verify()`: Version check + expiry check + Ed25519
    signature verification against server's verify key.

### Security notes

- Sealed Sender error messages are intentionally uniform ("Sealed message
  rejected") to prevent oracle attacks that could distinguish between
  decryption failure, certificate failure, or replay detection.
- Replay protection operates at two levels: EK_seal uniqueness check
  (before DH computation to save CPU on replays) and timestamp window
  validation (24-hour tolerance).
- Inner payload padding uses CSPRNG random bytes (not zeros) to resist
  compression-based side channels.

---

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
