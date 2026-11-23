# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-11-23

### License

- **Relicensed from AGPL-3.0 to Apache-2.0.** The library is an independent
  implementation written from the Signal Protocol specifications by its sole
  author, with no code from `libsignal`, so it can be offered under a
  permissive license: usable in closed-source apps and in apps distributed
  through the App Store and Google Play. Added a `NOTICE` file. Versions up
  to and including 0.4.0 remain available under the AGPL-3.0.
- No code changes.

## [0.4.0] - 2026-11-23

Third backport from the reference SnowChat deployment, covering what the
app's copy of the crypto code gained between 2026-11-10 and 2026-11-23
(SnowChat commits `3df0cc5`, `0aa549b`, `966a884`, `f137f43`, `7a882d0`,
`53c4560` and the Sealed Sender changes of 2026-11-22). It closes the
remaining paths by which a malicious server could get its own keys
accepted, makes every trust-deciding signature strict, and replaces the
v1 group machinery with the Sender Key wire format v4.

**This release is wire- and API-breaking. Read "Migration from 0.3.x"
below before upgrading; upgrade all peers together.**

### Security

- **Strict Ed25519 for every trust-deciding signature.** 0.3.0 verified
  Identity Binding v1 signatures strictly (canonical scalar S < L,
  small-order and non-canonical account keys refused), but the
  signed-prekey signature (`PreKeyBundle.verifySignature`, used by
  `createSession`), the Sealed Sender certificate
  (`SenderCertificate.verify`) and Sender Key messages used pinenacl's
  plain TweetNaCl `VerifyKey.verify`. That accepts a second, malleated
  signature (S + L) for any signed message and, for a small-order public
  key, a single forged signature (R = identity, S = 0) that verifies for
  every message. The SnowChat reference refuses both (`verifyEd25519Strict`
  on its server, `ed25519_strict.dart` in its app), so a signature one
  side accepted and the other refused could split their views. All three
  checks now use the new `verifyEd25519Strict`; `SealedSenderService`
  refuses a non-strict trusted key and `processSenderKey` refuses a
  non-strict signing key. Honest peers are unaffected: TweetNaCl always
  produces reduced signatures and random keys are never of small order.
  Tests show each input accepted by plain TweetNaCl and refused by the
  library.
- **Identity bindings are mandatory** (SnowChat `3df0cc5`, `0aa549b`).
  In 0.3.x a peer that presented no binding was admitted under a
  Signal-style TOFU policy, so a compromised server could strip the
  binding of a peer this device had never seen bound and substitute its
  own keys on first contact; without an `identityStore` there were no
  identity checks at all. Now every admission point (send-side bundle,
  receive-side PreKey message, directory pre-admission) refuses a peer
  without a valid binding — `IdentityBindingFailure.bindingRequired`, or
  `downgrade` for a latched peer — and records nothing for it.
- **Unproven 0.3.x identity records are not trusted.** An unbound record
  read from a `VerifiedIdentityStore` keeps only its account key; keys a
  0.3.x store recorded under TOFU (and its `edLegacy` / `pending*`
  fields) are dropped. Sessions persisted without a remote identity key
  (before 0.3.0) never match a bound identity and are purged; 0.3.0's
  inference that labelled such sessions and kept them is gone.
- **Sealed Sender server keys must be pinned** (SnowChat SC-06).
  `SealedSenderService` takes `trustedServerKeys`, meant to be pinned in
  the application build and never fetched from the server at run time —
  a server that can hand out its own key can sign a sender certificate
  for any account and impersonate any sender.
- **Sender Key messages are bound to their context and read once**
  (wire format v4). The signature covers a caller-supplied 32-byte
  binding plus the message's own chain id and iteration, so a member or
  the server cannot re-wrap a message under another header or push a
  receiver's chain forward with a forged iteration; a message key reads
  one message, so a replayed group message fails (`expired`) instead of
  returning plaintext again (this closes the Sender Key row of the
  in-memory replay-cache residual risk C-2).
- **No message plaintexts at rest in the session store.** The removed
  `MessageSendLog` kept sent plaintexts for 24 hours inside the session
  store to answer retry requests.
- **`SenderCertificate.toString` names no account or device** (SnowChat
  `logRef`): a certificate printed into a log no longer reveals the
  sender Sealed Sender hides.

### Breaking

- **`SignalProtocolService({required VerifiedIdentityStore identityStore})`.**
  The store is required; `identityPinStore:` and the unused
  `useMockFallback:` parameters are gone; `identityStore` is non-null.
- **`createSession` refuses a bundle without a binding** and
  **`decryptMessage` refuses a binding-less PreKey message** unless the
  `identityDirectoryLookup` returns a server-held binding for the header
  identity key — `IdentityBindingInvalidException(bindingRequired)`.
  `decryptMessage(senderIdentityKeyEd25519:)` is removed.
- **Identity API.** `IdentityAdmission.admitUnbound()` →
  `refuseUnbound()` (returns the exception to throw);
  `promotionNotice()` → `keyChangeNotice()` (bool, bound records only);
  `AdmittedIdentity` is `{identityKey, ed25519}` (no `bound`,
  `boundIdentityKey`, `boundDeviceId`).
  `VerifiedIdentityStore.pinFromInviteLink()` → `pinAccountKey()`;
  `rememberAccountKey()` only fills a missing record. The abstract store
  no longer has `readMetadata` / `writeMetadata` / `isPeerVerified`;
  `IdentityEventKind` is `{deviceKeysChanged, bindingRejected}`;
  `IdentityBindingFailure` gains `bindingRequired`.
- **Sealed Sender.** `SealedSenderService(serverVerifyKey:)` →
  `SealedSenderService(trustedServerKeys: [...])` (non-empty, strict
  Ed25519 keys, copied). `SenderCertificate.verify(Uint8List)` →
  `verify(List<Uint8List>)`.
- **Sender Key wire format v4** (wire-breaking: 0.3.x and 0.4.0 members
  cannot read each other's group messages or distribution messages).
  - `encryptGroupMessage` / `decryptGroupMessage` →
    `encryptBoundGroupMessage` / `decryptBoundGroupMessage`, which take a
    32-byte `binding` and throw `SenderKeyException(SenderKeyFailure)`.
  - `SenderKeyDistributionMessage.serialize()` is a fixed 72-byte body
    (chainId ‖ iteration ‖ chainKey ‖ signingKey, the SnowChat body);
    `deserialize(bytes, groupId:, senderId:)` takes the group and sender
    from the caller's authenticated context and returns `null` on a
    malformed body. The JSON form is gone.
  - `processSenderKey` returns `bool`; a chain already held is never
    replaced.
  - `SignalProtocolService` no longer exposes `createSenderKey`,
    `processSenderKey`, `encryptGroupMessage`, `decryptGroupMessage`,
    `senderKeyManager`, `skdmTracker` or `messageSendLog`. Use a
    `SenderKeyManager` directly and persist `toJson()` yourself; the
    session store no longer writes `senderKeys` (ignored on load, dropped
    on the next save).

### Added

- `verifyEd25519Strict()` and `isAcceptableEd25519PublicKey()`
  (`ed25519_strict.dart`).
- `encodeSealedPlaintext()` / `sealedPlaintextBlock`
  (`sealed_plaintext.dart`, SnowChat security review S4): opt-in padding
  of a JSON message plaintext with JSON whitespace to a multiple of a
  block (512 bytes by default) before Double Ratchet encryption, so
  messages that fit one block travel in Sealed Sender envelopes of one
  size (PreKey messages with their identity binding included). A plain
  JSON decoder reads it back; byte-identical to the SnowChat app.
- `SignalProtocolService.archiveSessionsOf(peerId)` — archive the
  sessions with every device of a peer (the peer says its sessions are
  gone and its current device is not known).
- `IdentityBindingFailure.bindingRequired`.
- Sender Key v4: `senderKeyWireV4`, `senderKeyBindingLength`,
  `senderKeyMessageOverhead`, `senderKeyMessageLength()`,
  `senderKeyDistributionLength`, `SenderKeyException`,
  `SenderKeyFailure`, `SenderKeyManager.fromJson()`.
- Tests: `ed25519_strict_test`, `identity_binding_mandatory_test`,
  `session_archive_test`, `sealed_trusted_keys_test`, `sealed_sender_tamper_test`,
  `sealed_padding_test`, a rewritten `sender_key_test` (with a v4 golden
  vector computed by the SnowChat app's code), and new refusal /
  migration cases in the session, store and service tests.

### Removed

- **`IdentityPinStore`** (`identity_pin_store.dart`) and
  **`IdentityKeyChangedException`** (`identity_key_changed_exception.dart`)
  — the TOFU identity model, deprecated in 0.3.0, removed as in the
  app (`0aa549b`). With bindings mandatory there is no unverified key to
  pin and no "verified legacy peer changed keys" state to block on.
- The legacy admission machinery: `admitUnbound`, pending key changes and
  `acceptPendingChange`, `importLegacyPin`, `seedLegacyIdentityKeys`
  (and the one-time IK seeding in `loadSessionStore`),
  `remoteIdentityKeySnapshot()`, `edLegacySourced`, `isPeerVerified` /
  `InMemoryVerifiedIdentityStore.verifiedLookup`, the
  `legacyKeyChanged` / `legacyKeyChangeBlocked` / `interceptionSuspected`
  events.
- **`MessageSendLog`** (`message_send_log.dart`). Not a Signal-protocol
  primitive: an application retry log that kept sent plaintexts for
  24 hours inside the session store so a retry request could be answered
  by re-encrypting them. Plaintext at rest is a liability, and whether
  and how to resend is application policy (libsignal leaves it to the
  app too). The reference app removed it with its retry path
  (2026-11-22).
- **`SenderKeyDistributionTracker`** (`sender_key_tracker.dart`). Not a
  Signal-protocol primitive: bookkeeping of which members hold the
  current Sender Key, i.e. application distribution policy. It was only
  meaningful together with the v1 group design the app removed
  (`f137f43`); who receives a key belongs to the application's
  membership logic.
- Sender Key v3 / v1 message formats, `rotateSenderKey()` and rotation
  versions (call `createSenderKey()` again and distribute the result),
  the origin-SKDM cache and `getExistingSKDM()`, `needsResave` and the
  legacy record migrations, `maxGroupSize` (a group-size limit is
  application policy).

### Migration from 0.3.x

1. **Identity.** Construct every `SignalProtocolService` with a
   persistent `VerifiedIdentityStore` (records AND latches). Every peer
   must publish an Identity Binding v1 (`IdentityBindingV1.sign` +
   upload) before it can be reached or can reach you; peers that relied
   on TOFU are now refused with `bindingRequired`. Remove
   `senderIdentityKeyEd25519:` from `decryptMessage` calls and pass
   `envelopeDeviceId` / `identityDirectoryLookup` instead. Rename
   `pinFromInviteLink` → `pinAccountKey`; drop your `readMetadata` /
   `writeMetadata` / `isPeerVerified` overrides and any handling of
   `IdentityKeyChangedException`, `acceptPendingChange` and the removed
   events. Existing 0.3.x records keep working: bound records are read
   as before; unbound ones are read as account-key pins (their TOFU keys
   are dropped).
2. **Sealed Sender.** Pin your server's Sealed Sender verify key(s) in
   the application build and pass them as
   `SealedSenderService(trustedServerKeys: [...])`; never take the key
   from a server response. Rotate by shipping the next key in the list
   before switching the server.
3. **Sender Key.** v4 is a wire break: upgrade every member, then have
   each member call `createSenderKey()` and distribute the 72-byte
   `serialize()` body over its 1:1 sessions; the receiver calls
   `SenderKeyDistributionMessage.deserialize(bytes, groupId:, senderId:)`
   with the group and the sender taken from the authenticated 1:1
   context. Compute the same 32-byte `binding` on both sides (e.g.
   `sha256(groupId ‖ messageId)` with the library's `sha256`). Persist
   `SenderKeyManager.toJson()` yourself (encrypted); the group state that
   0.3.x kept inside the session store is no longer loaded.
4. **Retries.** If you used `messageSendLog` to answer retry requests,
   keep any such log in your application (or, better, let the sender
   re-send from its own outbox).
5. **Sessions.** Sessions created by 0.3.x keep working. Sessions
   persisted before 0.3.0 (no remote identity key) are purged the first
   time the peer's bound sessions are enforced; the next send runs X3DH
   again.

### Not included

- SnowChat group protocol v2 (signed membership log, zkgroup credentials,
  the sealed group envelope), account-deletion proofs, the
  `EncryptedMessageHandler` orchestration, contact notices, the vouching
  marks of its `VerifiedIdentityStore` (`vouch` / `isVouched` — the
  app's group-picker policy) and the app's pinned production / dev
  Sealed Sender keys: application or SnowChat-specific. The v4 signature
  label stays byte-identical to the app (`SnowChat_GV2_Msg_v1`, see the
  hardcoded-labels risk) so the golden vector is shared.

## [0.3.0-alpha.1] - 2026-11-10

Second backport from the reference SnowChat deployment. These fixes had been
running in the SnowChat app since May–August 2026 but were only present in
the app's copy of the crypto code; this release brings the published library
back in line with it. Each fix is covered by a new regression test in
`test/signal_protocol_service_test.dart`.

This release also ships **Identity Binding v1** (SnowChat `1f90c4e`,
November 2026): account-signed Signal identities that a malicious server
cannot substitute, with Safety Number v2 over account keys. It replaces the
TOFU-only identity model of 0.2.x (see Added / Deprecated). Tests:
`test/identity_binding_test.dart`, `test/verified_identity_store_test.dart`,
`test/identity_binding_session_test.dart` (shared golden vectors in
`test/fixtures/identity_binding_v1.json`).

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
- **`decryptMessage(senderIdentityKeyEd25519: …)` throws `ArgumentError`
  when the service has an `identityStore`.** In that mode the sender is
  verified from its binding (or via `identityDirectoryLookup`); a
  server-supplied Ed25519 key is exactly what the binding replaces, so it is
  refused loudly instead of being silently ignored. Unchanged without an
  `identityStore`.
- **`SignalProtocolService(identityPinStore:, identityStore:)` together
  throws `ArgumentError`.** Pick one identity model.

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

- **Identity Binding v1** (SnowChat `1f90c4e`). A device's X25519 identity
  key and Ed25519 signing key are signed by the user's long-term ACCOUNT
  key, from which the peer id is derived, so anyone who knows a peer id can
  verify that peer's keys offline.
  - `IdentityBindingV1`: 172-byte message (`0xFF` prefix — no UTF-8 string
    signer can produce it — fixed-length fields), fail-closed `verify()`
    (canonical signature scalar S < L, small-order / non-canonical account
    keys rejected, constant-time id derivation check), `sign()` from an
    account seed, `nextEpoch()` minting rule, strict parsers. Byte-identical
    to the SnowChat server/app golden vectors.
  - `IdentityIdScheme` (pluggable account-key -> peer-id derivation; ids
    are 36 ASCII chars) with the SnowChat-compatible default
    `SnowChatIdScheme`.
  - `IdentityBinding` (server wire form), `EmbeddedIdentityBinding` (inside
    PreKey messages), `LocalIdentityBinding` (our own).
  - `VerifiedIdentityStore` (abstract: storage primitives + policy —
    monotonic epoch latch that survives `remove()`, invite-link pinning,
    pending-change re-verification, legacy pin import, one-time IK seeding,
    identity events) and `InMemoryVerifiedIdentityStore` (reference, tests).
  - `IdentityAdmission`: bound / unbound admission, highest-valid-epoch
    device selection, non-consuming directory pre-admission
    (`admitDirectory`), promotion notices (`deviceKeysChanged` vs
    `interceptionSuspected`).
  - `IdentityBindingInvalidException` (typed, non-retryable, with
    `IdentityBindingFailure` reason).
  - `SignalProtocolService(identityStore: …)`: `createSession` admits the
    bundle before X3DH (`identityBinding` / `identityBindingUnparseable` /
    `accountPublicKey` bundle keys); PreKey messages embed our binding
    (`setLocalIdentityBinding`); `decryptMessage` verifies the sender's
    binding offline — over the X3DH header identity key, against
    `envelopeDeviceId`, against the latch — before any signed / one-time
    prekey is used, with `identityDirectoryLookup` for binding-less senders;
    sessions record `remoteIdentityKey`, and sessions (active + archived)
    that do not match a bound peer's key are purged
    (`enforceBoundSessions`); legacy records are seeded once from the
    persisted remote identity keys on `loadSessionStore`.
  - Legacy (binding-less) peers follow a Signal-style policy: unverified ->
    keys updated + `legacyKeyChanged` event; verified -> held as pending and
    `IdentityKeyChangedException` until `acceptPendingChange`.
- **Safety Number v2** — `SafetyNumber.forAccountKeys()` hashes both users'
  account keys (version 2), so both peers always see the same 60 digits and
  a device reinstall does not change them. Byte-compatible with SnowChat.
- **`DoubleRatchetSession.remoteIdentityKey`** — persisted in `toJson()`;
  absent for sessions saved by earlier versions.
- **`IdentityKeyChangedException.peerId`** — alias of `peerSnowchatId`.
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

### Deprecated

- **`IdentityPinStore`** and the `identityPinStore:` constructor parameter.
  TOFU on the Signal Ed25519 key, keyed by device id, cannot detect a server
  substituting keys on first contact or after a reinstall. Still honoured
  when no `identityStore` is set; carry existing pins over with
  `VerifiedIdentityStore.importLegacyPin`.

### Changed

- **`saveSessionStore` returns whether bytes reached disk.** `false` when no
  store encryption key is set or the write failed. Callers that upload
  prekeys should persist first and refuse to upload on `false`
  (persist-before-advertise).

### Not included

- Application-side Identity Binding pieces stay in the SnowChat app: the
  migration of its pre-binding SecureStorage key layout
  (`signal_identity_pin:*`), keychain-locked (BFU) deferral and
  cross-isolate caching of its store implementation, account-key storage and
  the purpose-bound auth-challenge signer, binding upload / self-check /
  re-sign against its server, invite-link (`?k=`) parsing, held-message
  queueing and UI. They depend on the app's storage, server API and UI; the
  library exposes the hooks they build on (`VerifiedIdentityStore`
  primitives, `importLegacyPin`, `IdentityBindingV1.sign` / `nextEpoch`,
  `IdentityAdmission.admitDirectory`, identity events).
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
