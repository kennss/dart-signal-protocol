# Security Policy

## Reporting Vulnerabilities

**This is a cryptographic library. Security vulnerabilities have serious consequences.**

If you discover a security vulnerability, please report it responsibly:

- **Email**: kennt@calidalab.ai
- **DO NOT** open public GitHub issues for security vulnerabilities
- **Response time**: 72 hours
- **Disclosure window**: 90 days before public disclosure

### What to include

- Description of the vulnerability
- Reproduction steps (proof-of-concept code if applicable)
- Affected files and line numbers
- Potential impact and attack scenarios
- Suggested fix (if any)

---

## Security Audit History

All audits to date have been **internal**. No external third-party firm audit has been conducted. Findings marked "Resolved" were resolved within the scope of that internal audit; residual risks that extend beyond that scope are listed in [`§ Residual Risks & Caller Contracts`](#residual-risks--caller-contracts) below.

| Date | Scope | Performed by | Result |
|------|-------|--------------|--------|
| 2026-11-23 | 0.4.0 backport review (library vs. the SnowChat reference after 2026-11-10) | Internal (AI-assisted) | Found that the signed-prekey signature, the sender certificate and Sender Key messages were verified with plain TweetNaCl (accepting S ≥ L and small-order keys) while the reference refuses both — fixed with `verifyEd25519Strict`. Backported: mandatory bindings (TOFU first-contact substitution closed), pinned Sealed Sender keys (SnowChat SC-06), Sender Key v4 (context binding, signed header, one read per key), removal of the plaintext retry log. |
| 2026-11-10 | Identity Binding v1 (design + implementation review, SnowChat B-2) | Internal (AI-assisted, multi-pass) | Server key-substitution (SC-02) closed for bound peers; review findings (signing-oracle prefix, canonical S, small-order account keys, epoch floor, legacy-Ed weakness, notice-once, non-consuming pre-admission, strict parsing) resolved before release. |
| 2026-04-22 | Full protocol + service layer (Claude Opus 4.7 reconnaissance pass) | Internal (AI-assisted) | C-1, H-1, H-2, M-3, M-4 — resolved at service layer in v0.2.0-alpha.1 backport. C-2 documented as open limitation. |
| 2026-04 | Sealed Sender 6-stage review (design → code → critical audit → verification → fix → trace) | Internal | Resolved within scope (P0: 1, P1: 5). Replay-cache persistence carried forward as known limitation. |
| 2026-04 | Phase 8.7 E2EE stabilization (8 rounds, multi-agent reproduction + cross-verification) | Internal | 13 defects resolved. Zero plaintext leak paths found. |
| 2026-03 | Signal Protocol core (X3DH, Double Ratchet, Sender Key) — 3 internal reviews | Internal | Resolved within scope. |

**External audit — Planned.** Expected scope: side-channel analysis, deployment + opsec review, attestation. Targeted pre-`1.0.0`. If you are a cryptography auditor interested in reviewing this library, please reach out.

---

## Cryptographic Invariants

These MUST hold at all times. Violations are security bugs:

1. **X25519 DH all-zero check**: `x25519Dh()` rejects zero output (small-subgroup attack defense).
2. **No HSalsa20 on DH**: Uses `TweetNaCl.crypto_scalarmult()` directly, NOT `Box.sharedKey()`.
3. **Ephemeral keys zeroed after use**: Sealed Sender `ek_seal` zeroed in `finally` block.
4. **DH shared secrets zeroed after HKDF**: `dhResult.fillRange(0, len, 0x00)` after key derivation.
5. **Domain separation**: Each protocol uses unique info strings / signature labels (`SnowChat_X3DH_4DH` / `SnowChat_X3DH_5DH`, `SnowChat_Ratchet`, `SnowChat_SealedSender_v1`, `0xFF ‖ SnowChat_IdentityBinding_v1`, `0xFE ‖ SnowChat_GV2_Msg_v1`).
6. **Certificate verified before inner payload processed**: Sealed Sender unseal rejects forged certificates before DR decrypt.
7. **Replay protection (in-memory)**: `EK_seal` dedup cache (10K entries) checked before DH computation.
8. **Fail-closed on a missing or bad signed-prekey signature**: `createSession` refuses a bundle without the Ed25519 identity key or whose signed prekey does not verify (strictly), before identity admission or X3DH.
9. **Plaintext session-store fallback refused**: `saveSessionStore` skips the write if no encryption key is installed (rather than write identity + ratchet material in the clear).
10. **Identity admission before key material is used, always**: an identity store is required; bundles are admitted before X3DH; PreKey messages are admitted before any signed / one-time prekey is read or consumed. A peer without a valid binding is refused (`bindingRequired` / `downgrade`) and nothing is recorded for it — there is no TOFU path.
11. **Binding verification is fail-closed and never throws**: account key 32 B, canonical, not small-order; account key derives the peer id (constant time); canonical signature scalar (S < L); lowercase-UUID device id; 0xFF-prefixed fixed-length message, so no UTF-8 string signer can produce a valid binding.
12. **Latch never decreases and survives `remove()`**: a peer that once proved a binding can never be accepted unbound again; an epoch below the latch (or the same epoch for different keys) is rejected.
13. **Bound sessions only**: sessions (active and archived) whose recorded remote identity key differs from a bound peer's key — or that recorded none — are purged before encrypt / decrypt and never used.
14. **Strict Ed25519 for every trust decision**: identity bindings, signed prekeys, sender certificates and Sender Key messages are verified with a canonical scalar (S < L) under a canonical, non-small-order key (`verifyEd25519Strict`). Plain `VerifyKey.verify` is never used to decide trust.
15. **Sealed Sender keys come from the build**: `SealedSenderService` verifies certificates only against the `trustedServerKeys` it was constructed with (non-empty, strict keys, copied); the library never accepts a key from the network.
16. **Sender Key messages are bound and read once**: the v4 signature covers the caller's 32-byte binding, the version, chain id and iteration, and the ciphertext; a message key is dropped once it has read its message; a failed read changes no stored key.
17. **No plaintext at rest in the session store**: the store holds key material and ratchet state only (the 0.3.x retry log of sent plaintexts is removed).

---

## Residual Risks & Caller Contracts

These are the risks the library cannot, on its own, eliminate. Addressing them is the caller's responsibility until the items listed in [`Roadmap`](#roadmap) are completed.

### C-1b — Direct `DoubleRatchetSession.decrypt()` callers can have sessions destroyed by a single forged message

**Description.** [`DoubleRatchetSession.decrypt`](lib/src/double_ratchet.dart) advances ratchet state (`receivingChainKey`, `receiveMessageNumber`, and in the DH-ratchet branch `rootKey` + `sendingChain*`) before the AEAD check runs. An attacker who delivers a message with a valid serialised header but a tampered ciphertext will push the ratchet forward by one step and then trigger the Poly1305 failure. Without rollback, a single adversarial message can permanently desynchronise the chain — all subsequent legitimate messages fail to decrypt because the receiver's key material has already moved past.

**Scope.** Any caller that invokes `DoubleRatchetSession.decrypt()` directly, bypassing `SignalProtocolService`.

**Mitigation (if you use `SignalProtocolService`).** The service layer wraps every decrypt in [`SignalProtocolService._trialDecrypt`](lib/src/signal_protocol_service.dart), which snapshots via `toJson()` and restores on failure. Archived sessions (1-hour TTL) catch in-flight messages after session reset via `_tryDecryptFromArchive`. **Callers of `SignalProtocolService` are protected by default.**

**Mitigation (if you use `DoubleRatchetSession` directly).** Implement the same pattern:

```dart
final snapshot = session.toJson();
try {
  return session.decrypt(message);
} catch (e) {
  // Replace the mutated session with a fresh deserialised copy.
  session = DoubleRatchetSession.fromJson(snapshot);
  rethrow;
}
```

**Status.** Documented in the class-level docstring on `DoubleRatchetSession` and in this file. No runtime enforcement at the low-level API.

### C-2 — Sealed Sender replay cache is in-memory only

**Description.** `SealedSenderService._ReplayCache` is a process-local `Map<String, int>` keyed by `EK_seal` hex. On app restart the cache is empty. Within the 24-hour timestamp window (`_timestampWindowMs`), an attacker who captured a sealed envelope earlier can re-deliver it and `unseal()` will accept it as fresh.

**Impact — depends on what the inner payload is.**

| Inner payload | Outcome of replay attempt |
|---|---|
| **Double Ratchet ciphertext** — new message after original was consumed | DR layer rejects (trial-decrypt rollback if `SignalProtocolService` is used). No user-visible impact. |
| **Sender Key group ciphertext** (v4, since 0.4.0) — original message was consumed | The message key was dropped when it read the original: the replay fails as `SenderKeyFailure.expired` — provided the caller persisted the `SenderKeyManager` records with the plaintext. (0.3.x kept the key and returned the plaintext again.) |
| **VoIP / application signalling** | Application state machine typically rejects stale signalling; caller-specific. |

**Mitigation.** The caller should still deduplicate on a stable content identifier that survives process restart. Recommended: a unique index on `(sender_id, sent_timestamp, conversation_id)` in durable storage. `sender_id` comes from the Sealed Sender certificate (server-signed, tamper-proof); `sent_timestamp` comes from the inner plaintext; both are stable under replay.

**Status.** Not fixed in this release. Tracked as roadmap item "Persistent Sealed Sender replay cache".

### M-3 — Identity Binding v1 depends on the account key and on the caller's latch persistence

**Description.** Since 0.4.0 identity bindings are mandatory: `SignalProtocolService` requires a `VerifiedIdentityStore`, and a peer that presents no valid account-signed binding is refused (`bindingRequired`, or `downgrade` once latched) — the 0.3.x TOFU path for binding-less peers, through which a hostile server could substitute a never-bound peer's keys on first contact, is gone. What remains depends on things the library cannot see.

| Threat | Covered? |
|---|---|
| Server substitutes a peer's bundle (send side) | ✅ `signatureInvalid` / `accountKeyMismatch` |
| Server swaps the X3DH header identity key of a PreKey message | ✅ signature is verified over the header key, before prekeys are touched |
| Server strips a peer's binding (first contact or later) | ✅ `bindingRequired` / `downgrade` |
| Server replays an older, validly signed binding | ✅ `epochRegression` |
| Server hands out a peer id whose account key it controls (wrong id) | ❌ the id is the trust root — verify it out of band (`pinAccountKey`, Safety Numbers) |
| Account-key compromise (leaked recovery phrase) | ❌ an attacker can sign new bindings; surfaced only as a `deviceKeysChanged` notice |
| Integrator persists the latch unreliably | ❌ the downgrade check for a known peer degrades to `bindingRequired` only — still refused, but an older binding could be replayed; the latch MUST be persisted durably |

**Mitigation.** Inject a persistent `VerifiedIdentityStore` subclass, derive peer ids from account keys (`IdentityIdScheme`), upload bindings, pass `envelopeDeviceId` / `identityDirectoryLookup` on receive, treat `IdentityBindingInvalidException` as terminal, and show Safety Numbers over account keys (`SafetyNumber.forAccountKeys`). README `§ Known Risks #3` lists every caller obligation.

**Status.** Identity Binding v1 shipped in 0.3.0-alpha.1 and is mandatory since 0.4.0 (`IdentityPinStore` removed).

### M-4 — Sealed Sender trusts the keys the caller pins

**Description.** A sender certificate proves the sender's identity only as far as the server key that signed it is trusted. `SealedSenderService(trustedServerKeys: …)` accepts any listed key. If an application fetched the key from its server at run time, a compromised server could sign certificates for any account.

**Mitigation.** Pin the keys in the application build; rotate by shipping the next key in the list before switching the server (README `§ Known Risks #3a`).

**Status.** Enforced by API shape since 0.4.0 (no key-fetch path in the library); the pinning itself is the caller's.

### A-2 — `SignalProtocolService` imports `dart:io`; Flutter Web builds fail

**Description.** `saveSessionStore` / `loadSessionStore` use `dart:io`'s `File`. On Dart-to-JS compilation (Flutter Web), this fails.

**Mitigation.** Use the lower-level classes (`DoubleRatchetSession`, `SenderKeyManager`, `SealedSenderService`, `X3DH`, `PreKeyGenerator`) directly and implement storage yourself; those modules do not import `dart:io`.

**Status.** Roadmap item "Platform-agnostic session-store adapter" will resolve this.

### A-1 — HKDF `info` labels hardcoded to `SnowChat_*`

**Description.** Domain-separation labels are constants (`SnowChat_X3DH_4DH` / `SnowChat_X3DH_5DH`, `SnowChat_Ratchet`, `SnowChat_SealedSender_v1`, the Identity Binding v1 format label `SnowChat_IdentityBinding_v1` and the Sender Key v4 signature label `SnowChat_GV2_Msg_v1`). Products using this library as their cryptographic core inherit SnowChat's domain separation. The binding label is part of the fixed 172-byte v1 format shared with the SnowChat golden vectors; a dedicated account key per product keeps bindings from different products apart.

**Impact.** Not a security weakening; domain separation is still effective. Non-interoperable with forks that alter these labels.

**Status.** Roadmap item "Configurable HKDF info labels" will make these injectable. This will be a wire-breaking change for existing deployments.

---

## Side-channel and VM-level limitations

- **Dart VM timing**: No constant-time execution guarantee from the VM. Comparisons that must be constant-time are implemented with XOR-accumulate patterns (e.g. `_constantTimeBytesEqual`), but the underlying VM can still leak via allocation patterns, garbage collection pauses, or JIT warm-up.
- **Dart VM memory**: Key material in `Uint8List` can be zeroed explicitly (done for ephemeral DH outputs and OKM in Sealed Sender) but the GC can create transient copies outside our control.
- **Multi-tenant hostile environments**: Running this library inside an adversarial OS sandbox or shared memory environment is out of scope for the current threat model.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x | Yes — current |
| 0.3.x | Security fixes only (not interoperable with 0.4.x for groups — Sender Key v4 — and refused by 0.4.x peers when it publishes no binding) |
| 0.2.x | No (cannot establish new sessions with 0.3.x+ — X3DH info change) |
| 0.1.x | No |
| < 0.1 | No |

---

## Dependencies

| Library | Algorithms | Notes |
|---------|-----------|-------|
| `pinenacl ^0.6.0` | X25519, Ed25519, XSalsa20-Poly1305 | Pure Dart port of TweetNaCl. Only runtime dependency. |

---

## Roadmap

Ordered by priority:

1. **Persistent Sealed Sender replay cache** — addresses [C-2](#c-2--sealed-sender-replay-cache-is-in-memory-only).
2. **Platform-agnostic session-store adapter** — unblocks Flutter Web ([A-2](#a-2--signalprotocolservice-imports-dartio-flutter-web-builds-fail)).
3. **Configurable HKDF info labels** — addresses [A-1](#a-1--hkdf-info-labels-hardcoded-to-snowchat_).
4. **External third-party security audit** — scope TBD, pre-`1.0.0`.
5. **pub.dev publication** — gated on (1)-(4).
