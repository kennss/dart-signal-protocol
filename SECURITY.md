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
5. **HKDF domain separation**: Each protocol uses unique info strings (`SnowChat_X3DH`, `SnowChat_Ratchet`, `SnowChat_SealedSender_v1`).
6. **Certificate verified before inner payload processed**: Sealed Sender unseal rejects forged certificates before DR decrypt.
7. **Replay protection (in-memory)**: `EK_seal` dedup cache (10K entries) checked before DH computation.
8. **Fail-closed on missing sender Ed25519 verify key**: `createSession` and `_receiveSession` refuse session establishment rather than install an unverified session.
9. **Plaintext session-store fallback refused**: `saveSessionStore` skips the write if no encryption key is installed (rather than write identity + ratchet material in the clear).

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
| **Sender Key group ciphertext** — original message was consumed | `cachedMessageKeys` returns the stored key (kept for drift-retry safety). **`decrypt()` returns plaintext.** Caller-level deduplication is required. |
| **VoIP / application signalling** | Application state machine typically rejects stale signalling; caller-specific. |

**Mitigation.** The caller must deduplicate on a stable content identifier that survives process restart. Recommended: a unique index on `(sender_id, sent_timestamp, conversation_id)` in durable storage. `sender_id` comes from the Sealed Sender certificate (server-signed, tamper-proof); `sent_timestamp` comes from the inner plaintext; both are stable under replay.

**Status.** Not fixed in this release. Tracked as roadmap item "Persistent Sealed Sender replay cache".

### M-3 — TOFU identity pinning is opt-in

**Description.** `SignalProtocolService({IdentityPinStore? identityPinStore})` accepts an optional pin store. When omitted, `_tofuPinCheck` is a no-op — any Ed25519 identity key the remote peer presents is accepted on every session establishment. A server capable of swapping a peer's advertised identity key between sessions will not trigger `IdentityKeyChangedException`.

**Mitigation.** Implement and inject an `IdentityPinStore` backed by platform-secure storage:

```dart
class MyIdentityPinStore implements IdentityPinStore {
  @override
  Future<Uint8List?> getPinned(String sessionKey) async {
    // Read from Keychain / Keystore / encrypted SQLite
  }

  @override
  Future<void> pin(String sessionKey, Uint8List identityKey) async {
    // Write to the same backend
  }
}

final service = SignalProtocolService(identityPinStore: MyIdentityPinStore());
```

**Status.** Interface shipped (`identity_pin_store.dart`), no concrete implementation bundled. Considered final design — storage backends are deliberately out of scope.

### A-2 — `SignalProtocolService` imports `dart:io`; Flutter Web builds fail

**Description.** `saveSessionStore` / `loadSessionStore` use `dart:io`'s `File`. On Dart-to-JS compilation (Flutter Web), this fails.

**Mitigation.** Use the lower-level classes (`DoubleRatchetSession`, `SenderKeyManager`, `SealedSenderService`, `X3DH`, `PreKeyGenerator`) directly and implement storage yourself; those modules do not import `dart:io`.

**Status.** Roadmap item "Platform-agnostic session-store adapter" will resolve this.

### A-1 — HKDF `info` labels hardcoded to `SnowChat_*`

**Description.** Domain-separation labels are constants (`SnowChat_X3DH`, `SnowChat_Ratchet`, `SnowChat_MsgKey`, `SnowChat_SealedSender_v1`). Products using this library as their cryptographic core inherit SnowChat's domain separation.

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
| 0.2.x | Yes — current |
| 0.1.x | Security fixes only |
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
