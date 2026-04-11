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

## Security Audit History

| Date | Scope | Result |
|------|-------|--------|
| 2026-04 | Sealed Sender 6-stage pipeline (design → code → critical audit → algorithm verification → fix → final trace) | PASS — P0: 1 found/fixed, P1: 5 found/fixed |
| 2026-04 | Phase 8.7 E2EE stabilization (8 rounds reproduction + cross-verification agents) | PASS — 13 defects found/fixed, 0 plaintext leak paths |
| 2026-03 | Signal Protocol core (X3DH, Double Ratchet, Sender Key) — 3 internal reviews | PASS |

## Cryptographic Invariants

These MUST hold at all times. Violations are security bugs:

1. **X25519 DH all-zero check**: `x25519Dh()` rejects zero output (small-subgroup attack defense)
2. **No HSalsa20 on DH**: Uses `TweetNaCl.crypto_scalarmult()` directly, NOT `Box.sharedKey()`
3. **Ephemeral keys zeroed after use**: Sealed Sender `ek_seal` zeroed in `finally` block
4. **DH shared secrets zeroed after HKDF**: `dhResult.fillRange(0, len, 0x00)` after key derivation
5. **HKDF domain separation**: Each protocol uses unique info strings (`SnowChat_X3DH`, `SnowChat_Ratchet`, `SnowChat_SealedSender_v1`)
6. **Certificate verified before inner payload processed**: Sealed Sender unseal rejects forged certificates before DR decrypt
7. **Replay protection**: EK_seal dedup cache (10K entries) checked before DH computation

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x | Yes — current |
| 0.1.x | Security fixes only |
| < 0.1 | No |

## Dependencies

| Library | Algorithms | Notes |
|---------|-----------|-------|
| `pinenacl ^0.6.0` | X25519, Ed25519, XSalsa20-Poly1305 | Pure Dart port of TweetNaCl. Only runtime dependency. |

## Known Limitations

- **No external third-party audit yet** — seeking one
- **Dart VM timing**: no constant-time guarantees from the Dart VM
- **Wire format**: not compatible with libsignal (independent implementation)
- **In-memory replay cache**: lost on process restart (timestamp window still protects)
