# Tests

> Test suite coming soon.

This directory will contain unit tests for:

- `x25519.dart` — X25519 DH and Ed25519 ↔ X25519 conversion
- `hkdf.dart` — SHA-256, HMAC, HKDF (against RFC 5869 test vectors)
- `prekey_bundle.dart` — signature verification
- `x3dh.dart` — key agreement (against Signal X3DH spec test vectors)
- `double_ratchet.dart` — encryption/decryption, out-of-order messages,
  skipped message keys
- `sender_key.dart` — group encryption, key rotation, multi-state record
- `signal_protocol_service.dart` — end-to-end integration

Test coverage is currently low. Contributions of tests are highly
welcomed — see [CONTRIBUTING.md](../CONTRIBUTING.md) for details.

To run tests once they exist:

```bash
dart test
```

Or for a specific file:

```bash
dart test test/double_ratchet_test.dart
```
