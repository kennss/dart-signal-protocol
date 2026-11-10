# Tests

Unit and integration tests for every module:

- `x25519_test.dart` — X25519 DH and Ed25519 ↔ X25519 conversion
- `hkdf_test.dart` — SHA-256, HMAC, HKDF (RFC 5869 test vectors)
- `x3dh_test.dart` — key agreement (4-DH / 5-DH)
- `double_ratchet_test.dart` — encryption/decryption, out-of-order messages,
  skipped message keys
- `sender_key_test.dart` — group encryption, key rotation, multi-state record
- `file_encryptor_test.dart` — file body encryption
- `sealed_sender_test.dart`, `sender_certificate_test.dart` — Sealed Sender
- `signal_protocol_service_test.dart`, `integration_test.dart` — service
  layer end to end
- `identity_binding_test.dart` — Identity Binding v1 primitive, including the
  shared golden vectors in `fixtures/identity_binding_v1.json` (byte-identical
  to the SnowChat server and app vectors — do not edit them by hand)
- `verified_identity_store_test.dart` — store latch / pin / seeding policy
- `identity_binding_session_test.dart` — identity admission over real X3DH /
  Double Ratchet sessions, backward compatibility, Safety Number v2
- `identity_test_support.dart` — shared helpers (not a test file)

Contributions of tests are highly welcomed — see
[CONTRIBUTING.md](../CONTRIBUTING.md) for details.

Run everything from the package root (the fixture path is relative to it):

```bash
dart test
```

Or a specific file:

```bash
dart test test/double_ratchet_test.dart
```
