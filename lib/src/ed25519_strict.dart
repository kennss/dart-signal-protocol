/// @file        ed25519_strict.dart
/// @description Strict Ed25519 verification for every signature that decides
///              trust: signed-prekey signatures, sender certificates and
///              Sender Key messages (Identity Binding v1 applies the same
///              rules inside IdentityBindingV1.verify). TweetNaCl (and so
///              pinenacl's VerifyKey.verify) alone accepts a signature whose
///              scalar is not reduced (S >= L — a second, malleated signature
///              for the same message) and a public key of small order (for
///              which one forged signature verifies for EVERY message). The
///              SnowChat reference server and app refuse both; a signature
///              one side accepts and the other refuses splits their views.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-23
/// @lastUpdated 2026-11-23
///
/// @functions
///  - verifyEd25519Strict(): canonical, non-small-order key + S < L + verify
///  - isAcceptableEd25519PublicKey(): the key half of the strict rules
library;

import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;

import 'identity_binding.dart';

/// True when [publicKey] is a 32-byte canonical encoding of a point that is
/// not of small order (see [IdentityBindingV1.isAcceptableAccountKey] — the
/// same blocklist and canonical-y check).
bool isAcceptableEd25519PublicKey(Uint8List? publicKey) =>
    IdentityBindingV1.isAcceptableAccountKey(publicKey);

/// True only when [publicKey] is acceptable ([isAcceptableEd25519PublicKey]),
/// [signature] is 64 bytes with a canonical scalar (S < L, RFC 8032
/// section 5.1.7) and the signature verifies for [message]. Never throws.
bool verifyEd25519Strict(
  Uint8List publicKey,
  Uint8List message,
  Uint8List signature,
) {
  try {
    if (signature.length != 64) return false;
    if (!isAcceptableEd25519PublicKey(publicKey)) return false;
    if (!IdentityBindingV1.isCanonicalSignatureScalar(signature)) return false;
    // pinenacl throws on a bad signature or a key that is not on the curve.
    return ed.VerifyKey(Uint8List.fromList(publicKey)).verify(
      signature: ed.Signature(Uint8List.fromList(signature)),
      message: message,
    );
  } catch (_) {
    return false;
  }
}
