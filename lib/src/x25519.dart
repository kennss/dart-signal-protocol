/// @file        x25519.dart
/// @description X25519 Diffie-Hellman key exchange and Ed25519 -> X25519 key conversion, built on pinenacl's TweetNaCl
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-11-23 (English-only comments; library directive; analyzer clean). Earlier 2026-04-12
///
/// @functions
///  - X25519KeyPair: X25519 key pair data class
///  - X25519KeyPair.generate(): Generate a new X25519 key pair
///  - x25519Dh(privateKey, publicKey): raw X25519 DH (crypto_scalarmult)
///  - ed25519PublicKeyToX25519(ed25519PublicKey): Convert an Ed25519 public key to X25519
///  - ed25519PrivateKeyToX25519(ed25519PrivateSeed): Convert an Ed25519 private seed to X25519
library;

import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;
// Direct access to TweetNaCl for raw crypto_scalarmult (no HSalsa20);
// TweetNaClExt is part of the same public library.
import 'package:pinenacl/tweetnacl.dart';
import 'package:pinenacl/x25519.dart' as nacl;

/// An X25519 (Curve25519) key pair for Diffie-Hellman key exchange.
class X25519KeyPair {
  /// 32-byte X25519 private key.
  final Uint8List privateKey;

  /// 32-byte X25519 public key (point on Curve25519).
  final Uint8List publicKey;

  const X25519KeyPair({
    required this.privateKey,
    required this.publicKey,
  });

  /// Generate a new random X25519 key pair using pinenacl.
  factory X25519KeyPair.generate() {
    final pk = nacl.PrivateKey.generate();
    return X25519KeyPair(
      privateKey: Uint8List.fromList(pk.toList()),
      publicKey: Uint8List.fromList(pk.publicKey.toList()),
    );
  }
}

/// Compute raw X25519 Diffie-Hellman shared secret.
///
/// Returns a 32-byte shared secret from [privateKey] (our scalar)
/// and [publicKey] (their point).
///
/// Uses TweetNaCl's crypto_scalarmult directly (NOT Box.sharedKey which
/// applies HSalsa20 on top). Signal Protocol X3DH requires the raw DH output.
Uint8List x25519Dh(Uint8List privateKey, Uint8List publicKey) {
  final q = Uint8List(32);
  TweetNaCl.crypto_scalarmult(q, privateKey, publicKey);
  // Reject small-order points that produce all-zero shared secret
  if (q.every((b) => b == 0)) {
    throw ArgumentError('X25519 DH produced zero output — '
        'possible small-subgroup attack on remote public key');
  }
  return q;
}

/// Convert an Ed25519 public key (32 bytes) to an X25519 public key.
///
/// Uses pinenacl's TweetNaClExt (battle-tested libsodium port),
/// not custom BigInt arithmetic.
Uint8List ed25519PublicKeyToX25519(Uint8List edPublicKey) {
  final out = Uint8List(32);
  TweetNaClExt.crypto_sign_ed25519_pk_to_x25519_pk(out, edPublicKey);
  return out;
}

/// Convert an Ed25519 private key seed (32 bytes) to an X25519 private key.
///
/// Uses SHA-512 hash of the seed, then clamps first 32 bytes as X25519 scalar.
/// Compatible with libsodium's crypto_sign_ed25519_sk_to_x25519_sk.
Uint8List ed25519PrivateKeyToX25519(Uint8List ed25519PrivateSeed) {
  // TweetNaClExt expects 64-byte Ed25519 secret key (seed || public).
  // If we only have the 32-byte seed, we need to derive the 64-byte key first.
  // pinenacl's SigningKey can do this.
  final signingKey = ed.SigningKey(seed: ed25519PrivateSeed);
  // SigningKey stores the full 64-byte key internally
  final fullKey = Uint8List.fromList([
    ...ed25519PrivateSeed,
    ...signingKey.verifyKey,
  ]);
  final out = Uint8List(32);
  try {
    TweetNaClExt.crypto_sign_ed25519_sk_to_x25519_sk(out, fullKey);
    return out;
  } finally {
    // H-2 FIX: Zeroize sensitive expanded key material immediately after use.
    fullKey.fillRange(0, fullKey.length, 0x00);
  }
}
