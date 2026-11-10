/// @file        x3dh.dart
/// @description X3DH (Extended Triple Diffie-Hellman) key agreement protocol. Used for asynchronous session establishment
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-11-10 (backport SnowChat ddfbe6d: domain-separated HKDF info — SnowChat_X3DH_4DH vs SnowChat_X3DH_5DH; BREAKING wire change for new sessions)
///
/// @functions
///  - X3DHResult: X3DH session establishment result (shared secret + ephemeral public key)
///  - X3DH.initiateSession(): Alice initiates a session using Bob's PreKey bundle
///  - X3DH.receiveSession(): Bob establishes a session from Alice's initial message
///
/// @notes
///  - _x3dhInfo4DH / _x3dhInfo5DH: HKDF info strings. The 4-DH (no one-time
///    prekey) and 5-DH (with one-time prekey) paths use DIFFERENT info so a
///    silent OPK-path mismatch between initiator and responder fails loudly
///    on the first AEAD check instead of yielding a quietly wrong secret.

import 'dart:convert';
import 'dart:typed_data';

import 'x25519.dart';
import 'hkdf.dart';

/// Result of the X3DH key agreement (initiator side).
class X3DHResult {
  /// 32-byte shared secret derived from X3DH.
  final Uint8List sharedSecret;

  /// Alice's ephemeral public key, to be sent to Bob in the initial message.
  final Uint8List ephemeralPublicKey;

  const X3DHResult({
    required this.sharedSecret,
    required this.ephemeralPublicKey,
  });
}

/// X3DH info strings used in HKDF for domain separation.
///
/// Defense-in-depth: the unified info string is split into 4DH/5DH variants
/// so that a silent fall from the OPK path to the no-OPK path (initiator ran
/// 5-DH, responder ran 4-DH or vice versa) produces an *immediate* AEAD
/// verify failure on the very first message, instead of silently deriving a
/// different shared secret, passing all of X3DH, and leaving every Double
/// Ratchet message undecryptable forever. [SignalProtocolService] also fails
/// loud when a sender-named one-time prekey is missing locally, so this fall
/// should be impossible; the guard costs nothing.
///
/// BREAKING CHANGE (0.3.0): peers running 0.2.x derive X3DH secrets with the
/// old unified `SnowChat_X3DH` info and cannot establish a *new* session with
/// 0.3.x peers. Existing Double Ratchet sessions keep working because the
/// ratchet never re-runs HKDF with this info.
final Uint8List _x3dhInfo4DH =
    Uint8List.fromList(utf8.encode('SnowChat_X3DH_4DH'));
final Uint8List _x3dhInfo5DH =
    Uint8List.fromList(utf8.encode('SnowChat_X3DH_5DH'));

/// 32 zero bytes prepended to DH outputs per the Signal spec
/// (used as a padding prefix before concatenation).
final Uint8List _x3dhPad = Uint8List(32)..fillRange(0, 32, 0xFF);

/// Extended Triple Diffie-Hellman key agreement protocol.
///
/// Implements the Signal Protocol X3DH specification for asynchronous
/// session establishment between two parties.
///
/// DH calculations:
/// - DH1 = DH(IK_A, SPK_B)  — Alice's identity key + Bob's signed prekey
/// - DH2 = DH(EK_A, IK_B)   — Alice's ephemeral + Bob's identity key
/// - DH3 = DH(EK_A, SPK_B)  — Alice's ephemeral + Bob's signed prekey
/// - DH4 = DH(EK_A, OPK_B)  — Alice's ephemeral + Bob's one-time prekey (optional)
/// - SK  = HKDF(0xFF*32 || DH1 || DH2 || DH3 [|| DH4],
///         info = DH4 present ? "SnowChat_X3DH_5DH" : "SnowChat_X3DH_4DH")
class X3DH {
  /// Alice initiates a session using Bob's prekey bundle.
  ///
  /// All keys must be X25519 format (not Ed25519).
  ///
  /// Returns [X3DHResult] containing the shared secret and the ephemeral
  /// public key that must be sent to Bob.
  static X3DHResult initiateSession({
    required Uint8List identityKeyPrivate,
    required Uint8List remoteIdentityKey,
    required Uint8List remoteSignedPreKey,
    Uint8List? remoteOneTimePreKey,
  }) {
    // Generate ephemeral key pair
    final ephemeral = X25519KeyPair.generate();

    // Compute DH values
    final dh1 = x25519Dh(identityKeyPrivate, remoteSignedPreKey);
    final dh2 = x25519Dh(ephemeral.privateKey, remoteIdentityKey);
    final dh3 = x25519Dh(ephemeral.privateKey, remoteSignedPreKey);

    // Security: never log private keys, DH outputs, or shared secrets

    // Concatenate: 0xFF*32 || DH1 || DH2 || DH3 [|| DH4]
    final hasOpk = remoteOneTimePreKey != null;
    final dhLen = 32 + 32 + 32 + 32 + (hasOpk ? 32 : 0);
    final dhConcat = Uint8List(dhLen);
    var offset = 0;

    dhConcat.setAll(offset, _x3dhPad);
    offset += 32;
    dhConcat.setAll(offset, dh1);
    offset += 32;
    dhConcat.setAll(offset, dh2);
    offset += 32;
    dhConcat.setAll(offset, dh3);
    offset += 32;

    if (hasOpk) {
      final dh4 = x25519Dh(ephemeral.privateKey, remoteOneTimePreKey);
      dhConcat.setAll(offset, dh4);
    }

    // Derive shared secret using HKDF
    final sharedSecret = hkdfDerive(
      ikm: dhConcat,
      salt: Uint8List(32), // zero salt per Signal spec
      info: hasOpk ? _x3dhInfo5DH : _x3dhInfo4DH,
      length: 32,
    );

    return X3DHResult(
      sharedSecret: sharedSecret,
      ephemeralPublicKey: ephemeral.publicKey,
    );
  }

  /// Bob receives Alice's initial message and derives the same shared secret.
  ///
  /// All keys must be X25519 format.
  static Uint8List receiveSession({
    required Uint8List identityKeyPrivate,
    required Uint8List signedPreKeyPrivate,
    Uint8List? oneTimePreKeyPrivate,
    required Uint8List remoteIdentityKey,
    required Uint8List remoteEphemeralKey,
  }) {
    // Mirror DH calculations from Alice's perspective
    final dh1 = x25519Dh(signedPreKeyPrivate, remoteIdentityKey);
    final dh2 = x25519Dh(identityKeyPrivate, remoteEphemeralKey);
    final dh3 = x25519Dh(signedPreKeyPrivate, remoteEphemeralKey);

    // Security: never log private keys, DH outputs, or shared secrets

    final hasOpk = oneTimePreKeyPrivate != null;
    final dhLen = 32 + 32 + 32 + 32 + (hasOpk ? 32 : 0);
    final dhConcat = Uint8List(dhLen);
    var offset = 0;

    dhConcat.setAll(offset, _x3dhPad);
    offset += 32;
    dhConcat.setAll(offset, dh1);
    offset += 32;
    dhConcat.setAll(offset, dh2);
    offset += 32;
    dhConcat.setAll(offset, dh3);
    offset += 32;

    if (hasOpk) {
      final dh4 = x25519Dh(oneTimePreKeyPrivate, remoteEphemeralKey);
      dhConcat.setAll(offset, dh4);
    }

    final sk = hkdfDerive(
      ikm: dhConcat,
      salt: Uint8List(32),
      info: hasOpk ? _x3dhInfo5DH : _x3dhInfo4DH,
      length: 32,
    );
    return sk;
  }
}

