/// @file        x3dh.dart
/// @description X3DH (Extended Triple Diffie-Hellman) 키 합의 프로토콜. 비동기 세션 수립에 사용
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-03-30
///
/// @functions
///  - X3DHResult: X3DH 세션 수립 결과 (공유 비밀 + 임시 공개키)
///  - X3DH.initiateSession(): Alice가 Bob의 PreKey 번들로 세션 시작
///  - X3DH.receiveSession(): Bob이 Alice의 초기 메시지로 세션 수립

import 'dart:convert';
import 'dart:typed_data';

import 'logger.dart';

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

/// X3DH info string used in HKDF for domain separation.
final Uint8List _x3dhInfo = Uint8List.fromList(utf8.encode('SnowChat_X3DH'));

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
/// - SK  = HKDF(0xFF*32 || DH1 || DH2 || DH3 [|| DH4])
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
      final dh4 = x25519Dh(ephemeral.privateKey, remoteOneTimePreKey!);
      dhConcat.setAll(offset, dh4);
    }

    // Derive shared secret using HKDF
    final sharedSecret = hkdfDerive(
      ikm: dhConcat,
      salt: Uint8List(32), // zero salt per Signal spec
      info: _x3dhInfo,
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
      final dh4 = x25519Dh(oneTimePreKeyPrivate!, remoteEphemeralKey);
      dhConcat.setAll(offset, dh4);
    }

    final sk = hkdfDerive(
      ikm: dhConcat,
      salt: Uint8List(32),
      info: _x3dhInfo,
      length: 32,
    );
    return sk;
  }
}

