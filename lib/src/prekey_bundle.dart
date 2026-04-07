/// @file        prekey_bundle.dart
/// @description PreKey 번들 생성 및 관리. X3DH 세션 수립을 위한 서명 프리키, 일회용 프리키 생성
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-03-30
///
/// @functions
///  - PreKeyBundle: 서버 업로드용 PreKey 번들 데이터 클래스
///  - SignedPreKey: 서명된 프리키 데이터 클래스 (키쌍 + 서명)
///  - OneTimePreKey: 일회용 프리키 데이터 클래스
///  - PreKeyGenerator.generateSignedPreKey(): 서명된 프리키 생성 (Ed25519 서명)
///  - PreKeyGenerator.generateOneTimePreKeys(): 일회용 프리키 배치 생성
///  - PreKeyGenerator.buildBundleForUpload(): 서버 업로드용 번들 JSON 빌드

import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;

import 'x25519.dart';

/// A prekey bundle containing all keys needed for X3DH session establishment.
class PreKeyBundle {
  /// Bob's X25519 identity public key.
  final Uint8List identityKey;

  /// Bob's signed prekey public key (X25519).
  final Uint8List signedPreKey;

  /// Ed25519 signature over the signed prekey, made with Bob's identity key.
  final Uint8List signedPreKeySignature;

  /// ID of the signed prekey (for server tracking).
  final int signedPreKeyId;

  /// Optional one-time prekey public key (X25519).
  final Uint8List? oneTimePreKey;

  /// ID of the one-time prekey.
  final int? oneTimePreKeyId;

  /// Registration ID for the device.
  final int registrationId;

  const PreKeyBundle({
    required this.identityKey,
    required this.signedPreKey,
    required this.signedPreKeySignature,
    required this.signedPreKeyId,
    this.oneTimePreKey,
    this.oneTimePreKeyId,
    required this.registrationId,
  });

  /// Verify the signed prekey signature using the identity public key (Ed25519).
  bool verifySignature(Uint8List identityPublicKeyEd25519) {
    try {
      final verifyKey = ed.VerifyKey(identityPublicKeyEd25519);
      verifyKey.verify(
        signature: ed.Signature(signedPreKeySignature),
        message: signedPreKey,
      );
      return true;
    } catch (_) {
      return false;
    }
  }
}

/// A signed prekey with both private and public keys.
class SignedPreKey {
  final int keyId;
  final Uint8List privateKey; // X25519 private
  final Uint8List publicKey; // X25519 public
  final Uint8List signature; // Ed25519 signature over publicKey

  const SignedPreKey({
    required this.keyId,
    required this.privateKey,
    required this.publicKey,
    required this.signature,
  });
}

/// A one-time prekey with both private and public keys.
class OneTimePreKey {
  final int keyId;
  final Uint8List privateKey; // X25519 private
  final Uint8List publicKey; // X25519 public

  const OneTimePreKey({
    required this.keyId,
    required this.privateKey,
    required this.publicKey,
  });
}

/// Generator for PreKeys used in the X3DH protocol.
class PreKeyGenerator {
  /// Generate a signed prekey pair, signed with the Ed25519 identity key.
  ///
  /// [keyId] — numeric ID for this signed prekey.
  /// [identityPrivateKeySeed] — 32-byte Ed25519 private key seed for signing.
  static SignedPreKey generateSignedPreKey(
    int keyId,
    Uint8List identityPrivateKeySeed,
  ) {
    // Generate X25519 key pair for the signed prekey
    final kp = X25519KeyPair.generate();

    // Sign the public key with Ed25519 identity key
    final signingKey = ed.SigningKey(seed: identityPrivateKeySeed);
    final signedMessage = signingKey.sign(kp.publicKey);
    final signature = Uint8List.fromList(signedMessage.signature.toList());

    return SignedPreKey(
      keyId: keyId,
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
      signature: signature,
    );
  }

  /// Generate a batch of one-time prekey pairs.
  ///
  /// [startId] — starting key ID for the batch.
  /// [count] — number of prekeys to generate.
  static List<OneTimePreKey> generateOneTimePreKeys(int startId, int count) {
    return List.generate(count, (i) {
      final kp = X25519KeyPair.generate();
      return OneTimePreKey(
        keyId: startId + i,
        privateKey: kp.privateKey,
        publicKey: kp.publicKey,
      );
    });
  }

  /// Build a prekey bundle map suitable for uploading to the server.
  ///
  /// Keys are hex-encoded for transport.
  static Map<String, dynamic> buildBundleForUpload({
    required Uint8List identityPublicKey,
    required SignedPreKey signedPreKey,
    required List<OneTimePreKey> oneTimePreKeys,
    required int registrationId,
  }) {
    return {
      'identityKey': _bytesToHex(identityPublicKey),
      'signedPreKey': {
        'keyId': signedPreKey.keyId,
        'publicKey': _bytesToHex(signedPreKey.publicKey),
        'signature': _bytesToHex(signedPreKey.signature),
      },
      'oneTimePreKeys': oneTimePreKeys
          .map((opk) => {
                'keyId': opk.keyId,
                'publicKey': _bytesToHex(opk.publicKey),
              })
          .toList(),
      'registrationId': registrationId,
    };
  }

  static String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
