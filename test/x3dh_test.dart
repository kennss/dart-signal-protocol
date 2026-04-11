/// @file        x3dh_test.dart
/// @description X3DH 키 합의 프로토콜 테스트. 핸드셰이크 공유 비밀 일치, OPK 유무, 에러 조건 검증
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - Full X3DH handshake produces shared secret
///  - Both sides derive same secret
///  - Without one-time prekey
///  - With one-time prekey
///  - Different identity keys produce different secrets
///  - Ephemeral key is 32 bytes

import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('X3DH handshake', () {
    test('both sides derive same shared secret (without OPK)', () {
      // Alice: identity key
      final aliceIK = X25519KeyPair.generate();

      // Bob: identity key + signed prekey
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      // Alice initiates session
      final result = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      // Bob receives session
      final bobSecret = X3DH.receiveSession(
        identityKeyPrivate: bobIK.privateKey,
        signedPreKeyPrivate: bobSPK.privateKey,
        remoteIdentityKey: aliceIK.publicKey,
        remoteEphemeralKey: result.ephemeralPublicKey,
      );

      expect(result.sharedSecret, equals(bobSecret));
    });

    test('both sides derive same shared secret (with OPK)', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();
      final bobOPK = X25519KeyPair.generate();

      final result = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
        remoteOneTimePreKey: bobOPK.publicKey,
      );

      final bobSecret = X3DH.receiveSession(
        identityKeyPrivate: bobIK.privateKey,
        signedPreKeyPrivate: bobSPK.privateKey,
        oneTimePreKeyPrivate: bobOPK.privateKey,
        remoteIdentityKey: aliceIK.publicKey,
        remoteEphemeralKey: result.ephemeralPublicKey,
      );

      expect(result.sharedSecret, equals(bobSecret));
    });

    test('shared secret is 32 bytes', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      final result = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      expect(result.sharedSecret.length, 32);
    });

    test('ephemeral public key is 32 bytes', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      final result = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      expect(result.ephemeralPublicKey.length, 32);
    });

    test('with vs without OPK produces different secrets', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();
      final bobOPK = X25519KeyPair.generate();

      final resultNoOPK = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      final resultWithOPK = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
        remoteOneTimePreKey: bobOPK.publicKey,
      );

      // Different DH4 contribution means different secrets
      expect(
        _bytesEqual(resultNoOPK.sharedSecret, resultWithOPK.sharedSecret),
        isFalse,
      );
    });

    test('different identity keys produce different secrets', () {
      final aliceIK1 = X25519KeyPair.generate();
      final aliceIK2 = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      final result1 = X3DH.initiateSession(
        identityKeyPrivate: aliceIK1.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      final result2 = X3DH.initiateSession(
        identityKeyPrivate: aliceIK2.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      expect(
        _bytesEqual(result1.sharedSecret, result2.sharedSecret),
        isFalse,
      );
    });

    test('each initiation generates a unique ephemeral key', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      final result1 = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      final result2 = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      expect(
        _bytesEqual(result1.ephemeralPublicKey, result2.ephemeralPublicKey),
        isFalse,
      );
    });

    test('wrong receiver keys cannot derive same secret', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      final result = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      // Eve tries to receive with wrong keys
      final eveIK = X25519KeyPair.generate();
      final eveSPK = X25519KeyPair.generate();

      final eveSecret = X3DH.receiveSession(
        identityKeyPrivate: eveIK.privateKey,
        signedPreKeyPrivate: eveSPK.privateKey,
        remoteIdentityKey: aliceIK.publicKey,
        remoteEphemeralKey: result.ephemeralPublicKey,
      );

      expect(
        _bytesEqual(result.sharedSecret, eveSecret),
        isFalse,
      );
    });

    test('shared secret is not all zeros', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      final result = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      expect(result.sharedSecret.any((b) => b != 0), isTrue);
    });

    test('receiveSession output is 32 bytes', () {
      final aliceIK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();

      final result = X3DH.initiateSession(
        identityKeyPrivate: aliceIK.privateKey,
        remoteIdentityKey: bobIK.publicKey,
        remoteSignedPreKey: bobSPK.publicKey,
      );

      final bobSecret = X3DH.receiveSession(
        identityKeyPrivate: bobIK.privateKey,
        signedPreKeyPrivate: bobSPK.privateKey,
        remoteIdentityKey: aliceIK.publicKey,
        remoteEphemeralKey: result.ephemeralPublicKey,
      );

      expect(bobSecret.length, 32);
    });
  });
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}
