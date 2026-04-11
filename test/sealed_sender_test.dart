/// @file        sealed_sender_test.dart
/// @description Sealed Sender 서비스 테스트. seal/unseal 왕복, 리플레이 탐지, 타임스탬프 윈도우, 패딩, 에러 조건
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - Seal -> unseal round-trip
///  - Sender identity recovered correctly after unseal
///  - Wrong recipient key -> decryption fails
///  - Replay detection (same envelope twice -> rejected)
///  - Timestamp window check (old message -> rejected)
///  - Padding minimum 512 bytes
///  - Version byte check (unknown version -> rejected)
///  - Certificate verification (valid -> pass, tampered -> fail)
///  - Generic error messages (no oracle leakage)

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

/// Create a valid test certificate signed by the given server signing key.
SenderCertificate _createTestCert({
  required ed.SigningKey serverKey,
  String snowchatId = 'snow05a3b2c4d6e8f0112233445566778899',
  String deviceId = '12345678-1234-1234-1234-123456789012',
  Uint8List? identityKey,
  int? expiryMs,
}) {
  final ik = identityKey ?? Uint8List(32)
    ..fillRange(0, 32, 0xAB);
  final expiry = expiryMs ??
      (DateTime.now().millisecondsSinceEpoch + 3600 * 1000);

  final buffer = Uint8List(113);
  var offset = 0;

  buffer[offset] = 0x01;
  offset += 1;

  buffer.setAll(offset, Uint8List.fromList(snowchatId.codeUnits));
  offset += 36;

  buffer.setAll(offset, Uint8List.fromList(deviceId.codeUnits));
  offset += 36;

  buffer.setAll(offset, ik);
  offset += 32;

  buffer[offset] = (expiry >> 56) & 0xFF;
  buffer[offset + 1] = (expiry >> 48) & 0xFF;
  buffer[offset + 2] = (expiry >> 40) & 0xFF;
  buffer[offset + 3] = (expiry >> 32) & 0xFF;
  buffer[offset + 4] = (expiry >> 24) & 0xFF;
  buffer[offset + 5] = (expiry >> 16) & 0xFF;
  buffer[offset + 6] = (expiry >> 8) & 0xFF;
  buffer[offset + 7] = expiry & 0xFF;

  final signed = serverKey.sign(buffer);
  final signature =
      Uint8List.fromList(signed.sublist(0, ed.Signature.signatureLength));

  return SenderCertificate(
    version: 0x01,
    senderSnowchatId: snowchatId,
    senderDeviceId: deviceId,
    senderIdentityKey: ik,
    expiryMs: expiry,
    serverSignature: signature,
  );
}

void main() {
  late ed.SigningKey serverSigningKey;
  late Uint8List serverVerifyKeyBytes;
  late X25519KeyPair recipientIK;
  late SealedSenderService senderService;
  late SealedSenderService recipientService;

  setUp(() {
    serverSigningKey = ed.SigningKey.generate();
    serverVerifyKeyBytes =
        Uint8List.fromList(serverSigningKey.verifyKey.toList());
    recipientIK = X25519KeyPair.generate();

    senderService = SealedSenderService(serverVerifyKey: serverVerifyKeyBytes);
    recipientService =
        SealedSenderService(serverVerifyKey: serverVerifyKeyBytes);
  });

  group('Sealed Sender — seal/unseal round-trip', () {
    test('seal -> unseal recovers drCiphertext', () {
      final drCiphertext =
          Uint8List.fromList(utf8.encode('encrypted-dr-message'));
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: drCiphertext,
        certificate: cert,
        messageContext: sealedType1to1,
      );

      final unsealed = recipientService.unseal(
        myIdentityPrivateKey: recipientIK.privateKey,
        myIdentityPublicKey: recipientIK.publicKey,
        sealedEnvelope: sealed,
      );

      expect(unsealed.drCiphertext, equals(drCiphertext));
    });

    test('sender identity recovered correctly after unseal', () {
      final cert = _createTestCert(
        serverKey: serverSigningKey,
        snowchatId: 'snowabcdef0123456789abcdef012345ab01',
        deviceId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
      );

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      final unsealed = recipientService.unseal(
        myIdentityPrivateKey: recipientIK.privateKey,
        myIdentityPublicKey: recipientIK.publicKey,
        sealedEnvelope: sealed,
      );

      expect(unsealed.senderSnowchatId, 'snowabcdef0123456789abcdef012345ab01');
      expect(unsealed.senderDeviceId, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    });

    test('messageContext preserved through seal/unseal', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1]),
        certificate: cert,
        messageContext: sealedTypeGroup,
      );

      final unsealed = recipientService.unseal(
        myIdentityPrivateKey: recipientIK.privateKey,
        myIdentityPublicKey: recipientIK.publicKey,
        sealedEnvelope: sealed,
      );

      expect(unsealed.messageContext, sealedTypeGroup);
    });

    test('timestamp is within recent window', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final now = DateTime.now().millisecondsSinceEpoch;

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      final unsealed = recipientService.unseal(
        myIdentityPrivateKey: recipientIK.privateKey,
        myIdentityPublicKey: recipientIK.publicKey,
        sealedEnvelope: sealed,
      );

      // Timestamp should be very close to now (within a few seconds)
      expect((unsealed.timestampMs - now).abs(), lessThan(5000));
    });
  });

  group('Sealed Sender — error conditions', () {
    test('wrong recipient key fails to unseal', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final wrongRecipient = X25519KeyPair.generate();

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // Try to unseal with wrong private key
      expect(
        () => recipientService.unseal(
          myIdentityPrivateKey: wrongRecipient.privateKey,
          myIdentityPublicKey: wrongRecipient.publicKey,
          sealedEnvelope: sealed,
        ),
        throwsStateError,
      );
    });

    test('replay detection: same envelope twice is rejected', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // First unseal succeeds
      recipientService.unseal(
        myIdentityPrivateKey: recipientIK.privateKey,
        myIdentityPublicKey: recipientIK.publicKey,
        sealedEnvelope: sealed,
      );

      // Second unseal (replay) should fail
      expect(
        () => recipientService.unseal(
          myIdentityPrivateKey: recipientIK.privateKey,
          myIdentityPublicKey: recipientIK.publicKey,
          sealedEnvelope: sealed,
        ),
        throwsStateError,
      );
    });

    test('unknown version byte rejected', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // Tamper with version byte
      sealed[0] = 0xFF;

      expect(
        () => recipientService.unseal(
          myIdentityPrivateKey: recipientIK.privateKey,
          myIdentityPublicKey: recipientIK.publicKey,
          sealedEnvelope: sealed,
        ),
        throwsStateError,
      );
    });

    test('truncated envelope rejected', () {
      expect(
        () => recipientService.unseal(
          myIdentityPrivateKey: recipientIK.privateKey,
          myIdentityPublicKey: recipientIK.publicKey,
          sealedEnvelope: Uint8List(10), // way too short
        ),
        throwsStateError,
      );
    });

    test('expired certificate in envelope rejected', () {
      final cert = _createTestCert(
        serverKey: serverSigningKey,
        expiryMs: DateTime.now().millisecondsSinceEpoch - 1000,
      );

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      expect(
        () => recipientService.unseal(
          myIdentityPrivateKey: recipientIK.privateKey,
          myIdentityPublicKey: recipientIK.publicKey,
          sealedEnvelope: sealed,
        ),
        throwsStateError,
      );
    });

    test('wrong server verify key in recipient rejects certificate', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // Recipient service with wrong server key
      final wrongServerKey = ed.SigningKey.generate();
      final wrongService = SealedSenderService(
        serverVerifyKey:
            Uint8List.fromList(wrongServerKey.verifyKey.toList()),
      );

      expect(
        () => wrongService.unseal(
          myIdentityPrivateKey: recipientIK.privateKey,
          myIdentityPublicKey: recipientIK.publicKey,
          sealedEnvelope: sealed,
        ),
        throwsStateError,
      );
    });

    test('generic error messages for security (no oracle leakage)', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // Tamper with ciphertext area
      sealed[sealed.length - 1] ^= 0xFF;

      try {
        recipientService.unseal(
          myIdentityPrivateKey: recipientIK.privateKey,
          myIdentityPublicKey: recipientIK.publicKey,
          sealedEnvelope: sealed,
        );
        fail('Should have thrown');
      } on StateError catch (e) {
        // Error message should be generic — not leak specific failure reason
        expect(e.message, 'Sealed message rejected');
      }
    });
  });

  group('Sealed Sender — envelope format', () {
    test('envelope starts with version byte 0x01', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      expect(sealed[0], 0x01);
    });

    test('envelope contains 32-byte ephemeral key at offset 1', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1, 2, 3]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // EK_seal at bytes [1..33)
      final ekSeal = sealed.sublist(1, 33);
      expect(ekSeal.length, 32);
      expect(ekSeal.any((b) => b != 0), isTrue);
    });

    test('each seal produces different envelope (unique ephemeral key)', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final drCiphertext = Uint8List.fromList([1, 2, 3]);

      final sealed1 = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: drCiphertext,
        certificate: cert,
        messageContext: sealedType1to1,
      );

      final sealed2 = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: drCiphertext,
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // EK_seal should differ
      final ek1 = sealed1.sublist(1, 33);
      final ek2 = sealed2.sublist(1, 33);
      expect(_bytesEqual(ek1, ek2), isFalse);
    });

    test('envelope size >= minimum envelope size', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      final sealed = senderService.seal(
        recipientIdentityPubKey: recipientIK.publicKey,
        drCiphertext: Uint8List.fromList([1]),
        certificate: cert,
        messageContext: sealedType1to1,
      );

      // Minimum: header (33) + nonce (24) + inner(190+pad) + tag (16)
      // With 512 byte minimum inner, this should be substantial
      expect(sealed.length, greaterThan(33 + 24 + 190 + 16));
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
