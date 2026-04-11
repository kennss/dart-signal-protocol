/// @file        sender_certificate_test.dart
/// @description SenderCertificate 테스트. 직렬화/역직렬화, 필드 보존, 만료 검증, 서명 검증, 에러 조건
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - Serialize -> deserialize round-trip (177 bytes)
///  - Field values preserved
///  - Expired certificate -> verify fails
///  - Wrong server key -> verify fails
///  - Truncated bytes -> rejection
///  - Field length validation (snowchatId != 36 bytes -> error)

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
      (DateTime.now().millisecondsSinceEpoch + 3600 * 1000); // +1 hour

  // Build the signed portion manually to create a valid signature
  final buffer = Uint8List(113); // _signedPortionLength
  var offset = 0;

  // version
  buffer[offset] = 0x01;
  offset += 1;

  // snowchatId (36 bytes)
  final snowIdBytes = Uint8List.fromList(snowchatId.codeUnits);
  buffer.setAll(offset, snowIdBytes);
  offset += 36;

  // deviceId (36 bytes)
  final deviceIdBytes = Uint8List.fromList(deviceId.codeUnits);
  buffer.setAll(offset, deviceIdBytes);
  offset += 36;

  // identityKey (32 bytes)
  buffer.setAll(offset, ik);
  offset += 32;

  // expiry (8 bytes BE)
  buffer[offset] = (expiry >> 56) & 0xFF;
  buffer[offset + 1] = (expiry >> 48) & 0xFF;
  buffer[offset + 2] = (expiry >> 40) & 0xFF;
  buffer[offset + 3] = (expiry >> 32) & 0xFF;
  buffer[offset + 4] = (expiry >> 24) & 0xFF;
  buffer[offset + 5] = (expiry >> 16) & 0xFF;
  buffer[offset + 6] = (expiry >> 8) & 0xFF;
  buffer[offset + 7] = expiry & 0xFF;

  // Sign
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

  setUp(() {
    serverSigningKey = ed.SigningKey.generate();
    serverVerifyKeyBytes =
        Uint8List.fromList(serverSigningKey.verifyKey.toList());
  });

  group('SenderCertificate — serialization', () {
    test('toBytes produces exactly 177 bytes', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final bytes = cert.toBytes();
      expect(bytes.length, senderCertificateLength);
      expect(bytes.length, 177);
    });

    test('fromBytes -> toBytes round-trip preserves all fields', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final bytes = cert.toBytes();
      final restored = SenderCertificate.fromBytes(bytes);

      expect(restored.version, cert.version);
      expect(restored.senderSnowchatId, cert.senderSnowchatId);
      expect(restored.senderDeviceId, cert.senderDeviceId);
      expect(restored.senderIdentityKey, equals(cert.senderIdentityKey));
      expect(restored.expiryMs, cert.expiryMs);
      expect(restored.serverSignature, equals(cert.serverSignature));
    });

    test('field values preserved exactly', () {
      final ik = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        ik[i] = i;
      }

      final cert = _createTestCert(
        serverKey: serverSigningKey,
        snowchatId: 'snowabcdef0123456789abcdef012345ab01',
        deviceId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        identityKey: ik,
      );

      final bytes = cert.toBytes();
      final restored = SenderCertificate.fromBytes(bytes);

      expect(
          restored.senderSnowchatId, 'snowabcdef0123456789abcdef012345ab01');
      expect(restored.senderDeviceId, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
      expect(restored.senderIdentityKey, equals(ik));
    });
  });

  group('SenderCertificate — verification', () {
    test('valid certificate passes verify()', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      // Should not throw
      cert.verify(serverVerifyKeyBytes);
    });

    test('expired certificate fails verify()', () {
      final cert = _createTestCert(
        serverKey: serverSigningKey,
        expiryMs: DateTime.now().millisecondsSinceEpoch - 1000, // 1 sec ago
      );

      expect(
        () => cert.verify(serverVerifyKeyBytes),
        throwsStateError,
      );
    });

    test('wrong server key fails verify()', () {
      final cert = _createTestCert(serverKey: serverSigningKey);

      // Different server key
      final wrongKey = ed.SigningKey.generate();
      final wrongVerifyKey =
          Uint8List.fromList(wrongKey.verifyKey.toList());

      expect(
        () => cert.verify(wrongVerifyKey),
        throwsStateError,
      );
    });

    test('tampered certificate fails verify() — modified identityKey', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final bytes = cert.toBytes();

      // Tamper with byte 80 (part of senderIdentityKey, binary field)
      bytes[80] ^= 0xFF;

      final tampered = SenderCertificate.fromBytes(bytes);
      expect(
        () => tampered.verify(serverVerifyKeyBytes),
        throwsStateError,
      );
    });
  });

  group('SenderCertificate — error conditions', () {
    test('truncated bytes rejected', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final bytes = cert.toBytes();

      // Truncate to 100 bytes
      expect(
        () => SenderCertificate.fromBytes(bytes.sublist(0, 100)),
        throwsArgumentError,
      );
    });

    test('extra bytes rejected (not exactly 177)', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final bytes = cert.toBytes();

      // Add extra byte
      final padded = Uint8List(178);
      padded.setAll(0, bytes);
      padded[177] = 0xFF;

      expect(
        () => SenderCertificate.fromBytes(padded),
        throwsArgumentError,
      );
    });

    test('wrong version byte rejected', () {
      final cert = _createTestCert(serverKey: serverSigningKey);
      final bytes = cert.toBytes();

      // Change version from 0x01 to 0x02
      bytes[0] = 0x02;

      expect(
        () => SenderCertificate.fromBytes(bytes),
        throwsArgumentError,
      );
    });

    test('snowchatId wrong length rejected on toBytes()', () {
      final cert = SenderCertificate(
        version: 0x01,
        senderSnowchatId: 'short', // 5 chars, not 36
        senderDeviceId: '12345678-1234-1234-1234-123456789012',
        senderIdentityKey: Uint8List(32),
        expiryMs: DateTime.now().millisecondsSinceEpoch + 3600000,
        serverSignature: Uint8List(64),
      );

      expect(
        () => cert.toBytes(),
        throwsArgumentError,
      );
    });

    test('deviceId wrong length rejected on toBytes()', () {
      final cert = SenderCertificate(
        version: 0x01,
        senderSnowchatId: 'snow05a3b2c4d6e8f0112233445566778899',
        senderDeviceId: 'too-short', // not 36 chars
        senderIdentityKey: Uint8List(32),
        expiryMs: DateTime.now().millisecondsSinceEpoch + 3600000,
        serverSignature: Uint8List(64),
      );

      expect(
        () => cert.toBytes(),
        throwsArgumentError,
      );
    });

    test('isExpired returns true for past expiry', () {
      final cert = _createTestCert(
        serverKey: serverSigningKey,
        expiryMs: DateTime.now().millisecondsSinceEpoch - 60000,
      );
      expect(cert.isExpired, isTrue);
    });

    test('isExpired returns false for future expiry', () {
      final cert = _createTestCert(
        serverKey: serverSigningKey,
        expiryMs: DateTime.now().millisecondsSinceEpoch + 3600000,
      );
      expect(cert.isExpired, isFalse);
    });
  });
}
