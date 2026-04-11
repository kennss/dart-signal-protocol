/// @file        file_encryptor_test.dart
/// @description FileEncryptor 테스트. 암복호화 왕복, 잘못된 키, 빈 파일, 대용량 파일, 해시 검증
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - Encrypt -> decrypt round-trip
///  - Wrong key -> decryption fails
///  - Empty file handling
///  - Large file (1MB)
///  - Key is 32 bytes
///  - Content hash verification
///  - Hash mismatch detection

import 'dart:math';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('FileEncryptor — encrypt/decrypt round-trip', () {
    test('encrypt -> decrypt recovers original data', () async {
      final fileData = Uint8List.fromList(
        List.generate(256, (i) => i % 256),
      );

      final result = await FileEncryptor.encryptFile(fileData);
      final decrypted = await FileEncryptor.decryptFile(
        result.encryptedData,
        result.fileKey,
      );

      expect(decrypted, equals(fileData));
    });

    test('fileKey is 32 bytes', () async {
      final fileData = Uint8List.fromList([1, 2, 3]);
      final result = await FileEncryptor.encryptFile(fileData);
      expect(result.fileKey.length, 32);
    });

    test('contentHash is non-empty hex string', () async {
      final fileData = Uint8List.fromList([1, 2, 3]);
      final result = await FileEncryptor.encryptFile(fileData);

      expect(result.contentHash.isNotEmpty, isTrue);
      // SHA-256 hex = 64 chars
      expect(result.contentHash.length, 64);
      // All hex chars
      expect(
        RegExp(r'^[0-9a-f]+$').hasMatch(result.contentHash),
        isTrue,
      );
    });

    test('empty file encrypt -> decrypt round-trip', () async {
      final fileData = Uint8List(0);

      final result = await FileEncryptor.encryptFile(fileData);
      final decrypted = await FileEncryptor.decryptFile(
        result.encryptedData,
        result.fileKey,
      );

      expect(decrypted.length, 0);
    });

    test('large file (1MB) encrypt -> decrypt round-trip', () async {
      final rng = Random.secure();
      final fileData = Uint8List(1024 * 1024); // 1 MB
      for (var i = 0; i < fileData.length; i++) {
        fileData[i] = rng.nextInt(256);
      }

      final result = await FileEncryptor.encryptFile(fileData);
      final decrypted = await FileEncryptor.decryptFile(
        result.encryptedData,
        result.fileKey,
      );

      expect(decrypted, equals(fileData));
    });
  });

  group('FileEncryptor — wrong key rejection', () {
    test('wrong key fails to decrypt', () async {
      final fileData = Uint8List.fromList([10, 20, 30, 40, 50]);
      final result = await FileEncryptor.encryptFile(fileData);

      // Generate a different key
      final wrongKey = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        wrongKey[i] = (result.fileKey[i] + 1) % 256;
      }

      expect(
        () => FileEncryptor.decryptFile(result.encryptedData, wrongKey),
        throwsA(anything),
      );
    });
  });

  group('FileEncryptor — content hash verification', () {
    test('correct hash passes verification', () async {
      final fileData = Uint8List.fromList([1, 2, 3, 4, 5]);
      final result = await FileEncryptor.encryptFile(fileData);

      // Should not throw with correct hash
      final decrypted = await FileEncryptor.decryptFile(
        result.encryptedData,
        result.fileKey,
        expectedHash: result.contentHash,
      );

      expect(decrypted, equals(fileData));
    });

    test('wrong hash fails verification', () async {
      final fileData = Uint8List.fromList([1, 2, 3, 4, 5]);
      final result = await FileEncryptor.encryptFile(fileData);

      // Tamper with hash
      final wrongHash = 'a' * 64;

      expect(
        () => FileEncryptor.decryptFile(
          result.encryptedData,
          result.fileKey,
          expectedHash: wrongHash,
        ),
        throwsStateError,
      );
    });
  });

  group('FileEncryptor — unique encryption', () {
    test('same file produces different ciphertexts (random nonce)', () async {
      final fileData = Uint8List.fromList([1, 2, 3]);

      final result1 = await FileEncryptor.encryptFile(fileData);
      final result2 = await FileEncryptor.encryptFile(fileData);

      // Different encrypted data (different random nonce)
      expect(
        _bytesEqual(result1.encryptedData, result2.encryptedData),
        isFalse,
      );

      // Different file keys
      expect(
        _bytesEqual(result1.fileKey, result2.fileKey),
        isFalse,
      );
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
