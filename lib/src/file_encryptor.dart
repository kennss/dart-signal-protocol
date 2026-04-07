/// @file        file_encryptor.dart
/// @description 파일 암복호화. 랜덤 키로 파일을 XSalsa20-Poly1305 암호화하고 SHA-256 해시 생성
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-03-30
///
/// @functions
///  - EncryptedFileResult: 암호화된 파일 결과 (암호문, 파일 키, 콘텐츠 해시)
///  - FileEncryptor.encryptFile(): 랜덤 키로 파일 암호화
///  - FileEncryptor.decryptFile(): 파일 키로 파일 복호화

import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/x25519.dart' as nacl_api;

import 'hkdf.dart' show sha256;

// ---------------------------------------------------------------------------
// EncryptedFileResult
// ---------------------------------------------------------------------------

/// Result of encrypting a file.
class EncryptedFileResult {
  /// The encrypted file data (nonce + ciphertext + auth tag).
  final Uint8List encryptedData;

  /// 32-byte random key used for encryption (include in E2EE message).
  final Uint8List fileKey;

  /// SHA-256 hash of the encrypted data (hex-encoded) for integrity check.
  final String contentHash;

  const EncryptedFileResult({
    required this.encryptedData,
    required this.fileKey,
    required this.contentHash,
  });
}

// ---------------------------------------------------------------------------
// FileEncryptor
// ---------------------------------------------------------------------------

/// Encrypts and decrypts files using XSalsa20-Poly1305 (pinenacl SecretBox)
/// with random 32-byte keys.
///
/// Flow:
/// 1. Sender generates random 32-byte fileKey
/// 2. Sender encrypts file with fileKey -> encryptedData
/// 3. Sender computes SHA-256 of encryptedData -> contentHash
/// 4. Sender uploads encryptedData to server (server never sees fileKey)
/// 5. Sender sends { fileId, fileKey, fileName, mimeType, size, contentHash }
///    inside an E2EE message
/// 6. Recipient downloads encryptedData, verifies contentHash, decrypts with fileKey
class FileEncryptor {
  static final _rng = Random.secure();

  /// Encrypt file data with a random key.
  ///
  /// Returns [EncryptedFileResult] containing the encrypted data,
  /// the random file key, and the content hash.
  static Future<EncryptedFileResult> encryptFile(Uint8List fileData) async {
    // Generate random 32-byte key
    final fileKey = _randomBytes(32);

    // Encrypt with XSalsa20-Poly1305
    final box = nacl_api.SecretBox(fileKey);
    final nonce = _randomBytes(nacl_api.EncryptedMessage.nonceLength);
    final encrypted = box.encrypt(fileData, nonce: nonce);
    final encryptedData = Uint8List.fromList(encrypted.toList());

    // Compute SHA-256 hash of the encrypted data
    final hash = sha256(encryptedData);
    final contentHash = _bytesToHex(hash);

    return EncryptedFileResult(
      encryptedData: encryptedData,
      fileKey: fileKey,
      contentHash: contentHash,
    );
  }

  /// Decrypt file data with the provided key.
  ///
  /// [encryptedData] should contain the nonce prefix (24 bytes) followed
  /// by the ciphertext + auth tag, as produced by [encryptFile].
  ///
  /// Optionally verify [expectedHash] (SHA-256 of encryptedData) before
  /// decryption for integrity.
  static Future<Uint8List> decryptFile(
    Uint8List encryptedData,
    Uint8List fileKey, {
    String? expectedHash,
  }) async {
    // Verify content hash if provided
    if (expectedHash != null) {
      final actualHash = _bytesToHex(sha256(encryptedData));
      if (actualHash != expectedHash) {
        throw StateError(
          'File content hash mismatch. Expected: $expectedHash, '
          'Got: $actualHash. File may have been tampered with.',
        );
      }
    }

    // Decrypt with XSalsa20-Poly1305
    final box = nacl_api.SecretBox(fileKey);
    final nonceLen = nacl_api.EncryptedMessage.nonceLength;

    if (encryptedData.length <= nonceLen) {
      throw ArgumentError('Encrypted data too short');
    }

    final decrypted = box.decrypt(
      nacl_api.EncryptedMessage(
        nonce: encryptedData.sublist(0, nonceLen),
        cipherText: encryptedData.sublist(nonceLen),
      ),
    );

    return Uint8List.fromList(decrypted.toList());
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  static Uint8List _randomBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _rng.nextInt(256);
    }
    return bytes;
  }

  static String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
