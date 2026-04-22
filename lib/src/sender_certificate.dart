/// @file        sender_certificate.dart
/// @description Sealed Sender 용 발신자 인증서. 고정 177바이트 바이너리 직렬화/역직렬화, Ed25519 서명 검증, 만료 확인
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-11
/// @lastUpdated 2026-04-20
///
/// @functions
///  - SenderCertificate: 발신자 인증서 데이터 클래스 (177바이트 고정)
///  - SenderCertificate.toBytes(): 인증서를 177바이트 바이너리로 직렬화
///  - SenderCertificate.fromBytes(): 177바이트 바이너리에서 인증서 역직렬화
///  - SenderCertificate.verify(): Ed25519 서명 검증 + 만료 확인
///  - SenderCertificate.isExpired: 인증서 만료 여부

import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sender certificate version byte.
const int _certVersion = 0x01;

/// Total fixed certificate size: 1 + 36 + 36 + 32 + 8 + 64 = 177 bytes.
const int senderCertificateLength = 177;

/// Bytes covered by the server signature (version through expiry).
const int _signedPortionLength = 113;

/// Ed25519 signature length.
const int _signatureLength = 64;

/// SnowChat ID fixed length ("snow" + 32 hex chars).
const int _snowchatIdLength = 36;

/// Device ID fixed length (UUID v4).
const int _deviceIdLength = 36;

/// X25519 identity key length.
const int _identityKeyLength = 32;

/// Timestamp length (big-endian uint64 milliseconds).
const int _timestampLength = 8;

// ---------------------------------------------------------------------------
// SenderCertificate
// ---------------------------------------------------------------------------

/// A server-signed certificate that binds a sender's identity to their
/// SnowChat ID, device ID, and X25519 identity key with a time-bounded expiry.
///
/// Wire format (177 bytes, fixed size):
/// ```
/// [0]       version           = 0x01
/// [1..36]   senderSnowchatId  UTF-8 (36 bytes)
/// [37..72]  senderDeviceId    UTF-8 UUID (36 bytes)
/// [73..104] senderIdentityKey X25519 public key (32 bytes)
/// [105..112] expiry           Unix ms big-endian uint64
/// [113..176] serverSignature  Ed25519 over bytes [0..112]
/// ```
class SenderCertificate {
  /// Protocol version (must be 0x01 for v1).
  final int version;

  /// Sender's SnowChat ID (36 bytes: "snow" + 32 hex chars).
  final String senderSnowchatId;

  /// Sender's device UUID (36 bytes).
  final String senderDeviceId;

  /// Sender's X25519 identity public key (32 bytes).
  final Uint8List senderIdentityKey;

  /// Certificate expiry as Unix timestamp in milliseconds.
  final int expiryMs;

  /// Ed25519 server signature over the first 113 bytes.
  final Uint8List serverSignature;

  const SenderCertificate({
    required this.version,
    required this.senderSnowchatId,
    required this.senderDeviceId,
    required this.senderIdentityKey,
    required this.expiryMs,
    required this.serverSignature,
  });

  /// Whether this certificate has expired.
  bool get isExpired =>
      DateTime.now().millisecondsSinceEpoch >= expiryMs;

  // -------------------------------------------------------------------------
  // Serialization
  // -------------------------------------------------------------------------

  /// Serialize this certificate to a 177-byte fixed-size binary.
  Uint8List toBytes() {
    final buffer = Uint8List(senderCertificateLength);
    var offset = 0;

    // [0] version
    buffer[offset] = version;
    offset += 1;

    // [1..36] senderSnowchatId (UTF-8, exactly 36 bytes)
    final snowIdBytes = utf8.encode(senderSnowchatId);
    if (snowIdBytes.length != _snowchatIdLength) {
      throw ArgumentError(
        'senderSnowchatId must be exactly $_snowchatIdLength bytes, '
        'got ${snowIdBytes.length}',
      );
    }
    buffer.setAll(offset, snowIdBytes);
    offset += _snowchatIdLength;

    // [37..72] senderDeviceId (UTF-8 UUID, exactly 36 bytes)
    final deviceIdBytes = utf8.encode(senderDeviceId);
    if (deviceIdBytes.length != _deviceIdLength) {
      throw ArgumentError(
        'senderDeviceId must be exactly $_deviceIdLength bytes, '
        'got ${deviceIdBytes.length}',
      );
    }
    buffer.setAll(offset, deviceIdBytes);
    offset += _deviceIdLength;

    // [73..104] senderIdentityKey (32 bytes)
    if (senderIdentityKey.length != _identityKeyLength) {
      throw ArgumentError(
        'senderIdentityKey must be exactly $_identityKeyLength bytes, '
        'got ${senderIdentityKey.length}',
      );
    }
    buffer.setAll(offset, senderIdentityKey);
    offset += _identityKeyLength;

    // [105..112] expiry (big-endian uint64 ms)
    _putUint64BE(buffer, offset, expiryMs);
    offset += _timestampLength;

    // [113..176] serverSignature (64 bytes)
    buffer.setAll(offset, serverSignature);

    return buffer;
  }

  /// Deserialize a 177-byte binary into a [SenderCertificate].
  ///
  /// Throws [ArgumentError] if the buffer is the wrong size or the version
  /// byte is unrecognized.
  factory SenderCertificate.fromBytes(Uint8List bytes) {
    if (bytes.length != senderCertificateLength) {
      throw ArgumentError(
        'SenderCertificate must be exactly $senderCertificateLength bytes, '
        'got ${bytes.length}',
      );
    }

    var offset = 0;

    // [0] version
    final version = bytes[offset];
    if (version != _certVersion) {
      throw ArgumentError(
        'Unknown SenderCertificate version: 0x${version.toRadixString(16)}',
      );
    }
    offset += 1;

    // [1..36] senderSnowchatId
    final senderSnowchatId = utf8.decode(
      bytes.sublist(offset, offset + _snowchatIdLength),
    );
    offset += _snowchatIdLength;

    // [37..72] senderDeviceId
    final senderDeviceId = utf8.decode(
      bytes.sublist(offset, offset + _deviceIdLength),
    );
    offset += _deviceIdLength;

    // [73..104] senderIdentityKey
    final senderIdentityKey = Uint8List.fromList(
      bytes.sublist(offset, offset + _identityKeyLength),
    );
    offset += _identityKeyLength;

    // [105..112] expiry
    final expiryMs = _getUint64BE(bytes, offset);
    offset += _timestampLength;

    // [113..176] serverSignature
    final serverSignature = Uint8List.fromList(
      bytes.sublist(offset, offset + _signatureLength),
    );

    return SenderCertificate(
      version: version,
      senderSnowchatId: senderSnowchatId,
      senderDeviceId: senderDeviceId,
      senderIdentityKey: senderIdentityKey,
      expiryMs: expiryMs,
      serverSignature: serverSignature,
    );
  }

  // -------------------------------------------------------------------------
  // Verification
  // -------------------------------------------------------------------------

  /// Verify this certificate against the server's Ed25519 verify key.
  ///
  /// Checks in order (all must pass):
  /// 1. Version == 0x01
  /// 2. Not expired
  /// 3. Ed25519 signature over bytes [0..112] is valid
  ///
  /// Throws [StateError] on any verification failure with a descriptive message.
  void verify(Uint8List serverVerifyKey) {
    // 1. Version check
    if (version != _certVersion) {
      throw StateError(
        'SenderCertificate version mismatch: expected 0x01, got '
        '0x${version.toRadixString(16)}',
      );
    }

    // 2. Expiry check
    if (isExpired) {
      throw StateError(
        'SenderCertificate expired at '
        '${DateTime.fromMillisecondsSinceEpoch(expiryMs).toIso8601String()}',
      );
    }

    // 3. Server signature verification
    // Uses the same VerifyKey.verify() pattern as prekey_bundle.dart and
    // sender_key.dart. Throws on invalid signature.
    final certBytes = toBytes();
    final signedPortion = Uint8List.sublistView(
      certBytes,
      0,
      _signedPortionLength,
    );

    try {
      final verifyKey = ed.VerifyKey(serverVerifyKey);
      verifyKey.verify(
        signature: ed.Signature(serverSignature),
        message: signedPortion,
      );
    } catch (e) {
      if (e is StateError) rethrow;
      throw StateError(
        'SenderCertificate server signature verification failed: $e',
      );
    }
  }

  @override
  String toString() =>
      'SenderCertificate(v$version, sender=$senderSnowchatId, '
      'device=$senderDeviceId, '
      'expiry=${DateTime.fromMillisecondsSinceEpoch(expiryMs).toIso8601String()})';
}

// ---------------------------------------------------------------------------
// Big-endian uint64 helpers
// ---------------------------------------------------------------------------

/// Write a 64-bit integer as big-endian into [buffer] at [offset].
///
/// Dart's int is 64-bit on VM, 53-bit safe on web. Unix ms timestamps fit
/// well within 53 bits until year 285,616 AD.
void _putUint64BE(Uint8List buffer, int offset, int value) {
  buffer[offset] = (value >> 56) & 0xFF;
  buffer[offset + 1] = (value >> 48) & 0xFF;
  buffer[offset + 2] = (value >> 40) & 0xFF;
  buffer[offset + 3] = (value >> 32) & 0xFF;
  buffer[offset + 4] = (value >> 24) & 0xFF;
  buffer[offset + 5] = (value >> 16) & 0xFF;
  buffer[offset + 6] = (value >> 8) & 0xFF;
  buffer[offset + 7] = value & 0xFF;
}

/// Read a big-endian uint64 from [buffer] at [offset].
int _getUint64BE(Uint8List buffer, int offset) {
  return (buffer[offset] << 56) |
      (buffer[offset + 1] << 48) |
      (buffer[offset + 2] << 40) |
      (buffer[offset + 3] << 32) |
      (buffer[offset + 4] << 24) |
      (buffer[offset + 5] << 16) |
      (buffer[offset + 6] << 8) |
      buffer[offset + 7];
}
