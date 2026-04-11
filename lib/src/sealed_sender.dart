/// @file        sealed_sender.dart
/// @description Sealed Sender 서비스. seal() 암호화 / unseal() 복호화, 리플레이 캐시, 패딩 처리
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-11
/// @lastUpdated 2026-04-12
///
/// @functions
///  - SealedSenderService: Sealed Sender 암호화/복호화 서비스
///  - SealedSenderService.seal(): 수신자 IK로 DR 암호문 봉인 (ephemeral DH → HKDF → XSalsa20-Poly1305)
///  - SealedSenderService.unseal(): 봉인 해제 (리플레이 체크 → DH → HKDF → 복호화 → 인증서 검증)
///  - UnsealedMessage: 봉인 해제 결과 데이터 클래스
///  - _ReplayCache: EK_seal 기반 LRU 리플레이 캐시 (10K 엔트리, 24시간 TTL)

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/x25519.dart' as nacl_api;

import 'hkdf.dart' show hkdfDerive;
import 'logger.dart';
import 'sender_certificate.dart';
import 'x25519.dart';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sealed Sender protocol version.
const int _versionSealedSender = 0x01;

/// Message context: 1:1 direct message.
const int sealedType1to1 = 0x01;

/// Message context: group message.
const int sealedTypeGroup = 0x02;

/// HKDF info string for Sealed Sender key derivation.
final Uint8List _sealedSenderInfo =
    Uint8List.fromList(utf8.encode('SnowChat_SealedSender_v1'));

/// HKDF output length: 32 bytes key + 24 bytes nonce = 56 bytes.
const int _hkdfOutputLength = 56;

/// XSalsa20-Poly1305 key length.
const int _sealKeyLength = 32;

/// XSalsa20-Poly1305 nonce length.
const int _sealNonceLength = 24;

/// Poly1305 authentication tag length.
const int _tagLength = 16;

/// X25519 key length.
const int _x25519KeyLength = 32;

/// Wire format: version (1) + EK_seal (32).
const int _envelopeHeaderLength = 1 + _x25519KeyLength;

/// Minimum total inner payload size (padded).
const int _minInnerPayloadSize = 512;

/// Padding granularity in bytes.
const int _paddingGranularity = 64;

/// Maximum padding bytes.
const int _maxPaddingBytes = 256;

/// Inner payload fixed header: messageContext (1) + certificate (177) +
/// timestamp (8) + drCiphertextLen (4) = 190 bytes.
const int _innerHeaderLength = 1 + senderCertificateLength + 8 + 4;

/// Replay protection: timestamp window (24 hours in milliseconds).
const int _timestampWindowMs = 86400 * 1000;

/// Replay cache: maximum entries.
const int _maxReplayCacheEntries = 10000;

/// Minimum sealed envelope size:
/// header (33) + nonce (24) + inner header (190) + tag (16).
const int _minEnvelopeSize = _envelopeHeaderLength + _sealNonceLength + _innerHeaderLength + _tagLength;

// ---------------------------------------------------------------------------
// UnsealedMessage
// ---------------------------------------------------------------------------

/// Result of successfully unsealing a Sealed Sender envelope.
///
/// Contains the sender's identity (extracted from the verified certificate)
/// and the inner Double Ratchet (or Sender Key) ciphertext ready for the
/// existing decryption pipeline.
class UnsealedMessage {
  /// Sender's SnowChat ID (from certificate).
  final String senderSnowchatId;

  /// Sender's device UUID (from certificate).
  final String senderDeviceId;

  /// Sender's X25519 identity public key (from certificate).
  final Uint8List senderIdentityKey;

  /// Message context: [sealedType1to1] or [sealedTypeGroup].
  final int messageContext;

  /// Sender's local timestamp in milliseconds (from inner payload).
  final int timestampMs;

  /// Double Ratchet or Sender Key ciphertext (to pass into existing pipeline).
  final Uint8List drCiphertext;

  const UnsealedMessage({
    required this.senderSnowchatId,
    required this.senderDeviceId,
    required this.senderIdentityKey,
    required this.messageContext,
    required this.timestampMs,
    required this.drCiphertext,
  });
}

// ---------------------------------------------------------------------------
// Replay Cache
// ---------------------------------------------------------------------------

/// Bounded LRU replay cache keyed by EK_seal (ephemeral public key).
///
/// Each sealed message uses a unique ephemeral keypair. If we see the same
/// EK_seal twice, it is definitionally a replay. Entries are evicted after
/// [_timestampWindowMs] or when the cache exceeds [_maxReplayCacheEntries].
class _ReplayCache {
  /// EK_seal hex → receive timestamp in ms.
  final Map<String, int> _entries = {};

  /// Check if [ekSeal] has been seen before. If not, record it.
  ///
  /// Returns true if this is a DUPLICATE (replay). Returns false if new.
  bool isDuplicate(Uint8List ekSeal) {
    _evictExpired();

    final key = _bytesToHex(ekSeal);
    if (_entries.containsKey(key)) {
      return true;
    }

    // Record this entry.
    _entries[key] = DateTime.now().millisecondsSinceEpoch;

    // Size-based eviction (remove oldest if over limit).
    while (_entries.length > _maxReplayCacheEntries) {
      _entries.remove(_entries.keys.first);
    }

    return false;
  }

  /// Remove entries older than the timestamp window.
  void _evictExpired() {
    final cutoff =
        DateTime.now().millisecondsSinceEpoch - _timestampWindowMs;
    _entries.removeWhere((_, ts) => ts < cutoff);
  }

  static String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}

// ---------------------------------------------------------------------------
// SealedSenderService
// ---------------------------------------------------------------------------

/// Core Sealed Sender cryptographic service.
///
/// Implements the Phase 10.1 algorithm specification:
/// - **seal()**: Wrap a DR/SK ciphertext in an anonymous envelope using
///   ephemeral X25519 DH with the recipient's identity key.
/// - **unseal()**: Decrypt the envelope, verify the sender certificate,
///   and perform replay detection.
///
/// The sealed envelope hides the sender's identity from the server.
/// Only the recipient, who possesses the corresponding X25519 private key,
/// can decrypt and learn who sent the message.
class SealedSenderService {
  /// Server's Ed25519 verify key (hardcoded in client binary).
  ///
  /// Used to verify SenderCertificate signatures during unseal.
  /// This must match the server's signing key.
  final Uint8List serverVerifyKey;

  /// Replay detection cache.
  final _ReplayCache _replayCache = _ReplayCache();

  /// CSPRNG for padding.
  static final _rng = Random.secure();

  SealedSenderService({
    required this.serverVerifyKey,
  });

  // -------------------------------------------------------------------------
  // seal()
  // -------------------------------------------------------------------------

  /// Seal (encrypt) a DR/SK ciphertext into an anonymous envelope.
  ///
  /// Parameters:
  /// - [recipientIdentityPubKey]: Recipient's X25519 identity public key (IK_R)
  /// - [drCiphertext]: Double Ratchet or Sender Key ciphertext
  /// - [certificate]: Sender's valid SenderCertificate
  /// - [messageContext]: [sealedType1to1] or [sealedTypeGroup]
  ///
  /// Returns the sealed envelope bytes ready for base64 encoding and transport.
  ///
  /// The ephemeral private key is zeroed after use (defense in depth).
  Uint8List seal({
    required Uint8List recipientIdentityPubKey,
    required Uint8List drCiphertext,
    required SenderCertificate certificate,
    required int messageContext,
  }) {
    // Step 1: Generate ephemeral X25519 keypair.
    final ephemeral = X25519KeyPair.generate();

    try {
      // Step 2 & 3: Compute DH shared secret with all-zero check.
      // x25519Dh() uses TweetNaCl.crypto_scalarmult() directly and
      // rejects zero output (small-subgroup defense).
      final dhResult = x25519Dh(ephemeral.privateKey, recipientIdentityPubKey);

      // Step 4: HKDF key derivation.
      // salt = IK_R (recipient identity key for per-recipient domain separation)
      // info = "SnowChat_SealedSender_v1"
      // output = 56 bytes (32 key + 24 nonce)
      final okm = hkdfDerive(
        ikm: dhResult,
        salt: recipientIdentityPubKey,
        info: _sealedSenderInfo,
        length: _hkdfOutputLength,
      );

      // Zero DH result immediately after derivation (P0 defense in depth).
      dhResult.fillRange(0, dhResult.length, 0x00);

      final sealKey = Uint8List.sublistView(okm, 0, _sealKeyLength);
      final sealNonce =
          Uint8List.sublistView(okm, _sealKeyLength, _hkdfOutputLength);

      // Step 5: Build inner plaintext with padding.
      final innerPayload = _buildInnerPayload(
        messageContext: messageContext,
        certificate: certificate,
        drCiphertext: drCiphertext,
      );

      // Step 6: XSalsa20-Poly1305 encryption.
      // pinenacl SecretBox.encrypt() returns [nonce(24) || ciphertext+tag].
      // We supply our HKDF-derived nonce explicitly.
      final box = nacl_api.SecretBox(sealKey);
      final encrypted = box.encrypt(innerPayload, nonce: sealNonce);
      final sealedBytes = Uint8List.fromList(encrypted.toList());

      // Zero OKM after extracting key material (defense in depth).
      okm.fillRange(0, okm.length, 0x00);

      // Step 7: Assemble wire format.
      // VERSION (1) || EK_seal (32) || sealed_bytes (nonce + ciphertext + tag)
      final envelope = Uint8List(
        _envelopeHeaderLength + sealedBytes.length,
      );
      envelope[0] = _versionSealedSender;
      envelope.setAll(1, ephemeral.publicKey);
      envelope.setAll(_envelopeHeaderLength, sealedBytes);

      return envelope;
    } finally {
      // Step 8: Zero ephemeral private key (defense in depth).
      ephemeral.privateKey.fillRange(0, _x25519KeyLength, 0x00);
    }
  }

  // -------------------------------------------------------------------------
  // unseal()
  // -------------------------------------------------------------------------

  /// Unseal (decrypt) a Sealed Sender envelope.
  ///
  /// Parameters:
  /// - [myIdentityPrivateKey]: Recipient's X25519 identity private key (ik_R)
  /// - [myIdentityPublicKey]: Recipient's X25519 identity public key (IK_R)
  /// - [sealedEnvelope]: The raw sealed envelope bytes
  ///
  /// Returns an [UnsealedMessage] containing the sender identity and DR ciphertext.
  ///
  /// Throws [StateError] on any verification failure (version, decryption,
  /// certificate, replay, timestamp).
  UnsealedMessage unseal({
    required Uint8List myIdentityPrivateKey,
    required Uint8List myIdentityPublicKey,
    required Uint8List sealedEnvelope,
  }) {
    // Step 1: Parse wire format.
    if (sealedEnvelope.length < _minEnvelopeSize) {
      throw StateError('Sealed message rejected');
    }

    final version = sealedEnvelope[0];
    final ekSeal = Uint8List.sublistView(sealedEnvelope, 1, 1 + _x25519KeyLength);
    final sealedBytes = Uint8List.sublistView(
      sealedEnvelope,
      _envelopeHeaderLength,
    );

    // Step 2: Version check.
    if (version != _versionSealedSender) {
      throw StateError('Sealed message rejected');
    }

    // Step 2b: EK_seal replay check (before DH to avoid CPU waste on replays).
    if (_replayCache.isDuplicate(ekSeal)) {
      throw StateError('Sealed message rejected');
    }

    // Step 3: Compute DH shared secret (mirror of seal Step 2).
    // x25519Dh already checks for all-zero output.
    final dhResult = x25519Dh(myIdentityPrivateKey, ekSeal);

    // Step 4: HKDF key derivation (mirror of seal Step 4).
    final okm = hkdfDerive(
      ikm: dhResult,
      salt: myIdentityPublicKey,
      info: _sealedSenderInfo,
      length: _hkdfOutputLength,
    );

    // Zero DH result immediately after derivation (P0 defense in depth).
    dhResult.fillRange(0, dhResult.length, 0x00);

    final sealKey = Uint8List.sublistView(okm, 0, _sealKeyLength);
    // sealNonce is derived but pinenacl reads it from the message prefix.

    // Step 5: XSalsa20-Poly1305 decryption.
    // sealedBytes = [nonce(24) || ciphertext+tag]
    if (sealedBytes.length <= _sealNonceLength) {
      throw StateError('Sealed message rejected');
    }

    final Uint8List innerPayload;
    try {
      final box = nacl_api.SecretBox(sealKey);
      final decrypted = box.decrypt(
        nacl_api.EncryptedMessage(
          nonce: sealedBytes.sublist(0, _sealNonceLength),
          cipherText: sealedBytes.sublist(_sealNonceLength),
        ),
      );
      innerPayload = Uint8List.fromList(decrypted.toList());
    } catch (e) {
      // Zero OKM on failure path before rethrowing.
      okm.fillRange(0, okm.length, 0x00);
      throw StateError('Sealed message rejected');
    }

    // Zero OKM after extracting key material (defense in depth).
    okm.fillRange(0, okm.length, 0x00);

    // Step 6: Parse inner payload.
    if (innerPayload.length < _innerHeaderLength) {
      throw StateError('Sealed message rejected');
    }

    var offset = 0;

    // messageContext
    final messageContext = innerPayload[offset];
    offset += 1;

    // certificate (177 bytes)
    final certBytes = Uint8List.sublistView(
      innerPayload,
      offset,
      offset + senderCertificateLength,
    );
    offset += senderCertificateLength;

    // timestamp (8 bytes, big-endian uint64 ms)
    final timestampMs = _getUint64BE(innerPayload, offset);
    offset += 8;

    // drCiphertextLen (4 bytes, big-endian uint32)
    final drCiphertextLen = _getUint32BE(innerPayload, offset);
    offset += 4;

    // Validate drCiphertextLen fits within remaining bytes.
    if (offset + drCiphertextLen > innerPayload.length) {
      throw StateError('Sealed message rejected');
    }

    // drCiphertext
    final drCiphertext = Uint8List.sublistView(
      innerPayload,
      offset,
      offset + drCiphertextLen,
    );
    // Remaining bytes are padding -- discard.

    // Step 7: Replay protection.
    // 7a. Timestamp window check.
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    if ((nowMs - timestampMs).abs() > _timestampWindowMs) {
      throw StateError('Sealed message rejected');
    }

    // Note: EK_seal replay check already performed at Step 2b (before DH).

    // Step 8: Verify Sender Certificate.
    // Wrap in try/catch to prevent certificate-specific error messages
    // from leaking information (oracle attack prevention).
    final SenderCertificate certificate;
    try {
      certificate = SenderCertificate.fromBytes(certBytes);
      certificate.verify(serverVerifyKey);
    } catch (_) {
      throw StateError('Sealed message rejected');
    }

    // Step 9: Identity key cross-check is done by the caller after DR decrypt,
    // because the caller has access to the session store. We return the
    // certificate's identity key so the caller can perform the check.

    // Step 10: Return unsealed message.
    return UnsealedMessage(
      senderSnowchatId: certificate.senderSnowchatId,
      senderDeviceId: certificate.senderDeviceId,
      senderIdentityKey: certificate.senderIdentityKey,
      messageContext: messageContext,
      timestampMs: timestampMs,
      drCiphertext: drCiphertext,
    );
  }

  // -------------------------------------------------------------------------
  // Inner payload construction
  // -------------------------------------------------------------------------

  /// Build the inner plaintext payload with padding.
  ///
  /// Layout:
  /// ```
  /// messageContext (1) | certificate (177) | timestamp (8) |
  /// drCiphertextLen (4) | drCiphertext (N) | padding (P)
  /// ```
  Uint8List _buildInnerPayload({
    required int messageContext,
    required SenderCertificate certificate,
    required Uint8List drCiphertext,
  }) {
    final rawLen = _innerHeaderLength + drCiphertext.length;

    // Padding: round up to next 64-byte boundary, minimum 512 bytes.
    // The 512-byte minimum is unconditional -- never cap padding below it.
    final alignedLen = ((max(rawLen, _minInnerPayloadSize) +
            _paddingGranularity - 1) ~/
            _paddingGranularity) *
        _paddingGranularity;

    var paddingLen = alignedLen - rawLen;

    // Only apply padding cap when above the minimum size floor.
    // This guarantees _minInnerPayloadSize is always met.
    if (alignedLen > _minInnerPayloadSize && paddingLen > _maxPaddingBytes) {
      paddingLen = _maxPaddingBytes;
    }

    final totalLen = rawLen + paddingLen;
    final buffer = Uint8List(totalLen);
    var offset = 0;

    // messageContext (1 byte)
    buffer[offset] = messageContext;
    offset += 1;

    // certificate (177 bytes)
    buffer.setAll(offset, certificate.toBytes());
    offset += senderCertificateLength;

    // timestamp (8 bytes, big-endian uint64 ms)
    _putUint64BE(buffer, offset, DateTime.now().millisecondsSinceEpoch);
    offset += 8;

    // drCiphertextLen (4 bytes, big-endian uint32)
    _putUint32BE(buffer, offset, drCiphertext.length);
    offset += 4;

    // drCiphertext (N bytes)
    buffer.setAll(offset, drCiphertext);
    offset += drCiphertext.length;

    // padding (random bytes -- not zeros, to resist compression side-channels)
    for (var i = offset; i < totalLen; i++) {
      buffer[i] = _rng.nextInt(256);
    }

    return buffer;
  }

  // -------------------------------------------------------------------------
  // Binary helpers
  // -------------------------------------------------------------------------

  static void _putUint64BE(Uint8List buffer, int offset, int value) {
    buffer[offset] = (value >> 56) & 0xFF;
    buffer[offset + 1] = (value >> 48) & 0xFF;
    buffer[offset + 2] = (value >> 40) & 0xFF;
    buffer[offset + 3] = (value >> 32) & 0xFF;
    buffer[offset + 4] = (value >> 24) & 0xFF;
    buffer[offset + 5] = (value >> 16) & 0xFF;
    buffer[offset + 6] = (value >> 8) & 0xFF;
    buffer[offset + 7] = value & 0xFF;
  }

  static int _getUint64BE(Uint8List buffer, int offset) {
    return (buffer[offset] << 56) |
        (buffer[offset + 1] << 48) |
        (buffer[offset + 2] << 40) |
        (buffer[offset + 3] << 32) |
        (buffer[offset + 4] << 24) |
        (buffer[offset + 5] << 16) |
        (buffer[offset + 6] << 8) |
        buffer[offset + 7];
  }

  static void _putUint32BE(Uint8List buffer, int offset, int value) {
    buffer[offset] = (value >> 24) & 0xFF;
    buffer[offset + 1] = (value >> 16) & 0xFF;
    buffer[offset + 2] = (value >> 8) & 0xFF;
    buffer[offset + 3] = value & 0xFF;
  }

  static int _getUint32BE(Uint8List buffer, int offset) {
    return (buffer[offset] << 24) |
        (buffer[offset + 1] << 16) |
        (buffer[offset + 2] << 8) |
        buffer[offset + 3];
  }
}
