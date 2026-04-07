/// @file        double_ratchet.dart
/// @description Double Ratchet 알고리즘 구현. 메시지별 전방향/후방향 비밀성 보장
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-03-30
///
/// @functions
///  - EncryptedMessage: 암호화된 메시지 데이터 클래스 (암호문 + 래칫 키 + 메시지 번호)
///  - DoubleRatchetSession: Double Ratchet 세션 상태 및 암복호화 클래스
///  - DoubleRatchetSession.initSender(): X3DH 공유 비밀로 송신자 세션 초기화
///  - DoubleRatchetSession.initReceiver(): X3DH 공유 비밀로 수신자 세션 초기화
///  - DoubleRatchetSession.encrypt(): 평문을 암호화하여 EncryptedMessage 반환
///  - DoubleRatchetSession.decrypt(): EncryptedMessage를 복호화하여 평문 반환
///  - DoubleRatchetSession.toJson(): 세션 상태 직렬화
///  - DoubleRatchetSession.fromJson(): 세션 상태 역직렬화

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/x25519.dart' as nacl_api;

import 'hkdf.dart';
import 'x25519.dart';

/// Maximum number of skipped message keys to store (per the E2EE protocol doc).
const int maxSkippedKeys = 500;

/// Info strings for HKDF domain separation.
final Uint8List _rkInfo = Uint8List.fromList(utf8.encode('SnowChat_Ratchet'));
final Uint8List _mkInfo = Uint8List.fromList(utf8.encode('SnowChat_MsgKey'));

// ---------------------------------------------------------------------------
// EncryptedMessage
// ---------------------------------------------------------------------------

/// A message encrypted by the Double Ratchet.
class EncryptedMessage {
  /// Encrypted ciphertext (includes 24-byte nonce prefix for XSalsa20-Poly1305).
  final Uint8List ciphertext;

  /// Sender's current DH ratchet public key.
  final Uint8List ratchetPublicKey;

  /// Message number in the current sending chain.
  final int messageNumber;

  /// Length of the previous sending chain (for skipped key calculation).
  final int previousChainLength;

  const EncryptedMessage({
    required this.ciphertext,
    required this.ratchetPublicKey,
    required this.messageNumber,
    required this.previousChainLength,
  });

  /// Serialize header fields to bytes for AEAD Associated Data binding.
  /// Format: ratchetPublicKey (32B) || messageNumber (4B BE) || prevChainLen (4B BE)
  Uint8List serializeHeader() {
    final header = Uint8List(32 + 4 + 4);
    header.setAll(0, ratchetPublicKey);
    header[32] = (messageNumber >> 24) & 0xFF;
    header[33] = (messageNumber >> 16) & 0xFF;
    header[34] = (messageNumber >> 8) & 0xFF;
    header[35] = messageNumber & 0xFF;
    header[36] = (previousChainLength >> 24) & 0xFF;
    header[37] = (previousChainLength >> 16) & 0xFF;
    header[38] = (previousChainLength >> 8) & 0xFF;
    header[39] = previousChainLength & 0xFF;
    return header;
  }

  /// Serialize to JSON-compatible map (keys hex-encoded).
  Map<String, dynamic> toJson() => {
        'ciphertext': _bytesToHex(ciphertext),
        'ratchetPublicKey': _bytesToHex(ratchetPublicKey),
        'messageNumber': messageNumber,
        'previousChainLength': previousChainLength,
      };

  /// Deserialize from JSON map.
  factory EncryptedMessage.fromJson(Map<String, dynamic> json) {
    return EncryptedMessage(
      ciphertext: _hexToBytes(json['ciphertext'] as String),
      ratchetPublicKey: _hexToBytes(json['ratchetPublicKey'] as String),
      messageNumber: json['messageNumber'] as int,
      previousChainLength: json['previousChainLength'] as int,
    );
  }
}

// ---------------------------------------------------------------------------
// Key for skipped messages
// ---------------------------------------------------------------------------

/// Composite key for the skipped-messages map: (ratchetPublicKey, messageNumber).
class _SkippedKey {
  final String ratchetKeyHex;
  final int messageNumber;

  _SkippedKey(this.ratchetKeyHex, this.messageNumber);

  String get mapKey => '$ratchetKeyHex:$messageNumber';
}

// ---------------------------------------------------------------------------
// DoubleRatchetSession
// ---------------------------------------------------------------------------

/// Double Ratchet session state, implementing symmetric-key ratchet and
/// DH ratchet per the Signal specification.
///
/// Encryption uses XSalsa20-Poly1305 (pinenacl's SecretBox) which provides
/// AEAD semantics equivalent to AES-256-GCM in security properties.
class DoubleRatchetSession {
  /// Root key — updated on each DH ratchet step.
  Uint8List rootKey;

  /// Current sending chain key.
  Uint8List? sendingChainKey;

  /// Current receiving chain key.
  Uint8List? receivingChainKey;

  /// Our current DH ratchet key pair (private).
  Uint8List sendingRatchetPrivate;

  /// Our current DH ratchet public key.
  Uint8List sendingRatchetPublic;

  /// Their current DH ratchet public key.
  Uint8List? remoteRatchetKey;

  /// Number of messages sent in the current sending chain.
  int sendMessageNumber;

  /// Number of messages received in the current receiving chain.
  int receiveMessageNumber;

  /// Previous sending chain length (sent in message headers).
  int previousSendChainLength;

  /// Skipped message keys for out-of-order delivery.
  /// Key: "ratchetKeyHex:messageNumber", Value: hex-encoded message key.
  final Map<String, String> skippedKeys;

  DoubleRatchetSession._({
    required this.rootKey,
    this.sendingChainKey,
    this.receivingChainKey,
    required this.sendingRatchetPrivate,
    required this.sendingRatchetPublic,
    this.remoteRatchetKey,
    this.sendMessageNumber = 0,
    this.receiveMessageNumber = 0,
    this.previousSendChainLength = 0,
    Map<String, String>? skippedKeys,
  }) : skippedKeys = skippedKeys ?? {};

  /// Initialize a session for the initiator (Alice) after X3DH.
  ///
  /// [sharedSecret] — 32-byte SK from X3DH.
  /// [remoteRatchetKey] — Bob's signed prekey (used as initial ratchet key).
  factory DoubleRatchetSession.initSender(
    Uint8List sharedSecret,
    Uint8List remoteRatchetKey,
  ) {
    // Generate our first sending ratchet key pair
    final sendingKp = X25519KeyPair.generate();

    // Perform initial DH ratchet step
    final dhOutput = x25519Dh(sendingKp.privateKey, remoteRatchetKey);
    final derived = _kdfRk(sharedSecret, dhOutput);

    return DoubleRatchetSession._(
      rootKey: derived.rootKey,
      sendingChainKey: derived.chainKey,
      receivingChainKey: null,
      sendingRatchetPrivate: sendingKp.privateKey,
      sendingRatchetPublic: sendingKp.publicKey,
      remoteRatchetKey: Uint8List.fromList(remoteRatchetKey),
      sendMessageNumber: 0,
      receiveMessageNumber: 0,
      previousSendChainLength: 0,
    );
  }

  /// Initialize a session for the receiver (Bob) after X3DH.
  ///
  /// [sharedSecret] — 32-byte SK from X3DH.
  /// [ratchetKeyPrivate] — Bob's signed prekey private (used as initial ratchet).
  /// [ratchetKeyPublic] — Bob's signed prekey public.
  factory DoubleRatchetSession.initReceiver(
    Uint8List sharedSecret,
    Uint8List ratchetKeyPrivate,
    Uint8List ratchetKeyPublic,
  ) {
    return DoubleRatchetSession._(
      rootKey: sharedSecret,
      sendingChainKey: null,
      receivingChainKey: null,
      sendingRatchetPrivate: ratchetKeyPrivate,
      sendingRatchetPublic: ratchetKeyPublic,
      remoteRatchetKey: null,
      sendMessageNumber: 0,
      receiveMessageNumber: 0,
      previousSendChainLength: 0,
    );
  }

  // ---------------------------------------------------------------------------
  // Encrypt
  // ---------------------------------------------------------------------------

  /// Encrypt [plaintext] and advance the sending chain.
  EncryptedMessage encrypt(Uint8List plaintext) {
    if (sendingChainKey == null) {
      throw StateError(
        'Sending chain not initialized. Receiver must decrypt first.',
      );
    }

    // Derive message key from chain key
    final ckResult = _kdfCk(sendingChainKey!);
    sendingChainKey = ckResult.chainKey;
    final messageKey = ckResult.messageKey;

    final msgNum = sendMessageNumber;
    sendMessageNumber++;

    // Build header bytes for AD binding
    final headerMsg = EncryptedMessage(
      ciphertext: Uint8List(0), // placeholder
      ratchetPublicKey: Uint8List.fromList(sendingRatchetPublic),
      messageNumber: msgNum,
      previousChainLength: previousSendChainLength,
    );
    final headerBytes = headerMsg.serializeHeader();

    // Encrypt with XSalsa20-Poly1305 + header bound as AD
    final ciphertext = _encrypt(messageKey, plaintext, header: headerBytes);

    return EncryptedMessage(
      ciphertext: ciphertext,
      ratchetPublicKey: Uint8List.fromList(sendingRatchetPublic),
      messageNumber: msgNum,
      previousChainLength: previousSendChainLength,
    );
  }

  // ---------------------------------------------------------------------------
  // Decrypt
  // ---------------------------------------------------------------------------

  /// Decrypt an [EncryptedMessage] and advance the receiving chain.
  ///
  /// Handles DH ratchet steps and out-of-order messages.
  Uint8List decrypt(EncryptedMessage message) {
    // Build header bytes for AD verification
    final headerBytes = message.serializeHeader();

    // 1. Check skipped keys first
    final skipKey =
        '${_bytesToHex(message.ratchetPublicKey)}:${message.messageNumber}';
    if (skippedKeys.containsKey(skipKey)) {
      final mk = _hexToBytes(skippedKeys.remove(skipKey)!);
      return _decrypt(mk, message.ciphertext, header: headerBytes);
    }

    // 2. If the ratchet public key changed, perform a DH ratchet step
    if (remoteRatchetKey == null ||
        !_bytesEqual(message.ratchetPublicKey, remoteRatchetKey!)) {
      // Skip any remaining messages in the current receiving chain
      _skipMessageKeys(
        message.ratchetPublicKey,
        message.previousChainLength,
      );

      // DH Ratchet step
      _dhRatchet(message.ratchetPublicKey);
    }

    // 3. Skip ahead if needed in the current receiving chain
    _skipMessageKeys(
      message.ratchetPublicKey,
      message.messageNumber,
    );

    // 4. Derive the message key
    if (receivingChainKey == null) {
      throw StateError('Receiving chain key is null after ratchet step');
    }
    final ckResult = _kdfCk(receivingChainKey!);
    receivingChainKey = ckResult.chainKey;
    final messageKey = ckResult.messageKey;
    receiveMessageNumber++;

    return _decrypt(messageKey, message.ciphertext, header: headerBytes);
  }

  // ---------------------------------------------------------------------------
  // DH Ratchet
  // ---------------------------------------------------------------------------

  void _dhRatchet(Uint8List newRemoteRatchetKey) {
    previousSendChainLength = sendMessageNumber;
    sendMessageNumber = 0;
    receiveMessageNumber = 0;
    remoteRatchetKey = Uint8List.fromList(newRemoteRatchetKey);

    // Receiving chain: DH(our current private, their new public)
    final dhRecv = x25519Dh(sendingRatchetPrivate, newRemoteRatchetKey);
    final recvDerived = _kdfRk(rootKey, dhRecv);
    rootKey = recvDerived.rootKey;
    receivingChainKey = recvDerived.chainKey;

    // Generate new sending ratchet key pair
    final newKp = X25519KeyPair.generate();
    sendingRatchetPrivate = newKp.privateKey;
    sendingRatchetPublic = newKp.publicKey;

    // Sending chain: DH(our new private, their public)
    final dhSend = x25519Dh(newKp.privateKey, newRemoteRatchetKey);
    final sendDerived = _kdfRk(rootKey, dhSend);
    rootKey = sendDerived.rootKey;
    sendingChainKey = sendDerived.chainKey;
  }

  // ---------------------------------------------------------------------------
  // Skipped keys
  // ---------------------------------------------------------------------------

  void _skipMessageKeys(Uint8List ratchetKey, int until) {
    if (receivingChainKey == null) return;

    if (until - receiveMessageNumber > maxSkippedKeys) {
      throw StateError(
        'Too many skipped messages '
        '(${until - receiveMessageNumber} > $maxSkippedKeys)',
      );
    }

    while (receiveMessageNumber < until) {
      final ckResult = _kdfCk(receivingChainKey!);
      receivingChainKey = ckResult.chainKey;
      final key = _SkippedKey(
        _bytesToHex(ratchetKey),
        receiveMessageNumber,
      );
      skippedKeys[key.mapKey] = _bytesToHex(ckResult.messageKey);
      receiveMessageNumber++;

      // Enforce max skipped keys limit
      if (skippedKeys.length > maxSkippedKeys) {
        // Remove oldest entry (first key in insertion order)
        skippedKeys.remove(skippedKeys.keys.first);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Serialization
  // ---------------------------------------------------------------------------

  /// Serialize session state to a JSON-compatible map.
  /// PreKey session metadata (persisted for first message serialization).
  bool isPreKeySession = false;
  Uint8List? ephemeralPublicKey;
  int? preKeySignedPreKeyId;
  int? preKeyOneTimePreKeyId;

  Map<String, dynamic> toJson() => {
        'rootKey': _bytesToHex(rootKey),
        'sendingChainKey':
            sendingChainKey != null ? _bytesToHex(sendingChainKey!) : null,
        'receivingChainKey':
            receivingChainKey != null ? _bytesToHex(receivingChainKey!) : null,
        'sendingRatchetPrivate': _bytesToHex(sendingRatchetPrivate),
        'sendingRatchetPublic': _bytesToHex(sendingRatchetPublic),
        'remoteRatchetKey':
            remoteRatchetKey != null ? _bytesToHex(remoteRatchetKey!) : null,
        'sendMessageNumber': sendMessageNumber,
        'receiveMessageNumber': receiveMessageNumber,
        'previousSendChainLength': previousSendChainLength,
        'skippedKeys': skippedKeys,
        'isPreKeySession': isPreKeySession,
        if (ephemeralPublicKey != null)
          'ephemeralPublicKey': _bytesToHex(ephemeralPublicKey!),
        if (preKeySignedPreKeyId != null)
          'preKeySignedPreKeyId': preKeySignedPreKeyId,
        if (preKeyOneTimePreKeyId != null)
          'preKeyOneTimePreKeyId': preKeyOneTimePreKeyId,
      };

  /// Deserialize session state from a JSON map.
  factory DoubleRatchetSession.fromJson(Map<String, dynamic> json) {
    return DoubleRatchetSession._(
      rootKey: _hexToBytes(json['rootKey'] as String),
      sendingChainKey: json['sendingChainKey'] != null
          ? _hexToBytes(json['sendingChainKey'] as String)
          : null,
      receivingChainKey: json['receivingChainKey'] != null
          ? _hexToBytes(json['receivingChainKey'] as String)
          : null,
      sendingRatchetPrivate:
          _hexToBytes(json['sendingRatchetPrivate'] as String),
      sendingRatchetPublic:
          _hexToBytes(json['sendingRatchetPublic'] as String),
      remoteRatchetKey: json['remoteRatchetKey'] != null
          ? _hexToBytes(json['remoteRatchetKey'] as String)
          : null,
      sendMessageNumber: json['sendMessageNumber'] as int,
      receiveMessageNumber: json['receiveMessageNumber'] as int,
      previousSendChainLength: json['previousSendChainLength'] as int,
      skippedKeys:
          Map<String, String>.from(json['skippedKeys'] as Map? ?? {}),
    )
      ..isPreKeySession = json['isPreKeySession'] as bool? ?? false
      ..ephemeralPublicKey = json['ephemeralPublicKey'] != null
          ? _hexToBytes(json['ephemeralPublicKey'] as String)
          : null
      ..preKeySignedPreKeyId = json['preKeySignedPreKeyId'] as int?
      ..preKeyOneTimePreKeyId = json['preKeyOneTimePreKeyId'] as int?;
  }
}

// =============================================================================
// KDF functions
// =============================================================================

class _RkResult {
  final Uint8List rootKey;
  final Uint8List chainKey;
  _RkResult(this.rootKey, this.chainKey);
}

class _CkResult {
  final Uint8List chainKey;
  final Uint8List messageKey;
  _CkResult(this.chainKey, this.messageKey);
}

/// KDF_RK: Derive new root key and chain key from current root key and DH output.
_RkResult _kdfRk(Uint8List rootKey, Uint8List dhOutput) {
  final derived = hkdfDerive(
    ikm: dhOutput,
    salt: rootKey,
    info: _rkInfo,
    length: 64,
  );
  return _RkResult(
    Uint8List.sublistView(derived, 0, 32),
    Uint8List.sublistView(derived, 32, 64),
  );
}

/// KDF_CK: Derive new chain key and message key from current chain key.
///
/// Uses HMAC-SHA256 with different constants:
/// - chainKey  = HMAC(ck, 0x02)
/// - messageKey = HMAC(ck, 0x01)
_CkResult _kdfCk(Uint8List chainKey) {
  final messageKey = hmacSha256(chainKey, Uint8List.fromList([0x01]));
  final newChainKey = hmacSha256(chainKey, Uint8List.fromList([0x02]));
  return _CkResult(newChainKey, messageKey);
}

// =============================================================================
// Symmetric encryption (XSalsa20-Poly1305 via pinenacl SecretBox)
// =============================================================================

final _rng = Random.secure();

/// Encrypt [plaintext] with [messageKey] using XSalsa20-Poly1305.
/// [header] is prepended to plaintext before encryption to bind it
/// as Associated Data (AD). Signal spec requires header authentication
/// to prevent header manipulation attacks.
/// Returns nonce (24 bytes) || ciphertext+tag.
Uint8List _encrypt(Uint8List messageKey, Uint8List plaintext,
    {Uint8List? header}) {
  final box = nacl_api.SecretBox(messageKey);
  final nonce = Uint8List(nacl_api.EncryptedMessage.nonceLength);
  for (var i = 0; i < nonce.length; i++) {
    nonce[i] = _rng.nextInt(256);
  }
  // Bind header as AD by prepending: [4-byte header length][header][plaintext]
  // XSalsa20-Poly1305 doesn't support AD natively, so we include it in plaintext
  Uint8List payload;
  if (header != null) {
    payload = Uint8List(4 + header.length + plaintext.length);
    final hLen = header.length;
    payload[0] = (hLen >> 24) & 0xFF;
    payload[1] = (hLen >> 16) & 0xFF;
    payload[2] = (hLen >> 8) & 0xFF;
    payload[3] = hLen & 0xFF;
    payload.setAll(4, header);
    payload.setAll(4 + header.length, plaintext);
  } else {
    payload = plaintext;
  }
  final encrypted = box.encrypt(payload, nonce: nonce);
  // encrypted includes nonce prefix already in pinenacl
  return Uint8List.fromList(encrypted.toList());
}

/// Decrypt [ciphertextWithNonce] with [messageKey] using XSalsa20-Poly1305.
/// If [header] is provided, verifies it matches the header bound during encryption.
Uint8List _decrypt(Uint8List messageKey, Uint8List ciphertextWithNonce,
    {Uint8List? header}) {
  final box = nacl_api.SecretBox(messageKey);
  final decrypted = box.decrypt(
    nacl_api.EncryptedMessage(
      nonce: ciphertextWithNonce.sublist(0, nacl_api.EncryptedMessage.nonceLength),
      cipherText: ciphertextWithNonce.sublist(nacl_api.EncryptedMessage.nonceLength),
    ),
  );
  final raw = Uint8List.fromList(decrypted.toList());
  // Strip and verify bound header
  if (header != null) {
    if (raw.length <= 4) {
      throw StateError('Double Ratchet: payload too short for header binding');
    }
    final hLen = (raw[0] << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3];
    if (hLen != header.length || raw.length < 4 + hLen) {
      throw StateError('Double Ratchet: header length mismatch — tampered');
    }
    // Constant-time header verification (no timing leak)
    var diff = 0;
    for (var i = 0; i < hLen; i++) {
      diff |= raw[4 + i] ^ header[i];
    }
    if (diff != 0) {
      throw StateError('Double Ratchet header mismatch — message tampered');
    }
    return raw.sublist(4 + hLen);
  }
  return raw;
}

// =============================================================================
// Utility
// =============================================================================

String _bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Uint8List _hexToBytes(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}
