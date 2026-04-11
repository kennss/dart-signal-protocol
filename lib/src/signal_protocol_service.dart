/// @file        signal_protocol_service.dart
/// @description Signal Protocol 순수 Dart 구현체. X3DH, Double Ratchet, Sender Key, PreKey 관리를 pinenacl 기반으로 구현
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-29
/// @lastUpdated 2026-04-12
///
/// @functions
///  - SignalProtocolService: Signal Protocol 순수 Dart 구현 클래스
///  - SignalProtocolService.generateIdentityKeyPair(): X25519 ID 키쌍 생성
///  - SignalProtocolService.generateSignedPreKey(): 서명된 프리키 생성
///  - SignalProtocolService.generateOneTimePreKeys(): 일회용 프리키 배치 생성
///  - SignalProtocolService.getPreKeyBundle(): 서버 업로드용 PreKey 번들 조회
///  - SignalProtocolService.createSession(): X3DH로 새 세션 생성
///  - SignalProtocolService.hasSession(): 세션 존재 여부 확인
///  - SignalProtocolService.deleteSession(): 세션 삭제
///  - SignalProtocolService.encryptMessage(): Double Ratchet 메시지 암호화
///  - SignalProtocolService.decryptMessage(): Double Ratchet 메시지 복호화
///  - SignalProtocolService.createSenderKey(): 그룹용 Sender Key 생성
///  - SignalProtocolService.processSenderKey(): 그룹 Sender Key 처리
///  - SignalProtocolService.encryptGroupMessage(): 그룹 메시지 암호화
///  - SignalProtocolService.decryptGroupMessage(): 그룹 메시지 복호화
///  - SignalProtocolService.saveSessionStore(): 세션 상태 JSON 직렬화 저장
///  - SignalProtocolService.loadSessionStore(): 세션 상태 JSON 역직렬화 로드
///  - SignalProtocolException: Signal Protocol 예외 클래스

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;
import 'logger.dart';
import 'package:pinenacl/x25519.dart' as nacl_api;

import 'double_ratchet.dart';
import 'prekey_bundle.dart';
import 'message_send_log.dart';
import 'sender_key.dart';
import 'sender_key_tracker.dart';
import 'x25519.dart';
import 'x3dh.dart';

/// Pure-Dart implementation of the Signal Protocol, replacing the
/// previous Platform Channel / native bridge approach.
///
/// Uses pinenacl for all cryptographic primitives:
/// - X25519 for Diffie-Hellman key exchange
/// - Ed25519 for signing prekeys
/// - XSalsa20-Poly1305 for message encryption (via Double Ratchet)
/// - HMAC-SHA256 HKDF for key derivation
class SignalProtocolService {
  /// In-memory store of active Double Ratchet sessions.
  /// Key: "recipientId:deviceId"
  final Map<String, DoubleRatchetSession> _sessions = {};

  /// Local identity key pair (X25519).
  X25519KeyPair? _identityKeyPair;

  /// Whether an identity key pair has been loaded or generated.
  bool get hasIdentityKey => _identityKeyPair != null;

  /// X25519 identity public key (for comparison).
  Uint8List? get identityPublicKey =>
      _identityKeyPair != null ? Uint8List.fromList(_identityKeyPair!.publicKey) : null;

  /// Access Ed25519 signing seed (for secure storage backup).
  Uint8List? get signingKeySeed => _identitySigningKeySeed;

  /// Access Ed25519 verify key (for secure storage backup).
  Uint8List? get verifyKey => _identityVerifyKey;

  /// Access registration ID (for secure storage backup).
  int? get registrationId => _registrationId;

  /// Restore identity key pair from external storage (secure storage).
  void setIdentityKeyPair(Uint8List publicKey, Uint8List privateKey) {
    _identityKeyPair = X25519KeyPair(
      publicKey: publicKey,
      privateKey: privateKey,
    );
  }

  /// Restore registration ID from external storage.
  void setRegistrationId(int id) {
    _registrationId = id;
  }

  /// Clear all sessions (but keep PreKeys for incoming prekey messages).
  /// Called when identity keys change and all sessions become invalid.
  void clearAllSessions() {
    _sessions.clear();
    // Do NOT clear _signedPreKeys and _oneTimePreKeys — they are needed
    // by _receiveSession() to process incoming prekey messages.
    _senderKeyManager = SenderKeyManager();
    // Phase 6: also reset the in-memory SKDM tracker so the next group send
    // re-distributes to all members.
    _skdmTracker = SenderKeyDistributionTracker();
    debugPrint('[SignalProtocolService] All sessions cleared (prekeys kept)');
  }

  /// Generate Ed25519 signing key ONLY if missing. Does NOT touch _identityKeyPair.
  void generateSigningKeyIfMissing() {
    if (_identitySigningKeySeed != null) return;
    final signingKey = ed.SigningKey.generate();
    _identitySigningKeySeed = Uint8List.fromList(signingKey.seed);
    _identityVerifyKey = Uint8List.fromList(signingKey.verifyKey.toList());
    _registrationId ??= _rng.nextInt(0xFFFF);
  }

  /// Ed25519 identity key seed (for signing prekeys).
  Uint8List? _identitySigningKeySeed;

  /// Ed25519 identity public key (for prekey bundle).
  Uint8List? _identityVerifyKey;

  /// Generated signed prekeys (private keys kept for session establishment).
  final Map<int, SignedPreKey> _signedPreKeys = {};

  /// Generated one-time prekeys (private keys kept for session establishment).
  final Map<int, OneTimePreKey> _oneTimePreKeys = {};

  /// Registration ID for this device.
  int? _registrationId;

  /// Group sender key manager (full Sender Key protocol).
  SenderKeyManager _senderKeyManager = SenderKeyManager();

  /// SKDM distribution tracker (Phase 5.2) — tracks which members have
  /// received the current Sender Key to avoid redundant O(N) re-sends.
  SenderKeyDistributionTracker _skdmTracker = SenderKeyDistributionTracker();
  SenderKeyDistributionTracker get skdmTracker => _skdmTracker;

  /// Message send log for retry requests (Phase 5.2).
  MessageSendLog _messageSendLog = MessageSendLog();
  MessageSendLog get messageSendLog => _messageSendLog;

  /// Random generator for registration IDs.
  static final _rng = Random.secure();

  SignalProtocolService({bool? useMockFallback});

  // ---------------------------------------------------------------------------
  // Key Management
  // ---------------------------------------------------------------------------

  /// Generate a new X25519 identity key pair.
  /// Also generates an Ed25519 signing key for prekey signatures.
  ///
  /// Returns { 'publicKey': Uint8List, 'privateKey': Uint8List }.
  Future<Map<String, dynamic>> generateIdentityKeyPair() async {
    _identityKeyPair = X25519KeyPair.generate();
    _registrationId ??= _rng.nextInt(0xFFFF);

    // Also generate an Ed25519 key pair for signing prekeys.
    // In production, this would be the user's identity Ed25519 key from
    // key_derivation.dart — but for the Signal layer we generate a fresh one.
    // The caller (IdentityManager) can override with setSigningKey().
    if (_identitySigningKeySeed == null) {
      final signingKey = ed.SigningKey.generate();
      _identitySigningKeySeed = Uint8List.fromList(signingKey.seed);
      _identityVerifyKey =
          Uint8List.fromList(signingKey.verifyKey.toList());
    }

    return {
      'publicKey': Uint8List.fromList(_identityKeyPair!.publicKey),
      'privateKey': Uint8List.fromList(_identityKeyPair!.privateKey),
    };
  }

  /// Set the Ed25519 signing key seed from the user's identity (from KeyDerivation).
  /// Call this after identity creation to link the Signal keys to the user identity.
  void setSigningKey(Uint8List ed25519Seed, Uint8List ed25519PublicKey) {
    _identitySigningKeySeed = Uint8List.fromList(ed25519Seed);
    _identityVerifyKey = Uint8List.fromList(ed25519PublicKey);
  }

  /// Generate a signed pre-key with the given [keyId].
  /// Returns { 'keyId': int, 'publicKey': Uint8List, 'signature': Uint8List }.
  Future<Map<String, dynamic>> generateSignedPreKey(int keyId) async {
    _ensureIdentity();

    final spk = PreKeyGenerator.generateSignedPreKey(
      keyId,
      _identitySigningKeySeed!,
    );
    _signedPreKeys[keyId] = spk;

    return {
      'keyId': keyId,
      'publicKey': Uint8List.fromList(spk.publicKey),
      'signature': Uint8List.fromList(spk.signature),
    };
  }

  /// Generate a batch of one-time pre-keys starting from [startId].
  /// Returns a list of { 'keyId': int, 'publicKey': Uint8List }.
  Future<List<Map<String, dynamic>>> generateOneTimePreKeys(
    int startId,
    int count,
  ) async {
    final opks = PreKeyGenerator.generateOneTimePreKeys(startId, count);

    final result = <Map<String, dynamic>>[];
    for (final opk in opks) {
      _oneTimePreKeys[opk.keyId] = opk;
      result.add({
        'keyId': opk.keyId,
        'publicKey': Uint8List.fromList(opk.publicKey),
      });
    }
    return result;
  }

  /// Build a PreKey bundle suitable for uploading to the server.
  Future<Map<String, dynamic>> getPreKeyBundle() async {
    _ensureIdentity();

    // Use the latest signed prekey
    final latestSpk = _signedPreKeys.values.isNotEmpty
        ? _signedPreKeys.values.last
        : null;

    if (latestSpk == null) {
      throw SignalProtocolException(
        'No signed prekey available. Call generateSignedPreKey() first.',
      );
    }

    return {
      'identityKey': Uint8List.fromList(_identityKeyPair!.publicKey),
      'identityKeyEd25519': _identityVerifyKey != null
          ? Uint8List.fromList(_identityVerifyKey!)
          : null,
      'signedPreKey': {
        'keyId': latestSpk.keyId,
        'publicKey': Uint8List.fromList(latestSpk.publicKey),
        'signature': Uint8List.fromList(latestSpk.signature),
      },
      'registrationId': _registrationId,
    };
  }

  // ---------------------------------------------------------------------------
  // Session Management (X3DH)
  // ---------------------------------------------------------------------------

  /// Create a new session with [recipientId]:[deviceId] using the
  /// provided [preKeyBundle] fetched from the server.
  ///
  /// Performs X3DH as the initiator (Alice).
  Future<void> createSession({
    required String recipientId,
    required String deviceId,
    required Map<String, dynamic> preKeyBundle,
  }) async {
    assert(recipientId.isNotEmpty, 'recipientId must not be empty');
    assert(deviceId.isNotEmpty, 'deviceId must not be empty');
    _ensureIdentity();

    final sessionKey = '$recipientId:$deviceId';

    // Extract keys from prekey bundle
    final remoteIdentityKey = preKeyBundle['identityKey'] as Uint8List;
    final signedPreKeyData =
        preKeyBundle['signedPreKey'] as Map<String, dynamic>;
    final remoteSignedPreKey = signedPreKeyData['publicKey'] as Uint8List;
    final signedPreKeySignature = signedPreKeyData['signature'] as Uint8List;

    // H-1 FIX: Fail-closed — Ed25519 identity key is REQUIRED for signed
    // prekey signature verification. Without it, a MITM can inject a fake
    // signed prekey undetected (fail-open vulnerability).
    final remoteIdentityKeyEd25519 =
        preKeyBundle['identityKeyEd25519'] as Uint8List?;
    if (remoteIdentityKeyEd25519 == null) {
      throw SignalProtocolException(
        'PreKey bundle missing Ed25519 identity key — '
        'cannot verify signed prekey signature for $sessionKey. '
        'Refusing session to prevent MITM attack.',
      );
    }
    final bundle = PreKeyBundle(
      identityKey: remoteIdentityKey,
      signedPreKey: remoteSignedPreKey,
      signedPreKeySignature: signedPreKeySignature,
      signedPreKeyId: signedPreKeyData['keyId'] as int,
      registrationId: preKeyBundle['registrationId'] as int? ?? 0,
    );
    if (!bundle.verifySignature(remoteIdentityKeyEd25519)) {
      throw SignalProtocolException(
        'Signed prekey signature verification failed for $sessionKey',
      );
    }

    // Extract optional one-time prekey
    Uint8List? remoteOneTimePreKey;
    final opkData = preKeyBundle['oneTimePreKey'] as Map<String, dynamic>?;
    if (opkData != null) {
      remoteOneTimePreKey = opkData['publicKey'] as Uint8List;
    }

    // Perform X3DH
    final x3dhResult = X3DH.initiateSession(
      identityKeyPrivate: _identityKeyPair!.privateKey,
      remoteIdentityKey: remoteIdentityKey,
      remoteSignedPreKey: remoteSignedPreKey,
      remoteOneTimePreKey: remoteOneTimePreKey,
    );

    // Initialize Double Ratchet as sender
    final session = DoubleRatchetSession.initSender(
      x3dhResult.sharedSecret,
      remoteSignedPreKey,
    );

    _sessions[sessionKey] = session;

    // Store prekey message metadata for the first encrypted message.
    session.ephemeralPublicKey = x3dhResult.ephemeralPublicKey;
    session.isPreKeySession = true;
    session.preKeySignedPreKeyId = signedPreKeyData['keyId'] as int;
    session.preKeyOneTimePreKeyId = opkData?['keyId'] as int?;

    debugPrint(
      '[SignalProtocolService] Session created with $sessionKey via X3DH',
    );
  }

  /// Process an incoming pre-key message and establish a session as receiver.
  ///
  /// This is called internally during decryptMessage when messageType == 2.
  void _receiveSession({
    required String sessionKey,
    required Uint8List remoteIdentityKey,
    required Uint8List remoteEphemeralKey,
    required int signedPreKeyId,
    int? oneTimePreKeyId,
  }) {
    _ensureIdentity();

    final spk = _signedPreKeys[signedPreKeyId];
    debugPrint('[_receiveSession] Looking for SPK #$signedPreKeyId, '
        'available: ${_signedPreKeys.keys.toList()}, '
        'OPK #$oneTimePreKeyId, available: ${_oneTimePreKeys.keys.toList()}');
    if (spk == null) {
      throw SignalProtocolException(
        'Signed prekey $signedPreKeyId not found',
      );
    }

    Uint8List? opkPrivate;
    if (oneTimePreKeyId != null) {
      final opk = _oneTimePreKeys[oneTimePreKeyId];
      if (opk != null) {
        opkPrivate = opk.privateKey;
        // One-time prekeys are single-use — remove after consumption
        _oneTimePreKeys.remove(oneTimePreKeyId);
      }
    }

    final sharedSecret = X3DH.receiveSession(
      identityKeyPrivate: _identityKeyPair!.privateKey,
      signedPreKeyPrivate: spk.privateKey,
      oneTimePreKeyPrivate: opkPrivate,
      remoteIdentityKey: remoteIdentityKey,
      remoteEphemeralKey: remoteEphemeralKey,
    );

    final session = DoubleRatchetSession.initReceiver(
      sharedSecret,
      spk.privateKey,
      spk.publicKey,
    );

    _sessions[sessionKey] = session;

    debugPrint(
      '[SignalProtocolService] Session received from $sessionKey via X3DH',
    );
  }

  /// Check whether we already have an active session with the given device.
  Future<bool> hasSession(String recipientId, String deviceId) async {
    return _sessions.containsKey('$recipientId:$deviceId');
  }

  /// Delete the session for the given device.
  Future<void> deleteSession(String recipientId, String deviceId) async {
    _sessions.remove('$recipientId:$deviceId');
  }

  // ---------------------------------------------------------------------------
  // Message Encryption / Decryption (Double Ratchet)
  // ---------------------------------------------------------------------------

  /// Encrypt [plaintext] for the session with [recipientId]:[deviceId].
  /// Returns { 'ciphertext': Uint8List, 'messageType': int }.
  ///
  /// messageType: 1 = normal ciphertext, 2 = pre-key message (first message).
  ///
  /// IMPORTANT: Never log the plaintext content.
  Future<Map<String, dynamic>> encryptMessage({
    required String recipientId,
    required String deviceId,
    required Uint8List plaintext,
  }) async {
    final sessionKey = '$recipientId:$deviceId';
    final session = _sessions[sessionKey];
    if (session == null) {
      throw SignalProtocolException(
        'No session for $sessionKey. Call createSession() first.',
      );
    }

    final encrypted = session.encrypt(plaintext);
    final isPreKey = session.isPreKeySession;

    // Serialize the encrypted message into a transport format
    final payload = _serializeEncryptedMessage(
      encrypted,
      isPreKey: isPreKey,
      identityKey: isPreKey ? _identityKeyPair?.publicKey : null,
      ephemeralKey: isPreKey ? session.ephemeralPublicKey : null,
      signedPreKeyId: isPreKey ? session.preKeySignedPreKeyId : null,
      oneTimePreKeyId: isPreKey ? session.preKeyOneTimePreKeyId : null,
    );

    // After first message, no longer a prekey session
    if (isPreKey) {
      session.isPreKeySession = false;
      session.ephemeralPublicKey = null;
    }

    return {
      'ciphertext': payload,
      'messageType': isPreKey ? 2 : 1,
    };
  }

  /// Decrypt [ciphertext] from [senderId]:[deviceId].
  /// [messageType] indicates the Signal message type
  /// (1 = ciphertext, 2 = pre-key message).
  ///
  /// IMPORTANT: Never log the returned plaintext.
  Future<Uint8List> decryptMessage({
    required String senderId,
    required String deviceId,
    required Uint8List ciphertext,
    required int messageType,
  }) async {
    final sessionKey = '$senderId:$deviceId';

    if (messageType == 2) {
      // Pre-key message: extract X3DH parameters and establish/replace session.
      // Always call _receiveSession even if a session exists — the sender
      // used THEIR X3DH with OUR prekey bundle, so we must derive the same
      // shared secret. An existing session (from our ensureSession call)
      // used THEIR prekey bundle → different shared secret.
      final parsed = _deserializePreKeyMessage(ciphertext);
      _receiveSession(
        sessionKey: sessionKey,
        remoteIdentityKey: parsed.identityKey,
        remoteEphemeralKey: parsed.ephemeralKey,
        signedPreKeyId: parsed.signedPreKeyId,
        oneTimePreKeyId: parsed.oneTimePreKeyId,
      );
      // Decrypt the inner message
      final session = _sessions[sessionKey]!;
      return session.decrypt(parsed.encryptedMessage);
    }

    // Normal ciphertext message
    final session = _sessions[sessionKey];
    if (session == null) {
      throw SignalProtocolException(
        'No session for $sessionKey. Cannot decrypt.',
      );
    }

    final encrypted = _deserializeNormalMessage(ciphertext);
    return session.decrypt(encrypted);
  }

  // ---------------------------------------------------------------------------
  // Group Messaging (Sender Keys)
  // ---------------------------------------------------------------------------

  /// Access the underlying SenderKeyManager for direct usage by
  /// GroupSessionManager.
  SenderKeyManager get senderKeyManager => _senderKeyManager;

  /// Create a Sender Key for the given [groupId].
  /// Returns the distribution message bytes and distribution info.
  Future<Map<String, dynamic>> createSenderKey(
    String groupId, {
    String? myId,
  }) async {
    final senderId = myId ?? 'self';
    final distribution = _senderKeyManager.createSenderKey(groupId, senderId);
    return {
      'senderKeyMessage': distribution.serialize(),
      'distributionId': 'dist_$groupId',
      'groupId': groupId,
      'senderId': senderId,
    };
  }

  /// Process a Sender Key distribution message from another group member.
  Future<void> processSenderKey(
    String groupId,
    String senderId,
    Map<String, dynamic> senderKeyMessage,
  ) async {
    final data = senderKeyMessage['senderKeyMessage'] as Uint8List;
    final distribution = SenderKeyDistributionMessage.deserialize(data);
    _senderKeyManager.processSenderKey(distribution);
  }

  /// Encrypt [plaintext] for the group using the local Sender Key.
  Future<Uint8List> encryptGroupMessage(
    String groupId,
    Uint8List plaintext, {
    String? myId,
  }) async {
    final senderId = myId ?? 'self';
    try {
      return _senderKeyManager.encryptGroupMessage(
        groupId,
        senderId,
        plaintext,
      );
    } catch (e) {
      throw SignalProtocolException(
        'Failed to encrypt group message: $e',
      );
    }
  }

  /// Decrypt a group message from [senderId] in [groupId].
  Future<Uint8List> decryptGroupMessage(
    String groupId,
    String senderId,
    Uint8List ciphertext,
  ) async {
    try {
      return _senderKeyManager.decryptGroupMessage(
        groupId,
        senderId,
        ciphertext,
      );
    } catch (e) {
      throw SignalProtocolException(
        'Failed to decrypt group message from $senderId in $groupId: $e',
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Session Store Persistence
  // ---------------------------------------------------------------------------

  /// Serialize all session state and save to [path].
  Future<void> saveSessionStore(String path) async {
    final store = <String, dynamic>{};

    // Sessions
    final sessionsMap = <String, dynamic>{};
    for (final entry in _sessions.entries) {
      sessionsMap[entry.key] = entry.value.toJson();
    }
    store['sessions'] = sessionsMap;

    // Identity
    if (_identityKeyPair != null) {
      store['identityPublicKey'] = _bytesToHex(_identityKeyPair!.publicKey);
      store['identityPrivateKey'] = _bytesToHex(_identityKeyPair!.privateKey);
    }
    if (_identitySigningKeySeed != null) {
      store['identitySigningKeySeed'] = _bytesToHex(_identitySigningKeySeed!);
    }
    if (_identityVerifyKey != null) {
      store['identityVerifyKey'] = _bytesToHex(_identityVerifyKey!);
    }
    store['registrationId'] = _registrationId;

    // Signed prekeys
    final spkMap = <String, dynamic>{};
    for (final entry in _signedPreKeys.entries) {
      spkMap[entry.key.toString()] = {
        'keyId': entry.value.keyId,
        'privateKey': _bytesToHex(entry.value.privateKey),
        'publicKey': _bytesToHex(entry.value.publicKey),
        'signature': _bytesToHex(entry.value.signature),
      };
    }
    store['signedPreKeys'] = spkMap;

    // One-time prekeys
    final opkMap = <String, dynamic>{};
    for (final entry in _oneTimePreKeys.entries) {
      opkMap[entry.key.toString()] = {
        'keyId': entry.value.keyId,
        'privateKey': _bytesToHex(entry.value.privateKey),
        'publicKey': _bytesToHex(entry.value.publicKey),
      };
    }
    store['oneTimePreKeys'] = opkMap;

    // Sender keys
    store['senderKeys'] = _senderKeyManager.toJson();

    // Phase 6: SKDM distribution tracker is in-memory only — never persisted.
    // Persisting it caused "delivered but lost across restart" bugs because
    // the receiver's session store could be reset while the sender still
    // believed delivery had succeeded. Reactive sender_key_request handles
    // any cross-restart misses.

    // Message send log for retry (Phase 5.2 — kept for now, removed in Phase 6.5)
    store['messageSendLog'] = _messageSendLog.toJson();

    try {
      final file = File(path);
      final jsonBytes = Uint8List.fromList(utf8.encode(jsonEncode(store)));
      // Encrypt session store with derived key (Zero-Knowledge: no plaintext on disk)
      if (_storeEncryptionKey != null) {
        final box = nacl_api.SecretBox(_storeEncryptionKey!);
        final nonce = Uint8List(nacl_api.EncryptedMessage.nonceLength);
        final rng = Random.secure();
        for (var i = 0; i < nonce.length; i++) {
          nonce[i] = rng.nextInt(256);
        }
        final encrypted = box.encrypt(jsonBytes, nonce: nonce);
        await file.writeAsBytes(encrypted.toList());
        _storeWasEncrypted = true;
      } else {
        await file.writeAsString(jsonEncode(store));
      }
    } catch (e) {
      debugPrint('[SignalProtocolService] Failed to save session store: $e');
    }
  }

  /// Set the encryption key used for session store file protection.
  /// Should be derived from device-specific secure storage.
  Uint8List? _storeEncryptionKey;
  /// Track whether the store was successfully encrypted/decrypted.
  /// Once true, plaintext fallback is permanently disabled (tamper protection).
  bool _storeWasEncrypted = false;
  /// Whether the session store has been encrypted at least once.
  bool get isStoreEncrypted => _storeWasEncrypted;
  /// Mark the store as encrypted (called from session manager with persisted flag).
  void markStoreEncrypted() { _storeWasEncrypted = true; }
  void setStoreEncryptionKey(Uint8List key) {
    _storeEncryptionKey = key;
  }

  /// Load previously saved session state from [path].
  Future<void> loadSessionStore(String path) async {
    try {
      final file = File(path);
      if (!await file.exists()) return;

      Map<String, dynamic> store;
      if (_storeEncryptionKey != null) {
        // Encrypted store: read bytes → decrypt with SecretBox → parse JSON
        final rawData = await file.readAsBytes();
        try {
          final box = nacl_api.SecretBox(_storeEncryptionKey!);
          final nonceLen = nacl_api.EncryptedMessage.nonceLength;
          final decrypted = box.decrypt(nacl_api.EncryptedMessage(
            nonce: rawData.sublist(0, nonceLen),
            cipherText: rawData.sublist(nonceLen),
          ));
          store = jsonDecode(utf8.decode(decrypted)) as Map<String, dynamic>;
          _storeWasEncrypted = true;
        } catch (_) {
          if (_storeWasEncrypted) {
            // Store was previously encrypted — reject tampered/replaced file
            debugPrint('[SignalProtocolService] Encrypted session store '
                'decryption failed — refusing plaintext fallback (tamper protection)');
            return;
          }
          // One-time migration: read legacy plaintext store, will be encrypted on next save
          final content = await file.readAsString();
          store = jsonDecode(content) as Map<String, dynamic>;
          debugPrint('[SignalProtocolService] Migrating plaintext session store '
              'to encrypted format');
        }
      } else {
        final content = await file.readAsString();
        store = jsonDecode(content) as Map<String, dynamic>;
      }

      // Identity
      if (store['identityPublicKey'] != null &&
          store['identityPrivateKey'] != null) {
        _identityKeyPair = X25519KeyPair(
          publicKey: _hexToBytes(store['identityPublicKey'] as String),
          privateKey: _hexToBytes(store['identityPrivateKey'] as String),
        );
      }
      if (store['identitySigningKeySeed'] != null) {
        _identitySigningKeySeed =
            _hexToBytes(store['identitySigningKeySeed'] as String);
      }
      if (store['identityVerifyKey'] != null) {
        _identityVerifyKey =
            _hexToBytes(store['identityVerifyKey'] as String);
      }
      _registrationId = store['registrationId'] as int?;

      // Sessions
      final sessionsMap = store['sessions'] as Map<String, dynamic>?;
      if (sessionsMap != null) {
        for (final entry in sessionsMap.entries) {
          _sessions[entry.key] = DoubleRatchetSession.fromJson(
            entry.value as Map<String, dynamic>,
          );
        }
      }

      // Signed prekeys
      final spkMap = store['signedPreKeys'] as Map<String, dynamic>?;
      if (spkMap != null) {
        for (final entry in spkMap.entries) {
          final data = entry.value as Map<String, dynamic>;
          _signedPreKeys[int.parse(entry.key)] = SignedPreKey(
            keyId: data['keyId'] as int,
            privateKey: _hexToBytes(data['privateKey'] as String),
            publicKey: _hexToBytes(data['publicKey'] as String),
            signature: _hexToBytes(data['signature'] as String),
          );
        }
      }

      // One-time prekeys
      final opkMap = store['oneTimePreKeys'] as Map<String, dynamic>?;
      if (opkMap != null) {
        for (final entry in opkMap.entries) {
          final data = entry.value as Map<String, dynamic>;
          _oneTimePreKeys[int.parse(entry.key)] = OneTimePreKey(
            keyId: data['keyId'] as int,
            privateKey: _hexToBytes(data['privateKey'] as String),
            publicKey: _hexToBytes(data['publicKey'] as String),
          );
        }
      }

      // Sender keys
      final senderKeysMap = store['senderKeys'] as Map<String, dynamic>?;
      if (senderKeysMap != null) {
        _senderKeyManager = SenderKeyManager.fromJson(senderKeysMap);
      }

      // Phase 6: SKDM tracker is in-memory only — never restored from disk.
      // Reactive sender_key_request handles any cross-restart misses.
      // (Old persisted store may still contain 'skdmTracker' field; we ignore it.)
      _skdmTracker = SenderKeyDistributionTracker();

      // Message send log for retry (Phase 5.2)
      final sendLogMap = store['messageSendLog'] as Map<String, dynamic>?;
      if (sendLogMap != null) {
        _messageSendLog = MessageSendLog.fromJson(sendLogMap);
      }

      debugPrint(
        '[SignalProtocolService] Loaded ${_sessions.length} sessions from store',
      );
    } catch (e) {
      debugPrint('[SignalProtocolService] Failed to load session store: $e');
    }
  }

  // ---------------------------------------------------------------------------
  // Internal: Message serialization
  // ---------------------------------------------------------------------------

  /// Serialize an encrypted message for transport.
  /// Pre-key messages include extra headers for X3DH.
  Uint8List _serializeEncryptedMessage(
    EncryptedMessage encrypted, {
    bool isPreKey = false,
    Uint8List? identityKey,
    Uint8List? ephemeralKey,
    int? signedPreKeyId,
    int? oneTimePreKeyId,
  }) {
    final msgJson = encrypted.toJson();
    if (isPreKey && identityKey != null && ephemeralKey != null) {
      msgJson['identityKey'] = _bytesToHex(identityKey);
      msgJson['ephemeralKey'] = _bytesToHex(ephemeralKey);
      if (signedPreKeyId != null) {
        msgJson['signedPreKeyId'] = signedPreKeyId;
      }
      if (oneTimePreKeyId != null) {
        msgJson['oneTimePreKeyId'] = oneTimePreKeyId;
      }
    }
    return Uint8List.fromList(utf8.encode(jsonEncode(msgJson)));
  }

  /// Parse a pre-key message to extract X3DH params and inner encrypted message.
  _PreKeyMessageData _deserializePreKeyMessage(Uint8List data) {
    final json = jsonDecode(utf8.decode(data)) as Map<String, dynamic>;
    return _PreKeyMessageData(
      identityKey: _hexToBytes(json['identityKey'] as String),
      ephemeralKey: _hexToBytes(json['ephemeralKey'] as String),
      signedPreKeyId: json['signedPreKeyId'] as int? ?? 1,
      oneTimePreKeyId: json['oneTimePreKeyId'] as int?,
      encryptedMessage: EncryptedMessage.fromJson(json),
    );
  }

  /// Parse a normal (non-prekey) encrypted message.
  EncryptedMessage _deserializeNormalMessage(Uint8List data) {
    final json = jsonDecode(utf8.decode(data)) as Map<String, dynamic>;
    return EncryptedMessage.fromJson(json);
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  void _ensureIdentity() {
    if (_identityKeyPair == null) {
      throw SignalProtocolException(
        'Identity key pair not generated. Call generateIdentityKeyPair() first.',
      );
    }
    if (_identitySigningKeySeed == null) {
      throw SignalProtocolException(
        'Ed25519 signing key not set. Call setSigningKey() or generateIdentityKeyPair() first.',
      );
    }
  }

  static Uint8List _randomBytes(int length) {
    final rng = Random.secure();
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = rng.nextInt(256);
    }
    return bytes;
  }

  static String _bytesToHex(Uint8List bytes) {
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  static Uint8List _hexToBytes(String hex) {
    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }
}

// =============================================================================
// Internal data classes
// =============================================================================

class _PreKeyMessageData {
  final Uint8List identityKey;
  final Uint8List ephemeralKey;
  final int signedPreKeyId;
  final int? oneTimePreKeyId;
  final EncryptedMessage encryptedMessage;

  _PreKeyMessageData({
    required this.identityKey,
    required this.ephemeralKey,
    required this.signedPreKeyId,
    this.oneTimePreKeyId,
    required this.encryptedMessage,
  });
}

// =============================================================================
// Extensions for session metadata (pre-key tracking)
// =============================================================================

// =============================================================================
// Exceptions
// =============================================================================

class SignalProtocolException implements Exception {
  final String message;
  final String? code;
  final dynamic details;

  const SignalProtocolException(this.message, {this.code, this.details});

  @override
  String toString() => 'SignalProtocolException($code): $message';
}
