/// @file        signal_protocol_service.dart
/// @description Signal Protocol 순수 Dart 구현체. X3DH, Double Ratchet, Sender Key, PreKey 관리를 pinenacl 기반으로 구현
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-29
/// @lastUpdated 2026-04-20 (backport: multi-session per peer, archived sessions, trial-decrypt with snapshot/restore, TOFU identity pin, plaintext-fallback refuse)
///
/// @functions
///  - SignalProtocolService: Signal Protocol 순수 Dart 구현 클래스
///  - SignalProtocolService.generateIdentityKeyPair(): X25519 ID 키쌍 생성
///  - SignalProtocolService.generateSignedPreKey(): 서명된 프리키 생성
///  - SignalProtocolService.generateOneTimePreKeys(): 일회용 프리키 배치 생성 (Isolate offload 옵션)
///  - SignalProtocolService.getPreKeyBundle(): 서버 업로드용 PreKey 번들 조회
///  - SignalProtocolService.createSession(): X3DH로 새 세션 생성 (TOFU 검증 포함)
///  - SignalProtocolService.hasSession(): 세션 존재 여부 확인
///  - SignalProtocolService.deleteSession(): 세션 삭제
///  - SignalProtocolService.archiveSession(): 세션 아카이브 (삭제 대신 임시 보관, 1시간 TTL)
///  - SignalProtocolService.encryptMessage(): Double Ratchet 메시지 암호화
///  - SignalProtocolService.decryptMessage(): Double Ratchet 복호화 — trial-decrypt + 아카이브 fallback
///  - SignalProtocolService.createSenderKey(): 그룹용 Sender Key 생성
///  - SignalProtocolService.processSenderKey(): 그룹 Sender Key 처리
///  - SignalProtocolService.encryptGroupMessage(): 그룹 메시지 암호화
///  - SignalProtocolService.decryptGroupMessage(): 그룹 메시지 복호화
///  - SignalProtocolService.saveSessionStore(): 세션 상태 JSON 직렬화 저장 (아카이브 세션 포함)
///  - SignalProtocolService.loadSessionStore(): 세션 상태 JSON 역직렬화 로드 (아카이브 세션 복원 + TTL 체크)
///  - SignalProtocolException: Signal Protocol 예외 클래스

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;
import 'package:pinenacl/x25519.dart' as nacl_api;

import 'double_ratchet.dart';
import 'identity_key_changed_exception.dart';
import 'identity_pin_store.dart';
import 'logger.dart';
import 'message_send_log.dart';
import 'prekey_bundle.dart';
import 'sender_key.dart';
import 'sender_key_tracker.dart';
import 'x25519.dart';
import 'x3dh.dart';

/// Pure-Dart implementation of the Signal Protocol, replacing Platform
/// Channel / native bridge approaches.
///
/// Uses pinenacl for all cryptographic primitives:
/// - X25519 for Diffie-Hellman key exchange
/// - Ed25519 for signing prekeys
/// - XSalsa20-Poly1305 for message encryption (via Double Ratchet)
/// - HMAC-SHA256 HKDF for key derivation
///
/// ## Defense against Double Ratchet state-corruption attacks
///
/// The low-level [DoubleRatchetSession.decrypt] mutates ratchet state
/// before the AEAD check, which on its own is vulnerable to a single
/// tampered message permanently desynchronising the chain. This service
/// wraps every decrypt attempt in [_trialDecrypt], which snapshots the
/// session state via [DoubleRatchetSession.toJson] and restores it on
/// failure (see `_trialDecrypt`). In addition, archived session copies
/// are kept in [_archivedSessions] for up to 1 hour so that in-flight
/// messages encrypted under a superseded ratchet are still decryptable
/// (see [archiveSession] / [_tryDecryptFromArchive]).
///
/// Callers that invoke [DoubleRatchetSession.decrypt] directly
/// **without** going through this service must implement equivalent
/// snapshot/restore semantics themselves. The [DoubleRatchetSession]
/// class documents this requirement.
class SignalProtocolService {
  /// Multi-session storage. Each peer can have multiple Double Ratchet
  /// sessions to handle X3DH concurrent initiation.
  /// Key: "recipientId:deviceId" → list of sessions, MRU at the end.
  /// On decrypt, every session is tried (snapshot/restore on failure) until
  /// one succeeds. On encrypt, [list.last] (most recently used) is selected.
  final Map<String, List<DoubleRatchetSession>> _sessions = {};

  /// Maximum sessions kept per peer. Older sessions are LRU-evicted.
  /// 5 covers concurrent X3DH bursts; in normal sequential use this is 1-2.
  static const int _maxSessionsPerPeer = 5;

  // ---------------------------------------------------------------------------
  // Session Archiving
  // ---------------------------------------------------------------------------

  /// Archived sessions for in-flight message decryption after session reset.
  /// Key: "recipientId:deviceId" → list of archived session entries.
  /// Signal pattern: archive instead of hard-delete, allowing in-flight
  /// messages encrypted under the old ratchet to still be decryptable.
  /// TTL: 1 hour from archive time. Purged on load and periodically.
  final Map<String, List<_ArchivedSessionEntry>> _archivedSessions = {};

  /// Flag: archived session ratchet was advanced during decrypt — needs persist.
  bool _archiveDecryptDirty = false;

  /// Whether an archived session was advanced since the last `saveSessionStore`
  /// call. Callers can check this to decide whether to persist immediately.
  bool get archiveDecryptDirty => _archiveDecryptDirty;

  /// Maximum time an archived session is kept before purge (1 hour).
  static const Duration _archiveTtl = Duration(hours: 1);

  /// Archive all sessions for [recipientId]:[deviceId] instead of deleting.
  /// The archived sessions are kept for [_archiveTtl] to decrypt in-flight
  /// messages that were encrypted under the old ratchet state.
  ///
  /// After archiving, the active session list for this peer is cleared,
  /// ready for a fresh X3DH session to be created by the caller.
  Future<void> archiveSession(String recipientId, String deviceId) async {
    final sessionKey = '$recipientId:$deviceId';
    final activeSessions = _sessions.remove(sessionKey);
    if (activeSessions == null || activeSessions.isEmpty) {
      debugPrint('[SignalProtocolService] archiveSession: no active sessions '
          'for ${_maskSessionKey(sessionKey)} — nothing to archive');
      return;
    }

    final now = DateTime.now();
    final archived = _archivedSessions.putIfAbsent(sessionKey, () => []);
    for (final session in activeSessions) {
      archived.add(_ArchivedSessionEntry(
        sessionJson: session.toJson(),
        archivedAt: now,
      ));
    }
    // Per-peer cap: keep only the 5 most recent entries
    const maxArchivedPerPeer = 5;
    if (archived.length > maxArchivedPerPeer) {
      archived.removeRange(0, archived.length - maxArchivedPerPeer);
    }

    debugPrint('[SignalProtocolService] Archived ${activeSessions.length} '
        'sessions for ${_maskSessionKey(sessionKey)} (total archived: ${archived.length})');

    // Cleanup expired entries across all peers while we're at it
    _cleanupExpiredArchives();
  }

  /// Purge archived sessions older than [_archiveTtl].
  /// Called on archive, on load, and can be called periodically.
  void _cleanupExpiredArchives() {
    final now = DateTime.now();
    final expiredKeys = <String>[];
    for (final entry in _archivedSessions.entries) {
      entry.value.removeWhere(
        (a) => now.difference(a.archivedAt) > _archiveTtl,
      );
      if (entry.value.isEmpty) {
        expiredKeys.add(entry.key);
      }
    }
    for (final key in expiredKeys) {
      _archivedSessions.remove(key);
    }
    if (expiredKeys.isNotEmpty) {
      debugPrint('[SignalProtocolService] Purged archived sessions for '
          '${expiredKeys.length} peers (TTL expired)');
    }
  }

  /// Try decrypting [encrypted] using archived sessions for [sessionKey].
  /// Uses snapshot/restore to avoid corrupting archived session state on
  /// failed attempts. Returns the plaintext on success, null if no archived
  /// session could decrypt.
  Uint8List? _tryDecryptFromArchive(
    String sessionKey,
    EncryptedMessage encrypted,
  ) {
    final archived = _archivedSessions[sessionKey];
    if (archived == null || archived.isEmpty) return null;

    for (var i = archived.length - 1; i >= 0; i--) {
      final entry = archived[i];
      try {
        final session = DoubleRatchetSession.fromJson(entry.sessionJson);
        final plaintext = session.decrypt(encrypted);
        // Success — update the archived entry's session state (ratchet advanced)
        archived[i] = _ArchivedSessionEntry(
          sessionJson: session.toJson(),
          archivedAt: entry.archivedAt,
        );
        debugPrint('[SignalProtocolService] Decrypted using archived session '
            'for ${_maskSessionKey(sessionKey)} (archived ${DateTime.now().difference(entry.archivedAt).inSeconds}s ago)');
        return plaintext;
      } catch (_) {
        // This archived session couldn't decrypt — try next
        continue;
      }
    }
    return null;
  }

  /// Local identity key pair (X25519).
  X25519KeyPair? _identityKeyPair;

  /// Whether an identity key pair has been loaded or generated.
  bool get hasIdentityKey => _identityKeyPair != null;

  /// X25519 identity public key (for comparison).
  Uint8List? get identityPublicKey =>
      _identityKeyPair != null ? Uint8List.fromList(_identityKeyPair!.publicKey) : null;

  /// X25519 identity private key (for Sealed Sender unseal).
  /// SECURITY: Caller MUST NOT log or persist this value.
  Uint8List? get identityPrivateKey =>
      _identityKeyPair != null ? Uint8List.fromList(_identityKeyPair!.privateKey) : null;

  /// Remote identity keys learned during X3DH session establishment.
  /// Key: recipientId → their X25519 identity public key (32 bytes).
  /// Used by Sealed Sender seal() to encrypt the outer envelope.
  final Map<String, Uint8List> _remoteIdentityKeys = {};

  /// Get a remote peer's X25519 identity public key (learned during session creation).
  Uint8List? getRemoteIdentityKey(String recipientId) =>
      _remoteIdentityKeys[recipientId];

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
    _archivedSessions.clear();
    // Do NOT clear _signedPreKeys and _oneTimePreKeys — they are needed
    // by _receiveSession() to process incoming prekey messages.
    _senderKeyManager = SenderKeyManager();
    // Also reset the in-memory SKDM tracker so the next group send
    // re-distributes to all members.
    _skdmTracker = SenderKeyDistributionTracker();
    debugPrint('[SignalProtocolService] All sessions cleared (prekeys kept)');
  }

  // ---------------------------------------------------------------------------
  // Multi-session helpers
  // ---------------------------------------------------------------------------

  /// Append a new session to the peer's list, evicting oldest if over limit.
  /// Used by both [createSession] (outgoing X3DH) and [_receiveSession]
  /// (incoming prekey message).
  void _appendSession(String sessionKey, DoubleRatchetSession session) {
    final list = _sessions.putIfAbsent(sessionKey, () => []);
    list.add(session);
    while (list.length > _maxSessionsPerPeer) {
      list.removeAt(0); // LRU eviction (oldest at front)
    }
  }

  /// Move [session] to the back of [sessionKey]'s list (most recently used).
  /// Called after a successful encrypt/decrypt so the next encrypt picks it.
  void _markMostRecentlyUsed(String sessionKey, DoubleRatchetSession session) {
    final list = _sessions[sessionKey];
    if (list == null) return;
    if (!list.remove(session)) return;
    list.add(session);
  }

  /// Constant-time byte comparison for TOFU pin check so a timing
  /// side-channel cannot leak information about which prefix of a forged
  /// identity key matches the pinned one.
  static bool _constantTimeBytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Mask sessionKey ("recipientId:deviceId") for log + exception messages
  /// so PII (full identifiers) does not leak into stack traces, crash
  /// reports, or device logs.
  ///
  /// Format: first 8 chars + "..." + last 4 chars.
  static String _maskSessionKey(String sessionKey) {
    if (sessionKey.length <= 12) return sessionKey;
    return '${sessionKey.substring(0, 8)}...${sessionKey.substring(sessionKey.length - 4)}';
  }

  /// Try every session in [sessions] (newest first) to decrypt [encrypted].
  ///
  /// Uses snapshot/restore via [DoubleRatchetSession.toJson]/[fromJson] to
  /// roll back state mutations from failed attempts — this is the primary
  /// defense against a single tampered message corrupting ratchet state
  /// (see class-level docstring).
  ///
  /// Returns [_TrialDecryptResult] on success or null if no session worked.
  _TrialDecryptResult? _trialDecrypt(
    List<DoubleRatchetSession> sessions,
    EncryptedMessage encrypted,
  ) {
    for (var i = sessions.length - 1; i >= 0; i--) {
      final session = sessions[i];
      final snapshot = session.toJson();
      try {
        final plaintext = session.decrypt(encrypted);
        return _TrialDecryptResult(session, plaintext);
      } catch (_) {
        // Restore the mutated state in-place. The freshly deserialized
        // instance replaces the corrupted one at the same index.
        sessions[i] = DoubleRatchetSession.fromJson(snapshot);
        continue;
      }
    }
    return null;
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

  /// SKDM distribution tracker — tracks which members have received the
  /// current Sender Key to avoid redundant O(N) re-sends.
  SenderKeyDistributionTracker _skdmTracker = SenderKeyDistributionTracker();
  SenderKeyDistributionTracker get skdmTracker => _skdmTracker;

  /// Message send log for retry requests.
  MessageSendLog _messageSendLog = MessageSendLog();
  MessageSendLog get messageSendLog => _messageSendLog;

  /// Random generator for registration IDs.
  static final _rng = Random.secure();

  /// Optional TOFU pin store for remote Ed25519 identity keys. When null,
  /// the TOFU check is skipped (tests / scripts that don't wire persistent
  /// storage); production wiring should always inject a concrete store.
  final IdentityPinStore? _identityPinStore;

  SignalProtocolService({
    bool? useMockFallback,
    IdentityPinStore? identityPinStore,
  }) : _identityPinStore = identityPinStore;

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
    // In production, this would be the user's identity Ed25519 key from a
    // key derivation layer — but for the Signal layer we generate a fresh
    // one. The caller can override with setSigningKey().
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

  /// Set the Ed25519 signing key seed from the caller's identity layer.
  /// Call this after identity creation to link the Signal keys to the user
  /// identity.
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
  ///
  /// Perf: ~7.9s for 100 keys on a mid-range phone. Offloaded to a
  /// background isolate via [Isolate.run] so the calling isolate stays
  /// responsive. Callers that need a different offload mechanism (e.g.
  /// Flutter's `compute()`) can call
  /// [generateOneTimePreKeysIsolateWorker] directly.
  Future<List<Map<String, dynamic>>> generateOneTimePreKeys(
    int startId,
    int count,
  ) async {
    final opks = await Isolate.run(
      () => generateOneTimePreKeysIsolateWorker((startId, count)),
    );

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
  /// Performs X3DH as the initiator (Alice). Fails closed if the remote
  /// Ed25519 identity key is missing (prevents MITM via bundle omission),
  /// verifies the signed prekey signature, and runs a TOFU pin check via
  /// [IdentityPinStore] if one was injected.
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

    // Fail-closed: the server can omit the Ed25519 key to bypass signature
    // verification. Refuse the session and let retry pressure repair the
    // bundle upstream.
    final remoteIdentityKeyEd25519 =
        preKeyBundle['identityKeyEd25519'] as Uint8List?;
    if (remoteIdentityKeyEd25519 == null) {
      throw SignalProtocolException(
        'PreKey bundle missing Ed25519 identity key — refusing session '
        'establishment for ${_maskSessionKey(sessionKey)} (fail-closed)',
      );
    }
    final bundle = PreKeyBundle(
      identityKey: remoteIdentityKey,
      signedPreKey: remoteSignedPreKey,
      signedPreKeySignature: signedPreKeySignature,
      signedPreKeyId: signedPreKeyData['keyId'] as int,
      registrationId: preKeyBundle['registrationId'] as int? ?? 0,
    );
    // Ed25519 key present — MUST verify SPK signature (fail-closed on bad sig)
    if (!bundle.verifySignature(remoteIdentityKeyEd25519)) {
      throw SignalProtocolException(
        'Signed prekey signature verification failed for '
        '${_maskSessionKey(sessionKey)}',
      );
    }

    // TOFU identity pin check (optional — only runs when a store is injected).
    //   - First time we establish with this peer → store the Ed25519 key
    //   - Subsequent times → constant-time compare; mismatch ⇒ refuse
    await _tofuPinCheck(
      sessionKey: sessionKey,
      remoteIdentityKeyEd25519: remoteIdentityKeyEd25519,
    );

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

    // Store prekey message metadata for the first encrypted message.
    session.ephemeralPublicKey = x3dhResult.ephemeralPublicKey;
    session.isPreKeySession = true;
    session.preKeySignedPreKeyId = signedPreKeyData['keyId'] as int;
    session.preKeyOneTimePreKeyId = opkData?['keyId'] as int?;

    // Append to multi-session list (LRU eviction inside).
    _appendSession(sessionKey, session);

    // Cache remote identity key for Sealed Sender seal().
    _remoteIdentityKeys[recipientId] = Uint8List.fromList(remoteIdentityKey);

    debugPrint(
      '[SignalProtocolService] Session created with '
      '${_maskSessionKey(sessionKey)} via X3DH '
      '(total ${_sessions[sessionKey]!.length} for peer)',
    );
  }

  /// TOFU pin check helper shared by [createSession] and [_receiveSession].
  ///
  /// Stores the key on first encounter. On subsequent encounters, does a
  /// constant-time compare and throws [IdentityKeyChangedException] on
  /// mismatch so the caller can route it through their Safety Number /
  /// verification workflow. Storage failures surface as
  /// [SignalProtocolException] (never silently downgrade).
  Future<void> _tofuPinCheck({
    required String sessionKey,
    required Uint8List remoteIdentityKeyEd25519,
  }) async {
    final pinStore = _identityPinStore;
    if (pinStore == null) return;
    try {
      final pinned = await pinStore.getPinned(sessionKey);
      if (pinned == null) {
        await pinStore.pin(
          sessionKey,
          Uint8List.fromList(remoteIdentityKeyEd25519),
        );
        return;
      }
      if (!_constantTimeBytesEqual(pinned, remoteIdentityKeyEd25519)) {
        final colonIdx = sessionKey.lastIndexOf(':');
        final extractedSnow = colonIdx > 0
            ? sessionKey.substring(0, colonIdx)
            : sessionKey;
        final extractedDevice = colonIdx > 0
            ? sessionKey.substring(colonIdx + 1)
            : null;
        throw IdentityKeyChangedException(
          peerSnowchatId: extractedSnow,
          deviceId: extractedDevice,
          expectedKey: Uint8List.fromList(pinned),
          actualKey: Uint8List.fromList(remoteIdentityKeyEd25519),
        );
      }
    } on IdentityKeyChangedException {
      rethrow;
    } on SignalProtocolException {
      rethrow;
    } catch (e) {
      throw SignalProtocolException(
        'IdentityPinStore failure for ${_maskSessionKey(sessionKey)}: $e',
      );
    }
  }

  /// Process an incoming pre-key message and establish a session as receiver.
  ///
  /// This is called internally during decryptMessage when messageType == 2.
  ///
  /// Receive-side TOFU: when [remoteIdentityKeyEd25519] is supplied, enforce
  /// the same TOFU pin check as [createSession] BEFORE consuming any SPK /
  /// OPK material. A mismatch raises [IdentityKeyChangedException] so the
  /// upper layers can dead-letter the envelope without installing an
  /// attacker-controlled session.
  ///
  /// If [remoteIdentityKeyEd25519] is null we **fail-closed** to match the
  /// send-side policy already in [createSession]. The caller is responsible
  /// for fetching the sender's Ed25519 verify key from the prekey-bundle
  /// endpoint before calling this path.
  Future<void> _receiveSession({
    required String sessionKey,
    required Uint8List remoteIdentityKey,
    required Uint8List remoteEphemeralKey,
    required int signedPreKeyId,
    int? oneTimePreKeyId,
    Uint8List? remoteIdentityKeyEd25519,
  }) async {
    _ensureIdentity();

    // Receive-side TOFU. Run BEFORE we touch any one-time prekey so an
    // attacker who triggers a mismatch cannot also burn through our OPKs.
    if (remoteIdentityKeyEd25519 == null) {
      throw SignalProtocolException(
        'Pre-key envelope missing sender Ed25519 verify key — refusing to '
        'establish receive session for '
        '${_maskSessionKey(sessionKey)} (fail-closed)',
      );
    }
    await _tofuPinCheck(
      sessionKey: sessionKey,
      remoteIdentityKeyEd25519: remoteIdentityKeyEd25519,
    );

    final spk = _signedPreKeys[signedPreKeyId];
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

    // Append to multi-session list. Existing sessions (e.g. from a prior
    // outgoing X3DH) are KEPT — they're needed to decrypt in-flight messages
    // encrypted with the old shared secret. LRU eviction at the limit.
    _appendSession(sessionKey, session);

    // Cache remote identity key for Sealed Sender seal().
    final peerId = sessionKey.split(':').first;
    _remoteIdentityKeys[peerId] = Uint8List.fromList(remoteIdentityKey);

    debugPrint(
      '[SignalProtocolService] Session received from '
      '${_maskSessionKey(sessionKey)} via X3DH '
      '(total ${_sessions[sessionKey]!.length} for peer)',
    );
  }

  /// Check whether we already have an active session with the given device.
  /// Returns true if at least one session exists in the peer's list.
  Future<bool> hasSession(String recipientId, String deviceId) async {
    final list = _sessions['$recipientId:$deviceId'];
    return list != null && list.isNotEmpty;
  }

  /// Delete ALL sessions for the given device (full peer wipe).
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
    // Use the most recently used session (list.last).
    final list = _sessions[sessionKey];
    if (list == null || list.isEmpty) {
      throw SignalProtocolException(
        'No session for ${_maskSessionKey(sessionKey)}. '
        'Call createSession() first.',
      );
    }
    final session = list.last;

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
  /// [senderIdentityKeyEd25519] is REQUIRED whenever [messageType] == 2
  /// and the trial-decrypt path falls through to [_receiveSession]. The
  /// caller fetches it from the prekey-bundle endpoint so receive-side
  /// TOFU can run BEFORE we install an attacker-controlled session. For
  /// [messageType] == 1 (and for prekey envelopes that match an already-
  /// existing session), this argument is ignored.
  ///
  /// IMPORTANT: Never log the returned plaintext.
  Future<Uint8List> decryptMessage({
    required String senderId,
    required String deviceId,
    required Uint8List ciphertext,
    required int messageType,
    Uint8List? senderIdentityKeyEd25519,
  }) async {
    final sessionKey = '$senderId:$deviceId';

    if (messageType == 2) {
      // Pre-key message handling.
      // 1. Try every existing session first (snapshot/restore on failure).
      //    Handles the case where the sender retried a prekey msg and we've
      //    already processed it once — the inner message is decryptable by
      //    an existing session.
      // 2. If none works, derive a NEW session via _receiveSession (which
      //    APPENDS, not replaces — see _appendSession). Then try the new
      //    session. If the new session also fails, remove it (broken).
      final _PreKeyMessageData parsed;
      try {
        parsed = _deserializePreKeyMessage(ciphertext);
      } on FormatException catch (e) {
        throw SignalProtocolException(
          'Malformed pre-key message for ${_maskSessionKey(sessionKey)}: $e',
        );
      }

      final existing = _sessions[sessionKey];
      if (existing != null && existing.isNotEmpty) {
        final result = _trialDecrypt(existing, parsed.encryptedMessage);
        if (result != null) {
          _markMostRecentlyUsed(sessionKey, result.session);
          return result.plaintext;
        }
      }

      // No existing session decrypted → derive new from prekey msg.
      // Hand the sender's Ed25519 verify key down so _receiveSession can
      // run TOFU pin checks BEFORE consuming our SPK/OPK material.
      // _receiveSession will throw IdentityKeyChangedException (typed) on
      // mismatch or SignalProtocolException if the key is missing.
      await _receiveSession(
        sessionKey: sessionKey,
        remoteIdentityKey: parsed.identityKey,
        remoteEphemeralKey: parsed.ephemeralKey,
        signedPreKeyId: parsed.signedPreKeyId,
        oneTimePreKeyId: parsed.oneTimePreKeyId,
        remoteIdentityKeyEd25519: senderIdentityKeyEd25519,
      );

      // _receiveSession appended the new session to the end via _appendSession.
      final list = _sessions[sessionKey]!;
      final newSession = list.last;
      try {
        final plaintext = newSession.decrypt(parsed.encryptedMessage);
        // newSession is already last (MRU). No need to mark.
        return plaintext;
      } catch (e) {
        // The newly derived session can't decrypt either — it's broken.
        // Remove it so it doesn't pollute future trial decrypts.
        list.removeLast();
        if (list.isEmpty) _sessions.remove(sessionKey);

        // Try archived sessions before giving up.
        final archivedResult =
            _tryDecryptFromArchive(sessionKey, parsed.encryptedMessage);
        if (archivedResult != null) {
          _archiveDecryptDirty = true;
          return archivedResult;
        }
        rethrow;
      }
    }

    // Normal ciphertext message: short-circuit if there is nothing to try.
    final list = _sessions[sessionKey];
    final archived = _archivedSessions[sessionKey];
    final hasActive = list != null && list.isNotEmpty;
    final hasArchived = archived != null && archived.isNotEmpty;
    if (!hasActive && !hasArchived) {
      throw SignalProtocolException(
        'No session for ${_maskSessionKey(sessionKey)}. Cannot decrypt.',
      );
    }

    // Deserialize (after the cheap session-presence check). Convert parse
    // failures to SignalProtocolException so callers do not leak raw
    // FormatException to their error-handling layers.
    final EncryptedMessage encrypted;
    try {
      encrypted = _deserializeNormalMessage(ciphertext);
    } on FormatException catch (e) {
      throw SignalProtocolException(
        'Malformed ciphertext for ${_maskSessionKey(sessionKey)}: $e',
      );
    }

    // Trial decrypt across all active sessions (MRU first).
    if (hasActive) {
      final result = _trialDecrypt(list, encrypted);
      if (result != null) {
        _markMostRecentlyUsed(sessionKey, result.session);
        return result.plaintext;
      }
    }

    // Active sessions failed — try archived sessions as fallback. Handles
    // in-flight messages encrypted under a ratchet state that has since
    // been archived due to a session reset.
    final archivedResult = _tryDecryptFromArchive(sessionKey, encrypted);
    if (archivedResult != null) {
      _archiveDecryptDirty = true;
      return archivedResult;
    }

    // Both active and archived sessions failed.
    final activeCount = list?.length ?? 0;
    final archivedCount = archived?.length ?? 0;
    throw SignalProtocolException(
      'No session in ${_maskSessionKey(sessionKey)} could decrypt the message '
      '($activeCount active + $archivedCount archived sessions tried).',
    );
  }

  // ---------------------------------------------------------------------------
  // Group Messaging (Sender Keys)
  // ---------------------------------------------------------------------------

  /// Access the underlying SenderKeyManager for direct usage by group
  /// session managers.
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
  ///
  /// Plaintext fallback is DISABLED: if no encryption key has been installed
  /// via [setStoreEncryptionKey], the save is skipped entirely. This prevents
  /// identity keys + ratchet material from being written to disk in the
  /// clear when the caller forgets to wire up encryption.
  Future<void> saveSessionStore(String path) async {
    _archiveDecryptDirty = false;
    final store = <String, dynamic>{};

    // Sessions are stored as List<DoubleRatchetSession> per peer.
    // Serialize as a JSON array. fromJson handles both legacy (single Map)
    // and new (array) formats for backward compat.
    final sessionsMap = <String, dynamic>{};
    for (final entry in _sessions.entries) {
      sessionsMap[entry.key] =
          entry.value.map((s) => s.toJson()).toList();
    }
    store['sessions'] = sessionsMap;

    // Persist archived sessions with archivedAt timestamps so they survive
    // app kill/restart within TTL.
    _cleanupExpiredArchives();
    final archivedMap = <String, dynamic>{};
    for (final entry in _archivedSessions.entries) {
      archivedMap[entry.key] = entry.value
          .map((a) => {
                'sessionJson': a.sessionJson,
                'archivedAt': a.archivedAt.millisecondsSinceEpoch,
              })
          .toList();
    }
    if (archivedMap.isNotEmpty) {
      store['archivedSessions'] = archivedMap;
    }

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

    // Remote identity keys for Sealed Sender
    final remoteIdMap = <String, String>{};
    for (final entry in _remoteIdentityKeys.entries) {
      remoteIdMap[entry.key] = _bytesToHex(entry.value);
    }
    store['remoteIdentityKeys'] = remoteIdMap;

    // SKDM distribution tracker is in-memory only — never persisted.
    // Persisting caused "delivered but lost across restart" bugs because
    // the receiver's session store could be reset while the sender still
    // believed delivery had succeeded. A reactive sender_key_request handles
    // any cross-restart misses.

    // Message send log for retry (1:1 + group, 24h TTL)
    store['messageSendLog'] = _messageSendLog.toJson();

    try {
      final file = File(path);
      final jsonBytes = Uint8List.fromList(utf8.encode(jsonEncode(store)));
      if (_storeEncryptionKey != null) {
        // Zero-Knowledge: encrypt store with the caller-supplied key.
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
        // Plaintext fallback is refused. The previous behaviour wrote plain
        // JSON to disk if `setStoreEncryptionKey` had not yet been called
        // — exposing identity + ratchet material on any code path that
        // called saveSessionStore before initialize().
        debugPrint('[SignalProtocolService] saveSessionStore SKIPPED — '
            'no encryption key set. Caller must invoke '
            'setStoreEncryptionKey() before persisting.');
      }
    } catch (e) {
      debugPrint('[SignalProtocolService] Failed to save session store: $e');
    }
  }

  /// Set the encryption key used for session store file protection.
  /// Should be derived from device-specific secure storage.
  Uint8List? _storeEncryptionKey;

  /// Track whether the store was successfully encrypted/decrypted. Once
  /// true, plaintext fallback is permanently disabled (tamper protection).
  bool _storeWasEncrypted = false;

  /// Whether the session store has been encrypted at least once.
  bool get isStoreEncrypted => _storeWasEncrypted;

  /// Whether a store encryption key has been installed (does not require
  /// a successful save). Useful for short-circuiting setup flows once the
  /// key is in memory.
  bool get hasStoreEncryptionKey => _storeEncryptionKey != null;

  /// Mark the store as encrypted (called from session manager with persisted flag).
  void markStoreEncrypted() {
    _storeWasEncrypted = true;
  }

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
                'decryption failed — refusing plaintext fallback '
                '(tamper protection)');
            return;
          }
          // One-time migration: read legacy plaintext store, will be
          // encrypted on next save.
          final content = await file.readAsString();
          store = jsonDecode(content) as Map<String, dynamic>;
          debugPrint('[SignalProtocolService] Migrating plaintext session '
              'store to encrypted format');
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

      // Sessions deserialization with backward compat.
      // Legacy format: { "key": <single session JSON object> }
      // New format:    { "key": [<session JSON>, ...] }
      final sessionsMap = store['sessions'] as Map<String, dynamic>?;
      if (sessionsMap != null) {
        for (final entry in sessionsMap.entries) {
          final value = entry.value;
          if (value is List) {
            // New multi-session format
            _sessions[entry.key] = value
                .map((s) => DoubleRatchetSession.fromJson(
                    Map<String, dynamic>.from(s as Map)))
                .toList();
          } else if (value is Map) {
            // Legacy single-session format → wrap in list
            _sessions[entry.key] = [
              DoubleRatchetSession.fromJson(
                  Map<String, dynamic>.from(value)),
            ];
          }
        }
      }

      // Restore archived sessions + TTL expiry check.
      _archivedSessions.clear();
      final archivedMap = store['archivedSessions'] as Map<String, dynamic>?;
      if (archivedMap != null) {
        final now = DateTime.now();
        for (final entry in archivedMap.entries) {
          final entryList = entry.value as List<dynamic>;
          final validEntries = <_ArchivedSessionEntry>[];
          for (final item in entryList) {
            final map = Map<String, dynamic>.from(item as Map);
            final archivedAt = DateTime.fromMillisecondsSinceEpoch(
              map['archivedAt'] as int,
            );
            if (now.difference(archivedAt) <= _archiveTtl) {
              validEntries.add(_ArchivedSessionEntry(
                sessionJson:
                    Map<String, dynamic>.from(map['sessionJson'] as Map),
                archivedAt: archivedAt,
              ));
            }
          }
          if (validEntries.isNotEmpty) {
            _archivedSessions[entry.key] = validEntries;
          }
        }
        if (_archivedSessions.isNotEmpty) {
          final totalArchived = _archivedSessions.values
              .fold<int>(0, (sum, list) => sum + list.length);
          debugPrint('[SignalProtocolService] Restored $totalArchived archived '
              'sessions across ${_archivedSessions.length} peers');
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
        // If fromJson dropped malformed legacy entries, persist a clean
        // store on the next microtask to avoid re-entering load.
        if (_senderKeyManager.needsResave) {
          debugPrint('[SignalProtocolService] Pruned malformed sender keys '
              '— scheduling re-save');
          _senderKeyManager.needsResave = false;
          Future.microtask(() => saveSessionStore(path));
        }
      }

      // Restore remote identity keys for Sealed Sender
      final remoteIdMap =
          store['remoteIdentityKeys'] as Map<String, dynamic>?;
      if (remoteIdMap != null) {
        for (final entry in remoteIdMap.entries) {
          _remoteIdentityKeys[entry.key] =
              _hexToBytes(entry.value as String);
        }
      }

      // SKDM tracker is in-memory only — never restored from disk. Reactive
      // sender_key_request handles any cross-restart misses.
      _skdmTracker = SenderKeyDistributionTracker();

      // Message send log for retry
      final sendLogMap = store['messageSendLog'] as Map<String, dynamic>?;
      if (sendLogMap != null) {
        _messageSendLog = MessageSendLog.fromJson(sendLogMap);
      }

      final totalSessions =
          _sessions.values.fold<int>(0, (sum, list) => sum + list.length);
      debugPrint(
        '[SignalProtocolService] Loaded $totalSessions sessions across '
        '${_sessions.length} peers from store',
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
        'Ed25519 signing key not set. Call setSigningKey() or '
        'generateIdentityKeyPair() first.',
      );
    }
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

/// An archived session entry with its timestamp. Stored in
/// [SignalProtocolService._archivedSessions] for in-flight message
/// decryption after session reset. Purged after 1 hour TTL.
class _ArchivedSessionEntry {
  /// Serialized session state (from DoubleRatchetSession.toJson()). Stored
  /// as a JSON map rather than a live object to avoid holding references to
  /// mutable ratchet state. Deserialized on-demand during decrypt attempts.
  final Map<String, dynamic> sessionJson;

  /// When this session was archived. Used for TTL expiry checks.
  final DateTime archivedAt;

  _ArchivedSessionEntry({
    required this.sessionJson,
    required this.archivedAt,
  });
}

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

/// Result of [SignalProtocolService._trialDecrypt] — the session that
/// successfully decrypted plus the resulting plaintext. Caller is expected
/// to call `_markMostRecentlyUsed` with the returned session.
class _TrialDecryptResult {
  final DoubleRatchetSession session;
  final Uint8List plaintext;
  _TrialDecryptResult(this.session, this.plaintext);
}

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
