/// @file        sender_key.dart
/// @description Sender Key 프로토콜 구현. 그룹 E2EE를 위한 체인 래칫, 키 배포, 암복호화
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-04-20 (backport: SKDM chainId wire field, origin SKDM cache, removeSenderKeyForMember, needsResave, cache-msgKey-before-ratchet)
///
/// @functions
///  - SenderKeyState: Sender Key 상태 (체인 키, 반복 횟수, 서명 키)
///  - SenderKeyState.deriveMessageKey(): 체인 키에서 메시지 키 파생
///  - SenderKeyState.ratchet(): 체인 키 전진
///  - SenderKeyState.toJson(): 상태 직렬화
///  - SenderKeyState.fromJson(): 상태 역직렬화
///  - SenderKeyDistributionMessage: Sender Key 배포 메시지
///  - SenderKeyDistributionMessage.serialize(): 배포 메시지 직렬화
///  - SenderKeyDistributionMessage.deserialize(): 배포 메시지 역직렬화
///  - SenderKeyManager: Sender Key 관리자 (생성, 처리, 암복호화, 교체)
///  - SenderKeyManager.createSenderKey(): 그룹용 자체 Sender Key 생성
///  - SenderKeyManager.processSenderKey(): 수신된 Sender Key 처리
///  - SenderKeyManager.encryptGroupMessage(): 그룹 메시지 암호화
///  - SenderKeyManager.decryptGroupMessage(): 그룹 메시지 복호화
///  - SenderKeyManager.rotateSenderKey(): Sender Key 교체 (멤버 제거 시)
///  - SenderKeyManager.removeSenderKeyForMember(): 손상된 Sender Key 제거 (SKDM corrupt recovery)
///  - SenderKeyManager.toJson(): 전체 상태 직렬화
///  - SenderKeyManager.fromJson(): 전체 상태 역직렬화

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/x25519.dart' as nacl_api;
import 'package:pinenacl/ed25519.dart' as ed;

import 'hkdf.dart' show hmacSha256;
import 'logger.dart';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum group size supported by Sender Key protocol.
const int maxGroupSize = 1024;

/// Maximum number of forward-ratchet steps allowed when decrypting
/// out-of-order messages (prevents DoS via huge iteration gaps).
/// Signal uses 25,000 to support large groups with out-of-order delivery.
const int maxForwardRatchetSteps = 25000;

/// Maximum number of SenderKeyState generations to keep per sender.
/// Allows decrypting messages encrypted with previous keys during
/// key rotation transitions.
const int maxSenderKeyStates = 5;

/// Maximum number of cached message keys per SenderKeyState.
/// Prevents unbounded memory growth from out-of-order message gaps.
const int maxCachedMessageKeys = 2000;

final _rng = Random.secure();

// ---------------------------------------------------------------------------
// SenderKeyState
// ---------------------------------------------------------------------------

/// State for a single sender key (either our own or a remote member's).
///
/// Chain ratchet uses HMAC-SHA256:
/// - messageKey = HMAC(chainKey, 0x01)
/// - nextChainKey = HMAC(chainKey, 0x02)
///
/// Encryption uses XSalsa20-Poly1305 (pinenacl SecretBox).
class SenderKeyState {
  /// 31-bit random chain generation identifier.
  /// Used to distinguish different key generations after rotation.
  /// Defaults to 0 for legacy states (pre-Phase 5.2).
  final int chainId;

  /// Current chain ratchet iteration number.
  int iteration;

  /// Current 32-byte chain key.
  Uint8List chainKey;

  /// Ed25519 signing public key (used to authenticate sender).
  Uint8List signingKeyPublic;

  /// Ed25519 signing private key seed (only present for our own sender key).
  Uint8List? signingKeyPrivate;

  /// Out-of-order message key cache: iteration → derived message key.
  /// When receiving a message with a future iteration, intermediate keys
  /// are cached here for later out-of-order messages.
  final Map<int, Uint8List> cachedMessageKeys;

  SenderKeyState({
    this.chainId = 0,
    required this.iteration,
    required this.chainKey,
    required this.signingKeyPublic,
    this.signingKeyPrivate,
    Map<int, Uint8List>? cachedMessageKeys,
  }) : cachedMessageKeys = cachedMessageKeys ?? {};

  /// Derive the current message key from the chain key.
  /// messageKey = HMAC-SHA256(chainKey, 0x01)
  Uint8List deriveMessageKey() {
    return hmacSha256(chainKey, Uint8List.fromList([0x01]));
  }

  /// Advance the chain key forward by one step.
  /// nextChainKey = HMAC-SHA256(chainKey, 0x02)
  void ratchet() {
    chainKey = hmacSha256(chainKey, Uint8List.fromList([0x02]));
    iteration++;
  }

  /// Serialize state to JSON.
  Map<String, dynamic> toJson() {
    final json = <String, dynamic>{
      'chainId': chainId,
      'iteration': iteration,
      'chainKey': _bytesToHex(chainKey),
      'signingKeyPublic': _bytesToHex(signingKeyPublic),
      if (signingKeyPrivate != null)
        'signingKeyPrivate': _bytesToHex(signingKeyPrivate!),
    };
    if (cachedMessageKeys.isNotEmpty) {
      json['cachedMessageKeys'] = cachedMessageKeys.map(
        (k, v) => MapEntry(k.toString(), _bytesToHex(v)),
      );
    }
    return json;
  }

  /// Deserialize state from JSON (auto-migrates legacy without chainId).
  factory SenderKeyState.fromJson(Map<String, dynamic> json) {
    Map<int, Uint8List>? cached;
    final cachedJson = json['cachedMessageKeys'] as Map<String, dynamic>?;
    if (cachedJson != null) {
      cached = cachedJson.map(
        (k, v) => MapEntry(int.parse(k), _hexToBytes(v as String)),
      );
    }
    return SenderKeyState(
      chainId: json['chainId'] as int? ?? 0, // legacy migration: default 0
      iteration: json['iteration'] as int,
      chainKey: _hexToBytes(json['chainKey'] as String),
      signingKeyPublic: _hexToBytes(json['signingKeyPublic'] as String),
      signingKeyPrivate: json['signingKeyPrivate'] != null
          ? _hexToBytes(json['signingKeyPrivate'] as String)
          : null,
      cachedMessageKeys: cached,
    );
  }
}

// ---------------------------------------------------------------------------
// SenderKeyRecord — Multi-State Container (Phase 5.2, Signal-compliant)
// ---------------------------------------------------------------------------

/// Holds up to [maxSenderKeyStates] generations of [SenderKeyState] for a
/// single sender in a group. During key rotation, previous states are kept
/// so that in-flight messages encrypted with older keys can still be decrypted.
class SenderKeyRecord {
  final List<SenderKeyState> states;

  SenderKeyRecord({required this.states});

  /// Add a new state (newest first). Evicts oldest if over limit.
  void addState(SenderKeyState state) {
    states.insert(0, state);
    while (states.length > maxSenderKeyStates) {
      states.removeLast();
    }
  }

  /// Look up state by chainId. Returns null if not found.
  SenderKeyState? stateForChainId(int chainId) {
    for (final s in states) {
      if (s.chainId == chainId) return s;
    }
    return null;
  }

  /// Get the most recent (active) state.
  SenderKeyState get current => states.first;

  bool get isEmpty => states.isEmpty;

  Map<String, dynamic> toJson() => {
        'states': states.map((s) => s.toJson()).toList(),
      };

  /// Auto-migration: if JSON has 'states' array → new format.
  /// Otherwise → single legacy SenderKeyState wrapped in a list.
  factory SenderKeyRecord.fromJson(Map<String, dynamic> json) {
    if (json.containsKey('states')) {
      return SenderKeyRecord(
        states: (json['states'] as List)
            .map((s) => SenderKeyState.fromJson(s as Map<String, dynamic>))
            .toList(),
      );
    } else {
      // Legacy: single state → wrap in record
      return SenderKeyRecord(states: [SenderKeyState.fromJson(json)]);
    }
  }
}

// ---------------------------------------------------------------------------
// SenderKeyDistributionMessage
// ---------------------------------------------------------------------------

/// Message distributed to group members via 1:1 E2EE channels.
/// Contains the initial chain key and signing public key for a sender.
class SenderKeyDistributionMessage {
  final String groupId;
  final String senderId;

  /// 31-bit random chain generation identifier. Must match the wire chainId
  /// encoded in group message envelopes so that the receiver can pick the
  /// correct [SenderKeyState] when a sender rotates keys. Legacy SKDMs
  /// (pre-chainId) deserialize as 0.
  final int chainId;
  final int iteration;
  final Uint8List chainKey;
  final Uint8List signingKey;

  const SenderKeyDistributionMessage({
    required this.groupId,
    required this.senderId,
    required this.chainId,
    required this.iteration,
    required this.chainKey,
    required this.signingKey,
  });

  /// Serialize to bytes for distribution via 1:1 E2EE channel.
  Uint8List serialize() {
    final json = {
      'groupId': groupId,
      'senderId': senderId,
      'chainId': chainId,
      'iteration': iteration,
      'chainKey': _bytesToHex(chainKey),
      'signingKey': _bytesToHex(signingKey),
    };
    return Uint8List.fromList(utf8.encode(jsonEncode(json)));
  }

  /// Deserialize from bytes.
  factory SenderKeyDistributionMessage.deserialize(Uint8List data) {
    final json =
        jsonDecode(utf8.decode(data)) as Map<String, dynamic>;
    return SenderKeyDistributionMessage(
      groupId: json['groupId'] as String,
      senderId: json['senderId'] as String,
      // Legacy SKDMs (pre-chainId field) lack this field — fallback to 0.
      chainId: (json['chainId'] as int?) ?? 0,
      iteration: json['iteration'] as int,
      chainKey: _hexToBytes(json['chainKey'] as String),
      signingKey: _hexToBytes(json['signingKey'] as String),
    );
  }
}

// ---------------------------------------------------------------------------
// SenderKeyManager
// ---------------------------------------------------------------------------

/// Manages Sender Keys for all groups.
///
/// Each group member has a unique sender key. The key is created locally
/// and distributed to all other members via existing 1:1 E2EE channels.
///
/// Encryption is O(1) regardless of group size -- the same ciphertext
/// is sent to all recipients.
class SenderKeyManager {
  /// Sender key records. Key format: "groupId:senderId"
  /// Each record holds up to [maxSenderKeyStates] state generations.
  final Map<String, SenderKeyRecord> _senderKeys;

  /// Rotation version per group — incremented on rotateSenderKey().
  /// Used by SenderKeyDistributionTracker to detect key rotation.
  final Map<String, int> _rotationVersions;

  /// Set `true` by [SenderKeyManager.fromJson] when at least one malformed
  /// legacy entry was pruned during load. The caller (typically a session
  /// store loader) should re-save immediately to clean the disk file.
  bool needsResave = false;

  SenderKeyManager({
    Map<String, SenderKeyRecord>? senderKeys,
    Map<String, int>? rotationVersions,
  })  : _senderKeys = senderKeys ?? {},
        _rotationVersions = rotationVersions ?? {};

  /// Get current rotation version for a group (0 if never rotated).
  int getRotationVersion(String groupId) =>
      _rotationVersions[groupId] ?? 0;

  /// Create our own sender key for a group.
  ///
  /// Returns a [SenderKeyDistributionMessage] that should be sent to
  /// all group members via their 1:1 E2EE channels.
  SenderKeyDistributionMessage createSenderKey(
    String groupId,
    String myId,
  ) {
    // Reject empty owner id at the producer so state cannot accidentally
    // land at map key "$groupId:" (regression guard).
    if (myId.isEmpty) {
      throw ArgumentError(
          'createSenderKey: myId must not be empty (group $groupId)');
    }
    final chainKey = _randomBytes(32);
    final signingKey = ed.SigningKey.generate();
    final chainId = _rng.nextInt(0x7FFFFFFF); // 31-bit random

    final state = SenderKeyState(
      chainId: chainId,
      iteration: 0,
      chainKey: chainKey,
      signingKeyPublic: Uint8List.fromList(signingKey.verifyKey.toList()),
      signingKeyPrivate: Uint8List.fromList(signingKey.seed),
    );

    final key = '$groupId:$myId';
    final record = _senderKeys[key];
    if (record != null) {
      record.addState(state);
    } else {
      _senderKeys[key] = SenderKeyRecord(states: [state]);
    }

    final skdm = SenderKeyDistributionMessage(
      groupId: groupId,
      senderId: myId,
      chainId: chainId,
      iteration: 0,
      chainKey: Uint8List.fromList(chainKey),
      signingKey: Uint8List.fromList(signingKey.verifyKey.toList()),
    );

    // Cache the origin SKDM (iter=0) for future getExistingSKDM() calls.
    _originSKDMs[key] = skdm;

    return skdm;
  }

  /// Origin SKDM cache: stores the SKDM at iter=0 from createSenderKey().
  /// [getExistingSKDM] returns this instead of the advanced chain state so
  /// that receivers can decrypt messages from iteration 0 onward. Without
  /// this, a receiver getting an SKDM after messages were already sent would
  /// receive an advanced SKDM (iter=N) and fail to decrypt iter<N messages.
  final Map<String, SenderKeyDistributionMessage> _originSKDMs = {};

  /// Export the origin SKDM for distribution to group members.
  ///
  /// Returns the iter=0 snapshot captured during [createSenderKey], NOT the
  /// current advanced chain state. This ensures receivers can decrypt all
  /// messages from the beginning of this chain generation.
  SenderKeyDistributionMessage getExistingSKDM(String groupId, String myId) {
    if (myId.isEmpty) {
      throw ArgumentError(
          'getExistingSKDM: myId must not be empty (group $groupId)');
    }
    final key = '$groupId:$myId';

    // Return origin SKDM if available (preferred — covers iter=0 onward).
    final origin = _originSKDMs[key];
    if (origin != null) return origin;

    // Fallback: read current state (legacy path, before origin cache existed).
    final record = _senderKeys[key];
    if (record == null || record.isEmpty) {
      throw StateError(
          'No sender key for $groupId:$myId. Call createSenderKey() first.');
    }
    final state = record.current;
    return SenderKeyDistributionMessage(
      groupId: groupId,
      senderId: myId,
      chainId: state.chainId,
      iteration: state.iteration,
      chainKey: Uint8List.fromList(state.chainKey),
      signingKey: Uint8List.fromList(state.signingKeyPublic),
    );
  }

  /// Process a received sender key distribution message from another member.
  ///
  /// Replay protection: rejects duplicate SKDMs within the same chain
  /// generation. A new [chainId] triggers an unconditional state replacement
  /// to support key rotation.
  void processSenderKey(SenderKeyDistributionMessage message) {
    // Reject SKDMs from peers running a buggy build that distributed an
    // empty senderId. Without this guard we would accept garbage entries.
    if (message.senderId.isEmpty) {
      debugPrint('[SenderKey] Rejecting SKDM with empty senderId '
          '(group ${message.groupId})');
      return;
    }
    final key = '${message.groupId}:${message.senderId}';
    final newState = SenderKeyState(
      // Propagate chainId from SKDM so receiver state matches the wire
      // chainId emitted by the sender. Without this, legacy SKDMs default
      // to 0 → mismatch → permanent decrypt failure.
      chainId: message.chainId,
      iteration: message.iteration,
      chainKey: Uint8List.fromList(message.chainKey),
      signingKeyPublic: Uint8List.fromList(message.signingKey),
      signingKeyPrivate: null, // Remote keys: no private key
    );

    final record = _senderKeys[key];
    if (record != null) {
      // Replay protection only applies WITHIN the same chain generation. A
      // different chainId means the sender rotated (or we are migrating from
      // a legacy chainId=0 state to a real one) — accept unconditionally so
      // stale chainId=0 records cannot block new SKDMs forever.
      if (record.current.chainId == message.chainId) {
        // Same chainId == we already have this exact generation. Adding a
        // duplicate state with empty cachedMessageKeys would shadow the
        // populated older one (decrypt iterates newest→oldest) and break
        // out-of-order messages. Drop duplicates unconditionally.
        debugPrint('[SenderKey] Ignoring duplicate SKDM (same chainId '
            '${message.chainId}): incoming iter=${message.iteration}, '
            'current iter=${record.current.iteration}');
        return;
      } else {
        debugPrint('[SenderKey] chainId rotation detected '
            'old=${record.current.chainId} new=${message.chainId} '
            '— replacing record (legacy migration / sender key rotation)');
        // Drop legacy chainId=0 entries entirely so the decrypt loop does
        // not waste time trying them. Real rotations (both chainIds
        // non-zero) keep history for in-flight messages.
        if (record.current.chainId == 0) {
          record.states.clear();
        }
      }
      record.addState(newState);
    } else {
      _senderKeys[key] = SenderKeyRecord(states: [newState]);
    }
  }

  /// Encrypt a message with our own sender key for the group.
  ///
  /// Returns the wire bytes:
  /// `[version(1)][chainId(4 BE)][iteration(4 BE)][sig(64)][ct]`
  Uint8List encryptGroupMessage(
    String groupId,
    String myId,
    Uint8List plaintext,
  ) {
    if (myId.isEmpty) {
      throw ArgumentError(
          'encryptGroupMessage: myId must not be empty (group $groupId)');
    }
    final key = '$groupId:$myId';
    final record = _senderKeys[key];
    if (record == null || record.isEmpty) {
      throw StateError(
        'No sender key for group $groupId. Call createSenderKey() first.',
      );
    }
    final state = record.current;
    if (state.signingKeyPrivate == null) {
      throw StateError(
        'Cannot encrypt with a remote sender key (no private key).',
      );
    }

    // Derive message key and encrypt
    final messageKey = state.deriveMessageKey();
    final ciphertext = _encrypt(messageKey, plaintext);

    // Sign the ciphertext for authentication
    final signingKey = ed.SigningKey.fromSeed(state.signingKeyPrivate!);
    final signature = signingKey.sign(ciphertext);
    final signatureBytes =
        Uint8List.fromList(signature.sublist(0, ed.Signature.signatureLength));

    // Build output v3: [version(1)][chainId(4 BE)][iteration(4 BE)][sig(64)][ct]
    final chainIdBytes = _int32ToBE(state.chainId);
    final iterBytes = _int32ToBE(state.iteration);
    final output = Uint8List(1 + 4 + 4 + 64 + ciphertext.length);
    output[0] = _wireFormatVersion;
    output.setAll(1, chainIdBytes);
    output.setAll(5, iterBytes);
    output.setAll(9, signatureBytes);
    output.setAll(73, ciphertext);

    // Advance the chain
    state.ratchet();

    return output;
  }

  /// Decrypt a group message using the sender's key.
  /// Tries the most recent state first, then falls back to older generations.
  Uint8List decryptGroupMessage(
    String groupId,
    String senderId,
    Uint8List data,
  ) {
    final key = '$groupId:$senderId';
    final record = _senderKeys[key];
    if (record == null || record.isEmpty) {
      throw StateError(
        'No sender key for $senderId in group $groupId. '
        'Sender key distribution message not yet received.',
      );
    }

    // Version-aware parsing:
    // v3: [version(1)=3][chainId(4 BE)][iteration(4 BE)][sig(64)][ct]  min 73+
    // v1: [iteration(4 LE)][sig(64)][ct]  min 68+
    int messageIteration;
    int messageChainId;
    Uint8List signature;
    Uint8List ciphertext;

    if (data.length > 73 && data[0] == _wireFormatVersion) {
      // v3 format
      messageChainId = _beToInt32(data.sublist(1, 5));
      messageIteration = _beToInt32(data.sublist(5, 9));
      signature = data.sublist(9, 73);
      ciphertext = data.sublist(73);
    } else if (data.length >= 68) {
      // v1 legacy format
      messageChainId = 0; // legacy has no chainId
      messageIteration = _leToInt32(data.sublist(0, 4));
      signature = data.sublist(4, 68);
      ciphertext = data.sublist(68);
    } else {
      throw ArgumentError('Invalid group message: too short (${data.length})');
    }

    // Try each state generation (newest first). Capture the last error so we
    // can report what actually failed when all states are exhausted.
    Object? lastError;
    for (final state in record.states) {
      try {
        // Verify signature with this state's key
        final verifyKey = ed.VerifyKey(state.signingKeyPublic);
        verifyKey.verify(
          signature: ed.Signature(signature),
          message: ciphertext,
        );

        // Signature matches this state — decrypt with it.
        // Check for out-of-order (past message).
        if (messageIteration < state.iteration) {
          // Try cached message key (kept on read for drift-retry safety;
          // evicted by the 2000-cap, not by consume-on-use).
          final cachedKey = state.cachedMessageKeys[messageIteration];
          if (cachedKey != null) {
            return _decrypt(cachedKey, ciphertext);
          }
          throw StateError(
            'Message iteration $messageIteration behind ${state.iteration}, '
            'no cached key available.',
          );
        }

        final steps = messageIteration - state.iteration;
        if (steps > maxForwardRatchetSteps) {
          throw StateError(
            'Too many forward ratchet steps ($steps > $maxForwardRatchetSteps)',
          );
        }

        // Cache intermediate keys for out-of-order messages.
        while (state.iteration < messageIteration) {
          state.cachedMessageKeys[state.iteration] = state.deriveMessageKey();
          state.ratchet();
          // Evict oldest cached keys when cap is exceeded
          while (state.cachedMessageKeys.length > maxCachedMessageKeys) {
            state.cachedMessageKeys.remove(state.cachedMessageKeys.keys.first);
          }
        }

        // Derive message key and decrypt
        final messageKey = state.deriveMessageKey();
        final plaintext = _decrypt(messageKey, ciphertext);

        // Cache current message key BEFORE ratcheting (drift-retry safety).
        // If the caller's durable INSERT fails after this decrypt returns,
        // the retry attempt hits the "messageIteration < state.iteration"
        // branch and finds this cached key instead of throwing "no cached
        // key".
        state.cachedMessageKeys[state.iteration] =
            Uint8List.fromList(messageKey);
        while (state.cachedMessageKeys.length > maxCachedMessageKeys) {
          state.cachedMessageKeys.remove(state.cachedMessageKeys.keys.first);
        }

        // Advance chain past this message
        state.ratchet();
        return plaintext;
      } catch (e) {
        lastError = e;
        continue; // Try next state generation
      }
    }

    throw StateError(
      'Failed to decrypt group message from $senderId in $groupId '
      'with any of ${record.states.length} key states. '
      'Message wire iter=$messageIteration chainId=$messageChainId. '
      'Last error: $lastError',
    );
  }

  /// Rotate the sender key for a group (called when a member is removed).
  ///
  /// Creates a completely new sender key that must be redistributed to all
  /// remaining members via 1:1 E2EE. Previous states are KEPT (up to
  /// [maxSenderKeyStates]) so in-flight messages encrypted with the old key
  /// can still be decrypted; [createSenderKey] → [SenderKeyRecord.addState]
  /// handles the cap automatically.
  SenderKeyDistributionMessage rotateSenderKey(
    String groupId,
    String myId,
  ) {
    if (myId.isEmpty) {
      throw ArgumentError(
          'rotateSenderKey: myId must not be empty (group $groupId)');
    }
    // Increment rotation version so Tracker knows to re-distribute
    _rotationVersions[groupId] = (_rotationVersions[groupId] ?? 0) + 1;
    return createSenderKey(groupId, myId);
  }

  /// Remove all sender keys for a group (e.g., when leaving).
  void removeGroup(String groupId) {
    _senderKeys.removeWhere(
      (key, _) => key.startsWith('$groupId:'),
    );
    // Clean associated caches: origin SKDMs + rotation version
    _originSKDMs.removeWhere(
      (key, _) => key.startsWith('$groupId:'),
    );
    _rotationVersions.remove(groupId);
  }

  /// Remove the corrupt sender key for a specific member in a group.
  ///
  /// Called when we hold an SKDM for the sender but decryption still fails
  /// (ratchet desync, state corruption, etc.). After removal, a fresh SKDM
  /// request is typically sent and the message is parked until the new SKDM
  /// arrives. This breaks the permanent decrypt failure loop where a stale
  /// or corrupt state blocks all future messages from the sender.
  void removeSenderKeyForMember(String groupId, String senderId) {
    final key = '$groupId:$senderId';
    final removed = _senderKeys.remove(key);
    debugPrint('[SenderKeyManager] removeSenderKeyForMember: $key '
        '(removed=${removed != null})');
  }

  /// Check if we have a sender key for a specific member in a group.
  bool hasSenderKey(String groupId, String senderId) {
    final record = _senderKeys['$groupId:$senderId'];
    return record != null && !record.isEmpty;
  }

  /// Serialize all sender key state to JSON.
  Map<String, dynamic> toJson() {
    final map = <String, dynamic>{};
    for (final entry in _senderKeys.entries) {
      map[entry.key] = entry.value.toJson();
    }
    map['_rotationVersions'] = _rotationVersions;
    // Persist origin SKDMs so getExistingSKDM() survives app restart.
    final originMap = <String, Map<String, dynamic>>{};
    for (final entry in _originSKDMs.entries) {
      originMap[entry.key] = {
        'groupId': entry.value.groupId,
        'senderId': entry.value.senderId,
        'chainId': entry.value.chainId,
        'iteration': entry.value.iteration,
        'chainKey': base64Encode(entry.value.chainKey),
        'signingKey': base64Encode(entry.value.signingKey),
      };
    }
    map['_originSKDMs'] = originMap;
    return map;
  }

  /// Deserialize sender key state from JSON (auto-migrates legacy format).
  ///
  /// Drops malformed legacy entries whose key is `"<groupId>:"` (empty
  /// senderId). When any entries are dropped, sets [needsResave] so the
  /// caller can immediately persist a clean store.
  factory SenderKeyManager.fromJson(Map<String, dynamic> json) {
    final keys = <String, SenderKeyRecord>{};
    Map<String, int>? rotationVersions;
    bool dropped = false;
    for (final entry in json.entries) {
      if (entry.key == '_rotationVersions') {
        rotationVersions = Map<String, int>.from(entry.value as Map);
        continue;
      }
      // Skip origin SKDMs — deserialized separately below.
      if (entry.key == '_originSKDMs') continue;
      // Validate map key shape: must be "groupId:senderId" with non-empty
      // senderId. Drop malformed entries silently (regression artifact).
      final colonIdx = entry.key.indexOf(':');
      if (colonIdx == -1 || colonIdx == entry.key.length - 1) {
        debugPrint('[SenderKey] Dropping malformed key on load: '
            '"${entry.key}" (empty senderId)');
        dropped = true;
        continue;
      }
      // SenderKeyRecord.fromJson handles both legacy (single state) and new
      // format (states array) automatically.
      keys[entry.key] = SenderKeyRecord.fromJson(
          entry.value as Map<String, dynamic>);
    }
    final mgr = SenderKeyManager(
      senderKeys: keys,
      rotationVersions: rotationVersions,
    );
    mgr.needsResave = dropped;

    // Restore origin SKDMs
    final originRaw = json['_originSKDMs'] as Map<String, dynamic>?;
    if (originRaw != null) {
      for (final entry in originRaw.entries) {
        final v = entry.value as Map<String, dynamic>;
        mgr._originSKDMs[entry.key] = SenderKeyDistributionMessage(
          groupId: v['groupId'] as String,
          senderId: v['senderId'] as String,
          chainId: v['chainId'] as int,
          iteration: v['iteration'] as int,
          chainKey: base64Decode(v['chainKey'] as String),
          signingKey: base64Decode(v['signingKey'] as String),
        );
      }
    }

    return mgr;
  }
}

// =============================================================================
// Symmetric encryption (XSalsa20-Poly1305 via pinenacl SecretBox)
// =============================================================================

/// Encrypt [plaintext] with [messageKey] using XSalsa20-Poly1305.
/// Returns nonce (24 bytes) || ciphertext+tag.
Uint8List _encrypt(Uint8List messageKey, Uint8List plaintext) {
  final box = nacl_api.SecretBox(messageKey);
  final nonce = Uint8List(nacl_api.EncryptedMessage.nonceLength);
  for (var i = 0; i < nonce.length; i++) {
    nonce[i] = _rng.nextInt(256);
  }
  final encrypted = box.encrypt(plaintext, nonce: nonce);
  return Uint8List.fromList(encrypted.toList());
}

/// Decrypt [ciphertextWithNonce] with [messageKey] using XSalsa20-Poly1305.
Uint8List _decrypt(Uint8List messageKey, Uint8List ciphertextWithNonce) {
  final box = nacl_api.SecretBox(messageKey);
  final decrypted = box.decrypt(
    nacl_api.EncryptedMessage(
      nonce: ciphertextWithNonce.sublist(0, nacl_api.EncryptedMessage.nonceLength),
      cipherText: ciphertextWithNonce.sublist(nacl_api.EncryptedMessage.nonceLength),
    ),
  );
  return Uint8List.fromList(decrypted.toList());
}

// =============================================================================
// Utility
// =============================================================================

Uint8List _randomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _rng.nextInt(256);
  }
  return bytes;
}

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

/// Decode 4 little-endian bytes to a 32-bit integer (legacy v1 parsing).
int _leToInt32(Uint8List bytes) {
  return bytes[0] |
      (bytes[1] << 8) |
      (bytes[2] << 16) |
      (bytes[3] << 24);
}

/// Encode a 32-bit integer as 4 big-endian bytes (Signal wire format v3).
Uint8List _int32ToBE(int value) {
  return Uint8List(4)
    ..[0] = (value >> 24) & 0xFF
    ..[1] = (value >> 16) & 0xFF
    ..[2] = (value >> 8) & 0xFF
    ..[3] = value & 0xFF;
}

/// Decode 4 big-endian bytes to a 32-bit integer.
int _beToInt32(Uint8List bytes) {
  return (bytes[0] << 24) |
      (bytes[1] << 16) |
      (bytes[2] << 8) |
      bytes[3];
}

/// Wire format version for Sender Key messages.
const int _wireFormatVersion = 3;
