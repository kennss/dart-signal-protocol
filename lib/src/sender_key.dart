/// @file        sender_key.dart
/// @description Sender Key protocol, wire format v4 (backport of SnowChat
///              966a884 / f137f43): chain ratchet, key distribution message
///              and encrypt/decrypt where the signature covers a 32-byte
///              binding supplied by the caller (a hash that ties the message
///              to its transport context) and the message's own header. A
///              message key reads one message; a message that does not open
///              leaves the chain where it was; every signature is strict
///              Ed25519.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-11-23 (wire format v4 only — the v3 / v1 formats, rotation versions, the
///              origin-SKDM cache, needsResave and the legacy record formats are gone; the SKDM is
///              a fixed 72-byte body whose group and sender come from the caller's authenticated
///              context; strict Ed25519; English-only comments). Earlier 2026-04-20 (backport:
///              SKDM chainId wire field, origin SKDM cache, removeSenderKeyForMember, needsResave,
///              cache-msgKey-before-ratchet)
///
/// @functions
///  - senderKeyMessageLength(): Length of a Sender Key message for a plaintext length
///  - SenderKeyException / SenderKeyFailure: Why a message could not be read
///  - SenderKeyState: Sender Key state (chain key, iteration, signing key, cached message keys)
///  - SenderKeyState.deriveMessageKey() / ratchet(): the chain ratchet
///  - SenderKeyRecord: up to five chains of one sender
///  - SenderKeyDistributionMessage: a sender's key at a position of its chain
///  - SenderKeyDistributionMessage.serialize() / deserialize(): the 72-byte body
///  - SenderKeyManager.createSenderKey(): Create our own Sender Key for a group
///  - SenderKeyManager.processSenderKey(): Install a received Sender Key
///  - SenderKeyManager.encryptBoundGroupMessage(): Encrypt a message bound to its context
///  - SenderKeyManager.decryptBoundGroupMessage(): Decrypt a message, failing with a SenderKeyFailure
///  - SenderKeyManager.hasSenderKey(): Whether a key of a sender is held
///  - SenderKeyManager.removeSenderKeyForMember() / removeGroup(): drop keys
///  - SenderKeyManager.toJson() / fromJson(): The records, by "groupId:senderId"
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;
import 'package:pinenacl/x25519.dart' as nacl_api;

import 'ed25519_strict.dart';
import 'hkdf.dart' show hmacSha256;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of forward-ratchet steps allowed when decrypting
/// out-of-order messages (prevents DoS via huge iteration gaps).
/// Signal uses 25,000 to support large groups with out-of-order delivery.
const int maxForwardRatchetSteps = 25000;

/// Maximum number of chains (SenderKeyState) kept per sender: a new own chain
/// after a member left still lets messages of the earlier one be read.
const int maxSenderKeyStates = 5;

/// Maximum number of cached message keys per SenderKeyState.
/// Prevents unbounded memory growth from out-of-order message gaps.
const int maxCachedMessageKeys = 2000;

/// The Sender Key wire format (the only one since 0.4.0): the signature
/// covers a 32-byte binding supplied by the caller, the message's own
/// version, chain id and iteration, and the ciphertext.
///
/// Without the binding, anyone who can wrap a group message in a transport
/// envelope (every member, every former member, and in many designs the
/// server) could re-wrap someone else's message under a new header (a new
/// message id, another conversation) and have it accepted; without the
/// chain id and the iteration under the signature they could push a
/// receiver's copy of the chain forward past messages still in flight.
const int senderKeyWireV4 = 4;

/// Length of the binding a v4 signature covers.
const int senderKeyBindingLength = 32;

/// version(1) + chainId(4) + iteration(4) + signature(64).
const int _messageHeaderLength = 73;

/// Bytes a Sender Key message adds to its plaintext: the header above, the
/// 24-byte nonce and the 16-byte authentication tag.
const int senderKeyMessageOverhead = _messageHeaderLength + 24 + 16;

/// Length of a serialized [SenderKeyDistributionMessage]:
/// chainId(4) + iteration(4) + chainKey(32) + signingKey(32).
const int senderKeyDistributionLength = 72;

/// Length of the Sender Key message for a plaintext of [plaintextLength]
/// bytes. A sender that signs the message length into its own transport
/// header (and so into the binding) needs it before encrypting.
int senderKeyMessageLength(int plaintextLength) =>
    senderKeyMessageOverhead + plaintextLength;

/// Domain separation of the v4 signature: no other signature of the
/// protocol starts with this byte and label. The label is byte-identical to
/// the SnowChat reference implementation (see README, Known Risks: the
/// labels are hardcoded `SnowChat_*`).
const int _boundSignaturePrefix = 0xfe;
final Uint8List _boundSignatureLabel =
    Uint8List.fromList(ascii.encode('SnowChat_GV2_Msg_v1'));

final Uint8List _messageKeyInput = Uint8List.fromList([0x01]);
final Uint8List _chainKeyInput = Uint8List.fromList([0x02]);

/// Largest chain id (31-bit) and iteration (32-bit) the wire format carries.
const int _maxChainId = 0x7FFFFFFF;
const int _maxIteration = 0xFFFFFFFF;

final _rng = Random.secure();

/// Why a Sender Key message could not be read.
enum SenderKeyFailure {
  /// Not a v4 Sender Key message.
  malformed,

  /// No key of this sender, or none for the chain the message names. The
  /// claim is not authenticated — there is no key to check it with.
  noKey,

  /// The signature does not verify. The key is kept: anyone who can deliver
  /// a message can produce such a message, and must not thereby make a
  /// receiver throw away a good key.
  signature,

  /// The chain has moved past this message and its key is no longer cached
  /// (or the message was already read: a key reads one message).
  expired,

  /// The message is more than [maxForwardRatchetSteps] ahead of the chain.
  tooFarAhead,

  /// Signed by the sender, but the ciphertext does not open.
  decrypt,
}

/// A Sender Key message that could not be read. The key state is unchanged.
class SenderKeyException implements Exception {
  final SenderKeyFailure reason;
  final String message;

  const SenderKeyException(this.reason, this.message);

  @override
  String toString() => 'SenderKeyException(${reason.name}): $message';
}

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
  /// 31-bit random chain identifier: a message names the chain it was sent
  /// on, and the receiver finds the state by it.
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
    required this.chainId,
    required this.iteration,
    required this.chainKey,
    required this.signingKeyPublic,
    this.signingKeyPrivate,
    Map<int, Uint8List>? cachedMessageKeys,
  }) : cachedMessageKeys = cachedMessageKeys ?? {};

  /// Derive the current message key from the chain key.
  /// messageKey = HMAC-SHA256(chainKey, 0x01)
  Uint8List deriveMessageKey() => hmacSha256(chainKey, _messageKeyInput);

  /// Advance the chain key forward by one step.
  /// nextChainKey = HMAC-SHA256(chainKey, 0x02)
  void ratchet() {
    chainKey = hmacSha256(chainKey, _chainKeyInput);
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

  /// Deserialize state from JSON. Throws on a malformed entry.
  factory SenderKeyState.fromJson(Map<String, dynamic> json) {
    Map<int, Uint8List>? cached;
    final cachedJson = json['cachedMessageKeys'] as Map<String, dynamic>?;
    if (cachedJson != null) {
      cached = cachedJson.map(
        (k, v) => MapEntry(int.parse(k), _hexToBytes(v as String)),
      );
    }
    return SenderKeyState(
      chainId: json['chainId'] as int,
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
// SenderKeyRecord — the chains of one sender
// ---------------------------------------------------------------------------

/// Holds up to [maxSenderKeyStates] chains ([SenderKeyState]) of one sender
/// in one group, newest first. When the sender starts a new chain, the
/// earlier ones stay so that messages still in flight can be read.
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

  factory SenderKeyRecord.fromJson(Map<String, dynamic> json) =>
      SenderKeyRecord(
        states: (json['states'] as List)
            .map((s) => SenderKeyState.fromJson(s as Map<String, dynamic>))
            .toList(),
      );
}

// ---------------------------------------------------------------------------
// SenderKeyDistributionMessage
// ---------------------------------------------------------------------------

/// A sender's key at one position of its chain: what a member is given,
/// over an authenticated pairwise channel (a 1:1 Double Ratchet / Sealed
/// Sender message).
///
/// Wire form ([serialize]): chainId(u32 BE) ‖ iteration(u32 BE) ‖
/// chainKey(32) ‖ signingKey(32) — 72 bytes, the same body the SnowChat
/// reference carries. The group and the sender are deliberately NOT in it:
/// the receiver takes them from its own authenticated context (the session
/// the message arrived on, the conversation it belongs to), so a member
/// cannot install a key under another member's name.
class SenderKeyDistributionMessage {
  final String groupId;
  final String senderId;

  /// The chain the key belongs to (the chain id a message names).
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

  /// The 72-byte body. Throws [ArgumentError] when a field does not fit.
  Uint8List serialize() {
    if (chainId < 0 || chainId > _maxChainId) {
      throw ArgumentError('SenderKeyDistributionMessage: chainId out of range');
    }
    if (iteration < 0 || iteration > _maxIteration) {
      throw ArgumentError(
          'SenderKeyDistributionMessage: iteration out of range');
    }
    if (chainKey.length != 32 || signingKey.length != 32) {
      throw ArgumentError('SenderKeyDistributionMessage: keys must be 32 bytes');
    }
    final out = Uint8List(senderKeyDistributionLength);
    final view = ByteData.sublistView(out);
    view.setUint32(0, chainId, Endian.big);
    view.setUint32(4, iteration, Endian.big);
    out
      ..setAll(8, chainKey)
      ..setAll(40, signingKey);
    return out;
  }

  /// The message of [bytes] for [senderId] in [groupId] — both taken from
  /// the caller's authenticated context, never from the bytes. Null when
  /// [bytes] is not exactly a 72-byte body with a 31-bit chain id.
  static SenderKeyDistributionMessage? deserialize(
    Uint8List bytes, {
    required String groupId,
    required String senderId,
  }) {
    if (bytes.length != senderKeyDistributionLength) return null;
    final view = ByteData.sublistView(bytes);
    final chainId = view.getUint32(0, Endian.big);
    if (chainId > _maxChainId) return null;
    return SenderKeyDistributionMessage(
      groupId: groupId,
      senderId: senderId,
      chainId: chainId,
      iteration: view.getUint32(4, Endian.big),
      chainKey: Uint8List.fromList(bytes.sublist(8, 40)),
      signingKey: Uint8List.fromList(bytes.sublist(40, 72)),
    );
  }
}

// ---------------------------------------------------------------------------
// SenderKeyManager
// ---------------------------------------------------------------------------

/// Holds Sender Key records and reads, writes and makes keys with them. Key
/// format of the records: "groupId:senderId". The caller persists the
/// records ([toJson] / [SenderKeyManager.fromJson]) — they are not part of
/// the SignalProtocolService session store.
///
/// Encryption is O(1) regardless of group size — the same ciphertext is
/// sent to all recipients.
///
/// The key of a message that was read is not kept, so the same message
/// cannot be read a second time — a replayed message fails as `expired`.
/// Persist the records in the same transaction as the plaintext a read
/// produced: there is no kept key to retry from.
class SenderKeyManager {
  final Map<String, SenderKeyRecord> _senderKeys;

  SenderKeyManager({Map<String, SenderKeyRecord>? senderKeys})
      : _senderKeys = senderKeys ?? {};

  /// Create our own sender key for a group: a new chain, at position 0.
  /// Earlier own chains stay (up to [maxSenderKeyStates]). Call it again
  /// (and distribute the result) whenever a member leaves, so the departed
  /// member cannot read later messages.
  SenderKeyDistributionMessage createSenderKey(
    String groupId,
    String myId,
  ) {
    if (myId.isEmpty) {
      throw ArgumentError(
          'createSenderKey: myId must not be empty (group $groupId)');
    }
    final chainKey = _randomBytes(32);
    final signingKey = ed.SigningKey.generate();
    final chainId = _rng.nextInt(_maxChainId); // 31-bit random

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

    return SenderKeyDistributionMessage(
      groupId: groupId,
      senderId: myId,
      chainId: chainId,
      iteration: 0,
      chainKey: Uint8List.fromList(chainKey),
      signingKey: Uint8List.fromList(signingKey.verifyKey.toList()),
    );
  }

  /// Install a received key of another member.
  ///
  /// A chain already held is never replaced — not by an earlier position of
  /// it either (a second copy would start with an empty key cache and be
  /// found first). Returns true when the key is held afterwards (installed
  /// now, or already there), false when the message was refused: an empty
  /// sender, a field out of range, or a signing key that is not a strict
  /// Ed25519 key (such a key can never verify a message; installed, it
  /// would only sit in front of a good one).
  bool processSenderKey(SenderKeyDistributionMessage message) {
    if (message.senderId.isEmpty) return false;
    if (message.chainKey.length != 32 ||
        message.signingKey.length != 32 ||
        message.iteration < 0 ||
        message.iteration > _maxIteration ||
        message.chainId < 0 ||
        message.chainId > _maxChainId ||
        !isAcceptableEd25519PublicKey(message.signingKey)) {
      return false;
    }
    final key = '${message.groupId}:${message.senderId}';
    final newState = SenderKeyState(
      chainId: message.chainId,
      iteration: message.iteration,
      chainKey: Uint8List.fromList(message.chainKey),
      signingKeyPublic: Uint8List.fromList(message.signingKey),
    );

    final record = _senderKeys[key];
    if (record == null) {
      _senderKeys[key] = SenderKeyRecord(states: [newState]);
    } else if (record.stateForChainId(message.chainId) == null) {
      record.addState(newState);
    }
    return true;
  }

  /// Encrypt a message with our own sender key for the group.
  ///
  /// [binding] is the 32-byte hash that ties the message to its context,
  /// computed identically by sender and receivers — e.g. `sha256(groupId ‖
  /// transport header)` where the header names the message id (and, if it
  /// carries one, the message length: see [senderKeyMessageLength]). Use at
  /// least `sha256(groupId)`. A receiver that computes another binding
  /// refuses the message ([SenderKeyFailure.signature]).
  ///
  /// Layout: [version(1)=4][chainId(4 BE)][iteration(4 BE)][sig(64)][ct].
  /// Signed: 0xFE ‖ "SnowChat_GV2_Msg_v1" ‖ binding ‖ version ‖ chainId ‖
  /// iteration ‖ ct.
  ///
  /// [nonce] fixes the 24-byte nonce of the ciphertext — for golden test
  /// vectors only; production code must not pass it. Without it a fresh
  /// random nonce is drawn.
  Uint8List encryptBoundGroupMessage(
    String groupId,
    String myId,
    Uint8List plaintext,
    Uint8List binding, {
    Uint8List? nonce,
  }) {
    if (myId.isEmpty) {
      throw ArgumentError('encryptBoundGroupMessage: myId must not be empty');
    }
    if (binding.length != senderKeyBindingLength) {
      throw ArgumentError(
          'encryptBoundGroupMessage: binding must be $senderKeyBindingLength '
          'bytes');
    }
    final record = _senderKeys['$groupId:$myId'];
    if (record == null || record.isEmpty) {
      throw StateError('No sender key. Call createSenderKey() first.');
    }
    final state = record.current;
    if (state.signingKeyPrivate == null) {
      throw StateError(
          'Cannot encrypt with a remote sender key (no private key).');
    }
    if (state.iteration > _maxIteration) {
      throw StateError(
          'Sender key chain exhausted. Call createSenderKey() for a new one.');
    }

    final ciphertext =
        _encrypt(state.deriveMessageKey(), plaintext, nonce: nonce);
    final header = Uint8List(9)
      ..[0] = senderKeyWireV4
      ..setAll(1, _int32ToBE(state.chainId))
      ..setAll(5, _int32ToBE(state.iteration));
    final signature = ed.SigningKey.fromSeed(state.signingKeyPrivate!)
        .sign(_boundSignedBytes(binding, header, ciphertext))
        .signature;

    final output = Uint8List(_messageHeaderLength + ciphertext.length)
      ..setAll(0, header)
      ..setAll(9, signature)
      ..setAll(_messageHeaderLength, ciphertext);

    state.ratchet();
    return output;
  }

  /// Decrypt a message from [senderId], bound to [binding] (see
  /// [encryptBoundGroupMessage]).
  ///
  /// Throws [SenderKeyException]; the reason tells the caller what to do
  /// next (ask for the key, drop the message, ...). Whatever the reason, the
  /// stored key is neither changed nor removed.
  ///
  /// The caller decides whose messages to read at all: [senderId] must come
  /// from the caller's authenticated context and already be known as a
  /// member of the group.
  Uint8List decryptBoundGroupMessage(
    String groupId,
    String senderId,
    Uint8List data,
    Uint8List binding,
  ) {
    if (binding.length != senderKeyBindingLength) {
      throw ArgumentError(
          'decryptBoundGroupMessage: binding must be $senderKeyBindingLength '
          'bytes');
    }
    if (data.length < senderKeyMessageOverhead ||
        data[0] != senderKeyWireV4) {
      throw const SenderKeyException(
          SenderKeyFailure.malformed, 'Not a v4 Sender Key message.');
    }
    final record = _senderKeys['$groupId:$senderId'];
    final state = record?.stateForChainId(_beToInt32(data.sublist(1, 5)));
    if (state == null) {
      throw const SenderKeyException(
          SenderKeyFailure.noKey, 'No sender key for this chain.');
    }

    final header = Uint8List.sublistView(data, 0, 9);
    final signature = Uint8List.fromList(data.sublist(9, _messageHeaderLength));
    final ciphertext = Uint8List.fromList(data.sublist(_messageHeaderLength));
    if (!verifyEd25519Strict(state.signingKeyPublic,
        _boundSignedBytes(binding, header, ciphertext), signature)) {
      throw const SenderKeyException(
          SenderKeyFailure.signature, 'The signature does not verify.');
    }
    return _open(state, _beToInt32(data.sublist(5, 9)), ciphertext);
  }

  /// Reads [ciphertext], sent at [messageIteration] of the chain of [state].
  ///
  /// The state changes only when the ciphertext opens: the keys of the
  /// iterations skipped on the way are cached, a cached key that read its
  /// message is dropped, and the chain moves one past the message. A message
  /// that does not open leaves the chain where it was.
  Uint8List _open(
    SenderKeyState state,
    int messageIteration,
    Uint8List ciphertext,
  ) {
    // Out-of-order (past) message.
    if (messageIteration < state.iteration) {
      final cachedKey = state.cachedMessageKeys[messageIteration];
      if (cachedKey == null) {
        throw SenderKeyException(
          SenderKeyFailure.expired,
          'Message iteration $messageIteration behind ${state.iteration}, '
          'no cached key available.',
        );
      }
      final plaintext = _decryptOrFail(cachedKey, ciphertext);
      // A key reads one message. (Only once it has: a message that does not
      // open leaves the state as it was.)
      state.cachedMessageKeys.remove(messageIteration);
      return plaintext;
    }

    final steps = messageIteration - state.iteration;
    if (steps > maxForwardRatchetSteps) {
      throw SenderKeyException(
        SenderKeyFailure.tooFarAhead,
        'Too many forward ratchet steps ($steps > $maxForwardRatchetSteps)',
      );
    }

    // Walk a copy of the chain to the message.
    var chainKey = state.chainKey;
    final skipped = <int, Uint8List>{};
    for (var i = state.iteration; i < messageIteration; i++) {
      skipped[i] = hmacSha256(chainKey, _messageKeyInput);
      chainKey = hmacSha256(chainKey, _chainKeyInput);
    }
    final messageKey = hmacSha256(chainKey, _messageKeyInput);
    final plaintext = _decryptOrFail(messageKey, ciphertext);

    // Cache the keys of the skipped iterations for messages still in
    // flight (not the key of this message — it reads one message). The cap
    // bounds memory.
    state.cachedMessageKeys.addAll(skipped);
    while (state.cachedMessageKeys.length > maxCachedMessageKeys) {
      state.cachedMessageKeys.remove(state.cachedMessageKeys.keys.first);
    }

    // Advance chain past this message.
    state.chainKey = hmacSha256(chainKey, _chainKeyInput);
    state.iteration = messageIteration + 1;
    return plaintext;
  }

  /// Check if we have a sender key for a specific member in a group.
  bool hasSenderKey(String groupId, String senderId) {
    final record = _senderKeys['$groupId:$senderId'];
    return record != null && !record.isEmpty;
  }

  /// Drop every chain of [senderId] in [groupId] (a member left, or its key
  /// must be fetched again).
  void removeSenderKeyForMember(String groupId, String senderId) {
    _senderKeys.remove('$groupId:$senderId');
  }

  /// Drop every key of [groupId] (ours and the members').
  void removeGroup(String groupId) {
    final prefix = '$groupId:';
    _senderKeys.removeWhere((k, _) => k.startsWith(prefix));
  }

  /// The records, by "groupId:senderId" (each [SenderKeyRecord.toJson]).
  /// Holds our own signing seeds and chain keys: persist it encrypted.
  Map<String, dynamic> toJson() => {
        for (final entry in _senderKeys.entries)
          entry.key: entry.value.toJson(),
      };

  /// The manager of [json] ([toJson]). Throws [FormatException] on an
  /// entry whose key is not "groupId:senderId" with a non-empty sender, or
  /// whose record does not decode.
  factory SenderKeyManager.fromJson(Map<String, dynamic> json) {
    final keys = <String, SenderKeyRecord>{};
    for (final entry in json.entries) {
      final colon = entry.key.lastIndexOf(':');
      if (colon < 0 || colon == entry.key.length - 1) {
        throw const FormatException('SenderKeyManager: bad record key');
      }
      try {
        keys[entry.key] =
            SenderKeyRecord.fromJson(entry.value as Map<String, dynamic>);
      } catch (_) {
        throw const FormatException('SenderKeyManager: bad record');
      }
    }
    return SenderKeyManager(senderKeys: keys);
  }
}

// =============================================================================
// Symmetric encryption (XSalsa20-Poly1305 via pinenacl SecretBox)
// =============================================================================

/// Encrypt [plaintext] with [messageKey] using XSalsa20-Poly1305.
/// Returns nonce (24 bytes) || ciphertext+tag. Without [nonce] the nonce is
/// random.
Uint8List _encrypt(
  Uint8List messageKey,
  Uint8List plaintext, {
  Uint8List? nonce,
}) {
  final box = nacl_api.SecretBox(messageKey);
  if (nonce == null) {
    nonce = Uint8List(nacl_api.EncryptedMessage.nonceLength);
    for (var i = 0; i < nonce.length; i++) {
      nonce[i] = _rng.nextInt(256);
    }
  } else if (nonce.length != nacl_api.EncryptedMessage.nonceLength) {
    throw ArgumentError('nonce must be 24 bytes');
  }
  final encrypted = box.encrypt(plaintext, nonce: nonce);
  return Uint8List.fromList(encrypted.toList());
}

/// [_decrypt], failing with [SenderKeyFailure.decrypt].
Uint8List _decryptOrFail(Uint8List messageKey, Uint8List ciphertextWithNonce) {
  try {
    return _decrypt(messageKey, ciphertextWithNonce);
  } catch (_) {
    throw const SenderKeyException(
        SenderKeyFailure.decrypt, 'The ciphertext does not open.');
  }
}

/// What a v4 signature covers: 0xFE ‖ label ‖ binding(32) ‖ the first nine
/// bytes of the message (version, chain id, iteration) ‖ ciphertext.
Uint8List _boundSignedBytes(
  Uint8List binding,
  Uint8List header,
  Uint8List ciphertext,
) {
  final out = BytesBuilder(copy: false)
    ..addByte(_boundSignaturePrefix)
    ..add(_boundSignatureLabel)
    ..add(binding)
    ..add(header)
    ..add(ciphertext);
  return out.takeBytes();
}

/// Decrypt [ciphertextWithNonce] with [messageKey] using XSalsa20-Poly1305.
Uint8List _decrypt(Uint8List messageKey, Uint8List ciphertextWithNonce) {
  final box = nacl_api.SecretBox(messageKey);
  final decrypted = box.decrypt(
    nacl_api.EncryptedMessage(
      nonce: ciphertextWithNonce.sublist(
          0, nacl_api.EncryptedMessage.nonceLength),
      cipherText:
          ciphertextWithNonce.sublist(nacl_api.EncryptedMessage.nonceLength),
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

/// Encode a 32-bit integer as 4 big-endian bytes.
Uint8List _int32ToBE(int value) {
  return Uint8List(4)
    ..[0] = (value >> 24) & 0xFF
    ..[1] = (value >> 16) & 0xFF
    ..[2] = (value >> 8) & 0xFF
    ..[3] = value & 0xFF;
}

/// Decode 4 big-endian bytes to an unsigned 32-bit integer.
int _beToInt32(Uint8List bytes) {
  return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}
