/// @file        signal_protocol_service.dart
/// @description Pure Dart implementation of the Signal Protocol. X3DH, Double Ratchet, Sender Key and PreKey management built on pinenacl
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-29
/// @lastUpdated 2026-11-23 (backport SnowChat 3df0cc5 / 0aa549b — bindings mandatory, legacy TOFU
///              removed: identityStore is required; the deprecated IdentityPinStore, the
///              senderIdentityKeyEd25519 receive path, admitUnbound / IdentityKeyChangedException, the
///              one-time legacy IK seeding and remoteIdentityKeySnapshot() are gone; a peer without a
///              binding is refused at every admission point; a session without a stored remote IK
///              never matches a bound identity (no inference / labelling of pre-0.3.0 sessions);
///              archiveSessionsOf(). English-only comments; library directive). Earlier 2026-11-10 (Identity Binding v1 (SnowChat 1f90c4e): optional VerifiedIdentityStore replaces the TOFU IdentityPinStore — createSession() verifies the bundle's account-signed binding (or applies the Signal-style legacy policy) BEFORE X3DH; type-2 messages embed our binding and decryptMessage() verifies the sender's binding offline BEFORE any SPK/OPK is touched; sessions record remoteIdentityKey and sessions not matching a bound peer's IK are purged and never used. Earlier same day: backport SnowChat c062a09/dc71736/591d0b9/ddfbe6d: resolveSealedMessageType() + Sealed Sender Step 9, persistent PreKey until first inbound decrypt, type-2 archive fallback, OPK fail-loud, saveSessionStore -> Future<bool> with atomic write, signedPreKeyPublicKey()/hasAnySignedPreKey for SPK self-heal; header translated to English)
///
/// @functions
///  - SignalProtocolService: Pure Dart Signal Protocol implementation class
///  - SignalProtocolService.generateIdentityKeyPair(): Generate X25519 identity keypair
///  - SignalProtocolService.generateSignedPreKey(): Generate a signed prekey
///  - SignalProtocolService.generateOneTimePreKeys(): Generate a batch of one-time prekeys (optional Isolate offload)
///  - SignalProtocolService.getPreKeyBundle(): Get the server-upload PreKey bundle
///  - SignalProtocolService.signedPreKeyPublicKey(): Public key of a locally-held signed prekey (SPK self-heal reconcile)
///  - SignalProtocolService.hasAnySignedPreKey: Whether any signed prekey private key is held locally
///  - SignalProtocolService.createSession(): Create a new session via X3DH (identity admission first — a peer without a valid binding is refused)
///  - SignalProtocolService.hasSession(): Check whether a session exists
///  - SignalProtocolService.deleteSession(): Delete a session
///  - SignalProtocolService.archiveSession(): Archive a session (temporary retention instead of delete, 1h TTL)
///  - SignalProtocolService.archiveSessionsOf(): Archive the sessions with every device of a peer
///  - SignalProtocolService.encryptMessage(): Double Ratchet message encryption (keeps emitting PreKey/type-2 until the peer replies)
///  - SignalProtocolService.decryptMessage(): Double Ratchet decryption — trial-decrypt + archived-session fallback; retires pending-PreKey state on inbound success
///  - SignalProtocolService.resolveSealedMessageType(): Recover Signal messageType from an unsealed DR ciphertext + Sealed Sender Step 9 identity cross-check
///  - SignalProtocolService.createSenderKey(): Create a group Sender Key
///  - SignalProtocolService.processSenderKey(): Process a group Sender Key
///  - SignalProtocolService.encryptGroupMessage(): Encrypt a group message
///  - SignalProtocolService.decryptGroupMessage(): Decrypt a group message
///  - SignalProtocolService.saveSessionStore(): Atomically save encrypted session state (including archived sessions); returns whether bytes reached disk
///  - SignalProtocolService.loadSessionStore(): Load session state (restore archived sessions + TTL check)
///  - SignalProtocolService.setLocalIdentityBinding(): install our binding for type-2 embedding
///  - SignalProtocolService.enforceBoundSessions(): purge sessions not matching a bound peer IK
///  - SignalProtocolException: Signal Protocol exception class
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;
import 'package:pinenacl/x25519.dart' as nacl_api;

import 'double_ratchet.dart';
import 'identity_admission.dart';
import 'identity_binding.dart';
import 'identity_binding_exception.dart';
import 'identity_bytes.dart' show constantTimeEquals;
import 'logger.dart';
import 'message_send_log.dart';
import 'prekey_bundle.dart';
import 'sender_key.dart';
import 'sender_key_tracker.dart';
import 'verified_identity_store.dart';
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

  /// Archive the sessions with EVERY device of [recipientId] (see
  /// [archiveSession]) — for when the peer states that its sessions are gone
  /// and the device id it now uses is not known. Returns how many devices had
  /// sessions. Peer ids of an [IdentityIdScheme] have a fixed length, so the
  /// `"<peerId>:"` prefix matches that peer only.
  Future<int> archiveSessionsOf(String recipientId) async {
    final prefix = '$recipientId:';
    final keys = [
      for (final key in _sessions.keys)
        if (key.startsWith(prefix)) key,
    ];
    for (final key in keys) {
      await archiveSession(recipientId, key.substring(prefix.length));
    }
    return keys.length;
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

  /// Identity Binding v1: our own account-signed binding, embedded in every
  /// type-2 (PreKey) message so receivers can verify us offline.
  LocalIdentityBinding? _localBinding;

  /// Install (or clear) our binding (see [IdentityBindingV1.sign]). It is
  /// only embedded while it covers the CURRENT identity + Ed25519 keys; a
  /// stale binding is never sent. Re-install after rotating either key.
  void setLocalIdentityBinding(LocalIdentityBinding? binding) {
    _localBinding = binding;
  }

  LocalIdentityBinding? get localIdentityBinding => _localBinding;

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

  /// Constant-time byte comparison (identity keys), so a timing side-channel
  /// cannot leak which prefix of a forged key matches the expected one.
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

  // ---------------------------------------------------------------------------
  // Identity Binding v1 — admission + bound-session enforcement
  // ---------------------------------------------------------------------------

  /// Send-side admission for the bundle of [peerId]:[deviceId].
  ///
  /// Bundle keys read here (all optional): `identityBinding`
  /// ([IdentityBinding]), `identityBindingUnparseable` (bool — the server sent
  /// a binding object that failed [IdentityBinding.tryParseWire]) and
  /// `accountPublicKey` (Uint8List).
  Future<AdmittedIdentity> _admitForSend({
    required String peerId,
    required String deviceId,
    required Uint8List identityKey,
    required Uint8List ed25519,
    required Map<String, dynamic> bundle,
  }) async {
    final store = _identityStore;
    final admission = IdentityAdmission(store);
    try {
      if (bundle['identityBindingUnparseable'] == true) {
        throw admission.reject(peerId, IdentityBindingFailure.badFormat);
      }
      final rawBinding = bundle['identityBinding'];
      if (rawBinding != null && rawBinding is! IdentityBinding) {
        // Fail loud: a raw wire map here means the caller forgot to parse it
        // with IdentityBinding.tryParseWire — never treat it as "absent".
        throw ArgumentError(
            "preKeyBundle['identityBinding'] must be an IdentityBinding "
            '(parse the wire form with IdentityBinding.tryParseWire)');
      }
      final binding = rawBinding as IdentityBinding?;
      final account = bundle['accountPublicKey'] as Uint8List?;
      if (binding != null) {
        final acct = account ?? (await store.getFresh(peerId))?.accountPublicKey;
        if (acct == null) {
          throw admission.reject(peerId, IdentityBindingFailure.badFormat);
        }
        return await admission.admitBound(
          peerId: peerId,
          deviceId: deviceId,
          identityKey: identityKey,
          ed25519: ed25519,
          accountPublicKey: acct,
          epoch: binding.epoch,
          signature: binding.signature,
        );
      }
      throw await admission.refuseUnbound(peerId);
    } on SignalProtocolException {
      rethrow;
    } on ArgumentError {
      rethrow;
    } catch (e) {
      throw SignalProtocolException(
        'Identity store failure for ${_maskSessionKey('$peerId:$deviceId')} '
        '(transient): ${e.runtimeType}',
      );
    }
  }

  /// Receive-side admission for a PreKey message. With [directoryLookup] ==
  /// null this never leaves the process and returns null for a binding-less
  /// sender that is not latched (resolved later, only if a new session is
  /// needed — and then refused unless the directory holds a binding for the
  /// header IK).
  Future<AdmittedIdentity?> _admitForReceive({
    required String peerId,
    required String sessionDeviceId,
    required String? envelopeDeviceId,
    required _PreKeyMessageData parsed,
    required Future<RemoteIdentityDirectory?> Function()? directoryLookup,
  }) async {
    final store = _identityStore;
    final admission = IdentityAdmission(store);
    final headerIk = parsed.identityKey;
    try {
      if (parsed.bindingUnparseable) {
        throw admission.reject(peerId, IdentityBindingFailure.badFormat);
      }
      final emb = parsed.binding;
      if (emb != null) {
        // The binding must name the device the envelope / sealed certificate
        // names. Without a transport deviceId there is nothing to compare;
        // the signature and the epoch latch still apply.
        if (envelopeDeviceId != null &&
            envelopeDeviceId.isNotEmpty &&
            emb.deviceId != envelopeDeviceId) {
          throw admission.reject(peerId, IdentityBindingFailure.deviceMismatch);
        }
        // The signature is checked over the X3DH HEADER IK: a header carrying
        // any IK other than the one the account signed fails here.
        return await admission.admitBound(
          peerId: peerId,
          deviceId: emb.deviceId,
          identityKey: headerIk,
          ed25519: emb.ed25519,
          accountPublicKey: emb.accountPublicKey,
          epoch: emb.epoch,
          signature: emb.signature,
        );
      }

      // No embedded binding.
      if (await store.latchedEpoch(peerId, fresh: true) != null) {
        throw admission.reject(peerId, IdentityBindingFailure.downgrade);
      }
      final claimedDevice =
          (envelopeDeviceId != null && envelopeDeviceId.isNotEmpty)
              ? envelopeDeviceId
              : sessionDeviceId;
      if (directoryLookup == null) return null;

      // Binding-less sender: consult the non-consuming directory. Only a
      // server-held binding for the header IK admits it.
      RemoteIdentityDirectory? dir;
      try {
        dir = await directoryLookup();
      } catch (e) {
        throw SignalProtocolException(
          'Identity directory lookup failed for '
          '${_maskSessionKey('$peerId:$claimedDevice')} (transient): '
          '${e.runtimeType}',
        );
      }
      final dev = dir?.deviceById(claimedDevice);
      if (dev != null && (dev.binding != null || dev.bindingUnparseable)) {
        // The server holds a binding for this device, yet the message carried
        // none: it must at least use the bound IK, and the binding must verify.
        final b = dev.binding;
        final ed = dev.ed25519;
        final acct = dir!.accountPublicKey;
        if (b == null || ed == null || acct == null) {
          throw admission.reject(peerId, IdentityBindingFailure.badFormat);
        }
        if (!constantTimeEquals(dev.identityKey, headerIk)) {
          throw admission.reject(
              peerId, IdentityBindingFailure.identityKeyMismatch);
        }
        return await admission.admitBound(
          peerId: peerId,
          deviceId: dev.deviceId,
          identityKey: headerIk,
          ed25519: ed,
          accountPublicKey: acct,
          epoch: b.epoch,
          signature: b.signature,
        );
      }
      throw await admission.refuseUnbound(peerId);
    } on SignalProtocolException {
      rethrow;
    } catch (e) {
      throw SignalProtocolException(
        'Identity store failure for '
        '${_maskSessionKey('$peerId:$sessionDeviceId')} (transient): '
        '${e.runtimeType}',
      );
    }
  }

  /// If [peerId] is bound (Identity Binding v1), purge every session —
  /// active and archived — whose remote IK differs from the bound IK, so it
  /// can never be used to encrypt or decrypt. Returns the purge count.
  /// Store read failures are non-fatal here (nothing is purged).
  ///
  /// Called automatically by [hasSession], [encryptMessage] and
  /// [decryptMessage]; integrators may also call it after an out-of-band
  /// admission (e.g. [IdentityAdmission.admitDirectory]).
  Future<int> enforceBoundSessions(String peerId) async {
    final store = _identityStore;
    try {
      final rec = await store.get(peerId);
      if (rec == null || !rec.bound || rec.identityKey == null) return 0;
      if (!_hasSessionsNotMatching(peerId, rec.identityKey!)) return 0;
      // Destructive path: confirm against storage, not a cache — another
      // process / isolate may have accepted a newer bound identity.
      final fresh = await store.getFresh(peerId);
      if (fresh == null || !fresh.bound || fresh.identityKey == null) return 0;
      return _purgeSessionsNotMatching(peerId, fresh.identityKey!);
    } catch (e) {
      debugPrint('[SignalProtocolService] enforceBoundSessions skipped: '
          '${e.runtimeType}');
      return 0;
    }
  }

  /// Whether a session's stored remote IK is the bound IK. A session with no
  /// stored remote IK does not match: every session made or restored since
  /// 0.3.0 stores it (createSession / _receiveSession, toJson / fromJson);
  /// only sessions from before identity bindings lack it, and they are
  /// purged, never labelled by inference.
  static bool _sessionMatchesBound(Uint8List? sessionIk, Uint8List boundIk) =>
      sessionIk != null && _constantTimeBytesEqual(sessionIk, boundIk);

  static Uint8List? _archivedIk(_ArchivedSessionEntry a) {
    final hex = a.sessionJson['remoteIdentityKey'];
    return hex is String ? _hexToBytes(hex) : null;
  }

  bool _hasSessionsNotMatching(String peerId, Uint8List boundIk) {
    final prefix = '$peerId:';
    for (final e in _sessions.entries) {
      if (!e.key.startsWith(prefix)) continue;
      for (final sess in e.value) {
        if (!_sessionMatchesBound(sess.remoteIdentityKey, boundIk)) return true;
      }
    }
    for (final e in _archivedSessions.entries) {
      if (!e.key.startsWith(prefix)) continue;
      for (final a in e.value) {
        if (!_sessionMatchesBound(_archivedIk(a), boundIk)) return true;
      }
    }
    return false;
  }

  /// Purge for a bound peer: every session (active or archived) whose stored
  /// remote IK is not the bound IK is removed.
  int _purgeSessionsNotMatching(String peerId, Uint8List boundIk) {
    final prefix = '$peerId:';
    var removed = 0;
    for (final key in _sessions.keys.toList()) {
      if (!key.startsWith(prefix)) continue;
      final list = _sessions[key]!;
      final before = list.length;
      list.removeWhere(
          (sess) => !_sessionMatchesBound(sess.remoteIdentityKey, boundIk));
      removed += before - list.length;
      if (list.isEmpty) _sessions.remove(key);
    }
    for (final key in _archivedSessions.keys.toList()) {
      if (!key.startsWith(prefix)) continue;
      final list = _archivedSessions[key]!;
      final before = list.length;
      list.removeWhere((a) => !_sessionMatchesBound(_archivedIk(a), boundIk));
      removed += before - list.length;
      if (list.isEmpty) _archivedSessions.remove(key);
    }
    if (removed > 0) {
      // Removals must reach disk: reuse the "needs persist" flag.
      _archiveDecryptDirty = true;
      _remoteIdentityKeys[peerId] = Uint8List.fromList(boundIk);
      debugPrint('[SignalProtocolService] Purged $removed session(s) not '
          'matching the bound identity of ${_maskSessionKey(prefix)}');
    }
    return removed;
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

  /// Public key of the locally-held signed prekey [keyId], or `null` if we do
  /// not hold its private key.
  ///
  /// Used for signed-prekey self-heal: on startup the caller compares the
  /// signed prekey its server currently ADVERTISES (id + public key) against
  /// the local store. If the local store lacks that exact public key, the
  /// device is advertising a prekey it can no longer decrypt with, and every
  /// receive-first X3DH from a new contact would fail with "Signed prekey N
  /// not found". The caller should then generate + persist + re-advertise a
  /// fresh signed prekey. Compare by public key, not id, so a same-id /
  /// different-key collision is also caught.
  Uint8List? signedPreKeyPublicKey(int keyId) =>
      _signedPreKeys[keyId]?.publicKey;

  /// Whether any signed prekey private key is held locally. Fallback signal
  /// for signed-prekey self-heal when the server cannot report which signed
  /// prekey it advertises.
  bool get hasAnySignedPreKey => _signedPreKeys.isNotEmpty;

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

  /// Identity Binding v1 store. Required: every new session (send and
  /// receive) goes through [IdentityAdmission] BEFORE X3DH, a peer without a
  /// valid binding is refused, and sessions that do not match a bound peer's
  /// identity key are purged. There is no configuration without it.
  final VerifiedIdentityStore _identityStore;

  /// [identityStore] must be a persistent [VerifiedIdentityStore] in
  /// production (records AND latches); [InMemoryVerifiedIdentityStore] is
  /// for tests and tools only.
  SignalProtocolService({
    required VerifiedIdentityStore identityStore,
  }) : _identityStore = identityStore;

  /// The Identity Binding v1 store.
  VerifiedIdentityStore get identityStore => _identityStore;

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
      throw const SignalProtocolException(
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
  /// Ed25519 identity key is missing (prevents MITM via bundle omission) and
  /// verifies the signed prekey signature (strict Ed25519). Then, BEFORE
  /// X3DH, identity admission. Bundle keys `identityBinding`
  /// ([IdentityBinding], parsed with [IdentityBinding.tryParseWire]),
  /// `identityBindingUnparseable` (bool) and `accountPublicKey` (Uint8List).
  /// A valid binding is verified and recorded (choose the device with
  /// [IdentityAdmission.selectDevice] when the server lists several); a
  /// bundle without a binding is refused (bindings are mandatory). Throws
  /// [IdentityBindingInvalidException] (terminal: `bindingRequired`,
  /// `downgrade`, `signatureInvalid`, …). Store I/O failures surface as a
  /// transient [SignalProtocolException].
  ///
  /// Admitting from a non-consuming identity directory first
  /// ([IdentityAdmission.admitDirectory]) avoids consuming a one-time prekey
  /// for a peer that will be refused.
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

    // Identity Binding v1 admission BEFORE X3DH: a valid account-signed
    // binding is verified and recorded; a missing one is refused. The typed
    // failure propagates untouched.
    final admitted = await _admitForSend(
      peerId: recipientId,
      deviceId: deviceId,
      identityKey: remoteIdentityKey,
      ed25519: remoteIdentityKeyEd25519,
      bundle: preKeyBundle,
    );
    _purgeSessionsNotMatching(recipientId, admitted.identityKey);

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
    session.remoteIdentityKey = Uint8List.fromList(remoteIdentityKey);

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

  /// Process an incoming pre-key message and establish a session as receiver.
  ///
  /// This is called internally during decryptMessage when messageType == 2.
  ///
  /// Identity admission has already run in [decryptMessage] BEFORE this
  /// method touches any SPK/OPK material, so a rejected sender cannot burn
  /// our one-time prekeys.
  Future<void> _receiveSession({
    required String sessionKey,
    required Uint8List remoteIdentityKey,
    required Uint8List remoteEphemeralKey,
    required int signedPreKeyId,
    int? oneTimePreKeyId,
  }) async {
    _ensureIdentity();

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
      } else {
        // Fail loud: the sender's bundle named a one-time prekey we no longer
        // hold. Going ahead with opkPrivate=null would silently drop X3DH from
        // 5-DH to 4-DH while the sender ran the 5-DH path, so both sides would
        // derive different shared secrets and every message would stay
        // undecryptable until a session reset. Throwing lets the caller's
        // decrypt-failure path (archive / reset / retry) recover instead of
        // caching a permanently-poisoned session. The root cause is upstream
        // (server OPK race, or a crash between upload and persist); this
        // guard makes the symptom recoverable. Only prekey IDs are logged —
        // never key material.
        throw SignalProtocolException(
          'One-time prekey #$oneTimePreKeyId requested by sender but not in '
          'local store (available: ${_oneTimePreKeys.keys.toList()}). '
          'Refusing X3DH 4-DH fallthrough — would yield a mismatched shared '
          'secret.',
        );
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
    )..remoteIdentityKey = Uint8List.fromList(remoteIdentityKey);

    // Append to multi-session list. Existing sessions (e.g. from a prior
    // outgoing X3DH) are KEPT — they're needed to decrypt in-flight messages
    // encrypted with the old shared secret. LRU eviction at the limit.
    _appendSession(sessionKey, session);

    // Cache remote identity key for Sealed Sender seal().
    final peerId = sessionKey.substring(0, sessionKey.lastIndexOf(':'));
    _remoteIdentityKeys[peerId] = Uint8List.fromList(remoteIdentityKey);

    debugPrint(
      '[SignalProtocolService] Session received from '
      '${_maskSessionKey(sessionKey)} via X3DH '
      '(total ${_sessions[sessionKey]!.length} for peer)',
    );
  }

  /// Check whether we already have an active session with the given device.
  /// Returns true if at least one session exists in the peer's list.
  ///
  /// Sessions that do not match the peer's bound identity key are purged
  /// first (so they do not count and the caller re-runs X3DH).
  Future<bool> hasSession(String recipientId, String deviceId) async {
    await enforceBoundSessions(recipientId);
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
  /// PreKey (type-2) messages carry our [LocalIdentityBinding] (see
  /// [setLocalIdentityBinding]) while it covers the current identity keys.
  ///
  /// IMPORTANT: Never log the plaintext content.
  Future<Map<String, dynamic>> encryptMessage({
    required String recipientId,
    required String deviceId,
    required Uint8List plaintext,
  }) async {
    final sessionKey = '$recipientId:$deviceId';
    // Never encrypt on a session whose remote IK differs from the peer's
    // bound identity key.
    await enforceBoundSessions(recipientId);
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

    // Embed our account-signed binding in every PreKey message, but only
    // while it covers our CURRENT identity + Ed25519 keys.
    EmbeddedIdentityBinding? embedded;
    final local = _localBinding;
    final ikNow = _identityKeyPair?.publicKey;
    final edNow = _identityVerifyKey;
    if (isPreKey &&
        local != null &&
        ikNow != null &&
        edNow != null &&
        constantTimeEquals(local.identityKey, ikNow) &&
        constantTimeEquals(local.ed25519, edNow)) {
      embedded = local.embedded;
    }

    // Serialize the encrypted message into a transport format
    final payload = _serializeEncryptedMessage(
      encrypted,
      isPreKey: isPreKey,
      identityKey: isPreKey ? _identityKeyPair?.publicKey : null,
      ephemeralKey: isPreKey ? session.ephemeralPublicKey : null,
      signedPreKeyId: isPreKey ? session.preKeySignedPreKeyId : null,
      oneTimePreKeyId: isPreKey ? session.preKeyOneTimePreKeyId : null,
      identityBinding: embedded,
    );

    // Do NOT clear the prekey state here. libsignal keeps emitting PreKey
    // (type-2) messages until the initiator DECRYPTS an inbound message from
    // the peer (proof the peer bootstrapped the session) — see
    // _clearPrekeyState, called from decryptMessage's inbound-success paths.
    // Clearing after the first SEND (the pre-0.3.0 behavior) made every later
    // message type-1, so a receive-first peer whose only bootstrap-capable
    // (type-2) message was lost could never establish the inbound session.
    // Emitting the same X3DH header repeatedly is safe: the receiver consumes
    // the one-time prekey exactly once (decryptMessage trials the existing
    // session before _receiveSession) and the send chain advances normally —
    // only the wire wrapper differs.

    return {
      'ciphertext': payload,
      'messageType': isPreKey ? 2 : 1,
    };
  }

  /// Retire a session's pending-PreKey state once the peer has proven they
  /// bootstrapped it (i.e. we successfully decrypted an INBOUND message on
  /// it). After this, [encryptMessage] emits normal (type-1) messages for the
  /// session. Idempotent: a no-op on receiver / already-established sessions.
  ///
  /// MUST be called ONLY on the specific session that decrypted the inbound
  /// message (never a blanket clear across a peer's sessions): in a
  /// concurrent-initiation (glare) race, blanket-clearing would flip an
  /// initiator session the peer has not yet received to type-1 and make it
  /// permanently undecryptable.
  void _clearPrekeyState(DoubleRatchetSession session) {
    if (!session.isPreKeySession) return;
    session.isPreKeySession = false;
    session.ephemeralPublicKey = null;
    session.preKeySignedPreKeyId = null;
    session.preKeyOneTimePreKeyId = null;
  }

  /// Decrypt [ciphertext] from [senderId]:[deviceId].
  /// [messageType] indicates the Signal message type
  /// (1 = ciphertext, 2 = pre-key message).
  ///
  /// Identity Binding v1 — for type 2, BEFORE any new session is derived:
  ///  - the sender's embedded binding is verified offline: signature over
  ///    ([senderId], binding deviceId, epoch, X3DH header IK, binding Ed),
  ///    binding deviceId == [envelopeDeviceId] (the device named by the
  ///    envelope / sealed sender certificate — pass it whenever the
  ///    transport authenticates one), and the epoch latch;
  ///  - no embedded binding: latched sender -> rejected (downgrade);
  ///    otherwise [identityDirectoryLookup] (a NON-consuming identity lookup;
  ///    cache it per sender) is consulted, only when no existing session
  ///    decrypts the message: a server-held binding for the header IK is
  ///    verified and admitted, anything else is refused (bindingRequired).
  /// For a bound sender, sessions whose remote IK differs from the bound IK
  /// are purged before any trial decrypt, including archived ones.
  ///
  /// IMPORTANT: Never log the returned plaintext.
  Future<Uint8List> decryptMessage({
    required String senderId,
    required String deviceId,
    required Uint8List ciphertext,
    required int messageType,
    String? envelopeDeviceId,
    Future<RemoteIdentityDirectory?> Function()? identityDirectoryLookup,
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

      // Identity Binding v1: offline admission first (embedded binding). A
      // null result means "binding-less sender, not latched" — resolved with
      // the directory lookup only if no existing session decrypts the
      // message.
      var admitted = await _admitForReceive(
        peerId: senderId,
        sessionDeviceId: deviceId,
        envelopeDeviceId: envelopeDeviceId,
        parsed: parsed,
        directoryLookup: null,
      );
      if (admitted != null) {
        _purgeSessionsNotMatching(senderId, admitted.identityKey);
      } else {
        await enforceBoundSessions(senderId);
      }

      final existing = _sessions[sessionKey];
      if (existing != null && existing.isNotEmpty) {
        final result = _trialDecrypt(existing, parsed.encryptedMessage);
        if (result != null) {
          _markMostRecentlyUsed(sessionKey, result.session);
          // Defensive prekey retire on the specific decrypting session only.
          // In practice this is a no-op: a session that decrypts an INBOUND
          // type-2 is a receiver session (isPreKeySession=false); an initiator
          // prekey session cannot derive the peer's type-2 send chain. Kept
          // for symmetry with the type-1 primary retire point below.
          _clearPrekeyState(result.session);
          return result.plaintext;
        }
      }

      // No existing session decrypted → a new session will be derived. A
      // binding-less sender is resolved now (non-consuming lookup) — admitted
      // only through a server-held binding for the header IK, else refused.
      if (admitted == null) {
        admitted = await _admitForReceive(
          peerId: senderId,
          sessionDeviceId: deviceId,
          envelopeDeviceId: envelopeDeviceId,
          parsed: parsed,
          directoryLookup: identityDirectoryLookup ?? () async => null,
        );
        if (admitted != null) {
          _purgeSessionsNotMatching(senderId, admitted.identityKey);
        }
      }

      // Persistent-PreKey reset-race guard: now that the initiator sustains
      // type-2 until the peer replies, a re-sent type-2 can arrive after we
      // archived/reset the session AND its one-time prekey was already
      // consumed by the first copy — _receiveSession then throws (OPK gone)
      // BEFORE we reach the new-session archive fallback below. The same
      // in-flight message, had it been type-1, would have hit the type-1
      // archive fallback and recovered. Give type-2 the same recovery: on a
      // _receiveSession failure that is NOT an identity rejection, consult
      // the archive before rethrowing. IdentityBindingInvalidException MUST
      // propagate untouched so it routes to identity handling — never
      // silently archive-fallback past it.
      try {
        await _receiveSession(
          sessionKey: sessionKey,
          remoteIdentityKey: parsed.identityKey,
          remoteEphemeralKey: parsed.ephemeralKey,
          signedPreKeyId: parsed.signedPreKeyId,
          oneTimePreKeyId: parsed.oneTimePreKeyId,
        );
      } on IdentityBindingInvalidException {
        rethrow;
      } catch (_) {
        final archivedResult =
            _tryDecryptFromArchive(sessionKey, parsed.encryptedMessage);
        if (archivedResult != null) {
          _archiveDecryptDirty = true;
          return archivedResult;
        }
        rethrow;
      }

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

    // Normal ciphertext message. A bound peer's sessions with a different
    // remote IK (active or archived) are purged first — never used.
    await enforceBoundSessions(senderId);

    // Short-circuit if there is nothing to try.
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
        // Persistent-PreKey PRIMARY retire point: decrypting an INBOUND
        // normal (type-1) message on this session is proof the peer
        // bootstrapped it and now sends normal messages — so our initiator
        // prekey session no longer needs to advertise X3DH material. Retire
        // the pending-prekey state on THIS session only (never a blanket
        // per-peer clear: in a glare race that would flip an initiator
        // session the peer has not yet received to type-1, making it
        // permanently undecryptable). Idempotent on established sessions.
        _clearPrekeyState(result.session);
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
  ///
  /// Returns `true` iff the encrypted bytes actually reached disk. Returns
  /// `false` when no store encryption key is set or when the write fails.
  /// Callers that upload prekeys MUST persist first and fail closed on
  /// `false` (persist-before-advertise): advertising a signed / one-time
  /// prekey whose private key never reached disk makes every later
  /// receive-first X3DH against it undecryptable after a restart.
  ///
  /// The write is atomic: bytes go to a uniquely-named temp file next to
  /// [path] which is then renamed over [path], so a process kill mid-write
  /// leaves either the previous store or the new one — never a torn
  /// ciphertext that would fail to decrypt and lose every session.
  Future<bool> saveSessionStore(String path) async {
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
        // Atomic write: write to a UNIQUE temp file then rename over the
        // target. rename() is atomic on the same filesystem. The temp name
        // MUST be unique per call: saveSessionStore may run concurrently
        // (e.g. a debounced save firing while a prekey upload's persist is in
        // flight), and a shared temp path would let two writers interleave on
        // one file and publish a torn ciphertext anyway. With unique temps
        // each writer produces a complete, valid ciphertext and the last
        // rename wins.
        final suffix =
            List.generate(8, (_) => rng.nextInt(16).toRadixString(16)).join();
        final tmp = File('$path.$suffix.tmp');
        await tmp.writeAsBytes(encrypted.toList(), flush: true);
        try {
          await tmp.rename(path);
        } catch (_) {
          await tmp.delete().catchError((_) => tmp);
          rethrow;
        }
        _storeWasEncrypted = true;
        return true;
      } else {
        // Plaintext fallback is refused. The previous behaviour wrote plain
        // JSON to disk if `setStoreEncryptionKey` had not yet been called
        // — exposing identity + ratchet material on any code path that
        // called saveSessionStore before initialize().
        debugPrint('[SignalProtocolService] saveSessionStore SKIPPED — '
            'no encryption key set. Caller must invoke '
            'setStoreEncryptionKey() before persisting.');
        return false;
      }
    } catch (e) {
      debugPrint('[SignalProtocolService] Failed to save session store: $e');
      return false;
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
          const nonceLen = nacl_api.EncryptedMessage.nonceLength;
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

      // Sessions persisted before 0.3.0 carry no remoteIdentityKey: they never
      // match a bound identity and are purged the first time the peer's
      // bound sessions are enforced (enforceBoundSessions).

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
    EmbeddedIdentityBinding? identityBinding,
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
      // Our account-signed binding. Receivers before 0.3.0 ignore unknown
      // keys.
      if (identityBinding != null) {
        msgJson['identityBinding'] = identityBinding.toJson();
      }
    }
    return Uint8List.fromList(utf8.encode(jsonEncode(msgJson)));
  }

  /// Parse a pre-key message to extract X3DH params and inner encrypted message.
  _PreKeyMessageData _deserializePreKeyMessage(Uint8List data) {
    final json = jsonDecode(utf8.decode(data)) as Map<String, dynamic>;
    final rawBinding = json['identityBinding'];
    final binding = rawBinding == null
        ? null
        : EmbeddedIdentityBinding.tryParse(rawBinding);
    return _PreKeyMessageData(
      binding: binding,
      bindingUnparseable: rawBinding != null && binding == null,
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

  /// Recover the Signal message type (1 = normal, 2 = prekey) from an
  /// unsealed Double Ratchet ciphertext WITHOUT trusting any
  /// transport-supplied field, and cross-check the sender's X3DH identity
  /// against the Sealed Sender certificate.
  ///
  /// Call this on [UnsealedMessage.drCiphertext] with
  /// [UnsealedMessage.senderIdentityKey] and pass the result as
  /// `messageType` to [decryptMessage].
  ///
  /// Why not read messageType off the wire: Sealed Sender deliberately hides
  /// the inner message type from the transport, so a relay server never
  /// learns it and cannot be trusted to supply it. A receiver that defaulted
  /// to type-1 misrouted every first-contact prekey message as a normal
  /// message: the X3DH responder branch never ran, no session was built, and
  /// the very first message to a brand-new contact was lost. The DR
  /// ciphertext is self-describing JSON: a prekey message (X3DH bootstrap)
  /// carries both `identityKey` and `ephemeralKey` (see
  /// [_serializeEncryptedMessage]); a normal message never does
  /// ([EncryptedMessage.toJson] emits only ciphertext / ratchetPublicKey /
  /// messageNumber / previousChainLength — a disjoint key set). Presence of
  /// BOTH keys therefore identifies a prekey message with no false
  /// positives.
  ///
  /// Sealed Sender Step 9: for a prekey message the X25519 identity key
  /// embedded in the X3DH header MUST equal [certIdentityKey] (the identity
  /// the server-signed sender certificate vouches for), compared in constant
  /// time. A mismatch means the authenticated sender and the X3DH initiator
  /// identity disagree — rejected with the same opaque `StateError('Sealed
  /// message rejected')` every other unseal rejection uses (oracle-safe).
  /// Normal messages have no X3DH header to cross-check; their session
  /// lookup is already keyed on the certificate-authenticated sender, so a
  /// wrong-identity certificate cannot decrypt a victim's session.
  ///
  /// Robustness: a non-JSON / structurally-unparseable ciphertext degrades
  /// to messageType 1 (it then rides the normal trial-decrypt + retry path).
  /// A structurally-valid prekey header that fails validation — malformed
  /// hex in `identityKey`, or an identity failing the Step 9 cross-check —
  /// throws instead: that is a genuine rejection, not a normal message.
  /// Callers should invoke this inside the same `try` as [decryptMessage] so
  /// any such throw lands on their normal decrypt-failure path.
  int resolveSealedMessageType(
    Uint8List drCiphertext,
    Uint8List certIdentityKey,
  ) {
    final Map<String, dynamic> json;
    try {
      json = jsonDecode(utf8.decode(drCiphertext)) as Map<String, dynamic>;
    } catch (_) {
      // Malformed / non-JSON: treat as normal so it stays on the existing
      // session trial-decrypt + retry path instead of being rejected here.
      return 1;
    }
    final idHex = json['identityKey'];
    final ephHex = json['ephemeralKey'];
    if (idHex is! String || ephHex is! String) {
      return 1; // Normal message — no X3DH header present.
    }
    // Prekey message: bind the X3DH initiator identity to the certificate.
    final x3dhIdentity = _hexToBytes(idHex);
    if (x3dhIdentity.length != certIdentityKey.length ||
        !_constantTimeBytesEqual(x3dhIdentity, certIdentityKey)) {
      throw StateError('Sealed message rejected');
    }
    return 2;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  void _ensureIdentity() {
    if (_identityKeyPair == null) {
      throw const SignalProtocolException(
        'Identity key pair not generated. Call generateIdentityKeyPair() first.',
      );
    }
    if (_identitySigningKeySeed == null) {
      throw const SignalProtocolException(
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
  /// Sender's embedded binding (null when absent or unparseable).
  final EmbeddedIdentityBinding? binding;

  /// True when an `identityBinding` field was present but malformed.
  final bool bindingUnparseable;
  final Uint8List identityKey;
  final Uint8List ephemeralKey;
  final int signedPreKeyId;
  final int? oneTimePreKeyId;
  final EncryptedMessage encryptedMessage;

  _PreKeyMessageData({
    required this.binding,
    required this.bindingUnparseable,
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
