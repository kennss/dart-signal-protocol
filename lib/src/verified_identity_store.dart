/// @file        verified_identity_store.dart
/// @description Identity Binding v1 — per-peer store of the remote identity
///              we verified. Bindings are mandatory, so a record is either
///              BOUND (account key, device, epoch, IK, Ed, binding signature —
///              written by IdentityAdmission.admitBound) or holds only a
///              pinned ACCOUNT key (pinAccountKey / rememberAccountKey). No
///              record carries keys that were not proven by a binding.
///
///              The library does not prescribe persistence. Integrators
///              subclass [VerifiedIdentityStore] and implement a handful of
///              storage primitives against platform-secure storage (Keychain /
///              Keystore / encrypted DB); all policy-relevant operations
///              (monotonic latch, latch survives remove(), out-of-band account
///              key pin) are implemented once here on top of those primitives.
///              [InMemoryVerifiedIdentityStore] is a reference implementation
///              for tests and examples — it is NOT persistent.
///
///              Two independent persisted facts per peer:
///               - the RECORD (account key; for a bound peer also its device,
///                 epoch and keys) — may be removed when a contact is deleted;
///               - the LATCH (highest accepted binding epoch) — presence means
///                 "this peer proved a binding once"; it is NEVER removed by
///                 [VerifiedIdentityStore.remove], so a peer can never be
///                 silently downgraded to unbound keys afterwards, and it never
///                 decreases, so a superseded binding cannot be replayed.
///
///              App-specific concerns (keychain-locked deferral, cross-isolate
///              caching) belong in the integrator's subclass; see README.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-23 (backport SnowChat 0aa549b — legacy TOFU removed: no pending key
///              changes / acceptPendingChange, no importLegacyPin, no one-time IK seeding and its
///              metadata primitives, no edLegacySourced, no isPeerVerified / verifiedLookup, no
///              legacyKeyChanged / legacyKeyChangeBlocked / interceptionSuspected events;
///              pinFromInviteLink -> pinAccountKey (a link, a QR code or a backup pins the account
///              key); rememberAccountKey only fills a missing record; an UNBOUND record read from
///              storage keeps only its account key). Earlier 2026-11-10
///
/// @functions
///  - VerifiedIdentityRecord: per-peer record (+ JSON codec, schema 1)
///  - IdentityStoreEvent / IdentityEventKind: user-visible identity events
///  - VerifiedIdentityStore: abstract store (storage primitives + policy ops)
///  - VerifiedIdentityStore.get()/getFresh(): record lookup
///  - VerifiedIdentityStore.latchedEpoch(): highest bound epoch, null if never bound
///  - VerifiedIdentityStore.put(): persist a record
///  - VerifiedIdentityStore.raiseLatch(): monotonic latch update
///  - VerifiedIdentityStore.remove(): drop the record (latch is kept)
///  - VerifiedIdentityStore.pinAccountKey(): pin an account key out of band
///  - VerifiedIdentityStore.rememberAccountKey(): store a derive-checked account key
///  - VerifiedIdentityStore.emit()/events: identity event broadcast
///  - InMemoryVerifiedIdentityStore: non-persistent reference implementation
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'identity_binding.dart';
import 'identity_binding_exception.dart';
import 'identity_bytes.dart';

// =============================================================================
// Record
// =============================================================================

/// One remote identity, keyed by peer id. Either BOUND (every field set by
/// IdentityAdmission.admitBound) or an account-key pin (only
/// [accountPublicKey]).
class VerifiedIdentityRecord {
  static const int schema = 1;

  /// Peer id (derived from the account key under the store's scheme).
  final String peerId;

  /// Peer ACCOUNT public key (peer-id root). Present when a binding verified,
  /// when an out-of-band link / QR code / backup pinned it, or when the
  /// server supplied a key that derives the peer id (Safety Number of a peer
  /// not met yet).
  final Uint8List? accountPublicKey;

  /// Device the current keys belong to (bound records only).
  final String? deviceId;

  /// Epoch of the accepted binding (bound records only).
  final int? epoch;

  /// X25519 identity key used in X3DH (bound records only).
  final Uint8List? identityKey;

  /// Signal-layer Ed25519 signing key — signed-prekey signatures (bound
  /// records only).
  final Uint8List? ed25519;

  /// Binding signature (bound records only).
  final Uint8List? bindingSignature;

  /// True once a valid binding was accepted for the current keys.
  final bool bound;

  /// ms since epoch of the last write.
  final int updatedAt;

  const VerifiedIdentityRecord({
    required this.peerId,
    this.accountPublicKey,
    this.deviceId,
    this.epoch,
    this.identityKey,
    this.ed25519,
    this.bindingSignature,
    this.bound = false,
    required this.updatedAt,
  });

  /// The record with [accountPublicKey] set (the only field a non-binding
  /// write changes).
  VerifiedIdentityRecord copyWith({Uint8List? accountPublicKey}) {
    return VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: accountPublicKey ?? this.accountPublicKey,
      deviceId: deviceId,
      epoch: epoch,
      identityKey: identityKey,
      ed25519: ed25519,
      bindingSignature: bindingSignature,
      bound: bound,
      updatedAt: DateTime.now().millisecondsSinceEpoch,
    );
  }

  /// JSON schema 1. The id key is `snowId` for byte-compatibility with the
  /// SnowChat reference store (records written by either are interchangeable).
  Map<String, dynamic> toJson() => {
        'schema': schema,
        'snowId': peerId,
        if (accountPublicKey != null)
          'accountPub': bytesToHexLower(accountPublicKey!),
        if (deviceId != null) 'deviceId': deviceId,
        if (epoch != null) 'epoch': epoch.toString(),
        if (identityKey != null) 'ik': base64Encode(identityKey!),
        if (ed25519 != null) 'ed': base64Encode(ed25519!),
        if (bindingSignature != null) 'sig': base64Encode(bindingSignature!),
        'bound': bound,
        'updatedAt': updatedAt,
      };

  /// Strict decode; throws [FormatException] on any inconsistency so the
  /// caller can treat the entry as corrupt (the separate latch still blocks
  /// a downgrade for a peer that proved a binding).
  ///
  /// An UNBOUND record keeps only its account key: keys a 0.3.x store
  /// recorded under the removed TOFU policy (and its `edLegacy` / `pending*`
  /// fields) were never proven by a binding and are dropped, never trusted.
  factory VerifiedIdentityRecord.fromJson(Map<String, dynamic> j) {
    if (j['schema'] != schema) {
      throw const FormatException('unknown record schema');
    }
    Uint8List? b64(String k, {int len = 32}) {
      final v = j[k];
      if (v == null) return null;
      if (v is! String) throw FormatException('bad type for $k');
      final out = base64Decode(v);
      if (out.length != len) throw FormatException('bad length for $k');
      return out;
    }

    String? str(String k) {
      final v = j[k];
      if (v == null) return null;
      if (v is! String) throw FormatException('bad type for $k');
      return v;
    }

    final accountHex = j['accountPub'];
    final account = accountHex == null
        ? null
        : IdentityBindingV1.parseAccountKeyHex(accountHex);
    if (accountHex != null && account == null) {
      throw const FormatException('bad accountPub');
    }
    final peerId = str('snowId');
    if (peerId == null) throw const FormatException('missing id');
    final boundRaw = j['bound'];
    final bound = boundRaw is bool && boundRaw;
    final updatedAtRaw = j['updatedAt'];
    final updatedAt = updatedAtRaw is int ? updatedAtRaw : 0;
    if (!bound) {
      return VerifiedIdentityRecord(
        peerId: peerId,
        accountPublicKey: account,
        updatedAt: updatedAt,
      );
    }
    final epochStr = j['epoch'];
    final epoch =
        epochStr == null ? null : IdentityBindingV1.parseEpoch(epochStr);
    if (epochStr != null && epoch == null) {
      throw const FormatException('bad epoch');
    }
    final rec = VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: account,
      deviceId: str('deviceId'),
      epoch: epoch,
      identityKey: b64('ik'),
      ed25519: b64('ed'),
      bindingSignature: b64('sig', len: 64),
      bound: true,
      updatedAt: updatedAt,
    );
    if (rec.identityKey == null ||
        rec.ed25519 == null ||
        rec.accountPublicKey == null ||
        rec.epoch == null ||
        rec.deviceId == null) {
      throw const FormatException('bound record missing fields');
    }
    return rec;
  }
}

// =============================================================================
// Events
// =============================================================================

/// Kinds of user-visible identity events.
enum IdentityEventKind {
  /// Bound peer, same account, new device keys (reinstall) — non-blocking
  /// notice (still worth showing: it is also what a leaked account key
  /// looks like).
  deviceKeysChanged,

  /// A binding failed verification, or the peer presented none (see
  /// [IdentityStoreEvent.reason]).
  bindingRejected,
}

class IdentityStoreEvent {
  final IdentityEventKind kind;
  final String peerId;
  final IdentityBindingFailure? reason;
  final DateTime at;

  IdentityStoreEvent({
    required this.kind,
    required this.peerId,
    this.reason,
  }) : at = DateTime.now();
}

// =============================================================================
// Abstract store
// =============================================================================

/// Per-peer verified identity store. See the file header for the model.
///
/// Subclasses implement the storage primitives ([readRecord], [writeRecord],
/// [deleteRecord], [readLatch], [writeLatch]). Everything else is policy
/// implemented here and should not be overridden.
abstract class VerifiedIdentityStore {
  /// Peer-id scheme used to check account keys against peer ids.
  final IdentityIdScheme idScheme;

  final StreamController<IdentityStoreEvent> _events =
      StreamController<IdentityStoreEvent>.broadcast();

  VerifiedIdentityStore({this.idScheme = const SnowChatIdScheme()});

  // ---------------------------------------------------------------------------
  // Storage primitives (implement these)
  // ---------------------------------------------------------------------------

  /// Read the record for [peerId], or null. Decode with
  /// [VerifiedIdentityRecord.fromJson]; a corrupt persisted entry MUST be
  /// returned as null (treated as absent), never thrown. [fresh] asks the
  /// implementation to bypass any in-memory cache (another process / isolate
  /// may have written since); it is set before destructive decisions.
  /// Infrastructure failures (storage unavailable) should throw — the
  /// service surfaces them as a transient [SignalProtocolException].
  Future<VerifiedIdentityRecord?> readRecord(String peerId,
      {bool fresh = false});

  /// Persist [record] (replace).
  Future<void> writeRecord(VerifiedIdentityRecord record);

  /// Delete the record for [peerId]. MUST NOT touch the latch.
  Future<void> deleteRecord(String peerId);

  /// Highest accepted binding epoch for [peerId], or null if never latched.
  /// A corrupt persisted latch MUST be returned as 0 (fail closed: the peer
  /// stays latched), never as null.
  Future<int?> readLatch(String peerId, {bool fresh = false});

  /// Persist [epoch] as the latch of [peerId]. Called only with a value
  /// greater than the current one (see [raiseLatch]).
  Future<void> writeLatch(String peerId, int epoch);

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  /// Identity event stream (device key change, rejection).
  Stream<IdentityStoreEvent> get events => _events.stream;

  /// Broadcast an identity event. Never throws.
  void emit(IdentityStoreEvent event) {
    if (!_events.isClosed) _events.add(event);
  }

  /// Close the event stream.
  void dispose() {
    if (!_events.isClosed) _events.close();
  }

  // ---------------------------------------------------------------------------
  // Reads
  // ---------------------------------------------------------------------------

  /// Record for [peerId], or null.
  Future<VerifiedIdentityRecord?> get(String peerId) async {
    if (peerId.isEmpty) return null;
    return readRecord(peerId);
  }

  /// Like [get] but bypasses caches. Used before destructive decisions.
  Future<VerifiedIdentityRecord?> getFresh(String peerId) async {
    if (peerId.isEmpty) return null;
    return readRecord(peerId, fresh: true);
  }

  /// Highest accepted binding epoch for [peerId]; null when the peer never
  /// proved a binding.
  Future<int?> latchedEpoch(String peerId, {bool fresh = false}) async {
    if (peerId.isEmpty) return null;
    return readLatch(peerId, fresh: fresh);
  }

  // ---------------------------------------------------------------------------
  // Writes
  // ---------------------------------------------------------------------------

  Future<void> put(VerifiedIdentityRecord record) => writeRecord(record);

  /// Monotonic latch: stores max(current, [epoch]). Never lowers.
  Future<void> raiseLatch(String peerId, int epoch) async {
    if (peerId.isEmpty) return;
    if (epoch < 0) throw ArgumentError('latch epoch must be >= 0');
    final current = await readLatch(peerId, fresh: true);
    if (current != null && current >= epoch) return;
    await writeLatch(peerId, epoch);
  }

  /// Drop the record for [peerId] (contact removed / chat deleted). The latch
  /// is intentionally KEPT so a peer that once proved a binding can never be
  /// silently downgraded to an unbound key afterwards.
  Future<void> remove(String peerId) async {
    if (peerId.isEmpty) return;
    await deleteRecord(peerId);
  }

  /// Pin [accountPublicKey] for [peerId] from an out-of-band source the peer
  /// or the user controls (invite link, QR code, the user's own
  /// authenticated contact backup). Latches the peer so a server can never
  /// downgrade this contact to unbound keys. Returns false when the key does
  /// not derive [peerId] or conflicts with an already pinned key.
  Future<bool> pinAccountKey(String peerId, Uint8List accountPublicKey) async {
    if (!IdentityBindingV1.accountKeyMatchesPeerId(accountPublicKey, peerId,
        idScheme: idScheme)) {
      return false;
    }
    final existing = await getFresh(peerId);
    if (existing?.accountPublicKey != null &&
        !constantTimeEquals(existing!.accountPublicKey, accountPublicKey)) {
      return false;
    }
    final rec = existing == null
        ? VerifiedIdentityRecord(
            peerId: peerId,
            accountPublicKey: Uint8List.fromList(accountPublicKey),
            updatedAt: DateTime.now().millisecondsSinceEpoch,
          )
        : existing.copyWith(
            accountPublicKey: Uint8List.fromList(accountPublicKey));
    await put(rec);
    if (await latchedEpoch(peerId, fresh: true) == null) {
      await raiseLatch(peerId, 0);
    }
    return true;
  }

  /// Remember a server-supplied account key for a peer this store has no
  /// record of yet, only if it derives [peerId]. Used for the account-key
  /// Safety Number of a peer not met yet. Does NOT latch. (Every existing
  /// record already holds the account key: a binding carries it, a pin is
  /// one.)
  Future<void> rememberAccountKey(
      String peerId, Uint8List? accountPublicKey) async {
    if (!IdentityBindingV1.accountKeyMatchesPeerId(accountPublicKey, peerId,
        idScheme: idScheme)) {
      return;
    }
    if (await getFresh(peerId) != null) return;
    await put(VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: Uint8List.fromList(accountPublicKey!),
      updatedAt: DateTime.now().millisecondsSinceEpoch,
    ));
  }
}

// =============================================================================
// In-memory reference implementation
// =============================================================================

/// Non-persistent [VerifiedIdentityStore] for tests, examples and
/// short-lived tools. Production code MUST persist records AND latches in
/// secure storage: losing the latch silently re-opens the downgrade window.
class InMemoryVerifiedIdentityStore extends VerifiedIdentityStore {
  InMemoryVerifiedIdentityStore({super.idScheme});

  final Map<String, String> _records = {};
  final Map<String, int> _latches = {};

  @override
  Future<VerifiedIdentityRecord?> readRecord(String peerId,
      {bool fresh = false}) async {
    final raw = _records[peerId];
    if (raw == null) return null;
    try {
      final rec = VerifiedIdentityRecord.fromJson(
          Map<String, dynamic>.from(jsonDecode(raw) as Map));
      return rec.peerId == peerId ? rec : null;
    } catch (_) {
      return null;
    }
  }

  @override
  Future<void> writeRecord(VerifiedIdentityRecord record) async {
    // Round-trip through JSON so tests exercise the persisted codec.
    _records[record.peerId] = jsonEncode(record.toJson());
  }

  @override
  Future<void> deleteRecord(String peerId) async {
    _records.remove(peerId);
  }

  @override
  Future<int?> readLatch(String peerId, {bool fresh = false}) async =>
      _latches[peerId];

  @override
  Future<void> writeLatch(String peerId, int epoch) async {
    _latches[peerId] = epoch;
  }

  /// Test hook: overwrite the raw persisted JSON of a record.
  void putRawRecordForTesting(String peerId, String rawJson) {
    _records[peerId] = rawJson;
  }
}
