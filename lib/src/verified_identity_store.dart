/// @file        verified_identity_store.dart
/// @description Identity Binding v1 — per-peer store of the remote identity
///              we verified (bound peers) or TOFU-saw (legacy, binding-less
///              peers). Supersedes the TOFU-only IdentityPinStore.
///
///              The library does not prescribe persistence. Integrators
///              subclass [VerifiedIdentityStore] and implement a handful of
///              storage primitives against platform-secure storage (Keychain /
///              Keystore / encrypted DB); all policy-relevant operations
///              (monotonic latch, latch survives remove(), invite-link pin,
///              pending-change re-verification, legacy IK seeding) are
///              implemented once here on top of those primitives.
///              [InMemoryVerifiedIdentityStore] is a reference implementation
///              for tests and examples — it is NOT persistent.
///
///              Two independent persisted facts per peer:
///               - the RECORD (current keys, account key, bound flag, pending
///                 change) — may be removed when a contact is deleted;
///               - the LATCH (highest accepted binding epoch) — presence means
///                 "this peer proved a binding once"; it is NEVER removed by
///                 [VerifiedIdentityStore.remove], so a peer can never be
///                 silently downgraded to unbound keys afterwards, and it never
///                 decreases, so a superseded binding cannot be replayed.
///
///              App-specific concerns (migration from an application's legacy
///              key layout, keychain-locked deferral, cross-isolate caching)
///              belong in the integrator's subclass; see README.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
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
///  - VerifiedIdentityStore.pinFromInviteLink(): pin an account key out of band
///  - VerifiedIdentityStore.rememberAccountKey(): store a derive-checked account key
///  - VerifiedIdentityStore.acceptPendingChange(): re-verify -> adopt pending keys
///  - VerifiedIdentityStore.importLegacyPin(): carry over an IdentityPinStore pin
///  - VerifiedIdentityStore.seedLegacyIdentityKeys(): one-time IK seeding
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

/// One remote identity, keyed by peer id.
class VerifiedIdentityRecord {
  static const int schema = 1;

  /// Peer id (derived from the account key under the store's scheme).
  final String peerId;

  /// Peer ACCOUNT public key (peer-id root). Present when a binding verified,
  /// when an invite link pinned it, or when the server supplied a key that
  /// derives the peer id (legacy peer).
  final Uint8List? accountPublicKey;

  /// Device the current keys belong to.
  final String? deviceId;

  /// Epoch of the accepted binding (bound records only).
  final int? epoch;

  /// X25519 identity key used in X3DH.
  final Uint8List? identityKey;

  /// Signal-layer Ed25519 signing key (signed-prekey signatures).
  final Uint8List? ed25519;

  /// [ed25519] came from a weak, pre-binding source (e.g. an imported
  /// IdentityPinStore pin that may have been fed by a server lookup). On a
  /// legacy -> bound promotion only the IK is compared against it, and on a
  /// legacy key observation it is simply replaced, never treated as a change.
  final bool edLegacySourced;

  /// Binding signature (bound records only).
  final Uint8List? bindingSignature;

  /// True once a valid binding was accepted for the current keys.
  final bool bound;

  /// ms since epoch of the last write.
  final int updatedAt;

  /// Legacy peer whose keys changed while the user had marked them verified:
  /// the new keys wait here until the user re-verifies
  /// ([VerifiedIdentityStore.acceptPendingChange]). While set, the peer is
  /// blocked for sending and for new inbound sessions.
  final Uint8List? pendingIdentityKey;
  final Uint8List? pendingEd25519;
  final String? pendingDeviceId;

  const VerifiedIdentityRecord({
    required this.peerId,
    this.accountPublicKey,
    this.deviceId,
    this.epoch,
    this.identityKey,
    this.ed25519,
    this.edLegacySourced = false,
    this.bindingSignature,
    this.bound = false,
    required this.updatedAt,
    this.pendingIdentityKey,
    this.pendingEd25519,
    this.pendingDeviceId,
  });

  bool get hasPendingChange =>
      pendingIdentityKey != null || pendingEd25519 != null;

  VerifiedIdentityRecord copyWith({
    Uint8List? accountPublicKey,
    String? deviceId,
    int? epoch,
    Uint8List? identityKey,
    Uint8List? ed25519,
    Uint8List? bindingSignature,
    bool? bound,
    bool clearPending = false,
    Uint8List? pendingIdentityKey,
    Uint8List? pendingEd25519,
    String? pendingDeviceId,
  }) {
    return VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: accountPublicKey ?? this.accountPublicKey,
      deviceId: deviceId ?? this.deviceId,
      epoch: epoch ?? this.epoch,
      identityKey: identityKey ?? this.identityKey,
      ed25519: ed25519 ?? this.ed25519,
      edLegacySourced: ed25519 != null ? false : edLegacySourced,
      bindingSignature: bindingSignature ?? this.bindingSignature,
      bound: bound ?? this.bound,
      updatedAt: DateTime.now().millisecondsSinceEpoch,
      pendingIdentityKey: clearPending
          ? null
          : (pendingIdentityKey ?? this.pendingIdentityKey),
      pendingEd25519:
          clearPending ? null : (pendingEd25519 ?? this.pendingEd25519),
      pendingDeviceId:
          clearPending ? null : (pendingDeviceId ?? this.pendingDeviceId),
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
        if (edLegacySourced) 'edLegacy': true,
        if (bindingSignature != null) 'sig': base64Encode(bindingSignature!),
        'bound': bound,
        'updatedAt': updatedAt,
        if (pendingIdentityKey != null)
          'pendingIk': base64Encode(pendingIdentityKey!),
        if (pendingEd25519 != null) 'pendingEd': base64Encode(pendingEd25519!),
        if (pendingDeviceId != null) 'pendingDeviceId': pendingDeviceId,
      };

  /// Strict decode; throws [FormatException] on any inconsistency so the
  /// caller can treat the entry as corrupt (the separate latch still blocks
  /// a downgrade for a peer that proved a binding).
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
    final epochStr = j['epoch'];
    final epoch =
        epochStr == null ? null : IdentityBindingV1.parseEpoch(epochStr);
    if (epochStr != null && epoch == null) {
      throw const FormatException('bad epoch');
    }
    final peerId = str('snowId');
    if (peerId == null) throw const FormatException('missing id');
    final edLegacy = j['edLegacy'];
    final bound = j['bound'];
    final updatedAt = j['updatedAt'];
    final rec = VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: account,
      deviceId: str('deviceId'),
      epoch: epoch,
      identityKey: b64('ik'),
      ed25519: b64('ed'),
      edLegacySourced: edLegacy is bool && edLegacy,
      bindingSignature: b64('sig', len: 64),
      bound: bound is bool && bound,
      updatedAt: updatedAt is int ? updatedAt : 0,
      pendingIdentityKey: b64('pendingIk'),
      pendingEd25519: b64('pendingEd'),
      pendingDeviceId: str('pendingDeviceId'),
    );
    if (rec.bound &&
        (rec.identityKey == null ||
            rec.ed25519 == null ||
            rec.accountPublicKey == null ||
            rec.epoch == null)) {
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
  /// Legacy (unbound) peer changed keys; the user had NOT verified them ->
  /// keys updated, conversation continues, "safety number changed" notice.
  legacyKeyChanged,

  /// Legacy peer changed keys while marked verified -> blocked until the
  /// user re-verifies ([VerifiedIdentityStore.acceptPendingChange]).
  /// Emitted once, on the transition into the blocked state.
  legacyKeyChangeBlocked,

  /// Bound peer, same account, new device keys (reinstall) — non-blocking
  /// notice (still worth showing: it is also what a leaked account key
  /// looks like).
  deviceKeysChanged,

  /// Legacy -> bound promotion found that the keys used before differ from
  /// the account-signed ones: earlier traffic may have been intercepted.
  interceptionSuspected,

  /// A binding failed verification (see [IdentityStoreEvent.reason]).
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
/// [deleteRecord], [readLatch], [writeLatch], [readMetadata],
/// [writeMetadata]) and may override [isPeerVerified]. Everything else is
/// policy implemented here and should not be overridden.
abstract class VerifiedIdentityStore {
  /// Peer-id scheme used to check account keys against peer ids.
  final IdentityIdScheme idScheme;

  final StreamController<IdentityStoreEvent> _events =
      StreamController<IdentityStoreEvent>.broadcast();

  VerifiedIdentityStore({this.idScheme = const SnowChatIdScheme()});

  /// Metadata key guarding the one-time [seedLegacyIdentityKeys] run.
  static const String ikSeededMarkerKey = 'verified_identity_ik_seeded';

  // ---------------------------------------------------------------------------
  // Storage primitives (implement these)
  // ---------------------------------------------------------------------------

  /// Read the record for [peerId], or null. A corrupt persisted entry MUST be
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

  /// Small key/value metadata (one-time markers).
  Future<String?> readMetadata(String key);
  Future<void> writeMetadata(String key, String value);

  /// Whether the user marked [peerId] as verified (compared Safety Numbers).
  /// Default: never verified. Errors propagate (fail closed: the admission
  /// surfaces a transient error instead of guessing "not verified").
  Future<bool> isPeerVerified(String peerId) async => false;

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  /// Identity event stream (legacy key change, device key change, rejection…).
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
  /// controls (invite link, QR code). Latches the peer so a server can never
  /// downgrade this first contact to unbound keys. Returns false when the
  /// key does not derive [peerId] or conflicts with an already pinned key.
  Future<bool> pinFromInviteLink(
      String peerId, Uint8List accountPublicKey) async {
    if (!IdentityBindingV1.accountKeyMatchesPeerId(accountPublicKey, peerId,
        idScheme: idScheme)) {
      return false;
    }
    final existing = await get(peerId);
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
        : existing.copyWith(accountPublicKey: accountPublicKey);
    await put(rec);
    if (await latchedEpoch(peerId, fresh: true) == null) {
      await raiseLatch(peerId, 0);
    }
    return true;
  }

  /// Remember a server-supplied account key for a legacy peer, only if it
  /// derives [peerId] and no key is recorded yet. Used for the account-key
  /// Safety Number of peers that have no binding yet. Does NOT latch.
  Future<void> rememberAccountKey(
      String peerId, Uint8List? accountPublicKey) async {
    if (!IdentityBindingV1.accountKeyMatchesPeerId(accountPublicKey, peerId,
        idScheme: idScheme)) {
      return;
    }
    final existing = await get(peerId);
    if (existing == null) {
      await put(VerifiedIdentityRecord(
        peerId: peerId,
        accountPublicKey: Uint8List.fromList(accountPublicKey!),
        updatedAt: DateTime.now().millisecondsSinceEpoch,
      ));
      return;
    }
    if (existing.accountPublicKey != null) return;
    await put(existing.copyWith(accountPublicKey: accountPublicKey));
  }

  /// Re-verification (user compared Safety Numbers again): adopt the pending
  /// (blocked) keys as current and clear the block. Returns true when
  /// something changed.
  Future<bool> acceptPendingChange(String peerId) async {
    final rec = await getFresh(peerId);
    if (rec == null || !rec.hasPendingChange) return false;
    await put(VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: rec.accountPublicKey,
      deviceId: rec.pendingDeviceId ?? rec.deviceId,
      identityKey: rec.pendingIdentityKey ?? rec.identityKey,
      ed25519: rec.pendingEd25519 ?? rec.ed25519,
      bound: false,
      updatedAt: DateTime.now().millisecondsSinceEpoch,
    ));
    return true;
  }

  /// Carry over a pin from the deprecated `IdentityPinStore` (keyed
  /// `"peerId:deviceId"`, Ed25519 only). Writes a legacy-sourced record only
  /// when no record exists yet; never overwrites newer data. Integrators
  /// enumerate their own pin storage (the abstract IdentityPinStore has no
  /// enumeration API) and call this once per pin.
  Future<void> importLegacyPin({
    required String peerId,
    String? deviceId,
    required Uint8List ed25519,
  }) async {
    if (peerId.isEmpty || ed25519.length != 32) return;
    if (await getFresh(peerId) != null) return;
    await put(VerifiedIdentityRecord(
      peerId: peerId,
      deviceId: deviceId,
      ed25519: Uint8List.fromList(ed25519),
      edLegacySourced: true,
      updatedAt: DateTime.now().millisecondsSinceEpoch,
    ));
  }

  /// One-time seeding of legacy records from the X25519 identity keys the
  /// session store learned before Identity Binding existed (called by
  /// SignalProtocolService.loadSessionStore). Fills the IK of unbound
  /// records that lack one and creates a legacy baseline for peers with a
  /// session but no record. Guarded by [ikSeededMarkerKey] so a later
  /// [remove] is not undone on the next load.
  ///
  /// [deviceIds] gives the device each IK was learned from; a different
  /// device on a later bound promotion is reinstall evidence (device notice)
  /// rather than interception.
  Future<void> seedLegacyIdentityKeys(
    Map<String, Uint8List> remoteIks, {
    Map<String, String> deviceIds = const {},
  }) async {
    if (await readMetadata(ikSeededMarkerKey) == '1') return;
    for (final entry in remoteIks.entries) {
      final peerId = entry.key;
      final ik = entry.value;
      if (!IdentityBindingV1.isValidPeerId(peerId, idScheme: idScheme) ||
          ik.length != 32) {
        continue;
      }
      final rec = await getFresh(peerId);
      final dev = deviceIds[peerId];
      if (rec == null) {
        await put(VerifiedIdentityRecord(
          peerId: peerId,
          identityKey: Uint8List.fromList(ik),
          deviceId: dev,
          updatedAt: DateTime.now().millisecondsSinceEpoch,
        ));
      } else if (!rec.bound && rec.identityKey == null) {
        await put(rec.copyWith(
            identityKey: ik, deviceId: rec.deviceId == null ? dev : null));
      }
    }
    await writeMetadata(ikSeededMarkerKey, '1');
  }
}

// =============================================================================
// In-memory reference implementation
// =============================================================================

/// Non-persistent [VerifiedIdentityStore] for tests, examples and
/// short-lived tools. Production code MUST persist records AND latches in
/// secure storage: losing the latch silently re-opens the downgrade window.
class InMemoryVerifiedIdentityStore extends VerifiedIdentityStore {
  InMemoryVerifiedIdentityStore({super.idScheme, this.verifiedLookup});

  /// Optional "has the user verified this peer?" hook.
  Future<bool> Function(String peerId)? verifiedLookup;

  final Map<String, String> _records = {};
  final Map<String, int> _latches = {};
  final Map<String, String> _meta = {};

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

  @override
  Future<String?> readMetadata(String key) async => _meta[key];

  @override
  Future<void> writeMetadata(String key, String value) async {
    _meta[key] = value;
  }

  @override
  Future<bool> isPeerVerified(String peerId) async {
    final lookup = verifiedLookup;
    if (lookup == null) return false;
    return lookup(peerId);
  }

  /// Test hook: overwrite the raw persisted JSON of a record.
  void putRawRecordForTesting(String peerId, String rawJson) {
    _records[peerId] = rawJson;
  }
}
