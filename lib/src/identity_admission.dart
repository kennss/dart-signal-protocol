/// @file        identity_admission.dart
/// @description Identity Binding v1 — admission policy for remote Signal
///              identities. Decides, for a (peerId, deviceId, IK, Ed) tuple
///              presented by the server (send side) or by a PreKey message
///              (receive side), whether X3DH may run with it:
///
///              Bound (binding present):
///                verify binding -> account-key match with any recorded key ->
///                epoch latch (>= highest accepted; equal only for
///                byte-identical keys) -> record bound=true + raise latch.
///                A key change of a bound peer (same account) -> non-blocking
///                "device keys changed" notice.
///              Unbound (no binding): always refused — bindings are
///                mandatory. A latched peer is refused as a downgrade, any
///                other as bindingRequired. There is no TOFU fallback.
///
///              Pure policy over a VerifiedIdentityStore — no network and no
///              session state — so integrators can call it directly (e.g. to
///              pre-admit a peer from a non-consuming identity directory
///              BEFORE fetching / consuming a one-time prekey). Session
///              purging is done by SignalProtocolService using
///              [AdmittedIdentity.identityKey].
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-23 (backport SnowChat 3df0cc5 / 0aa549b: bindings are mandatory —
///              admitUnbound() and the legacy TOFU policy are gone, refuseUnbound() returns the
///              downgrade / bindingRequired refusal; AdmittedIdentity is always a bound identity
///              {identityKey, ed25519}; promotionNotice() -> keyChangeNotice(): only a bound peer's
///              key change gives a notice). Earlier 2026-11-10
///
/// @functions
///  - AdmittedIdentity: result of a successful admission
///  - RemoteDeviceIdentity / RemoteIdentityDirectory: server identity views
///  - IdentityAdmission.admitBound(): verify + record a bound identity
///  - IdentityAdmission.refuseUnbound(): the refusal for a peer without a binding
///  - IdentityAdmission.selectDevice(): pick the highest-epoch valid device
///  - IdentityAdmission.admitDirectory(): non-consuming pre-admission
///  - IdentityAdmission.reject(): emit a rejection event and build the exception
///  - IdentityAdmission.keyChangeNotice(): notice for a bound peer's key change
library;

import 'dart:typed_data';

import 'identity_binding.dart';
import 'identity_binding_exception.dart';
import 'identity_bytes.dart';
import 'verified_identity_store.dart';

/// Outcome of a successful admission: the peer's account-signed identity.
/// Every session (active or archived) whose remote IK differs from
/// [identityKey] must be purged / refused.
class AdmittedIdentity {
  final Uint8List identityKey;
  final Uint8List ed25519;

  const AdmittedIdentity({
    required this.identityKey,
    required this.ed25519,
  });
}

/// One device as listed by a server identity directory or a prekey bundle
/// endpoint.
class RemoteDeviceIdentity {
  final String deviceId;
  final Uint8List identityKey;
  final Uint8List? ed25519;

  /// Parsed binding, or null when absent / unparseable.
  final IdentityBinding? binding;

  /// True when the server sent a binding object that failed to parse
  /// (treated as an INVALID binding, never as "no binding").
  final bool bindingUnparseable;

  /// Index into the server's original device list (bundle selection).
  final int index;

  const RemoteDeviceIdentity({
    required this.deviceId,
    required this.identityKey,
    required this.ed25519,
    required this.binding,
    required this.bindingUnparseable,
    required this.index,
  });
}

/// Non-consuming identity directory of one user (no one-time prekeys).
class RemoteIdentityDirectory {
  final Uint8List? accountPublicKey;
  final List<RemoteDeviceIdentity> devices;

  const RemoteIdentityDirectory({
    required this.accountPublicKey,
    required this.devices,
  });

  RemoteDeviceIdentity? deviceById(String deviceId) {
    for (final d in devices) {
      if (d.deviceId == deviceId) return d;
    }
    return null;
  }
}

class IdentityAdmission {
  final VerifiedIdentityStore store;

  IdentityAdmission(this.store);

  IdentityIdScheme get _scheme => store.idScheme;

  /// Emit a rejection event and return the exception for the caller to throw.
  IdentityBindingInvalidException reject(
      String peerId, IdentityBindingFailure reason) {
    store.emit(IdentityStoreEvent(
      kind: IdentityEventKind.bindingRejected,
      peerId: peerId,
      reason: reason,
    ));
    return IdentityBindingInvalidException(peerId: peerId, reason: reason);
  }

  /// Pick the device to talk to. Among devices with a VALID binding, the
  /// highest epoch wins; others are ignored. When no device carries a
  /// binding, the first device is returned and the caller refuses it
  /// ([refuseUnbound]). When bindings are present but none verifies, the set
  /// is rejected — an honest server drops invalid bindings at upload, so
  /// this is tampering.
  RemoteDeviceIdentity? selectDevice({
    required String peerId,
    required Uint8List? accountPublicKey,
    required List<RemoteDeviceIdentity> devices,
  }) {
    if (devices.isEmpty) return null;
    RemoteDeviceIdentity? best;
    var anyBindingPresent = false;
    for (final d in devices) {
      if (d.binding == null && !d.bindingUnparseable) continue;
      anyBindingPresent = true;
      final b = d.binding;
      final ed = d.ed25519;
      if (b == null || ed == null || accountPublicKey == null) continue;
      final ok = IdentityBindingV1.verify(
        peerId: peerId,
        accountPublicKey: accountPublicKey,
        deviceId: d.deviceId,
        epoch: b.epoch,
        identityKey: d.identityKey,
        ed25519: ed,
        signature: b.signature,
        idScheme: _scheme,
      );
      if (!ok) continue;
      if (best == null || b.epoch > best.binding!.epoch) best = d;
    }
    if (best != null) return best;
    if (anyBindingPresent) {
      throw reject(peerId, IdentityBindingFailure.signatureInvalid);
    }
    return devices.first;
  }

  /// Admit a peer from a NON-consuming identity directory BEFORE any
  /// one-time prekey is fetched, so a refused peer never costs an OPK.
  /// Selects the device (highest valid epoch, or the first when nobody is
  /// bound), then runs [admitBound] for it — a device without a binding is
  /// refused ([refuseUnbound]). Throws the typed identity failures exactly
  /// like those; returns null when the directory lists no device.
  Future<({RemoteDeviceIdentity device, AdmittedIdentity admitted})?>
      admitDirectory({
    required String peerId,
    required RemoteIdentityDirectory directory,
  }) async {
    final account = directory.accountPublicKey ??
        (await store.getFresh(peerId))?.accountPublicKey;
    final pick = selectDevice(
      peerId: peerId,
      accountPublicKey: account,
      devices: directory.devices,
    );
    if (pick == null) return null;
    final b = pick.binding;
    final ed = pick.ed25519;
    final AdmittedIdentity admitted;
    if (b != null && ed != null && account != null) {
      admitted = await admitBound(
        peerId: peerId,
        deviceId: pick.deviceId,
        identityKey: pick.identityKey,
        ed25519: ed,
        accountPublicKey: account,
        epoch: b.epoch,
        signature: b.signature,
      );
    } else {
      throw await refuseUnbound(peerId);
    }
    return (device: pick, admitted: admitted);
  }

  /// Verify and record a bound identity. Throws
  /// [IdentityBindingInvalidException] on any failure (event emitted).
  Future<AdmittedIdentity> admitBound({
    required String peerId,
    required String deviceId,
    required Uint8List identityKey,
    required Uint8List ed25519,
    required Uint8List accountPublicKey,
    required int epoch,
    required Uint8List signature,
  }) async {
    final ok = IdentityBindingV1.verify(
      peerId: peerId,
      accountPublicKey: accountPublicKey,
      deviceId: deviceId,
      epoch: epoch,
      identityKey: identityKey,
      ed25519: ed25519,
      signature: signature,
      idScheme: _scheme,
    );
    if (!ok) throw reject(peerId, IdentityBindingFailure.signatureInvalid);

    // Fresh reads: never decide on a record / latch another process or
    // isolate has since changed.
    final existing = await store.getFresh(peerId);
    final latch = await store.latchedEpoch(peerId, fresh: true);

    if (existing?.accountPublicKey != null &&
        !constantTimeEquals(existing!.accountPublicKey, accountPublicKey)) {
      throw reject(peerId, IdentityBindingFailure.accountKeyMismatch);
    }

    final sameKeysAsBound = existing != null &&
        existing.bound &&
        existing.deviceId == deviceId &&
        constantTimeEquals(existing.identityKey, identityKey) &&
        constantTimeEquals(existing.ed25519, ed25519);

    // Exactly the keys we already trust (an older or equal epoch for the same
    // device/IK/Ed — e.g. a persistent PreKey message minted before a
    // re-sign): nothing can be replayed, accept without touching the store.
    if (sameKeysAsBound && (existing.epoch ?? -1) >= epoch) {
      return AdmittedIdentity(identityKey: identityKey, ed25519: ed25519);
    }

    if (latch != null) {
      if (epoch < latch) {
        // An older binding for DIFFERENT keys: replay of a superseded identity.
        throw reject(peerId, IdentityBindingFailure.epochRegression);
      }
      if (epoch == latch &&
          existing != null &&
          existing.bound &&
          !sameKeysAsBound) {
        // The same epoch can only legitimately re-appear for the same keys.
        throw reject(peerId, IdentityBindingFailure.epochRegression);
      }
    }

    // A bound peer's key change (same account — checked above).
    if (existing != null &&
        keyChangeNotice(
          existing: existing,
          deviceId: deviceId,
          identityKey: identityKey,
          ed25519: ed25519,
        )) {
      store.emit(IdentityStoreEvent(
        kind: IdentityEventKind.deviceKeysChanged,
        peerId: peerId,
      ));
    }

    await store.put(VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: Uint8List.fromList(accountPublicKey),
      deviceId: deviceId,
      epoch: epoch,
      identityKey: Uint8List.fromList(identityKey),
      ed25519: Uint8List.fromList(ed25519),
      bindingSignature: Uint8List.fromList(signature),
      bound: true,
      updatedAt: DateTime.now().millisecondsSinceEpoch,
    ));
    await store.raiseLatch(peerId, epoch);

    return AdmittedIdentity(identityKey: identityKey, ed25519: ed25519);
  }

  /// Whether moving from [existing] to the bound (deviceId, IK, Ed) is a key
  /// change worth a non-blocking "device keys changed" notice: a BOUND
  /// record whose device or keys differ. A record that only pins the account
  /// key (out-of-band pin, Safety Number lookup) holds no keys — first keys
  /// are no change.
  static bool keyChangeNotice({
    required VerifiedIdentityRecord existing,
    required String deviceId,
    required Uint8List identityKey,
    required Uint8List ed25519,
  }) {
    if (!existing.bound) return false;
    return existing.deviceId != deviceId ||
        !constantTimeEquals(existing.identityKey, identityKey) ||
        !constantTimeEquals(existing.ed25519, ed25519);
  }

  /// The refusal for a peer that presented NO binding (send side: none in
  /// the bundle / directory; receive side: none embedded and none the
  /// directory holds). Bindings are mandatory: without this, a compromised
  /// server could strip the binding of a peer this device has never seen
  /// bound and get its own keys accepted. A peer this device has seen bound
  /// (latched) is refused as a [IdentityBindingFailure.downgrade], any other
  /// as [IdentityBindingFailure.bindingRequired]. Returns the exception for
  /// the caller to throw (the event is emitted). Nothing is recorded.
  Future<IdentityBindingInvalidException> refuseUnbound(String peerId) async {
    final latched = await store.latchedEpoch(peerId, fresh: true) != null;
    return reject(
      peerId,
      latched
          ? IdentityBindingFailure.downgrade
          : IdentityBindingFailure.bindingRequired,
    );
  }
}
