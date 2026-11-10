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
///                Same-account key change -> non-blocking "device keys
///                changed" notice. Legacy -> bound promotion with different
///                keys -> "interception suspected" warning.
///              Unbound (no binding):
///                latched peer -> IdentityBindingInvalidException(downgrade).
///                Otherwise the Signal-style legacy policy:
///                  unchanged -> accept; changed & not verified -> update +
///                  notice + continue; changed & verified -> park the new
///                  keys as "pending" and throw IdentityKeyChangedException
///                  until the user re-verifies.
///
///              Pure policy over a VerifiedIdentityStore — no network and no
///              session state — so integrators can call it directly (e.g. to
///              pre-admit a peer from a non-consuming identity directory
///              BEFORE fetching / consuming a one-time prekey). Session
///              purging is done by SignalProtocolService using
///              [AdmittedIdentity.boundIdentityKey].
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - AdmittedIdentity: result of a successful admission
///  - RemoteDeviceIdentity / RemoteIdentityDirectory: server identity views
///  - IdentityAdmission.admitBound(): verify + record a bound identity
///  - IdentityAdmission.admitUnbound(): latch check + legacy policy
///  - IdentityAdmission.selectDevice(): pick the highest-epoch valid device
///  - IdentityAdmission.admitDirectory(): non-consuming pre-admission
///  - IdentityAdmission.reject(): emit a rejection event and build the exception
///  - IdentityAdmission.promotionNotice(): notice kind for a key transition
library;

import 'dart:typed_data';

import 'identity_binding.dart';
import 'identity_binding_exception.dart';
import 'identity_bytes.dart';
import 'identity_key_changed_exception.dart';
import 'verified_identity_store.dart';

/// Outcome of a successful admission.
class AdmittedIdentity {
  final Uint8List identityKey;
  final Uint8List? ed25519;
  final bool bound;

  /// Non-null when the peer is bound: every session (active or archived)
  /// whose remote IK differs from this key must be purged / refused.
  final Uint8List? boundIdentityKey;

  /// Device of the bound identity (lets the Signal layer keep pre-binding
  /// sessions of that same device instead of purging them).
  final String? boundDeviceId;

  const AdmittedIdentity({
    required this.identityKey,
    required this.ed25519,
    required this.bound,
    this.boundIdentityKey,
    this.boundDeviceId,
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
  /// binding, the first device is used (legacy, single-device world). When
  /// bindings are present but none verifies, the set is rejected — an honest
  /// server drops invalid bindings at upload, so this is tampering.
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
  /// bound), then runs [admitBound] / [admitUnbound] for it. Throws the typed
  /// identity failures exactly like those; returns null when the directory
  /// lists no device.
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
      admitted = await admitUnbound(
        peerId: peerId,
        deviceId: pick.deviceId,
        identityKey: pick.identityKey,
        ed25519: ed,
        accountPublicKey: directory.accountPublicKey,
      );
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
      return AdmittedIdentity(
        identityKey: identityKey,
        ed25519: ed25519,
        bound: true,
        boundIdentityKey: identityKey,
        boundDeviceId: deviceId,
      );
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

    if (existing != null) {
      final kind = promotionNotice(
        existing: existing,
        deviceId: deviceId,
        identityKey: identityKey,
        ed25519: ed25519,
      );
      if (kind != null) {
        store.emit(IdentityStoreEvent(kind: kind, peerId: peerId));
      }
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

    return AdmittedIdentity(
      identityKey: identityKey,
      ed25519: ed25519,
      bound: true,
      boundIdentityKey: identityKey,
      boundDeviceId: deviceId,
    );
  }

  /// Which notice (if any) a transition from [existing] to the bound
  /// (deviceId, IK, Ed) deserves.
  ///  - bound -> bound with any change: non-blocking device-keys notice.
  ///  - legacy -> bound (post-hoc interception detection):
  ///      * a legacy-sourced Ed is weak evidence -> only the IK is compared;
  ///      * a pending (blocked) change that matches the bound keys was the
  ///        real reinstall -> device notice;
  ///      * a different recorded deviceId is reinstall evidence -> device
  ///        notice (an honest reinstall must not trip the red alarm);
  ///      * otherwise the keys used before were not the account-signed ones
  ///        -> interceptionSuspected.
  static IdentityEventKind? promotionNotice({
    required VerifiedIdentityRecord existing,
    required String deviceId,
    required Uint8List identityKey,
    required Uint8List ed25519,
  }) {
    final ikChanged = existing.identityKey != null &&
        !constantTimeEquals(existing.identityKey, identityKey);
    if (existing.bound) {
      final edChanged = existing.ed25519 != null &&
          !constantTimeEquals(existing.ed25519, ed25519);
      return (ikChanged || edChanged || existing.deviceId != deviceId)
          ? IdentityEventKind.deviceKeysChanged
          : null;
    }
    final edChanged = !existing.edLegacySourced &&
        existing.ed25519 != null &&
        !constantTimeEquals(existing.ed25519, ed25519);
    if (existing.hasPendingChange) {
      final pendingMatches = (existing.pendingIdentityKey == null ||
              constantTimeEquals(existing.pendingIdentityKey, identityKey)) &&
          (existing.pendingEd25519 == null ||
              constantTimeEquals(existing.pendingEd25519, ed25519));
      return pendingMatches
          ? IdentityEventKind.deviceKeysChanged
          : IdentityEventKind.interceptionSuspected;
    }
    if (!ikChanged && !edChanged) return null;
    final reinstallEvidence =
        existing.deviceId != null && existing.deviceId != deviceId;
    return reinstallEvidence
        ? IdentityEventKind.deviceKeysChanged
        : IdentityEventKind.interceptionSuspected;
  }

  /// Admission for a peer that presented NO binding.
  ///
  /// [identityKey] is the X25519 IK that will be used in X3DH (bundle IK on
  /// send, PreKey header IK on receive). [ed25519] may be null on receive
  /// when it is unknown. [accountPublicKey] is an optional server-supplied
  /// account key (remembered only if it derives [peerId]).
  Future<AdmittedIdentity> admitUnbound({
    required String peerId,
    required String? deviceId,
    required Uint8List identityKey,
    required Uint8List? ed25519,
    Uint8List? accountPublicKey,
  }) async {
    if (await store.latchedEpoch(peerId, fresh: true) != null) {
      throw reject(peerId, IdentityBindingFailure.downgrade);
    }
    final existing = await store.getFresh(peerId);
    final knownAccount = existing?.accountPublicKey ??
        (IdentityBindingV1.accountKeyMatchesPeerId(accountPublicKey, peerId,
                idScheme: _scheme)
            ? accountPublicKey
            : null);

    if (existing == null ||
        (existing.identityKey == null && existing.ed25519 == null)) {
      // First sighting (TOFU baseline for an unbound peer).
      await store.put(VerifiedIdentityRecord(
        peerId: peerId,
        accountPublicKey: knownAccount,
        deviceId: deviceId,
        identityKey: Uint8List.fromList(identityKey),
        ed25519: ed25519 == null ? null : Uint8List.fromList(ed25519),
        updatedAt: DateTime.now().millisecondsSinceEpoch,
      ));
      return AdmittedIdentity(
          identityKey: identityKey, ed25519: ed25519, bound: false);
    }

    final ikChanged = existing.identityKey != null &&
        !constantTimeEquals(existing.identityKey, identityKey);
    // A legacy-sourced Ed may come from a server-trusting lookup — never
    // treat a difference against it as a key change; it is simply replaced
    // by the Ed actually used for X3DH.
    final edChanged = !existing.edLegacySourced &&
        existing.ed25519 != null &&
        ed25519 != null &&
        !constantTimeEquals(existing.ed25519, ed25519);

    if (!ikChanged && !edChanged) {
      // Unchanged — fill in any field we did not know yet; keys that came
      // back to the accepted value also clear a pending block.
      final replaceLegacyEd = existing.edLegacySourced && ed25519 != null;
      final needsFill = existing.identityKey == null ||
          (existing.ed25519 == null && ed25519 != null) ||
          replaceLegacyEd ||
          (existing.accountPublicKey == null && knownAccount != null) ||
          existing.hasPendingChange;
      final effectiveEd =
          replaceLegacyEd ? ed25519 : (existing.ed25519 ?? ed25519);
      if (needsFill) {
        await store.put(VerifiedIdentityRecord(
          peerId: peerId,
          accountPublicKey: existing.accountPublicKey ?? knownAccount,
          deviceId: existing.deviceId ?? deviceId,
          identityKey: existing.identityKey ?? identityKey,
          ed25519: effectiveEd,
          edLegacySourced: !replaceLegacyEd && existing.edLegacySourced,
          updatedAt: DateTime.now().millisecondsSinceEpoch,
        ));
      }
      return AdmittedIdentity(
          identityKey: identityKey, ed25519: effectiveEd, bound: false);
    }

    final alreadyPending = existing.hasPendingChange;
    final verified = alreadyPending || await store.isPeerVerified(peerId);
    if (verified) {
      await store.put(existing.copyWith(
        pendingIdentityKey: identityKey,
        pendingEd25519: ed25519,
        pendingDeviceId: deviceId,
      ));
      // Notify only on the TRANSITION into the blocked state — every
      // redelivery of a held message would otherwise re-emit the alarm.
      if (!alreadyPending) {
        store.emit(IdentityStoreEvent(
          kind: IdentityEventKind.legacyKeyChangeBlocked,
          peerId: peerId,
        ));
      }
      throw IdentityKeyChangedException(
        peerSnowchatId: peerId,
        deviceId: deviceId,
        expectedKey: Uint8List.fromList(
            ikChanged ? existing.identityKey! : existing.ed25519!),
        actualKey: Uint8List.fromList(ikChanged ? identityKey : ed25519!),
      );
    }

    await store.put(VerifiedIdentityRecord(
      peerId: peerId,
      accountPublicKey: existing.accountPublicKey ?? knownAccount,
      deviceId: deviceId ?? existing.deviceId,
      identityKey: Uint8List.fromList(identityKey),
      // An IK change without a known Ed means the old Ed is stale too.
      ed25519: ed25519 ?? (ikChanged ? null : existing.ed25519),
      updatedAt: DateTime.now().millisecondsSinceEpoch,
    ));
    store.emit(IdentityStoreEvent(
      kind: IdentityEventKind.legacyKeyChanged,
      peerId: peerId,
    ));
    return AdmittedIdentity(
        identityKey: identityKey, ed25519: ed25519, bound: false);
  }
}
