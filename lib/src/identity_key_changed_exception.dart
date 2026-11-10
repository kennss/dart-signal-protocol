/// @file        identity_key_changed_exception.dart
/// @description Typed exception raised when a peer's identity keys changed
///              and the change must be confirmed by the user before any new
///              session is established. With a VerifiedIdentityStore it is
///              raised only for a peer WITHOUT an identity binding that the
///              user had marked verified (the new keys are parked as pending
///              until VerifiedIdentityStore.acceptPendingChange); unverified
///              legacy peers are updated with a legacyKeyChanged event
///              instead. With the deprecated IdentityPinStore it is the TOFU
///              mismatch.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-20
/// @lastUpdated 2026-11-10 (Identity Binding v1 semantics; peerId alias)

import 'dart:typed_data';

/// Raised when a peer's identity keys observed during session setup differ
/// from the accepted ones and the user must re-verify (see file header).
///
/// Callers should route this into their Safety Number / verification flow
/// (re-prompt user, update UI, dead-letter the envelope, etc.) instead of
/// silently installing a session with a potentially malicious key.
class IdentityKeyChangedException implements Exception {
  /// SnowChat ID / user identifier of the peer whose key changed.
  final String peerSnowchatId;

  /// Device ID that changed keys, if known.
  final String? deviceId;

  /// Alias of [peerSnowchatId] (generic name).
  String get peerId => peerSnowchatId;

  /// The key we had pinned previously (first observation).
  final Uint8List expectedKey;

  /// The key we just observed (new / attacker-controlled).
  final Uint8List actualKey;

  const IdentityKeyChangedException({
    required this.peerSnowchatId,
    this.deviceId,
    required this.expectedKey,
    required this.actualKey,
  });

  @override
  String toString() {
    final dev = deviceId != null ? ':$deviceId' : '';
    return 'IdentityKeyChangedException(peer=$peerSnowchatId$dev, '
        'expectedLen=${expectedKey.length}, actualLen=${actualKey.length})';
  }
}
