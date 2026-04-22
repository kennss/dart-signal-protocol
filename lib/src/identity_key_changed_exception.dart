/// @file        identity_key_changed_exception.dart
/// @description Typed exception raised when a peer's Ed25519 identity key
///              observed during session establishment does not match the
///              previously pinned key (TOFU mismatch).
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-20
/// @lastUpdated 2026-04-20

import 'dart:typed_data';

/// Raised when a peer's Ed25519 verify key observed during session setup
/// differs from the key previously pinned via [IdentityPinStore].
///
/// Callers should route this into their Safety Number / verification flow
/// (re-prompt user, update UI, dead-letter the envelope, etc.) instead of
/// silently installing a session with a potentially malicious key.
class IdentityKeyChangedException implements Exception {
  /// SnowChat ID / user identifier of the peer whose key changed.
  final String peerSnowchatId;

  /// Device ID that changed keys, if known.
  final String? deviceId;

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
