/// @file        identity_binding_exception.dart
/// @description Hard-failure exception for Identity Binding v1. Raised when a
///              peer's key bundle / PreKey message carries a forged or
///              inconsistent identity binding, when a peer that proved a
///              binding before shows up without one (downgrade), or when an
///              epoch is replayed. Unlike transient Signal errors this is
///              NEVER retryable: callers must surface it (the
///              VerifiedIdentityStore has already emitted a bindingRejected
///              event) and stop — retrying cannot change the outcome and only
///              burns the peer's one-time prekeys.
///
///              The message text deliberately contains no key material and no
///              full identifiers, and avoids generic phrases ("could not
///              decrypt", "malformed", "not found") that string-matching
///              error classifiers tend to route into retry/reset paths.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - IdentityBindingFailure: reason taxonomy
///  - IdentityBindingInvalidException: typed hard failure (no retry)
library;

import 'signal_protocol_service.dart';

/// Why a binding was rejected. Names are wire/log-safe (no key material).
enum IdentityBindingFailure {
  /// Binding present but structurally unusable (bad lengths, bad encoding,
  /// or a binding without the account key needed to verify it).
  badFormat,

  /// The Ed25519 signature did not verify, or the account key does not
  /// derive the peer id.
  signatureInvalid,

  /// Account key differs from the one already recorded for the peer
  /// (invite-link pin or an earlier verified binding).
  accountKeyMismatch,

  /// Epoch lower than the highest accepted epoch (replay of a superseded
  /// identity), or the same epoch re-used for different keys.
  epochRegression,

  /// Peer proved a binding before (latched) but now presents none.
  downgrade,

  /// Binding's deviceId differs from the device the envelope / sender
  /// certificate names.
  deviceMismatch,

  /// The X25519 identity key in the message differs from the key the
  /// account bound for that device.
  identityKeyMismatch,
}

/// Typed, non-retryable identity failure. Extends [SignalProtocolException]
/// so generic handlers still see a protocol error, but callers SHOULD catch
/// this type first and treat it as terminal for the message / send attempt.
class IdentityBindingInvalidException extends SignalProtocolException {
  /// Peer whose binding failed.
  final String peerId;

  /// Rejection reason.
  final IdentityBindingFailure reason;

  IdentityBindingInvalidException({
    required this.peerId,
    required this.reason,
  }) : super(
          'Identity binding rejected for peer (${reason.name}); '
          'refusing session — not retryable',
          code: 'identity_binding_invalid',
        );
}
