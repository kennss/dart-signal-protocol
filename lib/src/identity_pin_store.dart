/// @file        identity_pin_store.dart
/// @description Abstract TOFU identity pin store. Stores a peer's Ed25519
///              verify key on first encounter and checks on subsequent
///              session establishments. Callers supply a concrete
///              implementation (backed by secure storage / Keychain / etc.).
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-20
/// @lastUpdated 2026-04-20
///
/// @functions
///  - IdentityPinStore: abstract TOFU pin interface
///  - IdentityPinStore.getPinned(): fetch the pinned key for a peer
///  - IdentityPinStore.pin(): record the first-observed key for a peer

import 'dart:typed_data';

/// Trust-on-First-Use (TOFU) pin store for peer Ed25519 identity keys.
///
/// This library does not prescribe persistence. A concrete implementation
/// should write to a platform-secure store (iOS Keychain, Android Keystore,
/// encrypted SQLite, etc.).
///
/// The key space is the session key `"recipientId:deviceId"` so that a peer
/// wiping and restoring on the same account still triggers re-verification.
///
/// Mismatches between the pinned key and the newly observed key MUST surface
/// as an [IdentityKeyChangedException] from the calling code so the upper
/// layers can run their Safety Number / verification workflow.
abstract class IdentityPinStore {
  /// Fetch the pinned 32-byte Ed25519 verify key for [sessionKey].
  /// Returns `null` if no pin exists yet (first encounter).
  Future<Uint8List?> getPinned(String sessionKey);

  /// Record the first-observed Ed25519 verify key for [sessionKey].
  /// Callers invoke this only when [getPinned] returned `null`.
  Future<void> pin(String sessionKey, Uint8List identityKey);
}
