/// @file        dart_signal_protocol.dart
/// @description Pure Dart implementation of the Signal Protocol
///              (X3DH + Double Ratchet + Sender Key) with zero native
///              dependencies. Public API entry point.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-07
/// @lastUpdated 2026-11-23 (ed25519_strict export). Earlier 2026-11-10 (Identity Binding v1 exports: binding, admission, verified identity store, Safety Number)

library dart_signal_protocol;

// Exports are kept in alphabetical order (directives_ordering). Areas:
//  - primitives:      ed25519_strict, hkdf, x25519
//  - 1:1 messaging:   double_ratchet, prekey_bundle, x3dh
//  - group messaging: message_send_log, sender_key, sender_key_tracker
//  - files:           file_encryptor
//  - Sealed Sender:   sealed_sender, sender_certificate
//  - identity:        identity_admission, identity_binding,
//                     identity_binding_exception, identity_key_changed_exception,
//                     safety_number, verified_identity_store
//                     (identity_pin_store is DEPRECATED — TOFU only)
//  - orchestrator:    signal_protocol_service
//  - logging:         logger (setSignalProtocolLogger only)
export 'src/double_ratchet.dart';
export 'src/ed25519_strict.dart';
export 'src/file_encryptor.dart';
export 'src/hkdf.dart';
export 'src/identity_admission.dart';
export 'src/identity_binding.dart';
export 'src/identity_binding_exception.dart';
export 'src/identity_key_changed_exception.dart';
export 'src/identity_pin_store.dart';
export 'src/logger.dart' show setSignalProtocolLogger;
export 'src/message_send_log.dart';
export 'src/prekey_bundle.dart';
export 'src/safety_number.dart';
export 'src/sealed_sender.dart';
export 'src/sender_certificate.dart';
export 'src/sender_key.dart';
export 'src/sender_key_tracker.dart';
export 'src/signal_protocol_service.dart';
export 'src/verified_identity_store.dart';
export 'src/x25519.dart';
export 'src/x3dh.dart';
