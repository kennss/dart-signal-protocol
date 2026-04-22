/// @file        dart_signal_protocol.dart
/// @description Pure Dart implementation of the Signal Protocol
///              (X3DH + Double Ratchet + Sender Key) with zero native
///              dependencies. Public API entry point.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-07
/// @lastUpdated 2026-04-20

library dart_signal_protocol;

// Cryptographic primitives
export 'src/x25519.dart';
export 'src/hkdf.dart';

// Signal Protocol — 1:1 messaging
export 'src/prekey_bundle.dart';
export 'src/x3dh.dart';
export 'src/double_ratchet.dart';

// Signal Protocol — group messaging (Sender Key)
export 'src/sender_key.dart';
export 'src/sender_key_tracker.dart';
export 'src/message_send_log.dart';

// File encryption (XSalsa20-Poly1305)
export 'src/file_encryptor.dart';

// Sealed Sender (sender anonymity)
export 'src/sender_certificate.dart';
export 'src/sealed_sender.dart';

// High-level orchestrator
export 'src/signal_protocol_service.dart';

// Identity pinning (TOFU)
export 'src/identity_pin_store.dart';
export 'src/identity_key_changed_exception.dart';

// Optional debug logging
export 'src/logger.dart' show setSignalProtocolLogger;
