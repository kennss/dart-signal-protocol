/// @file        logger.dart
/// @description Optional debug logging facade for dart_signal_protocol.
///              Replaces flutter/foundation's debugPrint with a no-op default
///              that users can override with their own callback.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-07
/// @lastUpdated 2026-04-07
///
/// @functions
///  - setSignalProtocolLogger(): register a callback to receive debug messages
///  - debugPrint(): no-op by default, forwards to callback if registered

void Function(String message)? _debugLogCallback;

/// Register a callback to receive internal debug log messages from this
/// library. By default the library produces no output.
///
/// Example:
/// ```dart
/// import 'package:dart_signal_protocol/dart_signal_protocol.dart';
///
/// void main() {
///   setSignalProtocolLogger(print); // forward debug messages to stdout
/// }
/// ```
///
/// SECURITY WARNING: Debug messages may include cryptographic state
/// (key fingerprints, session IDs, etc.). Never enable verbose logging
/// in production builds or save debug output to disk.
void setSignalProtocolLogger(void Function(String message) callback) {
  _debugLogCallback = callback;
}

/// Internal debug print used by the library.
///
/// Compatible signature with `package:flutter/foundation`'s `debugPrint`
/// so existing call sites work unchanged. By default this is a no-op;
/// register a callback via [setSignalProtocolLogger] to receive messages.
void debugPrint(String? message, {int? wrapWidth}) {
  if (message != null && _debugLogCallback != null) {
    _debugLogCallback!(message);
  }
}
