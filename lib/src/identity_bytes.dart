/// @file        identity_bytes.dart
/// @description Internal byte helpers shared by the Identity Binding modules
///              (constant-time comparison, strict lowercase hex codec). Not
///              exported from the public barrel.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - constantTimeEquals(): constant-time byte comparison (length leak only)
///  - bytesToHexLower(): lowercase hex encoding
///  - hexToBytes(): hex decoding (caller validates the format first)
library;

import 'dart:typed_data';

/// Constant-time equality for byte arrays. Only the length is leaked.
/// Null on either side compares unequal.
bool constantTimeEquals(List<int>? a, List<int>? b) {
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Lowercase hex encoding.
String bytesToHexLower(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Hex decoding. Throws [FormatException] on a non-hex digit; callers that
/// handle untrusted input validate the format (length, case) first.
Uint8List hexToBytes(String hex) {
  if (hex.length.isOdd) throw const FormatException('odd-length hex');
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
