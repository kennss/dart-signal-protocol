/// @file        safety_number.dart
/// @description 60-digit Safety Number (fingerprint) over two users' long-term
///              keys, following Signal's NumericFingerprintGenerator shape:
///              5200 iterations of SHA-512 per side, first 30 bytes, encoded
///              as 6 chunks of 5 decimal digits per side.
///
///              Use [SafetyNumber.forAccountKeys] (version 2): it hashes BOTH
///              users' ACCOUNT public keys — the keys Identity Binding v1 ties
///              every device's Signal keys to — so two honest users always
///              see identical digits, independent of which device / Signal
///              identity key is current. Mixing key kinds (e.g. my account
///              key with the peer's Signal key) never matches between honest
///              peers and makes the comparison worthless.
///
///              Intentional divergences from upstream Signal (NOT
///              interoperable with Signal clients, by design):
///                1. Round 0 hashes `u16BE(version) || key || utf8(id)` once;
///                   rounds 1..5199 hash `prev || key`. libsignal feeds the
///                   key twice into round 0. Both run SHA-512 5200 times.
///                2. Keys are raw 32 bytes (no 0x05 type prefix).
///              The version is mixed into round 0, so v1 and v2 numbers over
///              the same inputs never collide.
///
///              Byte-compatible with the SnowChat reference implementation.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - SafetyNumber.forAccountKeys(): version-2 number over two account keys
///  - SafetyNumber.compute(): generic number over two (id, 32-byte key) pairs
///  - SafetyNumber.formatForDisplay(): 6 lines x 2 chunks of 5 digits
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/digests.dart';

class SafetyNumber {
  SafetyNumber._();

  /// Version for account-key Safety Numbers (Identity Binding v1).
  static const int accountKeyVersion = 2;

  /// SHA-512 iterations per side (Signal v1).
  static const int _iterations = 5200;

  /// Digest bytes used per side (30 bytes -> 30 digits).
  static const int _fingerprintBytes = 30;

  /// Recommended: version-2 Safety Number over both users' ACCOUNT public
  /// keys (32-byte Ed25519). Symmetric: both peers compute the same 60
  /// digits. Throws [ArgumentError] on empty ids or non-32-byte keys.
  static String forAccountKeys({
    required String myId,
    required Uint8List myAccountKey,
    required String theirId,
    required Uint8List theirAccountKey,
  }) =>
      compute(
        myId: myId,
        myKey: myAccountKey,
        theirId: theirId,
        theirKey: theirAccountKey,
        version: accountKeyVersion,
      );

  /// Generic 60-digit number over (id, 32-byte key) pairs. Both sides are
  /// ordered by id so the result is symmetric. [version] is mixed into
  /// round 0 (u16 big-endian).
  static String compute({
    required String myId,
    required Uint8List myKey,
    required String theirId,
    required Uint8List theirKey,
    required int version,
  }) {
    if (myId.isEmpty || theirId.isEmpty) {
      throw ArgumentError('SafetyNumber: ids must not be empty');
    }
    if (myKey.length != 32 || theirKey.length != 32) {
      throw ArgumentError('SafetyNumber: keys must be exactly 32 bytes');
    }
    if (version < 0 || version > 0xffff) {
      throw ArgumentError('SafetyNumber: version must fit in u16');
    }

    final firstIsMe = myId.compareTo(theirId) < 0;
    final firstId = firstIsMe ? myId : theirId;
    final firstKey = firstIsMe ? myKey : theirKey;
    final secondId = firstIsMe ? theirId : myId;
    final secondKey = firstIsMe ? theirKey : myKey;

    final buf = StringBuffer();
    _encodeChunks(_iteratedHash(version, firstKey, firstId), buf);
    _encodeChunks(_iteratedHash(version, secondKey, secondId), buf);
    return buf.toString();
  }

  /// Layout the 60 digits as 6 lines of "12345 67890".
  static String formatForDisplay(String digits60) {
    if (digits60.length != 60) {
      throw ArgumentError(
          'formatForDisplay expects exactly 60 digits, got ${digits60.length}');
    }
    final lines = <String>[];
    for (var line = 0; line < 6; line++) {
      final start = line * 10;
      lines.add('${digits60.substring(start, start + 5)} '
          '${digits60.substring(start + 5, start + 10)}');
    }
    return lines.join('\n');
  }

  static Uint8List _iteratedHash(int version, Uint8List key, String id) {
    final initial = BytesBuilder(copy: false)
      ..addByte((version >> 8) & 0xff)
      ..addByte(version & 0xff)
      ..add(key)
      ..add(utf8.encode(id));
    var hash = Hash.sha512(initial.takeBytes());
    final next = BytesBuilder(copy: false);
    for (var i = 1; i < _iterations; i++) {
      next
        ..add(hash)
        ..add(key);
      hash = Hash.sha512(next.takeBytes());
    }
    return Uint8List.sublistView(hash, 0, _fingerprintBytes);
  }

  /// 30-byte fingerprint -> 6 x 5-digit chunks (40-bit BE mod 100000).
  static void _encodeChunks(Uint8List fp, StringBuffer out) {
    for (var i = 0; i < _fingerprintBytes; i += 5) {
      final v = (fp[i] << 32) |
          (fp[i + 1] << 24) |
          (fp[i + 2] << 16) |
          (fp[i + 3] << 8) |
          fp[i + 4];
      out.write((v % 100000).toString().padLeft(5, '0'));
    }
  }
}
