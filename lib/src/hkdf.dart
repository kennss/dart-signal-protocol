/// @file        hkdf.dart
/// @description HMAC-SHA256 기반 HKDF (RFC 5869) 키 유도 함수. Signal Protocol 키 파생에 사용
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-03-30
/// @lastUpdated 2026-03-30
///
/// @functions
///  - hmacSha256(key, data): HMAC-SHA256 계산
///  - hkdfExtract(salt, ikm): HKDF Extract 단계
///  - hkdfExpand(prk, info, length): HKDF Expand 단계
///  - hkdfDerive(ikm, salt, info, length): HKDF Extract + Expand 통합

import 'dart:typed_data';

/// Pure Dart implementation of SHA-256, HMAC-SHA256, and HKDF (RFC 5869).
///
/// No external crypto dependencies — all primitives implemented from
/// FIPS 180-4 (SHA-256) and RFC 2104 (HMAC) / RFC 5869 (HKDF).

// ---------------------------------------------------------------------------
// Pure Dart SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

const List<int> _k256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

int _rotr32(int x, int n) => ((x & 0xFFFFFFFF) >>> n) | ((x << (32 - n)) & 0xFFFFFFFF);

Uint8List sha256(Uint8List data) {
  // Pre-processing: adding padding bits
  final bitLen = data.length * 8;
  // Message must be padded to 512-bit (64-byte) boundary
  final padLen = (56 - (data.length + 1) % 64) % 64;
  final padded = Uint8List(data.length + 1 + padLen + 8);
  padded.setAll(0, data);
  padded[data.length] = 0x80;
  // Append length as 64-bit big-endian (FIPS 180-4 §5.1.1)
  padded[padded.length - 8] = (bitLen >>> 56) & 0xFF;
  padded[padded.length - 7] = (bitLen >>> 48) & 0xFF;
  padded[padded.length - 6] = (bitLen >>> 40) & 0xFF;
  padded[padded.length - 5] = (bitLen >>> 32) & 0xFF;
  padded[padded.length - 4] = (bitLen >>> 24) & 0xFF;
  padded[padded.length - 3] = (bitLen >>> 16) & 0xFF;
  padded[padded.length - 2] = (bitLen >>> 8) & 0xFF;
  padded[padded.length - 1] = bitLen & 0xFF;

  // Initialize hash values
  var h0 = 0x6a09e667;
  var h1 = 0xbb67ae85;
  var h2 = 0x3c6ef372;
  var h3 = 0xa54ff53a;
  var h4 = 0x510e527f;
  var h5 = 0x9b05688c;
  var h6 = 0x1f83d9ab;
  var h7 = 0x5be0cd19;

  final w = List<int>.filled(64, 0);

  for (var i = 0; i < padded.length; i += 64) {
    // Prepare message schedule
    for (var t = 0; t < 16; t++) {
      w[t] = (padded[i + t * 4] << 24) |
          (padded[i + t * 4 + 1] << 16) |
          (padded[i + t * 4 + 2] << 8) |
          padded[i + t * 4 + 3];
    }
    for (var t = 16; t < 64; t++) {
      final s0 = _rotr32(w[t - 15], 7) ^ _rotr32(w[t - 15], 18) ^ ((w[t - 15] & 0xFFFFFFFF) >>> 3);
      final s1 = _rotr32(w[t - 2], 17) ^ _rotr32(w[t - 2], 19) ^ ((w[t - 2] & 0xFFFFFFFF) >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & 0xFFFFFFFF;
    }

    var a = h0, b = h1, c = h2, d = h3;
    var e = h4, f = h5, g = h6, h = h7;

    for (var t = 0; t < 64; t++) {
      final s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25);
      final ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g);
      final temp1 = (h + s1 + ch + _k256[t] + w[t]) & 0xFFFFFFFF;
      final s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (s0 + maj) & 0xFFFFFFFF;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xFFFFFFFF;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xFFFFFFFF;
    }

    h0 = (h0 + a) & 0xFFFFFFFF;
    h1 = (h1 + b) & 0xFFFFFFFF;
    h2 = (h2 + c) & 0xFFFFFFFF;
    h3 = (h3 + d) & 0xFFFFFFFF;
    h4 = (h4 + e) & 0xFFFFFFFF;
    h5 = (h5 + f) & 0xFFFFFFFF;
    h6 = (h6 + g) & 0xFFFFFFFF;
    h7 = (h7 + h) & 0xFFFFFFFF;
  }

  final result = Uint8List(32);
  void _put32(int offset, int value) {
    result[offset] = (value >>> 24) & 0xFF;
    result[offset + 1] = (value >>> 16) & 0xFF;
    result[offset + 2] = (value >>> 8) & 0xFF;
    result[offset + 3] = value & 0xFF;
  }
  _put32(0, h0);
  _put32(4, h1);
  _put32(8, h2);
  _put32(12, h3);
  _put32(16, h4);
  _put32(20, h5);
  _put32(24, h6);
  _put32(28, h7);

  return result;
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (RFC 2104)
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256(key, data).
Uint8List hmacSha256(Uint8List key, Uint8List data) {
  const blockSize = 64; // SHA-256 block size

  // If key is longer than block size, hash it
  var k = key.length > blockSize ? sha256(key) : key;

  // Pad key to block size
  final paddedKey = Uint8List(blockSize);
  paddedKey.setAll(0, k);

  // Inner and outer padded keys
  final ipad = Uint8List(blockSize);
  final opad = Uint8List(blockSize);
  for (var i = 0; i < blockSize; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  // inner = SHA256(ipad || data)
  final innerInput = Uint8List(blockSize + data.length);
  innerInput.setAll(0, ipad);
  innerInput.setAll(blockSize, data);
  final inner = sha256(innerInput);

  // result = SHA256(opad || inner)
  final outerInput = Uint8List(blockSize + 32);
  outerInput.setAll(0, opad);
  outerInput.setAll(blockSize, inner);

  return sha256(outerInput);
}

// ---------------------------------------------------------------------------
// HKDF (RFC 5869) with HMAC-SHA256
// ---------------------------------------------------------------------------

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
Uint8List hkdfExtract(Uint8List salt, Uint8List ikm) {
  final effectiveSalt = salt.isEmpty ? Uint8List(32) : salt;
  return hmacSha256(effectiveSalt, ikm);
}

/// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to [length] bytes.
Uint8List hkdfExpand(Uint8List prk, Uint8List info, int length) {
  assert(length <= 255 * 32, 'HKDF output length too large');

  final n = (length + 31) ~/ 32; // ceil(length / hashLen)
  final okm = Uint8List(n * 32);
  var previous = Uint8List(0);

  for (var i = 1; i <= n; i++) {
    final input = Uint8List(previous.length + info.length + 1);
    input.setAll(0, previous);
    input.setAll(previous.length, info);
    input[input.length - 1] = i;

    previous = hmacSha256(prk, input);
    okm.setAll((i - 1) * 32, previous);
  }

  return Uint8List.sublistView(okm, 0, length);
}

/// Full HKDF: Extract then Expand.
///
/// [ikm] — input key material
/// [salt] — optional salt (if null/empty, uses zeros)
/// [info] — context/application-specific info
/// [length] — desired output length in bytes
Uint8List hkdfDerive({
  required Uint8List ikm,
  required Uint8List salt,
  required Uint8List info,
  required int length,
}) {
  final prk = hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}
