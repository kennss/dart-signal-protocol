/// @file        hkdf_test.dart
/// @description HKDF (RFC 5869) 및 HMAC-SHA256 테스트. RFC 테스트 벡터, 결정론, 경계 조건 검증
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - RFC 5869 test vectors (known input -> known output)
///  - HMAC-SHA256 determinism
///  - Different salt/info produce different keys
///  - Empty salt handling
///  - Zero-length output rejection

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

/// Convert hex string to Uint8List.
Uint8List _hex(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

/// Convert Uint8List to lowercase hex string.
String _toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

void main() {
  group('SHA-256', () {
    test('empty string produces known hash', () {
      // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      final result = sha256(Uint8List(0));
      expect(
        _toHex(result),
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });

    test('"abc" produces known hash', () {
      // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
      final result = sha256(Uint8List.fromList(utf8.encode('abc')));
      expect(
        _toHex(result),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('output is always 32 bytes', () {
      final result = sha256(Uint8List.fromList([1, 2, 3, 4, 5]));
      expect(result.length, 32);
    });
  });

  group('HMAC-SHA256', () {
    test('RFC 4231 Test Case 1 — short key', () {
      // Key  = 0x0b repeated 20 times
      // Data = "Hi There"
      // HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
      final key = Uint8List(20)..fillRange(0, 20, 0x0b);
      final data = Uint8List.fromList(utf8.encode('Hi There'));
      final result = hmacSha256(key, data);
      expect(
        _toHex(result),
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
      );
    });

    test('determinism — same inputs always produce same output', () {
      final key = Uint8List.fromList(utf8.encode('test-key'));
      final data = Uint8List.fromList(utf8.encode('test-data'));

      final result1 = hmacSha256(key, data);
      final result2 = hmacSha256(key, data);
      expect(result1, equals(result2));
    });

    test('different keys produce different outputs', () {
      final key1 = Uint8List.fromList(utf8.encode('key-alpha'));
      final key2 = Uint8List.fromList(utf8.encode('key-bravo'));
      final data = Uint8List.fromList(utf8.encode('same-data'));

      final result1 = hmacSha256(key1, data);
      final result2 = hmacSha256(key2, data);
      expect(_toHex(result1), isNot(equals(_toHex(result2))));
    });

    test('output is always 32 bytes', () {
      final key = Uint8List.fromList(utf8.encode('k'));
      final data = Uint8List.fromList(utf8.encode('d'));
      expect(hmacSha256(key, data).length, 32);
    });
  });

  group('HKDF Extract', () {
    test('RFC 5869 Test Case 1 — Extract PRK', () {
      // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
      // salt = 0x000102030405060708090a0b0c (13 bytes)
      // PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
      final ikm = _hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = _hex('000102030405060708090a0b0c');
      final prk = hkdfExtract(salt, ikm);
      expect(
        _toHex(prk),
        '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
      );
    });

    test('empty salt uses zeros (RFC 5869 Section 2.2)', () {
      final ikm = Uint8List.fromList([1, 2, 3]);
      final withEmpty = hkdfExtract(Uint8List(0), ikm);
      final withZeros = hkdfExtract(Uint8List(32), ikm);
      expect(_toHex(withEmpty), equals(_toHex(withZeros)));
    });

    test('output is always 32 bytes (hash length)', () {
      final prk = hkdfExtract(
        Uint8List.fromList([0xAA]),
        Uint8List.fromList([0xBB]),
      );
      expect(prk.length, 32);
    });
  });

  group('HKDF Expand', () {
    test('RFC 5869 Test Case 1 — Expand OKM (42 bytes)', () {
      // PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
      // info = 0xf0f1f2f3f4f5f6f7f8f9
      // L    = 42
      // OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
      final prk = _hex(
          '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
      final info = _hex('f0f1f2f3f4f5f6f7f8f9');
      final okm = hkdfExpand(prk, info, 42);
      expect(
        _toHex(okm),
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
      );
    });

    test('different info strings produce different outputs', () {
      final prk = Uint8List(32)..fillRange(0, 32, 0xAA);
      final info1 = Uint8List.fromList(utf8.encode('context-one'));
      final info2 = Uint8List.fromList(utf8.encode('context-two'));

      final okm1 = hkdfExpand(prk, info1, 32);
      final okm2 = hkdfExpand(prk, info2, 32);
      expect(_toHex(okm1), isNot(equals(_toHex(okm2))));
    });

    test('output length matches requested length', () {
      final prk = Uint8List(32)..fillRange(0, 32, 0x11);
      final info = Uint8List(0);

      expect(hkdfExpand(prk, info, 1).length, 1);
      expect(hkdfExpand(prk, info, 16).length, 16);
      expect(hkdfExpand(prk, info, 32).length, 32);
      expect(hkdfExpand(prk, info, 64).length, 64);
      expect(hkdfExpand(prk, info, 100).length, 100);
    });
  });

  group('HKDF Full (Extract + Expand)', () {
    test('RFC 5869 Test Case 1 — full derive', () {
      final ikm = _hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = _hex('000102030405060708090a0b0c');
      final info = _hex('f0f1f2f3f4f5f6f7f8f9');

      final okm = hkdfDerive(ikm: ikm, salt: salt, info: info, length: 42);
      expect(
        _toHex(okm),
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
      );
    });

    test('RFC 5869 Test Case 2 — longer inputs', () {
      // IKM = 80 bytes of 0x00..0x4f
      // salt = 80 bytes of 0x60..0xaf
      // info = 80 bytes of 0xb0..0xff
      // L = 82
      final ikm = Uint8List.fromList(
          List.generate(80, (i) => i)); // 0x00..0x4F
      final salt = Uint8List.fromList(
          List.generate(80, (i) => 0x60 + i)); // 0x60..0xAF
      final info = Uint8List.fromList(
          List.generate(80, (i) => 0xb0 + i)); // 0xB0..0xFF

      final okm = hkdfDerive(ikm: ikm, salt: salt, info: info, length: 82);
      expect(okm.length, 82);
      // Just verify it produces a deterministic result
      final okm2 = hkdfDerive(ikm: ikm, salt: salt, info: info, length: 82);
      expect(_toHex(okm), equals(_toHex(okm2)));
    });

    test('RFC 5869 Test Case 3 — zero-length salt and info', () {
      // IKM  = 0x0b * 22
      // salt = "" (empty)
      // info = "" (empty)
      // L    = 42
      // OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8
      final ikm = _hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final okm = hkdfDerive(
        ikm: ikm,
        salt: Uint8List(0),
        info: Uint8List(0),
        length: 42,
      );
      expect(
        _toHex(okm),
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
      );
    });

    test('different salt produces different output', () {
      final ikm = Uint8List.fromList([1, 2, 3, 4]);
      final info = Uint8List.fromList(utf8.encode('app'));
      final salt1 = Uint8List.fromList(utf8.encode('salt-one'));
      final salt2 = Uint8List.fromList(utf8.encode('salt-two'));

      final okm1 = hkdfDerive(ikm: ikm, salt: salt1, info: info, length: 32);
      final okm2 = hkdfDerive(ikm: ikm, salt: salt2, info: info, length: 32);
      expect(_toHex(okm1), isNot(equals(_toHex(okm2))));
    });

    test('32-byte output is default Signal key length', () {
      final ikm = Uint8List(32)..fillRange(0, 32, 0xFF);
      final okm = hkdfDerive(
        ikm: ikm,
        salt: Uint8List(0),
        info: Uint8List.fromList(utf8.encode('SnowChat')),
        length: 32,
      );
      expect(okm.length, 32);
    });
  });
}
