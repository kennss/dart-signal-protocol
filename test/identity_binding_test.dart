/// @file        identity_binding_test.dart
/// @description Identity Binding v1 primitive — the shared golden vectors
///              (byte-identical to the SnowChat server + app vectors) plus
///              encoder / verifier edge cases: 0xFF domain prefix, lowercase
///              UUID enforcement, strict epoch parsing, small-order /
///              non-canonical account keys, malleated (S + L) signatures, wire
///              / embedded / storage codecs, the pluggable IdentityIdScheme,
///              IdentityBindingV1.sign() and the nextEpoch() minting rule.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - main(): golden vector + edge-case tests
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

import 'identity_test_support.dart';

bool _verifyVector(Map<String, dynamic> v) {
  final epoch = IdentityBindingV1.parseEpoch(v['epoch']);
  if (epoch == null) return false;
  return IdentityBindingV1.verify(
    peerId: v['snowId'] as String,
    accountPublicKey: hexBytes(v['accountPublicKeyHex'] as String),
    deviceId: v['deviceId'] as String,
    epoch: epoch,
    identityKey: hexBytes(v['identityKeyHex'] as String),
    ed25519: hexBytes(v['ed25519Hex'] as String),
    signature: hexBytes(v['signatureHex'] as String),
  );
}

/// A non-SnowChat scheme: "acct" + hex(first 16 key bytes) (36 chars).
class _AcctScheme extends IdentityIdScheme {
  const _AcctScheme();

  @override
  String deriveId(Uint8List accountPublicKey) =>
      'acct${hexLower(accountPublicKey.sublist(0, 16))}';

  @override
  bool isValidId(String id) => RegExp(r'^acct[0-9a-f]{32}$').hasMatch(id);
}

void main() {
  final fixture = jsonDecode(
          File('test/fixtures/identity_binding_v1.json').readAsStringSync())
      as Map<String, dynamic>;
  final valid = Map<String, dynamic>.from(fixture['valid'] as Map);

  group('golden vectors', () {
    test('valid vector: message bytes match and signature verifies', () {
      final msg = IdentityBindingV1.buildMessage(
        peerId: valid['snowId'] as String,
        deviceId: valid['deviceId'] as String,
        epoch: IdentityBindingV1.parseEpoch(valid['epoch'])!,
        identityKey: hexBytes(valid['identityKeyHex'] as String),
        ed25519: hexBytes(valid['ed25519Hex'] as String),
      );
      expect(msg.length, IdentityBindingV1.messageLength);
      expect(msg.first, 0xFF);
      expect(hexLower(msg), valid['messageHex']);
      expect(_verifyVector(valid), isTrue);
    });

    test('default scheme derives the vector snowId from its account key', () {
      expect(
          const SnowChatIdScheme()
              .deriveId(hexBytes(valid['accountPublicKeyHex'] as String)),
          valid['snowId']);
    });

    for (final raw in fixture['invalid'] as List) {
      final c = Map<String, dynamic>.from(raw as Map);
      test('invalid vector "${c['name']}" fails verification', () {
        final merged = Map<String, dynamic>.from(valid)
          ..addAll(Map<String, dynamic>.from(c['override'] as Map));
        expect(_verifyVector(merged), isFalse);
      });
    }
  });

  group('encoder / verifier edge cases', () {
    final seed = Uint8List.fromList(List.filled(32, 7));
    final acct = ed.SigningKey(seed: seed);
    final acctPub = Uint8List.fromList(acct.verifyKey.toList());
    final peerId = const SnowChatIdScheme().deriveId(acctPub);
    const dev = '3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90';
    final ik = Uint8List.fromList(List.filled(32, 1));
    final edk = Uint8List.fromList(List.filled(32, 2));
    Uint8List sign(Uint8List m) =>
        Uint8List.fromList(acct.sign(m).signature.toList());
    bool check(Uint8List signature, {int epoch = 5}) => IdentityBindingV1.verify(
        peerId: peerId,
        accountPublicKey: acctPub,
        deviceId: dev,
        epoch: epoch,
        identityKey: ik,
        ed25519: edk,
        signature: signature);

    test('0xFF prefix: a utf8 string signature can never be a binding', () {
      final msg = IdentityBindingV1.buildMessage(
          peerId: peerId, deviceId: dev, epoch: 5, identityKey: ik, ed25519: edk);
      // What a string-signing oracle could at best produce: the same bytes
      // without the 0xFF prefix.
      expect(check(sign(Uint8List.fromList(msg.sublist(1)))), isFalse);
      // utf8.encode never yields 0xFF.
      expect(utf8.encode('\u{FFFF}ÿ').contains(0xFF), isFalse);
      expect(check(sign(msg)), isTrue);
    });

    test('deviceId must be a lowercase canonical UUID', () {
      expect(IdentityBindingV1.isValidDeviceId(dev), isTrue);
      expect(IdentityBindingV1.isValidDeviceId(dev.toUpperCase()), isFalse);
      expect(IdentityBindingV1.isValidDeviceId('primary'), isFalse);
      expect(
          () => IdentityBindingV1.buildMessage(
              peerId: peerId,
              deviceId: dev.toUpperCase(),
              epoch: 1,
              identityKey: ik,
              ed25519: edk),
          throwsArgumentError);
    });

    test('epoch parser is strict', () {
      expect(IdentityBindingV1.parseEpoch('0'), 0);
      expect(IdentityBindingV1.parseEpoch('1794326400000'), 1794326400000);
      expect(IdentityBindingV1.parseEpoch('9223372036854775807'),
          9223372036854775807);
      expect(IdentityBindingV1.parseEpoch('9223372036854775808'), isNull);
      expect(IdentityBindingV1.parseEpoch('-1'), isNull);
      expect(IdentityBindingV1.parseEpoch('01'), isNull);
      expect(IdentityBindingV1.parseEpoch('1e3'), isNull);
      expect(IdentityBindingV1.parseEpoch(''), isNull);
      expect(IdentityBindingV1.parseEpoch(5), isNull, reason: 'not a string');
    });

    test('small-order and non-canonical account keys are rejected', () {
      for (final h in [
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0100000000000000000000000000000000000000000000000000000000000000',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
        // sign-bit variants must be rejected too
        '0000000000000000000000000000000000000000000000000000000000000080',
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
        // non-canonical y >= p
        'f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      ]) {
        expect(IdentityBindingV1.isAcceptableAccountKey(hexBytes(h)), isFalse,
            reason: h);
      }
      expect(IdentityBindingV1.isAcceptableAccountKey(acctPub), isTrue);
      expect(IdentityBindingV1.isAcceptableAccountKey(Uint8List(31)), isFalse);
    });

    test('account key must derive the peer id', () {
      final other = ed.SigningKey(seed: Uint8List.fromList(List.filled(32, 8)));
      final otherPub = Uint8List.fromList(other.verifyKey.toList());
      expect(IdentityBindingV1.accountKeyMatchesPeerId(acctPub, peerId), isTrue);
      expect(
          IdentityBindingV1.accountKeyMatchesPeerId(otherPub, peerId), isFalse);
    });

    test('account key hex decoding is lowercase-only', () {
      final h = hexLower(acctPub);
      expect(IdentityBindingV1.parseAccountKeyHex(h), acctPub);
      expect(IdentityBindingV1.parseAccountKeyHex(h.toUpperCase()), isNull);
      expect(IdentityBindingV1.parseAccountKeyHex(h.substring(2)), isNull);
    });

    test('S + L (malleated, TweetNaCl-acceptable) signature is rejected', () {
      final msg = IdentityBindingV1.buildMessage(
          peerId: peerId, deviceId: dev, epoch: 3, identityKey: ik, ed25519: edk);
      final sig = sign(msg);
      final l = (BigInt.one << 252) +
          BigInt.parse('27742317777372353535851937790883648493');
      var s = BigInt.zero;
      for (var i = 63; i >= 32; i--) {
        s = (s << 8) | BigInt.from(sig[i]);
      }
      final s2 = s + l;
      expect(s2.bitLength <= 256, isTrue);
      final mal = Uint8List.fromList(sig);
      var v = s2;
      for (var i = 32; i < 64; i++) {
        mal[i] = (v & BigInt.from(0xff)).toInt();
        v = v >> 8;
      }
      expect(check(sig, epoch: 3), isTrue);
      expect(IdentityBindingV1.isCanonicalSignatureScalar(mal), isFalse);
      expect(check(mal, epoch: 3), isFalse);
    });

    test('wire + embedded codecs round-trip and reject malformed input', () {
      final b = IdentityBinding(signature: Uint8List(64), epoch: 42);
      expect(IdentityBinding.tryParseWire(b.toWireJson())!.epoch, 42);
      expect(
          IdentityBinding.tryParseWire(
              {'sig': 'AA==', 'epoch': '1', 'version': 1}),
          isNull);
      expect(
          IdentityBinding.tryParseWire(
              {'sig': base64Encode(Uint8List(64)), 'epoch': '1', 'version': 2}),
          isNull);
      expect(
          IdentityBinding.tryParseWire(
              {'sig': base64Encode(Uint8List(64)), 'epoch': 5, 'version': 1}),
          isNull,
          reason: 'numeric epoch is not the wire form');

      final e = EmbeddedIdentityBinding(
        accountPublicKey: acctPub,
        deviceId: dev,
        epoch: 9,
        ed25519: edk,
        signature: Uint8List(64),
      );
      final back =
          EmbeddedIdentityBinding.tryParse(jsonDecode(jsonEncode(e.toJson())));
      expect(back!.deviceId, dev);
      expect(back.epoch, 9);
      expect(EmbeddedIdentityBinding.tryParse({'version': 1}), isNull);
      // Non-string fields -> null, never a TypeError.
      expect(
          EmbeddedIdentityBinding.tryParse({
            'version': 1,
            'accountPublicKey': 123,
            'deviceId': dev,
            'epoch': '1',
            'ed25519': 'x',
            'sig': 'y',
          }),
          isNull);
      expect(
          EmbeddedIdentityBinding.tryParse({
            'version': 1,
            'accountPublicKey': 'a' * 64,
            'deviceId': dev,
            'epoch': 1,
            'ed25519': 'b' * 64,
            'sig': base64Encode(Uint8List(64)),
          }),
          isNull);
    });

    test('sign(): derives the id from the seed, verifies, storage round-trip',
        () {
      final local = IdentityBindingV1.sign(
          accountSeed: seed, deviceId: dev, epoch: 77, identityKey: ik, ed25519: edk);
      expect(local.peerId, peerId);
      expect(local.accountPublicKey, acctPub);
      expect(check(local.signature, epoch: 77), isTrue);
      expect(local.covers(deviceId: dev, ik: ik, edKey: edk), isTrue);
      expect(local.covers(deviceId: dev, ik: edk, edKey: edk), isFalse);
      final back = LocalIdentityBinding.tryParseStorage(
          jsonDecode(jsonEncode(local.toStorageJson())));
      expect(back!.epoch, 77);
      expect(back.signature, local.signature);
      expect(LocalIdentityBinding.tryParseStorage({'snowId': 1}), isNull);
    });
  });

  group('pluggable IdentityIdScheme', () {
    final seed = Uint8List.fromList(List.filled(32, 11));
    const dev = '11111111-2222-4333-8444-555555555555';
    final ik = Uint8List.fromList(List.filled(32, 3));
    final edk = Uint8List.fromList(List.filled(32, 4));

    test('a custom scheme signs and verifies under its own ids only', () {
      const scheme = _AcctScheme();
      final local = IdentityBindingV1.sign(
          accountSeed: seed,
          deviceId: dev,
          epoch: 1,
          identityKey: ik,
          ed25519: edk,
          idScheme: scheme);
      expect(local.peerId.startsWith('acct'), isTrue);
      bool verifyWith(IdentityIdScheme s, String id) => IdentityBindingV1.verify(
          peerId: id,
          accountPublicKey: local.accountPublicKey,
          deviceId: dev,
          epoch: 1,
          identityKey: ik,
          ed25519: edk,
          signature: local.signature,
          idScheme: s);
      expect(verifyWith(scheme, local.peerId), isTrue);
      // Same key under the default scheme: different id, and the signature
      // (over the "acct…" id) does not transfer.
      final snowId = const SnowChatIdScheme().deriveId(local.accountPublicKey);
      expect(verifyWith(const SnowChatIdScheme(), snowId), isFalse);
      expect(verifyWith(const SnowChatIdScheme(), local.peerId), isFalse);
    });

    test('ids must be exactly 36 ASCII bytes regardless of the scheme', () {
      expect(IdentityBindingV1.isValidPeerId('snow${'0' * 32}'), isTrue);
      expect(IdentityBindingV1.isValidPeerId('snow${'0' * 31}'), isFalse);
      expect(IdentityBindingV1.isValidPeerId('SNOW${'0' * 32}'), isFalse);
    });
  });

  group('nextEpoch()', () {
    test('max(now, every floor + 1)', () {
      expect(IdentityBindingV1.nextEpoch(nowMs: 1000), 1000);
      expect(
          IdentityBindingV1.nextEpoch(nowMs: 1000, exclusiveFloors: [999, null]),
          1000);
      expect(
          IdentityBindingV1.nextEpoch(nowMs: 1000, exclusiveFloors: [1000]),
          1001);
      expect(
          IdentityBindingV1.nextEpoch(
              nowMs: 1000, exclusiveFloors: [5000, 7000, null]),
          7001);
    });

    test('epoch space exhaustion fails closed', () {
      expect(
          () => IdentityBindingV1.nextEpoch(
              nowMs: 1, exclusiveFloors: [IdentityBindingV1.maxEpoch]),
          throwsStateError);
    });
  });
}
