/// @file        ed25519_strict_test.dart
/// @description Strict Ed25519 (0.4.0 security fix). For each rule the test
///              first shows that plain TweetNaCl (pinenacl VerifyKey.verify)
///              ACCEPTS the input, then that verifyEd25519Strict and every
///              trust-deciding check built on it refuse it: a malleated
///              signature (S + L), a small-order public key with a universal
///              forgery, a non-canonical key encoding — for the strict
///              primitive, the signed-prekey signature (PreKeyBundle /
///              SignalProtocolService.createSession) and the sender
///              certificate.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-23
/// @lastUpdated 2026-11-23
///
/// @functions
///  - _malleate(): turn a signature (R, S) into (R, S + L)
///  - _plainVerify(): pinenacl verify, false on exception
///  - main(): strict primitive, SPK signature and certificate tests
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

import 'identity_test_support.dart';

/// Ed25519 group order L.
final BigInt _l = (BigInt.one << 252) +
    BigInt.parse('27742317777372353535851937790883648493');

/// (R, S) -> (R, S + L): still a valid signature for TweetNaCl, which uses
/// S unreduced ([S]B = [S + L]B).
Uint8List _malleate(Uint8List sig) {
  var s = BigInt.zero;
  for (var i = 63; i >= 32; i--) {
    s = (s << 8) | BigInt.from(sig[i]);
  }
  var v = s + _l;
  expect(v.bitLength <= 256, isTrue);
  final out = Uint8List.fromList(sig);
  for (var i = 32; i < 64; i++) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v = v >> 8;
  }
  return out;
}

bool _plainVerify(Uint8List pub, Uint8List msg, Uint8List sig) {
  try {
    return ed.VerifyKey(pub).verify(signature: ed.Signature(sig), message: msg);
  } catch (_) {
    return false;
  }
}

/// The identity point (0, 1): order 1.
final Uint8List _identityPoint = Uint8List(32)..[0] = 1;

/// A "signature" (R = identity, S = 0) verifies under the identity public key
/// for ANY message with plain TweetNaCl: [0]B = R + [h]A = identity.
Uint8List _universalForgery() => Uint8List(64)..[0] = 1;

void main() {
  final signer = ed.SigningKey(seed: Uint8List.fromList(List.filled(32, 9)));
  final pub = Uint8List.fromList(signer.verifyKey);
  final msg = Uint8List.fromList(utf8.encode('strict ed25519'));
  final sig = Uint8List.fromList(signer.sign(msg).signature);

  group('verifyEd25519Strict', () {
    test('an honest signature verifies', () {
      expect(verifyEd25519Strict(pub, msg, sig), isTrue);
      expect(isAcceptableEd25519PublicKey(pub), isTrue);
    });

    test('S + L: plain TweetNaCl accepts, strict refuses', () {
      final mal = _malleate(sig);
      expect(_plainVerify(pub, msg, mal), isTrue,
          reason: 'the gap this release closes');
      expect(verifyEd25519Strict(pub, msg, mal), isFalse);
    });

    test(
        'small-order key: plain TweetNaCl accepts a forgery for any message, '
        'strict refuses the key', () {
      final forged = _universalForgery();
      for (final m in [
        msg,
        Uint8List(0),
        Uint8List.fromList([1, 2, 3])
      ]) {
        expect(_plainVerify(_identityPoint, m, forged), isTrue);
        expect(verifyEd25519Strict(_identityPoint, m, forged), isFalse);
      }
      expect(isAcceptableEd25519PublicKey(_identityPoint), isFalse);
    });

    test(
        'non-canonical key encodings and wrong lengths are refused, never '
        'thrown', () {
      // y = p (non-canonical encoding of 0).
      final nonCanonical = hexBytes(
          'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');
      expect(isAcceptableEd25519PublicKey(nonCanonical), isFalse);
      expect(verifyEd25519Strict(nonCanonical, msg, sig), isFalse);
      expect(verifyEd25519Strict(Uint8List(31), msg, sig), isFalse);
      expect(verifyEd25519Strict(pub, msg, Uint8List(63)), isFalse);
      expect(verifyEd25519Strict(pub, msg, Uint8List(65)), isFalse);
      expect(isAcceptableEd25519PublicKey(null), isFalse);
    });

    test('a tampered message or another key fails', () {
      final other = Uint8List.fromList(
          ed.SigningKey(seed: Uint8List.fromList(List.filled(32, 10)))
              .verifyKey);
      expect(verifyEd25519Strict(other, msg, sig), isFalse);
      final tampered = Uint8List.fromList(msg)..[0] ^= 1;
      expect(verifyEd25519Strict(pub, tampered, sig), isFalse);
    });
  });

  group('signed-prekey signature', () {
    test('PreKeyBundle.verifySignature refuses a malleated signature', () {
      final spk = PreKeyGenerator.generateSignedPreKey(
          1, Uint8List.fromList(signer.seed));
      PreKeyBundle bundle(Uint8List s) => PreKeyBundle(
            identityKey: Uint8List(32),
            signedPreKey: spk.publicKey,
            signedPreKeySignature: s,
            signedPreKeyId: 1,
            registrationId: 1,
          );
      expect(bundle(spk.signature).verifySignature(pub), isTrue);
      final mal = _malleate(spk.signature);
      expect(_plainVerify(pub, spk.publicKey, mal), isTrue);
      expect(bundle(mal).verifySignature(pub), isFalse);
    });

    test(
        'createSession refuses a bundle whose signed prekey is signed with '
        'S + L, before identity admission or X3DH', () async {
      final alice = await TestParty.create(
          seedByte: 1, deviceId: '0a0a0a0a-0000-4000-8000-00000000000a');
      final bob = await TestParty.create(
          seedByte: 2, deviceId: '0b0b0b0b-0000-4000-8000-00000000000b');
      final b = bob.bundle(
          binding: bob.bindingFor(epoch: 1000),
          accountPublicKey: bob.accountPub);
      final spk = Map<String, dynamic>.from(b['signedPreKey'] as Map);
      spk['signature'] = _malleate(spk['signature'] as Uint8List);
      b['signedPreKey'] = spk;
      await expectLater(
        alice.signal.createSession(
            recipientId: bob.peerId, deviceId: bob.deviceId, preKeyBundle: b),
        throwsA(isA<SignalProtocolException>()),
      );
      expect(await alice.signal.hasSession(bob.peerId, bob.deviceId), isFalse);
      expect(await alice.store.get(bob.peerId), isNull,
          reason: 'refused before admission recorded anything');
    });
  });

  group('sender certificate', () {
    SenderCertificate signedCert(ed.SigningKey server) {
      final unsigned = SenderCertificate(
        version: 1,
        senderSnowchatId: 'snow0123456789abcdef0123456789abcdef',
        senderDeviceId: '0a0a0a0a-0000-4000-8000-00000000000a',
        senderIdentityKey: Uint8List.fromList(List.filled(32, 7)),
        expiryMs: DateTime.now().millisecondsSinceEpoch + 3600 * 1000,
        serverSignature: Uint8List(64),
      );
      final signed = Uint8List.sublistView(unsigned.toBytes(), 0, 113);
      final s = Uint8List.fromList(server.sign(signed).signature);
      return SenderCertificate.fromBytes(Uint8List.fromList([...signed, ...s]));
    }

    SenderCertificate withSignature(SenderCertificate c, Uint8List s) =>
        SenderCertificate(
          version: c.version,
          senderSnowchatId: c.senderSnowchatId,
          senderDeviceId: c.senderDeviceId,
          senderIdentityKey: c.senderIdentityKey,
          expiryMs: c.expiryMs,
          serverSignature: s,
        );

    test('a malleated server signature is refused', () {
      final server =
          ed.SigningKey(seed: Uint8List.fromList(List.filled(32, 0x51)));
      final serverPub = Uint8List.fromList(server.verifyKey);
      final cert = signedCert(server);
      cert.verify([serverPub]);
      final mal = withSignature(cert, _malleate(cert.serverSignature));
      final signedPortion = Uint8List.sublistView(mal.toBytes(), 0, 113);
      expect(
          _plainVerify(serverPub, signedPortion, mal.serverSignature), isTrue);
      expect(() => mal.verify([serverPub]), throwsStateError);
    });

    test('a small-order "server key" with a universal forgery is refused', () {
      final server =
          ed.SigningKey(seed: Uint8List.fromList(List.filled(32, 0x52)));
      final forged = withSignature(signedCert(server), _universalForgery());
      final signedPortion = Uint8List.sublistView(forged.toBytes(), 0, 113);
      expect(
          _plainVerify(_identityPoint, signedPortion, forged.serverSignature),
          isTrue);
      expect(() => forged.verify([_identityPoint]), throwsStateError);
    });
  });
}
