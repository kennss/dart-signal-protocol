/// @file        sealed_padding_test.dart
/// @description encodeSealedPlaintext (ported from SnowChat's security
///              review S4, "the sizes the server sees"). The codec: block
///              multiples, JSON-whitespace padding that a plain JSON decoder
///              reads back, byte-identical output to the app. Over real
///              X3DH / Double Ratchet sessions and real Sealed Sender
///              envelopes: without padding a short and a longer message
///              travel in envelopes of different sizes; padded, they travel
///              in envelopes of one size — as the first (PreKey) message to a
///              new peer with its identity binding, and in an established
///              session alike.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-23
/// @lastUpdated 2026-11-23
///
/// @functions
///  - _Pair: a sender and a recipient with real sessions and a sealer
///  - main(): codec and envelope-size tests
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

import 'identity_test_support.dart';

const _devA = '11111111-1111-4111-8111-111111111111';
const _devB = '22222222-2222-4222-8222-222222222222';

/// A short message and a longer one that still fits one 512-byte block.
final Map<String, dynamic> _short = {'type': 'text', 'body': 'see you at 7?'};
final Map<String, dynamic> _long = {
  'type': 'text',
  'body': 'x' * 400,
  'cid': '6f1c2d3e-4a5b-4c6d-8e7f-8091a2b3c4d5',
};

class _Pair {
  final TestParty alice;
  final TestParty bob;
  final ed.SigningKey server;
  final SealedSenderService sealer;

  _Pair(this.alice, this.bob, this.server)
      : sealer = SealedSenderService(
            trustedServerKeys: [Uint8List.fromList(server.verifyKey)]);

  static Future<_Pair> make() async {
    final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
    final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
    alice.signal.setLocalIdentityBinding(alice.localBinding(epoch: 1000));
    bob.signal.setLocalIdentityBinding(bob.localBinding(epoch: 1000));
    await alice.signal.createSession(
      recipientId: bob.peerId,
      deviceId: _devB,
      preKeyBundle: bob.bundle(
          binding: bob.bindingFor(epoch: 1000),
          accountPublicKey: bob.accountPub),
    );
    return _Pair(alice, bob,
        ed.SigningKey(seed: Uint8List.fromList(List.filled(32, 9))));
  }

  /// Bob reads Alice's first (PreKey) message and replies; Alice reads the
  /// reply, so from then on she sends normal messages.
  Future<void> establish() async {
    final first = await alice.signal.encryptMessage(
        recipientId: bob.peerId,
        deviceId: _devB,
        plaintext: Uint8List.fromList(utf8.encode('{}')));
    await bob.signal.decryptMessage(
      senderId: alice.peerId,
      deviceId: _devA,
      ciphertext: first['ciphertext'] as Uint8List,
      messageType: 2,
      envelopeDeviceId: _devA,
    );
    final reply = await bob.signal.encryptMessage(
        recipientId: alice.peerId,
        deviceId: _devA,
        plaintext: Uint8List.fromList(utf8.encode('{}')));
    await alice.signal.decryptMessage(
      senderId: bob.peerId,
      deviceId: _devB,
      ciphertext: reply['ciphertext'] as Uint8List,
      messageType: 1,
    );
  }

  /// Encrypt [plaintext] for Bob and seal it; the envelope size and type.
  Future<({int size, int type})> send(Uint8List plaintext) async {
    final enc = await alice.signal.encryptMessage(
        recipientId: bob.peerId, deviceId: _devB, plaintext: plaintext);
    final envelope = sealer.seal(
      recipientIdentityPubKey: bob.identityKey,
      drCiphertext: enc['ciphertext'] as Uint8List,
      certificate: testSenderCertificate(server, alice),
      messageContext: sealedType1to1,
    );
    return (size: envelope.length, type: enc['messageType'] as int);
  }
}

void main() {
  group('codec', () {
    test('pads to the next multiple of the block, one block at least', () {
      expect(encodeSealedPlaintext({}).length, sealedPlaintextBlock);
      expect(encodeSealedPlaintext(_short).length, sealedPlaintextBlock);
      expect(encodeSealedPlaintext(_long).length, sealedPlaintextBlock);
      expect(encodeSealedPlaintext({'b': 'x' * 600}).length,
          2 * sealedPlaintextBlock);
      expect(encodeSealedPlaintext(_short, block: 64).length % 64, 0);
      // Exactly one block of JSON: no extra block.
      final exact = {'b': 'x' * (sealedPlaintextBlock - 8)};
      expect(utf8.encode(jsonEncode(exact)).length, sealedPlaintextBlock);
      expect(encodeSealedPlaintext(exact).length, sealedPlaintextBlock);
    });

    test(
        'the padding is spaces after the JSON; a plain JSON decoder reads '
        'it back', () {
      final bytes = encodeSealedPlaintext(_short);
      final json = utf8.encode(jsonEncode(_short));
      expect(bytes.sublist(0, json.length), json);
      expect(bytes.sublist(json.length).every((b) => b == 0x20), isTrue);
      expect(jsonDecode(utf8.decode(bytes)), _short);
    });

    test('a block that is not positive is refused', () {
      expect(
          () => encodeSealedPlaintext(_short, block: 0), throwsArgumentError);
      expect(() => encodeSealedPlaintext(_short, block: -512),
          throwsArgumentError);
    });
  });

  group('envelope sizes over real sessions', () {
    test('unpadded, a short and a longer message are told apart by size',
        () async {
      final pair = await _Pair.make();
      await pair.establish();
      final a =
          await pair.send(Uint8List.fromList(utf8.encode(jsonEncode(_short))));
      final b =
          await pair.send(Uint8List.fromList(utf8.encode(jsonEncode(_long))));
      expect(a.type, 1);
      expect(b.type, 1);
      expect(a.size, isNot(b.size));
    });

    test(
        'first contact (PreKey messages with the identity binding): padded, '
        'one size', () async {
      final sizes = <int>{};
      for (final payload in [_short, _long]) {
        final pair = await _Pair.make();
        final sent = await pair.send(encodeSealedPlaintext(payload));
        expect(sent.type, 2);
        sizes.add(sent.size);
      }
      expect(sizes, hasLength(1));
    });

    test('an established session: padded, one size', () async {
      final pair = await _Pair.make();
      await pair.establish();
      final sizes = <int>{};
      for (final payload in [_short, _long, <String, dynamic>{}]) {
        final sent = await pair.send(encodeSealedPlaintext(payload));
        expect(sent.type, 1);
        sizes.add(sent.size);
      }
      expect(sizes, hasLength(1));
    });

    test('a padded plaintext decrypts and decodes on the other side', () async {
      final pair = await _Pair.make();
      final enc = await pair.alice.signal.encryptMessage(
          recipientId: pair.bob.peerId,
          deviceId: _devB,
          plaintext: encodeSealedPlaintext(_long));
      final pt = await pair.bob.signal.decryptMessage(
        senderId: pair.alice.peerId,
        deviceId: _devA,
        ciphertext: enc['ciphertext'] as Uint8List,
        messageType: enc['messageType'] as int,
        envelopeDeviceId: _devA,
      );
      expect(jsonDecode(utf8.decode(pt)), _long);
    });
  });
}
