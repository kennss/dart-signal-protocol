/// @file        sender_key_test.dart
/// @description Sender Key protocol, wire format v4 (ported from SnowChat
///              966a884 / f137f43): the signature covers a caller-supplied
///              binding and the message's own header; strict Ed25519 (an
///              unreduced scalar is refused); a key reads one message; a
///              message that does not open leaves the chain where it was;
///              chains are found by id; a record survives a save and a load;
///              the output is byte-identical to the SnowChat reference. Plus
///              the library's own pieces: the 72-byte distribution body
///              (group and sender from the caller's context), small-order
///              signing keys refused at install, SenderKeyManager.fromJson
///              and key removal.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-11-23 (rewritten for wire format v4: the v3 / v1 formats, rotation versions,
///              the origin-SKDM cache and the JSON distribution message are gone)
///
/// @functions
///  - main(): the test groups below.
///  - _Pair: a sender and a receiver that share one Sender Key.
///  - _ratchet(): the chain key after n steps, computed outside the manager.
///  - _goldenV4: a v4 message computed by the SnowChat reference implementation
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

/// encryptBoundGroupMessage('room-1', alice, 'hello', binding 0x42 * 32,
/// nonce 0x03 * 24) from chain 77 at iteration 5, chain key 0x01 * 32,
/// signing seed 0x09 * 32 — computed with the SnowChat app's
/// sender_key.dart (2026-11-23, app commit 53c4560).
const _goldenV4 =
    '040000004d00000005fb1ceef937ced5c59cf93b044784902e674e3da32931d7a3b6960c'
    '8a9f9d9786f7f0f06bb8f7d50197754ea126bc3198e0b254b0500df1c9cb4d0575a51154'
    '05030303030303030303030303030303030303030303030303d32675e08009564a5c3cd2'
    '5f288ad2f3464a3cd8ce';

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

const _group = 'room-1';
const _alice = 'snow00000000000000000000000000000001';
const _bob = 'snow00000000000000000000000000000002';

Uint8List _text(String s) => Uint8List.fromList(utf8.encode(s));

int _be32(Uint8List bytes, int offset) =>
    ByteData.sublistView(bytes).getUint32(offset, Endian.big);

Uint8List _withBe32(Uint8List bytes, int offset, int value) {
  final out = Uint8List.fromList(bytes);
  ByteData.sublistView(out).setUint32(offset, value, Endian.big);
  return out;
}

Uint8List _ratchet(Uint8List chainKey, int steps) {
  var key = chainKey;
  for (var i = 0; i < steps; i++) {
    key = hmacSha256(key, Uint8List.fromList([0x02]));
  }
  return key;
}

bool _verifies(Uint8List publicKey, Uint8List message, Uint8List signature) {
  try {
    return ed.VerifyKey(publicKey)
        .verify(signature: ed.Signature(signature), message: message);
  } catch (_) {
    return false;
  }
}

/// The 32-byte little-endian scalar S of [signature] replaced by S + L: the
/// same signature to a verifier that does not insist on a reduced scalar.
Uint8List _plusGroupOrder(Uint8List signature) {
  final l = BigInt.parse(
      '7237005577332262213973186563042994240857116359379907606001950938285454250989');
  var s = BigInt.zero;
  for (var i = 63; i >= 32; i--) {
    s = (s << 8) | BigInt.from(signature[i]);
  }
  s += l;
  final out = Uint8List.fromList(signature);
  for (var i = 32; i < 64; i++) {
    out[i] = (s & BigInt.from(0xff)).toInt();
    s >>= 8;
  }
  return out;
}

/// A manager that sends as Alice from a chosen chain position.
SenderKeyManager _senderAt({
  required int chainId,
  required int iteration,
  required Uint8List chainKey,
  required Uint8List signingSeed,
}) =>
    SenderKeyManager(
      senderKeys: {
        '$_group:$_alice': SenderKeyRecord(states: [
          SenderKeyState(
            chainId: chainId,
            iteration: iteration,
            chainKey: chainKey,
            signingKeyPublic: Uint8List.fromList(
                ed.SigningKey(seed: signingSeed).verifyKey),
            signingKeyPrivate: signingSeed,
          ),
        ]),
      },
    );

Uint8List _fill(int value) => Uint8List(32)..fillRange(0, 32, value);

SenderKeyFailure? _failure(void Function() body) {
  try {
    body();
  } on SenderKeyException catch (e) {
    return e.reason;
  }
  return null;
}

/// Alice sends in [_group]; Bob has her key.
class _Pair {
  final SenderKeyManager sender;
  final SenderKeyManager receiver;
  final SenderKeyDistributionMessage skdm;

  _Pair._(this.sender, this.receiver, this.skdm);

  factory _Pair() {
    final sender = SenderKeyManager();
    final receiver = SenderKeyManager();
    final skdm = sender.createSenderKey(_group, _alice);
    receiver.processSenderKey(skdm);
    return _Pair._(sender, receiver, skdm);
  }

  Uint8List sendBound(String text, Uint8List binding) => sender
      .encryptBoundGroupMessage(_group, _alice, _text(text), binding);

  String receiveBound(Uint8List data, Uint8List binding) => utf8.decode(
      receiver.decryptBoundGroupMessage(_group, _alice, data, binding));
}

void main() {
  group('keys', () {
    test('a key of the wrong length is refused, a second copy is not', () {
      final skdm = SenderKeyManager().createSenderKey(_group, _alice);
      SenderKeyDistributionMessage shaped({
        Uint8List? chainKey,
        Uint8List? signingKey,
      }) =>
          SenderKeyDistributionMessage(
            groupId: _group,
            senderId: _alice,
            chainId: skdm.chainId,
            iteration: 0,
            chainKey: chainKey ?? skdm.chainKey,
            signingKey: signingKey ?? skdm.signingKey,
          );

      final manager = SenderKeyManager();
      expect(manager.processSenderKey(shaped(chainKey: Uint8List(31))),
          isFalse);
      expect(manager.processSenderKey(shaped(signingKey: Uint8List(33))),
          isFalse);
      expect(manager.hasSenderKey(_group, _alice), isFalse);
      expect(manager.processSenderKey(shaped()), isTrue);
      expect(manager.processSenderKey(shaped()), isTrue);
      expect(manager.hasSenderKey(_group, _alice), isTrue);
    });

    test('an empty owner or sender id is refused', () {
      expect(() => SenderKeyManager().createSenderKey(_group, ''),
          throwsArgumentError);
      final skdm = SenderKeyManager().createSenderKey(_group, _alice);
      expect(
          SenderKeyManager().processSenderKey(SenderKeyDistributionMessage(
            groupId: _group,
            senderId: '',
            chainId: skdm.chainId,
            iteration: 0,
            chainKey: skdm.chainKey,
            signingKey: skdm.signingKey,
          )),
          isFalse);
    });

    test('a record survives a save and a load on both sides', () {
      final binding = _fill(7);
      final pair = _Pair();
      final m0 = pair.sendBound('m0', binding);
      final m1 = pair.sendBound('m1', binding);
      expect(pair.receiveBound(m1, binding), 'm1'); // m0's key is now cached

      SenderKeyManager reloaded(SenderKeyManager m) => SenderKeyManager(
            senderKeys: {
              '$_group:$_alice': SenderKeyRecord.fromJson(jsonDecode(
                      jsonEncode(m.toJson()['$_group:$_alice']))
                  as Map<String, dynamic>),
            },
          );
      final sender = reloaded(pair.sender);
      final receiver = reloaded(pair.receiver);

      final m2 =
          sender.encryptBoundGroupMessage(_group, _alice, _text('m2'), binding);
      expect(_be32(m2, 5), 2);
      expect(
          utf8.decode(
              receiver.decryptBoundGroupMessage(_group, _alice, m2, binding)),
          'm2');
      expect(
          utf8.decode(
              receiver.decryptBoundGroupMessage(_group, _alice, m0, binding)),
          'm0');
    });
  });

  group('v4 wire format', () {
    final binding = _fill(0x42);

    test('the layout: version 4, chain id, iteration, signature, ciphertext',
        () {
      final pair = _Pair();
      final first = pair.sendBound('hello', binding);
      final second = pair.sendBound('again', binding);

      expect(first.length, senderKeyMessageLength(5));
      expect(first[0], 4);
      expect(_be32(first, 1), pair.skdm.chainId);
      expect(_be32(first, 5), 0);
      expect(_be32(second, 5), 1);
      expect(pair.receiveBound(first, binding), 'hello');
      expect(pair.receiveBound(second, binding), 'again');
    });

    test('the signature covers the binding, the header and the ciphertext',
        () {
      final pair = _Pair();
      final message = pair.sendBound('hello', binding);
      final signature = Uint8List.fromList(message.sublist(9, 73));
      final ciphertext = Uint8List.fromList(message.sublist(73));
      final signed = Uint8List.fromList([
        0xfe,
        ...ascii.encode('SnowChat_GV2_Msg_v1'),
        ...binding,
        ...message.sublist(0, 9),
        ...ciphertext,
      ]);

      expect(_verifies(pair.skdm.signingKey, signed, signature), isTrue);
      expect(_verifies(pair.skdm.signingKey, ciphertext, signature), isFalse);
    });

    test('another binding fails the signature and changes nothing', () {
      final pair = _Pair();
      final message = pair.sendBound('hello', binding);

      expect(_failure(() => pair.receiveBound(message, _fill(0x43))),
          SenderKeyFailure.signature);
      expect(pair.receiver.hasSenderKey(_group, _alice), isTrue);
      expect(pair.receiveBound(message, binding), 'hello');
    });

    test('a changed iteration fails the signature', () {
      final pair = _Pair();
      final m0 = pair.sendBound('m0', binding);
      final m1 = pair.sendBound('m1', binding);

      expect(_failure(() => pair.receiveBound(_withBe32(m0, 5, 20000), binding)),
          SenderKeyFailure.signature);
      expect(_failure(() => pair.receiveBound(_withBe32(m1, 5, 0), binding)),
          SenderKeyFailure.signature);
      expect(pair.receiveBound(m0, binding), 'm0');
      expect(pair.receiveBound(m1, binding), 'm1');
    });

    test('an altered ciphertext or signature fails the signature', () {
      final pair = _Pair();
      final message = pair.sendBound('hello', binding);

      for (final offset in [9, 72, 73, message.length - 1]) {
        final altered = Uint8List.fromList(message)..[offset] ^= 1;
        expect(_failure(() => pair.receiveBound(altered, binding)),
            SenderKeyFailure.signature,
            reason: 'offset $offset');
      }
      expect(pair.receiveBound(message, binding), 'hello');
    });

    test('a signature with an unreduced scalar is refused', () {
      final pair = _Pair();
      final message = pair.sendBound('hello', binding);
      final twin = Uint8List.fromList(message)
        ..setAll(9, _plusGroupOrder(Uint8List.fromList(message.sublist(9, 73))));
      final signed = Uint8List.fromList([
        0xfe,
        ...ascii.encode('SnowChat_GV2_Msg_v1'),
        ...binding,
        ...message.sublist(0, 9),
        ...message.sublist(73),
      ]);

      // The lenient verifier takes the twin; the v4 path does not.
      expect(
          _verifies(pair.skdm.signingKey, signed,
              Uint8List.fromList(twin.sublist(9, 73))),
          isTrue);
      expect(_failure(() => pair.receiveBound(twin, binding)),
          SenderKeyFailure.signature);
    });

    test('an unknown chain or sender is "no key", other formats malformed',
        () {
      final pair = _Pair();
      final message = pair.sendBound('hello', binding);
      // Another version byte (0x03 was the wire format of the removed v1
      // groups) is not a v4 message.
      final otherFormat = Uint8List.fromList(message)..[0] = 3;

      expect(
          _failure(() => pair.receiveBound(
              _withBe32(message, 1, pair.skdm.chainId ^ 1), binding)),
          SenderKeyFailure.noKey);
      expect(
          _failure(() => pair.receiver
              .decryptBoundGroupMessage(_group, _bob, message, binding)),
          SenderKeyFailure.noKey);
      expect(
          _failure(() => pair.receiver
              .decryptBoundGroupMessage('room-2', _alice, message, binding)),
          SenderKeyFailure.noKey);
      expect(_failure(() => pair.receiveBound(otherFormat, binding)),
          SenderKeyFailure.malformed);
      expect(
          _failure(() => pair.receiveBound(
              Uint8List.fromList(message.sublist(0, 112)), binding)),
          SenderKeyFailure.malformed);
      expect(() => pair.receiveBound(message, Uint8List(31)),
          throwsArgumentError);
      expect(() => pair.sendBound('x', Uint8List(33)), throwsArgumentError);
    });

    test('messages are read in any order, each one once', () {
      final pair = _Pair();
      final bindings = [for (var i = 0; i < 5; i++) _fill(i)];
      final m = [
        for (var i = 0; i < 5; i++) pair.sendBound('m$i', bindings[i]),
      ];

      // The binding belongs to the message even when its key is cached —
      // and a message that fails keeps its key for the real one.
      expect(pair.receiveBound(m[3], bindings[3]), 'm3');
      expect(_failure(() => pair.receiveBound(m[1], bindings[2])),
          SenderKeyFailure.signature);
      for (final i in [0, 4, 2, 1]) {
        expect(pair.receiveBound(m[i], bindings[i]), 'm$i');
      }
      // A key reads one message: the same message again has expired,
      // whether it was read from the chain (4) or from a cached key (0).
      for (final i in [4, 0, 3, 1, 2]) {
        expect(_failure(() => pair.receiveBound(m[i], bindings[i])),
            SenderKeyFailure.expired);
      }
    });

    test('a cached key survives a message that does not open with it', () {
      final pair = _Pair();
      final m0 = pair.sendBound('m0', binding);
      final m1 = pair.sendBound('m1', binding);
      expect(pair.receiveBound(m1, binding), 'm1');
      // Signed by nobody: refused before the key is touched.
      final forged = Uint8List.fromList(m0)..[m0.length - 1] ^= 1;
      expect(_failure(() => pair.receiveBound(forged, binding)),
          SenderKeyFailure.signature);
      expect(pair.receiveBound(m0, binding), 'm0');
    });

    test('a message from before the received chain position has expired',
        () {
      final sender = SenderKeyManager();
      final origin = sender.createSenderKey(_group, _alice);
      final m0 =
          sender.encryptBoundGroupMessage(_group, _alice, _text('m0'), binding);
      sender.encryptBoundGroupMessage(_group, _alice, _text('m1'), binding);
      final m2 =
          sender.encryptBoundGroupMessage(_group, _alice, _text('m2'), binding);

      final receiver = SenderKeyManager()
        ..processSenderKey(SenderKeyDistributionMessage(
          groupId: _group,
          senderId: _alice,
          chainId: origin.chainId,
          iteration: 2,
          chainKey: _ratchet(origin.chainKey, 2),
          signingKey: origin.signingKey,
        ));

      expect(
          _failure(() =>
              receiver.decryptBoundGroupMessage(_group, _alice, m0, binding)),
          SenderKeyFailure.expired);
      expect(
          utf8.decode(
              receiver.decryptBoundGroupMessage(_group, _alice, m2, binding)),
          'm2');
    });

    test('the sender itself cannot make a receiver walk too far', () {
      final seed = _fill(9);
      final far = _senderAt(
        chainId: 77,
        iteration: maxForwardRatchetSteps + 1,
        chainKey: _fill(1),
        signingSeed: seed,
      );
      final receiver = SenderKeyManager()
        ..processSenderKey(SenderKeyDistributionMessage(
          groupId: _group,
          senderId: _alice,
          chainId: 77,
          iteration: 0,
          chainKey: _fill(1),
          signingKey: Uint8List.fromList(
              ed.SigningKey(seed: seed).verifyKey),
        ));
      final message =
          far.encryptBoundGroupMessage(_group, _alice, _text('x'), binding);

      expect(
          _failure(() => receiver.decryptBoundGroupMessage(
              _group, _alice, message, binding)),
          SenderKeyFailure.tooFarAhead);
    });

    test('a signed message that does not open leaves the chain where it was',
        () {
      final seed = _fill(9);
      final publicKey =
          Uint8List.fromList(ed.SigningKey(seed: seed).verifyKey);
      // Same chain id and signing key, another chain key.
      final other = _senderAt(
          chainId: 77, iteration: 3, chainKey: _fill(2), signingSeed: seed);
      final honest = _senderAt(
          chainId: 77, iteration: 0, chainKey: _fill(1), signingSeed: seed);
      final receiver = SenderKeyManager()
        ..processSenderKey(SenderKeyDistributionMessage(
          groupId: _group,
          senderId: _alice,
          chainId: 77,
          iteration: 0,
          chainKey: _fill(1),
          signingKey: publicKey,
        ));

      final unreadable =
          other.encryptBoundGroupMessage(_group, _alice, _text('x'), binding);
      expect(
          _failure(() => receiver.decryptBoundGroupMessage(
              _group, _alice, unreadable, binding)),
          SenderKeyFailure.decrypt);

      final saved =
          receiver.toJson()['$_group:$_alice'] as Map<String, dynamic>;
      final state = (saved['states'] as List).single as Map<String, dynamic>;
      expect(state['iteration'], 0);
      expect(state.containsKey('cachedMessageKeys'), isFalse);

      final m0 =
          honest.encryptBoundGroupMessage(_group, _alice, _text('m0'), binding);
      expect(
          utf8.decode(
              receiver.decryptBoundGroupMessage(_group, _alice, m0, binding)),
          'm0');
    });

    test('each chain is found by its id after a new own chain', () {
      final pair = _Pair();
      final old = [for (var i = 0; i < 3; i++) pair.sendBound('old$i', binding)];
      final rotated = pair.sender.createSenderKey(_group, _alice);
      final fresh = pair.sendBound('new', binding);

      expect(pair.receiveBound(old[0], binding), 'old0');
      expect(pair.receiveBound(old[2], binding), 'old2');
      expect(_failure(() => pair.receiveBound(fresh, binding)),
          SenderKeyFailure.noKey);
      expect(pair.receiver.processSenderKey(rotated), isTrue);
      expect(pair.receiveBound(fresh, binding), 'new');

      // A second copy of the OLD chain's key does not hide its cached keys
      // (old1 was skipped over, never read), nor bring back a used one.
      expect(pair.receiver.processSenderKey(pair.skdm), isTrue);
      expect(pair.receiveBound(old[1], binding), 'old1');
      expect(_failure(() => pair.receiveBound(old[0], binding)),
          SenderKeyFailure.expired);
    });

    test('a fixed nonce gives the same bytes', () {
      Uint8List once() => _senderAt(
            chainId: 77,
            iteration: 5,
            chainKey: _fill(1),
            signingSeed: _fill(9),
          ).encryptBoundGroupMessage(_group, _alice, _text('hello'), binding,
              nonce: Uint8List(24)..fillRange(0, 24, 3));

      expect(once(), once());
      expect(Uint8List.fromList(once().sublist(73, 97)),
          Uint8List(24)..fillRange(0, 24, 3));
      // Byte-identical to the SnowChat reference implementation (its
      // sender_key.dart run on the same inputs).
      expect(_hex(once()), _goldenV4);
    });
  });

  group('distribution message (72-byte body)', () {
    test('round-trips; group and sender come from the caller, not the bytes',
        () {
      final skdm = SenderKeyManager().createSenderKey(_group, _alice);
      final bytes = skdm.serialize();
      expect(bytes.length, senderKeyDistributionLength);
      expect(_be32(bytes, 0), skdm.chainId);
      expect(_be32(bytes, 4), 0);
      expect(bytes.sublist(8, 40), skdm.chainKey);
      expect(bytes.sublist(40, 72), skdm.signingKey);

      final back = SenderKeyDistributionMessage.deserialize(bytes,
          groupId: 'room-9', senderId: _bob)!;
      expect(back.groupId, 'room-9');
      expect(back.senderId, _bob);
      expect(back.chainId, skdm.chainId);
      expect(back.chainKey, skdm.chainKey);
      expect(back.signingKey, skdm.signingKey);
    });

    test('a body of another length or with a 32-bit chain id is refused', () {
      final bytes = SenderKeyManager().createSenderKey(_group, _alice).serialize();
      SenderKeyDistributionMessage? read(Uint8List b) =>
          SenderKeyDistributionMessage.deserialize(b,
              groupId: _group, senderId: _alice);
      expect(read(Uint8List.fromList(bytes.sublist(0, 71))), isNull);
      expect(read(Uint8List.fromList([...bytes, 0])), isNull);
      expect(read(_withBe32(bytes, 0, 0x80000000)), isNull);
      expect(
          () => SenderKeyDistributionMessage(
                groupId: _group,
                senderId: _alice,
                chainId: 1,
                iteration: 0,
                chainKey: Uint8List(31),
                signingKey: Uint8List(32),
              ).serialize(),
          throwsArgumentError);
    });

    test('the distributed key reads the messages of the chain', () {
      final binding = _fill(1);
      final sender = SenderKeyManager();
      final bytes = sender.createSenderKey(_group, _alice).serialize();
      final m0 =
          sender.encryptBoundGroupMessage(_group, _alice, _text('m0'), binding);
      final receiver = SenderKeyManager();
      expect(
          receiver.processSenderKey(SenderKeyDistributionMessage.deserialize(
              bytes,
              groupId: _group,
              senderId: _alice)!),
          isTrue);
      expect(
          utf8.decode(
              receiver.decryptBoundGroupMessage(_group, _alice, m0, binding)),
          'm0');
    });

    test('a signing key of small order is refused at install', () {
      final skdm = SenderKeyManager().createSenderKey(_group, _alice);
      final smallOrder = Uint8List(32)..[0] = 1; // the identity point
      final manager = SenderKeyManager();
      expect(
          manager.processSenderKey(SenderKeyDistributionMessage(
            groupId: _group,
            senderId: _alice,
            chainId: skdm.chainId,
            iteration: 0,
            chainKey: skdm.chainKey,
            signingKey: smallOrder,
          )),
          isFalse);
      expect(manager.hasSenderKey(_group, _alice), isFalse);
    });
  });

  group('manager persistence and removal', () {
    test('fromJson(toJson()) keeps every record; a bad key or record throws',
        () {
      final binding = _fill(3);
      final pair = _Pair();
      final m0 = pair.sendBound('m0', binding);
      final m1 = pair.sendBound('m1', binding);
      expect(pair.receiveBound(m1, binding), 'm1');

      final sender = SenderKeyManager.fromJson(
          jsonDecode(jsonEncode(pair.sender.toJson())) as Map<String, dynamic>);
      final receiver = SenderKeyManager.fromJson(jsonDecode(
          jsonEncode(pair.receiver.toJson())) as Map<String, dynamic>);
      final m2 =
          sender.encryptBoundGroupMessage(_group, _alice, _text('m2'), binding);
      expect(
          utf8.decode(
              receiver.decryptBoundGroupMessage(_group, _alice, m2, binding)),
          'm2');
      expect(
          utf8.decode(
              receiver.decryptBoundGroupMessage(_group, _alice, m0, binding)),
          'm0');

      expect(() => SenderKeyManager.fromJson({'$_group:': <String, dynamic>{}}),
          throwsFormatException);
      expect(() => SenderKeyManager.fromJson({'nocolon': <String, dynamic>{}}),
          throwsFormatException);
      expect(
          () => SenderKeyManager.fromJson({
                '$_group:$_alice': {'states': 'x'}
              }),
          throwsFormatException);
    });

    test('removeSenderKeyForMember and removeGroup drop exactly those keys',
        () {
      final manager = SenderKeyManager()
        ..createSenderKey(_group, _alice)
        ..createSenderKey(_group, _bob)
        ..createSenderKey('room-2', _alice);
      manager.removeSenderKeyForMember(_group, _bob);
      expect(manager.hasSenderKey(_group, _bob), isFalse);
      expect(manager.hasSenderKey(_group, _alice), isTrue);
      manager.removeGroup(_group);
      expect(manager.hasSenderKey(_group, _alice), isFalse);
      expect(manager.hasSenderKey('room-2', _alice), isTrue);
    });
  });
}
