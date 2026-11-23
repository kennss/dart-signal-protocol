/// @file        identity_binding_session_test.dart
/// @description Identity Binding v1 end-to-end over the REAL Signal layer
///              (X3DH + Double Ratchet, pinenacl): send-side admission inside
///              createSession (tamper / substituted bundle / downgrade /
///              epoch regression / same-key re-sign / reinstall notice), the
///              refusal of a peer without a binding (bindings are mandatory:
///              an unbound bundle or a binding-less sender is refused and
///              nothing is recorded), transient store failures (never
///              fail-open), receive-side verification of the binding embedded
///              in type-2 messages (offline, header-IK swap rejected before
///              any OPK is consumed, device mismatch, malformed binding,
///              directory fallback, downgrade, server-bound IK mismatch,
///              transient lookup failure), device selection + non-consuming
///              directory admission, key-change notice rules, bound-session
///              purge (active + archived, and sessions without a stored remote
///              IK) and remoteIdentityKey persistence, archiveSessionsOf, and
///              Safety Number v2 symmetry + cross-implementation golden.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-23 (backport SnowChat 3df0cc5 / 0aa549b: bindings always mandatory —
///              the legacy TOFU cases became refusals; promotionNotice -> keyChangeNotice; no
///              store-less backward-compatibility group; sessions without a remote IK are purged;
///              archiveSessionsOf). Earlier 2026-11-10
///
/// @functions
///  - main(): session-level identity binding tests
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/x25519.dart' as nacl_api;
import 'package:test/test.dart';

import 'identity_test_support.dart';

const _devA = 'aaaaaaaa-1111-4111-8111-111111111111';
const _devB = 'bbbbbbbb-2222-4222-8222-222222222222';
const _devB2 = 'bbbbbbbb-3333-4333-8333-333333333333';

Uint8List _utf8(String s) => Uint8List.fromList(utf8.encode(s));

Matcher _bindingRejected(IdentityBindingFailure reason) =>
    isA<IdentityBindingInvalidException>()
        .having((e) => e.reason, 'reason', reason);

/// Collects identity events emitted by [store].
List<IdentityStoreEvent> _collect(VerifiedIdentityStore store) {
  final out = <IdentityStoreEvent>[];
  store.events.listen(out.add);
  return out;
}

Future<void> _flush() => Future<void>.delayed(Duration.zero);

/// An in-memory store whose reads throw while [fail] is set (storage
/// unavailable, e.g. a locked keychain).
class _FailingStore extends InMemoryVerifiedIdentityStore {
  bool fail = false;

  @override
  Future<VerifiedIdentityRecord?> readRecord(String peerId,
      {bool fresh = false}) {
    if (fail) throw StateError('storage unavailable');
    return super.readRecord(peerId, fresh: fresh);
  }

  @override
  Future<int?> readLatch(String peerId, {bool fresh = false}) {
    if (fail) throw StateError('storage unavailable');
    return super.readLatch(peerId, fresh: fresh);
  }
}

void main() {
  group('send side — createSession admission', () {
    late TestParty alice;
    late TestParty bob;

    setUp(() async {
      alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      bob = await TestParty.create(seedByte: 2, deviceId: _devB);
    });

    test('valid binding -> session created, record bound, latch = epoch, '
        'session records the remote IK', () async {
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      expect(await alice.signal.hasSession(bob.peerId, _devB), isTrue);
      final rec = await alice.store.get(bob.peerId);
      expect(rec!.bound, isTrue);
      expect(rec.identityKey, bob.identityKey);
      expect(rec.accountPublicKey, bob.accountPub);
      expect(await alice.store.latchedEpoch(bob.peerId), 1000);
    });

    test('tampered signature -> rejected, no session, event emitted', () async {
      final events = _collect(alice.store);
      final good = bob.bindingFor(epoch: 1000);
      final sig = Uint8List.fromList(good.signature)..[0] ^= 1;
      await expectLater(
        alice.signal.createSession(
          recipientId: bob.peerId,
          deviceId: _devB,
          preKeyBundle: bob.bundle(
              binding: IdentityBinding(signature: sig, epoch: 1000),
              accountPublicKey: bob.accountPub),
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.signatureInvalid)),
      );
      expect(await alice.signal.hasSession(bob.peerId, _devB), isFalse);
      await _flush();
      expect(events.single.kind, IdentityEventKind.bindingRejected);
      expect(events.single.reason, IdentityBindingFailure.signatureInvalid);
    });

    test('binding for another peer id (server substitutes a bundle) -> '
        'rejected', () async {
      final carol = await TestParty.create(seedByte: 3, deviceId: _devB);
      await expectLater(
        alice.signal.createSession(
          recipientId: carol.peerId,
          deviceId: _devB,
          preKeyBundle: bob.bundle(
              binding: bob.bindingFor(epoch: 1000),
              accountPublicKey: bob.accountPub),
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.signatureInvalid)),
      );
    });

    test('unparseable binding flag / binding without account key -> badFormat',
        () async {
      final b = bob.bundle()..['identityBindingUnparseable'] = true;
      await expectLater(
        alice.signal.createSession(
            recipientId: bob.peerId, deviceId: _devB, preKeyBundle: b),
        throwsA(_bindingRejected(IdentityBindingFailure.badFormat)),
      );
      await expectLater(
        alice.signal.createSession(
            recipientId: bob.peerId,
            deviceId: _devB,
            preKeyBundle: bob.bundle(binding: bob.bindingFor(epoch: 1))),
        throwsA(_bindingRejected(IdentityBindingFailure.badFormat)),
      );
    });

    test('raw wire map instead of a parsed IdentityBinding -> ArgumentError',
        () async {
      final b = bob.bundle()
        ..['identityBinding'] = bob.bindingFor(epoch: 1).toWireJson();
      await expectLater(
        alice.signal.createSession(
            recipientId: bob.peerId, deviceId: _devB, preKeyBundle: b),
        throwsArgumentError,
      );
    });

    test('latched peer without binding -> downgrade rejected', () async {
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      await alice.signal.deleteSession(bob.peerId, _devB);
      await expectLater(
        alice.signal.createSession(
          recipientId: bob.peerId,
          deviceId: _devB,
          preKeyBundle: bob.bundle(opkIndex: 1),
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.downgrade)),
      );
    });

    test('invite-link pin latches a first contact against downgrade',
        () async {
      expect(await alice.store.pinAccountKey(bob.peerId, bob.accountPub),
          isTrue);
      await expectLater(
        alice.signal.createSession(
            recipientId: bob.peerId, deviceId: _devB, preKeyBundle: bob.bundle()),
        throwsA(_bindingRejected(IdentityBindingFailure.downgrade)),
      );
      // A bound bundle (account key may come from the pin) is accepted.
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(binding: bob.bindingFor(epoch: 5), opkIndex: 1),
      );
      expect(await alice.signal.hasSession(bob.peerId, _devB), isTrue);
    });

    test('epoch regression (older binding for other keys) -> rejected',
        () async {
      final bobNew = await TestParty.create(seedByte: 2, deviceId: _devB2);
      await alice.signal.createSession(
        recipientId: bobNew.peerId,
        deviceId: _devB2,
        preKeyBundle: bobNew.bundle(
            binding: bobNew.bindingFor(epoch: 2000),
            accountPublicKey: bobNew.accountPub),
      );
      // A hostile server replays Bob's OLD (validly signed) bundle.
      await expectLater(
        alice.signal.createSession(
          recipientId: bob.peerId,
          deviceId: _devB,
          preKeyBundle: bob.bundle(
              binding: bob.bindingFor(epoch: 1000),
              accountPublicKey: bob.accountPub),
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.epochRegression)),
      );
    });

    test('same epoch re-used for different keys -> rejected', () async {
      final bobNew = await TestParty.create(seedByte: 2, deviceId: _devB2);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      await expectLater(
        alice.signal.createSession(
          recipientId: bobNew.peerId,
          deviceId: _devB2,
          preKeyBundle: bobNew.bundle(
              binding: bobNew.bindingFor(epoch: 1000),
              accountPublicKey: bobNew.accountPub),
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.epochRegression)),
      );
    });

    test('same keys re-signed later -> accepted; same keys older epoch -> '
        'accepted without store write', () async {
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1500),
            accountPublicKey: bob.accountPub,
            opkIndex: 1),
      );
      expect(await alice.store.latchedEpoch(bob.peerId), 1500);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub,
            opkIndex: 2),
      );
      expect((await alice.store.get(bob.peerId))!.epoch, 1500);
    });

    test('bound reinstall of the same account -> non-blocking device notice '
        'and sessions with the superseded IK purged', () async {
      final events = _collect(alice.store);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      final bobNew = await TestParty.create(seedByte: 2, deviceId: _devB2);
      await alice.signal.createSession(
        recipientId: bobNew.peerId,
        deviceId: _devB2,
        preKeyBundle: bobNew.bundle(
            binding: bobNew.bindingFor(epoch: 2000),
            accountPublicKey: bobNew.accountPub),
      );
      await _flush();
      expect(events.map((e) => e.kind),
          contains(IdentityEventKind.deviceKeysChanged));
      expect(await alice.signal.hasSession(bob.peerId, _devB), isFalse,
          reason: 'session with the superseded IK must be purged');
      expect(await alice.signal.hasSession(bobNew.peerId, _devB2), isTrue);
      await expectLater(
        alice.signal.encryptMessage(
            recipientId: bob.peerId, deviceId: _devB, plaintext: _utf8('x')),
        throwsA(isA<SignalProtocolException>()),
      );
    });

    test('an unbound attacker bundle under a never-bound peer id is refused '
        'and leaves nothing; the real bound keys are then admitted', () async {
      final mitm = await TestParty.create(seedByte: 9, deviceId: _devB);
      // The server hands out an unbound attacker bundle under Bob's id.
      await expectLater(
        alice.signal.createSession(
          recipientId: bob.peerId,
          deviceId: _devB,
          preKeyBundle: mitm.bundle(),
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.bindingRequired)),
      );
      expect(await alice.signal.hasSession(bob.peerId, _devB), isFalse);
      expect(await alice.store.get(bob.peerId), isNull);
      expect(await alice.store.latchedEpoch(bob.peerId), isNull);
      // Bob's real, bound keys.
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      expect((await alice.store.get(bob.peerId))!.identityKey, bob.identityKey);
    });

    test('a reinstall of a bound peer gives the device notice; the first '
        'binding after an account-key pin gives none', () async {
      final bobNew = await TestParty.create(seedByte: 2, deviceId: _devB2);
      final events = _collect(alice.store);
      expect(await alice.store.pinAccountKey(bob.peerId, bob.accountPub),
          isTrue);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      await _flush();
      expect(events, isEmpty);

      await alice.signal.createSession(
        recipientId: bobNew.peerId,
        deviceId: _devB2,
        preKeyBundle: bobNew.bundle(
            binding: bobNew.bindingFor(epoch: 9000),
            accountPublicKey: bobNew.accountPub),
      );
      await _flush();
      expect(events.map((e) => e.kind), [IdentityEventKind.deviceKeysChanged]);
    });

    test('a 0.3.x record with unproven (TOFU) keys is read as an account-key '
        'pin only: its keys are dropped and the first binding is no change',
        () async {
      // What a 0.3.x store wrote for a legacy peer: keys, no binding.
      alice.store.putRawRecordForTesting(
        bob.peerId,
        jsonEncode({
          'schema': 1,
          'snowId': bob.peerId,
          'accountPub': hexLower(bob.accountPub),
          'deviceId': _devB2,
          'ik': base64Encode(Uint8List(32)..[0] = 9),
          'ed': base64Encode(Uint8List(32)..[0] = 8),
          'edLegacy': true,
          'pendingIk': base64Encode(Uint8List(32)..[0] = 7),
          'bound': false,
          'updatedAt': 1,
        }),
      );
      final rec = await alice.store.get(bob.peerId);
      expect(rec!.accountPublicKey, bob.accountPub);
      expect(rec.identityKey, isNull);
      expect(rec.ed25519, isNull);
      expect(rec.deviceId, isNull);
      final events = _collect(alice.store);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      await _flush();
      expect(events, isEmpty);
      expect((await alice.store.get(bob.peerId))!.bound, isTrue);
    });
  });

  group('without a binding (bindings are mandatory)', () {
    late TestParty alice;

    setUp(() async {
      alice = await TestParty.create(seedByte: 1, deviceId: _devA);
    });

    test('a peer that presents no binding is refused at first contact and '
        'again later: bindingRequired, no session, nothing recorded', () async {
      final events = _collect(alice.store);
      final old = await TestParty.create(seedByte: 4, deviceId: _devB);
      final reinstalled = await TestParty.create(seedByte: 4, deviceId: _devB2);
      for (final (party, device) in [(old, _devB), (reinstalled, _devB2)]) {
        await expectLater(
          alice.signal.createSession(
              recipientId: old.peerId,
              deviceId: device,
              preKeyBundle: party.bundle()),
          throwsA(_bindingRejected(IdentityBindingFailure.bindingRequired)),
        );
        expect(await alice.signal.hasSession(old.peerId, device), isFalse);
      }
      expect(await alice.store.get(old.peerId), isNull);
      expect(await alice.store.latchedEpoch(old.peerId), isNull);
      await _flush();
      expect(events.map((e) => e.kind),
          everyElement(IdentityEventKind.bindingRejected));
      expect(events.map((e) => e.reason),
          everyElement(IdentityBindingFailure.bindingRequired));
    });

    test('a server-supplied account key does not stand in for a binding',
        () async {
      final bob = await TestParty.create(seedByte: 5, deviceId: _devB);
      await expectLater(
        alice.signal.createSession(
            recipientId: bob.peerId,
            deviceId: _devB,
            preKeyBundle: bob.bundle(accountPublicKey: bob.accountPub)),
        throwsA(_bindingRejected(IdentityBindingFailure.bindingRequired)),
      );
      expect(await alice.store.get(bob.peerId), isNull);
    });

    test('an identity store failure is transient, never fail-open', () async {
      final store = _FailingStore();
      final failing = SignalProtocolService(identityStore: store);
      await failing.generateIdentityKeyPair();
      await failing.generateSignedPreKey(1);
      final bob = await TestParty.create(seedByte: 6, deviceId: _devB);
      store.fail = true;
      await expectLater(
        failing.createSession(
            recipientId: bob.peerId,
            deviceId: _devB,
            preKeyBundle: bob.bundle(
                binding: bob.bindingFor(epoch: 1000),
                accountPublicKey: bob.accountPub)),
        throwsA(isA<SignalProtocolException>().having(
            (e) => e is IdentityBindingInvalidException, 'hard', isFalse)),
      );
      expect(await failing.hasSession(bob.peerId, _devB), isFalse);
      store.fail = false;
      await failing.createSession(
          recipientId: bob.peerId,
          deviceId: _devB,
          preKeyBundle: bob.bundle(
              binding: bob.bindingFor(epoch: 1000),
              accountPublicKey: bob.accountPub,
              opkIndex: 1));
      expect(await failing.hasSession(bob.peerId, _devB), isTrue);
    });
  });

  group('receive side — binding embedded in type-2', () {
    late TestParty alice;
    late TestParty bob;

    Future<Map<String, dynamic>> aliceFirstMessage(String text,
        {bool embed = true}) async {
      if (embed) {
        alice.signal.setLocalIdentityBinding(alice.localBinding(epoch: 5000));
      }
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      return alice.signal.encryptMessage(
          recipientId: bob.peerId, deviceId: _devB, plaintext: _utf8(text));
    }

    setUp(() async {
      alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      bob = await TestParty.create(seedByte: 2, deviceId: _devB);
    });

    test('valid embedded binding -> decrypts offline, sender recorded bound',
        () async {
      final enc = await aliceFirstMessage('hello');
      expect(enc['messageType'], 2);
      final json = jsonDecode(utf8.decode(enc['ciphertext'] as Uint8List));
      expect((json as Map)['identityBinding'], isNotNull);
      var lookups = 0;
      final pt = await bob.signal.decryptMessage(
        senderId: alice.peerId,
        deviceId: _devA,
        ciphertext: enc['ciphertext'] as Uint8List,
        messageType: 2,
        envelopeDeviceId: _devA,
        identityDirectoryLookup: () async {
          lookups++;
          return null;
        },
      );
      expect(utf8.decode(pt), 'hello');
      expect(lookups, 0, reason: 'bound sender must not hit the network');
      final rec = await bob.store.get(alice.peerId);
      expect(rec!.bound, isTrue);
      expect(rec.identityKey, alice.identityKey);
      expect(await bob.store.latchedEpoch(alice.peerId), 5000);
    });

    test('stale local binding (does not cover current keys) is not embedded',
        () async {
      final other = await TestParty.create(seedByte: 1, deviceId: _devA);
      alice.signal.setLocalIdentityBinding(other.localBinding(epoch: 1));
      final enc = await aliceFirstMessage('x', embed: false);
      final json = jsonDecode(utf8.decode(enc['ciphertext'] as Uint8List));
      expect((json as Map).containsKey('identityBinding'), isFalse);
    });

    test('header IK swapped -> rejected BEFORE any OPK is consumed', () async {
      final enc = await aliceFirstMessage('hello');
      final json = Map<String, dynamic>.from(
          jsonDecode(utf8.decode(enc['ciphertext'] as Uint8List)) as Map);
      final mitm = await TestParty.create(seedByte: 9, deviceId: _devA);
      final tampered = Map<String, dynamic>.from(json)
        ..['identityKey'] = hexLower(mitm.identityKey);
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: _utf8(jsonEncode(tampered)),
          messageType: 2,
          envelopeDeviceId: _devA,
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.signatureInvalid)),
      );
      // The genuine message still decrypts -> Bob's OPK was not burned.
      final pt = await bob.signal.decryptMessage(
        senderId: alice.peerId,
        deviceId: _devA,
        ciphertext: enc['ciphertext'] as Uint8List,
        messageType: 2,
        envelopeDeviceId: _devA,
      );
      expect(utf8.decode(pt), 'hello');
    });

    test('binding deviceId != envelope / certificate deviceId -> rejected',
        () async {
      final enc = await aliceFirstMessage('hello');
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
          envelopeDeviceId: 'cccccccc-4444-4444-8444-444444444444',
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.deviceMismatch)),
      );
    });

    test('malformed embedded binding -> typed badFormat rejection', () async {
      final enc = await aliceFirstMessage('x');
      final json = Map<String, dynamic>.from(
          jsonDecode(utf8.decode(enc['ciphertext'] as Uint8List)) as Map);
      (json['identityBinding'] as Map)['epoch'] = 5000; // wrong type
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: _utf8(jsonEncode(json)),
          messageType: 2,
          envelopeDeviceId: _devA,
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.badFormat)),
      );
    });

    test('binding-less sender whose directory holds no binding either -> '
        'refused, nothing recorded', () async {
      final enc = await aliceFirstMessage('unbound hi', embed: false);
      final json = jsonDecode(utf8.decode(enc['ciphertext'] as Uint8List));
      expect((json as Map)['identityBinding'], isNull);
      var lookups = 0;
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
          envelopeDeviceId: _devA,
          identityDirectoryLookup: () async {
            lookups++;
            return RemoteIdentityDirectory(
              accountPublicKey: alice.accountPub,
              devices: [
                RemoteDeviceIdentity(
                  deviceId: _devA,
                  identityKey: alice.identityKey,
                  ed25519: alice.ed25519,
                  binding: null,
                  bindingUnparseable: false,
                  index: 0,
                ),
              ],
            );
          },
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.bindingRequired)),
      );
      expect(lookups, 1);
      expect(await bob.store.get(alice.peerId), isNull);
      expect(await bob.signal.hasSession(alice.peerId, _devA), isFalse);
      // The refusal came before any prekey was used.
      expect(bob.signal.signedPreKeyPublicKey(1), isNotNull);
    });

    test('binding-less sender with no directory lookup -> refused', () async {
      final enc = await aliceFirstMessage('unbound hi', embed: false);
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
          envelopeDeviceId: _devA,
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.bindingRequired)),
      );
    });

    test('binding-less sender whose directory holds a binding for the header '
        'IK -> admitted through it', () async {
      final enc = await aliceFirstMessage('via directory', embed: false);
      final pt = await bob.signal.decryptMessage(
        senderId: alice.peerId,
        deviceId: _devA,
        ciphertext: enc['ciphertext'] as Uint8List,
        messageType: 2,
        envelopeDeviceId: _devA,
        identityDirectoryLookup: () async => RemoteIdentityDirectory(
          accountPublicKey: alice.accountPub,
          devices: [
            RemoteDeviceIdentity(
              deviceId: _devA,
              identityKey: alice.identityKey,
              ed25519: alice.ed25519,
              binding: alice.bindingFor(epoch: 4000),
              bindingUnparseable: false,
              index: 0,
            ),
          ],
        ),
      );
      expect(utf8.decode(pt), 'via directory');
      expect((await bob.store.get(alice.peerId))!.bound, isTrue);
      expect(await bob.store.latchedEpoch(alice.peerId), 4000);
    });

    test('binding-less message from a latched sender -> downgrade rejected',
        () async {
      await bob.store.raiseLatch(alice.peerId, 10);
      final enc = await aliceFirstMessage('hi', embed: false);
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
          envelopeDeviceId: _devA,
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.downgrade)),
      );
    });

    test('binding-less message whose IK differs from the server-bound IK -> '
        'rejected', () async {
      final enc = await aliceFirstMessage('hi', embed: false);
      final other = await TestParty.create(seedByte: 1, deviceId: _devA);
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
          envelopeDeviceId: _devA,
          identityDirectoryLookup: () async => RemoteIdentityDirectory(
            accountPublicKey: other.accountPub,
            devices: [
              RemoteDeviceIdentity(
                deviceId: _devA,
                identityKey: other.identityKey,
                ed25519: other.ed25519,
                binding: other.bindingFor(epoch: 7),
                bindingUnparseable: false,
                index: 0,
              ),
            ],
          ),
        ),
        throwsA(_bindingRejected(IdentityBindingFailure.identityKeyMismatch)),
      );
    });

    test('directory lookup failure for an unknown sender is transient',
        () async {
      final enc = await aliceFirstMessage('hi', embed: false);
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
          envelopeDeviceId: _devA,
          identityDirectoryLookup: () async => throw StateError('offline'),
        ),
        throwsA(isA<SignalProtocolException>().having(
            (e) => e is IdentityBindingInvalidException, 'hard', isFalse)),
      );
    });

    test('full round trip: bound both ways, replies are type-1', () async {
      final enc = await aliceFirstMessage('ping');
      expect(
          utf8.decode(await bob.signal.decryptMessage(
            senderId: alice.peerId,
            deviceId: _devA,
            ciphertext: enc['ciphertext'] as Uint8List,
            messageType: 2,
            envelopeDeviceId: _devA,
          )),
          'ping');
      final reply = await bob.signal.encryptMessage(
          recipientId: alice.peerId, deviceId: _devA, plaintext: _utf8('pong'));
      expect(reply['messageType'], 1);
      expect(
          utf8.decode(await alice.signal.decryptMessage(
            senderId: bob.peerId,
            deviceId: _devB,
            ciphertext: reply['ciphertext'] as Uint8List,
            messageType: 1,
          )),
          'pong');
    });
  });

  group('bound-session enforcement + persistence', () {
    test('archived sessions with a superseded IK are purged too', () async {
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      alice.signal.setLocalIdentityBinding(alice.localBinding(epoch: 1000));
      // Bound session Alice -> Bob, bootstrapped both ways.
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      final first = await alice.signal.encryptMessage(
          recipientId: bob.peerId, deviceId: _devB, plaintext: _utf8('hi'));
      await bob.signal.decryptMessage(
        senderId: alice.peerId,
        deviceId: _devA,
        ciphertext: first['ciphertext'] as Uint8List,
        messageType: 2,
        envelopeDeviceId: _devA,
      );
      Future<Map<String, dynamic>> bobSays(String t) => bob.signal.encryptMessage(
          recipientId: alice.peerId, deviceId: _devA, plaintext: _utf8(t));
      Future<String> aliceReads(Map<String, dynamic> m) async => utf8.decode(
          await alice.signal.decryptMessage(
              senderId: bob.peerId,
              deviceId: _devB,
              ciphertext: m['ciphertext'] as Uint8List,
              messageType: m['messageType'] as int));
      expect(await aliceReads(await bobSays('r1')), 'r1');
      final heldA = await bobSays('held-a');
      final heldB = await bobSays('held-b');

      // Control: an archived session still decrypts in-flight messages.
      await alice.signal.archiveSession(bob.peerId, _devB);
      expect(await aliceReads(heldA), 'held-a');

      // Bob's account now binds DIFFERENT keys for the same device: the
      // archived session (old IK) must be purged, not used as a fallback.
      final bobNew = await TestParty.create(seedByte: 2, deviceId: _devB);
      await alice.signal.createSession(
        recipientId: bobNew.peerId,
        deviceId: _devB,
        preKeyBundle: bobNew.bundle(
            binding: bobNew.bindingFor(epoch: 3000),
            accountPublicKey: bobNew.accountPub),
      );
      expect(alice.signal.archiveDecryptDirty, isTrue,
          reason: 'the purge must be persisted');
      await expectLater(aliceReads(heldB), throwsA(isA<SignalProtocolException>()));
    });

    test('remoteIdentityKey survives save/load; nothing is seeded into the '
        'identity store on load', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_b2');
      addTearDown(() => dir.delete(recursive: true));
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      final key = Uint8List.fromList(List.filled(32, 42));
      alice.signal.setStoreEncryptionKey(key);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      final path = '${dir.path}/store.bin';
      expect(await alice.signal.saveSessionStore(path), isTrue);

      final fresh = InMemoryVerifiedIdentityStore();
      final reloaded = SignalProtocolService(identityStore: fresh)
        ..setStoreEncryptionKey(key);
      await reloaded.loadSessionStore(path);
      expect(reloaded.getRemoteIdentityKey(bob.peerId), bob.identityKey);
      expect(await fresh.get(bob.peerId), isNull);

      // Same store as before: the restored session matches the bound IK.
      final again = SignalProtocolService(identityStore: alice.store)
        ..setStoreEncryptionKey(key);
      await again.loadSessionStore(path);
      expect(await again.hasSession(bob.peerId, _devB), isTrue);
    });

    test('a session persisted without a remote IK (pre-0.3.0) is purged for '
        'a bound peer, never labelled by inference', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_noik');
      addTearDown(() => dir.delete(recursive: true));
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      final key = Uint8List.fromList(List.filled(32, 43));
      alice.signal.setStoreEncryptionKey(key);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      final path = '${dir.path}/store.bin';
      expect(await alice.signal.saveSessionStore(path), isTrue);

      // Rewrite the store as a pre-0.3.0 build would have left it: the
      // session carries no remoteIdentityKey (the per-peer IK is still the
      // bound one — 0.3.0 used it to label such a session and keep it).
      final file = File(path);
      final raw = await file.readAsBytes();
      final box = nacl_api.SecretBox(key);
      final store = jsonDecode(utf8.decode(box.decrypt(nacl_api.EncryptedMessage(
          nonce: raw.sublist(0, 24), cipherText: raw.sublist(24))))) as Map;
      final sessions = store['sessions'] as Map;
      for (final list in sessions.values) {
        for (final sess in list as List) {
          (sess as Map).remove('remoteIdentityKey');
        }
      }
      expect((store['remoteIdentityKeys'] as Map)[bob.peerId],
          hexLower(bob.identityKey));
      final nonce = Uint8List.fromList(List.filled(24, 5));
      await file.writeAsBytes(box
          .encrypt(Uint8List.fromList(utf8.encode(jsonEncode(store))),
              nonce: nonce)
          .toList());

      final reloaded = SignalProtocolService(identityStore: alice.store)
        ..setStoreEncryptionKey(key);
      await reloaded.loadSessionStore(path);
      expect(await reloaded.hasSession(bob.peerId, _devB), isFalse);
      expect(reloaded.archiveDecryptDirty, isTrue);
    });

    test('archiveSessionsOf archives the sessions of one peer only',
        () async {
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      final carol = await TestParty.create(seedByte: 3, deviceId: _devB);
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      await alice.signal.createSession(
        recipientId: carol.peerId,
        deviceId: _devB,
        preKeyBundle: carol.bundle(
            binding: carol.bindingFor(epoch: 1000),
            accountPublicKey: carol.accountPub),
      );
      expect(await alice.signal.archiveSessionsOf(bob.peerId), 1);
      expect(await alice.signal.hasSession(bob.peerId, _devB), isFalse);
      expect(await alice.signal.hasSession(carol.peerId, _devB), isTrue);
      expect(await alice.signal.archiveSessionsOf(bob.peerId), 0);
    });
  });

  group('device selection + non-consuming directory admission', () {
    test('highest valid epoch wins; invalid-only -> rejected; none -> first',
        () async {
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      final admission = IdentityAdmission(bob.store);
      RemoteDeviceIdentity dev(String id, IdentityBinding? b, int i,
              {bool unparseable = false}) =>
          RemoteDeviceIdentity(
            deviceId: id,
            identityKey: bob.identityKey,
            ed25519: bob.ed25519,
            binding: b,
            bindingUnparseable: unparseable,
            index: i,
          );

      final pick = admission.selectDevice(
        peerId: bob.peerId,
        accountPublicKey: bob.accountPub,
        devices: [
          dev(_devB, bob.bindingFor(epoch: 1), 0),
          dev(_devB2, bob.bindingFor(epoch: 5, deviceIdOverride: _devB2), 1),
          dev(_devA, bob.bindingFor(epoch: 9), 2), // signed for _devB -> invalid
        ],
      );
      expect(pick!.deviceId, _devB2);

      expect(
        () => admission.selectDevice(
          peerId: bob.peerId,
          accountPublicKey: bob.accountPub,
          devices: [dev(_devA, bob.bindingFor(epoch: 9), 0)],
        ),
        throwsA(isA<IdentityBindingInvalidException>()),
      );
      expect(
        () => admission.selectDevice(
          peerId: bob.peerId,
          accountPublicKey: bob.accountPub,
          devices: [dev(_devB, null, 0, unparseable: true)],
        ),
        throwsA(isA<IdentityBindingInvalidException>()),
      );
      // Nobody bound: the first device is returned — and refused by the
      // admission (bindingRequired), see admitDirectory below.
      final unbound = admission.selectDevice(
        peerId: bob.peerId,
        accountPublicKey: bob.accountPub,
        devices: [dev(_devB, null, 0), dev(_devB2, null, 1)],
      );
      expect(unbound!.deviceId, _devB);
    });

    test('admitDirectory: forged binding rejected; unbound device refused — '
        'both before any bundle would be consumed', () async {
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      final admission = IdentityAdmission(alice.store);
      final good = bob.bindingFor(epoch: 1000);
      final forged = IdentityBinding(
          signature: Uint8List.fromList(good.signature)..[3] ^= 1,
          epoch: 1000);
      RemoteIdentityDirectory dir(TestParty p, IdentityBinding? b) =>
          RemoteIdentityDirectory(accountPublicKey: p.accountPub, devices: [
            RemoteDeviceIdentity(
              deviceId: p.deviceId,
              identityKey: p.identityKey,
              ed25519: p.ed25519,
              binding: b,
              bindingUnparseable: false,
              index: 0,
            ),
          ]);
      await expectLater(
          admission.admitDirectory(peerId: bob.peerId, directory: dir(bob, forged)),
          throwsA(isA<IdentityBindingInvalidException>()));
      final ok = await admission.admitDirectory(
          peerId: bob.peerId, directory: dir(bob, good));
      expect(ok!.admitted.identityKey, bob.identityKey);
      expect(ok.admitted.ed25519, bob.ed25519);
      expect(ok.device.deviceId, _devB);
      expect((await alice.store.get(bob.peerId))!.bound, isTrue);

      final unbound = await TestParty.create(seedByte: 5, deviceId: _devB2);
      await expectLater(
          admission.admitDirectory(
              peerId: unbound.peerId, directory: dir(unbound, null)),
          throwsA(_bindingRejected(IdentityBindingFailure.bindingRequired)));
      expect(await alice.store.get(unbound.peerId), isNull);
      // A latched peer without a binding is a downgrade.
      await expectLater(
          admission.admitDirectory(peerId: bob.peerId, directory: dir(bob, null)),
          throwsA(_bindingRejected(IdentityBindingFailure.downgrade)));
    });

    test('keyChangeNotice: only a bound record whose device or keys differ',
        () {
      final ik1 = Uint8List.fromList(List.filled(32, 1));
      final ik2 = Uint8List.fromList(List.filled(32, 2));
      final ed1 = Uint8List.fromList(List.filled(32, 5));
      final ed2 = Uint8List.fromList(List.filled(32, 6));
      const peer = 'snow0123456789abcdef0123456789abcdef';
      final bound = VerifiedIdentityRecord(
        peerId: peer,
        accountPublicKey: Uint8List.fromList(List.filled(32, 7)),
        deviceId: _devB,
        epoch: 1,
        identityKey: ik1,
        ed25519: ed1,
        bindingSignature: Uint8List(64),
        bound: true,
        updatedAt: 1,
      );
      bool notice(VerifiedIdentityRecord r, String dev, Uint8List ik,
              Uint8List ed) =>
          IdentityAdmission.keyChangeNotice(
              existing: r, deviceId: dev, identityKey: ik, ed25519: ed);
      expect(notice(bound, _devB, ik1, ed1), isFalse, reason: 'same keys');
      expect(notice(bound, _devB2, ik1, ed1), isTrue, reason: 'other device');
      expect(notice(bound, _devB, ik2, ed1), isTrue, reason: 'other IK');
      expect(notice(bound, _devB, ik1, ed2), isTrue, reason: 'other Ed');
      // A record that only pins the account key holds no keys: first keys
      // are no change.
      final pinned = VerifiedIdentityRecord(
        peerId: peer,
        accountPublicKey: Uint8List.fromList(List.filled(32, 7)),
        updatedAt: 1,
      );
      expect(notice(pinned, _devB, ik1, ed1), isFalse);
    });
  });

  group('Safety Number v2', () {
    test('both sides compute identical digits over account keys', () async {
      final a = await TestParty.create(seedByte: 1, deviceId: _devA);
      final b = await TestParty.create(seedByte: 2, deviceId: _devB);
      final fromA = SafetyNumber.forAccountKeys(
        myId: a.peerId,
        myAccountKey: a.accountPub,
        theirId: b.peerId,
        theirAccountKey: b.accountPub,
      );
      final fromB = SafetyNumber.forAccountKeys(
        myId: b.peerId,
        myAccountKey: b.accountPub,
        theirId: a.peerId,
        theirAccountKey: a.accountPub,
      );
      expect(fromA, fromB);
      expect(fromA.length, 60);
      final v1 = SafetyNumber.compute(
        myId: a.peerId,
        myKey: a.accountPub,
        theirId: b.peerId,
        theirKey: b.accountPub,
        version: 1,
      );
      expect(v1, isNot(fromA), reason: 'v1/v2 numbers must never collide');
      // Cross-implementation golden: computed with the SnowChat reference
      // implementation (package:crypto SHA-512) over the same inputs.
      expect(fromA,
          '286706919533166536893393779443725117679843022058336522854049');
      expect(v1,
          '612056284826198659157442854615930194720240643640813449754463');
      expect(SafetyNumber.formatForDisplay(fromA).split('\n').length, 6);
    });

    test('a device reinstall does not change the account-key number', () async {
      final a = await TestParty.create(seedByte: 1, deviceId: _devA);
      final b1 = await TestParty.create(seedByte: 2, deviceId: _devB);
      final b2 = await TestParty.create(seedByte: 2, deviceId: _devB2);
      expect(b1.identityKey, isNot(b2.identityKey));
      String n(TestParty b) => SafetyNumber.forAccountKeys(
            myId: a.peerId,
            myAccountKey: a.accountPub,
            theirId: b.peerId,
            theirAccountKey: b.accountPub,
          );
      expect(n(b1), n(b2));
    });
  });
}
