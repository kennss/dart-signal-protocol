/// @file        identity_binding_session_test.dart
/// @description Identity Binding v1 end-to-end over the REAL Signal layer
///              (X3DH + Double Ratchet, pinenacl): send-side admission inside
///              createSession (tamper / substituted bundle / downgrade /
///              epoch regression / same-key re-sign / reinstall notice /
///              legacy->bound interception warning), the Signal-style legacy
///              policy (unverified -> continue + notice, verified -> block
///              until re-verify, notice emitted once), receive-side
///              verification of the binding embedded in type-2 messages
///              (offline, header-IK swap rejected before any OPK is consumed,
///              device mismatch, malformed binding, directory fallback,
///              downgrade, server-bound IK mismatch, transient lookup
///              failure), device selection + non-consuming directory
///              admission, promotion-notice rules, bound-session purge
///              (active + archived) and remoteIdentityKey persistence,
///              backward compatibility without an identity store, and Safety
///              Number v2 symmetry + cross-implementation golden.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - main(): session-level identity binding tests
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
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
      expect(await alice.store.pinFromInviteLink(bob.peerId, bob.accountPub),
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

    test('legacy -> bound promotion with different keys -> interception '
        'warning', () async {
      final events = _collect(alice.store);
      final mitm = await TestParty.create(seedByte: 9, deviceId: _devB);
      // Transition period: the server hands out an unbound attacker bundle
      // under Bob's id (accepted as legacy TOFU)…
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: mitm.bundle(),
      );
      // …then Bob upgrades and presents his real, bound keys.
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      await _flush();
      expect(events.map((e) => e.kind),
          contains(IdentityEventKind.interceptionSuspected));
      expect((await alice.store.get(bob.peerId))!.identityKey, bob.identityKey);
    });

    test('honest reinstall over a legacy-sourced record -> device notice, '
        'NOT interception', () async {
      final bobNew = await TestParty.create(seedByte: 2, deviceId: _devB2);
      // Pre-binding state: imported pin + seeded IK with its device.
      await alice.store.put(VerifiedIdentityRecord(
        peerId: bob.peerId,
        deviceId: _devB,
        identityKey: bob.identityKey,
        ed25519: bob.ed25519,
        edLegacySourced: true,
        updatedAt: 1,
      ));
      final events = _collect(alice.store);
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
  });

  group('legacy policy (Signal style)', () {
    late TestParty alice;

    setUp(() async {
      alice = await TestParty.create(seedByte: 1, deviceId: _devA);
    });

    test('unverified key change -> updated, notice, session continues',
        () async {
      final events = _collect(alice.store);
      final old = await TestParty.create(seedByte: 4, deviceId: _devB);
      final reinstalled = await TestParty.create(seedByte: 4, deviceId: _devB2);
      await alice.signal.createSession(
          recipientId: old.peerId, deviceId: _devB, preKeyBundle: old.bundle());
      await alice.signal.createSession(
          recipientId: old.peerId,
          deviceId: _devB2,
          preKeyBundle: reinstalled.bundle());
      await _flush();
      expect(events.single.kind, IdentityEventKind.legacyKeyChanged);
      expect((await alice.store.get(old.peerId))!.identityKey,
          reinstalled.identityKey);
      expect(await alice.signal.hasSession(old.peerId, _devB2), isTrue);
    });

    test('verified key change -> blocked (notice once) until re-verify',
        () async {
      alice.store.verifiedLookup = (_) async => true;
      final events = _collect(alice.store);
      final old = await TestParty.create(seedByte: 5, deviceId: _devB);
      final reinstalled = await TestParty.create(seedByte: 5, deviceId: _devB2);
      await alice.signal.createSession(
          recipientId: old.peerId, deviceId: _devB, preKeyBundle: old.bundle());

      for (var i = 0; i < 2; i++) {
        await expectLater(
          alice.signal.createSession(
              recipientId: old.peerId,
              deviceId: _devB2,
              preKeyBundle: reinstalled.bundle(opkIndex: i)),
          throwsA(isA<IdentityKeyChangedException>()),
        );
      }
      await _flush();
      expect(events.single.kind, IdentityEventKind.legacyKeyChangeBlocked,
          reason: 'notice only on the transition into the blocked state');
      expect((await alice.store.get(old.peerId))!.hasPendingChange, isTrue);

      // Still blocked even though the verification flag now reads false.
      alice.store.verifiedLookup = (_) async => false;
      await expectLater(
        alice.signal.createSession(
            recipientId: old.peerId,
            deviceId: _devB2,
            preKeyBundle: reinstalled.bundle(opkIndex: 1)),
        throwsA(isA<IdentityKeyChangedException>()),
      );

      // User re-verifies -> pending keys adopted.
      expect(await alice.store.acceptPendingChange(old.peerId), isTrue);
      await alice.signal.createSession(
          recipientId: old.peerId,
          deviceId: _devB2,
          preKeyBundle: reinstalled.bundle(opkIndex: 2));
      expect(await alice.signal.hasSession(old.peerId, _devB2), isTrue);
    });

    test('verification lookup failure is transient, not fail-open', () async {
      alice.store.verifiedLookup = (_) async => throw StateError('db down');
      final old = await TestParty.create(seedByte: 6, deviceId: _devB);
      final reinstalled = await TestParty.create(seedByte: 6, deviceId: _devB2);
      await alice.signal.createSession(
          recipientId: old.peerId, deviceId: _devB, preKeyBundle: old.bundle());
      await expectLater(
        alice.signal.createSession(
            recipientId: old.peerId,
            deviceId: _devB2,
            preKeyBundle: reinstalled.bundle()),
        throwsA(isA<SignalProtocolException>()
            .having((e) => e is IdentityBindingInvalidException, 'hard', isFalse)),
      );
      expect((await alice.store.get(old.peerId))!.identityKey, old.identityKey,
          reason: 'keys must not be silently replaced');
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

    test('binding-less sender (old client) -> directory fallback, legacy '
        'accept', () async {
      final enc = await aliceFirstMessage('legacy hi', embed: false);
      final json = jsonDecode(utf8.decode(enc['ciphertext'] as Uint8List));
      expect((json as Map)['identityBinding'], isNull);
      var lookups = 0;
      final pt = await bob.signal.decryptMessage(
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
      );
      expect(utf8.decode(pt), 'legacy hi');
      expect(lookups, 1);
      final rec = await bob.store.get(alice.peerId);
      expect(rec!.bound, isFalse);
      expect(rec.identityKey, alice.identityKey);
      expect(rec.accountPublicKey, alice.accountPub);
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

    test('senderIdentityKeyEd25519 with an identity store -> ArgumentError',
        () async {
      final enc = await aliceFirstMessage('hi');
      await expectLater(
        bob.signal.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
          senderIdentityKeyEd25519: alice.ed25519,
        ),
        throwsArgumentError,
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
      // Legacy (unbound) session Alice -> Bob, bootstrapped both ways.
      await alice.signal.createSession(
          recipientId: bob.peerId, deviceId: _devB, preKeyBundle: bob.bundle());
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

    test('remoteIdentityKey survives save/load; IK seeding runs on load',
        () async {
      final dir = await Directory.systemTemp.createTemp('dsp_b2');
      addTearDown(() => dir.delete(recursive: true));
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      final key = Uint8List.fromList(List.filled(32, 42));
      alice.signal.setStoreEncryptionKey(key);
      await alice.signal.createSession(
          recipientId: bob.peerId, deviceId: _devB, preKeyBundle: bob.bundle());
      final path = '${dir.path}/store.bin';
      expect(await alice.signal.saveSessionStore(path), isTrue);

      final fresh = InMemoryVerifiedIdentityStore();
      final reloaded = SignalProtocolService(identityStore: fresh)
        ..setStoreEncryptionKey(key);
      await reloaded.loadSessionStore(path);
      expect(reloaded.getRemoteIdentityKey(bob.peerId), bob.identityKey);
      final seeded = await fresh.get(bob.peerId);
      expect(seeded!.identityKey, bob.identityKey);
      expect(seeded.deviceId, _devB);
      expect(seeded.bound, isFalse);
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
      final legacy = admission.selectDevice(
        peerId: bob.peerId,
        accountPublicKey: bob.accountPub,
        devices: [dev(_devB, null, 0), dev(_devB2, null, 1)],
      );
      expect(legacy!.deviceId, _devB);
    });

    test('admitDirectory: forged binding rejected; verified legacy change '
        'blocked — both before any bundle would be consumed', () async {
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
      expect(ok!.admitted.bound, isTrue);
      expect(ok.device.deviceId, _devB);

      final re = await TestParty.create(seedByte: 5, deviceId: _devB2);
      alice.store.verifiedLookup = (_) async => true;
      await alice.store.put(VerifiedIdentityRecord(
        peerId: re.peerId,
        deviceId: _devB,
        identityKey: Uint8List.fromList(List.filled(32, 7)),
        updatedAt: 1,
      ));
      await expectLater(
          admission.admitDirectory(peerId: re.peerId, directory: dir(re, null)),
          throwsA(isA<IdentityKeyChangedException>()));
    });

    test('promotionNotice rules', () {
      final ik1 = Uint8List.fromList(List.filled(32, 1));
      final ik2 = Uint8List.fromList(List.filled(32, 2));
      final ed1 = Uint8List.fromList(List.filled(32, 5));
      final ed2 = Uint8List.fromList(List.filled(32, 6));
      VerifiedIdentityRecord rec({
        String? dev,
        Uint8List? ik,
        bool legacyEd = false,
      }) =>
          VerifiedIdentityRecord(
            peerId: 'snow0123456789abcdef0123456789abcdef',
            deviceId: dev,
            identityKey: ik,
            ed25519: ed1,
            edLegacySourced: legacyEd,
            updatedAt: 1,
          );
      // Legacy-sourced Ed differs, IK same -> nothing.
      expect(
          IdentityAdmission.promotionNotice(
              existing: rec(dev: _devB, ik: ik1, legacyEd: true),
              deviceId: _devB,
              identityKey: ik1,
              ed25519: ed2),
          isNull);
      // Same device, different IK -> interception.
      expect(
          IdentityAdmission.promotionNotice(
              existing: rec(dev: _devB, ik: ik1),
              deviceId: _devB,
              identityKey: ik2,
              ed25519: ed1),
          IdentityEventKind.interceptionSuspected);
      // Unknown legacy device, different IK -> interception.
      expect(
          IdentityAdmission.promotionNotice(
              existing: rec(ik: ik1),
              deviceId: _devB,
              identityKey: ik2,
              ed25519: ed1),
          IdentityEventKind.interceptionSuspected);
      // Different device -> reinstall evidence.
      expect(
          IdentityAdmission.promotionNotice(
              existing: rec(dev: _devB, ik: ik1),
              deviceId: _devB2,
              identityKey: ik2,
              ed25519: ed1),
          IdentityEventKind.deviceKeysChanged);
    });
  });

  group('backward compatibility without an identity store', () {
    test('no store: bindings ignored, legacy fail-closed Ed25519 rule kept',
        () async {
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final plainBob = SignalProtocolService();
      await plainBob.generateIdentityKeyPair();
      await plainBob.generateSignedPreKey(1);
      final bobBundle = await plainBob.getPreKeyBundle();
      alice.signal.setLocalIdentityBinding(alice.localBinding(epoch: 1));
      // Alice (store) -> plain Bob: unbound legacy admission on Alice's side.
      await alice.signal.createSession(
          recipientId: 'snowfedcba9876543210fedcba9876543210',
          deviceId: _devB,
          preKeyBundle: bobBundle);
      final enc = await alice.signal.encryptMessage(
          recipientId: 'snowfedcba9876543210fedcba9876543210',
          deviceId: _devB,
          plaintext: _utf8('compat'));
      // Plain Bob still requires the sender Ed25519 for a new session…
      await expectLater(
        plainBob.decryptMessage(
          senderId: alice.peerId,
          deviceId: _devA,
          ciphertext: enc['ciphertext'] as Uint8List,
          messageType: 2,
        ),
        throwsA(isA<SignalProtocolException>()),
      );
      // …and decrypts with it, ignoring the embedded binding.
      final pt = await plainBob.decryptMessage(
        senderId: alice.peerId,
        deviceId: _devA,
        ciphertext: enc['ciphertext'] as Uint8List,
        messageType: 2,
        senderIdentityKeyEd25519: alice.ed25519,
      );
      expect(utf8.decode(pt), 'compat');
    });

    test('both identity stores -> ArgumentError', () {
      expect(
        () => SignalProtocolService(
          identityStore: InMemoryVerifiedIdentityStore(),
          // ignore: deprecated_member_use_from_same_package
          identityPinStore: _NoopPins(),
        ),
        throwsArgumentError,
      );
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

// ignore: deprecated_member_use_from_same_package
class _NoopPins implements IdentityPinStore {
  @override
  Future<Uint8List?> getPinned(String sessionKey) async => null;

  @override
  Future<void> pin(String sessionKey, Uint8List identityKey) async {}
}
