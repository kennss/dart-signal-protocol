/// @file        identity_binding_mandatory_test.dart
/// @description Mandatory identity bindings (ported from SnowChat 3df0cc5 /
///              0aa549b). A peer without a valid account-key binding must be
///              refused on both the send and the receive path, never admitted
///              under a TOFU policy, and nothing may be recorded for it.
///              Bound peers keep working.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-23
/// @lastUpdated 2026-11-23
///
/// @functions
///  - main(): send-side and receive-side mandatory tests
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

import 'identity_test_support.dart';

const _devA = '0a0a0a0a-0000-4000-8000-00000000000a';
const _devB = '0b0b0b0b-0000-4000-8000-00000000000b';

Matcher _rejectedWith(IdentityBindingFailure reason) =>
    isA<IdentityBindingInvalidException>()
        .having((e) => e.reason, 'reason', reason);

void main() {
  group('send side', () {
    late TestParty alice;
    late TestParty bob;

    setUp(() async {
      alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      bob = await TestParty.create(seedByte: 2, deviceId: _devB);
    });

    test('bundle without a binding -> bindingRequired, no session', () async {
      await expectLater(
        alice.signal.createSession(
          recipientId: bob.peerId,
          deviceId: _devB,
          preKeyBundle: bob.bundle(),
        ),
        throwsA(_rejectedWith(IdentityBindingFailure.bindingRequired)),
      );
      expect(await alice.signal.hasSession(bob.peerId, _devB), isFalse);
      expect(await alice.store.get(bob.peerId), isNull,
          reason: 'an unbound peer must not leave a TOFU record behind');
    });

    test('bundle with a valid binding -> session created, peer bound',
        () async {
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
      expect(await alice.signal.hasSession(bob.peerId, _devB), isTrue);
      expect((await alice.store.get(bob.peerId))!.bound, isTrue);
    });
  });

  group('receive side', () {
    late TestParty alice;
    late TestParty bob;

    setUp(() async {
      alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      bob = await TestParty.create(seedByte: 2, deviceId: _devB);
      // Alice reaches Bob through a bound bundle but sends WITHOUT embedding
      // her own binding — what a compromised server stripping it, or an
      // unbound client, looks like to Bob.
      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );
    });

    test('binding-less type-2 message -> bindingRequired, nothing recorded',
        () async {
      final enc = await alice.signal.encryptMessage(
          recipientId: bob.peerId,
          deviceId: _devB,
          plaintext: Uint8List.fromList(utf8.encode('no proof')));
      final json = jsonDecode(utf8.decode(enc['ciphertext'] as Uint8List));
      expect((json as Map)['identityBinding'], isNull);

      await expectLater(
        bob.signal.decryptMessage(
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
                binding: null,
                bindingUnparseable: false,
                index: 0,
              ),
            ],
          ),
        ),
        throwsA(_rejectedWith(IdentityBindingFailure.bindingRequired)),
      );
      expect(await bob.store.get(alice.peerId), isNull);
    });

    test('embedded binding -> decrypts as before', () async {
      alice.signal.setLocalIdentityBinding(alice.localBinding(epoch: 5000));
      final enc = await alice.signal.encryptMessage(
          recipientId: bob.peerId,
          deviceId: _devB,
          plaintext: Uint8List.fromList(utf8.encode('with proof')));
      final pt = await bob.signal.decryptMessage(
        senderId: alice.peerId,
        deviceId: _devA,
        ciphertext: enc['ciphertext'] as Uint8List,
        messageType: 2,
        envelopeDeviceId: _devA,
        identityDirectoryLookup: () async =>
            throw StateError('bound sender must not need a lookup'),
      );
      expect(utf8.decode(pt), 'with proof');
      expect((await bob.store.get(alice.peerId))!.bound, isTrue);
    });
  });
}
