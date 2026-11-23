/// @file        integration_test.dart
/// @description E2E integration tests. Full 1:1 messaging flow, group messaging flow, mixed scenarios
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-11-23 (bindings mandatory: the 1:1 flows run between bound TestParty
///              users — no senderIdentityKeyEd25519, no store-less service; English-only comments). Earlier 2026-11-10 (persistent PreKey: second message before the peer replies is still type-2)
///
/// @functions
///  - Full E2E: Alice and Bob initialize, create session, exchange 5 messages
///  - Group: 3 members, each sends a message, all receive all
///  - Mixed: 1:1 and group in same test
///  - SignalProtocolService full lifecycle
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

import 'identity_test_support.dart';

const _devA = '0a0a0a0a-0000-4000-8000-00000000000a';
const _devB = '0b0b0b0b-0000-4000-8000-00000000000b';

/// Alice and Bob, each with an account-signed binding installed; Alice holds
/// a session to Bob created from his bound bundle.
Future<(TestParty, TestParty)> _boundPair() async {
  final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
  final bob = await TestParty.create(seedByte: 2, deviceId: _devB);
  alice.signal.setLocalIdentityBinding(alice.localBinding(epoch: 1000));
  bob.signal.setLocalIdentityBinding(bob.localBinding(epoch: 1000));
  await alice.signal.createSession(
    recipientId: bob.peerId,
    deviceId: _devB,
    preKeyBundle: bob.bundle(
        binding: bob.bindingFor(epoch: 1000), accountPublicKey: bob.accountPub),
  );
  return (alice, bob);
}

void main() {
  group('Integration — full 1:1 E2E flow', () {
    test('Alice and Bob exchange 5 messages via SignalProtocolService',
        () async {
      final (aliceParty, bobParty) = await _boundPair();
      final alice = aliceParty.signal;
      final bob = bobParty.signal;
      final aliceId = aliceParty.peerId;
      final bobId = bobParty.peerId;

      // -- Alice sends first message (pre-key message, binding embedded) --
      final enc1 = await alice.encryptMessage(
        recipientId: bobId,
        deviceId: _devB,
        plaintext: Uint8List.fromList(utf8.encode('Hello Bob!')),
      );
      expect(enc1['messageType'], 2); // pre-key message

      // -- Bob decrypts first message: Alice's embedded binding is verified
      // offline before any prekey is used, then the session is established.
      final dec1 = await bob.decryptMessage(
        senderId: aliceId,
        deviceId: _devA,
        ciphertext: enc1['ciphertext'] as Uint8List,
        messageType: enc1['messageType'] as int,
        envelopeDeviceId: _devA,
      );
      expect(utf8.decode(dec1), 'Hello Bob!');

      // -- Exchange 4 more messages --
      // Alice -> Bob
      final enc2 = await alice.encryptMessage(
        recipientId: bobId,
        deviceId: _devB,
        plaintext: Uint8List.fromList(utf8.encode('Message 2')),
      );
      // Persistent PreKey (0.3.0): Alice has not yet decrypted anything from
      // Bob, so she keeps emitting PreKey (type-2) messages until Bob replies.
      expect(enc2['messageType'], 2);
      final dec2 = await bob.decryptMessage(
        senderId: aliceId,
        deviceId: _devA,
        ciphertext: enc2['ciphertext'] as Uint8List,
        messageType: enc2['messageType'] as int,
      );
      expect(utf8.decode(dec2), 'Message 2');

      // Bob -> Alice
      final enc3 = await bob.encryptMessage(
        recipientId: aliceId,
        deviceId: _devA,
        plaintext: Uint8List.fromList(utf8.encode('Bob reply 1')),
      );
      final dec3 = await alice.decryptMessage(
        senderId: bobId,
        deviceId: _devB,
        ciphertext: enc3['ciphertext'] as Uint8List,
        messageType: enc3['messageType'] as int,
      );
      expect(utf8.decode(dec3), 'Bob reply 1');

      // Alice decrypted an inbound message on the session, so her pending
      // PreKey state is retired and later messages are normal (type-1).

      // Alice -> Bob
      final enc4 = await alice.encryptMessage(
        recipientId: bobId,
        deviceId: _devB,
        plaintext: Uint8List.fromList(utf8.encode('Message 4')),
      );
      expect(enc4['messageType'], 1);
      final dec4 = await bob.decryptMessage(
        senderId: aliceId,
        deviceId: _devA,
        ciphertext: enc4['ciphertext'] as Uint8List,
        messageType: enc4['messageType'] as int,
      );
      expect(utf8.decode(dec4), 'Message 4');

      // Bob -> Alice
      final enc5 = await bob.encryptMessage(
        recipientId: aliceId,
        deviceId: _devA,
        plaintext: Uint8List.fromList(utf8.encode('Bob reply 2')),
      );
      final dec5 = await alice.decryptMessage(
        senderId: bobId,
        deviceId: _devB,
        ciphertext: enc5['ciphertext'] as Uint8List,
        messageType: enc5['messageType'] as int,
      );
      expect(utf8.decode(dec5), 'Bob reply 2');
    });

    test('hasSession and deleteSession work correctly', () async {
      final alice = await TestParty.create(seedByte: 1, deviceId: _devA);
      final bob = await TestParty.create(seedByte: 2, deviceId: _devB);

      expect(await alice.signal.hasSession(bob.peerId, _devB), isFalse);

      await alice.signal.createSession(
        recipientId: bob.peerId,
        deviceId: _devB,
        preKeyBundle: bob.bundle(
            binding: bob.bindingFor(epoch: 1000),
            accountPublicKey: bob.accountPub),
      );

      expect(await alice.signal.hasSession(bob.peerId, _devB), isTrue);

      await alice.signal.deleteSession(bob.peerId, _devB);
      expect(await alice.signal.hasSession(bob.peerId, _devB), isFalse);
    });
  });

  group('Integration — group E2E flow', () {
    test('3 members: each sends a message, all receive all', () async {
      final aliceMgr = SenderKeyManager();
      final bobMgr = SenderKeyManager();
      final charlieMgr = SenderKeyManager();

      const groupId = 'group-test-1';

      // Each member creates their sender key and distributes to others
      final aliceSkdm = aliceMgr.createSenderKey(groupId, 'alice');
      final bobSkdm = bobMgr.createSenderKey(groupId, 'bob');
      final charlieSkdm = charlieMgr.createSenderKey(groupId, 'charlie');

      // Distribute all SKDMs to all members
      bobMgr.processSenderKey(aliceSkdm);
      charlieMgr.processSenderKey(aliceSkdm);

      aliceMgr.processSenderKey(bobSkdm);
      charlieMgr.processSenderKey(bobSkdm);

      aliceMgr.processSenderKey(charlieSkdm);
      bobMgr.processSenderKey(charlieSkdm);

      // Alice sends
      final aliceMsg = aliceMgr.encryptGroupMessage(
        groupId,
        'alice',
        Uint8List.fromList(utf8.encode('Hello from Alice')),
      );
      expect(
        utf8.decode(
            bobMgr.decryptGroupMessage(groupId, 'alice', aliceMsg)),
        'Hello from Alice',
      );
      expect(
        utf8.decode(
            charlieMgr.decryptGroupMessage(groupId, 'alice', aliceMsg)),
        'Hello from Alice',
      );

      // Bob sends
      final bobMsg = bobMgr.encryptGroupMessage(
        groupId,
        'bob',
        Uint8List.fromList(utf8.encode('Hello from Bob')),
      );
      expect(
        utf8.decode(
            aliceMgr.decryptGroupMessage(groupId, 'bob', bobMsg)),
        'Hello from Bob',
      );
      expect(
        utf8.decode(
            charlieMgr.decryptGroupMessage(groupId, 'bob', bobMsg)),
        'Hello from Bob',
      );

      // Charlie sends
      final charlieMsg = charlieMgr.encryptGroupMessage(
        groupId,
        'charlie',
        Uint8List.fromList(utf8.encode('Hello from Charlie')),
      );
      expect(
        utf8.decode(
            aliceMgr.decryptGroupMessage(groupId, 'charlie', charlieMsg)),
        'Hello from Charlie',
      );
      expect(
        utf8.decode(
            bobMgr.decryptGroupMessage(groupId, 'charlie', charlieMsg)),
        'Hello from Charlie',
      );
    });
  });

  group('Integration — group via SignalProtocolService', () {
    test('group encrypt/decrypt via high-level API', () async {
      final alice = SignalProtocolService(
          identityStore: InMemoryVerifiedIdentityStore());
      await alice.generateIdentityKeyPair();

      final bob = SignalProtocolService(
          identityStore: InMemoryVerifiedIdentityStore());
      await bob.generateIdentityKeyPair();

      const groupId = 'group-svc-1';

      // Alice creates sender key
      final aliceSKResult = await alice.createSenderKey(
        groupId,
        myId: 'alice',
      );

      // Bob processes Alice's sender key
      await bob.processSenderKey(
        groupId,
        'alice',
        aliceSKResult,
      );

      // Alice encrypts
      final ciphertext = await alice.encryptGroupMessage(
        groupId,
        Uint8List.fromList(utf8.encode('Group hello!')),
        myId: 'alice',
      );

      // Bob decrypts
      final plaintext = await bob.decryptGroupMessage(
        groupId,
        'alice',
        ciphertext,
      );

      expect(utf8.decode(plaintext), 'Group hello!');
    });
  });

  group('Integration — mixed 1:1 + group', () {
    test('1:1 and group messaging coexist without interference', () async {
      final (aliceParty, bobParty) = await _boundPair();
      final alice = aliceParty.signal;
      final bob = bobParty.signal;

      // -- 1:1 session --
      final enc1to1 = await alice.encryptMessage(
        recipientId: bobParty.peerId,
        deviceId: _devB,
        plaintext: Uint8List.fromList(utf8.encode('Private DM')),
      );
      final dec1to1 = await bob.decryptMessage(
        senderId: aliceParty.peerId,
        deviceId: _devA,
        ciphertext: enc1to1['ciphertext'] as Uint8List,
        messageType: enc1to1['messageType'] as int,
        envelopeDeviceId: _devA,
      );
      expect(utf8.decode(dec1to1), 'Private DM');

      // -- Group messaging (same users) --
      const groupId = 'mixed-group';
      final aliceSK = await alice.createSenderKey(groupId, myId: 'alice');
      await bob.processSenderKey(groupId, 'alice', aliceSK);

      final groupCt = await alice.encryptGroupMessage(
        groupId,
        Uint8List.fromList(utf8.encode('Group msg')),
        myId: 'alice',
      );
      final groupPt = await bob.decryptGroupMessage(
        groupId,
        'alice',
        groupCt,
      );
      expect(utf8.decode(groupPt), 'Group msg');

      // -- Verify 1:1 still works after group --
      final enc1to1b = await alice.encryptMessage(
        recipientId: bobParty.peerId,
        deviceId: _devB,
        plaintext: Uint8List.fromList(utf8.encode('Still private')),
      );
      final dec1to1b = await bob.decryptMessage(
        senderId: aliceParty.peerId,
        deviceId: _devA,
        ciphertext: enc1to1b['ciphertext'] as Uint8List,
        messageType: enc1to1b['messageType'] as int,
      );
      expect(utf8.decode(dec1to1b), 'Still private');
    });
  });

  group('Integration — error handling', () {
    test('encrypt without session throws SignalProtocolException', () async {
      final alice = SignalProtocolService(
          identityStore: InMemoryVerifiedIdentityStore());
      await alice.generateIdentityKeyPair();

      expect(
        () => alice.encryptMessage(
          recipientId: 'nobody',
          deviceId: 'device-1',
          plaintext: Uint8List.fromList([1, 2, 3]),
        ),
        throwsA(isA<SignalProtocolException>()),
      );
    });

    test('decrypt without session throws SignalProtocolException', () async {
      final bob = SignalProtocolService(
          identityStore: InMemoryVerifiedIdentityStore());
      await bob.generateIdentityKeyPair();

      expect(
        () => bob.decryptMessage(
          senderId: 'nobody',
          deviceId: 'device-1',
          ciphertext: Uint8List.fromList([1, 2, 3]),
          messageType: 1,
        ),
        throwsA(isA<SignalProtocolException>()),
      );
    });

    test('generateIdentityKeyPair required before session operations',
        () async {
      final svc = SignalProtocolService(
          identityStore: InMemoryVerifiedIdentityStore());

      expect(
        () => svc.createSession(
          recipientId: 'bob',
          deviceId: 'device-1',
          preKeyBundle: {},
        ),
        throwsA(isA<SignalProtocolException>()),
      );
    });
  });
}
