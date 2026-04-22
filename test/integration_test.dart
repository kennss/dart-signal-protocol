/// @file        integration_test.dart
/// @description E2E 통합 테스트. 전체 1:1 메시징 플로우, 그룹 메시징 플로우, 혼합 시나리오
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - Full E2E: Alice and Bob initialize, create session, exchange 5 messages
///  - Group: 3 members, each sends a message, all receive all
///  - Mixed: 1:1 and group in same test
///  - SignalProtocolService full lifecycle

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('Integration — full 1:1 E2E flow', () {
    test('Alice and Bob exchange 5 messages via SignalProtocolService',
        () async {
      // -- Setup Alice --
      final alice = SignalProtocolService();
      await alice.generateIdentityKeyPair();
      await alice.generateSignedPreKey(1);
      await alice.generateOneTimePreKeys(100, 5);
      await alice.getPreKeyBundle(); // warm-up; Alice's bundle isn't consumed in this flow

      // -- Setup Bob --
      final bob = SignalProtocolService();
      await bob.generateIdentityKeyPair();
      await bob.generateSignedPreKey(1);
      await bob.generateOneTimePreKeys(200, 5);
      final bobBundle = await bob.getPreKeyBundle();

      // -- Alice creates session with Bob's bundle --
      await alice.createSession(
        recipientId: 'bob',
        deviceId: 'device-1',
        preKeyBundle: bobBundle,
      );

      // -- Alice sends first message (pre-key message) --
      final enc1 = await alice.encryptMessage(
        recipientId: 'bob',
        deviceId: 'device-1',
        plaintext: Uint8List.fromList(utf8.encode('Hello Bob!')),
      );
      expect(enc1['messageType'], 2); // pre-key message

      // -- Bob decrypts first message (establishes session) --
      // TOFU receive-side: supply Alice's Ed25519 verify key so _receiveSession
      // can pin / compare. Tests simulate the prekey-bundle lookup.
      final dec1 = await bob.decryptMessage(
        senderId: 'alice',
        deviceId: 'device-1',
        ciphertext: enc1['ciphertext'] as Uint8List,
        messageType: enc1['messageType'] as int,
        senderIdentityKeyEd25519: alice.verifyKey,
      );
      expect(utf8.decode(dec1), 'Hello Bob!');

      // -- Exchange 4 more messages --
      // Alice -> Bob
      final enc2 = await alice.encryptMessage(
        recipientId: 'bob',
        deviceId: 'device-1',
        plaintext: Uint8List.fromList(utf8.encode('Message 2')),
      );
      expect(enc2['messageType'], 1); // normal message now
      final dec2 = await bob.decryptMessage(
        senderId: 'alice',
        deviceId: 'device-1',
        ciphertext: enc2['ciphertext'] as Uint8List,
        messageType: enc2['messageType'] as int,
      );
      expect(utf8.decode(dec2), 'Message 2');

      // Bob -> Alice
      final enc3 = await bob.encryptMessage(
        recipientId: 'alice',
        deviceId: 'device-1',
        plaintext: Uint8List.fromList(utf8.encode('Bob reply 1')),
      );
      final dec3 = await alice.decryptMessage(
        senderId: 'bob',
        deviceId: 'device-1',
        ciphertext: enc3['ciphertext'] as Uint8List,
        messageType: enc3['messageType'] as int,
      );
      expect(utf8.decode(dec3), 'Bob reply 1');

      // Alice -> Bob
      final enc4 = await alice.encryptMessage(
        recipientId: 'bob',
        deviceId: 'device-1',
        plaintext: Uint8List.fromList(utf8.encode('Message 4')),
      );
      final dec4 = await bob.decryptMessage(
        senderId: 'alice',
        deviceId: 'device-1',
        ciphertext: enc4['ciphertext'] as Uint8List,
        messageType: enc4['messageType'] as int,
      );
      expect(utf8.decode(dec4), 'Message 4');

      // Bob -> Alice
      final enc5 = await bob.encryptMessage(
        recipientId: 'alice',
        deviceId: 'device-1',
        plaintext: Uint8List.fromList(utf8.encode('Bob reply 2')),
      );
      final dec5 = await alice.decryptMessage(
        senderId: 'bob',
        deviceId: 'device-1',
        ciphertext: enc5['ciphertext'] as Uint8List,
        messageType: enc5['messageType'] as int,
      );
      expect(utf8.decode(dec5), 'Bob reply 2');
    });

    test('hasSession and deleteSession work correctly', () async {
      final alice = SignalProtocolService();
      await alice.generateIdentityKeyPair();
      await alice.generateSignedPreKey(1);

      final bob = SignalProtocolService();
      await bob.generateIdentityKeyPair();
      await bob.generateSignedPreKey(1);
      final bobBundle = await bob.getPreKeyBundle();

      expect(await alice.hasSession('bob', 'device-1'), isFalse);

      await alice.createSession(
        recipientId: 'bob',
        deviceId: 'device-1',
        preKeyBundle: bobBundle,
      );

      expect(await alice.hasSession('bob', 'device-1'), isTrue);

      await alice.deleteSession('bob', 'device-1');
      expect(await alice.hasSession('bob', 'device-1'), isFalse);
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
      final alice = SignalProtocolService();
      await alice.generateIdentityKeyPair();

      final bob = SignalProtocolService();
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
      // Setup two users with both 1:1 and group capabilities
      final alice = SignalProtocolService();
      await alice.generateIdentityKeyPair();
      await alice.generateSignedPreKey(1);
      await alice.generateOneTimePreKeys(100, 5);

      final bob = SignalProtocolService();
      await bob.generateIdentityKeyPair();
      await bob.generateSignedPreKey(1);
      await bob.generateOneTimePreKeys(200, 5);

      final bobBundle = await bob.getPreKeyBundle();

      // -- 1:1 session --
      await alice.createSession(
        recipientId: 'bob',
        deviceId: 'device-1',
        preKeyBundle: bobBundle,
      );

      final enc1to1 = await alice.encryptMessage(
        recipientId: 'bob',
        deviceId: 'device-1',
        plaintext: Uint8List.fromList(utf8.encode('Private DM')),
      );
      final dec1to1 = await bob.decryptMessage(
        senderId: 'alice',
        deviceId: 'device-1',
        ciphertext: enc1to1['ciphertext'] as Uint8List,
        messageType: enc1to1['messageType'] as int,
        senderIdentityKeyEd25519: alice.verifyKey,
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
        recipientId: 'bob',
        deviceId: 'device-1',
        plaintext: Uint8List.fromList(utf8.encode('Still private')),
      );
      final dec1to1b = await bob.decryptMessage(
        senderId: 'alice',
        deviceId: 'device-1',
        ciphertext: enc1to1b['ciphertext'] as Uint8List,
        messageType: enc1to1b['messageType'] as int,
      );
      expect(utf8.decode(dec1to1b), 'Still private');
    });
  });

  group('Integration — error handling', () {
    test('encrypt without session throws SignalProtocolException', () async {
      final alice = SignalProtocolService();
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
      final bob = SignalProtocolService();
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
      final svc = SignalProtocolService();

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
