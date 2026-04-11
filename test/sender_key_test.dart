/// @file        sender_key_test.dart
/// @description Sender Key 프로토콜 테스트. 그룹 키 생성, SKDM 배포, 그룹 암복호화, 다중 멤버, 비멤버 거부
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - Group key generation
///  - SKDM creation and processing
///  - Group encrypt -> decrypt round-trip
///  - Multi-member group (3 members all decrypt)
///  - Non-member cannot decrypt
///  - Out-of-order group messages
///  - Chain ID uniqueness
///  - Key rotation
///  - SenderKeyRecord multi-state

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('SenderKeyManager — key creation', () {
    test('createSenderKey returns valid SKDM', () {
      final mgr = SenderKeyManager();
      final skdm = mgr.createSenderKey('group-1', 'alice');

      expect(skdm.groupId, 'group-1');
      expect(skdm.senderId, 'alice');
      expect(skdm.iteration, 0);
      expect(skdm.chainKey.length, 32);
      expect(skdm.signingKey.length, 32);
    });

    test('hasSenderKey returns true after creation', () {
      final mgr = SenderKeyManager();
      expect(mgr.hasSenderKey('group-1', 'alice'), isFalse);

      mgr.createSenderKey('group-1', 'alice');
      expect(mgr.hasSenderKey('group-1', 'alice'), isTrue);
    });

    test('each createSenderKey generates unique chain key', () {
      final mgr = SenderKeyManager();
      final skdm1 = mgr.createSenderKey('group-1', 'alice');

      // Create fresh manager for independent key
      final mgr2 = SenderKeyManager();
      final skdm2 = mgr2.createSenderKey('group-1', 'alice');

      expect(_bytesEqual(skdm1.chainKey, skdm2.chainKey), isFalse);
    });
  });

  group('SenderKeyDistributionMessage — serialization', () {
    test('serialize/deserialize round-trip preserves all fields', () {
      final mgr = SenderKeyManager();
      final original = mgr.createSenderKey('group-42', 'sender-x');

      final bytes = original.serialize();
      final restored = SenderKeyDistributionMessage.deserialize(bytes);

      expect(restored.groupId, original.groupId);
      expect(restored.senderId, original.senderId);
      expect(restored.iteration, original.iteration);
      expect(restored.chainKey, equals(original.chainKey));
      expect(restored.signingKey, equals(original.signingKey));
    });
  });

  group('SenderKeyManager — group encrypt/decrypt', () {
    test('encrypt -> decrypt round-trip (single member pair)', () {
      final aliceMgr = SenderKeyManager();
      final bobMgr = SenderKeyManager();

      // Alice creates sender key and distributes to Bob
      final skdm = aliceMgr.createSenderKey('group-1', 'alice');
      bobMgr.processSenderKey(skdm);

      // Alice encrypts
      final plaintext = Uint8List.fromList(utf8.encode('Hello group!'));
      final ciphertext = aliceMgr.encryptGroupMessage(
        'group-1',
        'alice',
        plaintext,
      );

      // Bob decrypts
      final decrypted = bobMgr.decryptGroupMessage(
        'group-1',
        'alice',
        ciphertext,
      );

      expect(utf8.decode(decrypted), 'Hello group!');
    });

    test('multi-member group: 3 members all decrypt', () {
      final aliceMgr = SenderKeyManager();
      final bobMgr = SenderKeyManager();
      final charlieMgr = SenderKeyManager();

      // Alice creates and distributes
      final skdm = aliceMgr.createSenderKey('group-1', 'alice');
      bobMgr.processSenderKey(skdm);
      charlieMgr.processSenderKey(skdm);

      // Alice encrypts
      final plaintext = Uint8List.fromList(utf8.encode('Group broadcast'));
      final ciphertext = aliceMgr.encryptGroupMessage(
        'group-1',
        'alice',
        plaintext,
      );

      // Both Bob and Charlie decrypt the same ciphertext
      final bobDecrypted = bobMgr.decryptGroupMessage(
        'group-1',
        'alice',
        ciphertext,
      );
      final charlieDecrypted = charlieMgr.decryptGroupMessage(
        'group-1',
        'alice',
        ciphertext,
      );

      expect(utf8.decode(bobDecrypted), 'Group broadcast');
      expect(utf8.decode(charlieDecrypted), 'Group broadcast');
    });

    test('multiple messages in sequence', () {
      final aliceMgr = SenderKeyManager();
      final bobMgr = SenderKeyManager();

      final skdm = aliceMgr.createSenderKey('group-1', 'alice');
      bobMgr.processSenderKey(skdm);

      for (var i = 0; i < 5; i++) {
        final plaintext = Uint8List.fromList(utf8.encode('Msg #$i'));
        final ciphertext = aliceMgr.encryptGroupMessage(
          'group-1',
          'alice',
          plaintext,
        );
        final decrypted = bobMgr.decryptGroupMessage(
          'group-1',
          'alice',
          ciphertext,
        );
        expect(utf8.decode(decrypted), 'Msg #$i');
      }
    });
  });

  group('SenderKeyManager — non-member rejection', () {
    test('non-member cannot decrypt (no sender key)', () {
      final aliceMgr = SenderKeyManager();
      final eveMgr = SenderKeyManager();

      aliceMgr.createSenderKey('group-1', 'alice');
      // Eve never receives the SKDM

      final ciphertext = aliceMgr.encryptGroupMessage(
        'group-1',
        'alice',
        Uint8List.fromList(utf8.encode('secret')),
      );

      expect(
        () => eveMgr.decryptGroupMessage('group-1', 'alice', ciphertext),
        throwsStateError,
      );
    });

    test('cannot encrypt without own sender key', () {
      final mgr = SenderKeyManager();

      expect(
        () => mgr.encryptGroupMessage(
          'group-1',
          'alice',
          Uint8List.fromList([1, 2, 3]),
        ),
        throwsStateError,
      );
    });
  });

  group('SenderKeyManager — out-of-order messages', () {
    test('out-of-order group messages decrypt correctly', () {
      final aliceMgr = SenderKeyManager();
      final bobMgr = SenderKeyManager();

      final skdm = aliceMgr.createSenderKey('group-1', 'alice');
      bobMgr.processSenderKey(skdm);

      final enc0 = aliceMgr.encryptGroupMessage(
        'group-1',
        'alice',
        Uint8List.fromList(utf8.encode('msg-0')),
      );
      final enc1 = aliceMgr.encryptGroupMessage(
        'group-1',
        'alice',
        Uint8List.fromList(utf8.encode('msg-1')),
      );
      final enc2 = aliceMgr.encryptGroupMessage(
        'group-1',
        'alice',
        Uint8List.fromList(utf8.encode('msg-2')),
      );

      // Receive out of order: 2, 0, 1
      final dec2 = bobMgr.decryptGroupMessage('group-1', 'alice', enc2);
      expect(utf8.decode(dec2), 'msg-2');

      final dec0 = bobMgr.decryptGroupMessage('group-1', 'alice', enc0);
      expect(utf8.decode(dec0), 'msg-0');

      final dec1 = bobMgr.decryptGroupMessage('group-1', 'alice', enc1);
      expect(utf8.decode(dec1), 'msg-1');
    });
  });

  group('SenderKeyManager — key rotation', () {
    test('rotateSenderKey creates new key and increments version', () {
      final mgr = SenderKeyManager();
      mgr.createSenderKey('group-1', 'alice');

      expect(mgr.getRotationVersion('group-1'), 0);

      final newSkdm = mgr.rotateSenderKey('group-1', 'alice');
      expect(mgr.getRotationVersion('group-1'), 1);
      expect(newSkdm.iteration, 0);
      expect(newSkdm.chainKey.length, 32);
    });

    test('removeGroup removes all keys for that group', () {
      final mgr = SenderKeyManager();
      mgr.createSenderKey('group-1', 'alice');
      mgr.createSenderKey('group-1', 'bob');

      expect(mgr.hasSenderKey('group-1', 'alice'), isTrue);
      expect(mgr.hasSenderKey('group-1', 'bob'), isTrue);

      mgr.removeGroup('group-1');

      expect(mgr.hasSenderKey('group-1', 'alice'), isFalse);
      expect(mgr.hasSenderKey('group-1', 'bob'), isFalse);
    });
  });

  group('SenderKeyManager — serialization', () {
    test('toJson/fromJson round-trip preserves state', () {
      final mgr = SenderKeyManager();
      final skdm = mgr.createSenderKey('group-1', 'alice');

      // Encrypt a message to advance state
      mgr.encryptGroupMessage(
        'group-1',
        'alice',
        Uint8List.fromList(utf8.encode('advance')),
      );

      // Serialize and restore
      final json = mgr.toJson();
      final restored = SenderKeyManager.fromJson(json);

      // Verify restored manager can still encrypt
      expect(restored.hasSenderKey('group-1', 'alice'), isTrue);

      // Decrypt with a separate manager that has the original SKDM
      final bobMgr = SenderKeyManager();
      bobMgr.processSenderKey(skdm);

      // Skip first message (iteration 0) since original mgr consumed it
      // The restored mgr is now at iteration 1
      final ciphertext = restored.encryptGroupMessage(
        'group-1',
        'alice',
        Uint8List.fromList(utf8.encode('from-restored')),
      );

      final decrypted = bobMgr.decryptGroupMessage(
        'group-1',
        'alice',
        ciphertext,
      );
      expect(utf8.decode(decrypted), 'from-restored');
    });
  });
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result == 0;
}
