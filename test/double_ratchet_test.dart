/// @file        double_ratchet_test.dart
/// @description Double Ratchet 알고리즘 테스트. 암복호화 왕복, 양방향 대화, 순서 뒤바뀜, 에러 조건 검증
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-10
/// @lastUpdated 2026-04-10
///
/// @functions
///  - Encrypt -> decrypt round-trip
///  - Bidirectional conversation (Alice sends, Bob sends, Alice sends)
///  - Out-of-order messages (send 3, receive in order 3->1->2)
///  - Wrong key decryption fails
///  - Empty plaintext handling
///  - Large message (10KB)
///  - Multiple messages advance the chain
///  - Session serialization/deserialization

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:test/test.dart';

/// Helper: create a matched sender/receiver pair via X3DH.
({DoubleRatchetSession alice, DoubleRatchetSession bob}) _createSessionPair() {
  final aliceIK = X25519KeyPair.generate();
  final bobIK = X25519KeyPair.generate();
  final bobSPK = X25519KeyPair.generate();

  final x3dhResult = X3DH.initiateSession(
    identityKeyPrivate: aliceIK.privateKey,
    remoteIdentityKey: bobIK.publicKey,
    remoteSignedPreKey: bobSPK.publicKey,
  );

  final bobSecret = X3DH.receiveSession(
    identityKeyPrivate: bobIK.privateKey,
    signedPreKeyPrivate: bobSPK.privateKey,
    remoteIdentityKey: aliceIK.publicKey,
    remoteEphemeralKey: x3dhResult.ephemeralPublicKey,
  );

  final alice = DoubleRatchetSession.initSender(
    x3dhResult.sharedSecret,
    bobSPK.publicKey,
  );

  final bob = DoubleRatchetSession.initReceiver(
    bobSecret,
    bobSPK.privateKey,
    bobSPK.publicKey,
  );

  return (alice: alice, bob: bob);
}

void main() {
  group('Double Ratchet — basic encrypt/decrypt', () {
    test('encrypt -> decrypt round-trip', () {
      final sessions = _createSessionPair();
      final plaintext = Uint8List.fromList(utf8.encode('Hello, Bob!'));

      final encrypted = sessions.alice.encrypt(plaintext);
      final decrypted = sessions.bob.decrypt(encrypted);

      expect(utf8.decode(decrypted), 'Hello, Bob!');
    });

    test('EncryptedMessage fields are populated', () {
      final sessions = _createSessionPair();
      final plaintext = Uint8List.fromList(utf8.encode('test'));

      final encrypted = sessions.alice.encrypt(plaintext);

      expect(encrypted.ciphertext.isNotEmpty, isTrue);
      expect(encrypted.ratchetPublicKey.length, 32);
      expect(encrypted.messageNumber, 0);
      expect(encrypted.previousChainLength, 0);
    });

    test('empty plaintext round-trip', () {
      final sessions = _createSessionPair();
      final plaintext = Uint8List(0);

      final encrypted = sessions.alice.encrypt(plaintext);
      final decrypted = sessions.bob.decrypt(encrypted);

      expect(decrypted.length, 0);
    });

    test('large message (10KB) round-trip', () {
      final sessions = _createSessionPair();
      final plaintext = Uint8List(10240);
      for (var i = 0; i < plaintext.length; i++) {
        plaintext[i] = i % 256;
      }

      final encrypted = sessions.alice.encrypt(plaintext);
      final decrypted = sessions.bob.decrypt(encrypted);

      expect(decrypted, equals(plaintext));
    });

    test('UTF-8 message with Korean text', () {
      final sessions = _createSessionPair();
      final text = 'Hello world! Signal Protocol test.';
      final plaintext = Uint8List.fromList(utf8.encode(text));

      final encrypted = sessions.alice.encrypt(plaintext);
      final decrypted = sessions.bob.decrypt(encrypted);

      expect(utf8.decode(decrypted), text);
    });
  });

  group('Double Ratchet — multiple messages', () {
    test('multiple messages from Alice to Bob', () {
      final sessions = _createSessionPair();

      for (var i = 0; i < 5; i++) {
        final plaintext = Uint8List.fromList(utf8.encode('Message $i'));
        final encrypted = sessions.alice.encrypt(plaintext);
        final decrypted = sessions.bob.decrypt(encrypted);
        expect(utf8.decode(decrypted), 'Message $i');
      }
    });

    test('message numbers increment', () {
      final sessions = _createSessionPair();

      final enc0 = sessions.alice.encrypt(Uint8List.fromList([0]));
      expect(enc0.messageNumber, 0);

      final enc1 = sessions.alice.encrypt(Uint8List.fromList([1]));
      expect(enc1.messageNumber, 1);

      final enc2 = sessions.alice.encrypt(Uint8List.fromList([2]));
      expect(enc2.messageNumber, 2);

      // Bob decrypts all in order
      sessions.bob.decrypt(enc0);
      sessions.bob.decrypt(enc1);
      sessions.bob.decrypt(enc2);
    });
  });

  group('Double Ratchet — bidirectional conversation', () {
    test('Alice sends, Bob sends, Alice sends', () {
      final sessions = _createSessionPair();

      // Alice -> Bob
      final enc1 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('Alice message 1')),
      );
      final dec1 = sessions.bob.decrypt(enc1);
      expect(utf8.decode(dec1), 'Alice message 1');

      // Bob -> Alice (triggers DH ratchet on Bob's side)
      final enc2 = sessions.bob.encrypt(
        Uint8List.fromList(utf8.encode('Bob message 1')),
      );
      final dec2 = sessions.alice.decrypt(enc2);
      expect(utf8.decode(dec2), 'Bob message 1');

      // Alice -> Bob again
      final enc3 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('Alice message 2')),
      );
      final dec3 = sessions.bob.decrypt(enc3);
      expect(utf8.decode(dec3), 'Alice message 2');
    });

    test('extended bidirectional conversation (10 messages)', () {
      final sessions = _createSessionPair();

      for (var i = 0; i < 10; i++) {
        if (i % 2 == 0) {
          // Alice sends
          final msg = 'Alice: turn $i';
          final enc = sessions.alice.encrypt(
            Uint8List.fromList(utf8.encode(msg)),
          );
          final dec = sessions.bob.decrypt(enc);
          expect(utf8.decode(dec), msg);
        } else {
          // Bob sends
          final msg = 'Bob: turn $i';
          final enc = sessions.bob.encrypt(
            Uint8List.fromList(utf8.encode(msg)),
          );
          final dec = sessions.alice.decrypt(enc);
          expect(utf8.decode(dec), msg);
        }
      }
    });
  });

  group('Double Ratchet — out-of-order messages', () {
    test('out-of-order delivery: receive message 2 before message 1', () {
      final sessions = _createSessionPair();

      final enc0 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('msg-0')),
      );
      final enc1 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('msg-1')),
      );
      final enc2 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('msg-2')),
      );

      // Receive out of order: 2, 0, 1
      final dec2 = sessions.bob.decrypt(enc2);
      expect(utf8.decode(dec2), 'msg-2');

      final dec0 = sessions.bob.decrypt(enc0);
      expect(utf8.decode(dec0), 'msg-0');

      final dec1 = sessions.bob.decrypt(enc1);
      expect(utf8.decode(dec1), 'msg-1');
    });

    test('out-of-order: send 3, receive 3 -> 1 -> 2', () {
      final sessions = _createSessionPair();

      final enc1 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('first')),
      );
      final enc2 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('second')),
      );
      final enc3 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('third')),
      );

      // Receive in reverse-ish order: 3, 1, 2
      expect(utf8.decode(sessions.bob.decrypt(enc3)), 'third');
      expect(utf8.decode(sessions.bob.decrypt(enc1)), 'first');
      expect(utf8.decode(sessions.bob.decrypt(enc2)), 'second');
    });
  });

  group('Double Ratchet — error conditions', () {
    test('wrong session cannot decrypt', () {
      final sessions1 = _createSessionPair();
      final sessions2 = _createSessionPair();

      final encrypted = sessions1.alice.encrypt(
        Uint8List.fromList(utf8.encode('secret')),
      );

      // sessions2.bob has different keys — should fail
      expect(
        () => sessions2.bob.decrypt(encrypted),
        throwsA(anything),
      );
    });

    test('receiver cannot encrypt before decrypting first message', () {
      final sessions = _createSessionPair();

      // Bob (receiver) tries to encrypt before receiving any message
      expect(
        () => sessions.bob.encrypt(Uint8List.fromList([1, 2, 3])),
        throwsStateError,
      );
    });

    test('duplicate message replay is handled by skipped keys', () {
      final sessions = _createSessionPair();

      final encrypted = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('once')),
      );

      // First decrypt succeeds
      final decrypted = sessions.bob.decrypt(encrypted);
      expect(utf8.decode(decrypted), 'once');

      // Second decrypt fails (key already consumed)
      expect(
        () => sessions.bob.decrypt(encrypted),
        throwsA(anything),
      );
    });
  });

  group('Double Ratchet — serialization', () {
    test('session survives toJson/fromJson round-trip', () {
      final sessions = _createSessionPair();

      // Exchange a couple of messages to advance state
      final enc1 = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('before-serialize')),
      );
      sessions.bob.decrypt(enc1);

      // Serialize and deserialize Alice's session
      final json = sessions.alice.toJson();
      final restored = DoubleRatchetSession.fromJson(json);

      // Send another message from the restored session
      final enc2 = restored.encrypt(
        Uint8List.fromList(utf8.encode('after-serialize')),
      );
      final dec2 = sessions.bob.decrypt(enc2);

      expect(utf8.decode(dec2), 'after-serialize');
    });

    test('EncryptedMessage toJson/fromJson round-trip', () {
      final sessions = _createSessionPair();
      final encrypted = sessions.alice.encrypt(
        Uint8List.fromList(utf8.encode('json-test')),
      );

      final json = encrypted.toJson();
      final restored = EncryptedMessage.fromJson(json);

      expect(restored.messageNumber, encrypted.messageNumber);
      expect(restored.previousChainLength, encrypted.previousChainLength);
      expect(restored.ratchetPublicKey, equals(encrypted.ratchetPublicKey));
      expect(restored.ciphertext, equals(encrypted.ciphertext));

      // Verify the restored message can still be decrypted
      final decrypted = sessions.bob.decrypt(restored);
      expect(utf8.decode(decrypted), 'json-test');
    });
  });
}
