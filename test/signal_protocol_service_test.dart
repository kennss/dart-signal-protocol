/// @file        signal_protocol_service_test.dart
/// @description Regression tests for SignalProtocolService behavior backported from SnowChat in 0.3.0: persistent PreKey (receive-first bootstrap), type-2 archive fallback, one-time prekey fail-loud, X3DH 4DH/5DH domain separation, sealed messageType recovery + Sealed Sender Step 9, signed-prekey self-heal accessors, atomic saveSessionStore, MessageSendLog aliases
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - _newPeer(): Create a SignalProtocolService with identity + SPK #1 (+ optional OPKs)
///  - _bundleWithOpk(): Prekey bundle that also advertises one one-time prekey
///  - _send() / _recv(): Thin encrypt/decrypt wrappers for readability
///  - _sealedCert(): Build a server-signed SenderCertificate for Sealed Sender tests
///  - Persistent PreKey: type-2 until first inbound decrypt; receive-first heal when the first type-2 is lost; survives store reload
///  - Type-2 archive fallback / OPK fail-loud: re-sent type-2 after reset
///  - X3DH domain separation: known-answer check of the 4DH/5DH HKDF info
///  - resolveSealedMessageType: prekey/normal detection, Step 9 mismatch, malformed input, full seal->unseal->decrypt flow
///  - SPK self-heal accessors: signedPreKeyPublicKey / hasAnySignedPreKey
///  - saveSessionStore: returns false without key, true + atomic (no temp leftovers) with key
///  - MessageSendLog.addAlias: lookup by alias, no-op cases
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

const _dev = 'device-1';

Future<SignalProtocolService> _newPeer({int opkStart = 0, int opkCount = 0}) async {
  final s = SignalProtocolService();
  await s.generateIdentityKeyPair();
  await s.generateSignedPreKey(1);
  if (opkCount > 0) await s.generateOneTimePreKeys(opkStart, opkCount);
  return s;
}

/// Bob's bundle plus one advertised one-time prekey (forces the 5-DH path).
Future<Map<String, dynamic>> _bundleWithOpk(SignalProtocolService bob) async {
  final bundle = await bob.getPreKeyBundle();
  final opks = await bob.generateOneTimePreKeys(500, 1);
  bundle['oneTimePreKey'] = opks.first;
  return bundle;
}

Future<Map<String, dynamic>> _send(
  SignalProtocolService from,
  String to,
  String text,
) =>
    from.encryptMessage(
      recipientId: to,
      deviceId: _dev,
      plaintext: Uint8List.fromList(utf8.encode(text)),
    );

Future<String> _recv(
  SignalProtocolService to,
  String from,
  Map<String, dynamic> enc, {
  Uint8List? senderEd25519,
}) async {
  final pt = await to.decryptMessage(
    senderId: from,
    deviceId: _dev,
    ciphertext: enc['ciphertext'] as Uint8List,
    messageType: enc['messageType'] as int,
    senderIdentityKeyEd25519: senderEd25519,
  );
  return utf8.decode(pt);
}

/// Server-signed Sender Certificate binding [identityKey] to the sender.
SenderCertificate _sealedCert(ed.SigningKey serverKey, Uint8List identityKey) {
  const snowchatId = 'snow05a3b2c4d6e8f0112233445566778899';
  const deviceId = '12345678-1234-1234-1234-123456789012';
  final expiry = DateTime.now().millisecondsSinceEpoch + 3600 * 1000;
  final buffer = Uint8List(113);
  var o = 0;
  buffer[o] = 0x01;
  o += 1;
  buffer.setAll(o, snowchatId.codeUnits);
  o += 36;
  buffer.setAll(o, deviceId.codeUnits);
  o += 36;
  buffer.setAll(o, identityKey);
  o += 32;
  for (var i = 0; i < 8; i++) {
    buffer[o + i] = (expiry >> (56 - 8 * i)) & 0xFF;
  }
  final signed = serverKey.sign(buffer);
  return SenderCertificate(
    version: 0x01,
    senderSnowchatId: snowchatId,
    senderDeviceId: deviceId,
    senderIdentityKey: identityKey,
    expiryMs: expiry,
    serverSignature:
        Uint8List.fromList(signed.sublist(0, ed.Signature.signatureLength)),
  );
}

void main() {
  group('Persistent PreKey (receive-first bootstrap)', () {
    test('initiator keeps emitting type-2 until it decrypts an inbound message',
        () async {
      final alice = await _newPeer();
      final bob = await _newPeer();
      await alice.createSession(
          recipientId: 'bob',
          deviceId: _dev,
          preKeyBundle: await bob.getPreKeyBundle());

      final m1 = await _send(alice, 'bob', 'one');
      final m2 = await _send(alice, 'bob', 'two');
      final m3 = await _send(alice, 'bob', 'three');
      expect([m1, m2, m3].map((m) => m['messageType']), everyElement(2));

      // Bob receives all three; only the first runs X3DH, the rest decrypt
      // on the existing session (the one-time prekey is consumed once).
      expect(await _recv(bob, 'alice', m1, senderEd25519: alice.verifyKey),
          'one');
      expect(await _recv(bob, 'alice', m2, senderEd25519: alice.verifyKey),
          'two');
      expect(await _recv(bob, 'alice', m3, senderEd25519: alice.verifyKey),
          'three');

      // Bob's reply is a normal message (Bob is the responder).
      final r1 = await _send(bob, 'alice', 'reply');
      expect(r1['messageType'], 1);
      expect(await _recv(alice, 'bob', r1), 'reply');

      // Alice decrypted an inbound message → pending PreKey state retired.
      final m4 = await _send(alice, 'bob', 'four');
      expect(m4['messageType'], 1);
      expect(await _recv(bob, 'alice', m4), 'four');
    });

    test('receive-first peer bootstraps even when the first type-2 is lost',
        () async {
      final alice = await _newPeer();
      final bob = await _newPeer();
      await alice.createSession(
          recipientId: 'bob',
          deviceId: _dev,
          preKeyBundle: await _bundleWithOpk(bob));

      await _send(alice, 'bob', 'lost in transit'); // never delivered
      final m2 = await _send(alice, 'bob', 'second');
      expect(m2['messageType'], 2);

      // Pre-0.3.0 m2 was type-1 and Bob (no session) could never decrypt it.
      expect(await _recv(bob, 'alice', m2, senderEd25519: alice.verifyKey),
          'second');
      final r = await _send(bob, 'alice', 'hi');
      expect(await _recv(alice, 'bob', r), 'hi');
    });

    test('pending PreKey state survives a session-store save/load', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_prekey_');
      addTearDown(() => dir.delete(recursive: true));
      final path = '${dir.path}/store.bin';
      final key = Uint8List.fromList(List.generate(32, (i) => i));

      final alice = await _newPeer();
      final bob = await _newPeer();
      await alice.createSession(
          recipientId: 'bob',
          deviceId: _dev,
          preKeyBundle: await bob.getPreKeyBundle());
      await _send(alice, 'bob', 'lost'); // first type-2 lost
      alice.setStoreEncryptionKey(key);
      expect(await alice.saveSessionStore(path), isTrue);

      final restored = SignalProtocolService()..setStoreEncryptionKey(key);
      await restored.loadSessionStore(path);
      final m = await _send(restored, 'bob', 'after restart');
      expect(m['messageType'], 2);
      expect(await _recv(bob, 'alice', m, senderEd25519: alice.verifyKey),
          'after restart');
    });
  });

  group('Type-2 re-send after reset', () {
    test('archived session decrypts a re-sent type-2 whose OPK is consumed',
        () async {
      final alice = await _newPeer();
      final bob = await _newPeer();
      await alice.createSession(
          recipientId: 'bob',
          deviceId: _dev,
          preKeyBundle: await _bundleWithOpk(bob));

      final m1 = await _send(alice, 'bob', 'first');
      expect(await _recv(bob, 'alice', m1, senderEd25519: alice.verifyKey),
          'first');
      await bob.archiveSession('alice', _dev);

      // Alice has not heard back, so m2 still names the consumed OPK.
      // _receiveSession fails (OPK gone) → the archive fallback recovers it.
      final m2 = await _send(alice, 'bob', 'second');
      expect(m2['messageType'], 2);
      expect(await _recv(bob, 'alice', m2, senderEd25519: alice.verifyKey),
          'second');
      expect(bob.archiveDecryptDirty, isTrue);
    });

    test('missing sender-named one-time prekey fails loud (no 4-DH fallthrough)',
        () async {
      final alice = await _newPeer();
      final bob = await _newPeer();
      await alice.createSession(
          recipientId: 'bob',
          deviceId: _dev,
          preKeyBundle: await _bundleWithOpk(bob));

      final m1 = await _send(alice, 'bob', 'first');
      await _recv(bob, 'alice', m1, senderEd25519: alice.verifyKey);
      await bob.deleteSession('alice', _dev); // hard wipe, nothing archived

      final m2 = await _send(alice, 'bob', 'second');
      await expectLater(
        _recv(bob, 'alice', m2, senderEd25519: alice.verifyKey),
        throwsA(isA<SignalProtocolException>().having(
            (e) => e.message, 'message', contains('One-time prekey #500'))),
      );
      expect(await bob.hasSession('alice', _dev), isFalse,
          reason: 'no poisoned session may be installed');
    });
  });

  group('X3DH HKDF domain separation', () {
    Uint8List concat(List<Uint8List> parts) {
      final out = BytesBuilder();
      out.add(Uint8List(32)..fillRange(0, 32, 0xFF));
      for (final p in parts) {
        out.add(p);
      }
      return out.toBytes();
    }

    test('4-DH and 5-DH derive with distinct info strings', () {
      final aliceIK = X25519KeyPair.generate();
      final aliceEK = X25519KeyPair.generate();
      final bobIK = X25519KeyPair.generate();
      final bobSPK = X25519KeyPair.generate();
      final bobOPK = X25519KeyPair.generate();

      final dh1 = x25519Dh(bobSPK.privateKey, aliceIK.publicKey);
      final dh2 = x25519Dh(bobIK.privateKey, aliceEK.publicKey);
      final dh3 = x25519Dh(bobSPK.privateKey, aliceEK.publicKey);
      final dh4 = x25519Dh(bobOPK.privateKey, aliceEK.publicKey);

      Uint8List expected(List<Uint8List> dhs, String info) => hkdfDerive(
            ikm: concat(dhs),
            salt: Uint8List(32),
            info: Uint8List.fromList(utf8.encode(info)),
            length: 32,
          );

      final sk4 = X3DH.receiveSession(
        identityKeyPrivate: bobIK.privateKey,
        signedPreKeyPrivate: bobSPK.privateKey,
        remoteIdentityKey: aliceIK.publicKey,
        remoteEphemeralKey: aliceEK.publicKey,
      );
      expect(sk4, expected([dh1, dh2, dh3], 'SnowChat_X3DH_4DH'));
      expect(sk4, isNot(expected([dh1, dh2, dh3], 'SnowChat_X3DH')));

      final sk5 = X3DH.receiveSession(
        identityKeyPrivate: bobIK.privateKey,
        signedPreKeyPrivate: bobSPK.privateKey,
        oneTimePreKeyPrivate: bobOPK.privateKey,
        remoteIdentityKey: aliceIK.publicKey,
        remoteEphemeralKey: aliceEK.publicKey,
      );
      expect(sk5, expected([dh1, dh2, dh3, dh4], 'SnowChat_X3DH_5DH'));
      expect(sk5, isNot(expected([dh1, dh2, dh3, dh4], 'SnowChat_X3DH')));
    });
  });

  group('resolveSealedMessageType', () {
    late SignalProtocolService alice;
    late SignalProtocolService bob;

    setUp(() async {
      alice = await _newPeer();
      bob = await _newPeer();
      await alice.createSession(
          recipientId: 'bob',
          deviceId: _dev,
          preKeyBundle: await bob.getPreKeyBundle());
    });

    test('prekey ciphertext with matching certificate identity → 2', () async {
      final m = await _send(alice, 'bob', 'x');
      expect(
        bob.resolveSealedMessageType(
            m['ciphertext'] as Uint8List, alice.identityPublicKey!),
        2,
      );
    });

    test('prekey ciphertext with a different certificate identity → rejected',
        () async {
      final m = await _send(alice, 'bob', 'x');
      final other = X25519KeyPair.generate().publicKey;
      expect(
        () => bob.resolveSealedMessageType(m['ciphertext'] as Uint8List, other),
        throwsA(isA<StateError>()
            .having((e) => e.message, 'message', 'Sealed message rejected')),
      );
      // Length mismatch is rejected the same way.
      expect(
        () => bob.resolveSealedMessageType(
            m['ciphertext'] as Uint8List, Uint8List(16)),
        throwsStateError,
      );
    });

    test('normal ciphertext → 1', () async {
      final m1 = await _send(alice, 'bob', 'boot');
      await _recv(bob, 'alice', m1, senderEd25519: alice.verifyKey);
      final r = await _send(bob, 'alice', 'normal');
      expect(r['messageType'], 1);
      expect(
        alice.resolveSealedMessageType(
            r['ciphertext'] as Uint8List, bob.identityPublicKey!),
        1,
      );
    });

    test('non-JSON / partial headers degrade to 1; malformed prekey hex throws',
        () {
      final key = alice.identityPublicKey!;
      expect(bob.resolveSealedMessageType(Uint8List.fromList([0xFF, 0x00]), key),
          1);
      expect(
          bob.resolveSealedMessageType(
              Uint8List.fromList(utf8.encode('[1,2,3]')), key),
          1);
      expect(
          bob.resolveSealedMessageType(
              Uint8List.fromList(utf8.encode('{"identityKey":"ab"}')), key),
          1);
      expect(
        () => bob.resolveSealedMessageType(
            Uint8List.fromList(
                utf8.encode('{"identityKey":"zz","ephemeralKey":"00"}')),
            key),
        throwsFormatException,
      );
    });

    test('first-contact sealed message: seal → unseal → resolve → decrypt',
        () async {
      final serverKey = ed.SigningKey.generate();
      final serverVerify = Uint8List.fromList(serverKey.verifyKey.toList());
      final sealer = SealedSenderService(trustedServerKeys: [serverVerify]);
      final unsealer = SealedSenderService(trustedServerKeys: [serverVerify]);

      final m = await _send(alice, 'bob', 'hello new contact');
      final envelope = sealer.seal(
        recipientIdentityPubKey: bob.identityPublicKey!,
        drCiphertext: m['ciphertext'] as Uint8List,
        certificate: _sealedCert(serverKey, alice.identityPublicKey!),
        messageContext: sealedType1to1,
      );
      final unsealed = unsealer.unseal(
        myIdentityPrivateKey: bob.identityPrivateKey!,
        myIdentityPublicKey: bob.identityPublicKey!,
        sealedEnvelope: envelope,
      );

      // The transport carries no messageType; recover it from the ciphertext.
      final type = bob.resolveSealedMessageType(
          unsealed.drCiphertext, unsealed.senderIdentityKey);
      expect(type, 2);
      final pt = await bob.decryptMessage(
        senderId: 'alice',
        deviceId: _dev,
        ciphertext: unsealed.drCiphertext,
        messageType: type,
        senderIdentityKeyEd25519: alice.verifyKey,
      );
      expect(utf8.decode(pt), 'hello new contact');
    });
  });

  group('Signed-prekey self-heal accessors', () {
    test('signedPreKeyPublicKey matches the advertised bundle', () async {
      final s = SignalProtocolService();
      await s.generateIdentityKeyPair();
      expect(s.hasAnySignedPreKey, isFalse);

      await s.generateSignedPreKey(7);
      expect(s.hasAnySignedPreKey, isTrue);
      final advertised = (await s.getPreKeyBundle())['signedPreKey']
          as Map<String, dynamic>;
      expect(advertised['keyId'], 7);
      expect(s.signedPreKeyPublicKey(7), advertised['publicKey']);
      expect(s.signedPreKeyPublicKey(8), isNull);
    });

    test('store lacking the advertised SPK is detectable before X3DH fails',
        () async {
      final bob = await _newPeer();
      final advertised = (await bob.getPreKeyBundle())['signedPreKey']
          as Map<String, dynamic>;

      // Bob lost his store but kept his identity (e.g. restore from seed).
      final bobAfterLoss = SignalProtocolService()
        ..setIdentityKeyPair(bob.identityPublicKey!, bob.identityPrivateKey!);
      expect(bobAfterLoss.signedPreKeyPublicKey(advertised['keyId'] as int),
          isNull,
          reason: 'caller must re-arm (generate + persist + re-advertise)');
    });
  });

  group('saveSessionStore', () {
    test('returns false without a store key and writes nothing', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_store_');
      addTearDown(() => dir.delete(recursive: true));
      final s = await _newPeer();
      final path = '${dir.path}/store.bin';
      expect(await s.saveSessionStore(path), isFalse);
      expect(File(path).existsSync(), isFalse);
    });

    test('returns true, round-trips, and leaves no temp files', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_store_');
      addTearDown(() => dir.delete(recursive: true));
      final key = Uint8List.fromList(List.generate(32, (i) => 255 - i));
      final s = await _newPeer()
        ..setStoreEncryptionKey(key);
      final path = '${dir.path}/store.bin';

      final results = await Future.wait(
          List.generate(4, (_) => s.saveSessionStore(path)));
      expect(results, everyElement(isTrue));
      expect(dir.listSync().map((e) => e.path), [path]);

      final restored = SignalProtocolService()..setStoreEncryptionKey(key);
      await restored.loadSessionStore(path);
      expect(restored.signedPreKeyPublicKey(1), s.signedPreKeyPublicKey(1));
    });
  });

  group('MessageSendLog.addAlias', () {
    test('alias resolves to the same entry', () {
      final log = MessageSendLog();
      final pt = Uint8List.fromList(utf8.encode('payload'));
      log.record('client-1', pt, conversationId: 'conv-1');
      log.addAlias('client-1', 'server-1');
      expect(log.lookup('server-1'), pt);
      expect(log.conversationIdFor('server-1'), 'conv-1');
      expect(log.isGroupMessage('server-1'), isFalse);
    });

    test('no-op for unknown primary or identical ids', () {
      final log = MessageSendLog();
      log.addAlias('missing', 'server-x');
      expect(log.lookup('server-x'), isNull);
      log.record('same', Uint8List.fromList([1]), conversationId: 'c');
      log.addAlias('same', 'same');
      expect(log.lookup('same'), [1]);
    });
  });
}
