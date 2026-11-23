/// @file        signal_protocol_service_test.dart
/// @description Regression tests for SignalProtocolService behavior backported from SnowChat in 0.3.0: persistent PreKey (receive-first bootstrap), type-2 archive fallback, one-time prekey fail-loud, X3DH 4DH/5DH domain separation, sealed messageType recovery + Sealed Sender Step 9, signed-prekey self-heal accessors, atomic saveSessionStore, MessageSendLog aliases
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-23 (bindings mandatory: every peer is a bound TestParty — the sender is
///              verified from the binding embedded in its PreKey messages, not from a server-supplied
///              Ed25519 key). Earlier 2026-11-10
///
/// @functions
///  - _peer(): A bound TestParty (account key + Signal identity + store) with its binding installed
///  - _connect(): Initiator session from the responder's bound bundle (optionally with a one-time prekey)
///  - _send() / _recv(): Thin encrypt/decrypt wrappers for readability
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

import 'identity_test_support.dart';

const _devA = '0a0a0a0a-0000-4000-8000-00000000000a';
const _devB = '0b0b0b0b-0000-4000-8000-00000000000b';

/// A bound user; its own binding is embedded in its PreKey messages.
Future<TestParty> _peer(int seedByte, String deviceId) async {
  final p = await TestParty.create(seedByte: seedByte, deviceId: deviceId);
  p.signal.setLocalIdentityBinding(p.localBinding(epoch: 1000));
  return p;
}

Future<(TestParty, TestParty)> _aliceBob() async =>
    (await _peer(1, _devA), await _peer(2, _devB));

/// [from] creates a session from [to]'s bound bundle. [withOpk] advertises
/// one-time prekey #1 (the 5-DH path).
Future<void> _connect(TestParty from, TestParty to, {bool withOpk = false}) =>
    from.signal.createSession(
      recipientId: to.peerId,
      deviceId: to.deviceId,
      preKeyBundle: to.bundle(
        binding: to.bindingFor(epoch: 1000),
        accountPublicKey: to.accountPub,
        opkIndex: withOpk ? 0 : null,
      ),
    );

Future<Map<String, dynamic>> _send(TestParty from, TestParty to, String text,
        {SignalProtocolService? via}) =>
    (via ?? from.signal).encryptMessage(
      recipientId: to.peerId,
      deviceId: to.deviceId,
      plaintext: Uint8List.fromList(utf8.encode(text)),
    );

Future<String> _recv(
    TestParty to, TestParty from, Map<String, dynamic> enc) async {
  final pt = await to.signal.decryptMessage(
    senderId: from.peerId,
    deviceId: from.deviceId,
    ciphertext: enc['ciphertext'] as Uint8List,
    messageType: enc['messageType'] as int,
    envelopeDeviceId: from.deviceId,
  );
  return utf8.decode(pt);
}

void main() {
  group('Persistent PreKey (receive-first bootstrap)', () {
    test('initiator keeps emitting type-2 until it decrypts an inbound message',
        () async {
      final (alice, bob) = await _aliceBob();
      await _connect(alice, bob, withOpk: true);

      final m1 = await _send(alice, bob, 'one');
      final m2 = await _send(alice, bob, 'two');
      final m3 = await _send(alice, bob, 'three');
      expect([m1, m2, m3].map((m) => m['messageType']), everyElement(2));

      // Bob receives all three; only the first runs X3DH, the rest decrypt
      // on the existing session (the one-time prekey is consumed once).
      expect(await _recv(bob, alice, m1), 'one');
      expect(await _recv(bob, alice, m2), 'two');
      expect(await _recv(bob, alice, m3), 'three');

      // Bob's reply is a normal message (Bob is the responder).
      final r1 = await _send(bob, alice, 'reply');
      expect(r1['messageType'], 1);
      expect(await _recv(alice, bob, r1), 'reply');

      // Alice decrypted an inbound message → pending PreKey state retired.
      final m4 = await _send(alice, bob, 'four');
      expect(m4['messageType'], 1);
      expect(await _recv(bob, alice, m4), 'four');
    });

    test('receive-first peer bootstraps even when the first type-2 is lost',
        () async {
      final (alice, bob) = await _aliceBob();
      await _connect(alice, bob, withOpk: true);

      await _send(alice, bob, 'lost in transit'); // never delivered
      final m2 = await _send(alice, bob, 'second');
      expect(m2['messageType'], 2);

      // Pre-0.3.0 m2 was type-1 and Bob (no session) could never decrypt it.
      expect(await _recv(bob, alice, m2), 'second');
      final r = await _send(bob, alice, 'hi');
      expect(await _recv(alice, bob, r), 'hi');
    });

    test('pending PreKey state survives a session-store save/load', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_prekey_');
      addTearDown(() => dir.delete(recursive: true));
      final path = '${dir.path}/store.bin';
      final key = Uint8List.fromList(List.generate(32, (i) => i));

      final (alice, bob) = await _aliceBob();
      await _connect(alice, bob);
      await _send(alice, bob, 'lost'); // first type-2 lost
      alice.signal.setStoreEncryptionKey(key);
      expect(await alice.signal.saveSessionStore(path), isTrue);

      final restored = SignalProtocolService(identityStore: alice.store)
        ..setStoreEncryptionKey(key)
        ..setLocalIdentityBinding(alice.localBinding(epoch: 1000));
      await restored.loadSessionStore(path);
      final m = await _send(alice, bob, 'after restart', via: restored);
      expect(m['messageType'], 2);
      expect(await _recv(bob, alice, m), 'after restart');
    });
  });

  group('Type-2 re-send after reset', () {
    test('archived session decrypts a re-sent type-2 whose OPK is consumed',
        () async {
      final (alice, bob) = await _aliceBob();
      await _connect(alice, bob, withOpk: true);

      final m1 = await _send(alice, bob, 'first');
      expect(await _recv(bob, alice, m1), 'first');
      await bob.signal.archiveSession(alice.peerId, _devA);

      // Alice has not heard back, so m2 still names the consumed OPK.
      // _receiveSession fails (OPK gone) → the archive fallback recovers it.
      final m2 = await _send(alice, bob, 'second');
      expect(m2['messageType'], 2);
      expect(await _recv(bob, alice, m2), 'second');
      expect(bob.signal.archiveDecryptDirty, isTrue);
    });

    test('missing sender-named one-time prekey fails loud (no 4-DH fallthrough)',
        () async {
      final (alice, bob) = await _aliceBob();
      await _connect(alice, bob, withOpk: true);
      final opkId = bob.oneTimePreKeys.first['keyId'] as int;

      final m1 = await _send(alice, bob, 'first');
      await _recv(bob, alice, m1);
      await bob.signal.deleteSession(alice.peerId, _devA); // nothing archived

      final m2 = await _send(alice, bob, 'second');
      await expectLater(
        _recv(bob, alice, m2),
        throwsA(isA<SignalProtocolException>().having(
            (e) => e.message, 'message', contains('One-time prekey #$opkId'))),
      );
      expect(await bob.signal.hasSession(alice.peerId, _devA), isFalse,
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
    late TestParty alice;
    late TestParty bob;

    setUp(() async {
      (alice, bob) = await _aliceBob();
      await _connect(alice, bob);
    });

    test('prekey ciphertext with matching certificate identity → 2', () async {
      final m = await _send(alice, bob, 'x');
      expect(
        bob.signal.resolveSealedMessageType(
            m['ciphertext'] as Uint8List, alice.identityKey),
        2,
      );
    });

    test('prekey ciphertext with a different certificate identity → rejected',
        () async {
      final m = await _send(alice, bob, 'x');
      final other = X25519KeyPair.generate().publicKey;
      expect(
        () => bob.signal
            .resolveSealedMessageType(m['ciphertext'] as Uint8List, other),
        throwsA(isA<StateError>()
            .having((e) => e.message, 'message', 'Sealed message rejected')),
      );
      // Length mismatch is rejected the same way.
      expect(
        () => bob.signal.resolveSealedMessageType(
            m['ciphertext'] as Uint8List, Uint8List(16)),
        throwsStateError,
      );
    });

    test('normal ciphertext → 1', () async {
      final m1 = await _send(alice, bob, 'boot');
      await _recv(bob, alice, m1);
      final r = await _send(bob, alice, 'normal');
      expect(r['messageType'], 1);
      expect(
        alice.signal.resolveSealedMessageType(
            r['ciphertext'] as Uint8List, bob.identityKey),
        1,
      );
    });

    test('non-JSON / partial headers degrade to 1; malformed prekey hex throws',
        () {
      final key = alice.identityKey;
      final b = bob.signal;
      expect(b.resolveSealedMessageType(Uint8List.fromList([0xFF, 0x00]), key),
          1);
      expect(
          b.resolveSealedMessageType(
              Uint8List.fromList(utf8.encode('[1,2,3]')), key),
          1);
      expect(
          b.resolveSealedMessageType(
              Uint8List.fromList(utf8.encode('{"identityKey":"ab"}')), key),
          1);
      expect(
        () => b.resolveSealedMessageType(
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

      final m = await _send(alice, bob, 'hello new contact');
      final envelope = sealer.seal(
        recipientIdentityPubKey: bob.identityKey,
        drCiphertext: m['ciphertext'] as Uint8List,
        certificate: testSenderCertificate(serverKey, alice),
        messageContext: sealedType1to1,
      );
      final unsealed = unsealer.unseal(
        myIdentityPrivateKey: bob.signal.identityPrivateKey!,
        myIdentityPublicKey: bob.identityKey,
        sealedEnvelope: envelope,
      );

      // The transport carries no messageType; recover it from the ciphertext.
      final type = bob.signal.resolveSealedMessageType(
          unsealed.drCiphertext, unsealed.senderIdentityKey);
      expect(type, 2);
      // The certificate names the sender and its device; the embedded
      // binding is verified against both before any prekey is used.
      final pt = await bob.signal.decryptMessage(
        senderId: unsealed.senderSnowchatId,
        deviceId: unsealed.senderDeviceId,
        ciphertext: unsealed.drCiphertext,
        messageType: type,
        envelopeDeviceId: unsealed.senderDeviceId,
      );
      expect(utf8.decode(pt), 'hello new contact');
    });
  });

  group('Signed-prekey self-heal accessors', () {
    test('signedPreKeyPublicKey matches the advertised bundle', () async {
      final s =
          SignalProtocolService(identityStore: InMemoryVerifiedIdentityStore());
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
      final bob = await _peer(2, _devB);
      final advertised = bob.preKeyBundle['signedPreKey'] as Map<String, dynamic>;

      // Bob lost his store but kept his identity (e.g. restore from seed).
      final bobAfterLoss = SignalProtocolService(identityStore: bob.store)
        ..setIdentityKeyPair(bob.identityKey, bob.signal.identityPrivateKey!);
      expect(bobAfterLoss.signedPreKeyPublicKey(advertised['keyId'] as int),
          isNull,
          reason: 'caller must re-arm (generate + persist + re-advertise)');
    });
  });

  group('saveSessionStore', () {
    test('returns false without a store key and writes nothing', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_store_');
      addTearDown(() => dir.delete(recursive: true));
      final s = (await _peer(1, _devA)).signal;
      final path = '${dir.path}/store.bin';
      expect(await s.saveSessionStore(path), isFalse);
      expect(File(path).existsSync(), isFalse);
    });

    test('returns true, round-trips, and leaves no temp files', () async {
      final dir = await Directory.systemTemp.createTemp('dsp_store_');
      addTearDown(() => dir.delete(recursive: true));
      final key = Uint8List.fromList(List.generate(32, (i) => 255 - i));
      final s = (await _peer(1, _devA)).signal..setStoreEncryptionKey(key);
      final path = '${dir.path}/store.bin';

      final results = await Future.wait(
          List.generate(4, (_) => s.saveSessionStore(path)));
      expect(results, everyElement(isTrue));
      expect(dir.listSync().map((e) => e.path), [path]);

      final restored =
          SignalProtocolService(identityStore: InMemoryVerifiedIdentityStore())
            ..setStoreEncryptionKey(key);
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
