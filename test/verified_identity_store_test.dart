/// @file        verified_identity_store_test.dart
/// @description VerifiedIdentityStore policy over the in-memory reference
///              implementation: latch monotonicity and survival across
///              remove(), invite-link pinning, server account-key
///              remembering, pending-change re-verification, legacy pin
///              import, one-time IK seeding, and the strict record codec
///              (corrupt record treated as absent while the latch holds).
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-10
///
/// @functions
///  - main(): store latch / pin / seeding / codec tests
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

const _peerA = 'snow0123456789abcdef0123456789abcdef';
const _peerB = 'snowfedcba9876543210fedcba9876543210';
const _dev = '3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90';

Uint8List _key(int b) => Uint8List.fromList(List.filled(32, b));

void main() {
  group('latch', () {
    test('monotonic; remove() drops the record but keeps the latch', () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.put(VerifiedIdentityRecord(
          peerId: _peerA, identityKey: _key(1), updatedAt: 1));
      await store.raiseLatch(_peerA, 50);
      await store.raiseLatch(_peerA, 10); // never lowers
      expect(await store.latchedEpoch(_peerA), 50);
      await store.remove(_peerA);
      expect(await store.get(_peerA), isNull);
      expect(await store.latchedEpoch(_peerA), 50);
    });

    test('corrupt record is treated as absent but the latch still holds',
        () async {
      final store = InMemoryVerifiedIdentityStore()
        ..putRawRecordForTesting(_peerA, '{not json');
      await store.raiseLatch(_peerA, 123);
      expect(await store.get(_peerA), isNull);
      expect(await store.latchedEpoch(_peerA), 123);
    });
  });

  group('account keys', () {
    final sk = ed.SigningKey(seed: _key(33));
    final pub = Uint8List.fromList(sk.verifyKey.toList());
    final peer = const SnowChatIdScheme().deriveId(pub);

    test('invite-link pin requires a key that derives the id, and latches',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      expect(await store.pinFromInviteLink(_peerA, pub), isFalse);
      expect(await store.latchedEpoch(_peerA), isNull);
      expect(await store.pinFromInviteLink(peer, pub), isTrue);
      expect((await store.get(peer))!.accountPublicKey, pub);
      expect(await store.latchedEpoch(peer), 0);
    });

    test('invite-link pin refuses a key conflicting with a recorded one',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.put(VerifiedIdentityRecord(
          peerId: peer, accountPublicKey: _key(9), updatedAt: 1));
      expect(await store.pinFromInviteLink(peer, pub), isFalse);
    });

    test('rememberAccountKey stores only a deriving key and never latches',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.rememberAccountKey(_peerA, pub);
      expect(await store.get(_peerA), isNull);
      await store.rememberAccountKey(peer, pub);
      expect((await store.get(peer))!.accountPublicKey, pub);
      expect(await store.latchedEpoch(peer), isNull);
    });
  });

  group('pending change + legacy import + seeding', () {
    test('acceptPendingChange adopts the parked keys and clears the block',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.put(VerifiedIdentityRecord(
        peerId: _peerA,
        deviceId: _dev,
        identityKey: _key(1),
        ed25519: _key(2),
        updatedAt: 1,
        pendingIdentityKey: _key(3),
        pendingEd25519: _key(4),
        pendingDeviceId: 'bbbbbbbb-2222-4222-8222-222222222222',
      ));
      expect(await store.acceptPendingChange(_peerA), isTrue);
      final rec = (await store.get(_peerA))!;
      expect(rec.identityKey, _key(3));
      expect(rec.ed25519, _key(4));
      expect(rec.hasPendingChange, isFalse);
      expect(await store.acceptPendingChange(_peerA), isFalse);
    });

    test('importLegacyPin writes a legacy-sourced record, never overwrites',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.importLegacyPin(peerId: _peerA, deviceId: _dev, ed25519: _key(5));
      final rec = (await store.get(_peerA))!;
      expect(rec.edLegacySourced, isTrue);
      expect(rec.deviceId, _dev);
      await store.importLegacyPin(peerId: _peerA, ed25519: _key(6));
      expect((await store.get(_peerA))!.ed25519, _key(5));
    });

    test('IK seeding fills unbound records once and is not repeated',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.put(
          VerifiedIdentityRecord(peerId: _peerA, ed25519: _key(1), updatedAt: 1));
      await store.seedLegacyIdentityKeys(
          {_peerA: _key(2), _peerB: _key(3), 'not-an-id': _key(4)},
          deviceIds: {_peerB: _dev});
      expect((await store.get(_peerA))!.identityKey, _key(2));
      expect((await store.get(_peerB))!.identityKey, _key(3));
      expect((await store.get(_peerB))!.deviceId, _dev);
      expect(await store.get('not-an-id'), isNull);

      await store.remove(_peerB);
      await store.seedLegacyIdentityKeys({_peerB: _key(3)});
      expect(await store.get(_peerB), isNull,
          reason: 'seeding is one-time: a removed record stays removed');
    });
  });

  group('record codec', () {
    test('round-trips every field; snowId key kept for compatibility', () {
      final rec = VerifiedIdentityRecord(
        peerId: _peerA,
        accountPublicKey: _key(7),
        deviceId: _dev,
        epoch: 99,
        identityKey: _key(1),
        ed25519: _key(2),
        bindingSignature: Uint8List(64),
        bound: true,
        updatedAt: 5,
      );
      final json = rec.toJson();
      expect(json['snowId'], _peerA);
      final back = VerifiedIdentityRecord.fromJson(
          Map<String, dynamic>.from(jsonDecode(jsonEncode(json)) as Map));
      expect(back.bound, isTrue);
      expect(back.epoch, 99);
      expect(back.accountPublicKey, _key(7));
      expect(back.bindingSignature, Uint8List(64));
    });

    test('bound record missing fields / bad types are rejected', () {
      expect(
          () => VerifiedIdentityRecord.fromJson(
              {'schema': 1, 'snowId': _peerA, 'bound': true}),
          throwsFormatException);
      expect(
          () => VerifiedIdentityRecord.fromJson(
              {'schema': 1, 'snowId': _peerA, 'ik': 5}),
          throwsFormatException);
      expect(
          () => VerifiedIdentityRecord.fromJson({'schema': 2, 'snowId': _peerA}),
          throwsFormatException);
    });
  });
}
