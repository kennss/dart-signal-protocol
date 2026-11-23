/// @file        verified_identity_store_test.dart
/// @description VerifiedIdentityStore policy over the in-memory reference
///              implementation: latch monotonicity and survival across
///              remove(), out-of-band account-key pinning, server account-key
///              remembering (only for a peer with no record), and the strict
///              record codec (corrupt record treated as absent while the
///              latch holds; an unbound record keeps only its account key).
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-23 (legacy TOFU removed: no pending change, legacy pin import or IK
///              seeding to test; pinFromInviteLink -> pinAccountKey; unbound records drop unproven
///              keys). Earlier 2026-11-10
///
/// @functions
///  - main(): store latch / pin / codec tests
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

const _peerA = 'snow0123456789abcdef0123456789abcdef';
const _dev = '3f2a9c1e-5b7d-4e8a-9c21-7d4e5f6a8b90';

Uint8List _key(int b) => Uint8List.fromList(List.filled(32, b));

void main() {
  group('latch', () {
    test('monotonic; remove() drops the record but keeps the latch', () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.put(VerifiedIdentityRecord(
          peerId: _peerA, accountPublicKey: _key(1), updatedAt: 1));
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

    test('an account-key pin requires a key that derives the id, and latches',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      expect(await store.pinAccountKey(_peerA, pub), isFalse);
      expect(await store.latchedEpoch(_peerA), isNull);
      expect(await store.pinAccountKey(peer, pub), isTrue);
      expect((await store.get(peer))!.accountPublicKey, pub);
      expect(await store.latchedEpoch(peer), 0);
    });

    test('an account-key pin refuses a key conflicting with a recorded one',
        () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.put(VerifiedIdentityRecord(
          peerId: peer, accountPublicKey: _key(9), updatedAt: 1));
      expect(await store.pinAccountKey(peer, pub), isFalse);
      expect((await store.get(peer))!.accountPublicKey, _key(9));
    });

    test('rememberAccountKey stores only a deriving key, only for a peer with '
        'no record, and never latches', () async {
      final store = InMemoryVerifiedIdentityStore();
      await store.rememberAccountKey(_peerA, pub);
      expect(await store.get(_peerA), isNull);
      await store.rememberAccountKey(peer, pub);
      final rec = (await store.get(peer))!;
      expect(rec.accountPublicKey, pub);
      expect(rec.bound, isFalse);
      expect(rec.identityKey, isNull);
      expect(rec.ed25519, isNull);
      expect(await store.latchedEpoch(peer), isNull);

      // An existing record (here one without an account key) is left as it is.
      final other = ed.SigningKey(seed: _key(44));
      final otherPub = Uint8List.fromList(other.verifyKey.toList());
      final otherPeer = const SnowChatIdScheme().deriveId(otherPub);
      await store.put(VerifiedIdentityRecord(peerId: otherPeer, updatedAt: 1));
      await store.rememberAccountKey(otherPeer, otherPub);
      expect((await store.get(otherPeer))!.accountPublicKey, isNull);
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
              {'schema': 1, 'snowId': _peerA, 'bound': true, 'ik': 5}),
          throwsFormatException);
      final full = VerifiedIdentityRecord(
        peerId: _peerA,
        accountPublicKey: _key(7),
        deviceId: _dev,
        epoch: 1,
        identityKey: _key(1),
        ed25519: _key(2),
        bindingSignature: Uint8List(64),
        bound: true,
        updatedAt: 5,
      ).toJson()
        ..remove('deviceId');
      expect(() => VerifiedIdentityRecord.fromJson(full), throwsFormatException);
      expect(
          () => VerifiedIdentityRecord.fromJson({'schema': 2, 'snowId': _peerA}),
          throwsFormatException);
    });

    test('an unbound record keeps only its account key: 0.3.x TOFU keys, '
        'legacy and pending fields are dropped, never trusted', () {
      final rec = VerifiedIdentityRecord.fromJson({
        'schema': 1,
        'snowId': _peerA,
        'accountPub': '07' * 32,
        'deviceId': _dev,
        'ik': base64Encode(_key(1)),
        'ed': base64Encode(_key(2)),
        'edLegacy': true,
        'pendingIk': base64Encode(_key(3)),
        'pendingEd': base64Encode(_key(4)),
        'pendingDeviceId': _dev,
        'bound': false,
        'updatedAt': 5,
      });
      expect(rec.bound, isFalse);
      expect(rec.accountPublicKey, _key(7));
      expect(rec.deviceId, isNull);
      expect(rec.identityKey, isNull);
      expect(rec.ed25519, isNull);
      expect(rec.toJson().keys,
          unorderedEquals(['schema', 'snowId', 'accountPub', 'bound', 'updatedAt']));
    });

    test('a bound record ignores unknown keys on decode', () {
      final json = VerifiedIdentityRecord(
        peerId: _peerA,
        accountPublicKey: _key(7),
        deviceId: _dev,
        epoch: 12,
        identityKey: _key(1),
        ed25519: _key(2),
        bindingSignature: Uint8List.fromList(List.filled(64, 3)),
        bound: true,
        updatedAt: 5,
      ).toJson()
        ..['pendingIk'] = base64Encode(_key(9));
      final back = VerifiedIdentityRecord.fromJson(json);
      expect(back.bound, isTrue);
      expect(back.epoch, 12);
      expect(back.toJson().containsKey('pendingIk'), isFalse);
    });
  });
}
