/// @file        session_archive_test.dart
/// @description SignalProtocolService.archiveSessionsOf() (ported from
///              SnowChat): the sessions with every device of ONE peer are
///              put aside — whatever device id they were made with — a new
///              session can be set up afterwards, what was in flight on the
///              old one still opens, and no other peer is touched.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-23
/// @lastUpdated 2026-11-23
///
/// @functions
///  - main(): the cases above.
///
/// Notes:
///  - For when a peer states that its sessions are gone and the device id it
///    uses now is not known.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'identity_test_support.dart';

Uint8List _bytes(String text) => Uint8List.fromList(utf8.encode(text));

void main() {
  const epoch = 1000;
  late TestParty alice;
  late TestParty bob;
  late TestParty carol;

  Future<void> connect(TestParty from, TestParty to, {int opk = 0}) =>
      from.signal.createSession(
        recipientId: to.peerId,
        deviceId: to.deviceId,
        preKeyBundle: to.bundle(
          binding: to.bindingFor(epoch: epoch),
          accountPublicKey: to.accountPub,
          opkIndex: opk,
        ),
      );

  Future<Map<String, dynamic>> send(
    TestParty from,
    TestParty to,
    String text,
  ) => from.signal.encryptMessage(
    recipientId: to.peerId,
    deviceId: to.deviceId,
    plaintext: _bytes(text),
  );

  Future<String> open(
    TestParty at,
    TestParty from,
    Map<String, dynamic> message,
  ) async => utf8.decode(
    await at.signal.decryptMessage(
      senderId: from.peerId,
      deviceId: from.deviceId,
      ciphertext: message['ciphertext'] as Uint8List,
      messageType: message['messageType'] as int,
      envelopeDeviceId: from.deviceId,
    ),
  );

  setUp(() async {
    alice = await TestParty.create(
      seedByte: 1,
      deviceId: '11111111-1111-4111-8111-111111111111',
    );
    bob = await TestParty.create(
      seedByte: 2,
      deviceId: '22222222-2222-4222-8222-222222222222',
    );
    carol = await TestParty.create(
      seedByte: 3,
      deviceId: '33333333-3333-4333-8333-333333333333',
    );
    for (final p in [alice, bob, carol]) {
      p.signal.setLocalIdentityBinding(p.localBinding(epoch: epoch));
    }
    await connect(alice, bob);
    await connect(alice, carol);
    expect(await open(bob, alice, await send(alice, bob, 'first')), 'first');
    expect(await open(carol, alice, await send(alice, carol, 'first')), 'first');
  });

  test('the sessions with one peer are put aside; the others stay', () async {
    expect(await alice.signal.hasSession(bob.peerId, bob.deviceId), isTrue);
    expect(await alice.signal.archiveSessionsOf(bob.peerId), 1);
    expect(await alice.signal.hasSession(bob.peerId, bob.deviceId), isFalse);
    expect(await alice.signal.hasSession(carol.peerId, carol.deviceId), isTrue);
    expect(await open(carol, alice, await send(alice, carol, 'still')), 'still');
    // Nothing left to put aside.
    expect(await alice.signal.archiveSessionsOf(bob.peerId), 0);
    expect(await alice.signal.archiveSessionsOf('snow${'0' * 32}'), 0);
  });

  test('a new session is set up afterwards, and what was in flight on the '
      'old one still opens', () async {
    final inFlight = await send(bob, alice, 'sent before');
    await alice.signal.archiveSessionsOf(bob.peerId);

    await connect(alice, bob, opk: 1);
    final fresh = await send(alice, bob, 'on the new session');
    expect(fresh['messageType'], 2); // a prekey message: a new session
    expect(await open(bob, alice, fresh), 'on the new session');
    expect(await open(alice, bob, inFlight), 'sent before');
    expect(await open(alice, bob, await send(bob, alice, 'answer')), 'answer');
  });

  test('whatever device the sessions were with', () async {
    // The peer was reached under another device id before.
    const other = '44444444-4444-4444-8444-444444444444';
    await alice.signal.createSession(
      recipientId: bob.peerId,
      deviceId: other,
      preKeyBundle: bob.bundle(
        binding: bob.bindingFor(epoch: epoch + 1, deviceIdOverride: other),
        accountPublicKey: bob.accountPub,
        opkIndex: 1,
      ),
    );
    expect(await alice.signal.hasSession(bob.peerId, other), isTrue);
    expect(await alice.signal.archiveSessionsOf(bob.peerId), 2);
    expect(await alice.signal.hasSession(bob.peerId, other), isFalse);
    expect(await alice.signal.hasSession(bob.peerId, bob.deviceId), isFalse);
  });
}
