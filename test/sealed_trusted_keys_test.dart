/// @file        sealed_trusted_keys_test.dart
/// @description Pinned Sealed Sender server keys (ported from SnowChat
///              SC-06 / A-3). A certificate signed by a key outside the
///              trusted list does not open; during a rotation a certificate
///              signed by either listed key opens; a service cannot be built
///              with no key or with a key that is not a strict Ed25519 key;
///              the caller's list is copied, so changing it later changes
///              nothing.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-23
/// @lastUpdated 2026-11-23
///
/// @functions
///  - main(): the cases above
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;
import 'package:test/test.dart';

import 'identity_test_support.dart';

void main() {
  ed.SigningKey key(int b) =>
      ed.SigningKey(seed: Uint8List.fromList(List.filled(32, b)));
  Uint8List pub(ed.SigningKey k) => Uint8List.fromList(k.verifyKey);

  final current = key(7);
  final next = key(8);
  final rogue = key(9);
  late TestParty sender;
  late X25519KeyPair recipient;
  late Uint8List payload;

  setUp(() async {
    sender = await TestParty.create(
      seedByte: 2,
      deviceId: '22222222-2222-4222-8222-222222222222',
    );
    recipient = X25519KeyPair.generate();
    final random = Random.secure();
    payload = Uint8List.fromList(List.generate(64, (_) => random.nextInt(256)));
  });

  Uint8List sealBy(ed.SigningKey server) =>
      SealedSenderService(trustedServerKeys: [pub(server)]).seal(
        recipientIdentityPubKey: recipient.publicKey,
        drCiphertext: payload,
        certificate: testSenderCertificate(server, sender),
        messageContext: sealedType1to1,
      );

  UnsealedMessage openWith(List<ed.SigningKey> trusted, Uint8List envelope) =>
      SealedSenderService(trustedServerKeys: trusted.map(pub).toList()).unseal(
        myIdentityPrivateKey: recipient.privateKey,
        myIdentityPublicKey: recipient.publicKey,
        sealedEnvelope: envelope,
      );

  test('a certificate signed by a key outside the list does not open', () {
    expect(() => openWith([current], sealBy(rogue)), throwsStateError);
    expect(() => openWith([current, next], sealBy(rogue)), throwsStateError);
  });

  test('during a rotation, a certificate signed by either listed key opens',
      () {
    expect(openWith([current, next], sealBy(current)).senderSnowchatId,
        sender.peerId);
    expect(openWith([current, next], sealBy(next)).senderSnowchatId,
        sender.peerId);
  });

  test('a service with no trusted key cannot be built', () {
    expect(() => SealedSenderService(trustedServerKeys: const []),
        throwsArgumentError);
  });

  test('a service with a key that is not a strict Ed25519 key cannot be built',
      () {
    final smallOrder = Uint8List(32)..[0] = 1; // the identity point
    for (final bad in [Uint8List(31), Uint8List(33), smallOrder]) {
      expect(() => SealedSenderService(trustedServerKeys: [pub(current), bad]),
          throwsArgumentError);
    }
  });

  test(
      'the trusted list is copied: changing the caller list or key bytes '
      'afterwards changes nothing', () {
    final keys = [pub(current)];
    final service = SealedSenderService(trustedServerKeys: keys);
    keys[0][0] ^= 0xff;
    keys.add(pub(rogue));
    final opened = service.unseal(
      myIdentityPrivateKey: recipient.privateKey,
      myIdentityPublicKey: recipient.publicKey,
      sealedEnvelope: sealBy(current),
    );
    expect(opened.senderSnowchatId, sender.peerId);
    expect(
        () => service.unseal(
              myIdentityPrivateKey: recipient.privateKey,
              myIdentityPublicKey: recipient.publicKey,
              sealedEnvelope: sealBy(rogue),
            ),
        throwsStateError);
    expect(() => service.trustedServerKeys.add(pub(rogue)),
        throwsUnsupportedError);
  });
}
