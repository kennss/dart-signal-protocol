/// @file        sealed_sender_tamper_test.dart
/// @description A sealed envelope changed on its way is refused whole
///              (ported from SnowChat, adversarial server). The server holds
///              the envelope between sender and recipient and may flip, cut,
///              extend, splice or replay it. Every one of those must fail to
///              unseal, with the same opaque error.
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
  final serverKey = ed.SigningKey(seed: Uint8List.fromList(List.filled(32, 7)));
  final serverVerifyKey = Uint8List.fromList(serverKey.verifyKey);
  late TestParty sender;
  late X25519KeyPair recipient;
  late Uint8List payload;
  late Uint8List envelope;

  SealedSenderService service() =>
      SealedSenderService(trustedServerKeys: [serverVerifyKey]);

  setUp(() async {
    sender = await TestParty.create(
      seedByte: 2,
      deviceId: '22222222-2222-4222-8222-222222222222',
    );
    recipient = X25519KeyPair.generate();
    final random = Random.secure();
    payload =
        Uint8List.fromList(List.generate(180, (_) => random.nextInt(256)));
    envelope = service().seal(
      recipientIdentityPubKey: recipient.publicKey,
      drCiphertext: payload,
      certificate: testSenderCertificate(serverKey, sender),
      messageContext: sealedType1to1,
    );
  });

  UnsealedMessage open(Uint8List bytes, {SealedSenderService? by}) =>
      (by ?? service()).unseal(
        myIdentityPrivateKey: recipient.privateKey,
        myIdentityPublicKey: recipient.publicKey,
        sealedEnvelope: bytes,
      );

  Matcher rejected() => throwsA(isA<StateError>()
      .having((e) => e.message, 'message', 'Sealed message rejected'));

  test('the envelope as sent opens, with its sender and its payload', () {
    final opened = open(envelope);
    expect(opened.senderSnowchatId, sender.peerId);
    expect(opened.senderDeviceId, sender.deviceId);
    expect(opened.senderIdentityKey, sender.identityKey);
    expect(opened.drCiphertext, payload);
  });

  test(
      'one flipped bit anywhere in it — version, ephemeral key, box, '
      'certificate, payload, padding — and it does not open', () {
    for (var i = 0; i < envelope.length; i++) {
      final changed = Uint8List.fromList(envelope)..[i] ^= 0x01;
      expect(() => open(changed), rejected(), reason: 'byte $i');
    }
  });

  test(
      'cut short, extended, or with its box swapped onto another ephemeral '
      'key, it does not open', () {
    expect(() => open(envelope.sublist(0, envelope.length - 1)), rejected());
    expect(() => open(Uint8List.fromList([...envelope, 0])), rejected());
    final other = service().seal(
      recipientIdentityPubKey: recipient.publicKey,
      drCiphertext: payload,
      certificate: testSenderCertificate(serverKey, sender),
      messageContext: sealedType1to1,
    );
    final spliced = Uint8List.fromList(envelope)
      ..setRange(1, 33, other.sublist(1, 33));
    expect(() => open(spliced), rejected());
  });

  test('the same envelope delivered twice opens once', () {
    final s = service();
    open(envelope, by: s);
    expect(() => open(envelope, by: s), rejected());
  });

  test('sealed for someone else, it does not open here', () {
    final elsewhere = service().seal(
      recipientIdentityPubKey: X25519KeyPair.generate().publicKey,
      drCiphertext: payload,
      certificate: testSenderCertificate(serverKey, sender),
      messageContext: sealedType1to1,
    );
    expect(() => open(elsewhere), rejected());
  });
}
