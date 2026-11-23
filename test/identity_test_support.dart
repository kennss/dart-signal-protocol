/// @file        identity_test_support.dart
/// @description Shared helpers for the Identity Binding v1 tests: a "party"
///              that owns a real account key, a real SignalProtocolService
///              (X3DH / Double Ratchet over pinenacl) and an in-memory
///              VerifiedIdentityStore — no mocks of the crypto under test.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-23 (testSenderCertificate(): a server-signed certificate for a party)
///              Earlier 2026-11-10
///
/// @functions
///  - TestParty.create(): account key + Signal identity + store for one user
///  - TestParty.bindingFor(): sign an Identity Binding v1 with the account key
///  - TestParty.bundle(): a decoded prekey bundle as createSession expects it
///  - TestParty.localBinding(): LocalIdentityBinding for type-2 embedding
///  - testSenderCertificate(): a sender certificate for a party, signed by a test server key
///  - hexBytes(): hex decoding helper
library;

import 'dart:typed_data';

import 'package:dart_signal_protocol/dart_signal_protocol.dart';
import 'package:pinenacl/ed25519.dart' as ed;

Uint8List hexBytes(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String hexLower(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// One user: account key (peer-id root) + Signal identity + identity store.
class TestParty {
  final Uint8List accountSeed;
  final ed.SigningKey accountKey;
  final Uint8List accountPub;
  final String peerId;
  final String deviceId;
  final SignalProtocolService signal;
  final InMemoryVerifiedIdentityStore store;
  final List<Map<String, dynamic>> oneTimePreKeys;
  final Map<String, dynamic> preKeyBundle;

  TestParty._({
    required this.accountSeed,
    required this.accountKey,
    required this.accountPub,
    required this.peerId,
    required this.deviceId,
    required this.signal,
    required this.store,
    required this.oneTimePreKeys,
    required this.preKeyBundle,
  });

  /// [seedByte] makes the ACCOUNT deterministic per party; the Signal
  /// identity is fresh every time (a "reinstall" of the same account).
  static Future<TestParty> create({
    required int seedByte,
    required String deviceId,
    int opkCount = 3,
  }) async {
    final seed = Uint8List.fromList(List.filled(32, seedByte));
    final accountKey = ed.SigningKey(seed: seed);
    final accountPub = Uint8List.fromList(accountKey.verifyKey.toList());
    final peerId = const SnowChatIdScheme().deriveId(accountPub);
    final store = InMemoryVerifiedIdentityStore();
    final signal = SignalProtocolService(identityStore: store);
    await signal.generateIdentityKeyPair();
    await signal.generateSignedPreKey(1);
    final opks = await signal.generateOneTimePreKeys(1, opkCount);
    final bundle = await signal.getPreKeyBundle();
    return TestParty._(
      accountSeed: seed,
      accountKey: accountKey,
      accountPub: accountPub,
      peerId: peerId,
      deviceId: deviceId,
      signal: signal,
      store: store,
      oneTimePreKeys: opks,
      preKeyBundle: bundle,
    );
  }

  Uint8List get identityKey => preKeyBundle['identityKey'] as Uint8List;
  Uint8List get ed25519 => preKeyBundle['identityKeyEd25519'] as Uint8List;

  /// Binding over this party's CURRENT keys (or overrides).
  IdentityBinding bindingFor({
    required int epoch,
    String? deviceIdOverride,
    Uint8List? ikOverride,
    Uint8List? edOverride,
  }) {
    final msg = IdentityBindingV1.buildMessage(
      peerId: peerId,
      deviceId: deviceIdOverride ?? deviceId,
      epoch: epoch,
      identityKey: ikOverride ?? identityKey,
      ed25519: edOverride ?? ed25519,
    );
    final sig = Uint8List.fromList(accountKey.sign(msg).signature.toList());
    return IdentityBinding(signature: sig, epoch: epoch);
  }

  LocalIdentityBinding localBinding({required int epoch}) =>
      IdentityBindingV1.sign(
        accountSeed: accountSeed,
        deviceId: deviceId,
        epoch: epoch,
        identityKey: identityKey,
        ed25519: ed25519,
      );

  /// Decoded bundle as an integrator hands it to createSession.
  /// [opkIndex] selects a one-time prekey (null -> none).
  Map<String, dynamic> bundle({
    IdentityBinding? binding,
    Uint8List? accountPublicKey,
    int? opkIndex = 0,
  }) {
    final spk = preKeyBundle['signedPreKey'] as Map<String, dynamic>;
    return {
      'identityKey': identityKey,
      'identityKeyEd25519': ed25519,
      'signedPreKey': {
        'keyId': spk['keyId'],
        'publicKey': spk['publicKey'],
        'signature': spk['signature'],
      },
      if (opkIndex != null)
        'oneTimePreKey': {
          'keyId': oneTimePreKeys[opkIndex]['keyId'],
          'publicKey': oneTimePreKeys[opkIndex]['publicKey'],
        },
      'registrationId': preKeyBundle['registrationId'],
      if (binding != null) 'identityBinding': binding,
      if (accountPublicKey != null) 'accountPublicKey': accountPublicKey,
    };
  }
}

/// A Sealed Sender certificate for [party] (its peer id, device and X25519
/// identity key), valid for an hour and signed by [server].
SenderCertificate testSenderCertificate(ed.SigningKey server, TestParty party) {
  final unsigned = SenderCertificate(
    version: 1,
    senderSnowchatId: party.peerId,
    senderDeviceId: party.deviceId,
    senderIdentityKey: party.identityKey,
    expiryMs: DateTime.now().millisecondsSinceEpoch + 3600 * 1000,
    serverSignature: Uint8List(64),
  );
  final signed = Uint8List.sublistView(unsigned.toBytes(), 0, 113);
  final sig = Uint8List.fromList(server.sign(signed).signature);
  return SenderCertificate.fromBytes(Uint8List.fromList([...signed, ...sig]));
}
