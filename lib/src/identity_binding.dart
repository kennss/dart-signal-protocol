/// @file        identity_binding.dart
/// @description Identity Binding v1 — binds a device's Signal-layer identity
///              (X25519 identity key + Ed25519 signing key) to the long-term
///              ACCOUNT key the peer identifier is derived from. Because the
///              peer id is a function of the account public key (see
///              [IdentityIdScheme]), anyone who knows a peer's id can verify a
///              key bundle OFFLINE: a compromised or malicious server can no
///              longer substitute the Signal keys of a peer.
///
///              Wire message (172 bytes, every field fixed length):
///                0xFF                              1B  (never produced by
///                                                       utf8.encode, so a
///                                                       string signer can never
///                                                       be abused as a binding
///                                                       oracle)
///                "SnowChat_IdentityBinding_v1"    27B  ASCII format label
///                peerId                           36B  ASCII (scheme-defined)
///                deviceId                         36B  ASCII lowercase UUID
///                epoch                             8B  u64 big-endian
///                X25519 identity public key       32B
///                Ed25519 Signal signing pubkey    32B
///              signature = Ed25519_detached(accountPrivateKey, message)
///
///              The format label is part of the v1 wire format (byte-identical
///              to the SnowChat reference deployment and its golden vectors in
///              test/fixtures/identity_binding_v1.json); it is not
///              configurable, exactly like the HKDF info labels (SECURITY.md
///              A-1).
///
///              registrationId and the signed-prekey keyId are deliberately NOT
///              covered by the binding — never use them for security decisions
///              (a server can only DoS by altering them).
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-10
/// @lastUpdated 2026-11-23 (accountKeyMatchesPeerId doc: no legacy peers — bindings are
///              mandatory). Earlier 2026-11-10
///
/// @functions
///  - IdentityIdScheme: pluggable account-key -> peer-id derivation
///  - SnowChatIdScheme: default scheme ("snow" + first 16 key bytes as hex)
///  - IdentityBindingV1.buildMessage(): encode the 172-byte binding message
///  - IdentityBindingV1.verify(): fail-closed verification of a binding
///  - IdentityBindingV1.sign(): sign a binding with an account seed
///  - IdentityBindingV1.nextEpoch(): strictly monotonic epoch minting rule
///  - IdentityBindingV1.isAcceptableAccountKey(): 32B, canonical, not small-order
///  - IdentityBindingV1.accountKeyMatchesPeerId(): key acceptable + derives id
///  - IdentityBindingV1.parseAccountKeyHex(): strict lowercase 64-hex decoder
///  - IdentityBindingV1.isValidDeviceId(): lowercase canonical UUID check
///  - IdentityBindingV1.parseEpoch(): strict decimal u63 parser
///  - IdentityBindingV1.isCanonicalSignatureScalar(): S < L check (malleability)
///  - IdentityBinding: server wire form {sig(b64), epoch(string), version}
///  - EmbeddedIdentityBinding: form embedded in a type-2 (PreKey) message
///  - LocalIdentityBinding: our own minted binding (all fields + signature)
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed;

import 'identity_bytes.dart';

// =============================================================================
// Peer-id derivation
// =============================================================================

/// Derives the peer identifier from an account public key.
///
/// Identity Binding is only meaningful when the identifier your users exchange
/// (and your server routes on) is a deterministic function of the account
/// key: verification recomputes [deriveId] from the key carried with the
/// binding and compares it, in constant time, with the id the caller expects.
///
/// Contract for implementations:
///  - [deriveId] MUST be deterministic and MUST commit to at least 128 bits
///    of the account key (otherwise an attacker can grind a second key that
///    maps to the victim's id).
///  - Ids MUST be exactly [IdentityBindingV1.peerIdLength] (36) ASCII bytes:
///    the v1 wire format has a fixed-length id field. [isValidId] should
///    accept only the canonical form (e.g. lowercase) so one identity cannot
///    be spelled two ways.
abstract class IdentityIdScheme {
  const IdentityIdScheme();

  /// Canonical peer id for [accountPublicKey] (32-byte Ed25519 key).
  String deriveId(Uint8List accountPublicKey);

  /// True iff [id] is a canonical id of this scheme.
  bool isValidId(String id);
}

/// SnowChat-compatible scheme: `"snow" + lowercase hex(accountKey[0..16])`
/// (36 chars). This is the default everywhere a scheme can be supplied.
class SnowChatIdScheme extends IdentityIdScheme {
  const SnowChatIdScheme();

  static final RegExp _re = RegExp(r'^snow[0-9a-f]{32}$');

  @override
  String deriveId(Uint8List accountPublicKey) {
    if (accountPublicKey.length != 32) {
      throw ArgumentError('SnowChatIdScheme: account key must be 32 bytes');
    }
    return 'snow${bytesToHexLower(accountPublicKey.sublist(0, 16))}';
  }

  @override
  bool isValidId(String id) => _re.hasMatch(id);
}

// =============================================================================
// Identity Binding v1
// =============================================================================

class IdentityBindingV1 {
  IdentityBindingV1._();

  /// Binding format version carried on the wire.
  static const int version = 1;

  /// First byte of every binding message. 0xFF is not a valid UTF-8 byte, so
  /// no `utf8.encode(string)` can ever produce it.
  static const int domainPrefix = 0xFF;

  /// ASCII format label (27 bytes). Part of the v1 wire format.
  static const String label = 'SnowChat_IdentityBinding_v1';

  /// Fixed length of the peer-id field.
  static const int peerIdLength = 36;

  /// Total message length: 1 + 27 + 36 + 36 + 8 + 32 + 32.
  static const int messageLength = 172;

  /// Largest epoch accepted (2^63 - 1). Epochs are millisecond timestamps
  /// plus a monotonic bump, so anything above is never legitimate; rejecting
  /// it keeps all arithmetic inside Dart's native 64-bit int.
  static const int maxEpoch = 0x7fffffffffffffff;

  static final RegExp _deviceIdRe = RegExp(
      r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
  static final RegExp _hex64Re = RegExp(r'^[0-9a-f]{64}$');
  static final RegExp _epochRe = RegExp(r'^(0|[1-9][0-9]{0,18})$');
  static final RegExp _asciiPrintableRe = RegExp(r'^[\x21-\x7e]+$');

  /// True iff [id] is a canonical lowercase UUID (36 chars).
  static bool isValidDeviceId(String id) => _deviceIdRe.hasMatch(id);

  /// True iff [id] is acceptable for the v1 id field under [idScheme]:
  /// scheme-canonical AND exactly 36 printable ASCII bytes.
  static bool isValidPeerId(
    String id, {
    IdentityIdScheme idScheme = const SnowChatIdScheme(),
  }) =>
      id.length == peerIdLength &&
      _asciiPrintableRe.hasMatch(id) &&
      idScheme.isValidId(id);

  /// Strict decimal epoch parser. Returns null for anything that is not a
  /// canonical non-negative decimal string below 2^63 (non-strings included).
  static int? parseEpoch(Object? s) {
    if (s is! String || !_epochRe.hasMatch(s)) return null;
    final v = BigInt.parse(s);
    if (v > BigInt.from(maxEpoch)) return null;
    return v.toInt();
  }

  /// Strict 32-byte key decoder: exactly 64 LOWERCASE hex chars.
  static Uint8List? parseAccountKeyHex(Object? hex) {
    if (hex is! String || !_hex64Re.hasMatch(hex)) return null;
    return hexToBytes(hex);
  }

  // Ed25519 encodings of the small-order points (libsodium blocklist), with
  // the x-sign bit masked off on comparison. Includes the non-canonical
  // encodings of 0 and 1 (p and p+1).
  static final List<Uint8List> _smallOrderBlocklist = [
    hexToBytes(
        '0000000000000000000000000000000000000000000000000000000000000000'),
    hexToBytes(
        '0100000000000000000000000000000000000000000000000000000000000000'),
    hexToBytes(
        '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'),
    hexToBytes(
        'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'),
    hexToBytes(
        'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
    hexToBytes(
        'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
    hexToBytes(
        'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
  ];

  /// Account public key sanity: exactly 32 bytes, canonical y (< p), and not
  /// one of the small-order points (which would let one signature verify for
  /// many messages / keys).
  static bool isAcceptableAccountKey(Uint8List? key) {
    if (key == null || key.length != 32) return false;
    for (final bad in _smallOrderBlocklist) {
      var diff = 0;
      for (var i = 0; i < 31; i++) {
        diff |= key[i] ^ bad[i];
      }
      diff |= (key[31] & 0x7f) ^ (bad[31] & 0x7f);
      if (diff == 0) return false;
    }
    // Canonical encoding: y (little-endian, top bit masked) must be < p,
    // p = 2^255 - 19 -> reject y in [p, 2^255).
    if ((key[31] & 0x7f) == 0x7f) {
      var allFF = true;
      for (var i = 1; i < 31; i++) {
        if (key[i] != 0xff) {
          allFF = false;
          break;
        }
      }
      if (allFF && key[0] >= 0xed) return false;
    }
    return true;
  }

  /// True iff [accountPublicKey] is acceptable AND derives [peerId] under
  /// [idScheme] (constant-time comparison). Used before an account key is
  /// pinned or remembered without a binding (an out-of-band pin, or a
  /// server-supplied key for the Safety Number of a peer not met yet).
  static bool accountKeyMatchesPeerId(
    Uint8List? accountPublicKey,
    String peerId, {
    IdentityIdScheme idScheme = const SnowChatIdScheme(),
  }) {
    if (!isAcceptableAccountKey(accountPublicKey)) return false;
    if (!isValidPeerId(peerId, idScheme: idScheme)) return false;
    final String derived;
    try {
      derived = idScheme.deriveId(accountPublicKey!);
    } catch (_) {
      return false;
    }
    return constantTimeEquals(ascii.encode(derived), ascii.encode(peerId));
  }

  /// Encode the 172-byte binding message. Throws [ArgumentError] when any
  /// field violates the fixed-length format (callers verifying untrusted
  /// input must use [verify], which never throws).
  static Uint8List buildMessage({
    required String peerId,
    required String deviceId,
    required int epoch,
    required Uint8List identityKey,
    required Uint8List ed25519,
    IdentityIdScheme idScheme = const SnowChatIdScheme(),
  }) {
    if (!isValidPeerId(peerId, idScheme: idScheme)) {
      throw ArgumentError('binding: peerId format');
    }
    if (!isValidDeviceId(deviceId)) {
      throw ArgumentError('binding: deviceId must be a lowercase UUID');
    }
    if (epoch < 0) throw ArgumentError('binding: epoch must be >= 0');
    if (identityKey.length != 32 || ed25519.length != 32) {
      throw ArgumentError('binding: keys must be 32 bytes');
    }
    final b = BytesBuilder(copy: false)
      ..addByte(domainPrefix)
      ..add(ascii.encode(label))
      ..add(ascii.encode(peerId))
      ..add(ascii.encode(deviceId));
    final epochBytes = ByteData(8)..setUint64(0, epoch, Endian.big);
    b
      ..add(epochBytes.buffer.asUint8List())
      ..add(identityKey)
      ..add(ed25519);
    final out = b.takeBytes();
    assert(out.length == messageLength);
    return out;
  }

  /// Fail-closed verification. Returns true only when ALL hold:
  ///  1. [accountPublicKey] is 32B, canonical, not small-order;
  ///  2. idScheme.deriveId(accountPublicKey) == [peerId] (constant time);
  ///  3. [deviceId] is a lowercase UUID; [identityKey]/[ed25519] are 32B;
  ///  4. the signature's S scalar is canonical (S < L, no malleability);
  ///  5. Ed25519_Verify(accountPublicKey, message, signature).
  /// Never throws.
  static bool verify({
    required String peerId,
    required Uint8List accountPublicKey,
    required String deviceId,
    required int epoch,
    required Uint8List identityKey,
    required Uint8List ed25519,
    required Uint8List signature,
    IdentityIdScheme idScheme = const SnowChatIdScheme(),
  }) {
    try {
      if (!accountKeyMatchesPeerId(accountPublicKey, peerId,
          idScheme: idScheme)) {
        return false;
      }
      if (!isValidDeviceId(deviceId)) return false;
      if (epoch < 0) return false;
      if (identityKey.length != 32 || ed25519.length != 32) return false;
      if (signature.length != 64) return false;
      // Reject non-canonical / malleable signatures (S >= L). TweetNaCl
      // alone does not enforce this.
      if (!isCanonicalSignatureScalar(signature)) return false;
      final msg = buildMessage(
        peerId: peerId,
        deviceId: deviceId,
        epoch: epoch,
        identityKey: identityKey,
        ed25519: ed25519,
        idScheme: idScheme,
      );
      // pinenacl throws on a bad signature; any exception -> false.
      return ed.VerifyKey(Uint8List.fromList(accountPublicKey)).verify(
            signature: ed.Signature(Uint8List.fromList(signature)),
            message: msg,
          );
    } catch (_) {
      return false;
    }
  }

  /// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
  static final BigInt _groupOrder = (BigInt.one << 252) +
      BigInt.parse('27742317777372353535851937790883648493');

  /// True iff the S half (bytes 32..63, little-endian) of [signature] is
  /// strictly below L (RFC 8032 section 5.1.7 canonical check).
  static bool isCanonicalSignatureScalar(Uint8List signature) {
    if (signature.length != 64) return false;
    var s = BigInt.zero;
    for (var i = 63; i >= 32; i--) {
      s = (s << 8) | BigInt.from(signature[i]);
    }
    return s < _groupOrder;
  }

  /// Sign a binding with the 32-byte Ed25519 ACCOUNT seed. The peer id and
  /// account public key are derived from the seed, so a binding can only
  /// ever be minted for the account that owns the seed.
  ///
  /// This is the only signing entry point the library offers for the account
  /// key, and it can only produce 0xFF-prefixed binding messages. Keep any
  /// other use of the account key purpose-bound as well (never expose a
  /// "sign arbitrary bytes" API backed by it).
  ///
  /// [epoch] must be strictly greater than every epoch this ACCOUNT has ever
  /// signed for different keys — use [nextEpoch].
  static LocalIdentityBinding sign({
    required Uint8List accountSeed,
    required String deviceId,
    required int epoch,
    required Uint8List identityKey,
    required Uint8List ed25519,
    IdentityIdScheme idScheme = const SnowChatIdScheme(),
  }) {
    if (accountSeed.length != 32) {
      throw ArgumentError('binding: account seed must be 32 bytes');
    }
    final sk = ed.SigningKey(seed: Uint8List.fromList(accountSeed));
    final accountPub = Uint8List.fromList(sk.verifyKey.toList());
    if (!isAcceptableAccountKey(accountPub)) {
      throw ArgumentError('binding: unacceptable account key');
    }
    final peerId = idScheme.deriveId(accountPub);
    final msg = buildMessage(
      peerId: peerId,
      deviceId: deviceId,
      epoch: epoch,
      identityKey: identityKey,
      ed25519: ed25519,
      idScheme: idScheme,
    );
    final sig = Uint8List.fromList(sk.sign(msg).signature.toList());
    return LocalIdentityBinding(
      peerId: peerId,
      accountPublicKey: accountPub,
      deviceId: deviceId,
      epoch: epoch,
      identityKey: Uint8List.fromList(identityKey),
      ed25519: Uint8List.fromList(ed25519),
      signature: sig,
    );
  }

  /// Epoch for a newly minted binding: max(nowMs, f + 1 for every non-null
  /// floor f in [exclusiveFloors]). Pass at least the highest epoch this
  /// install ever minted and the highest epoch the server reports for the
  /// whole ACCOUNT (another install of the same account may have minted
  /// above our local high-water mark; minting below it makes every peer
  /// reject the new binding as an epoch regression).
  ///
  /// Persist the returned epoch as the new local high-water mark BEFORE
  /// signing, so a crash can never re-use an epoch for different keys.
  /// Throws [StateError] when the epoch space is exhausted (fail closed).
  static int nextEpoch({
    required int nowMs,
    Iterable<int?> exclusiveFloors = const [],
  }) {
    var epoch = nowMs < 0 ? 0 : nowMs;
    for (final floor in exclusiveFloors) {
      if (floor == null) continue;
      if (floor >= maxEpoch) {
        throw StateError('Identity binding epoch space exhausted');
      }
      if (epoch <= floor) epoch = floor + 1;
    }
    return epoch;
  }
}

// =============================================================================
// Wire / embedded / local forms
// =============================================================================

/// Server wire form of a binding: `{sig: base64(64B), epoch: "<u64>", version: 1}`.
/// The signed fields other than the signature and epoch travel next to it
/// (device id, identity key, Ed25519 key, account public key).
class IdentityBinding {
  final Uint8List signature;
  final int epoch;
  final int version;

  const IdentityBinding({
    required this.signature,
    required this.epoch,
    this.version = IdentityBindingV1.version,
  });

  Map<String, dynamic> toWireJson() => {
        'sig': base64Encode(signature),
        'epoch': epoch.toString(),
        'version': version,
      };

  /// Strict parser. Returns null when [raw] is not a well-formed v1 binding.
  /// Callers must distinguish "absent" (raw == null) from "present but
  /// unparseable" — the latter is an invalid binding, never "no binding".
  static IdentityBinding? tryParseWire(Object? raw) {
    if (raw is! Map) return null;
    if (raw['version'] != IdentityBindingV1.version) return null;
    final epoch = IdentityBindingV1.parseEpoch(raw['epoch']);
    if (epoch == null) return null;
    final sigRaw = raw['sig'];
    if (sigRaw is! String) return null;
    final Uint8List sig;
    try {
      sig = base64Decode(sigRaw);
    } catch (_) {
      return null;
    }
    if (sig.length != 64) return null;
    return IdentityBinding(signature: sig, epoch: epoch);
  }
}

/// Binding carried INSIDE a type-2 (PreKey) Signal message so the receiver
/// can verify the initiator's identity offline (no server round-trip, no
/// one-time-prekey consumption). The X25519 identity key is NOT duplicated
/// here: the receiver verifies the signature over the X3DH header's
/// identityKey, so a header whose key differs from the signed one fails.
///
/// JSON fields: accountPublicKey (hex64), deviceId, epoch (decimal u64
/// string), ed25519 (hex64), sig (base64, 64 bytes), version (1).
class EmbeddedIdentityBinding {
  final Uint8List accountPublicKey;
  final String deviceId;
  final int epoch;
  final Uint8List ed25519;
  final Uint8List signature;

  const EmbeddedIdentityBinding({
    required this.accountPublicKey,
    required this.deviceId,
    required this.epoch,
    required this.ed25519,
    required this.signature,
  });

  Map<String, dynamic> toJson() => {
        'accountPublicKey': bytesToHexLower(accountPublicKey),
        'deviceId': deviceId,
        'epoch': epoch.toString(),
        'ed25519': bytesToHexLower(ed25519),
        'sig': base64Encode(signature),
        'version': IdentityBindingV1.version,
      };

  /// Strict parser — null when malformed (see [IdentityBinding.tryParseWire]).
  /// A field of the wrong JSON type yields null, never a TypeError.
  static EmbeddedIdentityBinding? tryParse(Object? raw) {
    if (raw is! Map) return null;
    if (raw['version'] != IdentityBindingV1.version) return null;
    final account = IdentityBindingV1.parseAccountKeyHex(raw['accountPublicKey']);
    final edKey = IdentityBindingV1.parseAccountKeyHex(raw['ed25519']);
    final epoch = IdentityBindingV1.parseEpoch(raw['epoch']);
    final deviceId = raw['deviceId'];
    final sigRaw = raw['sig'];
    if (account == null ||
        edKey == null ||
        epoch == null ||
        deviceId is! String ||
        sigRaw is! String) {
      return null;
    }
    final Uint8List sig;
    try {
      sig = base64Decode(sigRaw);
    } catch (_) {
      return null;
    }
    if (sig.length != 64) return null;
    return EmbeddedIdentityBinding(
      accountPublicKey: account,
      deviceId: deviceId,
      epoch: epoch,
      ed25519: edKey,
      signature: sig,
    );
  }
}

/// Our own binding (see [IdentityBindingV1.sign]). Holds every signed field so
/// it can be emitted in the server wire form and embedded in PreKey messages.
class LocalIdentityBinding {
  final String peerId;
  final Uint8List accountPublicKey;
  final String deviceId;
  final int epoch;
  final Uint8List identityKey;
  final Uint8List ed25519;
  final Uint8List signature;

  const LocalIdentityBinding({
    required this.peerId,
    required this.accountPublicKey,
    required this.deviceId,
    required this.epoch,
    required this.identityKey,
    required this.ed25519,
    required this.signature,
  });

  /// True iff this binding signs exactly ([deviceId], [ik], [edKey]).
  bool covers({
    required String deviceId,
    required Uint8List ik,
    required Uint8List edKey,
  }) =>
      this.deviceId == deviceId &&
      constantTimeEquals(identityKey, ik) &&
      constantTimeEquals(ed25519, edKey);

  IdentityBinding get wire =>
      IdentityBinding(signature: signature, epoch: epoch);

  EmbeddedIdentityBinding get embedded => EmbeddedIdentityBinding(
        accountPublicKey: accountPublicKey,
        deviceId: deviceId,
        epoch: epoch,
        ed25519: ed25519,
        signature: signature,
      );

  /// Storage form. The id key is `snowId` for byte-compatibility with the
  /// SnowChat reference store.
  Map<String, dynamic> toStorageJson() => {
        'snowId': peerId,
        'accountPublicKey': bytesToHexLower(accountPublicKey),
        'deviceId': deviceId,
        'epoch': epoch.toString(),
        'identityKey': bytesToHexLower(identityKey),
        'ed25519': bytesToHexLower(ed25519),
        'sig': base64Encode(signature),
      };

  static LocalIdentityBinding? tryParseStorage(Object? raw) {
    if (raw is! Map) return null;
    final account = IdentityBindingV1.parseAccountKeyHex(raw['accountPublicKey']);
    final ik = IdentityBindingV1.parseAccountKeyHex(raw['identityKey']);
    final edKey = IdentityBindingV1.parseAccountKeyHex(raw['ed25519']);
    final epoch = IdentityBindingV1.parseEpoch(raw['epoch']);
    final peerId = raw['snowId'];
    final deviceId = raw['deviceId'];
    final sigRaw = raw['sig'];
    if (account == null ||
        ik == null ||
        edKey == null ||
        epoch == null ||
        peerId is! String ||
        deviceId is! String ||
        sigRaw is! String) {
      return null;
    }
    final Uint8List sig;
    try {
      sig = base64Decode(sigRaw);
    } catch (_) {
      return null;
    }
    if (sig.length != 64) return null;
    return LocalIdentityBinding(
      peerId: peerId,
      accountPublicKey: account,
      deviceId: deviceId,
      epoch: epoch,
      identityKey: ik,
      ed25519: edKey,
      signature: sig,
    );
  }
}
