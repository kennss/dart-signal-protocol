/// @file        sealed_plaintext.dart
/// @description Opt-in size padding of a JSON message plaintext before it is
///              Double-Ratchet encrypted and sealed (backport of SnowChat's
///              encodeSealedPlaintext). SealedSenderService.seal() pads its
///              inner payload only to 512 bytes and then to 64-byte steps,
///              and a PreKey (type-2) Double Ratchet message carries the
///              X3DH header and the identity binding — so above the floor,
///              the envelope size the server stores tells message kinds and
///              lengths apart. Padding the plaintext itself to a fixed block
///              makes every message that fits one block travel in envelopes
///              of one size (one size for PreKey messages, one for normal
///              messages).
///
///              The padding is JSON whitespace (0x20), so the receiver decodes
///              a padded plaintext with a plain `jsonDecode(utf8.decode(..))`
///              and needs no unpadding step; it is byte-identical to the
///              SnowChat app's padding. It applies to JSON payloads only.
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-11-23
/// @lastUpdated 2026-11-23
///
/// @functions
///  - sealedPlaintextBlock: default block (512 bytes)
///  - encodeSealedPlaintext(): UTF-8 JSON of a payload, space-padded to a
///    multiple of the block
library;

import 'dart:convert';
import 'dart:typed_data';

/// Default padding block in bytes. SnowChat measured that its control
/// notices and short messages (with a name certificate) fit one block.
/// Pick a block that holds the messages you want to look alike.
const int sealedPlaintextBlock = 512;

/// [payload] as a message plaintext: its UTF-8 JSON followed by spaces
/// (0x20) up to the next multiple of [block] bytes (one block at least).
/// A JSON reader skips the trailing spaces, so the receiver decodes it like
/// an unpadded one. Throws [ArgumentError] when [block] is not positive.
Uint8List encodeSealedPlaintext(
  Map<String, dynamic> payload, {
  int block = sealedPlaintextBlock,
}) {
  if (block <= 0) {
    throw ArgumentError.value(block, 'block', 'must be positive');
  }
  final json = utf8.encode(jsonEncode(payload));
  final blocks = (json.length + block - 1) ~/ block;
  final out = Uint8List((blocks == 0 ? 1 : blocks) * block)..setAll(0, json);
  out.fillRange(json.length, out.length, 0x20);
  return out;
}
