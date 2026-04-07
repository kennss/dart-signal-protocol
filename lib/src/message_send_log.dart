/// @file        message_send_log.dart
/// @description 그룹 메시지 재전송용 발신 로그 — 복호화 실패 시 retry request에 응답하기 위해 최근 메시지 평문을 암호화 저장
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-04
/// @lastUpdated 2026-04-04
///
/// @functions
///  - MessageSendLog: 발신 메시지 로그 (LRU, 암호화, TTL)
///  - record(): 메시지 기록
///  - lookup(): 메시지 조회
///  - toJson(): 영속화용 직렬화
///  - fromJson(): 영속화된 상태 복원

import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

/// Stores recently sent group message plaintexts for retry requests.
///
/// When a recipient fails to decrypt a group message, they send a
/// `group_message_retry_request` back to the original sender. The sender
/// looks up the plaintext in this log and re-sends it via 1:1 E2EE.
///
/// Security:
/// - Entries are stored as raw bytes (encrypted at rest via session store SecretBox)
/// - LRU eviction with max [maxEntries] and [maxAge] TTL
/// - The entire log is persisted inside the session store, which is
///   encrypted with HKDF-derived key from the device's identity private key
class MessageSendLog {
  static const int maxEntries = 100;
  static const Duration maxAge = Duration(hours: 2);

  /// LRU map: messageId → _LogEntry (insertion order preserved)
  final LinkedHashMap<String, _LogEntry> _log;

  MessageSendLog() : _log = LinkedHashMap<String, _LogEntry>();
  MessageSendLog._(this._log);

  /// Record a sent message for potential retry.
  void record(String messageId, Uint8List plaintext, String groupId) {
    // LRU eviction
    if (_log.length >= maxEntries) {
      _log.remove(_log.keys.first); // Remove oldest (LRU)
    }
    _log[messageId] = _LogEntry(
      plaintext: plaintext,
      groupId: groupId,
      timestamp: DateTime.now(),
    );
  }

  /// Look up a previously sent message by ID.
  /// Returns null if not found or expired.
  Uint8List? lookup(String messageId) {
    final entry = _log[messageId];
    if (entry == null) return null;
    if (DateTime.now().difference(entry.timestamp) > maxAge) {
      _log.remove(messageId);
      return null;
    }
    return entry.plaintext;
  }

  /// Get the groupId for a logged message.
  String? groupIdFor(String messageId) {
    return _log[messageId]?.groupId;
  }

  /// Serialize for session store persistence.
  Map<String, dynamic> toJson() {
    _prune(); // Clean expired before saving
    final result = <String, dynamic>{};
    for (final entry in _log.entries) {
      result[entry.key] = {
        'plaintext': base64Encode(entry.value.plaintext),
        'groupId': entry.value.groupId,
        'timestamp': entry.value.timestamp.millisecondsSinceEpoch,
      };
    }
    return result;
  }

  /// Restore from session store.
  factory MessageSendLog.fromJson(Map<String, dynamic> json) {
    final log = LinkedHashMap<String, _LogEntry>();
    for (final entry in json.entries) {
      final data = entry.value as Map<String, dynamic>;
      final timestamp = DateTime.fromMillisecondsSinceEpoch(
          data['timestamp'] as int);
      // Skip expired entries on load
      if (DateTime.now().difference(timestamp) <= maxAge) {
        log[entry.key] = _LogEntry(
          plaintext: base64Decode(data['plaintext'] as String),
          groupId: data['groupId'] as String,
          timestamp: timestamp,
        );
      }
    }
    return MessageSendLog._(log);
  }

  /// Remove expired entries.
  void _prune() {
    final now = DateTime.now();
    _log.removeWhere((_, entry) => now.difference(entry.timestamp) > maxAge);
  }
}

class _LogEntry {
  final Uint8List plaintext;
  final String groupId;
  final DateTime timestamp;

  _LogEntry({
    required this.plaintext,
    required this.groupId,
    required this.timestamp,
  });
}
