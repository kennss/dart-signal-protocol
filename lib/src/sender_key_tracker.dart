/// @file        sender_key_tracker.dart
/// @description SKDM 배포 추적 — 그룹 멤버별 Sender Key 배포 상태를 추적하여 불필요한 재전송 방지
/// @author      Kennt Kim
/// @company     Calida Lab
/// @created     2026-04-04
/// @lastUpdated 2026-04-04
///
/// @functions
///  - SenderKeyDistributionTracker: SKDM 배포 추적 클래스
///  - needsSKDM(): 해당 멤버에게 SKDM 전송이 필요한지 판단
///  - markDelivered(): SKDM 전송 성공 기록
///  - invalidateGroup(): 키 회전 시 그룹 전체 추적 초기화
///  - removeMember(): 멤버 제거 시 해당 멤버 추적 제거
///  - toJson(): 영속화용 직렬화
///  - fromJson(): 영속화된 상태 복원

/// Tracks which group members have received a Sender Key Distribution
/// Message (SKDM) to avoid redundant re-sends.
///
/// Without this tracker, every group message sends SKDM + pairwise to
/// ALL members (O(N)). With the tracker, only members who haven't
/// received the current SKDM get it (O(K) where K ≈ 0 for most messages).
///
/// Persistence: serialized into the session store alongside SenderKeyManager,
/// so it's automatically encrypted at rest via SecretBox.
class SenderKeyDistributionTracker {
  /// groupId → { memberId → _TrackerEntry }
  final Map<String, Map<String, _TrackerEntry>> _delivered;

  SenderKeyDistributionTracker() : _delivered = {};
  SenderKeyDistributionTracker._(this._delivered);

  /// Default max age before SKDM is re-sent even if previously delivered.
  static const Duration defaultMaxAge = Duration(hours: 24);

  /// Check if SKDM needs to be sent to [memberId] in [groupId].
  ///
  /// Returns true if:
  /// - Member has never received SKDM
  /// - Key was rotated since last delivery (rotationVersion mismatch)
  /// - Last delivery was more than [maxAge] ago
  bool needsSKDM(
    String groupId,
    String memberId,
    int currentRotationVersion, {
    Duration maxAge = const Duration(hours: 24),
  }) {
    final groupMap = _delivered[groupId];
    if (groupMap == null) return true;
    final entry = groupMap[memberId];
    if (entry == null) return true;
    if (entry.rotationVersion != currentRotationVersion) return true;
    return DateTime.now().difference(entry.deliveredAt) > maxAge;
  }

  /// Record that SKDM was successfully sent to [memberId] in [groupId].
  void markDelivered(
    String groupId,
    String memberId,
    int rotationVersion,
  ) {
    _delivered.putIfAbsent(groupId, () => {});
    _delivered[groupId]![memberId] = _TrackerEntry(
      deliveredAt: DateTime.now(),
      rotationVersion: rotationVersion,
    );
  }

  /// Invalidate all tracking for [groupId] (e.g., after key rotation).
  /// Next message will re-send SKDM to all members.
  void invalidateGroup(String groupId) {
    _delivered.remove(groupId);
  }

  /// Remove tracking for a specific member (e.g., after member leaves).
  void removeMember(String groupId, String memberId) {
    _delivered[groupId]?.remove(memberId);
  }

  /// Serialize for session store persistence.
  Map<String, dynamic> toJson() {
    final result = <String, dynamic>{};
    for (final groupEntry in _delivered.entries) {
      final members = <String, dynamic>{};
      for (final memberEntry in groupEntry.value.entries) {
        members[memberEntry.key] = {
          'deliveredAt': memberEntry.value.deliveredAt.millisecondsSinceEpoch,
          'rotationVersion': memberEntry.value.rotationVersion,
        };
      }
      result[groupEntry.key] = members;
    }
    return result;
  }

  /// Restore from session store.
  factory SenderKeyDistributionTracker.fromJson(Map<String, dynamic> json) {
    final delivered = <String, Map<String, _TrackerEntry>>{};
    for (final groupEntry in json.entries) {
      final groupId = groupEntry.key;
      final members = groupEntry.value as Map<String, dynamic>;
      delivered[groupId] = {};
      for (final memberEntry in members.entries) {
        final data = memberEntry.value as Map<String, dynamic>;
        delivered[groupId]![memberEntry.key] = _TrackerEntry(
          deliveredAt: DateTime.fromMillisecondsSinceEpoch(
              data['deliveredAt'] as int),
          rotationVersion: data['rotationVersion'] as int? ?? 0,
        );
      }
    }
    return SenderKeyDistributionTracker._(delivered);
  }
}

class _TrackerEntry {
  final DateTime deliveredAt;
  final int rotationVersion;

  _TrackerEntry({
    required this.deliveredAt,
    required this.rotationVersion,
  });
}
