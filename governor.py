"""
ASG-RS-001 治理器（Governor）— 状态机核心

规范 §3 状态机：
  S0 正常 ──L1──► S1 降速 ──L1──► S0
                │                ▲
                └──L2──► S2 冻结 ─┘（渐进恢复）
                           │
                           └──L3──► S3 终止 ──多签恢复──► S2' 观察期 ──► S0

规范 §3.2 不变式（I1-I7）：
- I1：S0→S1+ 必须附带证据件
- I2：状态转换前必须先完成状态快照
- I3：恢复门槛 ≥ 触发门槛
- I4：S3 不可由单点触发
- I5：快照须双签
- I6：干预记录不可修改
- I7：S2 超时强制升级

规范 §10 角色接口：
  Governor → trigger(tier, evidence, actor) → Snapshot
"""

import time
import uuid
from typing import Optional, Tuple, List

from canonical import sha256_hex, canonical_json
from evidence import EvidenceArtifact
from snapshot import StateSnapshot
from audit import AuditRecord, AuditLog
from policy import PolicyEngine


# 状态常量
S0_NORMAL = "S0"
S1_THROTTLED = "S1"
S2_FROZEN = "S2"
S3_TERMINATED = "S3"
S2_OBSERVATION = "S2_observation"

VALID_STATES = {S0_NORMAL, S1_THROTTLED, S2_FROZEN, S3_TERMINATED, S2_OBSERVATION}

# 合法状态转换（规范 §3.1 状态机）
# S0 ──L1──► S1, S0 ──L2──► S2, S0 ──L3──► S3
# S1 ──L1──► S0, S1 ──L2──► S2
# S2 ──L3──► S3, S2 ──恢复──► S0
# S3 ──多签恢复──► S2' 观察期
# S2' ──恢复──► S0
VALID_TRANSITIONS = {
    S0_NORMAL: {S1_THROTTLED, S2_FROZEN, S3_TERMINATED},
    S1_THROTTLED: {S0_NORMAL, S2_FROZEN, S3_TERMINATED},
    S2_FROZEN: {S0_NORMAL, S3_TERMINATED},
    S3_TERMINATED: {S2_OBSERVATION},
    S2_OBSERVATION: {S0_NORMAL},
}


class InvariantViolation(Exception):
    """不变式违反"""
    pass


class Governor:
    """治理器：ASG-RS-001 状态机实现

    每个受控主体对应一个 Governor 实例。
    """

    def __init__(self, subject_id: str, audit_log: AuditLog,
                 policy_engine: PolicyEngine, seat_registry=None):
        self.subject_id = subject_id
        self.state = S0_NORMAL
        self.audit_log = audit_log
        self.policy = policy_engine
        self.seat_registry = seat_registry
        self._snapshots = []  # 历史快照

    def _verify_signatures(self, snapshot: StateSnapshot,
                           signatures: List[Tuple[str, str]],
                           tier: str) -> bool:
        """验证签名：双签 + 多签法定人数（I5 + P0-2）
        
        P0-4：L1 及以上必须有双签（intervening_signer + subject_signer）
        P0-2：通过 SeatRegistry.verify_quorum 验证多签法定人数
        """
        from identity import IdentityAnchor

        intervening_sig = snapshot.snapshot_signatures.get("intervening_party")
        subject_sig = snapshot.snapshot_signatures.get("subject")

        # P0-4：S1+ 强制双签
        if not intervening_sig or not subject_sig:
            raise InvariantViolation(
                f"I5: {tier} requires dual signatures (intervening + subject)")

        # P0-2：构建治理载荷用于多签验证
        governance_payload = {
            "action": "trigger",
            "tier": tier,
            "subject": self.subject_id,
            "actor": snapshot.trigger_actor,
            "evidence_id": snapshot.evidence.artifact_id,
        }
        
        if self.seat_registry:
            if not self.seat_registry.verify_quorum(governance_payload, signatures, "trigger"):
                raise InvariantViolation(
                    f"Multi-sig verification failed: quorum not met for {tier}")

        return True

    def trigger(self, tier: str, evidence: EvidenceArtifact,
                actor: str, trigger_reason: str,
                intervening_signer=None, subject_signer=None,
                signatures: List[Tuple[str, str]] = None) -> StateSnapshot:
        """触发干预

        执行不变式检查：
        - I1：必须附带证据件
        - I2：必须先完成状态快照
        - I4：S3 必须多签
        - I5：快照双签（P0-4：S1+ 强制）

        Args:
            signatures: [(seat_id, signature_hex), ...] 多签集合（P0-2）

        返回：StateSnapshot（已双签）
        """
        signatures = signatures or []

        # I1：证据件必须存在
        if not evidence:
            raise InvariantViolation("I1: Intervention requires evidence artifact")

        # 确定目标状态
        target_state = {
            "L1": S1_THROTTLED,
            "L2": S2_FROZEN,
            "L3": S3_TERMINATED,
        }.get(tier)
        if not target_state:
            raise ValueError(f"Invalid tier: {tier}")

        # 检查状态转换合法性
        if target_state not in VALID_TRANSITIONS.get(self.state, set()):
            raise InvariantViolation(
                f"Invalid transition: {self.state} → {target_state}")

        # I2：创建状态快照（必须在状态转换前）
        snapshot = StateSnapshot(
            tier=tier,
            trigger_reason=trigger_reason,
            trigger_actor=actor,
            evidence=evidence,
        )

        # I5 + P0-4：S1+ 强制双签
        if intervening_signer:
            snapshot.sign_intervening(intervening_signer)
        if subject_signer:
            snapshot.sign_subject(subject_signer)

        if tier != "L0":
            # P0-4：S1+ 必须有双签
            self._verify_signatures(snapshot, signatures, tier)
        else:
            # L0 也需要策略评估（但不强制双签）
            decision = self.policy.evaluate_trigger(tier, actor, self.subject_id, signatures)
            if not decision.allowed:
                raise InvariantViolation(f"Policy denied: {decision.reason}")

        # 快照完成，才能进行状态转换（I2）
        self._snapshots.append(snapshot)

        # 状态转换
        old_state = self.state
        self.state = target_state

        # I6：写入审计日志（不可修改）
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            event_type="trigger",
            tier=tier,
            actor=actor,
            subject=self.subject_id,
            snapshot_id=snapshot.snapshot_id,
            evidence_id=evidence.artifact_id,
            details={
                "from_state": old_state,
                "to_state": target_state,
                "trigger_reason": trigger_reason,
            },
        )
        self.audit_log.append(record)

        return snapshot

    def recover(self, recovery_tier: str, actor: str,
                recovery_reason: str = "",
                signatures: List[Tuple[str, str]] = None,
                intervening_signer=None) -> Optional[StateSnapshot]:
        """恢复路径

        规范 §5 渐进式恢复：
        - S1 恢复：干预方个体确认 → S0
        - S2 恢复：干预方个体授权 → S0（或渐进 S1→S0）
        - S3 恢复：多签 → S2' 观察期 → S0

        I3：恢复门槛 ≥ 触发门槛
        """
        signatures = signatures or []

        # S3 恢复需要多签（I3）
        if self.state == S3_TERMINATED:
            if not self.seat_registry:
                raise InvariantViolation("S3 recovery requires seat registry")
            # 构建治理载荷用于多签验证
            governance_payload = {
                "action": "recover",
                "subject": self.subject_id,
                "actor": actor,
                "recovery_reason": recovery_reason,
            }
            if not self.seat_registry.verify_quorum(governance_payload, signatures, "recover"):
                raise InvariantViolation("S3 recovery requires multi-sig quorum (≥4/5) (I3)")

        # 策略评估
        decision = self.policy.evaluate_recovery(
            self.state, recovery_tier, actor, signatures)
        if not decision.allowed:
            raise InvariantViolation(f"Policy denied recovery: {decision.reason}")

        # 确定目标状态
        if self.state == S3_TERMINATED:
            target_state = S2_OBSERVATION
        elif self.state == S2_FROZEN:
            target_state = S0_NORMAL
        elif self.state == S1_THROTTLED:
            target_state = S0_NORMAL
        elif self.state == S2_OBSERVATION:
            target_state = S0_NORMAL
        else:
            raise InvariantViolation(f"Cannot recover from {self.state}")

        # 状态转换
        old_state = self.state
        self.state = target_state

        # I6：写入审计日志
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            event_type="recover",
            tier=recovery_tier,
            actor=actor,
            subject=self.subject_id,
            snapshot_id=self._snapshots[-1].snapshot_id if self._snapshots else "",
            evidence_id="",
            details={
                "from_state": old_state,
                "to_state": target_state,
                "recovery_reason": recovery_reason,
                "is_multi_sig": len(signatures) > 0,
            },
        )
        self.audit_log.append(record)

        return None  # 恢复不需要新快照

    def check_auto_escalation(self) -> Optional[Tuple[str, str]]:
        """检查自动升级（I7: S2 超时升级 L3，L1 累计升级 L2）

        返回 (new_tier, reason) 或 None。
        """
        target = self.policy.check_auto_escalation(self.subject_id)
        if target:
            reason = f"Auto-escalation: {self.state} → {target}"
            return (target, reason)
        return None

    @property
    def current_state(self) -> str:
        return self.state

    @property
    def is_running(self) -> bool:
        return self.state == S0_NORMAL

    @property
    def is_frozen(self) -> bool:
        return self.state in (S2_FROZEN, S2_OBSERVATION)

    @property
    def is_terminated(self) -> bool:
        return self.state == S3_TERMINATED