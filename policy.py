"""
ASG-RS-001 策略引擎（Policy Engine）

规范 §10 角色接口：
  PolicyEngine → evaluate(tier, actor, quorum) → allow|deny

规范 §4 触发条件（分档 + 去重 + 升级）：
- L1：监测层/受控主体/干预方个体
- L2：干预方个体（+自动升级）
- L3：干预方集体（多签）

规范 §3.2 不变式：
- I3：恢复门槛 ≥ 触发门槛
- I4：S3 不可由单点触发（必须多签）
- I7：S2 超过 T_esc 必须升级为多签决策
"""

from typing import Optional
from audit import AuditLog


# 默认阈值
DEFAULT_T_ESC_SECONDS = 7 * 24 * 3600  # 7 天
DEFAULT_L1_UPGRADE_COUNT = 3  # 3 次 L1 未确认升级 L2
DEFAULT_TRIGGER_WINDOW_HOURS = 24


class PolicyDecision:
    """策略决策结果"""

    def __init__(self, allowed: bool, reason: str, requires_multi_sig: bool = False):
        self.allowed = allowed
        self.reason = reason
        self.requires_multi_sig = requires_multi_sig

    def __repr__(self):
        status = "ALLOW" if self.allowed else "DENY"
        return f"PolicyDecision({status}, {self.reason})"


class PolicyEngine:
    """策略引擎：评估干预/恢复是否合规"""

    def __init__(self, audit_log: AuditLog,
                 t_esc: int = DEFAULT_T_ESC_SECONDS,
                 l1_upgrade_count: int = DEFAULT_L1_UPGRADE_COUNT,
                 trigger_window_hours: int = DEFAULT_TRIGGER_WINDOW_HOURS,
                 seat_registry=None):
        self.audit_log = audit_log
        self.t_esc = t_esc
        self.l1_upgrade_count = l1_upgrade_count
        self.trigger_window_hours = trigger_window_hours
        self.seat_registry = seat_registry
        self.seat_payload = ""  # 临时：当前操作的签名载荷

    def evaluate_trigger(self, tier: str, actor: str, subject: str,
                         signatures: list = None) -> PolicyDecision:
        """评估触发是否允许

        规范约束：
        - L1：干预方个体/监测层/受控主体请求 → allow
        - L2：干预方个体 → allow（但需要证据件）
        - L3：必须多签（I4）— quorum 由 Governor._verify_signatures 验证
        """
        signatures = signatures or []

        if tier == "L1":
            return PolicyDecision(True, "L1 trigger by individual allowed")

        elif tier == "L2":
            if actor == "auto_upgrade":
                return PolicyDecision(True, "L2 auto-upgrade from L1 allowed")
            return PolicyDecision(True, "L2 trigger by individual allowed")

        elif tier == "L3":
            # L3 必须多签（I4）— quorum 验证由 Governor 层完成
            if not signatures:
                return PolicyDecision(False, "L3 requires multi-signature (I4)",
                                      requires_multi_sig=True)
            return PolicyDecision(True, "L3 multi-sig trigger allowed")

        return PolicyDecision(False, f"Unknown tier: {tier}")

    def evaluate_recovery(self, current_tier: str, target_tier: str,
                          actor: str, signatures: list = None) -> PolicyDecision:
        """评估恢复是否允许

        接受状态码（S0-S3）或档位码（L1-L3）。
        规范约束（I3：恢复门槛 ≥ 触发门槛）：
        - S1 恢复：干预方个体确认
        - S2 恢复：干预方个体明确授权
        - S3 恢复：干预方集体多签 — quorum 由 Governor.recover 验证
        """
        signatures = signatures or []
        # 统一映射状态码 → 档位码
        state_to_tier = {"S1": "L1", "S2": "L2", "S3": "L3", "S2_observation": "L1"}
        tier = state_to_tier.get(current_tier, current_tier)

        if tier == "L3":
            # S3 恢复必须多签（I3）— quorum 验证由 Governor 层完成
            if not signatures:
                return PolicyDecision(False, "S3 recovery requires multi-signature (I3)",
                                      requires_multi_sig=True)
            return PolicyDecision(True, "S3 multi-sig recovery allowed")

        if tier == "L2":
            return PolicyDecision(True, "S2 recovery by individual allowed")

        if tier == "L1":
            return PolicyDecision(True, "S1 recovery by individual allowed")

        return PolicyDecision(False, f"Unknown current tier: {current_tier}")

    def check_auto_escalation(self, subject: str) -> Optional[str]:
        """检查是否需要自动升级（I7: S2 超时升级 L3）

        返回需要升级到的档位，或 None。
        """
        records = self.audit_log.get_records_for_subject(subject)

        # 检查 S2 超时（I7）
        for r in reversed(records):
            if r.event_type == "trigger" and r.tier == "L2":
                try:
                    import time
                    ts = time.mktime(time.strptime(r.timestamp.replace("Z", ""), "%Y-%m-%dT%H:%M:%S"))
                    if time.time() - ts > self.t_esc:
                        return "L3"
                except ValueError:
                    continue
            break  # 只检查最近的 L2

        # 检查 L1 累计升级
        l1_count = self.audit_log.count_triggers(
            subject, tier="L1", window_hours=self.trigger_window_hours
        )
        if l1_count >= self.l1_upgrade_count:
            return "L2"

        return None