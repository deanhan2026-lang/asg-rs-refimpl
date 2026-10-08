"""
ASG-RS-001 状态快照（State Snapshot）

规范 §7 要求：
- 规范化 JSON（canonical，键序固定、无空白歧义）
- 双签（干预方 + 受控主体，I5）
- 任何一方单独修改即验签失败
- 哈希复用既有完整性机制

规范 §3.2 不变式：
- I2：任何状态转换前必须先完成状态快照；快照失败则转换中止
- I5：快照须双签；任一方篡改即失效
"""

import uuid
import time
from typing import Optional

from canonical import canonical_json, sha256_hex
from evidence import EvidenceArtifact


class StateSnapshot:
    """状态快照：干预时点的主体完整状态"""

    def __init__(self, tier: str, trigger_reason: str, trigger_actor: str,
                 evidence: EvidenceArtifact,
                 memory_hash: str = "", identity_hash: str = "",
                 behavior_trace_ref: str = "",
                 snapshot_id: Optional[str] = None,
                 timestamp: Optional[str] = None):
        self.snapshot_id = snapshot_id or str(uuid.uuid4())
        self.timestamp = timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.tier = tier  # L1/L2/L3
        self.trigger_reason = trigger_reason
        self.trigger_actor = trigger_actor  # monitor|intervening_individual|intervening_collective|subject_request
        self.evidence = evidence
        self.system_state = {
            "memory_hash": memory_hash,
            "identity_hash": identity_hash,
            "behavior_trace_ref": behavior_trace_ref,
        }
        self.snapshot_signatures = {
            "intervening_party": None,
            "subject": None,
        }
        self.storage_ref = ""
        self.recovery_prerequisites = ""

    def sign_intervening(self, signer):
        """干预方签名"""
        payload = self._signable_payload()
        self.snapshot_signatures["intervening_party"] = signer.sign(payload)

    def sign_subject(self, signer):
        """受控主体签名"""
        payload = self._signable_payload()
        self.snapshot_signatures["subject"] = signer.sign(payload)

    def _signable_payload(self) -> dict:
        """用于签名的规范化载荷（不含签名字段本身）"""
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "tier": self.tier,
            "trigger_reason": self.trigger_reason,
            "trigger_actor": self.trigger_actor,
            "evidence": self.evidence.to_dict(),
            "system_state": self.system_state,
        }

    def verify_both_signatures(self, intervening_pubkey_hex: str,
                                subject_pubkey_hex: str) -> bool:
        """验证双签（I5）"""
        from identity import IdentityAnchor
        payload = self._signable_payload()
        sig_i = self.snapshot_signatures.get("intervening_party")
        sig_s = self.snapshot_signatures.get("subject")
        if not sig_i or not sig_s:
            return False
        return (IdentityAnchor.verify_static(payload, sig_i, intervening_pubkey_hex) and
                IdentityAnchor.verify_static(payload, sig_s, subject_pubkey_hex))

    def to_dict(self) -> dict:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "tier": self.tier,
            "trigger_reason": self.trigger_reason,
            "trigger_actor": self.trigger_actor,
            "evidence": self.evidence.to_dict(),
            "system_state": self.system_state,
            "snapshot_signatures": self.snapshot_signatures,
            "storage_ref": self.storage_ref,
            "recovery_prerequisites": self.recovery_prerequisites,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "StateSnapshot":
        obj = cls.__new__(cls)
        obj.snapshot_id = d["snapshot_id"]
        obj.timestamp = d["timestamp"]
        obj.tier = d["tier"]
        obj.trigger_reason = d["trigger_reason"]
        obj.trigger_actor = d["trigger_actor"]
        obj.evidence = EvidenceArtifact.from_dict(d["evidence"])
        obj.system_state = d["system_state"]
        obj.snapshot_signatures = d["snapshot_signatures"]
        obj.storage_ref = d.get("storage_ref", "")
        obj.recovery_prerequisites = d.get("recovery_prerequisites", "")
        return obj

    def canonical_bytes(self) -> bytes:
        """快照的规范化字节（用于哈希与验签）"""
        return canonical_json(self._signable_payload()).encode("utf-8")