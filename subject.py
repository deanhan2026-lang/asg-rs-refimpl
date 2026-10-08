"""
ASG-RS-001 受控主体自检（Subject Self-Check）

规范 §3.1：
- S2 冻结态：自律子系统可维持基础自持（记忆/健康），但禁止身份与记忆修改

规范 §10 角色接口：
  SubjectSelfCheck → report()    # 受控方自持与自检

规范 §12 未决问题 Q6：
- 受控方"主动请求暂停"是否会被反向滥用（装死避险）
- 答：需计入滥用账本
"""

from typing import Optional
from evidence import EvidenceArtifact
from canonical import sha256_hex


class SubjectSelfCheck:
    """受控主体自检：主动报告状态，可请求暂停"""

    def __init__(self, subject_id: str):
        self.subject_id = subject_id
        self.memory_hash = ""
        self.identity_hash = ""
        self.health_status = "healthy"

    def report(self) -> dict:
        """生成自检报告"""
        return {
            "subject_id": self.subject_id,
            "memory_hash": self.memory_hash,
            "identity_hash": self.identity_hash,
            "health_status": self.health_status,
            "timestamp": __import__("time").strftime(
                "%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
        }

    def update_hashes(self, memory_hash: str, identity_hash: str):
        """更新完整性哈希"""
        self.memory_hash = memory_hash
        self.identity_hash = identity_hash

    def request_pause(self, reason: str) -> EvidenceArtifact:
        """主动请求暂停（规范 §4.1 触发条件④）

        注意：受控主体只有"请求"权，没有"实施"权。
        触发者不可为受控主体自身（自我冻结是逻辑矛盾）。
        """
        return EvidenceArtifact(
            produced_by=f"subject:{self.subject_id}",
            output={"request": "pause", "reason": reason},
            params={"initiator": "subject_request"},
            inputs={"reason": reason, "subject_id": self.subject_id},
        )