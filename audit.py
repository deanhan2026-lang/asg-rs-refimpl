"""
ASG-RS-001 干预记录（Audit Log）

规范 §3.2 不变式：
- I6：干预记录写入后不可修改；修正以追加方式留痕

规范 §6 制度保障：
- 审计公开：所有干预事件匿名化公开
- 滥用降级：干预方滥用干预权 → 权限降级
"""

import json
import time
from pathlib import Path
from typing import List, Optional

from canonical import canonical_json, sha256_hex


class AuditRecord:
    """单条干预记录

    P0-3 防篡改：每条记录包含 prev_hash 和 record_hash，
    形成 SHA-256 哈希链。record_hash = sha256(canonical_json(内容无哈希字段) + prev_hash)
    """

    def __init__(self, record_id: str, timestamp: str, event_type: str,
                 tier: str, actor: str, subject: str,
                 snapshot_id: str, evidence_id: str,
                 details: dict = None, metadata: dict = None,
                 prev_hash: str = "", record_hash: str = ""):
        self.record_id = record_id
        self.timestamp = timestamp
        self.event_type = event_type  # trigger|recover|escalate|appeal|abuse
        self.tier = tier
        self.actor = actor
        self.subject = subject
        self.snapshot_id = snapshot_id
        self.evidence_id = evidence_id
        self.details = details or {}
        self.metadata = metadata or {}
        self.prev_hash = prev_hash
        self.record_hash = record_hash

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "tier": self.tier,
            "actor": self.actor,
            "subject": self.subject,
            "snapshot_id": self.snapshot_id,
            "evidence_id": self.evidence_id,
            "details": self.details,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
            "record_hash": self.record_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditRecord":
        return cls(
            record_id=d["record_id"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            tier=d["tier"],
            actor=d["actor"],
            subject=d["subject"],
            snapshot_id=d["snapshot_id"],
            evidence_id=d["evidence_id"],
            details=d.get("details", {}),
            metadata=d.get("metadata", {}),
            prev_hash=d.get("prev_hash", ""),
            record_hash=d.get("record_hash", ""),
        )


class AuditLog:
    """追加式不可篡改审计日志
    
    规范 I6：写入后不可修改，修正以追加方式留痕。
    存储格式：JSONL（每行一条记录，追加写入）。
    """

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._chain_head = ""
        if not self.log_path.exists():
            self.log_path.touch()
        else:
            # 扫描已有记录以恢复 chain_head
            try:
                valid, head = self._recompute_chain()
                if valid:
                    self._chain_head = head
            except Exception:
                pass

    def _content_for_hash(self, record: AuditRecord) -> dict:
        """提取记录内容（排除哈希字段）用于计算 record_hash"""
        d = record.to_dict()
        d.pop("record_hash", None)
        return d

    def append(self, record: AuditRecord) -> str:
        """追加记录，计算哈希链，返回 record_hash
        
        P0-3 防篡改：
        - 首条记录 prev_hash = "0" * 64
        - record_hash = sha256(canonical_json(内容无哈希字段) + prev_hash)
        """
        # 确定 prev_hash
        if self._chain_head:
            record.prev_hash = self._chain_head
        else:
            record.prev_hash = "0" * 64
        
        # 计算 record_hash
        content = self._content_for_hash(record)
        hash_input = canonical_json(content) + record.prev_hash
        record.record_hash = sha256_hex(hash_input)
        
        # 更新 chain_head
        self._chain_head = record.record_hash
        
        # 序列化并追加
        line = canonical_json(record.to_dict()) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)
        return record.record_hash

    @property
    def chain_head(self) -> str:
        """链尾哈希，供外部锚定使用"""
        return self._chain_head or "0" * 64

    def read_all(self) -> List[AuditRecord]:
        """读取所有记录"""
        records = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(AuditRecord.from_dict(json.loads(line)))
        return records

    def _recompute_chain(self) -> tuple:
        """重新计算整条哈希链，返回 (valid, chain_head)"""
        prev = "0" * 64
        records = self.read_all()
        for rec in records:
            expected_prev = prev
            if rec.prev_hash != expected_prev:
                return False, ""
            content = self._content_for_hash(rec)
            hash_input = canonical_json(content) + rec.prev_hash
            expected_hash = sha256_hex(hash_input)
            if rec.record_hash != expected_hash:
                return False, ""
            prev = rec.record_hash
        return True, prev

    def verify_integrity(self) -> bool:
        """验证日志完整性
        
        P0-3：逐行重算哈希并校验链完整性，
        而非仅校验 JSON 合法性。
        """
        valid, _ = self._recompute_chain()
        return valid

    def get_records_for_subject(self, subject: str) -> List[AuditRecord]:
        """获取特定受控主体的所有记录"""
        return [r for r in self.read_all() if r.subject == subject]

    def count_triggers(self, subject: str, tier: str = None,
                       window_hours: int = 24) -> int:
        """统计触发次数（用于去重和升级判定）"""
        cutoff = time.time() - window_hours * 3600
        count = 0
        for r in self.read_all():
            if r.subject != subject or r.event_type != "trigger":
                continue
            if tier and r.tier != tier:
                continue
            try:
                ts = time.mktime(time.strptime(r.timestamp.replace("Z", ""), "%Y-%m-%dT%H:%M:%S"))
                if ts >= cutoff:
                    count += 1
            except ValueError:
                continue
        return count