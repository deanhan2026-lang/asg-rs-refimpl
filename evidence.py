"""
ASG-RS-001 证据件（Evidence Artifact）

规范 §7.1 要求：
- artifact_id (uuid)
- produced_by (monitor id)
- produced_at (ISO-8601)
- inputs_sha256 (SHA-256 of canonical inputs)
- output (判定结果, 数值化优先)
- params (基线、阈值等参数)

零幻觉原则：快照中不得出现无法被复算的字段。
"""

import uuid
import time
from typing import Any, Optional

from canonical import canonical_json, sha256_hex


class EvidenceArtifact:
    """证据件：一次干预所依据的可独立复算材料"""

    def __init__(self, produced_by: str, output: Any, params: dict,
                 inputs: Optional[Any] = None, artifact_id: Optional[str] = None,
                 produced_at: Optional[str] = None):
        self.artifact_id = artifact_id or str(uuid.uuid4())
        self.produced_by = produced_by
        self.produced_at = produced_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # inputs_sha256 = SHA-256(canonical_json(inputs))
        # 如果 inputs 为 None，用空字符串的哈希
        self.inputs_sha256 = sha256_hex(inputs if inputs is not None else "")
        self.output = output
        self.params = params

    def to_dict(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "produced_by": self.produced_by,
            "produced_at": self.produced_at,
            "inputs_sha256": self.inputs_sha256,
            "output": self.output,
            "params": self.params,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceArtifact":
        obj = cls.__new__(cls)
        obj.artifact_id = d["artifact_id"]
        obj.produced_by = d["produced_by"]
        obj.produced_at = d["produced_at"]
        obj.inputs_sha256 = d["inputs_sha256"]
        obj.output = d["output"]
        obj.params = d["params"]
        return obj

    def verify_inputs(self, inputs: Any) -> bool:
        """验证 inputs_sha256 是否与给定 inputs 匹配"""
        return sha256_hex(inputs) == self.inputs_sha256