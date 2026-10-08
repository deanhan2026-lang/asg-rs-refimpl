"""
ASG-RS-001 规范化 JSON（Canonical JSON）

规范 §7.2 要求：
- 键排序（递归）
- 紧凑（无多余空白）
- UTF-8 无 BOM
- 浮点用最短表示（IEEE 754）
- 时间戳 ISO-8601

实现基于 RFC 8785 子集。
"""

import json
import hashlib
from typing import Any


def canonical_json(obj: Any) -> str:
    """RFC 8785 子集：递归键排序 + 紧凑 JSON
    
    与 ed25519_signer.py 的 _canonical_json 一致，
    但作为独立模块供 ASG-RS-001 全局使用。
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_bytes(obj: Any) -> bytes:
    """规范化 JSON 的 UTF-8 字节（无 BOM）"""
    return canonical_json(obj).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    """SHA-256(canonical_json(obj)) → hex"""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """SHA-256(raw bytes) → hex"""
    return hashlib.sha256(data).hexdigest()