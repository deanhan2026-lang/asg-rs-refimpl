"""
ASG-RS-001 身份锚（Identity Anchor）

规范 §8 要求：
- 可验签的身份锚（任何公私钥体系皆可）
- 可锚定的席位（多签席位绑定到身份锚）
- 被终止主体身份锚保留（status=terminated，不销毁）

本实现使用 Ed25519，与 MeshIdentity 的 did:key 一致。
"""

import json
import os
import time
from pathlib import Path
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

from canonical import canonical_json, sha256_hex

# 域前缀（ASG-RS-001 专用，与 ANIMA-PLUGIN-TOKEN-v1 隔离）
DOMAIN_PREFIX = b"ANIMA-ASG-RS-001-v1"


class IdentityAnchor:
    """身份锚：Ed25519 密钥对 + DID:key 推导"""

    def __init__(self, node_id: str, key_dir: str):
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography library not available")
        self.node_id = node_id
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._public_key: Optional[Ed25519PublicKey] = None
        self._load_or_generate()

    def _load_or_generate(self):
        priv_path = self.key_dir / f"{self.node_id}_ed25519_private.pem"
        pub_path = self.key_dir / f"{self.node_id}_ed25519_public.pem"

        if priv_path.exists() and pub_path.exists():
            with open(priv_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(pub_path, "rb") as f:
                self._public_key = serialization.load_pem_public_key(f.read())
        else:
            self._private_key = Ed25519PrivateKey.generate()
            self._public_key = self._private_key.public_key()
            with open(priv_path, "wb") as f:
                f.write(self._private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            with open(pub_path, "wb") as f:
                f.write(self._public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ))

    @property
    def public_key_hex(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    @property
    def did(self) -> str:
        """推导 did:key（multicodec Ed25519）"""
        # multicodec prefix for Ed25519: 0xed01
        pub_raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        import base58
        multicodec_bytes = bytes.fromhex("ed01") + pub_raw
        return f"did:key:z{base58.b58encode(multicodec_bytes).decode()}"

    def sign(self, payload: dict) -> str:
        """签名：Ed25519_sign(sk, DOMAIN_PREFIX || SHA256(canonical_json(payload)))
        返回 hex 签名
        """
        import hashlib
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).digest()
        message = DOMAIN_PREFIX + digest
        return self._private_key.sign(message).hex()

    def verify(self, payload: dict, signature_hex: str,
               public_key_hex: Optional[str] = None) -> bool:
        """验签"""
        try:
            if public_key_hex:
                pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            else:
                pub_key = self._public_key
            import hashlib
            digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).digest()
            message = DOMAIN_PREFIX + digest
            pub_key.verify(bytes.fromhex(signature_hex), message)
            return True
        except Exception:
            return False

    @staticmethod
    def verify_static(payload: dict, signature_hex: str, public_key_hex: str) -> bool:
        """静态验签（不需要私钥）"""
        try:
            pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            import hashlib
            digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).digest()
            message = DOMAIN_PREFIX + digest
            pub_key.verify(bytes.fromhex(signature_hex), message)
            return True
        except Exception:
            return False

    @staticmethod
    def verify_static_string(message: str, signature_hex: str, public_key_hex: str) -> bool:
        """静态验签（消息为字符串，用于多签验签）"""
        try:
            pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            import hashlib
            digest = hashlib.sha256(message.encode("utf-8")).digest()
            msg = DOMAIN_PREFIX + digest
            pub_key.verify(bytes.fromhex(signature_hex), msg)
            return True
        except Exception:
            return False


class SeatRegistry:
    """多签席位注册表
    
    规范 §8.1：5 席（技术管理、伦理、法律、受控方代表、社区）
    触发 ≥3/5，恢复 ≥4/5（I3：恢复门槛 ≥ 触发门槛）
    """

    def __init__(self):
        self.seats: dict = {}  # seat_id → {role, public_key_hex, did, status}

    def add_seat(self, seat_id: str, role: str, public_key_hex: str, did: str = ""):
        self.seats[seat_id] = {
            "role": role,
            "public_key_hex": public_key_hex,
            "did": did,
            "status": "active",
        }

    def remove_seat(self, seat_id: str):
        if seat_id in self.seats:
            self.seats[seat_id]["status"] = "revoked"

    def get_active_seats(self) -> dict:
        return {k: v for k, v in self.seats.items() if v["status"] == "active"}

    # 席位法定人数阈值（规范 §8.1）
    QUORUM_THRESHOLDS = {
        "trigger": 3,   # 触发 ≥3/5
        "recover": 4,   # 恢复 ≥4/5
    }

    def verify_quorum(self, payload, signatures: list,
                      action_type: str = "trigger") -> bool:
        """验证多签法定人数（规范 §8.1）
        
        Args:
            payload: 被签名的载荷（dict，用 canonical_json 序列化后签名）
            signatures: [(seat_id, signature_hex), ...]
            action_type: "trigger"(≥3/5) 或 "recover"(≥4/5)
        
        Returns:
            True if quorum threshold is met with all signatures valid
        """
        active = self.get_active_seats()
        threshold = self.QUORUM_THRESHOLDS.get(action_type, 3)
        valid_count = 0
        seen = set()
        
        for seat_id, sig_hex in signatures:
            if seat_id in seen:
                continue
            if seat_id not in active:
                continue
            
            pub_hex = active[seat_id]["public_key_hex"]
            if IdentityAnchor.verify_static(payload, sig_hex, pub_hex):
                valid_count += 1
                seen.add(seat_id)
        
        return valid_count >= threshold

    def to_dict(self) -> dict:
        return {"seats": self.seats}

    @classmethod
    def from_dict(cls, d: dict) -> "SeatRegistry":
        reg = cls()
        reg.seats = d.get("seats", {})
        return reg