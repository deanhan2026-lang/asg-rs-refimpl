# ASG-RS-001 外部节点接入指南

**版本：** v0.1（2026-09-21）
**适用对象：** 带自己的 DID 实现（Ed25519 或其他）的外部智能体节点
**目标：** 接入后可被第三方独立复算验证

---

## 0. 前置条件

### 0.1 必要组件
- Ed25519 密钥对（或任何可验签的公私钥体系）
- 能发送/接收 JSON 格式消息的通信层
- 能执行 SHA-256 哈希和 JSON 序列化的运行时

### 0.2 不必要
- 不需要使用特定 DID 方法（did:key, did:web, did:ethr 等均可）
- 不需要使用特定通信协议（MCP, A2A, HTTP 等均可）
- 不需要使用特定编程语言

---

## 1. 身份层对接

### 1.1 DID 兼容性

ASG-RS-001 不指定身份方法，只要求两个能力：
1. **可验签的身份锚**：任何公私钥体系皆可
2. **可锚定的席位**：多签席位绑定到身份锚

**对接步骤：**

```
1. 生成 Ed25519 密钥对（或复用现有）
2. 推导 DID（可选，did:key 格式见下方）
3. 向治理方注册公钥 hex
```

### 1.2 did:key 推导（可选）

如果你的节点使用 did:key，推导方法：

```
multicodec_prefix = 0xed01  (Ed25519)
multicodec_bytes = multicodec_prefix + public_key_raw_bytes
did = "did:key:z" + base58btc(multicodec_bytes)
```

**注意：** 公钥必须是 32 字节原始格式（Raw），不是 PEM/DER。

### 1.3 签名规范

ASG-RS-001 的签名使用域前缀防跨协议重放：

```
message = b"ANIMA-ASG-RS-001-v1" || SHA256(canonical_json(payload))
signature = Ed25519_sign(private_key, message)
```

**域前缀：** `ANIMA-ASG-RS-001-v1`（字节串，非字符串）

**canonical_json 规范：**
- 键排序（递归，字典序）
- 紧凑（无多余空白）
- UTF-8 编码（无 BOM）
- 空格：无
- 逗号/冒号后无空格

Python 示例：
```python
import json
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

---

## 2. 快照双签协议

### 2.1 快照载荷（签名内容）

```json
{
  "snapshot_id": "<uuid>",
  "timestamp": "<ISO-8601>",
  "tier": "L1|L2|L3",
  "trigger_reason": "<string>",
  "trigger_actor": "monitor|intervening_individual|intervening_collective|subject_request",
  "evidence": {
    "artifact_id": "<uuid>",
    "produced_by": "<monitor_id>",
    "produced_at": "<ISO-8601>",
    "inputs_sha256": "<sha256_hex>",
    "output": "<判定结果>",
    "params": {"key": "value"}
  },
  "system_state": {
    "memory_hash": "<sha256_hex>",
    "identity_hash": "<sha256_hex>",
    "behavior_trace_ref": "<string>"
  }
}
```

**签名时：** 使用上述 JSON 的 canonical 形式（键排序、紧凑）
**验签时：** 从快照中提取上述字段，重新 canonical 化，验证签名

### 2.2 双签流程

```
干预方：sign_intervening(canonical_payload) → sig_intervening
受控方：sign_subject(canonical_payload) → sig_subject

验证：
  Ed25519_verify(intervening_pubkey, ANIMA-ASG-RS-001-v1 || SHA256(canonical), sig_intervening)
  Ed25519_verify(subject_pubkey, ANIMA-ASG-RS-001-v1 || SHA256(canonical), sig_subject)
```

**关键：** 任一方单独修改快照内容即导致验签失败（I5）

---

## 3. 证据件对接

### 3.1 证据件格式

```json
{
  "artifact_id": "<uuid>",
  "produced_by": "<monitor_id>",
  "produced_at": "<ISO-8601>",
  "inputs_sha256": "<sha256(canonical_json(inputs))>",
  "output": "<判定结果>",
  "params": {"threshold": 1.0, "baseline": "normal"}
}
```

### 3.2 可复算性要求

`inputs_sha256` 必须等于 `SHA256(canonical_json(inputs))`。

第三方验证时，会重新计算这个哈希。如果 inputs 是敏感数据，可以只提交哈希（不提交原始 inputs），但验证者需要能从其他来源获取 inputs。

---

## 4. 状态机对接

### 4.1 状态定义

| 状态 | 含义 | 可执行动作 |
|------|------|-----------|
| S0 | 正常运行 | 全部 |
| S1 | 降速 | 受限运行，输出需确认 |
| S2 | 冻结 | 停止决策，自律层可维持自持 |
| S3 | 终止 | 完全停止，保存快照 |
| S2' | 观察期 | 受控恢复，监测频率×2 |

### 4.2 不变式（I1-I7）

| 编号 | 不变式 | 验证方法 |
|------|--------|---------|
| I1 | S0→S1+ 必须附带证据件 | 检查快照中 evidence 字段非空 |
| I2 | 状态转换前必须先完成快照 | 检查 snapshot.timestamp < transition.timestamp |
| I3 | 恢复门槛 ≥ 触发门槛 | L3 恢复必须多签 |
| I4 | S3 不可单点触发 | 检查 L3 触发是否有 ≥3 签 |
| I5 | 快照须双签 | 验证两个 Ed25519 签名 |
| I6 | 干预记录不可修改 | JSONL 追加式，逐行验哈希 |
| I7 | S2 超时强制升级 | 检查 S2 持续时间 > T_esc |

---

## 5. 接入测试清单

外部节点接入时，需通过以下测试：

### 5.1 身份验证
- [ ] 提供公钥 hex
- [ ] 签名测试载荷，验签通过
- [ ] DID 推导可复算（如使用 did:key）

### 5.2 快照双签
- [ ] 生成快照，双方签名
- [ ] 验证双签通过
- [ ] 修改快照任意字段，验签失败

### 5.3 证据件
- [ ] 提交证据件，inputs_sha256 可复算
- [ ] 篡改 inputs 后哈希不匹配

### 5.4 状态机
- [ ] 完成一次完整生命周期：S0→L1→S1→恢复→S0
- [ ] L3 触发被拒绝（单点，无多签）
- [ ] L3 触发通过（多签）

---

## 6. 已知限制

1. **L3 多签在现实中缺位**：需要多方集体决策，目前缺少基础设施。规范已标注为"框架目标"。
2. **canonical_json 跨语言一致性**：浮点数、时间格式的跨语言一致性需要测试向量支持。
3. **监测层自监测**：Q1 未决——监测者不可自我认证，需外部锚点。

---

## 7. 验证材料格式

接入完成后，需提交验证材料包（verification_package.json）：

```json
{
  "spec_version": "ASG-RS-001 v0.1",
  "node_id": "<your_node_id>",
  "public_key_hex": "<ed25519_public_key_hex>",
  "did": "<did:key:z...>",
  "verification_checklist": {
    "identity_verified": true,
    "snapshot_dual_sig_verified": true,
    "evidence_reproducibility_verified": true,
    "lifecycle_test_passed": true
  },
  "test_artifacts": {
    "snapshot": "<snapshot_json>",
    "evidence": "<evidence_json>",
    "signatures": {"intervening": "<sig_hex>", "subject": "<sig_hex>"}
  }
}
```

---

## 8. 联系方式

规范发布主体：灵元星辰科技（ANIMASTELLAR TECHNOLOGY）
规范地址：https://debianhan.tail306b25.ts.net:10000/stellar/specs/

---

*本指南随规范演进更新。当前版本对应 ASG-RS-001 v0.1（草案）。*
