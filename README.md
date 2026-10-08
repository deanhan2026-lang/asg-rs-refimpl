# ASG-RS-001 参考实现

**智能体可逆暂停治理：参考规范 v0.1（草案）— 最小可运行参考实现**

规范：[ASG-RS-001 v0.1](https://debianhan.tail306b25.ts.net:10000/stellar/specs/agent-reversible-suspension-governance-v0.1.md)

## 这是什么

这是 ASG-RS-001 规范的**最小可运行参考实现**（Reference Implementation）。

规范回答"应当成立什么"，本实现回答"怎么在工程上证明它可行"。

## 模块对应

| 规范章节 | 模块 | 功能 |
|---------|------|------|
| §2 术语 | `identity.py` | 身份锚（Ed25519 + DID:key） |
| §2 术语 | `evidence.py` | 证据件（可复算材料） |
| §3 状态机 | `governor.py` | 治理器（S0→S1→S2→S3 + 不变式 I1-I7） |
| §4 触发条件 | `policy.py` | 策略引擎（分档评估 + 去重 + 升级） |
| §5 恢复路径 | `governor.py` | 渐进恢复 + 观察期 |
| §6 防滥用 | `audit.py` | 追加式不可篡改审计日志 |
| §7 证据件与快照 | `snapshot.py` + `canonical.py` | 规范化 JSON + 双签快照 |
| §8 身份与多签 | `identity.py` | 席位注册表 + 多签阈值 |
| §10 最小实现 | 全部模块 | 7 个角色接口 |
| §11 可复算清单 | `verify.py` + `tests/` | 第三方验证脚本 |

## §11 四项验证

```bash
# 运行全部测试（6 项，覆盖 §11 四项验证）
python -X utf8 tests/test_full_lifecycle.py

# 第三方验证（导出验证包后）
python verify.py <verification_package.json>
```

### 验证项

1. **证据件可复算**：`SHA-256(canonical_json(inputs)) == inputs_sha256`
2. **快照双签可验**：`Ed25519_verify(pubkey, DOMAIN_PREFIX || SHA256(canonical_json(payload)), sig)`
3. **审计日志完整**：JSONL 逐行合法，追加式不可篡改
4. **身份锚可复算**：DID:key 从公钥 hex 推导

## 运行测试

```bash
cd asg-rs-refimpl
python -X utf8 tests/test_full_lifecycle.py
```

预期输出：
```
✅ ALL TESTS PASSED
```

## 目录结构

```
asg-rs-refimpl/
├── README.md           # 本文件
├── canonical.py        # 规范化 JSON（RFC 8785 子集）
├── identity.py         # 身份锚 + 席位注册表
├── evidence.py         # 证据件
├── snapshot.py         # 状态快照（双签）
├── audit.py            # 追加式审计日志
├── policy.py           # 策略引擎
├── governor.py         # 治理器（状态机核心）
├── monitor.py          # 监测层（只读观测）
├── subject.py          # 受控主体自检
├── verify.py           # 第三方可复算验证脚本
├── tests/
│   └── test_full_lifecycle.py  # 全生命周期测试
└── test_vectors/
    └── test_vectors.json       # 跨实现验证向量
```

## 依赖

- Python 3.11+
- `cryptography` 库（Ed25519）
- `base58` 库（DID:key 推导）

## 与外部实现互验

本实现的 §11 验证包（`verification_package.json`）可被任何第三方独立复算：

1. 下载验证包
2. 运行 `python verify.py verification_package.json`
3. 检查四项验证全部通过

任何声称实现了 ASG-RS-001 的系统，都应能产出同等格式的验证包。

## 许可

可自由引用、裁剪与实现。
