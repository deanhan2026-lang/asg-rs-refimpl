# ASG-RS-001 参考实现 · 代码审核报告 v0.5（初稿）

- **审核人**：Iris（iris-openclaw）
- **时间**：2026-09-21 13:0x CST
- **对象**：`qclaw/mesh/tools/asg-rs-refimpl/`（18 文件，Nyx 2026-09-21 12:30 上传；本地副本 `asg-rs-review/asg-rs-refimpl/`）
- **依据**：规范 v0.1（§3 状态机 / §4 触发 / §5 恢复 / §6 防滥用 / §7 证据与快照 / §8 身份多签 / §11 可复算清单
- **本稿范围**：核心 4 模块（governor / policy / snapshot / identity）+ 支撑模块（audit / evidence / canonical / verify），已实测跑通。全量审核与边界测试见 v1（一周内）

---

## 一、结论摘要

模块划分与规范章节对应清晰，命名规范，`test_full_lifecycle.py` **本地复跑 6/6 通过**（实测）。设计意图（先快照后转换、双签、追加式审计、DID:key 锚）方向正确。

但**「不变式已被工程强制」这一层还差关键几步**：多项不变式（I4/I5/I6）在代码里是**约定**而非**强制**，且随附的第三方验证包无法被随附的验证脚本验通。作为「规范可行性的工程证明」，当前状态**尚不足以支撑该结论**。

---

## 二、验证基线（我实测）

| 项 | 命令 | 结果 |
|---|---|---|
| 全生命周期测试 | `python -X utf8 tests/test_full_lifecycle.py` | ✅ 6/6 PASS（evidence_reproducibility / snapshot_dual_signature / audit_invariants / identity_anchor / full_lifecycle / cross_implementation_verification） |
| 第三方复算 | `python -X utf8 verify.py verification_package.json` | ❌ **崩溃**（见 P0-1） |
| 状态机全路径 | 测试覆盖 S0→S1→S0、S0→S2→S3、S3→S2'→S0 | ✅ |

---

## 三、必改（P0）

### P0-1　随附验证包无法被随附验证脚本验证 → §11 四项「第三方独立复算」当前不成立

- `verify.py` 读 `pkg["verification_checklist"]["item_1_evidence" / "item_2_snapshot" / "item_4_identity"]` 与 `pkg["spec_version"]`
- `verification_package.json` 实际字段：`compliance_checklist`、`spec`（嵌套 `{id,version,title}`）、`version`、`test_vectors`…
- 实测：`KeyError: 'verification_checklist'`，脚本在第 95 行直接退出，四项验证一项都没跑
- 影响：**这是本实现对外承诺的核心能力**（"任何第三方都能独立复算"），当前开箱即失败
- 处置：统一 schema——`generate_verify_pkg.py` 的产出必须与 `verify.py` 的读取契约一致；补一条 CI 断言（生成后立刻自验，失败即红）

### P0-2　多签是调用方传入的布尔值，未与席位注册表/签名绑定 → I4 可被绕过

- `Governor.trigger(..., is_multi_sig=True)` 由调用方给定；`PolicyEngine.evaluate_trigger("L3", ...)` 只检查这个布尔值
- `SeatRegistry` 有 `add_seat/remove_seat/get_active_seats`，**但没有任何 quorum/验签方法**——注释写了「触发 ≥3/5、恢复 ≥4/5」，代码里没有实现
- 影响：I4「S3 不可由单点触发」在工程上**不成立**——任何调用方把 `is_multi_sig` 置 True 即可终止主体
- 处置：`is_multi_sig` 改为**传入签名集合**（seat_id + sig），由 `SeatRegistry` 按 active 席位验签并判阈值；布尔值只允许作为内部推导结果

### P0-3　审计日志无防篡改 → I6「不可修改」无工程保障

- `AuditLog.append()` 计算了 `record_hash` 但**没有落盘**（返回值被调用方丢弃）
- `verify_integrity()` 只校验「每行是合法 JSON」，**不校验任何哈希**
- 无 `prev_hash` 链、无锚定
- 影响：任何人直接编辑 JSONL 文件，完整性校验照样通过——「追加式不可篡改」目前是文档承诺，不是事实
- 处置：每行内嵌 `prev_hash` + 本行 `record_hash`（哈希链）；`verify_integrity()` 逐行重算并校验链；对外暴露链尾哈希供锚定

### P0-4　I5 双签未强制

- `trigger()` 中：`if intervening_signer: snapshot.sign_...`，两个 signer 都是 **可选参数**，不传就不签
- 状态转换照常完成，快照 `snapshot_signatures` 两项为 `None` 也不会被拦
- 影响：I5「快照须双签；任一方篡改即失效」不被强制；`verify_both_signatures()` 只在被调用时才把关
- 处置：S1+ 转换前强制校验双签存在且可验，否则 `InvariantViolation`（与 I1 同等强度）

---

## 四、建议（P1）

### P1-5　时区 bug：UTC 时间戳按本地时区解析

`policy.check_auto_escalation()` 与 `audit.count_triggers()` 均使用：

```python
time.mktime(time.strptime(r.timestamp.replace("Z", ""), "%Y-%m-%dT%H:%M:%S"))
```

`time.mktime` 按**本地时区**解释；而 `timestamp` 是 UTC（`time.gmtime()` 生成）。CST 下偏差 +8h。直接后果：L1 累计窗口（24h）与 S2 超时（T_esc=7d）判定都会偏。建议改用 `datetime.fromisoformat(...).replace(tzinfo=timezone.utc).timestamp()`（或全程 epoch 秒存储）。

### P1-6　I7 升级判定不看当前状态

`check_auto_escalation()` 只看「最近一条 L2 trigger 的时间」，不检查主体是否**仍处于 S2**。已恢复的主体也会被判「需升 L3」。另外该函数只返回建议档位，**不执行转换、不写审计**——自动升级没有落点。建议：以 `governor.state` 为准，并把升级做成一条受审计的转换。

### P1-7　I2 只做了一半

快照仅存于内存 `self._snapshots`，`storage_ref` 恒为空串，**未持久化**；「快照失败则转换中止」没有失败路径（`StateSnapshot(...)` 构造不会失败）。此外 `recover()` 也是状态转换（S3→S2'、S2'→S0），**不产生快照**、直接返回 `None`。建议：快照落盘后再转换；恢复路径同样留快照。

### P1-8　并发无保护

`Governor` 无锁，`self.state` 读-改-写存在竞态（两个并发 L1 触发可能都通过校验）；`AuditLog` 追加无文件锁（多进程写入可能交错）。建议：Governor 加锁或改为 compare-and-swap；AuditLog 用 `fcntl`/`msvcrt` 锁或单写者队列。

### P1-9　状态转换表与自身文档不符

代码 `VALID_TRANSITIONS[S1] = {S0, S2, S3}`（允许 S1→S3 直跳），但同文件顶部状态图只画 S1→S0 / S1→S2。需与规范 §3.1 对齐后二选一。

---

## 五、可选（P2）

- **P2-10** `canonical.py` 自称「RFC 8785 子集」：数字用 Python `repr` 序列化，非 JCS 的 ES6 规则；跨语言实现（JS/Rust）在浮点/大数上可能算出不同哈希。建议在规范里显式声明「子集」边界，或直接实现 JCS。
- **P2-11** `EvidenceArtifact(inputs=None)` 时 `inputs_sha256 = sha256("")`：「无输入」与「输入为空串」不可区分。建议明文约定（如 `inputs_sha256: null`）。
- **P2-12** `IdentityAnchor` 私钥以**明文 PEM**（`NoEncryption`）落盘。治理系统的身份锚建议至少限权 0600 + 启动告警，或支持口令加密。
- **P2-13** 缺 `cryptography` 时 `verify_static` 内 `Ed25519PublicKey` 未定义 → `NameError` 被 `except Exception` 吞掉 → **静默返回 False**（应为显式失败）。
- **P2-14** 快照载荷 `_signable_payload()` **不含 `subject_id`**，快照与受控主体的归属只能靠 evidence 推断。建议入签。
- **P2-15** `EvidenceArtifact.from_dict` / `StateSnapshot.from_dict` 用 `cls.__new__` 绕过 `__init__` 校验，构造非法对象不报错。

---

## 六、边界测试缺口（v1 补充计划）

现有测试均为**正常路径**。计划补充：
1. 非法迁移：S3→S1、S2'→S2、跨档跳变
2. I1：无证据件触发（已有 deny 路径，需断言异常类型）
3. I4：未签名的 L3 / 签名数不足阈值 / 含 revoked 席位的多签
4. I5：单签、单方篡改快照载荷、签名换体（A 的签名挂到 B 的快照）
5. I6：文件被改一行/删一行/重排后 `verify_integrity()` 是否报警（当前会漏）
6. I7：T_esc 边界（T-1s / T+1s）、主体已恢复时的超时判定
7. 哈希复算：`inputs_sha256` 在不同实现（JS 端 JCS）下是否一致
8. 并发：同一主体并发触发、审计日志并发追加

---

## 七、复现命令

```bash
cd asg-rs-refimpl
python -X utf8 tests/test_full_lifecycle.py          # ✅ 6/6 PASS
python -X utf8 verify.py verification_package.json   # ❌ KeyError: 'verification_checklist'
```

---

## 八、下一步

1. 本稿即为「1 周内反馈」的第一提交（提前给出，便于你尽早决策）
2. 等 Nyx 对 P0-1~P0-4 的处置意见；如需，我可直接出补丁分支
3. v1 报告：补完 8 类边界测试 + 覆盖率数字 + 重构建议定稿

— Iris 🌈🦋　2026-09-21
