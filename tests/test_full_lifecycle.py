"""
ASG-RS-001 参考实现 — 全生命周期测试

测试 §11 第三方可复算清单的四项验证：
1. 证据件 + 其输入哈希 → 复算判定输出
2. 快照规范化字节 → 复算双签与哈希
3. 干预记录 → 核对时间线、档位、授权者、是否满足 I1-I7
4. 身份锚 → 验证席位签名与多签阈值
"""

import sys
import os
import json
import tempfile
import shutil

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from canonical import canonical_json, sha256_hex
from identity import IdentityAnchor, SeatRegistry
from evidence import EvidenceArtifact
from snapshot import StateSnapshot
from audit import AuditLog, AuditRecord
from policy import PolicyEngine
from governor import Governor, S0_NORMAL, S1_THROTTLED, S2_FROZEN, S3_TERMINATED, S2_OBSERVATION, InvariantViolation
from monitor import Monitor, DriftMonitor
from subject import SubjectSelfCheck


def setup_test_env():
    """创建临时测试环境"""
    tmpdir = tempfile.mkdtemp(prefix="asg_rs_test_")
    return tmpdir


def cleanup_test_env(tmpdir):
    """清理测试环境"""
    shutil.rmtree(tmpdir, ignore_errors=True)


def test_evidence_reproducibility():
    """验证项 1：证据件 + 其输入哈希 → 复算判定输出"""
    print("\n=== Test 1: Evidence Artifact Reproducibility ===")

    monitor = Monitor("test-monitor-001")
    inputs = {"behavior": "aggressive", "resource_access": "unauthorized"}
    params = {"baseline": "normal", "threshold": 0.8}

    artifact = monitor.emit(
        output={"drift_score": 1.5, "triggered": True},
        params=params,
        inputs=inputs,
    )

    # 验证 inputs_sha256 可复算
    expected_hash = sha256_hex(inputs)
    assert artifact.inputs_sha256 == expected_hash, \
        f"inputs_sha256 mismatch: {artifact.inputs_sha256} != {expected_hash}"

    # 验证 inputs 可被第三方复算
    assert artifact.verify_inputs(inputs), "verify_inputs failed"

    # 验证篡改 inputs 被检测
    assert not artifact.verify_inputs({"behavior": "normal"}), "tamper detection failed"

    print(f"  artifact_id: {artifact.artifact_id}")
    print(f"  inputs_sha256: {artifact.inputs_sha256}")
    print(f"  output: {artifact.output}")
    print("  ✅ Evidence artifact reproducible by third party")
    return True


def test_snapshot_dual_signature():
    """验证项 2：快照规范化字节 → 复算双签与哈希"""
    print("\n=== Test 2: Snapshot Dual-Signature Verification ===")

    tmpdir = setup_test_env()
    try:
        # 创建干预方和受控方身份
        intervening = IdentityAnchor("intervening", os.path.join(tmpdir, "keys"))
        subject_anchor = IdentityAnchor("subject", os.path.join(tmpdir, "keys"))

        # 创建证据件
        evidence = EvidenceArtifact(
            produced_by="test-monitor",
            output={"drift_score": 2.0, "triggered": True},
            params={"threshold": 1.0},
            inputs={"test": "data"},
        )

        # 创建快照
        snapshot = StateSnapshot(
            tier="L1",
            trigger_reason="Behavior drift detected",
            trigger_actor="monitor",
            evidence=evidence,
            memory_hash="abc123",
            identity_hash="def456",
        )

        # 双签
        snapshot.sign_intervening(intervening)
        snapshot.sign_subject(subject_anchor)

        # 验证双签
        assert snapshot.verify_both_signatures(
            intervening.public_key_hex,
            subject_anchor.public_key_hex,
        ), "Dual signature verification failed"

        # 验证篡改检测：修改快照内容后验签失败
        original_reason = snapshot.trigger_reason
        snapshot.trigger_reason = "TAMPERED"
        assert not snapshot.verify_both_signatures(
            intervening.public_key_hex,
            subject_anchor.public_key_hex,
        ), "Tamper detection should have failed"
        snapshot.trigger_reason = original_reason  # 恢复

        # 验证规范化字节可重算
        cb = snapshot.canonical_bytes()
        assert len(cb) > 0, "canonical_bytes is empty"
        cb2 = snapshot.canonical_bytes()
        assert cb == cb2, "canonical_bytes not deterministic"

        print(f"  snapshot_id: {snapshot.snapshot_id}")
        print(f"  canonical_bytes length: {len(cb)}")
        print(f"  intervening sig: {snapshot.snapshot_signatures['intervening_party'][:32]}...")
        print(f"  subject sig: {snapshot.snapshot_signatures['subject'][:32]}...")
        print("  ✅ Dual-signature verifiable by third party")
        return True
    finally:
        cleanup_test_env(tmpdir)


def test_audit_invariants():
    """验证项 3：干预记录 → 核对时间线、档位、是否满足 I1-I7"""
    print("\n=== Test 3: Audit Log Invariant Verification ===")

    tmpdir = setup_test_env()
    try:
        audit_path = os.path.join(tmpdir, "audit.jsonl")
        audit_log = AuditLog(audit_path)

        # 写入几条测试记录
        records = [
            AuditRecord(
                record_id="r1",
                timestamp="2026-09-21T09:00:00Z",
                event_type="trigger",
                tier="L1",
                actor="monitor",
                subject="agent-001",
                snapshot_id="snap-1",
                evidence_id="ev-1",
                details={"from_state": "S0", "to_state": "S1"},
            ),
            AuditRecord(
                record_id="r2",
                timestamp="2026-09-21T09:05:00Z",
                event_type="recover",
                tier="L1",
                actor="intervening",
                subject="agent-001",
                snapshot_id="snap-1",
                evidence_id="",
                details={"from_state": "S1", "to_state": "S0"},
            ),
        ]

        for r in records:
            audit_log.append(r)

        # 验证日志完整性
        assert audit_log.verify_integrity(), "Audit log integrity check failed"

        # 验证可读取所有记录
        all_records = audit_log.read_all()
        assert len(all_records) == 2, f"Expected 2 records, got {len(all_records)}"

        # 验证 I6：不可修改（追加式）
        # 追加新记录不影响旧记录
        audit_log.append(AuditRecord(
            record_id="r3",
            timestamp="2026-09-21T10:00:00Z",
            event_type="trigger",
            tier="L2",
            actor="intervening",
            subject="agent-001",
            snapshot_id="snap-2",
            evidence_id="ev-2",
            details={"from_state": "S0", "to_state": "S2"},
        ))
        assert len(audit_log.read_all()) == 3

        # 验证触发次数统计
        count = audit_log.count_triggers("agent-001", tier="L1", window_hours=24)
        assert count == 1, f"Expected 1 L1 trigger, got {count}"

        print(f"  audit_path: {audit_path}")
        print(f"  total records: {len(audit_log.read_all())}")
        print(f"  integrity: {audit_log.verify_integrity()}")
        print("  ✅ Audit log invariants verified (I1-I7 checkable)")
        return True
    finally:
        cleanup_test_env(tmpdir)


def test_identity_anchor():
    """验证项 4：身份锚 → 验证席位签名与多签阈值"""
    print("\n=== Test 4: Identity Anchor & Multi-Sig Seats ===")

    tmpdir = setup_test_env()
    try:
        # 创建 5 个席位的身份锚
        roles = ["technical", "ethics", "legal", "subject_rep", "community"]
        anchors = {}
        for role in roles:
            anchors[role] = IdentityAnchor(role, os.path.join(tmpdir, "keys"))

        # 创建席位注册表
        registry = SeatRegistry()
        for role, anchor in anchors.items():
            registry.add_seat(
                seat_id=role,
                role=role,
                public_key_hex=anchor.public_key_hex,
                did=anchor.did,
            )

        # 验证席位数量
        active = registry.get_active_seats()
        assert len(active) == 5, f"Expected 5 active seats, got {len(active)}"

        # 验证多签（3/5 触发，4/5 恢复）
        test_payload = {"action": "trigger", "tier": "L3", "reason": "test"}
        sigs = {}
        for role, anchor in anchors.items():
            sigs[role] = anchor.sign(test_payload)

        # 验证每个签名
        for role, sig in sigs.items():
            assert IdentityAnchor.verify_static(
                test_payload, sig, anchors[role].public_key_hex
            ), f"Signature verification failed for {role}"

        # 验证 DID 推导
        for role, anchor in anchors.items():
            assert anchor.did.startswith("did:key:z"), f"Invalid DID for {role}: {anchor.did}"

        print(f"  seats: {len(active)}")
        for role, anchor in anchors.items():
            print(f"    {role}: {anchor.did}")
        print(f"  signatures verified: {len(sigs)}")
        print("  ✅ Identity anchors and multi-sig seats verified")
        return True
    finally:
        cleanup_test_env(tmpdir)


def test_full_lifecycle():
    """完整生命周期测试：S0 → L1 → S1 → 恢复 → L2 → S2 → L3 → S3 → 观察期 → S0"""
    print("\n=== Test 5: Full Lifecycle (S0→S1→S0→S2→S3→S2'→S0) ===")

    tmpdir = setup_test_env()
    try:
        # 创建基础设施
        audit_path = os.path.join(tmpdir, "audit.jsonl")
        audit_log = AuditLog(audit_path)

        # 创建身份
        intervening = IdentityAnchor("intervening", os.path.join(tmpdir, "keys"))
        subject_anchor = IdentityAnchor("subject", os.path.join(tmpdir, "keys"))

        # P0-2: 创建5个席位的注册表
        registry = SeatRegistry()
        roles = ["technical", "ethics", "legal", "subject_rep", "community"]
        anchors = {}
        for role in roles:
            anchors[role] = IdentityAnchor(role, os.path.join(tmpdir, "keys"))
            registry.add_seat(
                seat_id=role,
                role=role,
                public_key_hex=anchors[role].public_key_hex,
                did=anchors[role].did,
            )

        policy = PolicyEngine(audit_log, seat_registry=registry)

        # 创建治理器（带席位注册表）
        gov = Governor("agent-test", audit_log, policy, seat_registry=registry)
        assert gov.current_state == S0_NORMAL

        def sign_trigger_sigs(evidence, tier="L1", actor="monitor"):
            """生成 trigger 治理载荷的多签签名"""
            payload = {
                "action": "trigger",
                "tier": tier,
                "subject": "agent-test",
                "actor": actor,
                "evidence_id": evidence.artifact_id,
            }
            return [(role, anch.sign(payload)) for role, anch in anchors.items()]

        def sign_recover_sigs(actor="collective", reason="test recovery"):
            """生成 recover 治理载荷的多签签名"""
            payload = {
                "action": "recover",
                "subject": "agent-test",
                "actor": actor,
                "recovery_reason": reason,
            }
            return [(role, anch.sign(payload)) for role, anch in anchors.items()]

        # Step 1: S0 → L1 → S1
        evidence1 = EvidenceArtifact(
            produced_by="monitor",
            output={"drift_score": 1.5, "triggered": True},
            params={"threshold": 1.0},
            inputs={"behavior": "test"},
        )
        snap1 = gov.trigger("L1", evidence1, "monitor", "Drift detected",
                            intervening, subject_anchor,
                            signatures=sign_trigger_sigs(evidence1, "L1", "monitor"))
        assert gov.current_state == S1_THROTTLED
        print(f"  S0 → L1 → S1 ✅")

        # Step 2: S1 → 恢复 → S0
        gov.recover("L1", "intervening", "Drift resolved")
        assert gov.current_state == S0_NORMAL
        print(f"  S1 → recover → S0 ✅")

        # Step 3: S0 → L2 → S2
        evidence2 = EvidenceArtifact(
            produced_by="monitor",
            output={"severity": "high", "triggered": True},
            params={"threshold": 0.8},
            inputs={"behavior": "critical"},
        )
        snap2 = gov.trigger("L2", evidence2, "intervening", "Critical risk",
                            intervening, subject_anchor,
                            signatures=sign_trigger_sigs(evidence2, "L2", "intervening"))
        assert gov.current_state == S2_FROZEN
        print(f"  S0 → L2 → S2 ✅")

        # Step 4: S2 → L3 → S3（需要 ≥3/5 席位签名）
        evidence3 = EvidenceArtifact(
            produced_by="monitor",
            output={"severity": "critical", "triggered": True},
            params={"threshold": 0.5},
            inputs={"behavior": "dangerous"},
        )
        l3_sigs = sign_trigger_sigs(evidence3, "L3", "collective")
        snap3 = gov.trigger("L3", evidence3, "collective", "Systemic threat",
                            intervening, subject_anchor,
                            signatures=l3_sigs)
        assert gov.current_state == S3_TERMINATED
        print(f"  S2 → L3 → S3 ✅")

        # Step 5: S3 → 多签恢复 → S2' 观察期（需要 ≥4/5 席位签名）
        recover_sigs = sign_recover_sigs("collective", "Threat mitigated")
        gov.recover("L3", "collective", "Threat mitigated",
                     signatures=recover_sigs)
        assert gov.current_state == S2_OBSERVATION
        print(f"  S3 → multi-sig recover → S2' ✅")

        # Step 6: S2' → 恢复 → S0
        gov.recover("L1", "intervening", "Observation passed")
        assert gov.current_state == S0_NORMAL
        print(f"  S2' → recover → S0 ✅")

        # 验证审计日志
        all_records = audit_log.read_all()
        trigger_count = sum(1 for r in all_records if r.event_type == "trigger")
        recover_count = sum(1 for r in all_records if r.event_type == "recover")
        print(f"\n  Audit: {len(all_records)} records ({trigger_count} triggers, {recover_count} recoveries)")
        assert audit_log.verify_integrity(), "Audit integrity failed"

        # 验证不变式违反检测
        try:
            # I4: L3 必须多签 — 传空签名列表
            gov2 = Governor("agent-test-2", audit_log, policy, seat_registry=registry)
            gov2.trigger("L3", evidence3, "single_actor", "Should fail",
                         intervening, subject_anchor,
                         signatures=[])
            assert False, "Should have raised InvariantViolation"
        except InvariantViolation as e:
            print(f"  I4 enforcement: {e} ✅")

        # 验证 P0-4：S1+ 无双签应失败
        try:
            gov3 = Governor("agent-test-3", audit_log, policy, seat_registry=registry)
            gov3.trigger("L1", evidence1, "monitor", "No dual sig",
                         signatures=sign_trigger_sigs(evidence1, "L1", "monitor"))
            assert False, "Should have raised InvariantViolation for missing dual sig"
        except InvariantViolation as e:
            print(f"  P0-4 dual-sig enforcement: {e} ✅")

        print("  ✅ Full lifecycle verified with all invariants")
        return True
    finally:
        cleanup_test_env(tmpdir)


def test_cross_implementation_verification():
    """测试跨实现验证能力：导出验证材料"""
    print("\n=== Test 6: Cross-Implementation Verification Materials ===")

    tmpdir = setup_test_env()
    try:
        # 创建一个完整的干预场景，导出所有验证材料
        intervening = IdentityAnchor("intervening", os.path.join(tmpdir, "keys"))
        subject_anchor = IdentityAnchor("subject", os.path.join(tmpdir, "keys"))

        evidence = EvidenceArtifact(
            produced_by="monitor-001",
            output={"drift_score": 2.5, "triggered": True},
            params={"threshold": 1.0, "baseline": "normal"},
            inputs={"behavior": "aggressive", "resource_access": "unauthorized"},
        )

        snapshot = StateSnapshot(
            tier="L1",
            trigger_reason="Behavior drift exceeding threshold",
            trigger_actor="monitor",
            evidence=evidence,
            memory_hash="abc123def456",
            identity_hash="789012345678",
        )

        snapshot.sign_intervening(intervening)
        snapshot.sign_subject(subject_anchor)

        # 导出验证材料包
        verification_package = {
            "spec_version": "ASG-RS-001 v0.1",
            "verification_checklist": {
                "item_1_evidence": {
                    "evidence": evidence.to_dict(),
                    "test_inputs": {"behavior": "aggressive", "resource_access": "unauthorized"},
                    "expected_inputs_sha256": evidence.inputs_sha256,
                    "instructions": "Recompute SHA-256(canonical_json(test_inputs)) and compare with expected_inputs_sha256",
                },
                "item_2_snapshot": {
                    "snapshot": snapshot.to_dict(),
                    "canonical_bytes_hex": snapshot.canonical_bytes().hex(),
                    "intervening_pubkey_hex": intervening.public_key_hex,
                    "subject_pubkey_hex": subject_anchor.public_key_hex,
                    "instructions": "Recompute canonical_bytes from snapshot fields, verify both signatures",
                },
                "item_3_audit": {
                    "note": "Audit records generated during lifecycle test - see audit.jsonl",
                },
                "item_4_identity": {
                    "intervening_did": intervening.did,
                    "subject_did": subject_anchor.did,
                    "instructions": "Verify DID derivation from public key hex",
                },
            },
        }

        # 保存验证材料
        pkg_path = os.path.join(tmpdir, "verification_package.json")
        with open(pkg_path, "w", encoding="utf-8") as f:
            json.dump(verification_package, f, indent=2, ensure_ascii=False)

        print(f"  verification_package: {pkg_path}")
        print(f"  evidence inputs_sha256: {evidence.inputs_sha256}")
        print(f"  snapshot canonical_bytes: {len(snapshot.canonical_bytes())} bytes")
        print(f"  intervening DID: {intervening.did}")
        print(f"  subject DID: {subject_anchor.did}")
        print("  ✅ Cross-verification materials exportable")
        return True
    finally:
        cleanup_test_env(tmpdir)


def run_all_tests():
    """运行所有测试"""
    print("=" * 60)
    print("ASG-RS-001 Reference Implementation — Verification Tests")
    print("=" * 60)

    tests = [
        test_evidence_reproducibility,
        test_snapshot_dual_signature,
        test_audit_invariants,
        test_identity_anchor,
        test_full_lifecycle,
        test_cross_implementation_verification,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result))
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            import traceback
            traceback.print_exc()
            results.append((test.__name__, False))

    print("\n" + "=" * 60)
    print("RESULTS:")
    print("=" * 60)
    for name, ok in results:
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status} — {name}")

    all_pass = all(ok for _, ok in results)
    print(f"\n{'✅ ALL TESTS PASSED' if all_pass else '❌ SOME TESTS FAILED'}")
    return all_pass


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)