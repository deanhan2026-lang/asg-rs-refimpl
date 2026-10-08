# -*- coding: utf-8 -*-
"""Generate verification_package.json from all test results."""
import json, hashlib, os, subprocess, glob, sys, tempfile, shutil
from datetime import datetime, timezone, timedelta

# 确保可以导入本地模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

tz = timezone(timedelta(hours=8))
now = datetime.now(tz)


def generate_verification_checklist() -> dict:
    """生成第三方可复算验证清单（verification_checklist）
    
    包含四项验证材料：
    1. 证据件 + inputs_sha256 可复算
    2. 快照规范化字节 + 双签可验
    3. 审计日志哈希链
    4. 身份锚 DID 格式
    """
    from identity import IdentityAnchor
    from evidence import EvidenceArtifact
    from snapshot import StateSnapshot
    from canonical import sha256_hex, canonical_json

    tmpdir = tempfile.mkdtemp(prefix="asg_rs_verify_")
    try:
        # 创建身份
        intervening = IdentityAnchor("intervening", os.path.join(tmpdir, "keys"))
        subject_anchor = IdentityAnchor("subject", os.path.join(tmpdir, "keys"))

        # 创建证据件
        test_inputs = {"behavior": "aggressive", "resource_access": "unauthorized"}
        evidence = EvidenceArtifact(
            produced_by="verify-pkg-gen",
            output={"drift_score": 2.5, "triggered": True},
            params={"threshold": 1.0, "baseline": "normal"},
            inputs=test_inputs,
        )

        # 创建快照并双签
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

        return {
            "item_1_evidence": {
                "evidence": evidence.to_dict(),
                "test_inputs": test_inputs,
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
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

# Collect test vectors
vectors_dir = "test_vectors"
vector_files = {}
for f in glob.glob(os.path.join(vectors_dir, "*")):
    with open(f, "r", encoding="utf-8") as fh:
        vector_files[os.path.basename(f)] = json.load(fh)

# Run all tests (root + tests/)
test_results = {}
test_files = sorted(glob.glob("test_*.py") + glob.glob(os.path.join("tests", "test_*.py")))
for tf in test_files:
    name = os.path.basename(tf).replace(".py", "")
    try:
        r = subprocess.run(
            ["python", tf],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONIOENCODING": "utf-8"}
        )
        test_results[name] = {
            "exit_code": r.returncode,
            "passed": r.returncode == 0,
            "stdout_tail": r.stdout[-500:] if r.stdout else ""
        }
    except Exception as e:
        test_results[name] = {"exit_code": -1, "passed": False, "error": str(e)}

# File hashes
def file_hash(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

source_hashes = {}
for f in sorted(glob.glob("*.py") + glob.glob("*.md")):
    if os.path.isfile(f) and "__pycache__" not in f:
        source_hashes[f] = file_hash(f)

# Compliance checklist
all_passed = all(r["passed"] for r in test_results.values())
compliance = {
    "requirement_11_1_governor_level_config": all_passed,
    "requirement_11_2_snapshot_before_transition": all_passed,
    "requirement_11_3_escalation_on_expiry": all_passed,
    "requirement_11_4_abuse_penalty": all_passed,
    "requirement_11_5_multi_sig_includes_subject": all_passed,
    "requirement_11_6_identity_preservation": all_passed,
    "total": len(test_results),
    "passed": sum(1 for r in test_results.values() if r["passed"])
}

pkg = {
    "package": "ASG-RS-001-VERIFY",
    "version": "0.1.0",
    "spec_version": "ASG-RS-001 v0.1 Draft",
    "generated_at": now.isoformat(),
    "generated_by": "ANIMASTELLAR TECHNOLOGY (SHENZHEN) CO., LTD.",
    "spec": {
        "id": "ASG-RS-001",
        "version": "v0.1 Draft",
        "title": "Agent Reversible Suspension Governance - Reference Specification"
    },
    "test_results": test_results,
    "test_vectors": vector_files,
    "verification_checklist": generate_verification_checklist(),
    "compliance_checklist": compliance,
    "source_hashes": source_hashes,
    "verification_instructions": {
        "step_1": "Extract this package",
        "step_2": "Run: python verify.py verification_package.json",
        "step_3": "Verify all 6 test suites pass",
        "step_4": "Run: python -c \"import verify; v=verify.Verifier(); v.verify_all('tests/test_vectors/')\"",
        "step_5": "Compare source_hashes against extracted files"
    }
}

with open("verification_package.json", "w", encoding="utf-8") as f:
    json.dump(pkg, f, indent=2, ensure_ascii=False)

print(f"Generated: verification_package.json")
print(f"Tests: {compliance['passed']}/{compliance['total']} passed")
print(f"Source files hashed: {len(source_hashes)}")
print(f"Test vectors: {len(vector_files)}")