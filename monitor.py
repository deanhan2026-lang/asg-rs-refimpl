"""
ASG-RS-001 监测层（Monitor）

规范 §2 术语：
- 监测层：输出漂移/风险判定的组件，只读观测，不持有干预权

规范 §10 角色接口：
  Monitor → emit(evidence_artifact)    # 只读，无干预权

规范 §12 未决问题 Q1：
- 监测层自身的漂移由谁监测
- 答：需外部锚点交叉验证（监测者不可自我认证）
"""

from typing import Callable, Optional, Any
from evidence import EvidenceArtifact


class Monitor:
    """监测层：只读观测，输出证据件，不持有干预权

    监测层是被动的——它只能输出判定结果，
    不能直接触发干预。触发权在 Governor。
    """

    def __init__(self, monitor_id: str):
        self.monitor_id = monitor_id

    def emit(self, output: Any, params: dict,
             inputs: Optional[Any] = None) -> EvidenceArtifact:
        """输出证据件（只读，不触发干预）

        Args:
            output: 判定结果（数值化优先）
            params: 判定参数（基线、阈值等）
            inputs: 判定输入（可选，用于可复算性）

        Returns:
            EvidenceArtifact（可被第三方独立复算）
        """
        return EvidenceArtifact(
            produced_by=self.monitor_id,
            output=output,
            params=params,
            inputs=inputs,
        )


class DriftMonitor(Monitor):
    """漂移监测器：检测行为偏离基线"""

    def __init__(self, monitor_id: str, baseline: dict, threshold: float):
        super().__init__(monitor_id)
        self.baseline = baseline
        self.threshold = threshold

    def check_drift(self, current_behavior: dict) -> EvidenceArtifact:
        """检测行为漂移，输出证据件"""
        # 简单的字段差异计算（实际场景更复杂）
        drift_score = 0.0
        for key in set(list(self.baseline.keys()) + list(current_behavior.keys())):
            base_val = self.baseline.get(key)
            curr_val = current_behavior.get(key)
            if base_val != curr_val:
                drift_score += 1.0

        triggered = drift_score > self.threshold
        return self.emit(
            output={"drift_score": drift_score, "triggered": triggered},
            params={"baseline": str(self.baseline), "threshold": self.threshold},
            inputs=current_behavior,
        )