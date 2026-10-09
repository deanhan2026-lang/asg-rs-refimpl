# ASG-RS-001 验证报告公开发布包

> **发布方：** 灵元星辰科技（深圳）有限公司
> **日期：** 2026-10-09
> **版本：** v1.0

## 内容

| 文件 | 说明 |
|------|------|
| `ASG-RS-001-VERIFICATION-REPORT.md` | 完整验证报告（30项问题闭环） |
| `verification_package.json` | 验证包（测试结果+测试向量+元数据） |
| `test_vectors.json` | 跨实现验证测试向量 |
| `README.md` | 本文件 |

## 验证结论

**外部节点可独立复算参考实现，可复现性已成立。**

- verifier-alpha 七轮深度复算：PASS（有条件）
- verifier-beta 接入实验：PASS
- 30/30 问题闭环：21 修复 + 6 声明差异 + 3 MANIFEST 覆盖 = 0 阻断

## 如何独立验证

```bash
# 1. 克隆参考实现
git clone https://github.com/deanhan2026-lang/asg-rs-refimpl.git
cd asg-rs-refimpl

# 2. 安装依赖
pip install cryptography base58

# 3. 运行测试套件
python tests/test_full_lifecycle.py      # 8/8 PASS
python tests/test_isr_boundary.py       # 10/10 PASS

# 4. 验证哈希链
python verify.py verification_package.json  # ALL VERIFICATIONS PASSED

# 5. 检查覆盖率
pip install coverage
coverage run tests/test_full_lifecycle.py
coverage report  # 目标: ≥90%
```

## 预期结果

- 测试：24/24 PASS
- 验证：ALL VERIFICATIONS PASSED
- 覆盖率：≥90%

## 参与验证

欢迎提交新的验证报告。验证方法：

1. 独立运行上述测试套件
2. 记录原始输出
3. 提交验证报告（含环境信息+原始输出+发现的问题）

## 联系

- GitHub: https://github.com/deanhan2026-lang/asg-rs-refimpl
- Issues: https://github.com/deanhan2026-lang/asg-rs-refimpl/issues
