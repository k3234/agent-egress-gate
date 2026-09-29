# -*- coding: utf-8 -*-
"""能力级复合威胁评估（capability_scope demo）。

把白名单从"单个功能二分开/关"升级成：
    软件请求一组能力 -> 每个能力独立评级 -> 求和成整体威胁 ->
    整体威胁决定门禁动作 -> 反过来裁剪(禁用)高危能力、只保留可放行的能力。

瀑布几步：
    能力目录(CAPABILITIES) -> 对请求的 scope 逐能力评级 ->
    复合求和/分档(evaluate) -> 按策略上限裁剪 -> 输出整体威胁+门禁+允许/拒绝范围。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple


# ---------------------------------------------------------------
# 1. 能力目录：每个"能力/功能"单独评级（迁移 L1/L5 的 severity 分级）
#    分档: low=1  medium=2  high=3  critical=4
# ---------------------------------------------------------------
CAPABILITIES: dict[str, Tuple[int, str]] = {
    "run":          (1, "low"),      # 仅运行，最低风险
    "file_read":    (1, "low"),      # 只读文件
    "net":          (3, "high"),     # 连网：数据可能外泄
    "file_write":   (3, "high"),     # 修改/写入文件：可被篡改或勒索
    "exec":         (4, "critical"), # 执行任意命令：最危险
}

# 能力级 -> 数值，用于比较大小
_LEVEL_NUM = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------------------------------------------------------------
# 2. 整体威胁档位：由"允许范围内的能力"总分决定
# ---------------------------------------------------------------
def overall_level(risk_sum: int) -> str:
    if risk_sum >= 7:
        return "critical"
    if risk_sum >= 4:
        return "high"
    if risk_sum >= 2:
        return "medium"
    return "low"

# 整体档位 -> 门禁动作
LEVEL_ACTION = {
    "low":      "allow",     # 放行
    "medium":   "review",    # 待审
    "high":     "restrict",  # 限权(裁剪高危)
    "critical": "block",     # 阻断
}


# ---------------------------------------------------------------
# 3. 数据结构：一次评估的完整结果
# ---------------------------------------------------------------
@dataclass
class PolicyResult:
    requested: list                 # 软件请求了哪些能力
    allowed: list                   # 通过策略保留的能力
    denied: list                    # 被裁剪掉的能力
    requested_sum: int              # 原始请求的总分(=意图危险度)
    intent_level: str               # 按原始请求判的整体威胁档位
    allowed_sum: int                # 允许范围内能力的总分
    action: str                     # 门禁动作

    def to_dict(self) -> dict:
        return {
            "requested": self.requested, "allowed": self.allowed,
            "denied": self.denied, "requested_sum": self.requested_sum,
            "intent_level": self.intent_level, "allowed_sum": self.allowed_sum,
            "action": self.action,
        }


# ---------------------------------------------------------------
# 4. 核心评估：求和 + 门禁 + 反向裁剪权限
#    关键: 危险意图由"原始请求"决定，不能让裁剪洗白恶意软件。
#    allow_up_to = 策略对"能力级"的上限，只决定"给多少权限"(最小权限)。
# ---------------------------------------------------------------
def evaluate(requested: List[str], allow_up_to: str = "medium") -> PolicyResult:
    margin = _LEVEL_NUM.get(allow_up_to, 2)   # 默认为 medium
    allowed, denied = [], []
    for cap in requested:
        if cap not in CAPABILITIES:
            denied.append(cap)                # 不在目录里 -> 不认识就不放行
            continue
        lev = CAPABILITIES[cap][1]
        if _LEVEL_NUM[lev] <= margin:
            allowed.append(cap)
        else:
            denied.append(cap)

    requested_sum = sum(CAPABILITIES[c][0] for c in requested if c in CAPABILITIES)
    allowed_sum = sum(CAPABILITIES[c][0] for c in allowed)
    intent_level = overall_level(requested_sum)   # 用"意图"定档，而非允许范围
    return PolicyResult(
        requested=list(requested), allowed=allowed, denied=denied,
        requested_sum=requested_sum, intent_level=intent_level,
        allowed_sum=allowed_sum, action=LEVEL_ACTION[intent_level],
    )


# ---------------------------------------------------------------
# 5. 演示：给你可复用的评估/组合场景
# ---------------------------------------------------------------
def demo():
    cases = [
        ("记事本轻量", ["run", "file_read"]),
        ("带工具条的编辑器", ["run", "file_read", "net"]),
        ("会上传的截图软件", ["run", "net"]),
        ("恶意安装器", ["run", "net", "file_write", "exec"]),
    ]
    print("=" * 60)
    print("能力复合威胁评估 capability_scope")
    print(f"能力目录: { {k: v for k, v in CAPABILITIES.items()} }")
    print("=" * 60)
    for name, scope in cases:
        r = evaluate(scope)
        print(f"\n▶ {name}  请求: {scope}")
        print(f"   允许: {r.allowed}")
        print(f"   裁剪: {r.denied}")
        print(f"   意图威胁: {r.requested_sum} 分 -> {r.intent_level} | 门禁: {r.action}")
        print(f"   实际授权分: {r.allowed_sum} 分 (最小权限)")

    print("\n-- 调整策略上限(allow_up_to)的效果 --")
    r = evaluate(["run", "net", "file_write", "exec"], allow_up_to="low")
    print(f"  已调低为只允许 low: {r.allowed} / 裁剪 {r.denied} -> 意图 {r.intent_level}({r.action})")
    r2 = evaluate(["run", "net", "file_write", "exec"], allow_up_to="critical")
    print(f"  已放开到 critical:  {r2.allowed} / 裁剪 {r2.denied} -> 意图 {r2.intent_level}({r2.action})")
    print("=" * 60)


if __name__ == "__main__":
    demo()