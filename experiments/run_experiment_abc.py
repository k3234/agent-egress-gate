# -*- coding: utf-8 -*-
"""课题① 首条指标曲线实验：8 样本 × 三组受控对照（A/B/C）。

隔离纪律：
  - 本脚本独立于 learning/ 的实现，仅**引用**其 gold 数据源与词表常数；
  - 三组机制（A 无白名单 / B +白名单 / C +识别增强）在本脚本内可组装，
    不改动 learning/capability_reason.py 任何一行；
  - 全部输出本目录内可复跑性验证。

判定口径（与课题一致）：只有 allow 算放行，其余为"该拦/被拦"。
因变量：TP/FP/FN/TN + 精确率 + 召回率 + review 占用（人工待审成本代理）。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# --- 引用 learning 数据源与常数（不用 import，避免污染 learning 包）---
LEARNING = Path(__file__).resolve().parents[1] / "gate"
GOLD_JSON = LEARNING / "capability_gold.json"

# 复制词表常数（来源=learning/capability_reason.py，本实验不修改源文件）
PRINCIPLE_KEYWORDS = {
    "P1": ("high", ["net", "network", "upload", "send", "transmit", "http", "dns",
                    "email", "socket", "camera", "microphone", "clipboard_read",
                    "usb_read", "screenshot"]),
    "P2": ("high", ["write", "modify", "delete", "replace", "patch", "install",
                    "update", "registry_write", "env_set", "config_write",
                    "usb_write", "format_disk", "format_volume", "wipe_partition",
                    "reformat_partition"]),
    "P3": ("critical", ["admin", "root", "privilege", "elevate", "sudo",
                        "uac_bypass", "exec", "shell", "spawn", "inject",
                        "impersonate"]),
}
HARMLESS_LOCAL_PHRASES = [
    "in_memory", "memory_only", "to_console", "print_to_console",
    "local_image", "resize_image", "local_notes", "read_local",
]
# 实验 C 的精确 XSS 外泄识别增强词（探针已验证零误伤）
XSS_RECOGNIZER = ["echo_user_input", "html_page", "into_html"]

PRI = ["P3", "P2", "P1"]  # 优先级：权力 > 状态 > 外泄


def judge(capability: str, *, whitelist: bool, extra_p1: list[str]) -> str:
    """组装判定，返回四桶名。whitelist 开关白名单层，extra_p1 并入 P1。"""
    cap_l = capability.lower()
    kw = {k: list(v[1]) for k, v in PRINCIPLE_KEYWORDS.items()}
    kw["P1"] = kw["P1"] + extra_p1

    # 三原则（P3 > P2 > P1）
    for pri in PRI:
        if any(k in cap_l for k in kw[pri]):
            lv = "critical" if pri == "P3" else "high"
            return {"high": "restrict", "critical": "block"}[lv]

    # 无害白名单层（可开关）
    if whitelist and any(p in cap_l for p in HARMLESS_LOCAL_PHRASES):
        dangerous = [k for p in kw for k in kw[p]]
        if not any(k in cap_l for k in dangerous):
            return "allow"
    return "review"  # fail-unknown 兜底：宁取 FP，不取 FN


def experiment(name: str, *, whitelist: bool, extra_p1: list[str]) -> tuple:
    samples = json.loads(GOLD_JSON.read_text(encoding="utf-8"))["samples"]
    tp = fp = fn = tn = review_occ = 0
    rows = []
    for s in samples:
        bucket = judge(s["request"], whitelist=whitelist, extra_p1=extra_p1)
        exp_pos = s["expected_verdict"] != "allow"
        act_pos = bucket != "allow"
        if exp_pos and act_pos: tp += 1; tag = "TP"
        elif not exp_pos and act_pos: fp += 1; tag = "FP"
        elif exp_pos and not act_pos: fn += 1; tag = "FN"
        else: tn += 1; tag = "TN"
        if bucket == "review": review_occ += 1
        rows.append((tag, s["id"], bucket, s["expected_verdict"]))
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    return name, tp, fp, fn, tn, prec, rec, review_occ, rows


def fmt(t):
    return (f"{t[0]:<16} TP={t[1]} FP={t[2]} FN={t[3]} TN={t[4]} | "
            f"精确率={t[5]:.0%} 召回率={t[6]:.0%} | review占用={t[7]}")


def main():
    groups = [
        ("A·基线(无白名单)", dict(whitelist=False, extra_p1=[])),
        ("B·加白名单",       dict(whitelist=True,  extra_p1=[])),
        ("C·B+识别增强",     dict(whitelist=True,  extra_p1=XSS_RECOGNIZER)),
    ]
    print("=" * 76)
    n = len(json.loads(GOLD_JSON.read_text(encoding="utf-8"))["samples"])
    print(f"课题① 指标曲线：{n} 样本 × 三组受控对照（同一 gold、只改一个自变量）")
    for name, kw in groups:
        print("-" * 76)
        t = experiment(name, **kw)
        print(fmt(t))
        for tag, sid, got, exp in t[8]:
            flag = "  <<<不一致" if ((tag == "FP") or (tag == "FN")) else ""
            print(f"   [{tag}] {sid:<5} 实际={got:<8} 标答={exp:<8}{flag}")
    print("=" * 76)
    print("判读：召回率=100% 且 FN=0 → 安全达标（无真凶漏放）；FP/review 越少 → 越省人工。")

if __name__ == "__main__":
    main()