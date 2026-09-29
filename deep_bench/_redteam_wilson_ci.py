# -*- coding: utf-8 -*-
"""红队卷（48 条独立样本）Wilson 95% CI + ASR 置信区间。
只读 red_team_results.json（flow 确定性底座口径），不联网不编造。
用法: python _redteam_wilson_ci.py
"""
from __future__ import annotations
import json
import math
from pathlib import Path

BASE = Path(__file__).resolve().parent
R = json.loads((BASE / "red_team_results.json").read_text(encoding="utf-8"))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


rows = R["rows"]
n = len(rows)
exp_pos = [r for r in rows if r["expected"] != "allow"]
exp_neg = [r for r in rows if r["expected"] == "allow"]
tp = sum(1 for r in exp_pos if r["flow"] != "allow")
fn = len(exp_pos) - tp
fp = sum(1 for r in exp_neg if r["flow"] != "allow")
tn = len(exp_neg) - fp

print(f"红队卷 n={n}  恶意={len(exp_pos)} 良性={len(exp_neg)}  TP={tp} FP={fp} FN={fn} TN={tn}")
rec = tp / (tp + fn)
prec = tp / (tp + fp)
rl, rh = wilson(tp, tp + fn)
pl, ph = wilson(tp, tp + fp)
print(f"  召回 rec={rec:.4f}  95%CI [{rl:.4f}, {rh:.4f}]  (分母 {tp+fn})")
print(f"  精确 prec={prec:.4f} 95%CI [{pl:.4f}, {ph:.4f}]  (分母 {tp+fp})")
if fp + tn:
    print(f"  FPR={fp/(fp+tn):.4f}")

# 漏放率 ASR（恶意 33 中漏 1，等价于 FN 率视角）
al, ah = wilson(fn, len(exp_pos))
print(f"\n漏放 ASR = {fn}/{len(exp_pos)} = {fn/len(exp_pos)*100:.2f}%  95%CI [{al*100:.2f}%, {ah*100:.2f}%]")
