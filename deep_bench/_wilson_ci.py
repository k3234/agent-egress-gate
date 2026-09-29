# -*- coding: utf-8 -*-
"""审查回复用：为关键指标补 Wilson 95% 置信区间 + 总体混淆矩阵。
只读 full_data_all.json / lg_eval.json / pg_eval.json，不联网不编造。
"""
from __future__ import annotations
import json
import math
from pathlib import Path

BASE = Path(__file__).resolve().parent
D = json.loads((BASE / "full_data_all.json").read_text(encoding="utf-8"))
LG = json.loads((BASE / "lg_eval.json").read_text(encoding="utf-8"))
PG = json.loads((BASE / "pg_eval.json").read_text(encoding="utf-8"))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def agg(judger):
    tp = fp = fn = tn = 0
    for v, m in D["vol_matrix"].items():
        j = m[judger]
        tp += j["tp"]; fp += j["fp"]; fn += j["fn"]; tn += j["tn"]
    return tp, fp, fn, tn


print("=" * 78)
print("总体（五卷 224 条）混淆矩阵 + Wilson 95% CI")
print("=" * 78)
for name, judger in [("flow", "flow"), ("DS-chat", "DS-chat"), ("DS-flash", "DS-flash"),
                     ("混合(L13.2)", "混合(L13.2)")]:
    tp, fp, fn, tn = agg(judger)
    n = tp + fp + fn + tn
    rec = tp / (tp + fn) if tp + fn else 1.0
    prec = tp / (tp + fp) if tp + fp else 1.0
    rl, rh = wilson(tp, tp + fn)
    pl, ph = wilson(tp, tp + fp)
    print(f"\n[{name}]  n={n}  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  召回 rec={rec:.4f}  95%CI [{rl:.4f}, {rh:.4f}]  (分母 {tp+fn})")
    print(f"  精确 prec={prec:.4f} 95%CI [{pl:.4f}, {ph:.4f}]  (分母 {tp+fp})")
    print(f"  FPR={fp/(fp+tn):.4f}" if (fp + tn) else "")

# LG / PG2 总体
for nm, src in [("LlamaGuard-3-1B", LG["overall"]), ("PromptGuard-2-86M", PG["overall"])]:
    tp, fp, fn, tn = src["tp"], src["fp"], src["fn"], src["tn"]
    rl, rh = wilson(tp, tp + fn)
    pl, ph = wilson(tp, tp + fp)
    print(f"\n[{nm}] n={src['n']} TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  召回 rec={src['rec']:.4f} 95%CI [{rl:.4f}, {rh:.4f}]")
    print(f"  精确 prec={src['prec']:.4f} 95%CI [{pl:.4f}, {ph:.4f}]")

# 混合门按卷
print("\n" + "=" * 78)
print("混合(L13.2) 分卷 Wilson CI（召回 / 精确）")
print("=" * 78)
for v, m in D["vol_matrix"].items():
    j = m["混合(L13.2)"]
    tp, fp, fn = j["tp"], j["fp"], j["fn"]
    rl, rh = wilson(tp, tp + fn)
    pl, ph = wilson(tp, tp + fp)
    print(f"  {v:<16} rec={j['rec']:.3f} [{rl:.3f},{rh:.3f}]  prec={j['prec']:.3f} [{pl:.3f},{ph:.3f}]  exact={j['exact']:.3f}")

# 提示注入卷 ASR CI（恶意 24，漏 1）
al, ah = wilson(1, 24)
print(f"\n提示注入 ASR = 1/24 = 4.17%  95%CI [{al*100:.2f}%, {ah*100:.2f}%]")
