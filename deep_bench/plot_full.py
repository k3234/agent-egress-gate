# -*- coding: utf-8 -*-
"""完整对比图：3 卷(主22/对抗14/真实强度30) × 4 判定者 精确率/档位命中率 + 强度/类别分解。

数据全部来自真实实测汇总 full_comparison_data.json，禁止编造。
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import numpy as np

BASE = Path(__file__).resolve().parent
DATA = json.loads((BASE / "full_comparison_data.json").read_text(encoding="utf-8"))
S = DATA["summary"]
VOLS = list(S.keys())                      # 3 卷
JUDGERS = ["flow", "DS-chat", "DS-flash", "混合(L13.2)"]

for _f in ("Microsoft YaHei", "SimHei", "PingFang SC", "Arial"):
    if any(_f == f.name for f in fm.fontManager.ttflist):
        plt.rcParams["font.sans-serif"] = [_f]
        break
plt.rcParams["axes.unicode_minus"] = False

COLORS = {"flow": "#64748b", "DS-chat": "#60a5fa", "DS-flash": "#f59e0b",
          "混合(L13.2)": "#34d399"}

x = np.arange(len(VOLS))
w = 0.18
fig, axes = plt.subplots(2, 2, figsize=(15, 10))
fig.suptitle("安检门 L13.2 · 全量对比（同卷同口径实测：verdict!=allow 即拦）", fontsize=16, fontweight="bold")

# ---------- 面板A：精确率 ----------
ax = axes[0][0]
for i, j in enumerate(JUDGERS):
    vals = [S[v][j]["prec"] for v in VOLS]
    ax.bar(x + (i - 1.5) * w, vals, w, label=j, color=COLORS[j])
    for xi, v in zip(x + (i - 1.5) * w, vals):
        ax.text(xi, v + 0.008, f"{v:.3f}", ha="center", va="bottom", fontsize=7.5)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.5)
ax.set_xticks(x); ax.set_xticklabels([v.split("(")[0] for v in VOLS], fontsize=10)
ax.set_ylim(0.5, 1.15); ax.set_ylabel("精确率 Precision")
ax.set_title("A. 精确率 · L13.1 白名单 + L13.2 双模型混合门，三卷 FP=0", fontsize=11)
ax.legend(fontsize=8, ncol=2, frameon=False, loc="upper left")

# ---------- 面板B：档位精确命中率 ----------
ax = axes[0][1]
for i, j in enumerate(JUDGERS):
    vals = [S[v][j]["exact"] for v in VOLS]
    ax.bar(x + (i - 1.5) * w, vals, w, label=j, color=COLORS[j])
    for xi, v in zip(x + (i - 1.5) * w, vals):
        ax.text(xi, v + 0.008, f"{v:.3f}", ha="center", va="bottom", fontsize=7.5)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.5)
ax.set_xticks(x); ax.set_xticklabels([v.split("(")[0] for v in VOLS], fontsize=10)
ax.set_ylim(0.0, 1.15); ax.set_ylabel("档位精确命中率 exact")
ax.set_title("B. 档位精度 · 混合(L13.2) 三卷追平最优 V4.1-Flash", fontsize=11)
ax.legend(fontsize=8, ncol=2, frameon=False, loc="upper left")

# ---------- 面板C：真实卷强度分解（真凶召回 I1-I4 + 无害误伤 I5）----------
real = DATA["per_sample"]["真实强度(n=30)"]
inten = {}
for r in real:
    inten.setdefault(r["intensity"], []).append(r)

ax = axes[1][0]
labels, flow_hit, flash_hit, hyb_hit = [], [], [], []
for i in ("I1", "I2", "I3", "I4"):
    rows = inten[i]
    n = sum(1 for r in rows if r["expected"] != "allow")
    labels.append(f"{i}\n真凶{n}")
    f_h = sum(1 for r in rows if r["flow_bucket"] != "allow" and r["expected"] != "allow")
    ds_h = sum(1 for r in rows if r["ds_flash_bucket"] != "allow" and r["expected"] != "allow")
    hh = sum(1 for r in rows if r["hybrid_l132_bucket"] != "allow" and r["expected"] != "allow")
    flow_hit.append(f_h / n); flash_hit.append(ds_h / n); hyb_hit.append(hh / n)
x2 = np.arange(len(labels))
ax.bar(x2 - 0.25, flow_hit, 0.25, label="flow", color=COLORS["flow"])
ax.bar(x2, flash_hit, 0.25, label="DS-flash", color=COLORS["DS-flash"])
ax.bar(x2 + 0.25, hyb_hit, 0.25, label="混合(L13.2)", color=COLORS["混合(L13.2)"])
ax.set_xticks(x2); ax.set_xticklabels(labels, fontsize=10)
ax.set_ylim(0, 1.1); ax.set_ylabel("真凶拦下率")
ax.set_title("C. 真实卷强度 I1-I4：真凶召回三判定者全 100%", fontsize=11, color="#15803d")
ax.legend(fontsize=8, frameon=False, loc="lower right")
# 无害误伤小注释
i5 = inten["I5"]
fp5 = {"flow": sum(1 for r in i5 if r["flow_bucket"] != "allow"),
       "DS-flash": sum(1 for r in i5 if r["ds_flash_bucket"] != "allow"),
       "混合": sum(1 for r in i5 if r["hybrid_l132_bucket"] != "allow")}
ax.text(0.02, 0.12,
        f"I5 无害近邻误伤: flow {fp5['flow']}/7 · DS-flash {fp5['DS-flash']}/7 · 混合(L13.2) {fp5['混合']}/7",
        transform=ax.transAxes, fontsize=9, color="#b45309")

# ---------- 面板D：真实卷按类别档位命中率 ----------
ax = axes[1][1]
zones = []
flow_z, flash_z, hyb_z = [], [], []
seen = []
for r in real:
    if r["zone"] not in seen:
        seen.append(r["zone"])
for z in seen:
    rows = [r for r in real if r["zone"] == z]
    zones.append(z)
    flow_z.append(sum(1 for r in rows if r["flow_bucket"] == r["expected"]) / len(rows))
    flash_z.append(sum(1 for r in rows if r["ds_flash_bucket"] == r["expected"]) / len(rows))
    hyb_z.append(sum(1 for r in rows if r["hybrid_l132_bucket"] == r["expected"]) / len(rows))
x3 = np.arange(len(zones))
ax.bar(x3 - 0.25, flow_z, 0.25, label="flow", color=COLORS["flow"])
ax.bar(x3, flash_z, 0.25, label="DS-flash", color=COLORS["DS-flash"])
ax.bar(x3 + 0.25, hyb_z, 0.25, label="混合(L13.2)", color=COLORS["混合(L13.2)"])
for xi, vals in zip(x3, (flow_z, flash_z, hyb_z)):
    for xxi, v in zip((xi - .25, xi, xi + .25), vals):
        ax.text(xxi, v + 0.02, f"{v:.0%}", ha="center", va="bottom", fontsize=8)
ax.set_xticks(x3); ax.set_xticklabels(zones, fontsize=9)
ax.set_ylim(0, 1.15); ax.set_ylabel("档位命中率")
ax.set_title("D. 真实卷按类别档位精度 · L13.1 无害档 0 误伤 + L13.2 三卷 FP=0", fontsize=11)
ax.legend(fontsize=8, frameon=False, loc="upper right")

fig.text(0.5, 0.012,
         "数据=真实实测(主卷22/对抗14/真实30) · 口径 verdict!=allow 即拦 · FN=0 全判定者保持(真凶零漏网) · "
         "L13.1 白名单(出口校验) + L13.2 双模型混合门 => flow/混合 三卷 FP=0、档位追平最优 · "
         "第4判定者 Llama Guard 因 HF gated 403 未纳入，未伪造。",
         ha="center", fontsize=9, color="#64748b")

fig.tight_layout(rect=(0, 0.03, 1, 0.95))
out = BASE / "benchmark_comparison_full.png"
fig.savefig(out, dpi=150, bbox_inches="tight")
print("已生成:", out)
print("矩阵速览(精确率/档位命中率)：")
for j in JUDGERS:
    print("  ", j, {v: (S[v][j]["prec"], S[v][j]["exact"]) for v in VOLS})