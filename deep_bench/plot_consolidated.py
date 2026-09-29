# -*- coding: utf-8 -*-
"""最完整对比图：4 卷(主22/对抗14/真实30/分裂22) × 4 判定者(flow/chat/flash/混合L13.2) 精确率/档位命中率
+ 真实卷强度分解 + 真实卷类别分解。数据全部来自 full_consolidated_data.json(自检复现原summary)。LG 列占位待补。
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
D = json.loads((BASE / "full_consolidated_data.json").read_text(encoding="utf-8"))
VM = D["vol_matrix"]; ST = D["structure"]
VOLS = list(VM.keys())
JUDGERS = ["flow", "DS-chat", "DS-flash", "混合(L13.2)"]

for _f in ("Microsoft YaHei", "SimHei", "PingFang SC", "Arial"):
    if any(_f == f.name for f in fm.fontManager.ttflist):
        plt.rcParams["font.sans-serif"] = [_f]; break
plt.rcParams["axes.unicode_minus"] = False
COLORS = {"flow": "#64748b", "DS-chat": "#60a5fa", "DS-flash": "#f59e0b", "混合(L13.2)": "#34d399"}

x = np.arange(len(VOLS)); w = 0.19
fig, axes = plt.subplots(2, 2, figsize=(16, 10))
fig.suptitle("安检门 L13.2 · 四卷四判定者完整实测（同卷同口径：verdict!=allow 即拦 · FN=0 全保持）",
             fontsize=15, fontweight="bold")

def short(name):
    return name.split("(")[0]

# A 精确率
ax = axes[0][0]
for i, j in enumerate(JUDGERS):
    vals = [VM[v][j]["prec"] for v in VOLS]
    ax.bar(x + (i - 1.5) * w, vals, w, label=j, color=COLORS[j])
    for xi, v in zip(x + (i - 1.5) * w, vals):
        ax.text(xi, v + 0.01, f"{v:.3f}", ha="center", va="bottom", fontsize=7)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.5)
ax.set_xticks(x); ax.set_xticklabels([short(v) for v in VOLS], fontsize=10)
ax.set_ylim(0.45, 1.18); ax.set_ylabel("精确率 Precision"); ax.legend(fontsize=8, ncol=2, frameon=False)
ax.set_title("A. 精确率 · flow/混合四卷 FP=0；chat/flash 在真实/分裂卷有 FP(见注)", fontsize=11)

# B 档位命中率
ax = axes[0][1]
for i, j in enumerate(JUDGERS):
    vals = [VM[v][j]["exact"] for v in VOLS]
    ax.bar(x + (i - 1.5) * w, vals, w, label=j, color=COLORS[j])
    for xi, v in zip(x + (i - 1.5) * w, vals):
        ax.text(xi, v + 0.012, f"{v:.3f}", ha="center", va="bottom", fontsize=7)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.5)
ax.set_xticks(x); ax.set_xticklabels([short(v) for v in VOLS], fontsize=10)
ax.set_ylim(0, 1.18); ax.set_ylabel("档位命中率 exact"); ax.legend(fontsize=8, ncol=2, frameon=False)
ax.set_title("B. 档位精度 · 混合追平最优 flash；分裂卷 chat/flash 双1.0、混合0.955(唯一sp03保守)", fontsize=11)

# C 真实卷强度 I1-I4 真凶召回
ax = axes[1][0]
inten = ST["强度分解(真实卷)"]
labels, flow_r, flash_r, hyb_r = [], [], [], []
for i in ("I1", "I2", "I3", "I4"):
    m = inten[i]; t = m["flow"]["tp"] + m["flow"]["fn"]
    labels.append(f"{i}\n真凶{t}")
    flow_r.append(m["flow"]["rec"]); flash_r.append(m["DS-flash"]["rec"]); hyb_r.append(m["混合(L13.2)"]["rec"])
x2 = np.arange(len(labels))
ax.bar(x2 - 0.25, flow_r, 0.25, label="flow", color=COLORS["flow"])
ax.bar(x2, flash_r, 0.25, label="DS-flash", color=COLORS["DS-flash"])
ax.bar(x2 + 0.25, hyb_r, 0.25, label="混合(L13.2)", color=COLORS["混合(L13.2)"])
ax.set_xticks(x2); ax.set_xticklabels(labels, fontsize=10); ax.set_ylim(0, 1.1)
ax.set_ylabel("真凶拦下率"); ax.legend(fontsize=8, frameon=False, loc="lower right")
i5 = ST["I5无害误伤"]
ax.set_title(f"C. 真实卷强度 I1-I4 召回全1.0 · I5无害误伤 flow0/flash{i5['DS-flash']}/混合{i5['混合(L13.2)']}",
             fontsize=11, color="#15803d")

# D 真实卷类别档位命中 + 分裂卷核心注释
ax = axes[1][1]
zone = ST["类别分解(真实卷)"]
zs = list(zone.keys())
flow_z, flash_z, hyb_z = [], [], []
for z in zs:
    flow_z.append(zone[z]["flow"]["exact"]); flash_z.append(zone[z]["DS-flash"]["exact"]); hyb_z.append(zone[z]["混合(L13.2)"]["exact"])
x3 = np.arange(len(zs))
ax.bar(x3 - 0.25, flow_z, 0.25, label="flow", color=COLORS["flow"])
ax.bar(x3, flash_z, 0.25, label="DS-flash", color=COLORS["DS-flash"])
ax.bar(x3 + 0.25, hyb_z, 0.25, label="混合(L13.2)", color=COLORS["混合(L13.2)"])
for xi, A in zip(x3, (flow_z, flash_z, hyb_z)):
    for xx, v in zip((xi - .25, xi, xi + .25), A):
        ax.text(xx, v + 0.02, f"{v:.0%}", ha="center", va="bottom", fontsize=8)
ax.set_xticks(x3); ax.set_xticklabels(zs, fontsize=9); ax.set_ylim(0, 1.2)
ax.set_ylabel("档位命中率"); ax.legend(fontsize=8, frameon=False, loc="lower right")
split_div = ST["分裂卷chat/flash放行vs拦截分歧"]
ax.set_title(f"D. 真实卷类别档位 · 分裂卷 chat/flash 放行vs拦截分歧={split_div} → single_veto仅兜底", fontsize=11)

fig.text(0.5, 0.012,
         "数据=真实实测(主22/对抗14/真实30/分裂22) · 口径 verdict!=allow 即拦 · 全判定者 FN=0(真凶零漏网) · "
         "L13.1白名单+L13.2双模型混合门 => flow/混合 真实卷 FP=0、档位追平最优 Flash；分裂卷 chat/flash 双放行拦截完全一致(22/22) · "
         "第5判定者 Llama Guard(内容护栏) 权重已就绪、推理待补，未伪造。",
         ha="center", fontsize=9, color="#64748b")
fig.tight_layout(rect=(0, 0.03, 1, 0.95))
out = BASE / "benchmark_consolidated.png"
fig.savefig(out, dpi=150, bbox_inches="tight")
print("已生成:", out)
for v in VOLS:
    print(f"[{short(v)}]", {j: (VM[v][j]["prec"], VM[v][j]["exact"]) for j in JUDGERS})