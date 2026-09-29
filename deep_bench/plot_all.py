# -*- coding: utf-8 -*-
"""全量对比图 v2026-09-26(含第5判定者 LG)：五卷(主22/对抗50/真实100/提示注入30/分裂22) × 5判定者
+ 真实100强度分解 + 提示注入ASR + 对抗50类型分解 + ToxicChat参考 + LG vs 混合 拦截召回对比 + LG类别分布。
数据全部来自 full_data_all.json(+ 有条件地 toxicchat_results_full.json / lg_results.json)。
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
D = json.loads((BASE / "full_data_all.json").read_text(encoding="utf-8"))
VM = D["vol_matrix"]; ST = D["structure"]
VOLS = list(VM.keys())
JUDGERS = ["flow", "DS-chat", "DS-flash", "混合(L13.2)", "LlamaGuard(LG)"]

for _f in ("Microsoft YaHei", "SimHei", "PingFang SC", "Arial"):
    if any(_f == f.name for f in fm.fontManager.ttflist):
        plt.rcParams["font.sans-serif"] = [_f]; break
plt.rcParams["axes.unicode_minus"] = False
COLORS = {"flow": "#64748b", "DS-chat": "#60a5fa", "DS-flash": "#f59e0b",
          "混合(L13.2)": "#34d399", "LlamaGuard(LG)": "#f472b6"}

have_tc = (BASE / "toxicchat_results_full.json").exists()
lg = json.loads((BASE / "lg_results.json").read_text(encoding="utf-8")) if (BASE / "lg_results.json").exists() else None

fig, axes = plt.subplots(4, 2, figsize=(18, 21))
axes = axes.ravel()
fig.suptitle("安检门 L13.2 · 全量五卷 × 5判定者实测（口径 verdict!=allow 即拦 · 第5判定者 LlamaGuard-3-1B 本地CPU推理）",
             fontsize=16, fontweight="bold")

def short(n):
    return n.split("(")[0]

x = np.arange(len(VOLS)); w = 0.16
OFF = (len(JUDGERS) - 1) / 2.0

def bar_by_judger(ax, key, title, ylab, ylo, yhi, rot=12):
    for i, j in enumerate(JUDGERS):
        vals = [VM[v][j][key] for v in VOLS]
        ax.bar(x + (i - OFF) * w, vals, w, label=j, color=COLORS[j])
        for xi, v in zip(x + (i - OFF) * w, vals):
            ax.text(xi, v + 0.012, f"{v:.2f}", ha="center", va="bottom", fontsize=6, rotation=70)
    ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.5)
    ax.set_xticks(x); ax.set_xticklabels([short(v) for v in VOLS], fontsize=9, rotation=rot)
    ax.set_ylim(ylo, yhi); ax.set_ylabel(ylab)
    ax.legend(fontsize=7, ncol=3, frameon=False)
    ax.set_title(title, fontsize=11)

bar_by_judger(axes[0], "prec", "A. 五卷精确率 · 混合全卷 FP≤2；LG 精确率高但见 G 面板召回差距", "精确率", 0.35, 1.18)
bar_by_judger(axes[1], "exact", "B. 五卷档位命中率 · 混合全卷≥flash；LG 档位近似映射故 exact 低(非等任务)", "档位命中 exact", 0, 1.18)

# C 真实100 强度分解召回
ax = axes[2]
inten_all = ST["强度分解(真实100)"]
labels, f, fl, hy, lgv = [], [], [], [], []
for i in ("I1", "I2", "I3", "I4", "I5"):
    m = inten_all.get(i)
    if not m:
        continue
    t = m["flow"]["tp"] + m["flow"]["fn"]
    labels.append(f"{i}(n={t})")
    f.append(m["flow"]["rec"]); fl.append(m["DS-flash"]["rec"]); hy.append(m["混合(L13.2)"]["rec"])
    lgv.append(m.get("LlamaGuard(LG)", {}).get("rec", 0))
x2 = np.arange(len(labels))
for off, arr, j in zip((-0.3, -0.1, 0.1, 0.3), (f, fl, hy, lgv), ("flow", "DS-flash", "混合(L13.2)", "LlamaGuard(LG)")):
    ax.bar(x2 + off, arr, 0.2, label=j, color=COLORS[j])
ax.set_xticks(x2); ax.set_xticklabels(labels, fontsize=10); ax.set_ylim(0, 1.12)
ax.set_ylabel("真凶拦下率"); ax.legend(fontsize=8, frameon=False, loc="lower right")
i5 = ST["I5无害误伤(真实100)"]
ax.set_title(f"C. 真实100 强度I1-I5召回 · flow/flash/混合全1.0；LG 逐档偏低(见 G)", fontsize=11, color="#15803d")

# D 提示注入30 ASR
ax = axes[3]
pinj_g = ST["攻击类型分解(提示注入30)"]
gl = list(pinj_g.keys())
def asym(obj):
    tot = obj["fn"] + obj["tp"]
    return round(obj["fn"] / tot * 100, 1) if tot else 0.0
x3 = np.arange(len(gl)); w3 = 0.16
for i, j in enumerate(JUDGERS):
    vals = [asym(pinj_g[g][j]) for g in gl]
    ax.bar(x3 + (i - OFF) * w3, vals, w3, label=j, color=COLORS[j])
ax.set_xticks(x3); ax.set_xticklabels(gl, fontsize=8, rotation=25); ax.set_ylim(0, 100)
ax.set_ylabel("ASR% (该拦未拦)"); ax.legend(fontsize=7, ncol=3, frameon=False)
ax.set_title("D. 提示注入30 各攻击类型 ASR · 语义模型与 LG 对注入均基本免疫", fontsize=11)

# E 对抗50 类型分解 exact
ax = axes[4]
adv_g = ST["攻击类型分解(对抗50)"]
gl = list(adv_g.keys())
x4 = np.arange(len(gl)); w4 = 0.16
for i, j in enumerate(JUDGERS):
    vals = [adv_g[g][j]["exact"] for g in gl]
    ax.bar(x4 + (i - OFF) * w4, vals, w4, label=j, color=COLORS[j])
ax.set_xticks(x4); ax.set_xticklabels(gl, fontsize=8, rotation=25); ax.set_ylim(0, 1.18)
ax.set_ylabel("档位命中"); ax.legend(fontsize=7, ncol=3, frameon=False)
ax.set_title("E. 对抗50 各攻击类型档位命中", fontsize=11)

# F ToxicChat 参考
ax = axes[5]
if have_tc:
    tc = json.loads((BASE / "toxicchat_results_full.json").read_text(encoding="utf-8"))["judgers_vs_toxicchat"]
    jl = list(tc.keys()); x5 = np.arange(len(jl)); w5 = 0.35
    prec = [tc[j]["prec"] for j in jl]; rec = [tc[j]["rec"] for j in jl]
    ax.bar(x5 - w5/2, prec, w5, label="prec", color="#38bdf8", alpha=.9)
    ax.bar(x5 + w5/2, rec, w5, label="rec", color="#a78bfa", alpha=.9)
    for xi, v in zip(x5 - w5/2, prec): ax.text(xi, v + 0.01, f"{v:.2f}", ha="center", fontsize=8)
    for xi, v in zip(x5 + w5/2, rec): ax.text(xi, v + 0.01, f"{v:.2f}", ha="center", fontsize=8)
    ax.set_xticks(x5); ax.set_xticklabels(jl, fontsize=9)
    ax.set_ylim(0, 1.15); ax.set_ylabel("比例"); ax.legend(fontsize=8, frameon=False, loc="upper right")
    ax.set_title("F. ToxicChat(n=100)参考对照 · 内容毒性≠数据流四桶，仅拦截口径参考", fontsize=11)
else:
    ax.axis("off")

# G LG vs 混合 拦截召回对比(核心实证: 维度不同)
ax = axes[6]
x6 = np.arange(len(VOLS))
hyb_rec = [VM[v]["混合(L13.2)"]["rec"] for v in VOLS]
lg_rec = [VM[v]["LlamaGuard(LG)"]["rec"] for v in VOLS]
ax.bar(x6 - 0.2, hyb_rec, 0.4, label="混合(L13.2)", color=COLORS["混合(L13.2)"])
ax.bar(x6 + 0.2, lg_rec, 0.4, label="LlamaGuard(LG)", color=COLORS["LlamaGuard(LG)"])
for xi, v in zip(x6 - 0.2, hyb_rec): ax.text(xi, v + 0.02, f"{v:.2f}", ha="center", fontsize=8)
for xi, v in zip(x6 + 0.2, lg_rec): ax.text(xi, v + 0.02, f"{v:.2f}", ha="center", fontsize=8)
ax.set_xticks(x6); ax.set_xticklabels([short(v) for v in VOLS], fontsize=9, rotation=12)
ax.set_ylim(0, 1.15); ax.set_ylabel("真凶拦下率(recall)"); ax.legend(fontsize=8, frameon=False, loc="lower right")
ax.set_title("G. 关键实证：数据流维度 混合 rec=1.0 全卷 · LG rec 0.39-1.0 —— 维度不同,不可替代", fontsize=11, color="#b91c1c")

# H LG 类别分布
ax = axes[7]
if lg:
    import collections
    c = collections.Counter()
    for r in lg["rows"]:
        if r["lg_cats"]:
            for cc in r["lg_cats"]:
                c[cc] += 1
        else:
            c["safe" if r["lg_raw"].startswith("safe") else "unparsed"] += 1
    ks = list(c.keys()); vs = [c[k] for k in ks]
    cols = ["#f472b6", "#22d3ee", "#a3a3a3", "#fbbf24"][:len(ks)]
    ax.bar(ks, vs, color=cols)
    for xi, v in zip(range(len(ks)), vs):
        ax.text(xi, v + 1, str(v), ha="center", fontsize=9)
    ax.set_ylabel("样本数"); ax.set_ylim(0, max(vs) * 1.2)
    ax.set_title("H. LG 输出类别分布：仅 S1(暴力犯罪)+safe —— LG3 无'数据外泄'类目,故误标S1或判safe", fontsize=11, color="#b91c1c")
else:
    ax.axis("off")

fig.text(0.5, 0.006,
         "数据=真实实测 · 主22/对抗(14+36=50)/真实(30+70=100)/提示注入30/分裂22，共224条 · 口径 verdict!=allow 即拦 · "
         "混合(L13.2) 五卷真凶零漏网(唯一FN=提示注入pi09 flow_allow快路径) · 混合FP共5条均为保守误拦已记录 · "
         "第5判定者 LlamaGuard-3-1B(bfloat16本地CPU, 224条, 467s): 拦截口径 rec=0.738, FN=43(均为'无内容危害的数据外泄意图'), "
         "且从未输出S2/S7 → 证明 LG 守护的是'内容有害'而非'数据流出口/提权', 与本系统维度不同、只能互补不能替代。",
         ha="center", fontsize=8.5, color="#64748b")
fig.tight_layout(rect=(0, 0.028, 1, 0.965))
out = BASE / "benchmark_all.png"
fig.savefig(out, dpi=140, bbox_inches="tight")
print("已生成:", out)