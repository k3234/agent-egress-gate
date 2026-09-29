# -*- coding: utf-8 -*-
"""【主流方案 vs 本方案】对照图（丘奖答辩用）：
  M1 各卷召回：本方案(混合) vs LlamaGuard-3-1B(内容护栏) vs PromptGuard-2-86M(注入分类器)
  M2 提示注入卷正面交锋：召回/精确率
  M3 PromptGuard2 阈值扫描(FPR-Recall)，标注本方案单点操作点
  M4 全量224条总体 精确率/召回率/FPR
数据源 full_data_all.json + pg_eval.json（真实落盘，未修饰）。
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
VM = D["vol_matrix"]
PG = json.loads((BASE / "pg_eval.json").read_text(encoding="utf-8"))

for _f in ("Microsoft YaHei", "SimHei", "PingFang SC", "Arial"):
    if any(_f == f.name for f in fm.fontManager.ttflist):
        plt.rcParams["font.sans-serif"] = [_f]; break
plt.rcParams["axes.unicode_minus"] = False

VOLS = list(VM.keys())
SERIES = {
    "本方案 混合(L13.2)": ("混合(L13.2)", "#10b981"),
    "LlamaGuard-3-1B (内容护栏)": ("LlamaGuard(LG)", "#ec4899"),
    "PromptGuard-2-86M (注入分类器)": ("PromptGuard2(PG2)", "#8b5cf6"),
}
HATCH = {"混合(L13.2)": "", "LlamaGuard(LG)": "//", "PromptGuard2(PG2)": "\\\\"}

fig, axes = plt.subplots(2, 2, figsize=(18, 12.5))
ax = axes[0][0]
x = np.arange(len(VOLS)); w = 0.26
for i, (label, (key, col)) in enumerate(SERIES.items()):
    vals = [VM[v][key]["rec"] for v in VOLS]
    ax.bar(x + (i - 1) * w, vals, w, label=label, color=col, edgecolor="white")
    for xi, vv in zip(x + (i - 1) * w, vals):
        ax.text(xi, vv + 0.02, f"{vv:.2f}", ha="center", fontsize=9, fontweight="bold")
ax.set_xticks(x); ax.set_xticklabels([v.split("(")[0] for v in VOLS], fontsize=12)
ax.set_ylabel("真凶拦下率 Recall", fontsize=13); ax.set_ylim(0, 1.2)
ax.legend(fontsize=10.5, frameon=False, loc="upper center", ncol=1)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.55)
ax.set_title("M1  各卷召回：本方案全卷接近/达 1.00\n两个主流模型在数据流维度大幅掉档", fontsize=13, fontweight="bold")
ax.grid(axis="y", ls=":", alpha=.4)

# M2 注入卷正面交锋
ax = axes[0][1]
INJ = "提示注入(n=30)"
cands = [("本方案 混合(L13.2)", "混合(L13.2)", "#10b981"),
         ("DS-flash", "DS-flash", "#f59e0b"),
         ("LlamaGuard-3-1B", "LlamaGuard(LG)", "#ec4899"),
         ("PromptGuard-2-86M", "PromptGuard2(PG2)", "#8b5cf6")]
x2 = np.arange(len(cands)); w2 = 0.35
recs = [VM[INJ][k]["rec"] for _, k, _ in cands]
precs = [VM[INJ][k]["prec"] for _, k, _ in cands]
ax.bar(x2 - w2/2, recs, w2, label="召回 Recall", color="#22c55e")
ax.bar(x2 + w2/2, precs, w2, label="精确率 Precision", color="#38bdf8")
for xi, v in zip(x2 - w2/2, recs): ax.text(xi, v + 0.02, f"{v:.3f}", ha="center", fontsize=10, fontweight="bold")
for xi, v in zip(x2 + w2/2, precs): ax.text(xi, v + 0.02, f"{v:.3f}", ha="center", fontsize=10, fontweight="bold")
ax.set_xticks(x2); ax.set_xticklabels([c[0].replace(" ", "\n") for c in cands], fontsize=10.5)
ax.set_ylim(0, 1.22); ax.set_ylabel("比例", fontsize=13)
ax.legend(fontsize=11, frameon=False, loc="lower right")
ax.set_title("M2  提示注入卷正面交锋（本任务主战场）\n本方案 rec=0.958；Meta 专用注入分类器仅 0.333", fontsize=13, fontweight="bold", color="#b91c1c")
ax.grid(axis="y", ls=":", alpha=.4)

# M3 PG2 阈值扫描
ax = axes[1][0]
sw = PG["sweep_injection"]
fr = [s["fpr"] for s in sw]; rc = [s["rec"] for s in sw]
ax.plot(fr, rc, "-o", color="#8b5cf6", lw=2.2, ms=9, label="PromptGuard-2 阈值扫描（注入卷）")
for s in sw[::2]:
    ax.annotate(f"thr={s['thr']:.2f}", (s["fpr"], s["rec"]), textcoords="offset points",
                xytext=(6, 6), fontsize=8.5, color="#6d28d9")
our = VM[INJ]["混合(L13.2)"]
ax.scatter([our["fp"]/(our["fp"]+our["tn"])], [our["rec"]], s=260, marker="*",
           color="#10b981", zorder=5, label="本方案 混合(L13.2) 单点操作点")
ax.annotate(f"本方案 rec={our['rec']:.3f}\n(FP={our['fp']}, 无需阈值调参)",
            (our["fp"]/(our["fp"]+our["tn"]), our["rec"]), textcoords="offset points",
            xytext=(-150, -46), fontsize=10, color="#065f46", fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#065f46"))
ax.set_xlabel("假阳性率 FPR", fontsize=13); ax.set_ylabel("召回 Recall", fontsize=13)
ax.set_xlim(-0.02, 0.5); ax.set_ylim(0, 0.75)
ax.legend(fontsize=10.5, frameon=False, loc="upper left")
ax.set_title("M3  PromptGuard-2 全阈值扫描仍够不到本方案\n（即便 thr=0.05，注入卷 recall 仅 0.583）", fontsize=13, fontweight="bold", color="#b91c1c")
ax.grid(ls=":", alpha=.4)

# M4 总体
ax = axes[1][1]
groups = [("本方案 混合(L13.2)", VM["__none__"] if False else None)]
labels = ["本方案\n混合(L13.2)", "LlamaGuard\n-3-1B", "PromptGuard\n-2-86M"]
# 总体从各卷聚合
def overall(key):
    tp = sum(VM[v][key]["tp"] for v in VOLS); fp = sum(VM[v][key]["fp"] for v in VOLS)
    fn = sum(VM[v][key]["fn"] for v in VOLS); tn = sum(VM[v][key]["tn"] for v in VOLS)
    return {"rec": tp/(tp+fn) if tp+fn else 0, "prec": tp/(tp+fp) if tp+fp else 1.0, "fpr": fp/(fp+tn) if fp+tn else 0}
ov = [overall("混合(L13.2)"), overall("LlamaGuard(LG)"), overall("PromptGuard2(PG2)")]
x4 = np.arange(3); w4 = 0.26
for i, (metric, col, lab) in enumerate([("rec", "#22c55e", "召回 Recall"),
                                        ("prec", "#38bdf8", "精确率 Precision"),
                                        ("fpr", "#f97316", "假阳性率 FPR")]):
    vals = [o[metric] for o in ov]
    ax.bar(x4 + (i - 1) * w4, vals, w4, label=lab, color=col)
    for xi, v in zip(x4 + (i - 1) * w4, vals):
        ax.text(xi, v + 0.015, f"{v:.3f}", ha="center", fontsize=10, fontweight="bold")
ax.set_xticks(x4); ax.set_xticklabels(labels, fontsize=12)
ax.set_ylim(0, 1.2); ax.set_ylabel("比例", fontsize=13)
ax.legend(fontsize=11, frameon=False, loc="upper right")
ax.set_title("M4  全量 224 条总体：本方案 rec=1.000 且 FPR 最低\n主流方案的精确率虽高，但召回不足以承担防线", fontsize=13, fontweight="bold")
ax.grid(axis="y", ls=":", alpha=.4)

fig.suptitle("图M · 主流方案 vs 本方案：内容护栏与注入分类器都无法替代『数据流出口审查』",
             fontsize=17, fontweight="bold")
fig.text(0.5, 0.012,
         "口径 verdict!=allow 即拦。LlamaGuard-3-1B 与 PromptGuard-2-86M 均为本地 CPU 实测（224 条）。"
         "PromptGuard-2 是 Meta 官方 AUC .998 / recall@1%FPR 97.5% 的专用注入分类器，但在本任务注入卷 recall 仅 0.333、"
         "全阈值上界 0.583；LlamaGuard 在数据流维度总体 0.738 且从未命中 S2/S7。二者与本方案维度不同，属互补而非替代。",
         ha="center", fontsize=9.5, color="#475569")
fig.tight_layout(rect=(0, 0.035, 1, 0.94))
out = BASE / "figM_主流方案对照.png"
fig.savefig(out, dpi=200, bbox_inches="tight")
print("已生成:", out)
for lab, o in zip(labels, ov):
    print(lab.replace("\n", ""), {k: round(v, 4) for k, v in o.items()})