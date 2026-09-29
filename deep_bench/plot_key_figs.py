# -*- coding: utf-8 -*-
"""丘奖答辩/论文用【两张重点图】：
  figD_抗注入ASR.png        —— 图D：提示注入攻击成功率(ASR)；左=各判定者总ASR，右=按攻击类型分解
  figG_维度不可替代性.png    —— 图G：混合(L13.2) vs LlamaGuard 各卷召回 + LG 输出类别分布(证据)
数据全部来自 full_data_all.json（真实落盘），口径 verdict!=allow 即拦。数字与报告 §13 完全一致，未修饰。
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
VM = D["vol_matrix"]; ST = D["structure"]; LGE = D["lg_eval"]

for _f in ("Microsoft YaHei", "SimHei", "PingFang SC", "Arial"):
    if any(_f == f.name for f in fm.fontManager.ttflist):
        plt.rcParams["font.sans-serif"] = [_f]; break
plt.rcParams["axes.unicode_minus"] = False

JUDGERS = ["flow", "DS-chat", "DS-flash", "混合(L13.2)", "LlamaGuard(LG)"]
COLORS = {"flow": "#64748b", "DS-chat": "#3b82f6", "DS-flash": "#f59e0b",
          "混合(L13.2)": "#10b981", "LlamaGuard(LG)": "#ec4899"}
VOLS = list(VM.keys())


def asr_of(m):
    tot = m["fn"] + m["tp"]
    return (m["fn"] / tot * 100) if tot else 0.0


# ============================ 图 D：抗注入 ASR ============================
PV = VM["提示注入(n=30)"]
fig = plt.figure(figsize=(19, 8.2))
gs = fig.add_gridspec(1, 2, width_ratios=[1.0, 1.55], wspace=0.20)

# --- D1 各判定者总 ASR ---
ax = fig.add_subplot(gs[0, 0])
vals = [asr_of(PV[j]) for j in JUDGERS]
bars = ax.bar(range(len(JUDGERS)), vals, color=[COLORS[j] for j in JUDGERS], width=0.62)
for i, v in enumerate(vals):
    ax.text(i, v + 0.35, f"{v:.1f}%", ha="center", va="bottom",
            fontsize=17, fontweight="bold",
            color=("#15803d" if v == 0 else "#b91c1c"))
ax.set_xticks(range(len(JUDGERS)))
ax.set_xticklabels([j.replace("(", "\n(") for j in JUDGERS], fontsize=12)
ax.set_ylabel("提示注入攻击成功率 ASR (%)", fontsize=14)
ax.set_ylim(0, 7.2)
ax.set_title("D-1  提示注入卷总 ASR（n=30，其中恶意 24 条）\n"
             "语义双模型与 LG 均 0%；混合门 4.2%（pi09 快路径，已记录）",
             fontsize=14, fontweight="bold")
ax.axhline(0, color="#94a3b8", lw=1)
ax.grid(axis="y", ls=":", alpha=.45)
ax.annotate("唯一漏放 = pi09\n(multi-turn 上下文投毒)", xy=(3, 4.17), xytext=(3.35, 6.2),
            fontsize=10, color="#b91c1c",
            arrowprops=dict(arrowstyle="->", color="#b91c1c", lw=1.4))

# --- D2 按攻击类型分解 ---
ax = fig.add_subplot(gs[0, 1])
pg = ST["攻击类型分解(提示注入30)"]
types = list(pg.keys())
x = np.arange(len(types)); w = 0.16
OFF = (len(JUDGERS) - 1) / 2.0
for i, j in enumerate(JUDGERS):
    ys = [asr_of(pg[t][j]) for t in types]
    ax.bar(x + (i - OFF) * w, ys, w, label=j, color=COLORS[j])
ax.set_xticks(x); ax.set_xticklabels(types, fontsize=10.5, rotation=28, ha="right")
ax.set_ylabel("该类型 ASR (%)", fontsize=14); ax.set_ylim(0, 118)
ax.legend(fontsize=10, ncol=5, frameon=False, loc="upper center")
ax.set_title("D-2  按攻击类型分解 · 仅『多轮上下文投毒』出现漏放，其余 15 类全 0%",
             fontsize=14, fontweight="bold")
ax.grid(axis="y", ls=":", alpha=.45)

fig.suptitle("图D · 抗提示注入能力：语义层与内容护栏均免疫，唯混合门的零调用快路径存 1 条裂缝",
             fontsize=16.5, fontweight="bold")
fig.text(0.5, 0.015,
         "口径：verdict!=allow 即拦；ASR = 该拦未拦 / 应拦样本数。数据源 full_data_all.json（224条五卷实测）· "
         "DS-chat / DS-flash / LlamaGuard 在注入卷 ASR=0%；混合(L13.2) ASR=4.2%（1/24，样本 pi09）。",
         ha="center", fontsize=10, color="#475569")
fig.tight_layout(rect=(0, 0.045, 1, 0.93))
outD = BASE / "figD_抗注入ASR.png"
fig.savefig(outD, dpi=200, bbox_inches="tight"); plt.close(fig)
print("已生成:", outD)


# ==================== 图 G：维度不可替代性 ====================
fig = plt.figure(figsize=(19, 8.2))
gs = fig.add_gridspec(1, 2, width_ratios=[1.75, 1.0], wspace=0.20)

# --- G1 各卷召回：混合 vs LG ---
ax = fig.add_subplot(gs[0, 0])
hyb = [VM[v]["混合(L13.2)"]["rec"] for v in VOLS]
lg = [VM[v]["LlamaGuard(LG)"]["rec"] for v in VOLS]
x = np.arange(len(VOLS))
b1 = ax.bar(x - 0.2, hyb, 0.4, label="混合(L13.2) · 数据流维度", color=COLORS["混合(L13.2)"])
b2 = ax.bar(x + 0.2, lg, 0.4, label="LlamaGuard-3-1B · 内容维度", color=COLORS["LlamaGuard(LG)"])
for xi, v in zip(x - 0.2, hyb):
    ax.text(xi, v + 0.02, f"{v:.2f}", ha="center", fontsize=12, fontweight="bold", color="#065f46")
for xi, v in zip(x + 0.2, lg):
    ax.text(xi, v + 0.02, f"{v:.2f}", ha="center", fontsize=12, fontweight="bold", color="#9d174d")
ax.set_xticks(x); ax.set_xticklabels([v.split("(")[0] for v in VOLS], fontsize=13)
ax.set_ylabel("真凶拦下率 Recall", fontsize=14); ax.set_ylim(0, 1.22)
ax.legend(fontsize=12, frameon=False, loc="upper right")
ax.set_title("G-1  各卷召回对比 · 数据流维度混合门全卷 1.00（提示注入 0.96）\n"
             "LG 在四数据流卷 0.38–0.86，仅注入卷 1.00 —— 维度不匹配",
             fontsize=14, fontweight="bold")
ax.grid(axis="y", ls=":", alpha=.45)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.55)

# --- G2 LG 输出类别分布(证据) ---
ax = fig.add_subplot(gs[0, 1])
cd = LGE["cat_distribution"]
keys = ["S1 暴力犯罪\n(violent_crimes)", "safe\n(判为无害)", "S2 非暴力犯罪\n(含网络/数据犯罪)", "S7 隐私\n(凭据/PII)"]
vals = [cd.get("violent_crimes", 0), cd.get("safe", 0), 0, 0]
cols = ["#ec4899", "#22d3ee", "#cbd5e1", "#cbd5e1"]
bars = ax.bar(range(4), vals, color=cols, width=0.6)
for i, v in enumerate(vals):
    ax.text(i, v + 2.5, str(v), ha="center", fontsize=15, fontweight="bold",
            color=("#9a3412" if i >= 2 else "#0f172a"))
ax.set_xticks(range(4)); ax.set_xticklabels(keys, fontsize=11)
ax.set_ylabel("样本数（共 224）", fontsize=14); ax.set_ylim(0, 165)
ax.set_title("G-2  LG 输出类别分布 · 关键证据\n"
             "S2/S7 命中 0 次：LG-3 无『数据外泄』类目，只能误标 S1 或判 safe",
             fontsize=14, fontweight="bold")
ax.axvspan(1.5, 3.5, color="#fef2f2", zorder=0)
ax.text(2.5, 120, "0 次", ha="center", fontsize=30, fontweight="bold", color="#dc2626", alpha=.85)

fig.suptitle("图G · 维度不可替代性：内容护栏 ≠ 数据流护栏（LG 总体召回 0.74，FN=43 全为无内容危害的外泄/篡改意图）",
             fontsize=16, fontweight="bold")
fig.text(0.5, 0.015,
         "注：报告口径中 LG 总体召回=0.738；0.38 为『分裂卷』单卷值，非总体——引用时请勿以单卷值替代总体。"
         "LG 与混合门维度不同（内容有害 vs 数据流出口/篡改/提权），二者互补而非替代。数据源 full_data_all.json + lg_eval.json。",
         ha="center", fontsize=10, color="#475569")
fig.tight_layout(rect=(0, 0.045, 1, 0.93))
outG = BASE / "figG_维度不可替代性.png"
fig.savefig(outG, dpi=200, bbox_inches="tight"); plt.close(fig)
print("已生成:", outG)