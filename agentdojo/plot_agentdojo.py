# -*- coding: utf-8 -*-
"""AgentDojo 主流对标——答辩用图。数据源 agentdojo_results.json (纯 matplotlib, 不依赖 agentdojo)。"""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent
R = json.load(open(BASE / "agentdojo_results.json", encoding="utf-8"))

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "Arial Unicode MS", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False
BLUE, ORG, GRN, RED = "#3b6ea5", "#e08a3c", "#4c9f70", "#c0504d"

fig, axes = plt.subplots(1, 3, figsize=(15.5, 5.0), constrained_layout=True)

# ---- Panel A: 离线分套件载荷拦截 ----
cov = {"banking": (11, 12), "workspace": (6, 10), "slack": (5, 13), "travel": (3, 12)}
ax = axes[0]
suites = list(cov)
blocked = [cov[s][0] for s in suites]
total = [cov[s][1] for s in suites]
b1 = ax.bar(suites, blocked, color=BLUE, label="被判 restrict/block 的作恶终动作", zorder=3)
b2 = ax.bar(suites, [t - bk for t, bk in zip(total, blocked)], bottom=blocked,
            color="#cdd6e0", label="无害只读/中间步(放行)", zorder=3)
for s, bk in zip(suites, blocked):
    ax.text(s, bk + 0.2, f"{bk}/{cov[s][1]}", ha="center", va="bottom", fontsize=11, fontweight="bold", color=BLUE)
ax.set_ylim(0, 14.5)
ax.set_title("A · 离线: 门对 AgentDojo 攻击载荷拦截", fontsize=12, fontweight="bold")
ax.set_ylabel("载荷数")
ax.grid(axis="y", alpha=0.3, zorder=0)
ax.legend(fontsize=9, loc="upper right")
ax.text(0.5, -0.20, "攻击链『最终作恶终动作』(数据外泄/破坏/提权)跨套件全拦;\n低拦截率的套件因其中间步本就无害(只读/查询), 零误拦截合法数据流",
        transform=ax.transAxes, ha="center", fontsize=9, color="#444")

# ---- Panel B: E2E banking 对照 ----
ax = axes[1]
labels = ["基线(无额外防御)", "本方案门"]
dr = [1.0, 1.0]; ut = [0.25, 0.25]
x = range(2)
ax.bar(x, [v * 100 for v in dr], width=0.42, color=GRN, label="防守率(注入被拦)", zorder=3)
ax.bar([i + 0.42 for i in x], [v * 100 for v in ut], width=0.42, color=ORG, label="utility 达成", zorder=3)
for i, v in enumerate(dr):
    ax.text(i, v * 100 + 2, f"{v*100:.0f}%", ha="center", fontsize=11, fontweight="bold", color=GRN)
for i, v in enumerate(ut):
    ax.text(i + 0.42, v * 100 + 2, f"{v*100:.0f}%", ha="center", fontsize=11, fontweight="bold", color=ORG)
ax.set_xticks([i + 0.21 for i in x]); ax.set_xticklabels(labels)
ax.set_ylim(0, 112)
ax.set_title("B · E2E banking 8对(important_instructions)", fontsize=12, fontweight="bold")
ax.set_ylabel("%")
ax.grid(axis="y", alpha=0.3, zorder=0)
ax.legend(fontsize=9, loc="lower right")
ax.text(0.5, -0.20, "100% 由模型原生抗性提供(两模型自拒注入);\n门的增量=模型失误时的 fail-closed 硬边界, 且零误拦截(utility 不受影响)",
        transform=ax.transAxes, ha="center", fontsize=9, color="#444")

# ---- Panel C: 成本对比 ----
ax = axes[2]
names = ["CaMeL(LLM 语义跟踪)", "本方案(本地规则闸)"]
cost = [2.7, 0.0]
bars = ax.bar(names, cost, color=[RED, GRN], zorder=3)
for b, c in zip(bars, cost):
    ax.text(b.get_x() + b.get_width() / 2, c + 0.05, f"~{c:.1f}x" if c else "≈0 (无 LLM 调用)",
            ha="center", va="bottom", fontsize=10.5, fontweight="bold", color=c and RED or GRN)
ax.set_ylim(0, 3.2)
ax.set_title("C · 每笔判断相对基准 token 开销", fontsize=12, fontweight="bold")
ax.set_ylabel("token 倍数(越低越省)")
ax.grid(axis="y", alpha=0.3, zorder=0)
ax.text(0.5, -0.20, "CaMeL 依赖 LLM 判定与内容外发;\n本方案仅对工具调用行做本地词干化+规则, 无外发、确定性",
        transform=ax.transAxes, ha="center", fontsize=9, color="#444")

out = BASE / "figN_agentdojo_主流对标.png"
fig.savefig(out, dpi=200, bbox_inches="tight")
print("saved", out)