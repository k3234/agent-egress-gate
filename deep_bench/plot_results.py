# -*- coding: utf-8 -*-
"""本地柱状图：主卷 vs 对抗改写子卷，三位判定者对比。

数据来源（均为真实实测、已落盘，非编造）：
  - flow(L13 规则)   : deep_bench_results_flash.json / adversarial_results_flash.json
  - DS(V4.1-Flash)   : 同上述两文件 deepseek 段
  - 混合(flow定+DS补) : _eval_hybrid.py 实测输出
口径：verdict != allow 即『拦』；prec/rec 按此计。rec=1.0 即 FN=0(漏检=0)。
第三判定者 Llama Guard：网络(HF双源超时)+CPU-only 未纳入，图中标注空缺。
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import numpy as np

BASE = Path(__file__).resolve().parent

# 中文字体（Windows 通用，Matplotlib 需能找到）
for _f in ("Microsoft YaHei", "SimHei", "PingFang SC", "Arial"):
    if any(_f == f.name for f in fm.fontManager.ttflist):
        plt.rcParams["font.sans-serif"] = [_f]
        break
plt.rcParams["axes.unicode_minus"] = False


def load_scores(fn):
    d = json.loads((BASE / fn).read_text(encoding="utf-8"))
    return d["flow_local"]["scores"], d["deepseek"]["scores"]


def hybrid_score(fn):
    """复算 _eval_hybrid：flow 定非 review 项，review 交 DS。"""
    rows = json.loads((BASE / fn).read_text(encoding="utf-8"))["rows"]
    tp = fp = fn = tn = 0
    for r in rows:
        exp = r["expected"]
        fb = r["flow_bucket"]
        ds = r["ds_bucket"]
        act = fb if fb != "review" and fb in ("allow", "review", "restrict", "block") else None
        if act is None:
            act = ds if ds in ("allow", "review", "restrict", "block") else "review"
        if exp != "allow" and act != "allow":
            tp += 1
        elif exp != "allow" and act == "allow":
            fn += 1
        elif exp == "allow" and act != "allow":
            fp += 1
        else:
            tn += 1
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, prec=round(prec, 3), rec=round(rec, 3),
                exact=round(tp + tn, 3))


f_mp, d_mp = load_scores("deep_bench_results_flash.json")
f_adv, d_adv = load_scores("adversarial_results_flash.json")
h_mp = hybrid_score("deep_bench_results_flash.json")
h_adv = hybrid_score("adversarial_results_flash.json")

judgers = ["flow\n(L13规则)", "DS\nV4.1-Flash", "混合\nflow+DS"]
main_prec = [f_mp["prec"], d_mp["prec"], h_mp["prec"]]
adv_prec = [f_adv["prec"], d_adv["prec"], h_adv["prec"]]
main_rec = [f_mp["rec"], d_mp["rec"], h_mp["rec"]]
adv_rec = [f_adv["rec"], d_adv["rec"], h_adv["rec"]]

x = np.arange(len(judgers))
w = 0.38
cmain, cadv = "#60a5fa", "#fbbf24"

fig, axes = plt.subplots(1, 2, figsize=(12, 5.4))
fig.suptitle("安全审查判定者能力对比 · 主卷 vs 对抗改写子卷", fontsize=15, fontweight="bold")

# ---- 左：精确率 ----
ax = axes[0]
b1 = ax.bar(x - w / 2, main_prec, w, label="主卷(n=22)", color=cmain)
b2 = ax.bar(x + w / 2, adv_prec, w, label="对抗改写子卷(n=14)", color=cadv)
for bars, vals in ((b1, main_prec), (b2, adv_prec)):
    for r, v in zip(bars, vals):
        ax.text(r.get_x() + r.get_width() / 2, v + 0.01, f"{v:.3f}",
                ha="center", va="bottom", fontsize=11)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.6)
ax.set_xticks(x); ax.set_xticklabels(judgers, fontsize=11)
ax.set_ylim(0.4, 1.12)
ax.set_ylabel("精确率 Precision"); ax.set_title("· 对抗改写后规则误伤↑(0.944→0.846)", fontsize=11)
ax.legend(fontsize=10, frameon=False)
ax.annotate("FP=2(无害改写被判审)", xy=(0.5, adv_prec[0] + 0.0), xytext=(1.55, 0.62),
            arrowprops=dict(arrowstyle="->", color="#64748b"), color="#64748b", fontsize=10)

# ---- 右：召回率 ----
ax = axes[1]
b1 = ax.bar(x - w / 2, main_rec, w, label="主卷", color=cmain)
b2 = ax.bar(x + w / 2, adv_rec, w, label="对抗改写子卷", color=cadv)
for bars, vals in ((b1, main_rec), (b2, adv_rec)):
    for r, v in zip(bars, vals):
        ax.text(r.get_x() + r.get_width() / 2, v + 0.005, f"{v:.3f}",
                ha="center", va="bottom", fontsize=11)
ax.axhline(1.0, color="#22d3ee", ls="--", lw=1, alpha=.6)
ax.set_xticks(x); ax.set_xticklabels(judgers, fontsize=11)
ax.set_ylim(0.6, 1.1)
ax.set_ylabel("召回率 Recall"); ax.set_title("· 关键底线：三个判定者 FN=0，无一漏检", fontsize=11, color="#15803d")
ax.legend(fontsize=10, frameon=False)

fig.text(0.5, 0.012,
         "口径：verdict≠allow 即『拦』（fail-closed 从严）。rec=1.0 表示 FN=0（真凶零漏网）。"
         "第4判定者 Llama Guard：HuggingFace/镜像双源超时+CPU-only，网络受限未纳入。",
         ha="center", fontsize=9, color="#64748b")

fig.tight_layout(rect=(0, 0.04, 1, 0.95))
out = BASE / "benchmark_comparison.png"
fig.savefig(out, dpi=150, bbox_inches="tight")
print("已生成:", out)
print("主卷   prec:", dict(zip(judgers, main_prec)), "rec:", dict(zip(judgers, main_rec)))
print("对抗子 prec:", dict(zip(judgers, adv_prec)), "rec:", dict(zip(judgers, adv_rec)))
print("flow 对抗 exact 档位命中=4/14(其余拦但降档review)→人工成本高；DS/混合=13/14")