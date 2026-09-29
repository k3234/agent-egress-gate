# -*- coding: utf-8 -*-
"""核对答辩口径用的关键数字：提示注入 ASR、四/五卷 FN、LG 召回。只读落盘数据。"""
import json
from pathlib import Path
BASE = Path(__file__).resolve().parent
D = json.loads((BASE / "full_data_all.json").read_text(encoding="utf-8"))
VM = D["vol_matrix"]

print("=== 提示注入卷(n=30) 各判定者 ===")
pv = VM["提示注入(n=30)"]
for j, m in pv.items():
    fn, tp = m["fn"], m["tp"]
    asr = fn / (fn + tp) * 100 if (fn + tp) else 0.0
    print(f"{j:<16} TP={tp} FN={fn} -> ASR={asr:.2f}%")

print("\n=== 四数据流卷（不含提示注入）混合 FN ===")
tot = 0
for v, m in VM.items():
    if v.startswith("提示注入"):
        continue
    tot += m["混合(L13.2)"]["fn"]
    print(f"{v:<16} n={m['混合(L13.2)']['n']} 混合FN={m['混合(L13.2)']['fn']}")
n_dflow = sum(m["混合(L13.2)"]["n"] for v, m in VM.items() if not v.startswith("提示注入"))
print(f"四数据流卷合计 n={n_dflow}, 混合 FN={tot}")

print("\n=== 混合 五卷全部 FN ===")
tf = sum(m["混合(L13.2)"]["fn"] for m in VM.values())
print("混合五卷 FN 合计 =", tf)
print("混合五卷 N 合计 =", sum(m["混合(L13.2)"]["n"] for m in VM.values()))

print("\n=== LG 召回 ===")
for v, m in VM.items():
    print(f"{v:<16} rec={m['LlamaGuard(LG)']['rec']}")
print("LG 总体 rec =", D["lg_eval"]["cat_distribution"], D["lg_eval"]["n_fn"])
