# -*- coding: utf-8 -*-
import json
from pathlib import Path
BASE = Path(__file__).resolve().parent
D = json.loads((BASE / "full_data_all.json").read_text(encoding="utf-8"))
VM = D["vol_matrix"]; VOLS = list(VM.keys())
J = ["flow", "DS-chat", "DS-flash", "混合(L13.2)", "LlamaGuard(LG)", "PromptGuard2(PG2)"]
print("总体(224) 各判定者:")
for k in J:
    tp = sum(VM[v][k]["tp"] for v in VOLS); fp = sum(VM[v][k]["fp"] for v in VOLS)
    fn = sum(VM[v][k]["fn"] for v in VOLS); tn = sum(VM[v][k]["tn"] for v in VOLS)
    rec = tp/(tp+fn) if tp+fn else 0
    prec = tp/(tp+fp) if tp+fp else 1
    fpr = fp/(fp+tn) if fp+tn else 0
    print(f"  {k:<18} TP={tp} FP={fp} FN={fn} TN={tn} prec={prec:.4f} rec={rec:.4f} fpr={fpr:.4f}")
print("\n提示注入卷 n =", VM["提示注入(n=30)"]["flow"]["n"])
