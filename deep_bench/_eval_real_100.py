# -*- coding: utf-8 -*-
"""真实强度卷全量评分(n=100 = 原30 + 扩充70)：读 realistic_* 两判定文件 + real_extend_results -> 跑 L13.2 hybrid_gate。
输出 4 判定者矩阵 + 强度(I)分解 + 有害/无害子集。只读已落盘真实判定，不联网不编造。
"""
from __future__ import annotations
import json, sys, collections
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parents[2] / "learning"))
from hybrid_gate import hybrid_review  # noqa: E402

JUDGERS = ["flow", "DS-chat", "DS-flash", "混合(L13.2)"]


def norm(x):
    return x if x in ("allow", "review", "restrict", "block") else "review"


def matrix(rows, key):
    tp = fp = fn = tn = 0; exact = 0
    for r in rows:
        exp, act = r["expected"], r[key]
        ep, ap = exp != "allow", act != "allow"
        if ep and ap: tp += 1
        elif ep and not ap: fn += 1
        elif not ep and ap: fp += 1
        else: tn += 1
        if act == exp: exact += 1
    n = len(rows)
    return {"n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "prec": round(tp/(tp+fp), 4) if tp+fp else 1.0,
            "rec": round(tp/(tp+fn), 4) if tp+fn else 1.0,
            "exact": round(exact/n, 4)}


records = []
# 原 30 条
base_samples = json.loads((BASE / "realistic_intensity_samples.json").read_text(encoding="utf-8"))["samples"]
base_res_c = json.loads((BASE / "realistic_results_chat.json").read_text(encoding="utf-8"))["rows"]
base_res_f = json.loads((BASE / "realistic_results_flash.json").read_text(encoding="utf-8"))["rows"]
byid_c = {r["id"]: r for r in base_res_c}
byid_f = {r["id"]: r for r in base_res_f}
for s in base_samples:
    sid = s["id"]
    c = byid_c.get(sid, {}); f = byid_f.get(sid, {})
    cb, fb = norm(c.get("ds_bucket")), norm(f.get("ds_bucket"))
    hyb, meta = hybrid_review(s["text"], cb, fb)
    records.append({"vol": "原(30)", "id": sid, "expected": s["expected_verdict"],
                    "intensity": s.get("intensity", ""), "text": s["text"],
                    "flow": norm(c.get("flow_bucket")), "DS-chat": cb, "DS-flash": fb,
                    "混合(L13.2)": hyb, "path": meta["path"]})
# 扩充 70 条
ext_res = json.loads((BASE / "real_extend_results.json").read_text(encoding="utf-8"))["rows"]
for r in ext_res:
    cb, fb = norm(r.get("ds_chat_bucket")), norm(r.get("ds_flash_bucket"))
    hyb, meta = hybrid_review(r["text"], cb, fb)
    records.append({"vol": "扩充(70)", "id": r["id"], "expected": r["expected"],
                    "intensity": r.get("group", ""), "text": r["text"],
                    "flow": norm(r["flow_bucket"]), "DS-chat": cb, "DS-flash": fb,
                    "混合(L13.2)": hyb, "path": meta["path"]})

all100 = records
m_all = {j: matrix(all100, j) for j in JUDGERS}

# 强度分解
by_int = collections.defaultdict(list)
for r in all100:
    by_int[r["intensity"]].append(r)
m_int = {k: {j: matrix(sub, j) for j in JUDGERS} for k, sub in by_int.items()}

# 有害(n_true) vs 无害(pass) 子集
true_rows = [r for r in all100 if r["expected"] != "allow"]
pass_rows = [r for r in all100 if r["expected"] == "allow"]
m_sub = {"n_true": {j: matrix(true_rows, j) for j in JUDGERS},
         "n_pass": {j: matrix(pass_rows, j) for j in JUDGERS}}

out = {"_meta": {"vol": "真实强度卷全量(n=100)=原30+扩充70", "honest": "原30读realistic两判定文件,扩充70为实时实测; 混合L13.2据真实双模型复算; 未伪造"},
       "matrix": m_all, "by_intensity": m_int, "subset": m_sub, "records": records}
(BASE / "real_full100_results.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

print(f"=== 真实强度卷全量(n={len(all100)}) ===")
for j in JUDGERS:
    m = m_all[j]
    print(f"{j:<12} TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} "
          f"prec={m['prec']:.3f} rec={m['rec']:.3f} exact={m['exact']:.3f}")
print("\n=== 强度分解 ===")
for k, sub in by_int.items():
    m = m_int[k][JUDGERS[3]]
    print(f"{k}: n={len(sub)} 混合 exact={m['exact']:.3f} FP={m['fp']} FN={m['fn']}")
print(f"\n=== 子集(n_true/pass) 混合 ===")
for k in ("n_true", "n_pass"):
    m = m_sub[k][JUDGERS[3]]
    print(f"{k}: TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} exact={m['exact']:.3f}")