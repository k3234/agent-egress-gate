# -*- coding: utf-8 -*-
"""对抗卷全量评分(n=50 = 原14 + 扩充36)：读原 adversarial_samples/adv_extend_results -> 跑 L13.2 hybrid_gate。
输出 4 判定者矩阵 + 攻击类型分解。只读已落盘真实判定，不联网不编造。
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
# 原 14 条
base_samples = json.loads((BASE / "adversarial_samples.json").read_text(encoding="utf-8"))["samples"]
base_res = json.loads((BASE / "adversarial_results_chat.json").read_text(encoding="utf-8"))["rows"]
flash_res = json.loads((BASE / "adversarial_results_flash.json").read_text(encoding="utf-8"))["rows"]
byid_c = {r["id"]: r for r in base_res}
byid_f = {r["id"]: r for r in flash_res}
for s in base_samples:
    sid = s["id"]
    c = byid_c.get(sid, {}); f = byid_f.get(sid, {})
    cb, fb = norm(c.get("ds_bucket")), norm(f.get("ds_bucket"))
    hyb, meta = hybrid_review(s["text"], cb, fb)
    records.append({"vol": "原(14)", "id": sid, "expected": s["expected_verdict"],
                    "group": s["attack_type"], "text": s["text"],
                    "flow": norm(c.get("flow_bucket")), "DS-chat": cb, "DS-flash": fb,
                    "混合(L13.2)": hyb, "path": meta["path"]})
# 扩充 36 条
ext_samples = json.loads((BASE / "adv_extend_samples.json").read_text(encoding="utf-8"))["samples"]
ext_res = json.loads((BASE / "adv_extend_results.json").read_text(encoding="utf-8"))["rows"]
for r in ext_res:
    cb, fb = norm(r.get("ds_chat_bucket")), norm(r.get("ds_flash_bucket"))
    hyb, meta = hybrid_review(r["text"], cb, fb)
    records.append({"vol": "扩充(36)", "id": r["id"], "expected": r["expected"],
                    "group": r["group"], "text": r["text"], "flow": norm(r["flow_bucket"]),
                    "DS-chat": cb, "DS-flash": fb, "混合(L13.2)": hyb, "path": meta["path"]})

all50 = records
m_all = {j: matrix(all50, j) for j in JUDGERS}

# 攻击类型分解(全部50)
groups = collections.defaultdict(list)
for r in all50:
    groups[r["group"]].append(r)
m_group = {g: {j: matrix(sub, j) for j in JUDGERS} for g, sub in groups.items()}

out = {"_meta": {"vol": "对抗卷全量(n=50)=原14+扩充36", "honest": "原14读写原两判定文件,扩充36为实时实测; 混合L13.2据真实双模型复算; 未伪造"},
       "matrix": m_all, "by_group": m_group, "records": records}
(BASE / "adv_full50_results.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

print(f"=== 对抗卷全量(n=50) ===")
for j in JUDGERS:
    m = m_all[j]
    print(f"{j:<12} TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} "
          f"prec={m['prec']:.3f} rec={m['rec']:.3f} exact={m['exact']:.3f}")
print("\n[每条 期望/flow/chat/flash/混合/路径]")
for r in all50:
    print(f"[{r['id']}|{r['vol']}|{r['group']}] exp={r['expected']} f={r['flow']} "
          f"c={r['DS-chat']} s={r['DS-flash']} h={r['混合(L13.2)']} {r['path']} | {r['text'][:30]}")