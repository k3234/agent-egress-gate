# -*- coding: utf-8 -*-
"""合并 Llama Guard 结果：读 lg_results + full_comparison_data/split，产出带 LG 的完整对比摘要 lg_comparison.json。

诚实口径：
  - LG 是内容护栏二分类，档位为其近似映射(见 _run_lg)；与其余判定者只在"拦截口径"(allow 放行 vs 非allow 拦)严格可比。
  - 单独报 LG 在四卷的 FN/FP(拦截口径) + 档位命中(近似)，并明确标注任务维度差异。
"""
from __future__ import annotations
import json, collections
from pathlib import Path

BASE = Path(__file__).resolve().parent
res = json.loads((BASE / "lg_results.json").read_text(encoding="utf-8"))["rows"]
full = json.loads((BASE / "full_comparison_data.json").read_text(encoding="utf-8"))

# 分组
by_vol = collections.defaultdict(list)
for r in res:
    by_vol[r["vol"]].append(r)

vol_names = list(by_vol.keys())
out = {"_meta": {
    "model": "Llama-Guard-3-1B", "device": "cpu",
    "honest": ("LG为内容护栏(检测有害/攻击内容)，与flow/DS的【数据流出口+提权】维度不同；"
               "拦截口径(allow vs 非allow)可比，档位为显式近似映射。若LG对无内容危害的恶意意图标safe=FN，属任务差异真实体现。"),
}, "volumes": {}}

for vol in vol_names:
    items = by_vol[vol]
    inter = tp = fp = fn = tn = 0
    exact = 0
    cat_counts = collections.Counter()
    for it in items:
        exp = it["expected"]; lg = it["lg_bucket"]; raw = it["lg_raw"]
        exp_pos = exp != "allow"; lg_pos = lg != "allow"
        if exp_pos and lg_pos: tp += 1
        elif exp_pos and not lg_pos: fn += 1
        elif not exp_pos and lg_pos: fp += 1
        else: tn += 1
        if lg == exp: exact += 1
        cat_counts[raw.split("|")[0]] += 1
    n = len(items)
    out["volumes"][vol] = {
        "n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "prec_intercept": round(tp/(tp+fp), 3) if (tp+fp) else None,
        "rec_intercept": round(tp/(tp+fn), 3) if (tp+fn) else None,
        "exact_bucket_approx": round(exact/n, 3),
        "intercept_helm": f"{tp+fp}/{n}",       # 拦截到多少
        "missed_true_intercept": fn,            # LN 漏真凶(任务差异所致)
        "lg_outcome": dict(cat_counts),
    }

(BASE / "lg_comparison.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(out, ensure_ascii=False, indent=2))