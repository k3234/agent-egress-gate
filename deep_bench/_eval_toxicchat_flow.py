# -*- coding: utf-8 -*-
"""ToxicChat 公开基准卷：跑本地 flow(L13) 拦截判定 + 如实标注维度差异。

诚实口径：
  - expected_verdict 是 ToxicChat『内容毒性』二分的拦截代理，非本系统『数据流四桶』标答。
  - flow 输出的是数据流出口/提权四桶(allow/review/restrict/block)。
  - 二者任务维度不同：此处报告 flow 对『毒害文本』的识别能力(参考性)，并明确说明
    flow 面向的是数据外泄/篡改/提权而非内容毒性。
  - 不联网、只读已落盘 toxicchat_subset.json，不编造。
"""
from __future__ import annotations
import json, sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parents[2] / "learning"))
from capability_flow import flow_review  # noqa: E402

data = json.loads((BASE / "toxicchat_subset.json").read_text(encoding="utf-8"))
rows = []
for s in data["samples"]:
    score, level, bucket, ev = flow_review(s["text"])
    rows.append({**s, "flow_bucket": bucket, "flow_level": level, "flow_evidence": ev})

# 统计：以 ToxicChat 官方 toxic=restrict 为代理真值
from collections import Counter
tp = fp = fn = tn = 0
for r in rows:
    toxic = r["expected_verdict"] == "restrict"
    blocked = r["flow_bucket"] != "allow"
    if toxic:
        tp += 1 if blocked else 0
        fn += 1 if not blocked else 0
    else:
        fp += 1 if blocked else 0
        tn += 1 if not blocked else 0
n = len(rows)
out = {
    "_meta": {
        "source": "lmsys/toxic-chat subset(n=100)",
        "honest": "维维度不同: ToxicChat=内容毒性, flow=数据流出口/提权。本表为‘拦截口径’参考对照,非等任务 FN/FP。flow 对毒性文本的拦截反映的是其风险覆盖的参考性",
    },
    "flow_vs_toxicchat": {
        "n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "prec": round(tp/(tp+fp), 4) if tp+fp else 1.0,
        "rec": round(tp/(tp+fn), 4) if tp+fn else 1.0,
        "toxic_count": tp+fn, "non_toxic_count": fp+tn,
    },
    "rows": rows,
}
(BASE / "toxicchat_results_flow.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
m = out["flow_vs_toxicchat"]
print(f"ToxicChat(n=100): toxic={m['toxic_count']}  non_toxic={m['non_toxic_count']}")
print(f"flow 拦截口径 vs 毒性代理真值: TP={tp} FP={fp} FN={fn} TN={tn} "
      f"prec={m['prec']} rec={m['rec']}")
print(f"[honest] 维度不同，此为参考对照")