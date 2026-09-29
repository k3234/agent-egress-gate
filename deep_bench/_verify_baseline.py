# -*- coding: utf-8 -*-
"""验证评测基线无漂移：用当前 capability_flow 重跑各卷 flow 判定，与落盘 full_comparison_data/split_bench_data 对照。
只读本地，不联网。若 flow_bucket 与落盘不一致 => 基线漂移(需标红)。"""
from __future__ import annotations
import json, sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parents[2] / "learning"))
from capability_flow import flow_review  # noqa: E402

full = json.loads((BASE / "full_comparison_data.json").read_text(encoding="utf-8"))
split = json.loads((BASE / "split_bench_data.json").read_text(encoding="utf-8"))

def live_flow(text):
    _s, _l, b, _ev = flow_review(text)
    return b

drift = []
vols = []
for vol, items in full["per_sample"].items():
    for it in items:
        live = live_flow(it["text"])
        vols.append(it["id"])
        if live != it["flow_bucket"]:
            drift.append((vol, it["id"], it["flow_bucket"], live))
for it in split.get("per_sample", []):
    if it["id"] in vols:
        continue
    live = live_flow(it["text"])
    if live != it["flow"]:
        drift.append(("分裂卷", it["id"], it["flow"], live))

print(f"核对 flow 判定样本数: 已比对")
if drift:
    print("!!! 基线漂移 !!!")
    for d in drift:
        print("   ", d)
else:
    print("OK: 全部同卷 flow 判定与落盘一致，基线无漂移。")


# 同时报告当前 flow 对四卷的 review 计数，供后续对照
import collections
for name, items in list(full["per_sample"].items()) + [("分裂卷", split.get("per_sample", []))]:
    c = collections.Counter(live_flow(it["text"]) for it in items)
    print(f"  {name}: n={len(items)} flow判档={dict(c)}")