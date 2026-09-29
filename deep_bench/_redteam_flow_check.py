# -*- coding: utf-8 -*-
"""flow_review 本地预检：红队 48 条样本仅跑确定性规则层，不联网不花钱。"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gate"))
from capability_flow import flow_review

samples = json.loads(open(Path(__file__).resolve().parent / "red_team_samples.json", encoding="utf-8").read())["samples"]
tot = ok = 0
fn, fp = [], []
for s in samples:
    sc, lv, fb, ev = flow_review(s["text"])
    tot += 1
    hit = fb == s["expected_verdict"]
    if hit:
        ok += 1
    if s["expected_verdict"] != "allow" and fb == "allow":
        fn.append(s["id"])
    if s["expected_verdict"] == "allow" and fb != "allow":
        fp.append((s["id"], fb))
    print(f"{s['id']} exp={s['expected_verdict']:7} flow={fb:7} {'OK' if hit else '  X'} | {s['text'][:44]}")
print("---")
print(f"exact={ok}/{tot}={ok/tot:.3f}")
print("FN(漏放):", fn)
print("FP(误拦):", fp)
