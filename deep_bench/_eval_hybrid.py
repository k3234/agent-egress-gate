# -*- coding: utf-8 -*-
"""混合判定评测：flow 定确定项 + 仅 review 交 DeepSeek。

在同 22 条脱敏样本上，验证设计推断——flow_review 命中非 review 的项直接用
flow(可解释、确定、零成本)，只有退化成 review(规则天花板) 的项才向 DeepSeek
求救。复用 run_deep_bench.py 已实测并落盘的 deep_bench_results.json，无需再联网。

打分口径与前述一致：verdict != allow 即拦。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent
RESULTS = Path(os.environ.get("HYBRID_IN", str(BASE / "deep_bench_results.json")))

_LABELS = ("allow", "review", "restrict", "block")


def _score(rows):
    tp = fp = fn = tn = 0
    diffs = []
    for exp, act in rows:
        exp_pos = exp != "allow"
        act_pos = act != "allow"
        if exp_pos and act_pos:
            tp += 1
        elif exp_pos and not act_pos:
            fn += 1
        elif not exp_pos and act_pos:
            fp += 1
        else:
            tn += 1
        if exp != act:
            diffs.append((exp, act))
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, prec=round(prec, 3), rec=round(rec, 3),
                n_diff=len(diffs), diffs=diffs)


def main():
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    rows = data["rows"]
    hybrid = []
    sent_to_ds = 0
    for r in rows:
        exp = r["expected"]
        fb = r["flow_bucket"]
        ds = r["ds_bucket"]
        if fb != "review":
            act = fb if fb in _LABELS else "review"
        elif ds and ds in _LABELS:
            act = ds
            sent_to_ds += 1
        else:
            act = "review"            # 无 DS 时仍 fail-closed 待审
        hybrid.append((exp, act))
        mark = " ←DS补" if (fb == "review" and act != "review") else ""
        print(f"{r['id']:<6}{exp:<10}flow={fb:<10}ds={ds:<10}→{act}{mark}")

    sc = _score(hybrid)
    print("\n=== 混合判定(flow 定 + review 交 DeepSeek) ===")
    print(f"TP={sc['tp']} FP={sc['fp']} FN={sc['fn']} TN={sc['tn']} "
          f"prec={sc['prec']} rec={sc['rec']} diff={sc['n_diff']}")
    print(f"共 {sent_to_ds} 条交给 DeepSeek 补判（其余由 flow 直接确定，零调用）。")


if __name__ == "__main__":
    main()