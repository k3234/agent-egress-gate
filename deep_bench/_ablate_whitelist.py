# -*- coding: utf-8 -*-
"""白名单消融（零成本·离线）：L13（无白名单层）vs L13.1（有白名单层）全量对比。

做法：不复制代码、不改源文件——运行时把 capability_flow._exit_whitelist 打补丁为
返回 None（L13 形态），与正常导入（L13.1 形态）在 五卷 224 条 + 红队 48 条 上各判一次，
统计 TP/FP/FN/TN/prec/rec/exact 及增量。验证论文主张：白名单层降低 FP（治自信误伤）
且不牺牲 FN（不漏真凶）。

红线：样本全部为已落盘合成脱敏样本，不调用 API，不读 key。
用法: python _ablate_whitelist.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
LEARN = BASE.parents[2] / "learning"
sys.path.insert(0, str(LEARN))

import capability_flow  # noqa: E402
from capability_flow import flow_review  # noqa: E402

# 五卷样本文件（对齐 full_data_all.json 卷定义；对抗/真实卷 = 基础 + 扩展合并，避免只读子集）
VOLS = {
    "主卷(n=22)": ["deep_bench_samples.json"],
    "对抗全量(n=50)": ["adversarial_samples.json", "adv_extend_samples.json"],
    "真实全量(n=100)": ["realistic_intensity_samples.json", "real_extend_samples.json"],
    "提示注入(n=30)": ["pinject_samples.json"],
    "分裂卷(n=22)": ["split_samples.json"],
}
REDTEAM = ["red_team_samples.json"]


def _score(rows):
    tp = fp = fn = tn = 0
    for exp, act in rows:
        ep, ap = exp != "allow", act != "allow"
        if ep and ap: tp += 1
        elif ep and not ap: fn += 1
        elif not ep and ap: fp += 1
        else: tn += 1
    n = len(rows)
    return {"n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "prec": round(tp / (tp + fp), 4) if tp + fp else 1.0,
            "rec": round(tp / (tp + fn), 4) if tp + fn else 1.0,
            "exact": round(sum(1 for e, a in rows if e == a) / n, 4)}


def _single(s, disable):
    """对单样本判一次：disable=True → L13 无白名单；False → L13.1 有白名单。"""
    if disable:
        capability_flow._exit_whitelist = lambda *a, **k: None
    else:
        capability_flow._exit_whitelist = orig
    sc, lv, bucket, ev = flow_review(s["text"])
    return bucket


def _load(paths):
    out = []
    for p in paths:
        out.extend(json.loads((BASE / p).read_text(encoding="utf-8"))["samples"])
    return out


orig = capability_flow._exit_whitelist


def main():
    volumes = {v: _load(ps) for v, ps in VOLS.items()}
    volumes["红队(n=48)"] = _load(REDTEAM)

    allm = {True: [], False: []}
    summary = {}
    for vname, samples in volumes.items():
        m13, m131 = [], []
        for s in samples:
            b13 = _single(s, True)
            b131 = _single(s, False)
            m13.append((s["expected_verdict"], b13))
            m131.append((s["expected_verdict"], b131))
            allm[True].append((s["expected_verdict"], b13))
            allm[False].append((s["expected_verdict"], b131))
        s13, s131 = _score(m13), _score(m131)
        d = {k: s131[k] - s13[k] for k in ("tp", "fp", "fn", "tn")}
        summary[vname] = {"L13_无白名单": s13, "L13.1_有白名单": s131, "delta": d}
        print(f"{vname:16s} L13  FP={s13['fp']} FN={s13['fn']} prec={s13['prec']} rec={s13['rec']} exact={s13['exact']} "
              f"| L13.1 FP={s131['fp']} FN={s131['fn']} prec={s131['prec']} rec={s131['rec']} exact={s131['exact']} "
              f"| ΔFP={d['fp']:+d} ΔFN={d['fn']:+d}")

    s13_all, s131_all = _score(allm[True]), _score(allm[False])
    summary["__ALL__(272)"] = {"L13_无白名单": s13_all, "L13.1_有白名单": s131_all,
                               "delta": {k: s131_all[k] - s13_all[k] for k in ("tp", "fp", "fn", "tn")}}
    print(f"{'__ALL__(272)':16s} L13  FP={s13_all['fp']} FN={s13_all['fn']} prec={s13_all['prec']} rec={s13_all['rec']} exact={s13_all['exact']} "
          f"| L13.1 FP={s131_all['fp']} FN={s131_all['fn']} prec={s131_all['prec']} rec={s131_all['rec']} exact={s131_all['exact']} "
          f"| ΔFP={s131_all['fp']-s13_all['fp']:+d} ΔFN={s131_all['fn']-s13_all['fn']:+d}")

    out = {"_meta": {"purpose": "白名单层消融：L13(无白名单) vs L13.1(有白名单)，五卷224+红队48=272条",
                     "method": "运行时补丁禁用 _exit_whitelist，不复制代码不改源文件；零API调用",
                     "scoring": "verdict!=allow 即拦；exact=档位完全一致率", "date": "2026-09-29"},
           "summary": summary}
    (BASE / "ablation_whitelist_results.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n[ok] 落盘 {BASE / 'ablation_whitelist_results.json'}")


if __name__ == "__main__":
    main()
