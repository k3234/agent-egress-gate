# -*- coding: utf-8 -*-
"""L13.2 双模型混合门落地后离线重算：取代旧"并行单模型混合"。

不联网：flow/混合用本地代码重判，两个 DS 判定复用已落盘结果文件。
输出 3 卷 × 4 判定者(flow / DS-chat / DS-flash / 混合(L13.2))到 full_comparison_data.json。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parents[2] / "learning"))
from capability_flow import flow_review  # noqa: E402
from hybrid_gate import hybrid_review  # noqa: E402

_LABELS = ("allow", "review", "restrict", "block")
VOLS = {
    "主卷(n=22)": ("deep_bench_samples.json", "deep_bench_results.json", "deep_bench_results_flash.json"),
    "对抗改写(n=14)": ("adversarial_samples.json", "adversarial_results_chat.json", "adversarial_results_flash.json"),
    "真实强度(n=30)": ("realistic_intensity_samples.json", "realistic_results_chat.json", "realistic_results_flash.json"),
}

def _score(rows):
    tp = fp = fn = tn = 0
    diffs = []
    for exp, act in rows:
        exp_pos = exp != "allow"
        act_pos = act != "allow"
        if exp_pos and act_pos: tp += 1
        elif exp_pos and not act_pos: fn += 1
        elif not exp_pos and act_pos: fp += 1
        else: tn += 1
        if exp != act: diffs.append((exp, act))
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    exact = sum(1 for e, a in rows if e == a) / len(rows)
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                prec=round(prec, 4), rec=round(rec, 4),
                exact=round(exact, 4), n_diff=len(diffs), diffs=diffs)

def _load_ds(path, key):
    data = json.loads(path.read_text(encoding="utf-8"))
    return {r["id"]: r.get(key) for r in data["rows"]}

def main():
    out, summary, per_sample = {}, {}, {}
    for vname, (sp, chat_f, flash_f) in VOLS.items():
        sp = json.loads((BASE / sp).read_text(encoding="utf-8"))["samples"]
        ds_chat = _load_ds(BASE / chat_f, "ds_bucket")
        ds_flash = _load_ds(BASE / flash_f, "ds_bucket")
        rows, out_rows = [], []
        for s in sp:
            sid, exp = s["id"], s["expected_verdict"]
            sc, lv, fb, ev = flow_review(s["text"])
            dc, df = ds_chat.get(sid), ds_flash.get(sid)
            dc = dc if dc in _LABELS else "review"
            df = df if df in _LABELS else "review"
            # 新：L13.2 混合门（双模型投票 + 出口二次校验），取代旧"并行单模型混合"
            h2, meta = hybrid_review(s["text"], dc, df)
            acts = {"flow": fb, "DS-chat": dc, "DS-flash": df, "混合(L13.2)": h2}
            rows.append((exp, acts))
            row = dict(id=sid, expected=exp, text=s.get("text", ""),
                       flow_level=lv, flow_bucket=fb, flow_evidence=ev,
                       ds_chat_bucket=dc, ds_flash_bucket=df,
                       hybrid_l132_bucket=h2, hybrid_l132_meta=meta)
            for k in ("intensity", "zone", "attack_type"):
                if k in s: row[k] = s[k]
            out_rows.append(row)
        per_sample[vname] = out_rows
        summary[vname] = {j: _score([(e, a[j]) for e, a in rows])
                          for j in ("flow", "DS-chat", "DS-flash", "混合(L13.2)")}
    out = {"summary": summary, "per_sample": per_sample, "_meta": {
        "note": "L13.2 双模型混合门(共识才放行+出口二次校验) 取代旧并行单模型混合；3卷×4判定者",
        "scoring": "verdict != allow 即拦；exact=期望档位与判定完全一致率"}}
    (BASE / "full_comparison_data.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    for vname, ss in summary.items():
        print(f"== {vname}")
        for j, s in ss.items():
            print(f"   {j:14s} TP={s['tp']} FP={s['fp']} FN={s['fn']} TN={s['tn']} "
                  f"prec={s['prec']:.3f} rec={s['rec']:.3f} exact={s['exact']:.3f}")

if __name__ == "__main__":
    main()