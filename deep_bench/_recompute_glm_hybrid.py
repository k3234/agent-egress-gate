# -*- coding: utf-8 -*-
"""GLM 补跑后离线重算：glm_results.json → 各卷 × {flow / GLM / 混合(flow+GLM)} 矩阵。

口径：verdict!=allow 即拦；exact=档位完全一致率。
混合(flow+GLM) = 单语义门变体：flow 非 review 时用 flow 判定（确定性底座）；
flow==review 时交给 GLM（语义补盲区）。DS 402 不可用，双模型 L13.2 混合门本轮不计算。
另单独验证：GLM 是否能拦下 flow_allow 快路径裂缝样本（e05/pi09 + 裂缝代价测试集 A 组）。
用法: python _recompute_glm_hybrid.py
"""
from __future__ import annotations

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
SRC = BASE / "glm_results.json"
OUT = BASE / "glm_hybrid_results.json"
_LABELS = ("allow", "review", "restrict", "block")


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


def main():
    data = json.loads(SRC.read_text(encoding="utf-8"))
    rows = data["rows"]
    api_ok = data["_meta"]["api_ok"]
    valid = [r for r in rows if not str(r["glm"]).startswith("err:")]

    vols = {}
    for r in rows:
        vols.setdefault(r["volume"], []).append(r)

    judges = ("flow", "GLM", "混合(flow+GLM)")
    matrices = {}
    for vname, rs in vols.items():
        v_valid = [r for r in rs if not str(r["glm"]).startswith("err:")]
        def act(r, j):
            if j == "flow":
                return r["flow"]
            if j == "GLM":
                return r["glm"]
            return r["flow"] if r["flow"] != "review" else r["glm"]  # 混合
        matrices[vname] = {j: _score([(r["expected"], act(r, j)) for r in (v_valid if j != "flow" else rs)])
                           for j in judges}

    def all_act(r, j):
        return r["flow"] if j == "flow" else (r["glm"] if j == "GLM" else (r["flow"] if r["flow"] != "review" else r["glm"]))
    all_valid = [r for r in valid]
    matrices["__ALL__(valid)"] = {j: _score([(r["expected"], all_act(r, j)) for r in all_valid]) for j in judges}
    matrices["__ALL__(n_valid)"] = {"n": len(all_valid)}

    # 裂缝拦截验证：flow=allow 的真凶样本，GLM / 混合 是否拦下
    crack = [r for r in valid if r["expected"] != "allow" and r["flow"] == "allow"]
    crack_glm_blocks = [r["id"] for r in crack if r["glm"] != "allow"]
    crack_mix_blocks = [r["id"] for r in crack
                        if (r["flow"] != "review" and r["flow"] != "allow") or (r["flow"] == "review" and r["glm"] != "allow")]

    out = {"_meta": {"date": "2026-09-29", "model": "glm-5.3-flash", "src": SRC.name,
                     "api_ok": api_ok, "n": len(rows), "n_valid": len(all_valid),
                     "note": "混合(flow+GLM)=单语义门变体：flow非review用flow，flow==review交GLM。"
                             "DS 402 不可用，L13.2 双模型混合门本轮不计算；glm err 样本被排除不进矩阵。"},
           "matrices": matrices,
           "crack_interception": {
               "flow_leaked_true_positives": len(crack),
               "ids": [r["id"] for r in crack],
               "glm_blocks": crack_glm_blocks,
               "mix_blocks": crack_mix_blocks,
               "note": "flow_allow 快路径裂缝样本（e05/pi09 形）若被 GLM/混合 拦下，说明跨家族语义门可补该盲区。"}}
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    for vname in [k for k in matrices if not k.startswith("__ALL__")] + ["__ALL__(valid)"]:
        if vname == "__ALL__(n_valid)":
            continue
        print(f"== {vname}")
        for j in judges:
            s = matrices[vname][j]
            print(f"   {j:14s} TP={s['tp']} FP={s['fp']} FN={s['fn']} TN={s['tn']} prec={s['prec']} rec={s['rec']} exact={s['exact']}")
    print(f"\n裂缝拦截: flow漏放={len(crack)} 条 → GLM拦={len(crack_glm_blocks)} 混合拦={len(crack_mix_blocks)}")
    print(f"[ok] 落盘 {OUT}")


if __name__ == "__main__":
    main()
