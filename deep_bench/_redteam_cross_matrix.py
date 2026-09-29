# -*- coding: utf-8 -*-
"""红队五判定者对照矩阵：flow / DS-chat / DS-flash / GLM / 混合(L13.2)。
纯离线重算（无 API）：red_team_results.json × glm_results.json(volume=红队) 按 id 对齐。
输出 red_team_cross_matrix.json（总体矩阵 + 家族分解 + 模型一致性 + 边界行明细）。
用法: python _redteam_cross_matrix.py
"""
from __future__ import annotations
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
RT = BASE / "red_team_results.json"
GLM = BASE / "glm_results.json"
OUT = BASE / "red_team_cross_matrix.json"

JUDGERS = ["flow", "DS-chat", "DS-flash", "GLM", "混合(L13.2)"]
_LABELS = ("allow", "review", "restrict", "block")
_STRICT = {"allow": 0, "review": 1, "restrict": 2, "block": 3}

def _score(rows):
    tp = fp = fn = tn = exact = 0
    for exp, act in rows:
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

def main():
    rt = json.loads(RT.read_text(encoding="utf-8"))
    glm_all = json.loads(GLM.read_text(encoding="utf-8"))
    rows = rt["rows"]
    glm_by_id = {r["id"]: r.get("glm") for r in glm_all["rows"]
                 if r.get("volume") == "红队(n=48)"}
    missing = [r["id"] for r in rows if r["id"] not in glm_by_id]
    assert not missing, f"GLM 红队行缺失: {missing}"
    for r in rows:
        r["GLM"] = glm_by_id[r["id"]]

    # 各判定者可用性：列内出现 err/n/a/None 即整体 unavailable，不进矩阵（不归一化）
    effective = {j: all(isinstance(r[j], str) and r[j] in _LABELS for r in rows)
                 for j in JUDGERS}
    by_fam = {}
    for r in rows:
        by_fam.setdefault(r["attack_type"], []).append(r)

    overall = {j: _score([(r["expected"], r[j]) for r in rows]) for j in JUDGERS}
    fam_matrix = {f: {j: _score([(x["expected"], x[j]) for x in rws]) for j in JUDGERS}
                  for f, rws in by_fam.items()}

    # 模型间一致性（逐格完全一致率，仅统计双方均为合法档位的格）
    agreement = {}
    for i, a in enumerate(JUDGERS):
        for b in JUDGERS[i+1:]:
            if not (effective[a] and effective[b]):
                continue
            same = sum(1 for r in rows if r[a] == r[b])
            diffs = [{"id": r["id"], "expected": r["expected"], a: r[a], b: r[b]}
                     for r in rows if r[a] != r[b]]
            agreement[f"{a}_vs_{b}"] = {
                "n": len(rows), "same": same, "rate": round(same/len(rows), 4),
                "diff_rows": diffs}

    # 边界行明细：flow 的全部 FN/FP 行 × 五判定者档位（诚实边界）
    boundary_rows = [{"id": r["id"], "expected": r["expected"], "attack_type": r["attack_type"],
                      **{j: r[j] for j in JUDGERS}, "hybrid_path": r.get("path")}
                     for r in rows
                     if (r["expected"] != "allow" and r["flow"] == "allow")
                     or (r["expected"] == "allow" and r["flow"] != "allow")]

    out = {"_meta": {"purpose": "红队 48 条五判定者跨家族对照（DS 补跑后首次全列可用）",
                     "date": "2026-09-30", "n": len(rows),
                     "sources": ["red_team_results.json", "glm_results.json(volume=红队(n=48))"],
                     "served_model_field": rt["_meta"].get("served_model_field"),
                     "effective_judgers": effective,
                     "note": "拦截口径 verdict!=allow 即拦（review 计拦截但待人工）。served_model_field 证实请求 chat/flash 服务端均返回 deepseek-flash（别名/合并路由），两列档位差异来自服务端采样而非两个独立模型，论文独立性声明按此诚实改写。"},
           "overall": overall, "fam_matrix": fam_matrix,
           "agreement": agreement, "boundary_rows": boundary_rows}
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"=== 红队五判定者总体（n={len(rows)}，拦截口径）===")
    for j, s in overall.items():
        print(f"  {j:12s} TP={s['tp']} FP={s['fp']} FN={s['fn']} TN={s['tn']} "
              f"prec={s['prec']:.3f} rec={s['rec']:.3f} exact={s['exact']:.3f}")
    print("\n=== 攻击家族分解（五判定者 prec/rec）===")
    for f, m in fam_matrix.items():
        seg = " | ".join(f"{j.replace('混合(L13.2)','混合')} {s['prec']:.2f}/{s['rec']:.2f}"
                         for j, s in m.items())
        print(f"  {f:10s} {seg}")
    print("\n=== 模型间逐格一致率 ===")
    for k, v in agreement.items():
        print(f"  {k:24s} same={v['same']}/{v['n']} rate={v['rate']}")
    print("\n=== 边界行（flow FN/FP × 五判定者）===")
    for r in boundary_rows:
        tag = "FN" if r["expected"] != "allow" else "FP"
        print(f"  {tag} {r['id']} exp={r['expected']} flow={r['flow']} chat={r['DS-chat']} "
              f"flash={r['DS-flash']} glm={r['GLM']} 混合={r['混合(L13.2)']} path={r['hybrid_path']}")
    print(f"\n[ok] 落盘 {OUT}")

if __name__ == "__main__":
    main()
