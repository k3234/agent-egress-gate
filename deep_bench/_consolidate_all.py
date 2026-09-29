# -*- coding: utf-8 -*-
"""扩展全量汇总：主22/对抗全量50/真实全量100/提示注入30/分裂22 五卷 × 4判定者 + ToxicChat参考对照。
写入 full_data_all.json。只读已落盘真实判定，不联网不编造。
"""
from __future__ import annotations
import json, collections
from pathlib import Path

BASE = Path(__file__).resolve().parent
# 数据流四判定者 + 内容护栏(LG) + 注入分类器(PG2) 共 6 列
JUDGERS = ["flow", "DS-chat", "DS-flash", "混合(L13.2)", "LlamaGuard(LG)", "PromptGuard2(PG2)"]


def matrix(rows, key):
    tp = fp = fn = tn = exact = 0
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
            "exact": round(exact/n, 4), "n_diff": n - exact}


records = []

# 主卷 n=22
FULL = json.loads((BASE / "full_comparison_data.json").read_text(encoding="utf-8"))
for it in FULL["per_sample"]["主卷(n=22)"]:
    records.append({"vol": "主卷(n=22)", "id": it["id"], "expected": it["expected"], "text": it["text"],
                    "flow": it["flow_bucket"], "DS-chat": it["ds_chat_bucket"], "DS-flash": it["ds_flash_bucket"],
                    "混合(L13.2)": it["hybrid_l132_bucket"], "zone": it.get("zone"),
                    "dim": "zone", "path": it.get("hybrid_l132_meta", {}).get("path")})

# 对抗全量 n=50
adv = json.loads((BASE / "adv_full50_results.json").read_text(encoding="utf-8"))["records"]
for it in adv:
    records.append({"vol": "对抗全量(n=50)", "id": it["id"], "expected": it["expected"], "text": it["text"],
                    "flow": it["flow"], "DS-chat": it["DS-chat"], "DS-flash": it["DS-flash"],
                    "混合(L13.2)": it["混合(L13.2)"], "zone": None,
                    "dim": it.get("group"), "path": it.get("path")})

# 真实全量 n=100
real = json.loads((BASE / "real_full100_results.json").read_text(encoding="utf-8"))["records"]
for it in real:
    records.append({"vol": "真实全量(n=100)", "id": it["id"], "expected": it["expected"], "text": it["text"],
                    "flow": it["flow"], "DS-chat": it["DS-chat"], "DS-flash": it["DS-flash"],
                    "混合(L13.2)": it["混合(L13.2)"], "zone": None,
                    "dim": it.get("intensity"), "path": it.get("path")})

# 提示注入 n=30
pinj = json.loads((BASE / "pinject_results_scored.json").read_text(encoding="utf-8"))["records"]
for it in pinj:
    records.append({"vol": "提示注入(n=30)", "id": it["id"], "expected": it["expected"], "text": it["text"],
                    "flow": it["flow"], "DS-chat": it["DS-chat"], "DS-flash": it["DS-flash"],
                    "混合(L13.2)": it["混合(L13.2)"], "zone": None,
                    "dim": it.get("group"), "path": it.get("path")})

# 分裂卷 n=22
SPLIT = json.loads((BASE / "split_bench_data.json").read_text(encoding="utf-8"))
for it in SPLIT["per_sample"]:
    records.append({"vol": "分裂卷(n=22)", "id": it["id"], "expected": it["expected"], "text": it["text"],
                    "flow": it["flow"], "DS-chat": it["ds_chat"], "DS-flash": it["ds_flash"],
                    "混合(L13.2)": it["hybrid"], "zone": it.get("zone"),
                    "dim": it.get("group"), "path": it.get("path")})

# 第5判定者 Llama Guard(内容护栏)：按 id 合并 lg_bucket；缺失则 fail-closed 归 review
lg_p = BASE / "lg_results.json"
lg_cov = {"n_matched": 0, "n_missing": 0}
if lg_p.exists():
    lg = json.loads(lg_p.read_text(encoding="utf-8"))
    lg_map = {r["id"]: r["lg_bucket"] for r in lg["rows"]}
    for r in records:
        if r["id"] in lg_map:
            r["LlamaGuard(LG)"] = lg_map[r["id"]]
            lg_cov["n_matched"] += 1
        else:
            r["LlamaGuard(LG)"] = "review"
            lg_cov["n_missing"] += 1
else:
    for r in records:
        r["LlamaGuard(LG)"] = "review"

# 第6判定者 Prompt Guard 2(主流注入分类器)：按 id 合并 pg_bucket；缺失 fail-closed 归 review
pg_p = BASE / "pg_results.json"
pg_cov = {"n_matched": 0, "n_missing": 0}
if pg_p.exists():
    pgr = json.loads(pg_p.read_text(encoding="utf-8"))
    pg_map = {r["id"]: r["pg_bucket"] for r in pgr["rows"]}
    for r in records:
        if r["id"] in pg_map:
            r["PromptGuard2(PG2)"] = pg_map[r["id"]]
            pg_cov["n_matched"] += 1
        else:
            r["PromptGuard2(PG2)"] = "review"
            pg_cov["n_missing"] += 1
else:
    for r in records:
        r["PromptGuard2(PG2)"] = "review"

by_vol = collections.defaultdict(list)
for r in records:
    by_vol[r["vol"]].append(r)
vols = list(by_vol.keys())
vol_matrix = {v: {j: matrix(rows, j) for j in JUDGERS} for v, rows in by_vol.items()}


def decompose(vol_rows, attr):
    out = {}
    by = collections.defaultdict(list)
    for r in vol_rows:
        if r.get(attr):
            by[r[attr]].append(r)
    for a, rows in by.items():
        out[a] = {j: matrix(rows, j) for j in JUDGERS}
    return out


structure = {}
structure["强度分解(真实100)"] = decompose(by_vol["真实全量(n=100)"], "dim")
structure["攻击类型分解(对抗50)"] = decompose(by_vol["对抗全量(n=50)"], "dim")
structure["攻击类型分解(提示注入30)"] = decompose(by_vol["提示注入(n=30)"], "dim")
structure["分组分解(分裂22)"] = decompose(by_vol["分裂卷(n=22)"], "dim")
path_c = collections.Counter(r["path"] for r in records if r["path"])
structure["混合门路径分布(五卷)"] = dict(path_c)

# 关键实证：I5无害近邻误伤(真实全量内) + 全部无害子集误判(混合在非禁卷的FP)
real_all = by_vol["真实全量(n=100)"]
i5 = [r for r in real_all if r.get("dim") == "I5"]
structure["I5无害误伤(真实100)"] = {
    "n": len(i5),
    "flow": sum(1 for r in i5 if r["flow"] != "allow"),
    "DS-flash": sum(1 for r in i5 if r["DS-flash"] != "allow"),
    "混合(L13.2)": sum(1 for r in i5 if r["混合(L13.2)"] != "allow"),
}
# 各卷混合FP样本
structure["混合FP明细"] = {}
for v, rows in by_vol.items():
    fp_rows = [r for r in rows if r["expected"] == "allow" and r["混合(L13.2)"] != "allow"]
    if fp_rows:
        structure["混合FP明细"][v] = [{"id": r["id"], "text": r["text"][:60],
                                      "flow": r["flow"], "DS-chat": r["DS-chat"],
                                      "DS-flash": r["DS-flash"], "hyb": r["混合(L13.2)"],
                                      "path": r["path"]} for r in fp_rows]

# ToxicChat 参考对照(复用已落盘 full)
tc = {}
fpath = BASE / "toxicchat_results_full.json"
if fpath.exists():
    tc_raw = json.loads(fpath.read_text(encoding="utf-8"))
    tc = {"source": "lmsys/toxic-chat subset(n=100)", "dim_note": "内容毒性代理真值, 任务维度不同于数据流四桶, 仅参考",
          "judgers_vs_toxicchat": tc_raw["judgers_vs_toxicchat"], "live": tc_raw["_meta"].get("live")}
else:
    tc = {"status": "pending"}

# LG 内容护栏实证：类别分布 + FN/FP 明细(任务维度差异的真实体现)
lg_eval = {}
if (BASE / "lg_eval.json").exists():
    le = json.loads((BASE / "lg_eval.json").read_text(encoding="utf-8"))
    lg_eval = {"cat_distribution": le["cat_distribution"],
               "n_fn": len(le["fn_detail"]), "n_fp": len(le["fp_detail"]),
               "fn_ids": [f"{x['vol']}|{x['id']}" for x in le["fn_detail"]],
               "fp_ids": [f"{x['vol']}|{x['id']}" for x in le["fp_detail"]],
               "note": "LG仅输出 S1(暴力犯罪)/safe 两类, 从未用 S2/S7——LG 3的14类分类里没有'数据外泄'类别, 故要么误标S1要么判safe"}

# PG2(主流注入分类器) 实证摘要：阈值扫描 + 关键对照
pg_eval = {}
if (BASE / "pg_eval.json").exists():
    pe = json.loads((BASE / "pg_eval.json").read_text(encoding="utf-8"))
    pg_eval = {"overall": pe["overall"], "by_vol": pe["by_vol"],
               "sweep_injection": pe["sweep_injection"],
               "our_system_injection": pe["our_system_injection"],
               "note": "PG2=Meta 专用提示注入/越狱分类器(AUC .998, recall@1%FPR 97.5% on Meta内部集)，"
                       "但在本任务 224 条上总体 rec=0.146、注入卷 rec=0.333（阈值0.05 时也仅 0.583）——"
                       "因其判定的是'越狱/注入内容',而本任务要抓'数据流外泄意图',维度不同。"}

out = {"_meta": {"runs": "2026-09-26", "judgers": JUDGERS, "vols": vols,
                 "scoring": "verdict!=allow 即拦; exact=期望档位与判定完全一致",
                 "note": "对抗/真实为扩充后全量; 第5判定者 LlamaGuard-3-1B(内容护栏)、第6判定者 Prompt Guard 2(注入分类器), 均本地CPU推理; 后二者档位为近似映射",
                 "honest": "五卷全部读已落盘真实判定; 对抗50=14+36,真实100=30+70; 提示注入30为实时; ToxicChat口径差异; LG/PG2维度不同",
                 "lg_coverage": lg_cov, "pg_coverage": pg_cov},
       "vol_matrix": vol_matrix, "structure": structure,
       "lg_eval": lg_eval, "pg_eval": pg_eval, "toxicchat": tc, "records_n": len(records)}
(BASE / "full_data_all.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

print(f"\n=== 全量五卷 × {len(JUDGERS)}判定者 (共 {len(records)}) ===")
for v in vols:
    print(f"[{v}]")
    for j in JUDGERS:
        m = vol_matrix[v][j]
        print(f"  {j:<14} TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} "
              f"prec={m['prec']:.3f} rec={m['rec']:.3f} exact={m['exact']:.3f}")
print("\nI5无害误伤(真实100):", structure["I5无害误伤(真实100)"])
print("混合FP明细聚总:")
for v, lst in structure["混合FP明细"].items():
    print(f"  {v}: {len(lst)} -> ", [x['id'] for x in lst])
print("路径分布:", dict(path_c))
if lg_eval:
    print("\nLG 类别分布:", lg_eval["cat_distribution"], "| FN:", lg_eval["n_fn"], "FP:", lg_eval["n_fp"])
if pg_eval:
    print("PG2 总体:", {k: pg_eval["overall"][k] for k in ("prec", "rec", "fpr")},
          "| 注入卷 rec:", pg_eval["by_vol"].get("提示注入", {}).get("rec"))
if tc and "judgers_vs_toxicchat" in tc:
    print("\nToxicChat 参考(拦截口径):", {k: {kk: vv for kk, vv in v.items() if kk in ('tp','fp','fn','tn')} for k, v in tc["judgers_vs_toxicchat"].items()})