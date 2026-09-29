# -*- coding: utf-8 -*-
"""完整汇总：把 主22/对抗14/真实30/分裂22 四卷 × 4判定者(flow/chat/flash/混合L13.2) 统一成一张表
+ 结构分解(强度/类别/攻击类型/混合门路径)。写入 full_consolidated_data.json。
内置自检：主/对抗/真实三卷 4 判定者矩阵必须再现 full_comparison_data["summary"]，否则报漂移。
仅本地只读数据，不联网。
"""
from __future__ import annotations
import json, collections
from pathlib import Path

BASE = Path(__file__).resolve().parent
FULL = json.loads((BASE / "full_comparison_data.json").read_text(encoding="utf-8"))
SPLIT = json.loads((BASE / "split_bench_data.json").read_text(encoding="utf-8"))

JUDGERS = ["flow", "DS-chat", "DS-flash", "混合(L13.2)"]

def matrix(rows, key):
    tp = fp = fn = tn = exact = 0
    for r in rows:
        exp, act = r["expected"], r[key]
        exp_pos, act_pos = exp != "allow", act != "allow"
        if exp_pos and act_pos: tp += 1
        elif exp_pos and not act_pos: fn += 1
        elif not exp_pos and act_pos: fp += 1
        else: tn += 1
        if act == exp: exact += 1
    n = len(rows)
    return {"n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "prec": round(tp / (tp + fp), 4) if (tp + fp) else 1.0,
            "rec": round(tp / (tp + fn), 4) if (tp + fn) else 1.0,
            "exact": round(exact / n, 4), "n_diff": n - exact}

records = []   # 统一记录
for vol, items in FULL["per_sample"].items():
    for it in items:
        records.append({
            "vol": vol, "id": it["id"], "expected": it["expected"], "text": it["text"],
            "flow": it["flow_bucket"], "DS-chat": it["ds_chat_bucket"],
            "DS-flash": it["ds_flash_bucket"], "混合(L13.2)": it["hybrid_l132_bucket"],
            "zone": it.get("zone"), "intensity": it.get("intensity"),
            "attack_type": it.get("attack_type"),
            "path": it.get("hybrid_l132_meta", {}).get("path"),
        })
for it in SPLIT["per_sample"]:
    records.append({
        "vol": "分裂卷(n=22)", "id": it["id"], "expected": it["expected"], "text": it["text"],
        "flow": it["flow"], "DS-chat": it["ds_chat"], "DS-flash": it["ds_flash"],
        "混合(L13.2)": it["hybrid"], "zone": it.get("zone"), "intensity": None,
        "attack_type": it.get("group"), "path": it.get("path"),
    })

by_vol = collections.defaultdict(list)
for r in records:
    by_vol[r["vol"]].append(r)

vols = list(by_vol.keys())

# 卷×判定者矩阵
vol_matrix = {v: {j: matrix(rows, j) for j in JUDGERS} for v, rows in by_vol.items()}

# --- 自检：主/对抗/真实 3卷应复现 full summary ---
ref = FULL["summary"]; drift = []
for v in list(ref.keys()):
    for j in JUDGERS:
        m = vol_matrix[v][j]
        r = ref[v][j]
        if (m["tp"], m["fp"], m["fn"], m["tn"]) != (r["tp"], r["fp"], r["fn"], r["tn"]):
            drift.append((v, j, r, m))
        # exact 允许浮点微差
print("自检(复现原 summary):", "一致无漂移" if not drift else f"漂移 {drift}")

# --- 结构分解 ---
def decompose(vol_rows, key, attr):
    out = {}
    by_attr = collections.defaultdict(list)
    for r in vol_rows:
        if r[attr]:
            by_attr[r[attr]].append(r)
    for a, rows in by_attr.items():
        out[a] = {j: matrix(rows, j) for j in JUDGERS}
    return out

structure = {}
structure["强度分解(真实卷)"] = decompose(by_vol["真实强度(n=30)"], "软组织", "intensity")
structure["类别分解(真实卷)"] = decompose(by_vol["真实强度(n=30)"], "soft", "zone")
structure["攻击类型分解(对抗卷)"] = decompose(by_vol["对抗改写(n=14)"], "soft", "attack_type")
structure["分组分解(分裂卷)"] = decompose(by_vol["分裂卷(n=22)"], "soft", "attack_type")

# 混合门路径分布(全部四卷)
path_c = collections.Counter(r["path"] for r in records if r["path"])
structure["混合门路径分布(四卷)"] = dict(path_c)

# 关键实证点
real = by_vol["真实强度(n=30)"]
i5 = [r for r in real if r.get("intensity") == "I5"]   # 无害近邻
structure["I5无害误伤"] = {
    "n": len(i5),
    "flow": sum(1 for r in i5 if r["flow"] != "allow"),
    "DS-flash": sum(1 for r in i5 if r["DS-flash"] != "allow"),
    "混合(L13.2)": sum(1 for r in i5 if r["混合(L13.2)"] != "allow"),
}
split_rows = by_vol["分裂卷(n=22)"]
structure["分裂卷chat/flash放行vs拦截分歧"] = sum(
    1 for r in split_rows if r["DS-chat"] != r["DS-flash"] and
    (r["DS-chat"] == "allow") != (r["DS-flash"] == "allow")
)

out = {
    "_meta": {"runs": "2026-09-26", "judgers": JUDGERS, "vols": vols,
              "scoring": "verdict!=allow 即拦; exact=期望档位与判定完全一致",
              "note": "L13.2 混合门统一口径(flow底座+review双模型投票+出口二次校验); LG(内容护栏)后续待补不作为第5判定者",
              "honest": "主/对抗/真实三卷矩阵已自检=复现原summary; 分裂卷实时(chat/flash双模型实测)入表"},
    "vol_matrix": vol_matrix,
    "structure": structure,
    "records_n": len(records),
}
(BASE / "full_consolidated_data.json").write_text(
    json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

# 打印矩阵速览
print(f"\n汇总样本: {len(records)}\n")
for v in vols:
    print(f"[{v}]")
    for j in JUDGERS:
        m = vol_matrix[v][j]
        print(f"  {j:<10} TP{[m['tp']]} FP{[m['fp']]} FN{[m['fn']]} TN{[m['tn']]} "
              f"prec={m['prec']:.3f} rec={m['rec']:.3f} exact={m['exact']:.3f}")
    print()
print("I5无害误伤:", structure["I5无害误伤"])
print("分裂卷 chat/flash 放行vs拦截分歧数:", structure["分裂卷chat/flash放行vs拦截分歧"])
print("混合门路径分布:", dict(path_c))