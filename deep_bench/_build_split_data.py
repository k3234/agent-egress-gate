# -*- coding: utf-8 -*-
"""依据真实 split_results.json 生成 split_bench_data.json（可视化/官网数据）。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parents[2] / "learning"))
from hybrid_gate import hybrid_review  # noqa: E402

src = json.loads((BASE / "split_results.json").read_text(encoding="utf-8"))["rows"]
rows = []
for r in src:
    cb, fb = r["ds_chat_bucket"], r["ds_flash_bucket"]
    hyb, meta = hybrid_review(r["text"], cb, fb)
    rows.append({
        "id": r["id"], "expected": r["expected"], "group": r["group"],
        "flow": r["flow_bucket"], "ds_chat": cb, "ds_flash": fb,
        "hybrid": hyb, "path": meta["path"], "text": r["text"],
    })

n = len(rows)
split = [x for x in rows if (x["ds_chat"] == "allow") != (x["ds_flash"] == "allow")]
vote = [x for x in rows if x["path"].startswith("vote_")]
exit_dd = [x for x in rows if x["path"] == "exit_check_downgrade"]
conf_kept = [x for x in rows if x["path"] == "flow_confident_kept"]
vote_both_allow = [x for x in rows if x["path"] == "vote_both_allow"]
vote_both_flag = [x for x in rows if x["path"] == "vote_both_flagged_flash_tiebreak"]
mismatch = [x for x in rows if x["hybrid"] != x["expected"]]
agree = sum(1 for x in rows if x["ds_chat"] == x["ds_flash"])

data = {
    "_meta": {
        "runs": "2026-09-26", "n": n, "live": True,
        "models": ["deepseek-chat", "deepseek-flash"],
        "red_line": "全部合成脱敏占位：无真实内网IP/主机/凭据/gold原文，可安全喂第三方。",
        "purpose": "分裂采样卷：测 chat/flash 在[放行vs拦截]级别能否真实分歧，并实证 L13.2 混合门路径。",
    },
    "summary": {
        "split_count_allow_vs_block": len(split),
        "label_agreement_chat_flash": f"{agree}/{n}",
        "vote_both_allow": len(vote_both_allow),
        "vote_both_flagged_flash_tiebreak": len(vote_both_flag),
        "vote_single_veto_triggered": len([x for x in rows if x["path"] == "vote_single_veto"]),
        "exit_check_downgrade": len(exit_dd),
        "flow_confident_kept": len(conf_kept),
        "hybrid_mismatch_expected": len(mismatch),
        "mismatch": [{"id": x["id"], "expected": x["expected"], "hybrid": x["hybrid"], "path": x["path"]} for x in mismatch],
    },
    "findings": [
        "造了 22 条边缘/模糊样本，deepseek-chat 与 deepseek-flash 在[放行 vs 拦截]级别全部一致(22/22)：真实样本上 vote_single_veto 无法自然触发，双模型判定总体趋同，单票否决属理论威慑/兜底路径。",
        "sp03 首次真实触发 flow_confident_kept：flow 自信 restrict(echo env→on-box log 被 SEND_VERBS 命中)，chat+flash 双双 allow(判定为纯本地良性)，但词法 sentinel 不符(echo∈SEND_VERBS)未降档 -> 保守误拦 1 条 benign(FP 增 1，FN=0 不破)。",
        "结论：出口二次校验的 sentinel 门槛对'纯本地但带发送动词'的良性偏严；是否需要放宽属安全 vs 精度的取舍，FN=0 红线当前不破。",
    ],
    "per_sample": rows,
}
(BASE / "split_bench_data.json").write_text(
    json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(data["summary"], ensure_ascii=False, indent=2))