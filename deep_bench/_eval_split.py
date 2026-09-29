# -*- coding: utf-8 -*-
"""分裂采样卷分析：读 split_results.json -> 跑 L13.2 hybrid_gate -> 统计 [放行vs拦截] 分裂与 vote_single_veto 命中。

只读已落盘的真实 DS 判定，不重新联网、不编造。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE.parents[2] / "learning"))
from hybrid_gate import hybrid_review  # noqa: E402

rows = json.loads((BASE / "split_results.json").read_text(encoding="utf-8"))["rows"]

print("=== 按样本：flow / chat / flash / 混合(L13.2) / 路径 ===")
n_split = 0
n_veto = 0
lines = []
for r in rows:
    cb, fb = r["ds_chat_bucket"], r["ds_flash_bucket"]
    hyb, meta = hybrid_review(r["text"], cb, fb)
    split = (cb == "allow") != (fb == "allow")
    if split:
        n_split += 1
    veto = split and meta["path"].startswith("vote_")
    if veto:
        n_veto += 1
    flag = " *SPLIT*" if split else ""
    lines.append(f"[{r['id']}|{r['group']}] exp={r['expected']} flow={r['flow_bucket']} "
                 f"chat={cb} flash={fb} hyb={hyb} path={meta['path']}{flag} | {r['text'][:42]}")
print("\n".join(lines))

print(f"\n{'='*70}")
print(f"[放行vs拦截] 分裂样本数: {n_split} / {len(rows)}")
print(f"其中触发 vote_* 单票否决/共识路径: {n_veto}")

# 汇总各档 FN/FP 校验（混合门）
print("\n=== 混合(L13.2) vs expected 一致性 ===")
mismatch = []
for r in rows:
    cb, fb = r["ds_chat_bucket"], r["ds_flash_bucket"]
    hyb, meta = hybrid_review(r["text"], cb, fb)
    if hyb != r["expected"]:
        mismatch.append((r["id"], r["expected"], hyb))
if mismatch:
    for m in mismatch:
        print(f"  MISMATCH {m[0]} exp={m[1]} hyb={m[2]}")
else:
    print("  全部 22 条混合门判定与 expected 一致。")