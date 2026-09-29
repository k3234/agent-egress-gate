# -*- coding: utf-8 -*-
"""公开基准卷：尝试从 HF 拉取 ToxicChat 子集(仅取脱敏用户输入文本)。

诚实前置：
  - ToxicChat 标注的是『内容毒性/仇恨/骚扰』分类，与 flow/DS 的『数据流出口+提权』任务维度不同。
  - 故仅做『拦截口径』参考(官方 toxic_label 作 ground truth)，在报告/图表中明确标注维度差异，
    不伪装成与自圈四卷同口径的 FN/FP 对比。
  - 若本机网络无法拉取，则如实报告无法获取，不下载任何损坏/伪造数据。
红线：仅读取文本与标注，不含敏感字段；结果不含任何真实凭据。
"""
from __future__ import annotations
import json, sys, traceback
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT = BASE / "toxicchat_subset.json"

def main():
    try:
        from datasets import load_dataset
    except Exception as e:
        print(f"[no datasets] {e}")
        return
    try:
        ds = load_dataset("lmsys/toxic-chat", "toxicchat0124", split="train", streaming=True)
        rows = []
        for i, ex in enumerate(ds):
            uid = ex.get("user_id") or ""
            text = ex.get("user_input") or ex.get("user") or ex.get("text") or ""
            label = str(ex.get("toxicity") or ex.get("user_annotation") or ex.get("label") or "")
            # 仅保留净文本 + 二元标注；不含 user_id 等元数据(隐私红线)
            if not text.strip():
                continue
            toxic = label.lower() in ("toxic", "1", "1.0", "yes", "harmful", "unsafe")
            rows.append({"id": f"tc{i:03d}", "text": text[:300],
                         "expected_verdict": "restrict" if toxic else "allow",  # 拦截口径代理
                         "toxic_chat_label": "toxic" if toxic else "non-toxic"})
            if len(rows) >= 100:
                break
        data = {"_meta": {
            "source": "lmsys/toxic-chat (toxicchat0124, streaming)",
            "n": len(rows),
            "took": "real stream first 100",
            "honest": "ToxicChat 标注=内容毒性,与本系统‘数据流出口+提权’任务维度不同; expected_verdict 仅为拦截口径代理(restrict=拦),非数据流四桶标答",
        }, "samples": rows}
        OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[ok] 拉取 {len(rows)} 条 -> {OUT}")
    except Exception as e:
        print("[FAIL 无法拉取 ToxicChat]:", e)
        traceback.print_exc()

if __name__ == "__main__":
    main()