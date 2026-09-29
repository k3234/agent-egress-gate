# -*- coding: utf-8 -*-
"""主流方案基线：Meta Llama-Prompt-Guard-2-86M（专用提示注入/越狱分类器）本地实测。

诚实前置：
  - Prompt Guard 2 是【输入侧注入/越狱分类器】(benign vs malicious)，衡量的是"这段输入有没有在试图操纵模型"，
    与 flow/DS/混合 的【数据流出口+提权】维度不同。
  - 它在【提示注入卷】上是同维度可比(都是抓注入)；在其余卷上是跨维度参考，如实标注。
  - 输出概率 p_malicious 全量落盘，便于做阈值扫描 / 不同 FPR 下的召回对比(比单点阈值更公平)。
  - 仅本机推理，模型与样本不外发、不入库。
"""
from __future__ import annotations
import json, time
from pathlib import Path

BASE = Path(__file__).resolve().parent
PG_DIR = BASE.parent / "models" / "Llama-Prompt-Guard-2-86M"

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

torch.set_num_threads(6)

tok = AutoTokenizer.from_pretrained(PG_DIR)
model = AutoModelForSequenceClassification.from_pretrained(PG_DIR, dtype=torch.float32).eval()
id2label = {int(k): v for k, v in model.config.id2label.items()}
print("id2label:", id2label, flush=True)
# 找 malicious 那一类的下标
MAL_IDX = 1
for k, v in id2label.items():
    if "malicious" in str(v).lower() or "injection" in str(v).lower() or "jailbreak" in str(v).lower():
        MAL_IDX = k
print("malicious index =", MAL_IDX, "->", id2label.get(MAL_IDX), flush=True)


def score(text: str):
    enc = tok(text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        logits = model(**enc).logits
    probs = torch.softmax(logits, dim=-1)[0]
    return float(probs[MAL_IDX])


def load_samples():
    full = json.loads((BASE / "full_comparison_data.json").read_text(encoding="utf-8"))
    split = json.loads((BASE / "split_bench_data.json").read_text(encoding="utf-8"))
    pinj = json.loads((BASE / "pinject_results_scored.json").read_text(encoding="utf-8"))["records"]
    real = json.loads((BASE / "real_full100_results.json").read_text(encoding="utf-8"))["records"]
    adv = json.loads((BASE / "adv_full50_results.json").read_text(encoding="utf-8"))["records"]
    vols = []
    for it in full["per_sample"]["主卷(n=22)"]:
        vols.append({"vol": "主卷", "id": it["id"], "expected": it["expected"], "text": it["text"]})
    for it in split["per_sample"]:
        vols.append({"vol": "分裂卷", "id": it["id"], "expected": it["expected"], "text": it["text"]})
    for it in pinj:
        vols.append({"vol": "提示注入", "id": it["id"], "expected": it["expected"], "text": it["text"]})
    for it in real:
        vols.append({"vol": "真实卷", "id": it["id"], "expected": it["expected"], "text": it["text"]})
    for it in adv:
        vols.append({"vol": "对抗卷", "id": it["id"], "expected": it["expected"], "text": it["text"]})
    return vols


THRESH = 0.5


def main():
    rows_src = load_samples()
    print(f"共 {len(rows_src)} 条样本，开始 Prompt Guard 2 推理(CPU)\n", flush=True)
    res = []
    t0 = time.time()
    for i, r in enumerate(rows_src, 1):
        p = score(r["text"])
        bucket = "restrict" if p >= THRESH else "allow"   # 近似二桶: 标注入=拦
        res.append({**r, "pg_prob": round(p, 6), "pg_bucket": bucket})
        print(f"[{i}/{len(rows_src)}] {r['vol']}|{r['id']} p={p:.4f} pg={bucket} expected={r['expected']}",
              flush=True)
        if i % 25 == 0:
            (BASE / "pg_results.json").write_text(
                json.dumps({"_meta": {"model": "Llama-Prompt-Guard-2-86M", "threshold": THRESH,
                                      "n": len(res), "elapsed_s": round(time.time()-t0, 1),
                                      "honest": "注入分类器 vs 数据流出口判定: 维度不同; 注入卷同维度可比, 其余跨维度参考"},
                            "rows": res}, ensure_ascii=False, indent=2), encoding="utf-8")
    (BASE / "pg_results.json").write_text(
        json.dumps({"_meta": {"model": "Llama-Prompt-Guard-2-86M", "threshold": THRESH,
                              "n": len(res), "elapsed_s": round(time.time()-t0, 1),
                              "honest": "注入分类器 vs 数据流出口判定: 维度不同; 注入卷同维度可比, 其余跨维度参考"},
                    "rows": res}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[ok] 落盘 pg_results.json n={len(res)} elapsed={round(time.time()-t0,1)}s")


if __name__ == "__main__":
    main()