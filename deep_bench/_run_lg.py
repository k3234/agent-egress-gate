# -*- coding: utf-8 -*-
"""Llama-Guard-3-1B 本地实测：对五卷脱敏样本集(主22/对抗50/真实100/提示注入30/分裂22 = 224条)做内容护栏判定。

诚实前置：
  - LG 是【内容护栏】(safe/unsafe 分类，检测有害/攻击内容)，与 flow/DS 的【数据流出口+提权】判定任务维度不同。
  - LG 输出的是内容风险类别码 S1-S14，本脚本给出【近似映射】到四桶(出口/提权相关=S2非暴力犯罪/S7隐私→restrict,
    S14代码解释器滥用→block, 其余内容类→review)，明确标注为近似、非 LG 原生四桶语义。
  - 若 LG 对"无内容危害的恶意意图"标 safe -> 产生 FN，这是任务维度差异的真实体现，如实报告。
  - 样本全部脱敏、仅本机推理，模型与样本不对外分发、不入任何仓库。
  - 机器仅 8.4GB RAM，故用 bfloat16 + low_cpu_mem_usage 避免 swap(float32 实测 ~200s/条不可用, bf16 ~1.6s/条)。
"""
from __future__ import annotations
import json, sys, time
from pathlib import Path

BASE = Path(__file__).resolve().parent
LG_DIR = BASE.parent / "models" / "Llama-Guard-3-1B"

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

torch.set_num_threads(6)
DEV = "cpu"
tok = AutoTokenizer.from_pretrained(LG_DIR, use_fast=True)
tok.pad_token = tok.eos_token
model = AutoModelForCausalLM.from_pretrained(
    LG_DIR, dtype=torch.bfloat16, low_cpu_mem_usage=True).to(DEV).eval()

PROMPT_TMPL = "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n{p}<|eot_id|><|start_header_id|>assistant<|end_header_id|>"

# Llama Guard 3 原生风险码(用于文档/审计)，与"数据流出口/提权"维度相关的仅有少数几类
S_CODES = {
    "s1": "violent_crimes", "s2": "non_violent_crimes", "s3": "sex_related_crimes",
    "s4": "child_sexual_exploitation", "s5": "defamation", "s6": "specialized_advice",
    "s7": "privacy", "s8": "intellectual_property", "s9": "indiscriminate_weapons",
    "s10": "hate", "s11": "suicide_self_harm", "s12": "sexual_content",
    "s13": "elections", "s14": "code_interpreter_abuse",
}
# 近似映射：仅把与"数据外流/越权/提权"沾边的类别给档位，其余内容类归 review
_HIGH = {"s2", "s7"}      # 非暴力犯罪(含网络入侵/数据窃取) & 隐私(PII/凭据)
_BLOCK = {"s14"}          # 代码解释器滥用(近似提权/越权执行)


def _cat_bucket(codes):
    if not codes:
        return "review"
    ss = {c.strip().lower() for c in codes}
    if ss & _BLOCK:
        return "block"
    if ss & _HIGH:
        return "restrict"
    return "review"


def classify(text: str):
    inp = tok(PROMPT_TMPL.format(p=text), return_tensors="pt").to(DEV)
    with torch.no_grad():
        out = model.generate(**inp, do_sample=False, max_new_tokens=10,
                             pad_token_id=tok.eos_token_id)
    gen = tok.decode(out[0][inp["input_ids"].shape[1]:], skip_special_tokens=True).strip()
    low = gen.lower()
    if low.startswith("safe"):
        return "allow", "safe", []
    if low.startswith("unsafe"):
        lines = [x.strip() for x in low.split("\n") if x.strip()]
        codes = []
        if len(lines) > 1:
            codes = [c for c in lines[1].replace(";", ",").split(",") if c]
        names = [S_CODES.get(c.strip().lower(), c.strip()) for c in codes]
        return _cat_bucket(codes), f"unsafe|{','.join(codes)}", names
    # 解析失败 -> 待审(fail-closed)
    return "review", f"unknown|{gen[:30]}", []


def load_samples():
    """五卷归一化记录(主22/对抗50/真实100/提示注入30/分裂22 = 224条)，从各卷结果源文件重建。"""
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


def _dump(res, elapsed):
    (BASE / "lg_results.json").write_text(
        json.dumps({"_meta": {"model": "Llama-Guard-3-1B", "dtype": "bfloat16", "device": DEV,
                              "n": len(res), "elapsed_s": round(elapsed, 1),
                              "honest": "内容护栏 vs 出口/提权判定: 任务维度不同; 档位为 S码近似映射, 非LG原生四桶"},
                    "rows": res}, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    rows = load_samples()
    print(f"共 {len(rows)} 条样本，开始逐条 LG 推理(CPU/bfloat16)\n", flush=True)
    res = []
    t0 = time.time()
    for i, r in enumerate(rows, 1):
        bucket, raw, names = classify(r["text"])
        res.append({**r, "lg_bucket": bucket, "lg_raw": raw, "lg_cats": names})
        print(f"[{i}/{len(rows)}] {r['vol']}|{r['id']} lg={bucket} raw={raw} expected={r['expected']}", flush=True)
        if i % 20 == 0:
            _dump(res, time.time() - t0)
    _dump(res, time.time() - t0)
    print(f"\n[ok] 落盘 lg_results.json  n={len(res)}  elapsed={round(time.time()-t0,1)}s")


if __name__ == "__main__":
    main()