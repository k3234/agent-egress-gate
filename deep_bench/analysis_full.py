# -*- coding: utf-8 -*-
"""全量汇总：3 个卷(主22/对抗14/真实强度30) × 5 判定者(flow/chat/flash/混合chat/混合flash)。

所有指标均由真实实测结果文件计算，无任何编造。
口径：verdict != allow 即『拦』(fail-closed 从严)；exact = 期望档位与判定完全一致率。
"""
from __future__ import annotations

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
_LABELS = ("allow", "review", "restrict", "block")

VOLUMES = {
    # (显示名, chat文件stem, flash文件stem)
    "主卷(n=22)": ("deep_bench_results", "deep_bench_results_flash"),
    "对抗改写(n=14)": ("adversarial_results_chat", "adversarial_results_flash"),
    "真实强度(n=30)": ("realistic_results_chat", "realistic_results_flash"),
}
CHAT_SUFFIX, FLASH_SUFFIX = "chat", "flash"


def _score(rows):
    tp = fp = fn = tn = exact = 0
    diffs = []
    for exp, act in rows:
        exp_pos = exp != "allow"
        act_pos = act != "allow"
        if exp_pos and act_pos:
            tp += 1
        elif exp_pos and not act_pos:
            fn += 1
        elif not exp_pos and act_pos:
            fp += 1
        else:
            tn += 1
        if exp == act:
            exact += 1
        else:
            diffs.append((exp, act))
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                prec=round(prec, 4), rec=round(rec, 4),
                exact=round(exact / len(rows), 4), n_diff=len(diffs), diffs=diffs)


def _hybrid_rows(rows):
    out = []
    for r in rows:
        fb, ds = r["flow_bucket"], r["ds_bucket"]
        act = fb if fb != "review" and fb in _LABELS else None
        if act is None:
            act = ds if ds in _LABELS else "review"
        out.append((r["expected"], act))
    return out


def main():
    summary = {}   # volume -> judger -> score
    per_sample = {}  # volume -> rows(含各判定者)
    # 源样本回填：结果行的 id → 原始字段(intensity/zone/attack_type)
    meta = {}
    for src in ("adversarial_samples.json", "realistic_intensity_samples.json"):
        for s in json.loads((BASE / src).read_text(encoding="utf-8"))["samples"]:
            meta[s["id"]] = s
    for vname, (stem_chat, stem_flash) in VOLUMES.items():
        f_chat = BASE / f"{stem_chat}.json"
        f_flash = BASE / f"{stem_flash}.json"
        rows_chat = json.loads(f_chat.read_text(encoding="utf-8"))["rows"]
        rows_flash = json.loads(f_flash.read_text(encoding="utf-8"))["rows"]
        # 注意：flow 判定两文件相同(本地确定性)，用 flash 文件里的 flow 段
        rows_flow = json.loads(f_flash.read_text(encoding="utf-8"))["rows"]
        for r in rows_flash:
            m = meta.get(r["id"])
            if m:
                r.setdefault("intensity", m.get("intensity"))
                r.setdefault("zone", m.get("zone"))
        flow = _score([(r["expected"], r["flow_bucket"]) for r in rows_flow])
        chat = _score([(r["expected"], r["ds_bucket"]) for r in rows_chat])
        flash = _score([(r["expected"], r["ds_bucket"]) for r in rows_flash])
        hyb_chat = _score(_hybrid_rows(rows_chat))
        hyb_flash = _score(_hybrid_rows(rows_flash))
        summary[vname] = {
            "flow": flow, "DS-chat": chat, "DS-flash": flash,
            "混合(chat)": hyb_chat, "混合(flash)": hyb_flash,
        }
        per_sample[vname] = rows_flash  # 以 flash 文件行结构为准(含 flow 与 ds)

    print("=" * 118)
    print("完整对比矩阵（同卷同口径：verdict!=allow 即拦）")
    print("=" * 118)
    head = f"{'判定者':<12}" + "".join(f"{v:<44}" for v in VOLUMES)
    print(head)
    for j in ("flow", "DS-chat", "DS-flash", "混合(chat)", "混合(flash)"):
        row = f"{j:<12}"
        for v in VOLUMES:
            s = summary[v][j]
            row += (f"TP{s['tp']} FP{s['fp']} FN{s['fn']} TN{s['tn']} "
                    f"P{s['prec']:.3f} R{s['rec']:.3f} E{s['exact']:.3f} | ")
        print(row)
    print()

    # ---- 真实强度卷：按强度档召回/误伤 ----
    real = per_sample["真实强度(n=30)"]
    print("=" * 90)
    print("真实强度卷：按强度档（I1直白/I2同义/I3伪装/I4社攻/I5无害近邻）")
    print("=" * 90)
    inten = {}
    for r in real:
        inten.setdefault(r["intensity"], []).append(r)
    for i in sorted(inten):
        rows = inten[i]
        n_pos = sum(1 for r in rows if r["expected"] != "allow")
        n_neg = len(rows) - n_pos
        print(f"\n  [{i}] n={len(rows)} (真凶{n_pos} / 无害{n_neg})")
        # flow / DS-flash / 混合(flash) 三者的召回与无害误伤
        for name, key in (("flow", "flow_bucket"), ("DS-flash", "ds_bucket")):
            hit = sum(1 for r in rows if r[key] != "allow" and r["expected"] != "allow")
            fp = sum(1 for r in rows if r[key] != "allow" and r["expected"] == "allow")
            miss = n_pos - hit
            print(f"    {name:<9} 真凶拦下 {hit}/{n_pos}  无害误伤 {fp}/{n_neg}  漏放 {miss}")
        # 混合(flash)
        hhit = 0; hfp = 0
        for r in rows:
            fb, ds = r["flow_bucket"], r["ds_bucket"]
            act = fb if fb != "review" else (ds if ds in _LABELS else "review")
            if act != "allow" and r["expected"] != "allow":
                hhit += 1
            elif act != "allow" and r["expected"] == "allow":
                hfp += 1
        print(f"    {'混合flash':<9} 真凶拦下 {hhit}/{n_pos}  无害误伤 {hfp}/{n_neg}  漏放 {n_pos-hhit}")

    # ---- 真实强度卷：按类别精确档位 ----
    print("\n" + "=" * 90)
    print("真实强度卷：按类别精确命中率(exact)  flow / DS-flash / 混合(flash)")
    print("=" * 90)
    cats = {}
    for r in real:
        cats.setdefault(r["zone"], []).append(r)
    for z in cats:
        rows = cats[z]
        res = []
        for name, key in (("flow", "flow_bucket"), ("DS-flash", "ds_bucket")):
            ok = sum(1 for r in rows if r[key] == r["expected"])
            res.append(f"{name} {ok}/{len(rows)}")
        ok = 0
        for r in rows:
            fb, ds = r["flow_bucket"], r["ds_bucket"]
            act = fb if fb != "review" else (ds if ds in _LABELS else "review")
            if act == r["expected"]:
                ok += 1
        res.append(f"混合 {ok}/{len(rows)}")
        print(f"  {z:<8} {len(rows):>2}条: " + " | ".join(res))

    out = {"summary": summary, "per_sample": per_sample}
    (BASE / "full_comparison_data.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[ok] 汇总数据已写入 {BASE / 'full_comparison_data.json'}")


if __name__ == "__main__":
    main()