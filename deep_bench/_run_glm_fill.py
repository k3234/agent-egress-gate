# -*- coding: utf-8 -*-
"""补齐 GLM 补跑：仅对缺失的 44 条（对抗基础14 + 真实基础30）调 GLM，合并回 glm_results.json。

背景：_run_glm.py 的 VOLS 误用扩展子集文件（adv_extend 36 / real_extend 70），
漏掉基础卷（adversarial 14 / realistic 30）。五卷完整=22+50+100+30+22=224。
用法: python _run_glm_fill.py
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

BASE = Path(__file__).resolve().parent
PROJECT = BASE.parents[2]
LEARN = PROJECT / "learning"
sys.path.insert(0, str(LEARN))
from capability_flow import flow_review  # noqa: E402
from _run_glm import _dotenv, _glm, _parse  # noqa: E402  复用同一定义，保证口径一致

MODEL = "glm-5.3-flash"
OUT = BASE / "glm_results.json"
FILL = {
    "对抗全量(n=50)": "adversarial_samples.json",
    "真实全量(n=100)": "realistic_intensity_samples.json",
}


def main():
    key = _dotenv(PROJECT / "api-demo" / ".env").get("GLM_API_KEY", "").strip()
    live = bool(key)
    data = json.loads(OUT.read_text(encoding="utf-8"))
    rows = data["rows"]
    have = {r["id"] for r in rows}
    tasks = []
    for vname, spf in FILL.items():
        for s in json.loads((BASE / spf).read_text(encoding="utf-8"))["samples"]:
            if s["id"] not in have:
                tasks.append((vname, s))
    print(f"[i] 已有 {len(rows)} 条，待补 {len(tasks)} 条", flush=True)
    if not tasks:
        print("[ok] 无需补跑")
        return

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_glm, s["text"], key): (vname, s) for vname, s in tasks}
        for fut in as_completed(futures):
            vname, s = futures[fut]
            sc, lv, fb, ev = flow_review(s["text"])
            gl = fut.result()
            rows.append({"id": s["id"], "expected": s["expected_verdict"], "volume": vname,
                         "text": s["text"], "flow": fb, "flow_evidence": ev, "glm": gl,
                         "zone": s.get("zone"), "attack_type": s.get("attack_type")})
            print(f"[{vname}] {s['id']} flow={fb} glm={gl}", flush=True)
    rows.sort(key=lambda r: (r["volume"], r["id"]))
    api_ok = not any(str(r["glm"]).startswith("err:") for r in rows)
    data["rows"] = rows
    data["_meta"].update({"n": len(rows), "api_ok": api_ok,
                          "note": "flow 本地确定性；glm 真实 API。err 如实保留不归一化。"})
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n[ok] 合并完成 n={len(rows)} api_ok={api_ok} → {OUT}")


if __name__ == "__main__":
    main()
