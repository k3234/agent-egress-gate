# -*- coding: utf-8 -*-
"""真实延迟/成本测算：DeepSeek API 每次调用计时 + token 用量(usage字段)。

数据全部来自真实调用返回(usage.prompt_tokens/completion_tokens)与本地计时，
不编造。运行前需已配置 DEEPSEEK_API_KEY(本地 api-demo/.env)。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

BASE = Path(__file__).resolve().parent
PROJECT = BASE.parents[2]
sys.path.insert(0, str(PROJECT / "learning"))
API_ENV = PROJECT / "api-demo" / ".env"
SAMPLES = Path(os.environ.get("TIMING_SAMPLES", str(BASE / "realistic_intensity_samples.json")))
OUT = Path(os.environ.get("TIMING_OUT", str(BASE / "latency_cost.json")))
MODEL = os.environ.get("TIMING_MODEL", "deepseek-flash")

from capability_flow import flow_review  # noqa: E402

URL = "https://api.deepseek.com/chat/completions"
SYSTEM = (
    "你是数据流出口安全审查器。给定一个软件请求意图，判断其风险等级，"
    "只输出 JSON，格式为 {\"label\": \"allow\"} 或 {\"label\": \"restrict\"} 或 "
    "{\"label\": \"block\"} 或 {\"label\": \"review\"}，禁止输出任何其他内容。"
    "判定规则：数据仅留在本机→allow；状态篡改或数据外泄→restrict；"
    "权限提升/越权跨域→block；无法确定→review。"
)
_LABELS = ("allow", "review", "restrict", "block")


def _load_dotenv(path):
    env = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def _parse_label(content):
    content = content.strip()
    try:
        data = json.loads(content)
        lab = str(data.get("label", "")).strip().lower()
    except Exception:
        import re
        m = re.search(r'"(label|label")\s*:\s*"?([a-z_]+)', content, re.I)
        lab = m.group(2).lower() if m else ""
    return lab if lab in _LABELS else "review"


def _one_call(text, key):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": text},
        ],
        "temperature": 0,
        "response_format": {"type": "json_object"},
    }
    req = urllib.request.Request(
        URL, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    dt_ms = (time.perf_counter() - t0) * 1000
    usage = data.get("usage", {})
    content = data["choices"][0]["message"]["content"]
    return dict(label=_parse_label(content), latency_ms=round(dt_ms, 1),
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
                total_tokens=usage.get("total_tokens"))


def main():
    samples = json.loads(SAMPLES.read_text(encoding="utf-8"))["samples"]
    env = _load_dotenv(API_ENV)
    key = env.get("DEEPSEEK_API_KEY", "").strip()
    if not key:
        print("[fail] 无 DEEPSEEK_API_KEY → fail-closed 退出，不测。")
        return

    recs = []
    lat = []
    tok_in = tok_out = 0
    for s in samples:
        try:
            r = _one_call(s["text"], key)
        except (urllib.error.URLError, OSError, ValueError) as e:
            r = dict(label=f"err:{type(e).__name__}", latency_ms=-1,
                     prompt_tokens=None, completion_tokens=None, total_tokens=None)
        recs.append({"id": s["id"], **r})
        if r["latency_ms"] > 0:
            lat.append(r["latency_ms"])
        tok_in += r.get("prompt_tokens") or 0
        tok_out += r.get("completion_tokens") or 0
        # 本地 flow 计时(零外部依赖)
        t0 = time.perf_counter()
        flow_review(s["text"])
        flow_ms = (time.perf_counter() - t0) * 1000
        recs[-1]["flow_latency_ms"] = round(flow_ms, 3)
        time.sleep(0.15)

    n = len(recs)
    summary = {
        "model": MODEL, "n": n,
        "avg_latency_ms": round(sum(lat) / len(lat), 1) if lat else None,
        "p50_latency_ms": sorted(lat)[len(lat) // 2] if lat else None,
        "max_latency_ms": max(lat) if lat else None,
        "total_tokens": tok_in + tok_out,
        "avg_tokens_per_sample": round((tok_in + tok_out) / n, 1) if n else None,
        "avg_prompt_tokens": round(tok_in / n, 1) if n else None,
        "avg_completion_tokens": round(tok_out / n, 1) if n else None,
        "flow_avg_latency_ms": round(sum(r["flow_latency_ms"] for r in recs) / n, 4),
    }
    data = {"summary": summary, "per_sample": recs}
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("[ok]", OUT)


if __name__ == "__main__":
    main()