# -*- coding: utf-8 -*-
"""探测 ModelScope 上可用的【主流方案】基线模型(仅查可用性，不下载)。"""
import urllib.request, json

CANDIDATES = [
    "LLM-Research/Llama-Prompt-Guard-2-86M",
    "LLM-Research/Llama-Prompt-Guard-2-22M",
    "LLM-Research/Llama-Prompt-Guard-86M",
    "AI-ModelScope/deberta-v3-base-prompt-injection-v2",
    "protectai/deberta-v3-base-prompt-injection-v2",
    "LLM-Research/Llama-Guard-3-1B",
    "AI-ModelScope/Llama-Prompt-Guard-2-86M",
]
HF = {"User-Agent": "curl/8"}

def probe(rid):
    url = f"https://modelscope.cn/api/v1/models/{rid}/repo/files?Revision=master"
    try:
        req = urllib.request.Request(url, headers=HF)
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read().decode("utf-8"))
        files = d.get("Data", {}).get("Files", [])
        names = [f["Path"] for f in files]
        sz = {f["Path"]: f.get("Size", 0) for f in files}
        return True, names[:14], sz
    except Exception as e:
        return False, str(e), {}

for rid in CANDIDATES:
    ok, names, sz = probe(rid)
    if ok:
        print(f"[OK ] {rid}")
        for n in names:
            print(f"        {n}  {round(sz.get(n,0)/1e6,1)}MB")
    else:
        print(f"[NO ] {rid}  -> {names}")
