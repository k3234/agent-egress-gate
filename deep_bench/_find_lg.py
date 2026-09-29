# -*- coding: utf-8 -*-
"""探测一批 ModelScope 候选仓库，找能下载 Llama-Guard-3-1B 的那个。"""
import urllib.request, json

CAND = [
    "meta-llama/Llama-Guard-3-1B",
    "LLM-Research/Llama-Guard-3-1B",
    "AI-ModelScope/Llama-Guard-3-1B",
    "modelscope/Llama-Guard-3-1B",
    "unsloth/Llama-Guard-3-1B",
    "JohnSmith/Llama-Guard-3-1B",
    "AI-ModelScope/Llama-Guard-3-1B",
    "yanmian/Llama_Guard_3_1B",
    "yxzll/Llama-Guard-3-1B",
    "noc515/Llama-Guard-3-1B",
]
for rid in CAND:
    api = f"https://modelscope.cn/api/v1/models/{rid}/repo/files?Revision=master"
    try:
        req = urllib.request.Request(api, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8"))
        files = data.get("Data", {}).get("Files", []) or []
        names = [f.get("Path") for f in files]
        has_safet = any("safetensors" in (n or "") for n in names)
        print(f"[OK ] {rid}  files={len(names)}  has_safetensors={has_safet}")
        for n in names:
            if n.endswith((".safetensors", ".json", ".model")):
                sz = next((f.get("Size") for f in files if f.get("Path") == n), 0)
                print(f"      {n} {round((sz or 0)/1e6,1)}MB")
    except urllib.error.HTTPError as e:
        print(f"[{e.code}] {rid}")
    except Exception as e:
        print(f"[ERR] {rid} {type(e).__name__}: {e}")