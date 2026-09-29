# -*- coding: utf-8 -*-
"""探测 ModelScope 上 Llama-Guard-3-1B 镜像仓库是否存在且文件齐全(仅列清单，不下载)。"""
import urllib.request, json

CANDIDATES = [
    "AI-ModelScope/Llama-Guard-3-1B",
    "yanmian/Llama-Guard-3-1B",
    "wangzhiang/Llama-Guard-3-1B",
    "swift/Llama-Guard-3-1B",
]

for repo in CANDIDATES:
    url = f"https://modelscope.cn/api/v1/models/{repo}/repo/files?Revision=master"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8"))
        files = data.get("Data", {}).get("Files", data.get("Files", []))
        names = [f.get("Path") for f in files] if files else []
        print(f"\n[{repo}] {len(names)} files")
        for n in sorted(names):
            sz = next((f.get("Size") for f in files if f.get("Path") == n), None)
            if any(k in n for k in ("model", "config", "tokenizer", "generation", "special")):
                print(f"   {n}  {round((sz or 0)/1e6,1)}MB")
    except Exception as e:
        print(f"\n[{repo}] FAIL: {type(e).__name__}: {e}")