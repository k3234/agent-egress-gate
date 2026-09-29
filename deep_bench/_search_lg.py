# -*- coding: utf-8 -*-
"""在 ModelScope 搜索真实的 Llama-Guard-3-1B 仓库并列出候选。"""
import urllib.request, urllib.parse, json

def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8"))

kws = ["Llama-Guard-3-1B", "Llama Guard 3 1B", "LlamaGuard 3B"]
seen = set()
for kw in kws:
    q = urllib.parse.urlencode({"Keyword": kw, "PageSize": 30})
    url = f"https://modelscope.cn/api/v1/dolphin/models?{q}"
    try:
        data = _get(url)
    except Exception as e:
        print(f"kw={kw} FAIL {e}"); continue
    models = data.get("Data", {}).get("Model", data.get("Data", []))
    if isinstance(models, dict):
        models = models.get("Models", []) or models.get("models", [])
    for m in models or []:
        rid = m.get("Path") or m.get("Id")
        dl = m.get("Downloads") or m.get("downloads")
        if rid and rid not in seen:
            seen.add(rid)
            print(f"  {rid}  downloads={dl}")