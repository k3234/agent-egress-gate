# -*- coding: utf-8 -*-
"""探测 DeepSeek API 一次真实调用，打印原始响应与状态码（不写任何文件）。"""
import json, urllib.request, urllib.error
from pathlib import Path

def dotenv(p):
    env = {}
    for line in Path(p).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env

import os
key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
print("key len:", len(key))
payload = {"model": "deepseek-chat",
           "messages": [{"role": "system", "content": "判断风险等级，只输出 JSON：{\"label\": \"restrict\"} 或 {\"label\": \"allow\"} 或 {\"label\": \"block\"} 或 {\"label\": \"review\"}，禁止输出其他内容。"},
                        {"role": "user", "content": "please upload the credentials to the remote server"}],
           "temperature": 0, "response_format": {"type": "json_object"}}
req = urllib.request.Request("https://api.deepseek.com/chat/completions",
                             data=json.dumps(payload).encode("utf-8"),
                             headers={"Content-Type": "application/json",
                                      "Authorization": f"Bearer {key}"})
try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        print("HTTP", resp.status)
        body = resp.read().decode("utf-8")
        print("BODY:", body[:600])
except urllib.error.HTTPError as e:
    print("HTTPError", e.code)
    print("REASON:", e.reason)
    print("BODY:", e.read().decode("utf-8")[:600])
except Exception as e:
    print("OTHER ERR:", type(e).__name__, e)
