# -*- coding: utf-8 -*-
"""测试 ModelScope 大文件下载 URL 的响应，定位 safetensors 0MB 问题。"""
import urllib.request, urllib.error, json

RID = "LLM-Research/Llama-Guard-3-1B"
FILE = "tokenizer.json"
URLS = [
    f"https://modelscope.cn/models/{RID}/resolve/master/{FILE}",
    f"https://modelscope.cn/api/v1/models/{RID}/repo?Revision=master&FilePath={FILE}",
]
for url in URLS:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8"}, method="HEAD")
        with urllib.request.urlopen(req, timeout=20) as r:
            print(f"HEAD {url}\n  status={r.status} content-length={r.headers.get('Content-Length')} "
                  f"type={r.headers.get('Content-Type')}")
            if r.status in (301,302,307,308):
                print(f"  -> Location: {r.headers.get('Location')}")
    except urllib.error.HTTPError as e:
        print(f"HEAD {url}\n  HTTPError {e.code}")
    except Exception as e:
        print(f"HEAD {url}\n  ERR {type(e).__name__}: {e}")

# 也 GET 一个用标准库跟随重定向读前 5MB，确认是否能拿到 body
for name, url in [("resolve", URLS[0])]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=60) as r:
            n = 0
            while n < (5 << 20):
                b = r.read(1 << 20)
                if not b:
                    break
                n += len(b)
            print(f"\nGET {name}: read {round(n/1e6,1)}MB, final url={r.url}")
    except Exception as e:
        print(f"\nGET {name} ERR {type(e).__name__}: {e}")