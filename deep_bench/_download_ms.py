# -*- coding: utf-8 -*-
"""通用 ModelScope 模型下载器(仅本地推理用，不外发/不入库)。
用法: python _download_ms.py <repo_id> <dest_dir>
完整性判定：safetensors 以【头解析】为 ground-truth(ModelScope 报告 Size 不可靠)，非 safetensors 用 Size。
支持断点续传 + 自动重试。
"""
import urllib.request, json, sys, time, struct
from pathlib import Path

RID = sys.argv[1] if len(sys.argv) > 1 else "LLM-Research/Llama-Prompt-Guard-2-86M"
DEST = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(
    __file__).resolve().parent.parent / "models" / "Llama-Prompt-Guard-2-86M"
DEST.mkdir(parents=True, exist_ok=True)
HF = {"User-Agent": "curl/8"}
MAX_ATTEMPT = 120


def _safe_needed_bytes(path: Path):
    if not path.exists() or path.stat().st_size < 8:
        return None
    try:
        with open(path, "rb") as f:
            n = struct.unpack("<Q", f.read(8))[0]
            if n < 0 or n > 64 * 1024 * 1024:
                return None
            f.seek(8)
            meta = json.loads(f.read(n))
        mx = max(v["data_offsets"][1] for k, v in meta.items() if k != "__metadata__")
        return ((8 + n + 7) & ~7) + mx
    except Exception:
        return None


def _list_files():
    url = f"https://modelscope.cn/api/v1/models/{RID}/repo/files?Revision=master"
    with urllib.request.urlopen(urllib.request.Request(url, headers=HF), timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))["Data"]["Files"]


files = _list_files()
print(f"repo={RID}  文件数={len(files)}\n目标={DEST}\n")
fail = []
for f in files:
    name = f["Path"]; size = f.get("Size", 0)
    if name.endswith(".safetensors") is False and size and size > 200 * 1024 * 1024:
        print(f"[warn] 大非权重文件 {name} {round(size/1e6,1)}MB 跳过"); continue
    out = DEST / name
    need = _safe_needed_bytes(out) if name.endswith(".safetensors") else (size if size else 0)
    if need and out.exists() and out.stat().st_size >= need:
        print(f"[skip] {name}"); continue
    if name.endswith(".safetensors") and out.exists():
        print(f"[REMAKE] {name} 不完整，删除重下(旧 {out.stat().st_size}B need {need}B)")
        out.unlink()
    url = f"https://modelscope.cn/api/v1/models/{RID}/repo?Revision=master&FilePath={name}"
    tmp = Path(str(out) + ".part")
    attempts = 0
    while True:
        attempts += 1
        start = tmp.stat().st_size if tmp.exists() else 0
        headers = dict(HF)
        if start:
            headers["Range"] = f"bytes={start}-"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "ab" if start else "wb") as fh:
                done = start
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    fh.write(chunk); done += len(chunk)
            cur = _safe_needed_bytes(tmp) if name.endswith(".safetensors") else size
            if cur and done >= cur:
                tmp.rename(out); print(f"[ok ] {name} {round(done/1e6,1)}MB"); break
            if cur is None:
                tmp.rename(out); print(f"[ok?] {name} 头不可解析接受落盘 {round(done/1e6,1)}MB"); break
            if attempts >= MAX_ATTEMPT:
                fail.append((name, f"max_attempt {done}/{cur}")); print(f"[FAIL] {name}"); break
            time.sleep(2)
        except Exception as e:
            print(f"  [attempt {attempts}] {e}")
            if attempts >= MAX_ATTEMPT:
                fail.append((name, str(e))); print(f"[FAIL] {name}"); break
            time.sleep(2)

print("\n完成，失败:", fail if fail else "无")
print("目录:", DEST)
