# -*- coding: utf-8 -*-
"""从 ModelScope 下载 Llama-Guard-3-1B 权重到本地(仅本地推理，不对外/不提交)。
下载【仅】白名单安全评测需要；红线：本模型及样本不打包外发、不入任何仓库。
"""
import urllib.request, json, sys, time, os, struct
from pathlib import Path

RID = "LLM-Research/Llama-Guard-3-1B"
DEST = Path(__file__).resolve().parent.parent / "models" / "Llama-Guard-3-1B"
DEST.mkdir(parents=True, exist_ok=True)
# 只下载 safetensors 权重，跳过非权重小文件由 HF 加载时自动处理
ONLY_SAFE = True

HF = {"User-Agent": "curl/8"}


def _safe_needed_bytes(path: Path):
    """解析 safetensors 头，返回完整文件应有的字节数；解析失败返回 None(=无法判定)。
    ground-truth 校验，避免 ModelScope 报告的 Size 不准确导致截断文件被误判完成。"""
    if not path.exists() or path.stat().st_size < 8:
        return None
    try:
        with open(path, "rb") as f:
            n = struct.unpack("<Q", f.read(8))[0]
            if n < 0 or n > 64 * 1024 * 1024:
                return None
            f.seek(8)
            meta = json.loads(f.read(n))
        mx = 0
        for k, v in meta.items():
            if k == "__metadata__":
                continue
            mx = max(mx, v["data_offsets"][1])
        data_off = (8 + n + 7) & ~7
        return data_off + mx
    except Exception:
        return None

def _list_files():
    url = f"https://modelscope.cn/api/v1/models/{RID}/repo/files?Revision=master"
    req = urllib.request.Request(url, headers=HF)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))["Data"]["Files"]

files = _list_files()
names = [f["Path"] for f in files]
if ONLY_SAFE:
    files = [f for f in files if f["Path"].endswith(".safetensors")]
print("待下载:", len(files), "个 safetensors 权重文件")

fail = []
MAX_ATTEMPT = 120
for f in files:
    name = f["Path"]; size = f.get("Size", 0)
    out = DEST / name
    need = _safe_needed_bytes(out) if name.endswith(".safetensors") else (size if size else 0)
    if need and out.exists() and out.stat().st_size >= need:
        print(f"[skip] {name}  size={out.stat().st_size} need={need}")
        continue
    if name.endswith(".safetensors") and out.exists():
        print(f"[REMAKE] {name} 截断/不完整，删除重下(旧 {out.stat().st_size}B, need {need}B)", flush=True)
        out.unlink()
    url = f"https://modelscope.cn/api/v1/models/{RID}/repo?Revision=master&FilePath={name}"
    tmp = Path(str(out) + ".part")
    attempts = 0
    last_err = ""
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
            cur_need = _safe_needed_bytes(tmp) if name.endswith(".safetensors") else size
            print(f"  [attempt {attempts}] done={round(done/1e6,1)}MB", flush=True)
            if cur_need and done >= cur_need:
                tmp.rename(out)
                print(f"[ok ] {name}  {round(done/1e6,1)}MB 完成", flush=True)
                break
            if cur_need is None:
                # 头解析失败且文件已较大，接受落盘(fail-open 以免死循环)
                tmp.rename(out)
                print(f"[ok?] {name} 头不可解析, 接受落盘 {round(done/1e6,1)}MB", flush=True)
                break
            if attempts >= MAX_ATTEMPT:
                fail.append((name, f"max_attempt {done}/{cur_need}"))
                print(f"[FAIL] {name} 达最大尝试仍不完整", flush=True)
                break
            time.sleep(3)  # 重试续传
        except Exception as e:
            last_err = str(e)
            cur = tmp.stat().st_size if tmp.exists() else start
            print(f"  [attempt {attempts}] err={e} 已续传至 {round(cur/1e6,1)}MB", flush=True)
            if attempts >= MAX_ATTEMPT:
                fail.append((name, last_err))
                print(f"[FAIL] {name} 达最大尝试: {last_err}", flush=True)
                break
            time.sleep(3)

print("\n完成，失败:", fail if fail else "无")
print("目录:", DEST)