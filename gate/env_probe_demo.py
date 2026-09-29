# -*- coding: utf-8 -*-
"""EnvProbe 最小实现作业：采集本机环境画像并用规则打分（severity）。

只在本机学习的演示脚本，不纳入产品库代码。
瀑布几步：探针采集 -> 装进 EnvSnapshot -> score 评分 -> 打印结论。

第 5 步的 score() 是留给你的作业，其余已搭好。
"""
from __future__ import annotations

from dataclasses import dataclass, field
import subprocess
import ctypes
import sys
import hashlib
import json
from pathlib import Path


# ---------------------------------------------------------------
# 第 1 步 数据结构：一台机器的"环境体检报告长什么样"
# ---------------------------------------------------------------
@dataclass
class EnvSnapshot:
    # True = 当前进程以管理员权限运行（危险信号）
    is_admin: bool = False
    # 从 Temp / Roaming / ProgramData 等病毒驻留地运行的进程路径
    suspicious_paths: list = field(default_factory=list)
    # 无法读取杀软状态时出于保守按 True 记录"未知"
    antivirus_unknown: bool = False
    # 杀软是否在运行（能读到才算 True）
    antivirus_active: bool = False


# ---------------------------------------------------------------
# 第 2 步 探针：当前进程是不是管理员权限？
# ---------------------------------------------------------------
def check_admin() -> bool:
    """用 ctypes 直接问 Windows：当前进程是提升权限的吗？"""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------
# 第 3 步 探针：有没有进程从"病毒驻留地"运行？
#     -- 通过 subprocess 调用 PowerShell 拿到所有进程路径，再筛
# ---------------------------------------------------------------
BAD_DIRS = ("\\temp\\", "appdata\\roaming", "programdata")

def check_suspicious_paths(scope: str = "run") -> list:
    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path",
    ]
    raw = ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        raw = r.stdout or ""
    except Exception as e:
        print(f"   [探针3] 获取进程路径失败，跳过该项。原因：{e}")
        return []
    wl = load_whitelist()          # 排查前先把白名单读进来
    hits = []
    for line in raw.splitlines():
        p = line.strip()
        if not p:
            continue
        if any(b in p.lower() for b in BAD_DIRS):
            # 先查白名单：路径对 + 签名对 + 该功能放行 -> 放过
            if is_whitelisted(p, wl, scope):
                continue
            hits.append(p)
    return hits


# ---------------------------------------------------------------
# 第 4 步 探针：杀软在运行吗？
#     注意：你机器上 Get-MpComputerStatus 可能报 0x800106ba，
#     所以这里必须 try/except —— 探针拿不到数据也不能崩，返回"未知"。
# ---------------------------------------------------------------
def check_antivirus():
    cmd = [
        "powershell", "-NoProfile", "-Command",
        "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        out = (r.stdout or "").strip()
        return out == "True", False   # (active, unknown)
    except Exception:
        return False, True             # 读不到 -> 保守：active=False, unknown=True


# ---------------------------------------------------------------
# 第 5 步 ★ 你的作业：把环境画像 翻译(打分) 成 severity 等级 ★
# ---------------------------------------------------------------
def score(snap: EnvSnapshot) -> str:
    """根据探针结果计算环境可信度。

    评分规则（把每次 hit 的分数累加）：
      - 管理员权限运行        -> +3    （最危险的信号）
      - 有病毒驻留地路径进程   -> +2
      - 杀软未知(unknown)     -> +2    （拿不到就保守，宁可多扣分）
      - 其他读数没异常         -> 0

    档位（累加后的总分数）：
      - 总分 >= 4  -> "critical"
      - 总分 >= 2  -> "high"
      - 否则        -> "low"

    提示：先想办法拿到这些字段的值，再累加，再分档。
    写完后运行，看看能到哪一档。
    """
    # ---------- 这里开始写 ----------
    hit = 0
    if snap.is_admin:
        hit += 3
    if snap.suspicious_paths:
        hit += 2
    if snap.antivirus_unknown:
        hit += 2
    if hit >= 4: return "critical"
    elif hit >= 2: return "high"
    else: return "low"


# ---------------------------------------------------------------
# 第 7 步 白名单：让"好进程"免于误报
#     关键设计：不是只记路径，而是 路径 + 内容签名(sha256) 完全绑定。
#     这样攻击者把病毒复制到白名单路径上也绕不过——内容变了签名就翻脸。
# ---------------------------------------------------------------
WHITELIST_FILE = Path(__file__).parent / "whitelist.json"

@dataclass
class WhitelistEntry:
    path: str
    sha256: str          # 文件内容指纹，与签名完全绑定
    scope: list          # 只放行这些功能（软件的部分功能）
    reason: str = ""     # 记下"为什么放行"，对齐 json 里的字段


def file_sha256(path: str) -> str:
    """对文件内容算 SHA-256。逐块读，避免一次吞进内存。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_whitelist() -> list:
    """从 whitelist.json 读取白名单条目。"""
    if not WHITELIST_FILE.exists():
        return []
    try:
        data = json.loads(WHITELIST_FILE.read_text(encoding="utf-8"))
        return [WhitelistEntry(**e) for e in data.get("entries", [])]
    except Exception:
        return []   # 读不到白名单 -> 当作没有，宁可多报也不放过


def is_whitelisted(path: str, wl: list, scope: str) -> bool:
    """排查前的白名单判定：路径对 + 签名对 + 该功能被放行，三者都过才算豁免。"""
    for e in wl:
        if e.path.lower() == path.lower():
            try:
                if file_sha256(path) == e.sha256 and scope in e.scope:
                    return True
            except Exception:
                return False   # 连文件都读不到/算不动 -> 绝不豁免
    return False
    

# ---------------------------------------------------------------
# 第 6 步 主流程：调用探针 -> 组装档案 -> 打印结论
# ---------------------------------------------------------------
def main():
    active, unknown = check_antivirus()
    snap = EnvSnapshot(
        is_admin=check_admin(),
        suspicious_paths=check_suspicious_paths(),
        antivirus_unknown=unknown,
        antivirus_active=active,
    )
    trust = score(snap)

    print("=" * 52)
    print("本机环境档案 EnvSnapshot")
    print("=" * 52)
    print(f"  管理员权限运行      : {snap.is_admin}")
    print(f"  病毒驻留地进程       : {len(snap.suspicious_paths)} 条")
    for p in snap.suspicious_paths[:5]:
        print(f"      - {p}")
    print(f"  杀软已启动          : {snap.antivirus_active}")
    print(f"  杀软状态未知        : {snap.antivirus_unknown}")
    print("-" * 52)
    print(f"  环境信任等级(severity): {trust}")
    print("=" * 52)


if __name__ == "__main__":
    main()