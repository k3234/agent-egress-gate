# -*- coding: utf-8 -*-
"""L13 第三区凭证门（实体化）：主口令派生，每区独立密钥，双值配对才放跨区。

用户方案实体化（记 1 个主口令，机制不减）：
  - 每个沙箱区有独立密钥 + 关联区 ID；两个值只在自己区互相对应。
  - 跨区请求必须证明"我是某区可信成员" -> 给出 (区ID, 该区密钥)，两值配对才放行。
  - 凭证由人工侧保存：主口令只从环境变量读，绝不进代码/仓库/沙盒。
  - 记忆减负：只记 1 个主口令，各区密钥由它 + 区ID 确定性派生；
    派生单向 -> A 区密钥泄漏反推不出主口令，其他区不受影响（区隔离仍在）。
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Tuple

PBKDF2_ITERS = 100_000
KEY_BYTES = 32
ENV_MASTER = "L13_ZONE_MASTER"          # 主口令只放环境变量（红线：不进代码/仓库）


def derive_zone_key(master: str, zone_id: str) -> bytes:
    """由主口令 + 区ID 确定性派生该区密钥（PBKDF2-HMAC-SHA256）。

    同一主口令 + 同一区ID 永远派生出同一密钥（可复核对）；
    区ID 不同则密钥不同（区隔离）；派生单向，无法反推主口令。
    """
    if not isinstance(master, str) or not master:
        raise ValueError("主口令不能为空")
    salt = f"zone:{zone_id}".encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", master.encode("utf-8"),
                               salt, PBKDF2_ITERS, KEY_BYTES)


def load_master() -> str:
    """从环境变量取主口令。缺失即抛错（fail-closed：无主口令不静默运行）。"""
    m = os.environ.get(ENV_MASTER, "")
    if not m:
        raise RuntimeError(f"缺环境变量 {ENV_MASTER}（fail-closed：无主口令拒绝运行）")
    return m


def zone_cred_ok(claimed_id: str, claimed_key: bytes, master: str) -> Tuple[bool, str]:
    """验证 (区ID, 密钥) 是否相互正确对应。

    用声称的区ID 由主口令派生出"该区应有的密钥"，再与请求给的密钥做常数时间比较；
    两值必须同属一区才放行，否则拒绝。常数时间比较阻止时序侧信道探测密钥。
    """
    if not isinstance(claimed_id, str) or not claimed_id:
        return False, "区ID缺失"
    if not isinstance(claimed_key, bytes) or len(claimed_key) != KEY_BYTES:
        return False, "密钥长度不符"
    expected = derive_zone_key(master, claimed_id)
    if not hmac.compare_digest(expected, claimed_key):
        return False, "区ID与密钥不对应（需相互配对）"
    return True, "凭证配对通过，允许跨区"