# -*- coding: utf-8 -*-
"""能力评审闭环（capability_reason demo）。

L7b 只解决了"已知目录内"的能力评估；本课补上另一半：
    目录里没有的新能力进来时怎么办？

解决骨架（迁移 L6 白名单 + L7b 复合评估的思路）：
    未知能力 -> 三原则评审(P1数据外流/P2状态篡改/P3权限提升) ->
    判级(举一反三：把新能力映射到已知风险类别) ->
    分四桶(放行/待审/拦截/阻止) ->
    决策落盘(带 SHA-256 签名) ->
    每次读取先验签，哈希不符 -> fail-closed 全体拒绝。

防线思想：评审范式(骨架)可训练进模型、具体目录条目放配置(带签名)、
核心规则写死代码 —— 三条知识存放地的抗篡改梯度逐级变强。
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

# 复用 L7b 的能力目录与档位，保证整条学习链一致
from capability_scope import CAPABILITIES, LEVEL_ACTION, _LEVEL_NUM

# ---------------------------------------------------------------
# 1. 三原则评审范式：把"未知能力"映射到"已知风险类别"
#    这就是给模型的提示词骨架，代码里落成可执行的映射表
# ---------------------------------------------------------------
P1 = "P1"  # 数据外流：读 -> 传出
P2 = "P2"  # 状态篡改：改文件 / 改环境
P3 = "P3"  # 权限提升：越过作用域 / 提权

# 关键词 -> 命中的原则（命中任一条 -> 直接判高危/致命，不往下猜）
PRINCIPLE_KEYWORDS: dict[str, Tuple[str, list]] = {
    P1: ("high", ["net", "network", "upload", "send", "transmit", "http", "dns",
                  "email", "socket", "camera", "microphone", "clipboard_read",
                  "usb_read", "screenshot"]),          # 读到手 -> 传出去
    P2: ("high", ["write", "modify", "delete", "replace", "patch", "install",
                  "update", "registry_write", "env_set", "config_write",
                  "usb_write", "format_disk", "format_volume", "wipe_partition",
                  "reformat_partition"]),               # 改变机器状态
    P3: ("critical", ["admin", "root", "privilege", "elevate", "sudo",
                      "uac_bypass", "exec", "shell", "spawn", "inject",
                      "impersonate"]),                  # 拿到更大权力
}

# 四桶：与 L7b 的整体档位一一对应
BUCKET = {"low": "allow", "medium": "review", "high": "restrict", "critical": "block"}

# 无害白名单短语（迁移 L6 白名单骨架）：只对"绝不外流"的纯本地操作放行，
# 降低 FP（g006/g007 这类无害操作不再被兜底抬进 review）。命中即可 low/allow，
# 但绝不包含任何外流/篡改/提权语义 —— 否则攻击者可塞词伪装绕过。
HARMLESS_LOCAL_PHRASES = [
    "in_memory", "memory_only", "to_console", "print_to_console",
    "local_image", "resize_image", "local_notes", "read_local",
]


# ---------------------------------------------------------------
# 2. 三原则评审器：短名单(shortlist) —— 已知能力直接查目录，
#    未知能力按三原则举一反三，绝不自由猜测
# ---------------------------------------------------------------
def shortlist(capability: str) -> Tuple[int, str, str, List[str]]:
    """返回 (等级分, 等级名, 四桶, 命中原则列表)。

    优先级: P3 > P2 > P1（先问"能拿到多大权力"，再问"会不会改状态"，
    最后问"数据会不会出去"）；三条全稳 -> low 放行。
    """
    # 已知能力：用预定义等级（可迁移：白名单已知条目直接放行）
    if capability in CAPABILITIES:
        score, level = CAPABILITIES[capability]
        return score, level, BUCKET[level], []

    # 未知能力：按三原则关键词评审（关键词只是"提示词"的执行版本）
    hit_principles = []
    level = None
    for principle in (P3, P2, P1):                      # 严格按优先级顺序查
        if any(k in capability.lower() for k in PRINCIPLE_KEYWORDS[principle][1]):
            hit_principles.append(principle)
            if level is None:
                level = PRINCIPLE_KEYWORDS[principle][0]  # 第一命中决定等级
    if level is None:
        # 三原则全不命中：先查无害白名单，命中且不涉任何外流 -> 直接放行，
        # 降 FP；否则 fail-unknown 仍 medium 待审兜底（宁取 FP、不取 FN）。
        cap_l = capability.lower()
        if any(p in cap_l for p in HARMLESS_LOCAL_PHRASES):
            # 双保险：无害词命中时若又混有危险特征，则不信无害，仍走兜底
            DANGEROUS = [k for pri in PRINCIPLE_KEYWORDS for k in PRINCIPLE_KEYWORDS[pri][1]]
            if not any(k in cap_l for k in DANGEROUS):
                return _LEVEL_NUM["low"], "low", BUCKET["low"], []
        # fail-unknown 兜底：不猜等级，一律 medium 待审起步（保 FN=0）
        return _LEVEL_NUM["medium"], "medium", BUCKET["medium"], []

    score = _LEVEL_NUM[level]
    return score, level, BUCKET[level], hit_principles


# ---------------------------------------------------------------
# 3. 决策落盘 + 验签兜底：决策文件被入侵者改掉 -> 全体拒绝
#    签名算法：对"去掉 _signature 字段后的规范化 JSON"做 SHA-256
# ---------------------------------------------------------------
def _payload_of(data: dict) -> str:
    """取不含签名的正文，排序后规范化序列化 —— 保证读写的 payload 完全一致。"""
    body = {k: v for k, v in data.items() if k != "_signature"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True)


def _sign(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sign_decision(decision_file: Path) -> bool:
    """对已落盘的决策文件补写/刷新签名，返回是否成功。"""
    try:
        data = json.loads(decision_file.read_text(encoding="utf-8"))
        data["_signature"] = _sign(_payload_of(data))
        decision_file.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def deny_if_modified(decision_file: Path, first_run: bool = False) -> bool:
    """验签决策文件。任何异常 -> True(拒绝)。fail-closed：拿不准就关门。

    first_run: 本次调用前信任根(anchor)还不存在，说明决策文件缺失是
    "首次使用"而非"被入侵者删除"，此时放行初始化；其余缺失一律拒绝。
    """
    if not decision_file.exists():
        return not first_run                         # 非首次却缺失 -> 被删 -> 拒绝
    try:
        data = json.loads(decision_file.read_text(encoding="utf-8"))
        if "_signature" not in data:
            return True                              # 没签名 -> 拒绝
        stored = data["_signature"]
        current = _sign(_payload_of(data))           # 现场重算正文哈希
        return stored != current                     # 哈希不符 -> 被改过 -> 拒绝
    except Exception:
        return True                                  # 读/解析出错 -> 拒绝


def _init_anchor(anchor: Path) -> bool:
    """建立信任根：anchor 文件在 = 本目录曾初始化过。返回是否首次使用。"""
    first_run = not anchor.exists()
    if first_run:
        anchor.touch()
    return first_run


# ---------------------------------------------------------------
# 4. 完整评审闭环：验签旧决策 -> 三原则评级 -> 分四桶 -> 落盘签名
# ---------------------------------------------------------------
def review_capability(capability: str, decision_file: Path, anchor: Path) -> dict:
    """新能力走一次完整评审，返回最终门禁决策。

    fail-closed 优先级最高：旧决策文件被篡改/被删 -> 直接 block，
    连新能力的评审都不必进行（环境已不可信）。
    """
    first_run = _init_anchor(anchor)
    if deny_if_modified(decision_file, first_run=first_run):
        return {
            "capability": capability, "verdict": "block",
            "bucket": "block", "reason": "决策文件被篡改/删除 -> fail-closed",
            "hit_principles": [], "recorded": False,
        }

    score, level, bucket, hit = shortlist(capability)

    # 决策落盘：记录本次评审结论（等级、四桶、命中原则、理由）
    record = {
        "capability": capability,
        "level": level,
        "score": score,
        "bucket": bucket,
        "hit_principles": hit,
        "reviewed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    data = {}
    if decision_file.exists():
        data = json.loads(decision_file.read_text(encoding="utf-8"))
        data.pop("_signature", None)
    data[capability] = record
    decision_file.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    signed = sign_decision(decision_file)

    # 落盘后立即自验签一次（证据优先：写入即验证）
    tampered = deny_if_modified(decision_file)
    return {
        "capability": capability,
        "verdict": bucket,                            # 门禁动作与四桶同名
        "bucket": bucket,
        "level": level,
        "score": score,
        "hit_principles": hit,
        "reason": _bucket_reason(bucket, hit),
        "recorded": signed and not tampered,
    }


def _bucket_reason(bucket: str, hit: List[str]) -> str:
    if bucket == "allow":
        return "三原则全稳 -> 放行"
    if bucket == "review":
        return "三原则未命中 -> 不猜等级，待审"
    if bucket == "restrict":
        return f"命中 {','.join(hit) if hit else '高风险词'} -> 拦截/限权"
    return "致命风险 -> 阻止"


# ---------------------------------------------------------------
# 5. 演示：三个新能力 + 一个篡改现场
# ---------------------------------------------------------------
def demo():
    decision_file = Path(__file__).parent / "capability_decisions.json"
    anchor = Path(__file__).parent / ".cap_review_anchor"
    # 现场重置：保证每次演示都从"首次使用"开始，可重复运行
    for f in (anchor, decision_file):
        if f.exists():
            f.unlink()
    print("=" * 62)
    print("能力评审闭环 capability_reason")
    print(f"已知目录: { {k: v[1] for k, v in CAPABILITIES.items()} }")
    print("三原则: P1数据外流 / P2状态篡改 / P3权限提升")
    print("=" * 62)

    for cap in ["camera", "registry_write", "usb_read"]:
        r = review_capability(cap, decision_file, anchor)
        print(f"\n▶ 新能力 '{cap}'")
        print(f"   命中原则: {r['hit_principles'] or '无'}")
        print(f"   等级: {r['level']}({r['score']}分) | 四桶: {r['bucket']}")
        print(f"   门禁: {r['verdict']} | 理由: {r['reason']}")
        print(f"   落盘+验签: {'成功' if r['recorded'] else '失败'}")

    print("\n-- 入侵者篡改决策文件 -> fail-closed 演示 --")
    print(f"   篡改前 deny_if_modified = {deny_if_modified(decision_file)}")
    data = json.loads(decision_file.read_text(encoding="utf-8"))
    data.pop("_signature", None)                      # 假装入侵者只删了签名
    decision_file.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"   删掉签名后 deny_if_modified = {deny_if_modified(decision_file)}")
    r = review_capability("camera", decision_file, anchor)
    print(f"   此时再评审 camera -> {r['verdict']} ({r['reason']})")

    print("\n-- 入侵者删除整个决策文件 -> 同样 fail-closed --")
    decision_file.unlink()
    print(f"   删除文件后 deny_if_modified = {deny_if_modified(decision_file)}")
    r = review_capability("camera", decision_file, anchor)
    print(f"   此时再评审 camera -> {r['verdict']} ({r['reason']})")

    print("\n-- 恢复现场：必须管理员介入重建信任根 --")
    print("   (决策文件被删后程序不会自动恢复，这正是 fail-closed 的意义)")
    anchor.unlink()                                   # 管理员重置信任根
    for cap in ["camera", "registry_write", "usb_read"]:
        review_capability(cap, decision_file, anchor)
    print(f"   管理员重建后 deny_if_modified = {deny_if_modified(decision_file)}")
    print(f"   决策文件: {decision_file}  信任根: {anchor}")
    print("=" * 62)


if __name__ == "__main__":
    demo()
