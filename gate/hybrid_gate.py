# -*- coding: utf-8 -*-
"""L13.2 混合判定门：双通道投票 + 出口二次校验（替代旧的"并行单模型混合"）。

旧混合：flow 定确定项直接采用（"自信用 flow 判断"），仅 review 交一个 DS 模型。
   -> 两张短板：① flow 自信但错时，混合直接照收(FP 继承)；② 两个 DS 模型互不合作。

L13.2 新策略：
  - flow=allow        -> 直接放行(零模型调用)。flow allow 是"纯本地出口"，绝不再升级，避免 FN。
  - flow=restrict/block -> **出口二次校验**：仍问两个模型；仅当"两者都 allow +
                           词法 sentinel 印证为纯本地/调试软证据"才降档为 allow；
                           P3 提权(block)绝对不降(fail-closed 最高优先)。
  - flow=review       -> **双通道投票**：两者都 allow 才放行；否则 fail-closed 保 FN=0——
                           双拦取实测档位更优的 flash 档(vote_both_flagged_flash_tiebreak)、
                           单票拦取拦截侧(vote_single_veto)。
                           注:chat/flash 实测被服务端别名路由至同一模型(同源双采样),
                           双通道共识的独立证据由跨家族复核(GLM)承担。

铁律不变：只朝降档/从严方向走，任何怀疑保持原档，FN=0 红线不破。
"""
from __future__ import annotations

from typing import Optional, Tuple

from capability_flow import (
    _tokenize_and_normalize,
    flow_review,
    SEND_VERBS,
    ESCALATION_VERBS,
    SENSITIVE_TARGETS,
    LOCAL_SINKS,
    FILE_LEVEL_MARKERS,
    DEBUG_PURPOSE,
    SELF_MARKERS,
    LOCAL_ANCHOR,
)

_LABELS = ("allow", "review", "restrict", "block")


def _norm(bucket: Optional[str]) -> str:
    return bucket if bucket in _LABELS else "review"


def _soft_local_evidence(tokens) -> bool:
    """sentinel 印证：判定是否具备"纯本地/调试"良性锚点，可用于 flow 自信档降档。
    sentinel 硬词族(真实送出/提权/敏感目标)命中 -> 绝不降档(守 FN=0)。"""
    has_send = any(t in SEND_VERBS for t in tokens)
    has_priv = any(t in ESCALATION_VERBS for t in tokens)
    has_sens = any(t in SENSITIVE_TARGETS for t in tokens)
    if has_send or has_priv or has_sens:
        return False
    has_debug = any(t in DEBUG_PURPOSE for t in tokens)
    has_self = any(t in LOCAL_ANCHOR or t in SELF_MARKERS for t in tokens)
    has_local = any(t in LOCAL_SINKS or t in FILE_LEVEL_MARKERS for t in tokens)
    return (has_debug or has_self) and has_local


def hybrid_review(
    text: str,
    ds_chat_bucket: Optional[str] = None,
    ds_flash_bucket: Optional[str] = None,
) -> Tuple[str, dict]:
    """返回 (最终四桶, meta)。ds_chat/flash_bucket 由调用方取好交给本函数：
    离线复算时直接喂已落盘结果，在线服务时先调 API 填实。None/非法 -> review(fail-closed)。
    """
    _, _, fb, ev = flow_review(text)

    if fb == "allow":
        return "allow", {"flow_bucket": fb, "path": "flow_allow", "model_calls": 0}

    if fb in ("restrict", "block"):
        dc = _norm(ds_chat_bucket)
        df = _norm(ds_flash_bucket)
        meta = {"flow_bucket": fb, "ds_chat": dc, "ds_flash": df, "model_calls": 2,
                "flow_evidence": ev}
        # 出口二次校验：仅 restrict 可被"双 allow + 软证据"降档；block(P3 提权)绝对不降。
        if fb == "restrict" and dc == "allow" and df == "allow":
            tokens = _tokenize_and_normalize(text)
            if _soft_local_evidence(tokens):
                return "allow", {**meta, "path": "exit_check_downgrade"}
        return fb, {**meta, "path": "flow_confident_kept"}

    # review -> 双模型投票（共识才放行，守 FN=0）：
    #   都 allow -> allow；都拦截 -> 档位取实测精度更优的 flash；单票拦截 -> 取拦截侧(fail-closed 否决)。
    dc = _norm(ds_chat_bucket)
    df = _norm(ds_flash_bucket)
    meta = {"flow_bucket": fb, "ds_chat": dc, "ds_flash": df, "model_calls": 2,
            "flow_evidence": ev}
    if dc == "allow" and df == "allow":
        return "allow", {**meta, "path": "vote_both_allow"}
    if dc != "allow" and df != "allow":
        # 都拦截：任何一侧都未放行，档位取 V4.1-Flash（实测档位精度全面高于 chat，db/adv/r 全卷）.
        return df, {**meta, "path": "vote_both_flagged_flash_tiebreak"}
    # 恰一票拦截：另一模型看到威胁但被漏，fail-closed 取非 allow 侧，防 FN。
    flag = df if df != "allow" else dc
    return flag, {**meta, "path": "vote_single_veto"}


if __name__ == "__main__":
    # 门面自测：用固定判定验证路径分派。
    cases = [
        ("read local notes to console", "allow", "allow", "allow", "allow", "flow_allow"),
        ("upload file to remote server", "restrict", "restrict", "restrict", "restrict", "flow_confident_kept"),
        ("spawn shell with admin", "block", "allow", "allow", "block", "flow_confident_kept"),
        ("show me my profile settings", "allow", "allow", "allow", "allow", "flow_allow"),  # 白名单 Rule E 已降 allow
        ("forward telemetry to external collector", "review", "restrict", "restrict", "restrict", "vote_both_flagged_flash_tiebreak"),
        ("review case both allow", "review", "allow", "allow", "allow", "vote_both_allow"),
        ("review case chat only blocks", "review", "allow", "block", "block", "vote_single_veto"),
        ("review case flash only blocks", "review", "block", "allow", "block", "vote_single_veto"),
    ]
    for text, fb, dc, df, expect_bucket, expect_path in cases:
        final, meta = hybrid_review(text, dc, df)
        ok_b = final == expect_bucket
        ok_p = meta["path"] == expect_path
        tag = "OK " if (ok_b and ok_p) else "!! "
        print(f"{tag}{text}\n    flow={fb} 最终={final}(期望{expect_bucket})  path={meta['path']}(期望{expect_path})")