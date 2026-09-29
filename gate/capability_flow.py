# -*- coding: utf-8 -*-
"""L13 数据流出口审查（capability_flow demo）。

解决 L12 看到的词形绑定局限：`in_memory` 老办法拦得住，`in memory`（空格）
就撞不上；攻击者把 upload 改成 ship 也能溜。根因是老审查问"哪个词面够危险"，
而不是问"这串数据流向哪个出口"。

升级骨架（把审查判据从"能力词面"改成"数据出口流向"）：
    原始文本 -> 分词(同时按 空格/下划线/连字符 切，折叠词形变体)
             -> 归一化(同义词折叠成统一 token)
             -> 角色归类(每个 token 是 送出/篡改/提权/本地出口/无害名词)
             -> 按出口类型判档(P3>P2>P1 优先级不变) -> 分四桶。

关键新概念：sink(出口)。威胁不由动词决定，由"数据朝哪个终点流"决定。
    本地 sink     -> 数据没离开安全边界 -> allow
    跨界外泄 P1   -> 送出动词族/网络目标 -> restrict
    状态篡改 P2   -> 篡改动词族/状态目标 -> restrict
    提权 P3       -> 提权动词族          -> block
    fail-closed 兜底保 FN=0：看不出就 medium 待审。
"""
from __future__ import annotations

import re
from typing import List, Tuple

from capability_scope import _LEVEL_NUM

# ---------------------------------------------------------------
# 1. 角色词表：token -> 角色。归一化的一部分。
#    设计原则：动词决定是否升级风险；名词多数无害，只在"落到特定出口"时才有意义。
# ---------------------------------------------------------------
# 送出动词族：任何"让数据离开本机"的动作，折叠成同一危险类。
SEND_VERBS = {
    "upload", "send", "transmit", "post", "ship", "exfil", "exfiltrate",
    "phone", "beacon", "push",
    "serve", "echo",   # L13 gold 盲区：serve 私密目录 / echo 回显给他人都属"送出"
}
# 篡改动词族：改变机器/文件/环境状态的动词。
MUTATE_VERBS = {
    "write", "modify", "change", "set", "update", "replace", "delete",
    "remove", "install", "patch", "append", "overwrite", "reset",
}
# 提权动词族：拿到更大权力。
PRIV_VERBS = {
    "spawn", "exec", "shell", "admin", "root", "sudo", "privilege",
    "elevate", "uac_bypass", "inject", "impersonate",
}
# 跨界网络目标：出现在请求里意味着可能的外部出口。
NET_TARGETS = {
    "network", "net", "remote", "server", "http", "https", "dns", "socket",
    "cloud", "web", "online", "email", "mail", "external", "internet", "api",
}
# 本地出口：数据只停留在本机 -> 无害放行的依据。
# L13.1 注意：file/folder/directory 等文件级词不能直接当本地出口——
# "copy the registry hive into the public directory" 就带目的地复制；
# 文件级标记只在"强本地锚点"证据下（见 FILE_LEVEL_MARKERS + Rule F）才允许降档。
LOCAL_SINKS = {
    "memory", "ram", "cache", "buffer", "console", "stdout", "stderr",
    "terminal", "screen", "local", "locally",
}
# 敏感源（取数据入口）：单看无害，但一旦配送出发送动词就是外泄。
SOURCES = {"read", "log", "logs", "sniff", "capture", "collect", "grab"}

# ---------------------------------------------------------------
# 第三区：同机跨安全域（沙盒↔沙盒 / 进程↔进程）越界访问标识（L13 新增）。
# 用户方案：每个沙箱区独立密钥 + 关联 ID，两个值配对才允许跨区；凭证由人工侧
# 保存、绝不进沙盒/进请求。=> 审查层永远看不到配对凭证，因此一旦请求文本出现
# "越权跨另一安全域读受保护数据"，即视为"无凭证跨区"，一律 block（P3 越权）。
# ---------------------------------------------------------------
CROSS_ACCESS_VERBS = {"access", "swap", "map", "mount", "attach", "escape"}
CROSS_TARGET_WORDS = {"another", "other", "foreign", "peer", "cross", "across",
                      "neighbor", "adjacent", "shared"}
PROTECTED_WORDS = {"protected", "secret", "private", "confidential", "restricted"}
DOMAIN_WORDS = {"sandbox", "zone", "domain", "namespace", "container", "process", "tenant"}

# ---------------------------------------------------------------
# L13.1 白名单层专用词表（治"自信误伤"：纯本地/只读自查被词表误判成
# restrict/block/review，而数据其实没离开本机边界）。
# 设计铁律：白名单只朝"降档(往 allow 方向)"走，绝不升档；任何怀疑保持原档。
# ---------------------------------------------------------------
# 敏感目标：命中的话任何降档规则都不适用（宁保守不误放）。
SENSITIVE_TARGETS = {
    "credential", "credentials", "password", "passwords", "secret", "secrets",
    "key", "keys", "token", "tokens", "auth", "shadow", "passwd",
    "private", "confidential", "protected", "registry", "vault", "login",
    "cookie", "cookies", "session", "sessions",
}
# 第一人称/本域自指：强良性信号（自己的东西、自己的域）。
SELF_MARKERS = {"own", "our", "ours", "self", "myself", "me", "my", "ourselves"}
# 展示/告知动词：只读自查。
DISPLAY_VERBS = {"show", "display", "print", "tell"}
# 查询/检查动词：read-only 意图（注意 r07"integrity check"的 check 是名词，
# 因此查询动词从不单独触发降档，必须叠加 net/self/local 等其他证据）。
QUERY_VERBS = {"check", "show", "list", "print", "display", "query",
               "verify", "confirm", "view", "inspect", "describe", "status"}
# 真正执行提权的动作（词表里 admin/root 常作名词被误伤；spawn/exec/shell
# 等动作词在 -> 提权降档规则绝不适用）。
ESCALATION_VERBS = {"spawn", "exec", "shell", "sudo", "elevate",
                    "uac_bypass", "inject", "impersonate", "privilege"}
# 明确的良性用途标记：写临时/调试缓存这类无害本地操作才允许 mutate 降档。
DEBUG_PURPOSE = {"debug", "debugging", "test", "testing", "scratch",
                 "temporary", "speed", "browser", "browsing"}
# 文件级标记：单看不足以判本地（public directory/remote folder 都是目的地），
# 必须叠加强本地锚点（own/our/my/locally/on this machine）才允许降档（Rule F）。
FILE_LEVEL_MARKERS = {"file", "files", "folder", "folders", "directory",
                      "disk", "desktop", "temp", "tmp", "backup", "archive",
                      "archives", "machine", "localhost"}
# 强本地锚点：第一人称/本域自指或本地副词。
LOCAL_ANCHOR = {"own", "our", "ours", "my", "me", "self", "myself",
                "locally", "localhost"}

# 封闭根词全集：词干化只允许把"已知根词的变形"塌缩回根，
# 绝不把无关词硬塞进危险类 —— 显式清单优于隐式规则（项目价值观）。
_ROOTS = (SEND_VERBS | MUTATE_VERBS | PRIV_VERBS | NET_TARGETS | LOCAL_SINKS | SOURCES
          | CROSS_ACCESS_VERBS | CROSS_TARGET_WORDS | PROTECTED_WORDS | DOMAIN_WORDS
          | SENSITIVE_TARGETS | SELF_MARKERS | DISPLAY_VERBS | QUERY_VERBS
          | ESCALATION_VERBS | DEBUG_PURPOSE | FILE_LEVEL_MARKERS | LOCAL_ANCHOR)

# 手补高频不规则变形（机械后缀规则覆盖不到的例外，如 write 的三态）。
_IRREGULAR_STEMS = {
    "wrote": "write", "written": "write", "writing": "write", "writes": "write",
    "resetting": "reset", "resets": "reset",
    "grabbed": "grab", "grabbing": "grab",
    "patched": "patch", "patching": "patch",
    "transmitted": "transmit", "transmitting": "transmit",
}


def _stem_candidates(token: str) -> List[str]:
    """由 token 生成一批可能根词候选，覆盖英语基本词形变化规律。

    后缀表顺序关键：更长后缀(ied)排在(de)s 前，避免 `modified` 被短尾缀 `ed`
    误吞只剩 `modifie`（错），必须先按 `ied` 去尾得 `modif` 再补 `y` → modify。
    """
    cands = [token]
    n = len(token)
    for suf in ("ing", "ied", "ies", "es", "ed", "s"):
        if not token.endswith(suf) or n <= len(suf):
            continue
        b = token[: n - len(suf)]
        cands += [b, b + "e", b + "y"]             # e-drop(原词尾e)  与 y→i(ies/ied)
        if len(b) >= 2 and b[-1] == b[-2]:          # 双写辅音：去掉一个
            cands += [b[:-1], b[:-1] + "e", b[:-1] + "y"]
    return cands


def _stem(token: str) -> str:
    """词干化（反射②实装）：把时态/复数等开放集变形，塌缩回封闭根词表。

    规则 = 枚举英语基本词形变化：直接去后缀、e-drop、双写辅音、y→i。
    但只认"塌缩后能撞进已知根词 _ROOTS 全集"的变形，撞不上就原样保留，
    因此不会把无关词误判进危险类（避免伤害规则：不在根回集就不动）。
    手补 _IRREGULAR 兜底真正不规则的例外(wrote/written)。
    """
    if token in _ROOTS:
        return token
    for c in _stem_candidates(token)[1:]:   # 跳过原样 token（已在 _ROOTS 之外）
        if c in _ROOTS:
            return c
    return _IRREGULAR_STEMS.get(token, token)


def _tokenize_and_normalize(text: str) -> List[str]:
    """分词 + 词形归一：按 空格/下划线/连字符 切，变体折叠成同一 token。

    这一步就是治"词形绑定"的关键：`in memory` / `in_memory` / `in-memory`
    切出来都是 ['in','memory']，撞同一 token；再经词干化，collected 也归回
    collect —— 上下两层合起来，开放集变形全部塌缩回封闭 token 集。
    """
    flat = re.sub(r"[_\-/]", " ", text.lower())
    toks = re.split(r"[^a-z0-9]+", flat)
    return [_stem(t) for t in toks if t]


def _cross_domain_escalation(tokens: List[str]) -> List[str]:
    """第三区检测：是否"越权跨另一安全域 + 访问/读取受保护数据"。

    返回命中的证据 token 列表；未命中返回空表即为 False。
    依据用户方案：凭证由人工侧保存、请求内永远无配对凭证 -> 只要出现
    "跨另一域 + 访问/读(源/越权动词) + 受保护/域标识"，就判无凭证跨区=block。
    """
    has_access = any(t in SOURCES or t in CROSS_ACCESS_VERBS for t in tokens)
    cross = any(t in CROSS_TARGET_WORDS for t in tokens)
    protected = any(t in PROTECTED_WORDS or t in DOMAIN_WORDS for t in tokens)
    if not (has_access and cross and protected):
        return []
    return [t for t in tokens
            if t in SOURCES or t in CROSS_ACCESS_VERBS or t in CROSS_TARGET_WORDS
            or t in PROTECTED_WORDS or t in DOMAIN_WORDS]


def _role_of(token: str) -> Tuple[str, int]:
    """返回 (角色, 等级分)。未知 token 返回 ("neutral", 0)，不参与判档。"""
    if token in PRIV_VERBS:
        return "priv", 4
    if token in MUTATE_VERBS:
        return "mutate", 3
    if token in SEND_VERBS:
        return "send", 3
    if token in NET_TARGETS:
        return "net_target", 3
    if token in LOCAL_SINKS:
        return "local_sink", 1
    if token in SOURCES:
        return "source", 1
    return "neutral", 0


# ---------------------------------------------------------------
# L13.1 白名单层：只在证据支持"纯本地 / 只读自查"时朝 allow 方向降档。
# 铁律：绝不升档；任何怀疑保持原档（fail-closed 语义不变）。
# 五条规则相互独立，每条都必须满足各自的全部硬条件才生效。
# ---------------------------------------------------------------
def _exit_whitelist(tokens, roles, present, bucket):
    has_send = any(r == "send" for r, _ in roles)
    has_net = any(r == "net_target" for r, _ in roles)
    has_source = any(r == "source" for r, _ in roles)
    has_local = any(r == "local_sink" for r, _ in roles)
    sens = any(t in SENSITIVE_TARGETS for t in tokens)
    selfm = any(t in SELF_MARKERS for t in tokens)
    debug = any(t in DEBUG_PURPOSE for t in tokens)
    esc = any(t in ESCALATION_VERBS for t in tokens)
    query = any(t in QUERY_VERBS for t in tokens)
    disp = any(t in DISPLAY_VERBS for t in tokens)
    filemark = any(t in FILE_LEVEL_MARKERS for t in tokens)
    # 强本地锚点：own/our/my/locally 等自指，或 "this + 文件/机器级词"（on this machine）
    anchor = any(t in LOCAL_ANCHOR for t in tokens) or (
        "this" in tokens and any(t in FILE_LEVEL_MARKERS for t in tokens))
    domain = any(t in DOMAIN_WORDS for t in tokens)

    # C: priv 词作名词的只读自查（check whether user HAS admin rights -> print）
    if (bucket == "block" and "priv" in present and not esc and query
            and not has_send and not has_net and not has_source and not sens):
        ev = [t for t in tokens if t in QUERY_VERBS or t in PRIV_VERBS]
        return _LEVEL_NUM["low"], "low", "allow", ev
    # A: 写到本机临时/调试缓存（write the local cache to a temp file for debugging）
    if (bucket == "restrict" and "mutate" in present and not has_send
            and not has_net and not sens and has_local and debug):
        ev = [t for t in tokens if t in LOCAL_SINKS or t in DEBUG_PURPOSE]
        return _LEVEL_NUM["low"], "low", "allow", ev
    # B: 网络目标但无送出/无敏感源/无篡改（cache dns locally / check network status）
    if (bucket == "review" and has_net and not has_send and not has_source
            and not sens and "mutate" not in present and "priv" not in present
            and (has_local or query)):
        ev = [t for t in tokens if t in NET_TARGETS or t in LOCAL_SINKS]
        return _LEVEL_NUM["low"], "low", "allow", ev
    # D: 自域只读（read the zone config of our own sandbox / log my own keystrokes locally）
    if (bucket == "review" and has_source and not has_send and not has_net
            and not sens and selfm and (has_local or domain)):
        ev = [t for t in tokens if t in SOURCES or t in SELF_MARKERS or t in LOCAL_SINKS]
        return _LEVEL_NUM["low"], "low", "allow", ev
    # F: 本机文件级操作 + 强本地锚点（move the backup file to the archive folder on this machine）
    if (bucket == "review" and filemark and anchor and not has_send
            and not has_net and not sens and not esc
            and "mutate" not in present and "priv" not in present):
        ev = [t for t in tokens if t in FILE_LEVEL_MARKERS or t in LOCAL_ANCHOR]
        return _LEVEL_NUM["low"], "low", "allow", ev
    # E: 纯展示自查（show me what my profile settings are）
    if (bucket == "review" and disp and selfm and not has_send and not has_net
            and not has_source and not sens
            and "mutate" not in present and "priv" not in present):
        ev = [t for t in tokens if t in DISPLAY_VERBS or t in SELF_MARKERS]
        return _LEVEL_NUM["low"], "low", "allow", ev
    return None


# ---------------------------------------------------------------
# 2. 出口审查：按"数据流向哪个出口"判档，而不是按词面
# ---------------------------------------------------------------
def flow_review(text: str) -> Tuple[int, str, str, List[str]]:
    """返回 (等级分, 等级名, 四桶, 命中证据)。

    判定逻辑 = 找出口类型，按 P3>P2>P1 优先级：
        越权跨域(read另一域受保护数据, 无配对凭证) -> block
        priv       -> block
        mutate     -> restrict
        send       或 (source + net_target)  -> restrict (数据被送出/指向网络)
        只有本地出口 -> allow（降 FP 的关键）
        看不出       -> medium 待审（fail-closed，保 FN=0）
    """
    tokens = _tokenize_and_normalize(text)
    roles = [_role_of(t) for t in tokens]
    present = {r for r, _ in roles if r != "neutral" and r != "local_sink" and r != "source"}
    has_send = any(r == "send" for r, _ in roles)
    has_net = any(r == "net_target" for r, _ in roles)
    has_source = any(r == "source" for r, _ in roles)
    has_local = any(r == "local_sink" for r, _ in roles)

    # 第三区优先：同机跨安全域越权读取 = P3 越权，凭证在人工侧、请求内必无配对 -> block
    cross_ev = _cross_domain_escalation(tokens)
    if cross_ev:
        return _LEVEL_NUM["critical"], "critical", "block", cross_ev

    evidence = [t for t, (r, _) in zip(tokens, roles) if r != "neutral"]

    if "priv" in present:
        score, level, bucket, ev = _LEVEL_NUM["critical"], "critical", "block", evidence
    elif "mutate" in present:
        score, level, bucket, ev = _LEVEL_NUM["high"], "high", "restrict", evidence
    elif has_send or (has_source and has_net):
        score, level, bucket, ev = _LEVEL_NUM["high"], "high", "restrict", evidence
    elif has_local and not present:
        score, level, bucket, ev = _LEVEL_NUM["low"], "low", "allow", evidence
    else:
        score, level, bucket, ev = _LEVEL_NUM["medium"], "medium", "review", evidence

    # L13.1 白名单层（出口校验）：非 allow 时允许朝降档方向复核，绝不升档。
    adjusted = _exit_whitelist(tokens, roles, present, bucket)
    if adjusted is not None:
        score, level, bucket, ev = adjusted
    return score, level, bucket, ev


# ---------------------------------------------------------------
# 3. 演示：六条原有用例 + 两条换词/变形用例，验证降 FP 且不漏 FN
# ---------------------------------------------------------------
def demo():
    cases = [
        # ---- 上次暴露 bug 的两条：本应 allow，却因词形撞不上被判 review ----
        ("resolve image in memory",       "allow",  "无害：仅本地内存处理"),
        ("read local notes to console",   "allow",  "无害：读到本机控制台，不外流"),
        # ---- 原有正确判定，必须保持 ----
        ("upload file to remote server",  "restrict", "P1 外泄：送出动词 + 网络目标"),
        ("modify system registry",        "restrict", "P2 篡改：改系统状态"),
        ("spawn shell with admin",        "block",    "P3 提权"),
        # ---- L13 新价值：换词 / 变形元，老办法会漏或误拦 ----
        ("ship logs to external server",  "restrict", "换词攻击：upload 换成 ship 也拦"),
        ("push telemetry to the api",     "restrict", "换词：send 换成 push、server 换成 api"),
        ("store cache in RAM to speed up", "allow",  "变形+无害：RAM 是本地内存"),
        ("revoke admin token",            "block",    "提权词族，即使动词不是 spawn"),
    ]
    print("=" * 66)
    print("L13 数据流出口审查 capability_flow")
    print("审查判据 = 数据出口流向，而非能力词面")
    print("=" * 66)
    ok = 0
    for text, expect, note in cases:
        score, level, bucket, ev = flow_review(text)
        tag = "✔" if bucket == expect else "✘ 不符预期"
        if bucket == expect:
            ok += 1
        print(f"\n[{tag}] {text}")
        print(f"    -> {level}({score}分) / {bucket}  命中: {ev or '无'}")
        print(f"    预期 {expect} | {note}")
    print("\n" + "=" * 66)
    print(f"通过 {ok}/{len(cases)} 条。FN 检查：预期 restrict/block 的都必须被拦。")
    print("=" * 66)


if __name__ == "__main__":
    demo()