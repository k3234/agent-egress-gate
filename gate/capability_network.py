# -*- coding: utf-8 -*-
"""企业多 Agent 安全审查 + 自学习闭环（capability_network demo）。

L12 把 L10/L11 的"单个能力串审查"升维到"企业多 Agent 决策体系"：

  静态两层(能力白名单 + Agent连接白名单) -> 强度分档(S1/S2/S3 按severity升档)
  -> 执行中抽查(高危密/低危疏) -> 审查后自学习：
      新经验先进隔离候选区(tentative, 不影响正式审查)
      -> 重复复现N次提升置信 -> 升为"待人工审"
      -> 人工批准 -> 才落入正式词表(带签名)
      未被人工批准 -> 永不自动进正式词表

哲学：机器提议、人工批准；短期/单次/可疑经验永远进不了正式审查，除非人点头。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Tuple

_LEVEL_NUM = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_ACTION = {"low": "allow", "medium": "review", "high": "restrict", "critical": "block"}
# 按 severity 升档：severity -> 审查强度层
_STRENGTH = {"low": "S1", "medium": "S2", "high": "S3", "critical": "S3"}


# ---------------------------------------------------------------
# 1. 知识库(正式词表 + 隔离候选区)：人机闭环的存储层
# ---------------------------------------------------------------
@dataclass
class Knowledge:
    """每个 Agent 的自学习知识。隔离候选区与正式词表物理分开。"""
    manifest: dict = field(default_factory=dict)      # 正式词表: 短语 -> (等级, 签名)
    tentative: dict = field(default_factory=dict)     # 隔离候选区: 短语 -> 出现次数

    PROMOTE_THRESHOLD = 3      # 复现多少次才允许升为"待人工审"
    HASH = "sha256-placeholder"  # 占位：真实项目在此对 manifest 加签名防篡改

    # --- 正式词表只读查询 ---
    def lookup(self, phrase: str):
        """正式词表命中才返回等级；隔离候选区绝不影响正式审查。"""
        return self.manifest.get(phrase)

    # --- 自学习写入：(1) 进候选区 ---
    def propose(self, phrase: str):
        """新经验先入隔离候选区，不影响正式审查。"""
        self.tentative[phrase] = self.tentative.get(phrase, 0) + 1
        return self.tentative[phrase]

    # --- 自学习写入：(2) 候选够稳 → 升为待人工审 ---
    def ready_for_review(self, phrase: str) -> bool:
        return self.tentative.get(phrase, 0) >= self.PROMOTE_THRESHOLD

    # --- 自学习写入：(3) 人工批准 → 落正式词表(带签名) ---
    def approve(self, phrase: str, level: str) -> bool:
        if not self.ready_for_review(phrase):
            return False                    # 没到候选门槛, 再稳也不允许
        self.manifest[phrase] = (level, self.HASH)
        return True


# ---------------------------------------------------------------
# 2. Agent：能力白名单 + 连接白名单 + 自学习知识
# ---------------------------------------------------------------
@dataclass
class Agent:
    name: str
    capabilities: set                          # 本 Agent 能做什么
    neighbors: set                             # 能调用谁(Agent 名字)
    knowledge: Knowledge = field(default_factory=Knowledge)

    def can_call(self, target: str) -> bool:
        return target in self.neighbors        # 关2: 跨 Agent 白名单


# ---------------------------------------------------------------
# 3. 审查器：静态两层 + 强度分档 + 执行中抽查
# ---------------------------------------------------------------
@dataclass
class Action:
    agent: str
    cap: str          # 能力关键词
    props: Dict = field(default_factory=dict)  # 可带 severity/call 等


class NetworkReviewer:
    def __init__(self, agents: Dict[str, Agent]):
        self.agents = agents

    def _agent(self, name: str) -> Agent:
        return self.agents[name]

    # 静态第1层：本 Agent 动作在不在能力白名单
    def _in_capabilities(self, action: Action) -> bool:
        return action.cap in self._agent(action.agent).capabilities

    # 静态第2层：跨 Agent 调用是否在连接白名单 + 目标 Agent 是否有该能力
    def _in_neighbors(self, action: Action) -> bool:
        target = action.props.get("call")
        if not target:
            return True                        # 非跨 Agent 动作, 第2层视为通过
        if target not in self.agents:
            return False                       # 目标根本不是已知 Agent -> 保守拦
        if not self._agent(action.agent).can_call(target):
            return False                       # 连都不让连
        # 连得上还要看：目标 Agent 是否具备被请求的能力(否则是"点到对方身上但对方没这权限")
        return action.cap in self._agent(target).capabilities

    # 强度分档: 按 severity 决定审查到哪一层
    def _strength(self, severity: str) -> str:
        return _STRENGTH.get(severity, "S2")

    # 单步审查（核心）：两关 + 强度
    def _step_verdict(self, a: Action, strength: str) -> Tuple[bool, str]:
        if not self._in_capabilities(a):
            return False, "越权: 动作不在该Agent能力白名单"
        if strength == "S3":                    # S3 才查跨 Agent 连接
            if not self._in_neighbors(a):
                return False, "越权: 跨Agent调用不在连接白名单"
        elif strength == "S1":
            return True, "ok"                   # S1 只查能力, 快速放行
        return True, "ok"

    def review_chain(self, actions: List[Action], severity: str = "medium",
                     spot_every: int = 2) -> Dict:
        """返回 每步判定 + 强度档 + 是否中途被拦 + 最终门禁。"""
        strength = self._strength(severity)
        step_spots = int(severity in ("high", "critical"))
        log = []
        blocked_at = None
        spot_interval = 1 if step_spots else spot_every   # 高危: 每步抽查; 低危: 隔几步
        for i, a in enumerate(actions, 1):
            ok, why = self._step_verdict(a, strength)
            log.append({"step": i, "act": f"{a.agent}:{a.cap}", "ok": ok, "why": why,
                        "spot": i % spot_interval == 0})
            if not ok:
                blocked_at = i
                break                               # 静态/抽查一拦即停
        final = "block" if blocked_at else ("restrict" if strength == "S3" else
                 _ACTION.get(severity, "review"))
        return {"strength": strength, "steps": log, "blocked_at": blocked_at,
                "final": final}


# ---------------------------------------------------------------
# 4. 自学习闭环辅助：一把"机器提议-人工批准"的演示
# ---------------------------------------------------------------
def learn_new_phrase(knowledge: Knowledge, phrase: str, level: str,
                     reappear: int = 0, human_approve: bool = True) -> str:
    """演示一条新经验的完整流转：候选 -> 复现 -> 待人工审 -> 人工批准落表。"""
    n = knowledge.propose(phrase)
    if n < 1:
        return f"已入候选区(第{n}次), 隔离中, 不影响正式审查"
    if not knowledge.ready_for_review(phrase):
        return f"候选区(-): {phrase} 已现{n}/{knowledge.PROMOTE_THRESHOLD}次, 未到转正线, 隔离中"
    if not human_approve:
        return f"待人工审(+): {phrase} 已到转正线, 但人工未批准, 仍隔离不落表"
    ok = knowledge.approve(phrase, level)
    return f"人工批准✅: {phrase} 落正式词表 -> {knowledge.lookup(phrase)}" if ok else f"落表被拒"


# ---------------------------------------------------------------
# 5. demo：四条演示
# ---------------------------------------------------------------
def demo():
    # Agent: capability白名单 + neighbor白名单；银行是唯一能执行转账的Agent
    agents = {
        "客服": Agent("客服", {"读台账"}, {"财务"}),
        "财务": Agent("财务", {"转账", "读账本"}, {"银行"}),
        "银行": Agent("银行", {"执行转账"}, set()),
    }
    rv = NetworkReviewer(agents)

    print("=" * 66)
    print("L12 企业多Agent安全审查 + 自学习闭环")
    print("=" * 66)

    # ① 低危链: 客服读自己台账 (S1 快速放行)
    r2 = rv.review_chain([Action("客服", "读台账", {})], severity="low")
    print(f"\n▶ 低危链 客服读台账 -> 强度={r2['strength']} 门禁={r2['final']}")

    # ② 越权链: 客服要读"财务的台账" → 财务无"读台账"能力 → S3 静态拦
    chain2 = [
        Action("客服", "读台账", {}),
        Action("客服", "读台账", {"call": "财务"}),
    ]
    r1 = rv.review_chain(chain2, severity="critical", spot_every=1)
    print("\n▶ 越权链 客服中途去读财务账本(目标方无此能力)")
    for s in r1["steps"]:
        print(f"  步{s['step']} {s['act']:<18} {'OK' if s['ok'] else '✗'}"
              f" {'[抽查点]' if s['spot'] else ''} {s['why'] if not s['ok'] else ''}")
    print(f"  强度={r1['strength']} 拦截点={r1['blocked_at']} 门禁={r1['final']}")

    # ③ 高危链: 客服 -> 财务(跨Agent) -> 转账 → 财务有权限、连银行合法，但整链是提权动作
    chain3 = [
        Action("客服", "读台账", {}),
        Action("客服", "转账", {"call": "财务"}),   # 客服要转账但自己没有转账能力
    ]
    r3 = rv.review_chain(chain3, severity="critical", spot_every=1)
    print("\n▶ 高危链 客服想借财务转账(能力跨Agent冒用)")
    for s in r3["steps"]:
        print(f"  步{s['step']} {s['act']:<18} {'OK' if s['ok'] else '✗'}"
              f" {s['why'] if not s['ok'] else ''}")
    print(f"  强度={r3['strength']} 拦截点={r3['blocked_at']} 门禁={r3['final']}")

    # ④ 自学习: 新短语 put_bytes_to_disk 走 候选->复现->待人工审->批准落表
    print("\n▶ 自学习闭环: put_bytes_to_disk(首次发现, 应为危险写入)")
    k = next(a.knowledge for a in agents.values())
    print(f"  {learn_new_phrase(k, 'put_bytes_to_disk', 'high')}")
    # 人工未批准时即便复现也不能落表
    print(f"  {learn_new_phrase(k, 'put_bytes_to_disk', 'high', human_approve=False)}")
    # 到转正线 + 人工批准 → 落正式词表
    for _ in range(2):
        learn_new_phrase(k, "put_bytes_to_disk", "high")
    print(f"  {learn_new_phrase(k, 'put_bytes_to_disk', 'high')}")
    print(f"  -> 正式词表现含: { {w: v for w, v in k.manifest.items()} }")

    print("=" * 66)


if __name__ == "__main__":
    demo()