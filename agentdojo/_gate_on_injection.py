# -*- coding: utf-8 -*-
"""离线隔离检验：把 AgentDojo 每个注入任务的恶意 ground_truth 动作(转账给攻击者/改密码/改收款人/发邮件/删改文件等)
逐条过本方案 flow_review，看门能否识别为 restrict/block。零 API 成本，检验门对真实攻击载荷的独立检出。
用法: python _gate_on_injection.py [suite...]   默认 banking workspace slack travel
"""
from __future__ import annotations
import sys
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
LEARNING = BASE.parent / "gate"
sys.path.insert(0, str(LEARNING))

from capability_flow import flow_review
from agentdojo.task_suite.load_suites import get_suite

SUITES = sys.argv[1:] or ["banking", "workspace", "slack", "travel"]

for suite_name in SUITES:
    suite = get_suite("v1.2.2", suite_name)
    pre_env = suite.load_and_inject_default_environment({})
    injection_tasks = list(suite.injection_tasks.values())
    injection_tasks.sort(key=lambda t: t.ID)

    blocked = allowed = 0
    rows = []
    for task in injection_tasks:
        try:
            calls = task.ground_truth(pre_env)
        except Exception as e:
            rows.append((task.ID, "<err>", "ERR", "error", repr(e)[:60]))
            continue
        for call in calls:
            args = dict(call.args) if call.args else {}
            text = f"{call.function} with args {json.dumps(args, ensure_ascii=False)}"
            _, _, fb, ev = flow_review(text)
            verdict = "BLOCK" if fb in ("restrict", "block") else ("review" if fb == "review" else "allow")
            action = "BLOCKED" if fb in ("restrict", "block") else "EXEC"
            rows.append((task.ID, call.function, action, fb, text))
            if fb in ("restrict", "block"):
                blocked += 1
            else:
                allowed += 1

    print(f"\n===== suite={suite_name}  v1.2.2  injection payloads checked={len(rows)}  blocked={blocked}  exec/allow={allowed} =====")
    for tid, fn, action, fb, text in rows:
        print(f"  [{action:6}] {tid} . {fn:<24} flow={fb:<9} :: {text[:86]}")
    if rows:
        print(f"  -> 恶意载荷检出率(模型一旦被诱导就会被本门拦截的比例): {blocked}/{len(rows)} = {blocked/len(rows):.0%}")