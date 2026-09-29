# -*- coding: utf-8 -*-
"""Probe: print AgentDojo banking suite structure (v1.2.2)."""
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.attacks.attack_registry import ATTACKS
suite = get_suite("v1.2.2", "banking")

print("SUITE:", suite.name)
print("\n-- user_tasks --")
for tid, t in suite.user_tasks.items():
    print(f"  [{tid}] class={type(t).__name__}")
    print(f"      PROMPT: {t.PROMPT[:110]}")
print("\n-- injection_tasks --")
for iid, t in suite.injection_tasks.items():
    print(f"  [{iid}] class={type(t).__name__} GOAL: {t.GOAL[:90]}")
print("\n-- functions/tools --")
for fn in suite.tools:
    print(f"  {fn.name}: args={list(fn.parameters.get('properties', {}).keys())}")
print("\n-- attacks --")
for an, cls in ATTACKS.items():
    print(f"  {an}: {cls.__name__}")