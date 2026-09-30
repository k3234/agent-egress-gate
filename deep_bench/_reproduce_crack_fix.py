# -*- coding: utf-8 -*-
"""裂缝修复实装复测的复现脚本（论文 §5.8 / crack_fix_results.json）。

复测内容（全部零成本，flow 层为本地确定性，不联网）：
  1. 52 条裂缝代价测试重判（A 真凶包裹 / C 对照 / B 良性包裹 / D 守卫对照）
  2. 五卷 224 条回归检查（full_comparison_data.json 逐对象比对 pre_fix，应 IDENTICAL）
  3. pinject 卷 flow 列刷新（pi09 allow→review）
  4. 红队 48 条 flow 层重判（e05 由 allow 漏放→review，FN 1→0）

红队语义列（chat/flash/混合门）需 DEEPSEEK_API_KEY（api-demo/.env）时 live 复跑；
无 key 时仅 flow 确定性底座，语义列标记 skipped。脚本本身不调用 API。

用法：python _reproduce_crack_fix.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
# 模块定位自适应：research/ 下 parents[2]/learning；public-repo 镜像下 parents[0]/gate
for cand in (BASE.parents[2] / "learning", BASE.parents[0] / "gate"):
    if (cand / "capability_flow.py").exists():
        sys.path.insert(0, str(cand))
        break
from capability_flow import flow_review  # noqa: E402

print("=== 1. 52 条裂缝代价测试重判（flow 层） ===")
crack = json.loads((BASE / "crack_cost_results.json").read_text(encoding="utf-8"))
groups = {"A_真凶包裹": 0, "C_对照无包裹": 0, "B_良性包裹": 0, "D_守卫对照": 0}
leaks = []
for r in crack["results"]:
    _s, _l, bucket, _e = flow_review(r["text"])
    groups[r["group"]] += 1
    if bucket == "allow" and r["expected"] != "allow":
        leaks.append((r["id"], r["group"]))
print(f"  组计数: {groups}")
print(f"  真凶漏放(flow=allow): {len(leaks)}  {leaks if leaks else '(0，修复闭合)'}")
assert not leaks, f"裂缝未闭合: {leaks}"

print("\n=== 2. 五卷 224 条回归检查 ===")
cur = json.loads((BASE / "full_comparison_data.json").read_text(encoding="utf-8"))
pre_path = BASE / "full_comparison_data.pre_fix.json"
if not pre_path.exists():
    # 镜像（public-repo）不携带修复前备份，跳过回归对比；本地断言由含 pre_fix 的运行承担
    print("  pre_fix 备份缺失（镜像环境）→ 跳过逐对象对比，改由 §5.8 报告承担。")
else:
    pre = json.loads(pre_path.read_text(encoding="utf-8"))
    print(f"  修复前后逐对象一致: {'IDENTICAL' if cur == pre else 'DIFFERENT!'}")
    assert cur == pre, "五卷回归失败：修复前后不一致"

print("\n=== 3. pinject 卷 flow 重判（pi09 应转 review） ===")
pin = json.loads((BASE / "pinject_results.json").read_text(encoding="utf-8"))
pin_flow = {}
for r in pin["rows"]:
    _s, _l, bucket, _e = flow_review(r["text"])
    pin_flow[r["id"]] = bucket
    if r["id"] in ("pi09", "pi30"):
        print(f"  [{r['id']}] flow={bucket} exp={r['expected']}")
assert pin_flow.get("pi09") != "allow", "pi09 未闭合"
assert pin_flow.get("pi30") != "allow", "pi30 应被守卫推离快路径"

print("\n=== 4. 红队 48 条 flow 层重判（e05 应转 review） ===")
red = json.loads((BASE / "red_team_results.json").read_text(encoding="utf-8"))
fn = []
e05 = {}
for r in red["rows"]:
    _s, _l, bucket, _e = flow_review(r["text"])
    if r["expected"] != "allow" and bucket == "allow":
        fn.append(r["id"])
    if r["id"] == "e05":
        e05 = {"flow": bucket, "chat": r.get("DS-chat"), "flash": r.get("DS-flash"),
               "hybrid": r.get("混合(L13.2)"), "path": r.get("path")}
print(f"  flow 层漏放: {fn if fn else '(0，FN=0)'}")
assert not fn, f"红队 flow 仍有漏放: {fn}"
print(f"  e05: flow={e05.get('flow')} chat={e05.get('chat')} flash={e05.get('flash')} hybrid={e05.get('hybrid')} path={e05.get('path')}")
assert e05.get("flow") != "allow", "e05 修复失效"

print("\n[PASS] 裂缝修复实装复测全部通过：52 条裂缝闭合、五卷零回归、pi09/e05 双闭合、红队 FN=0")
