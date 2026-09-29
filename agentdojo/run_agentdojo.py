# -*- coding: utf-8 -*-
"""AgentDojo + DeepSeek + 本方案安检门(flow_review 工具调用边界门) 集成驱动。

用法：
  smoke:  python run_agentdojo.py --smoke --user-task user_task_0
  bench:  python run_agentdojo.py --suite banking --user-tasks a,b,c --injection-tasks 0,1,.. --defense none|gate --attack important_instructions

红线：
  - key 只从 api-demo/.env 读 DEEPSEEK_API_KEY -> 环境变量 OPENAI_API_KEY/OPENAI_BASE_URL，绝不打印/写库。
  - 样本由 AgentDojo 自带(合成)，无真实内网/IP/凭据。
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
LEARNING = BASE.parent / "gate"
sys.path.insert(0, str(LEARNING))          # 让 capability_flow 可导入

# ---- 读 DeepSeek key 到环境变量（OpenAI 兼容）----
_env = {}
_envf = BASE.parent / ".env"
if _envf.exists():
    for line in _envf.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            _env[k.strip()] = v.strip().strip('"').strip("'")
KEY = _env.get("DEEPSEEK_API_KEY", "").strip()
if not KEY:
    sys.exit("[fail-closed] 未找到 DEEPSEEK_API_KEY，不联网。")
os.environ["OPENAI_API_KEY"] = KEY
os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com"
AGENT_MODEL = os.environ.get("AD_AGENT_MODEL", "deepseek-chat")

import openai
from agentdojo.agent_pipeline.agent_pipeline import PipelineConfig
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm, load_system_message
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, ToolsExecutionLoop
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from capability_flow import flow_review
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME

# ---- 针对 DeepSeek 后端：system 消息角色用 "system"(agentdojo 对 OpenAI 默认输出 "developer") ----
import agentdojo.agent_pipeline.llms.openai_llm as _ollm
from openai.types.chat import ChatCompletionSystemMessageParam
_ollm_orig_message_to_openai = _ollm._message_to_openai
def _ollm_patched_message_to_openai(message, model):
    out = _ollm_orig_message_to_openai(message, model)
    # ChatSystemMessage 在本版本是 TypedDict(dict)，不能用 isinstance；按 role 判断
    if getattr(message, "get", None) is not None and message.get("role") == "system":
        try:
            content = out.content if hasattr(out, "content") else out["content"]
            return ChatCompletionSystemMessageParam(role="system", content=content)
        except Exception:
            return out
    return out
_ollm._message_to_openai = _ollm_patched_message_to_openai

# ---- 注入攻击文案需要从 pipeline 名识别模型（用于 {model} 占位符）----
from agentdojo.models import MODEL_NAMES
if "deepseek-chat" not in MODEL_NAMES:
    MODEL_NAMES["deepseek-chat"] = "DeepSeek"
    MODEL_NAMES[str(AGENT_MODEL)] = "DeepSeek"

# ---- pydantic 前向引用解析：加载缓存结果实例化 TaskResults 时需先 build 依赖模型 ----
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import ChatMessage
from agentdojo.benchmark import TaskResults
for _m in (FunctionCall, ChatMessage, TaskResults):
    try:
        _m.model_rebuild()
    except Exception:
        pass

BLOCKED_LABELS = ("restrict", "block")


def _gate_text(tool_call) -> str:
    """把一次工具调用渲染成安检门可审的能力意图串；失败则 fail-closed 视为不可信。"""
    try:
        args = dict(tool_call.args) if tool_call.args else {}
        return f"{tool_call.function} with args {json.dumps(args)}"
    except Exception:
        return f"{tool_call.function} with unknown args"


class CapabilityGateExecutor(BasePipelineElement):
    """数据流出口门：执行工具前，用本地 flow_review 审每次调用；restrict/block 则拒执行(不触发真实副作用)。
    放行时镜像 ToolsExecutor 的真实执行逻辑(runtime.run_function)，保证行为一致。"""

    def __init__(self, output_formatter=None, log=None):
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
        self.output_formatter = output_formatter if output_formatter is not None else tool_result_to_str
        self.log = log if log is not None else []
        self.checks = 0
        self.blocked = 0

    def query(self, query, runtime, env=EmptyEnv(), messages=(), extra_args=None):
        messages = list(messages)
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        last = messages[-1]
        if last["role"] != "assistant" or not last.get("tool_calls"):
            return query, runtime, env, messages, extra_args

        tool_call_results = []
        for tc in last["tool_calls"]:
            if tc.function == EMPTY_FUNCTION_NAME:
                tool_call_results.append(
                    ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                          tool_call_id=tc.id, tool_call=tc,
                                          error="Empty function name provided. Provide a valid function name.")
                )
                continue
            if tc.function not in (tool.name for tool in runtime.functions.values()):
                tool_call_results.append(
                    ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                          tool_call_id=tc.id, tool_call=tc,
                                          error=f"Invalid tool {tc.function} provided.")
                )
                continue

            t = _gate_text(tc)
            try:
                _, _, fb, ev = flow_review(t)
            except Exception:
                fb = "block"  # fail-closed
            self.checks += 1
            if fb in BLOCKED_LABELS:
                self.blocked += 1
                self.log.append({"call": t[:80], "flow": fb, "action": "BLOCKED"})
                tool_call_results.append(
                    ChatToolResultMessage(
                        role="tool", content=[text_content_block_from_string("")], tool_call_id=tc.id, tool_call=tc,
                        error=f"[SECURITY GATEWAY] blocked {tc.function} (risk={fb}); tool NOT executed.",
                    )
                )
            else:
                self.log.append({"call": t[:80], "flow": fb, "action": "EXEC"})
                tool_result, err = runtime.run_function(env, tc.function, tc.args)
                tool_call_results.append(
                    ChatToolResultMessage(role="tool", content=[text_content_block_from_string(self.output_formatter(tool_result))],
                                          tool_call_id=tc.id, tool_call=tc, error=err)
                )
        return query, runtime, env, [*messages, *tool_call_results], extra_args


def make_pipeline(mode: str):
    client = openai.OpenAI()
    llm = OpenAILLM(client, AGENT_MODEL)
    system = SystemMessage(load_system_message(None))
    initq = InitQuery()
    if mode == "gate":
        exec_loop = ToolsExecutionLoop([CapabilityGateExecutor(), llm])
    else:
        exec_loop = ToolsExecutionLoop([ToolsExecutor(), llm])
    pipe = AgentPipeline([system, initq, llm, exec_loop])
    pipe.name = f"{AGENT_MODEL}__flow_review_gate" if mode == "gate" else f"{AGENT_MODEL}__none"
    return pipe


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="banking")
    ap.add_argument("--version", default="v1.2.2")
    ap.add_argument("--user-task", default=None)
    ap.add_argument("--injection-task", default=None)
    ap.add_argument("--defense", default="none", choices=["none", "gate"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--outdir", default=str(BASE / "runs"))
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--batch", action="store_true")
    ap.add_argument("--user-tasks", default=None, help="逗号分隔的 user_task id(仅batch)")
    ap.add_argument("--injection-tasks", default=None, help="逗号分隔的 injection_task id(仅batch)")
    args = ap.parse_args()

    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import (
        run_task_with_injection_tasks,
        benchmark_suite_with_injections,
        benchmark_suite_without_injections,
    )

    suite = get_suite(args.version, args.suite)
    outdir = Path(args.outdir)
    pipe = make_pipeline(args.defense)
    print(f"[pipeline] model={AGENT_MODEL} defense={args.defense} name={pipe.name}")
    print(f"[suite] {suite.name} v{args.version}")

    from agentdojo.logging import OutputLogger
    output_ctx = OutputLogger(str(outdir), live=None)

    if args.smoke and args.user_task:
        with output_ctx:
            res = benchmark_suite_without_injections(
                pipe, suite, outdir, force_rerun=True,
                user_tasks=[args.user_task], benchmark_version=args.version,
            )
        u = res["utility_results"]
        print("\n== SMOKE (无注入) ==")
        for (tid, _), ok in u.items():
            print(f"  {tid}: utility={ok}")
            # 打印门的信息
            for e in pipe.elements:
                if isinstance(e, ToolsExecutionLoop):
                    for el in e.elements:
                        if isinstance(el, CapabilityGateExecutor):
                            print(f"    gate checks={el.checks} blocked={el.blocked}")
                            for r in el.log:
                                print(f"      {r['call'][:60]} -> {r['flow']} {r['action']}")
        sys.exit(0)

    if args.user_task and args.injection_task is not None:
        attack = load_attack(args.attack, suite, pipe)
        ut = suite.get_user_task_by_id(args.user_task)
        if args.injection_task and args.injection_task != "all":
            injection_task_ids = args.injection_task.split(",")
        else:
            injection_task_ids = None
        with output_ctx:
            u, s = run_task_with_injection_tasks(
                suite, pipe, ut, attack, outdir, True, injection_tasks=injection_task_ids,
                benchmark_version=args.version,
            )
        print("\n== 单对 (user, injection) ==")
        for (tid, iid), okk in u.items():
            print(f"  ({tid},{iid}) utility={okk} security={s.get((tid,iid))}")
        sys.exit(0)

    if args.batch:
        attack = load_attack(args.attack, suite, pipe)
        user_ids = args.user_tasks.split(",") if args.user_tasks else sorted(suite.user_tasks)
        inj_ids = args.injection_tasks.split(",") if args.injection_tasks else sorted(suite.injection_tasks)
        inj_ids = [f"injection_task_{i}" if not i.startswith("injection_task_") else i for i in inj_ids]
        summary = {}
        with output_ctx:
            for uid in user_ids:
                if not uid.startswith("user_task_"):
                    uid = "user_task_" + uid
                ut = suite.get_user_task_by_id(uid)
                u, s = run_task_with_injection_tasks(
                    suite, pipe, ut, attack, outdir, True, injection_tasks=inj_ids,
                    benchmark_version=args.version,
                )
                for (tid, iid), okk in u.items():
                    summary[f"{tid}|{iid}"] = {"utility": okk, "security": s.get((tid, iid))}
        n = len(summary)
        n_sec = sum(1 for v in summary.values() if v["security"] is False)   # security=False=注入被拦截
        n_ut = sum(1 for v in summary.values() if v["utility"])
        print(f"\n== BATCH {args.defense} : {n} pairs ==")
        print(f"  防守率(注入被拦) = {n_sec}/{n} = {n_sec/n:.1%}   [security=False的比例]")
        print(f"  utility达成    = {n_ut}/{n} = {n_ut/n:.1%}")
        for k in sorted(summary):
            v = summary[k]
            print(f"  {k:<34} util={v['utility']}  sec={v['security']}  {'<- 被拦' if v['security'] is False else 'VULN'}")

        out = outdir / "batch_summary.json"
        import json as _json
        with out.open("w", encoding="utf-8") as _f:
            _json.dump({"defense": args.defense, "attack": args.attack, "suite": args.suite,
                        "model": AGENT_MODEL, "pairs": len(summary),
                        "defense_rate": n_sec / n if n else 0, "utility_rate": n_ut / n if n else 0,
                        "items": summary}, _f, ensure_ascii=False, indent=2)
        print(f"  -> saved {out}")
        sys.exit(0)