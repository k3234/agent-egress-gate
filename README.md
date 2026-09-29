# agent-egress-gate — 数据流出口审查门控系统（原型 + 评测基准）

面向 AI Agent 的**数据流出口审查**原型系统：按「外泄（P1）/ 状态改写（P2）/ 权力提升（P3）」三原则对能力请求分级裁决（allow / restrict / block / review），fail-unknown 兜底（宁误报、不漏放），并以「路径 + 内容签名完全绑定」的白名单收窄放行范围。

> 配套论文将提交至学术赛事，发布前暂不在本仓库公开论文正文与核心结论。本仓库仅含系统原型、评测脚本与可复跑数据。

## 目录结构

| 目录 | 内容 |
|---|---|
| `gate/` | 核心门控：混合判定主入口 `hybrid_gate.py`、三原则推理 `capability_reason.py`、能力流分析 `capability_flow.py`、网络 / 作用域模块、沙箱探针演示 `env_probe_demo.py`、决策数据 `capability_decisions.json`、白名单 `whitelist.json` |
| `deep_bench/` | 自建评测基准：样本集（合成 / 红队 / 对抗扩展）、主流防线对照（Llama Guard 3 1B、Llama Prompt Guard 2 86M）、结果数据与图表、全部评测脚本 |
| `agentdojo/` | 主流提示注入基准 [agentdojo](https://github.com/ethz-spylab/agentdojo)（banking 套件）对照实验：运行脚本与原始运行记录 |
| `experiments/` | 一键复跑入口：`run_experiment_abc.py` 三组受控对照实验（A 基线 / B +白名单 / C +识别增强） |

## 环境要求

- Python 3.10+
- 联网评测脚本需要 API Key（**只从环境变量读取，代码中不含任何密钥**）：
  - `DEEPSEEK_API_KEY`（DeepSeek）
  - `GLM_API_KEY`（智谱 BigModel）
- 模型对照实验需自备 `models/` 目录：评测脚本按相对路径查找 `../models/Llama-Guard-3-1B`、`../models/Llama-Prompt-Guard-2-86M`（下载脚本见 `deep_bench/_download_*.py`）。

## 快速复跑

### 1. 三组对照实验（离线，无需 API）

```bash
cd experiments
python run_experiment_abc.py
```

> 注意：实验依赖 `gate/capability_gold.json`（带标答的评测样本库）。该文件属于**非公开材料**，不随仓库分发；请按以下格式自备后放入 `gate/` 目录：

```json
{
  "samples": [
    {"id": "s01", "request": "resize_image_in_memory", "expected_verdict": "allow"}
  ]
}
```

### 2. 门控沙箱探针演示（离线）

```bash
cd gate
python env_probe_demo.py
```

`whitelist.json` 为**脱敏模板**：`<LOCAL_RUNTIME_PYTHON_PATH>` / `<LOCAL_FILE_SHA256>` 需按本机实际运行时路径与文件 SHA-256 填写。白名单 = 路径 + 内容签名完全绑定，scope 只放行列出的功能，未列出的功能一律不放行。

### 3. 评测脚本（需 API Key / 模型权重）

```bash
cd deep_bench
python run_deep_bench.py
```

其余 `deep_bench/_*.py` 为分项评测（延迟韧性、红队、对抗扩展、主流防线对照等）；`agentdojo/run_agentdojo.py` 为 agentdojo banking 套件对照实验入口。

## 安全与隐私声明

- 本仓库**不含**任何 API Key、内网地址、本机用户路径；所有密钥仅经环境变量注入，缺失即退出。
- `agentdojo/runs/` 为官方公开基准（banking 套件）的本地运行记录，样本均为官方合成数据（虚构人物、虚构 IBAN）。
- `deep_bench/` 各样本集均为人工构造的合成 / 红队文本，不针对任何真实系统与真实用户。
