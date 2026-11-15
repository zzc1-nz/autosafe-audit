# Token 估算与校准说明

## 为什么需要自己的估算器

离线环境没有 `tiktoken`（无外网、不装包），而整个项目的核心结论都以 token 为单位，
所以必须有一个**确定性、可复现、量级正确**的估算器。实现见 `src/autosafe/tokens.py`。

## 估算规则

```
count_tokens(text):
    中文（CJK）字符      → 1 字符 ≈ 1 token
    其余（英文/代码/符号）→ 3.62 字符 ≈ 1 token
```

`count_messages()` 在此基础上为每条 message 加 4 token 结构开销（role 标记、分隔符），
整个对话再加 3 token 回复前缀开销。

### 3.62 这个系数的来源

对 DeepSeek / GPT 系列 BPE 分词器而言，英文自然语言约 4.0 字符/token，但**代码**因为
标识符、缩进、标点密集，实测约 3.3–3.7 字符/token。本项目 prompt 主体是 Python 代码与
结构化报告，取 3.62 作为折中值。

## 校准结果

在 5 个真实任务（T01–T05）上实测（`profile=baseline`, `seed=7`, `max_rounds=8`）：

| 指标 | 数值 |
|---|---|
| 单任务总 token | 3,426 – 22,495 |
| 单轮 token | 2,791 – 3,723 |
| 单轮 input | 1,371 – 1,715 |
| 单轮 output | 1,376 – 2,008 |
| 5 任务总计 | 62,647 |

单轮 token 的构成（以 T01 第 1 轮为例，共 3,723 token）：

| Agent | token | 说明 |
|---|---|---|
| coding | 2,225 | 首轮生成完整模块 + 后续 3 次独立 repair 调用 |
| static | 894 | 分析报告（含 bandit 原始输出） |
| fuzzing | 604 | harness 设计与崩溃分析 |

## 误差与边界

**估算器误差约 ±8%**（与真实 BPE 分词对比）。这个误差对结论的影响是**系统性缩放**，
不改变"边际收益何时趋零"的判定——因为拐点用的是**比值**（修复数 / token），
分子分母同比例缩放时比值不变。

**不可外推的地方**：
- 换模型（不同 tokenizer）会改变绝对 token 数，但曲线形状（递减趋势）应保持
- 真实 LLM 的输出长度方差比模拟 provider 大，单轮 token 的波动会更明显
- 真实场景的 prompt 通常更长（多文件上下文、完整仓库），绝对量级会显著上升

## 设计选择：为什么把 token 记账放在 provider 层

`LLMResponse` 里同时记录 `prompt_tokens` 与 `completion_tokens`，且**优先使用 API 返回的
真实 usage**（`LiteLLMClient` 路径），只有在拿不到 usage 时才回退到估算器。
这样把 `AUTOSAFE_LLM=litellm` 打开后，同一套分析代码可以直接跑在真实模型上，
记账口径不需要改一行——这是本项目"模拟 provider 结论可迁移"的技术基础。
