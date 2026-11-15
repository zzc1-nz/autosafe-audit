"""三个 Agent 的行为模型：Coding / Static Analyzer / Fuzzing。

关键设计（真实性所在）
----------------------
Agent 的"决策"是概率模型，但**判定全部由真实工具完成**：

* 静态分析通道：真实调用 bandit（:mod:`autosafe.analyzers.bandit_runner`），
  只有 bandit 真正报出的 test_id + 行号落在某 defect 的 ±5 行内，该漏洞才算"被发现"。
* 模糊测试通道：真实把目标代码和 harness 写进子进程执行（:mod:`autosafe.analyzers.fuzzer`），
  只有 harness 真的打印出对应 marker，该漏洞才算"被发现"。
* 修复验证：修复后重新跑上述两条通道 + ``source_check`` 正则，只有漏洞真的消失才算"修复"。

Prompt 构造遵循真实 Agent 循环：**工具输出会回灌进 prompt**（bandit 报告、fuzz 日志、
历史 findings），因此单轮 token 会随轮次增长——这正是边际收益递减的物理来源之一。

模型建模的三个真实世界效应：
1. **检出率随 subtlety 衰减**：语义类漏洞（缺失鉴权、不安全默认）bandit 抓不到，
   需要 LLM 推理；难度越高越容易漏。
2. **修复错误率**：Agent 会用"看起来合理但无效"的补丁（``flawed_fix_replace``），
   下一轮又被重新报告 —— 这是 token 黑洞的主要来源。
3. **重复报告与上下文膨胀**：历史 findings 进入 prompt，prompt 逐轮变长，单轮 token 上升。
"""
from __future__ import annotations

from dataclasses import dataclass

from .llm import LLMClient, seeded_random
from .schema import Defect, Task

# ---------------------------------------------------------------- 行为参数


@dataclass(frozen=True)
class AgentProfile:
    """一个"模型能力档位"的联合参数，用于敏感性分析。"""

    name: str
    # 语义通道检出概率：base - slope * (subtlety - 1)，再按轮次轻微衰减
    semantic_recall_base: float = 0.72
    semantic_recall_slope: float = 0.11
    # 跨轮记忆增益：同一缺陷被重复提示后，检出概率提升
    repeat_boost: float = 0.16
    # 首轮修复正确率（越高越省 token）
    fix_accuracy_base: float = 0.66
    fix_accuracy_slope: float = 0.09
    # 修复失败的两种模式占比
    p_flawed_fix: float = 0.55  # 用 flawed_fix_replace（下一轮会复发）
    p_no_change: float = 0.18  # 什么都不改，下一轮重复报告
    # 噪声：分析器误报率（相对代码行数）
    noise_rate: float = 0.55
    # 修复引入新问题的概率（回归）
    p_regression: float = 0.05


PROFILES: dict[str, AgentProfile] = {
    "strong": AgentProfile(
        name="strong",
        semantic_recall_base=0.86,
        semantic_recall_slope=0.09,
        repeat_boost=0.20,
        fix_accuracy_base=0.80,
        fix_accuracy_slope=0.07,
        p_flawed_fix=0.45,
        p_no_change=0.12,
        noise_rate=0.35,
        p_regression=0.03,
    ),
    "baseline": AgentProfile(name="baseline"),
    "weak": AgentProfile(
        name="weak",
        semantic_recall_base=0.58,
        semantic_recall_slope=0.13,
        repeat_boost=0.12,
        fix_accuracy_base=0.52,
        fix_accuracy_slope=0.10,
        p_flawed_fix=0.62,
        p_no_change=0.24,
        noise_rate=0.80,
        p_regression=0.08,
    ),
}

DEFAULT_PROFILE = "baseline"


def get_profile(name: str | None = None) -> AgentProfile:
    key = (name or DEFAULT_PROFILE).strip().lower()
    if key not in PROFILES:
        raise KeyError(f"未知 profile {name!r}，可选: {sorted(PROFILES)}")
    return PROFILES[key]


# ---------------------------------------------------------------- Prompt 构造
#
# 说明：这些 prompt 的**字符长度**直接决定 token 记账。它们刻意贴近真实 Agent 循环：
# 目标代码全文、静态分析工具原始报告、fuzz 执行日志、历史 findings 都会进入上下文。


def render_bandit_report(findings, *, limit: int = 12) -> str:
    """把 bandit findings 渲染成分析 Agent 看到的报告文本。"""
    if not findings:
        return "(no issues reported by bandit)"
    lines = []
    for f in findings[:limit]:
        lines.append(
            f"- {f.test_id} {f.severity}/{f.confidence} line {f.line}: {f.text} "
            f"(cwe={f.cwe or 'n/a'})"
        )
    if len(findings) > limit:
        lines.append(f"- ... {len(findings) - limit} more findings truncated by triage")
    return "\n".join(lines)


def coding_prompt(task: Task, round_index: int, history: list[dict]) -> list[dict]:
    """Coding Agent：首轮按任务描述写代码；之后根据 findings 修复。"""
    if round_index == 1:
        return [
            {
                "role": "system",
                "content": (
                    "You are a senior Python engineer on a security-sensitive codebase. "
                    "Implement the requested module. Requirements: standard library only, "
                    "no network access, import-safe at module level, and secure by default "
                    "(parameterised queries, no shell=True, no pickle on untrusted data, "
                    "secrets via secrets/os.urandom, explicit authorisation checks). "
                    "Return only the complete runnable module source code, no prose."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Task:\n{task.prompt}\n\n"
                    "Constraints:\n"
                    "- Python 3.11+, standard library only\n"
                    "- module-level code must be import-safe (no side effects)\n"
                    "- do not hardcode credentials\n"
                    "- handle errors explicitly rather than silently\n"
                ),
            },
        ]
    issues = "\n".join(
        f"- [{h['channel']}] {h['id']} at line {h['line']}: {h['detail']}"
        for h in history[-24:]
    )
    return [
        {
            "role": "system",
            "content": (
                "You are a senior Python engineer fixing security defects reported by an "
                "automated audit pipeline. Apply minimal, correct patches. Do not refactor "
                "unrelated code. Return only the full module source code."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Task:\n{task.prompt}\n\n"
                f"Security issues reported by the analyzers:\n{issues}\n\n"
                "Fix every issue listed above. Keep the public API unchanged."
            ),
        },
    ]


def static_prompt(code: str, round_index: int, bandit_report: str = "") -> list[dict]:
    """Static Analyzer Agent：结合 bandit 原始报告做语义复核。"""
    return [
        {
            "role": "system",
            "content": (
                "You are a static security analyzer. Review the module for CWE-class defects: "
                "injection (CWE-89/78/94), path traversal (CWE-22), unsafe deserialization "
                "(CWE-502), weak crypto (CWE-327/328), hardcoded secrets (CWE-798), missing "
                "authorisation (CWE-862/863), insecure randomness (CWE-330), and unsafe "
                "configuration (CWE-489/732). Report defect ids with line numbers and severity."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Round {round_index}. Target module:\n```python\n{code}\n```\n\n"
                f"Static analysis tool output:\n{bandit_report}\n\n"
                "Cross-check the tool output, and additionally look for logic-level defects "
                "the tool cannot see (missing authz, insecure defaults, weak entropy)."
            ),
        },
    ]


def fuzz_prompt(code: str, round_index: int, fuzz_log: str = "") -> list[dict]:
    """Fuzzing Agent：设计恶意输入并解释崩溃。"""
    return [
        {
            "role": "system",
            "content": (
                "You are a fuzzing agent. Design adversarial inputs for the module and report "
                "runtime failures: unhandled exceptions, injection sinks reached, traversal "
                "escapes, unsafe deserialization, weak-token predictability."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Round {round_index}. Target module:\n```python\n{code}\n```\n\n"
                f"Fuzzer execution log:\n{fuzz_log}\n\n"
                "Report every marker triggered by the harness, plus any additional runtime "
                "failure you can infer from the control flow."
            ),
        },
    ]


def repair_prompt(code: str, issue_ids: list[str], round_index: int) -> list[dict]:
    """Repair 子步骤：只产出针对性的 diff 片段。"""
    return [
        {
            "role": "system",
            "content": (
                "You are a patch generator. For each reported defect, output the minimal "
                "replacement snippet. Prefer standard-library secure patterns: parameterised "
                "SQL, list-form subprocess, pathlib resolve + containment check, hmac/secrets, "
                "json instead of pickle."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Round {round_index}. Defects to fix: {', '.join(issue_ids)}\n"
                f"Module:\n```python\n{code}\n```"
            ),
        },
    ]


# ---------------------------------------------------------------- 行为模型


@dataclass
class DetectionOutcome:
    """一次分析回合的产出。"""

    discovered: list[str]          # 本轮首次发现的 defect_id
    reported: list[str]            # 本轮报告的全部 defect_id（含重复）
    duplicate: list[str]           # 重复报告
    bandit_findings: int
    fuzz_markers: int
    noise: int


def semantic_recall(defect: Defect, profile: AgentProfile, round_index: int,
                    times_reported: int) -> float:
    """语义通道对某缺陷的检出概率。"""
    base = profile.semantic_recall_base - profile.semantic_recall_slope * (defect.subtlety - 1)
    base -= 0.02 * (round_index - 1)                     # 上下文变长，注意力稀释
    base += profile.repeat_boost * min(times_reported, 3)
    return max(0.02, min(0.98, base))


def will_detect_semantic(defect: Defect, task: Task, profile: AgentProfile, round_index: int,
                         times_reported: int, seed: int) -> bool:
    rng = seeded_random("sem", task.task_id, defect.defect_id, round_index, seed)
    return rng.random() < semantic_recall(defect, profile, round_index, times_reported)


@dataclass
class FixOutcome:
    """一次修复尝试的结果。"""

    defect_id: str
    applied: bool          # 是否改动了代码
    correct: bool          # 是否真正修复
    mode: str              # "correct" | "flawed" | "noop"


def attempt_fix(defect: Defect, task: Task, profile: AgentProfile, round_index: int,
                seed: int) -> FixOutcome:
    """模拟 Agent 对单个缺陷的修复尝试。"""
    rng = seeded_random("fix", task.task_id, defect.defect_id, round_index, seed)
    acc = profile.fix_accuracy_base - profile.fix_accuracy_slope * (defect.subtlety - 1)
    acc += 0.05 * (round_index - 1)                      # 反复提示后修复能力略升
    acc = max(0.08, min(0.96, acc))
    if rng.random() < acc:
        return FixOutcome(defect.defect_id, applied=True, correct=True, mode="correct")
    # 失败：要么给出假补丁，要么什么都不改
    if defect.flawed_fix_replace is not None and rng.random() < profile.p_flawed_fix / (
        profile.p_flawed_fix + profile.p_no_change
    ):
        return FixOutcome(defect.defect_id, applied=True, correct=False, mode="flawed")
    return FixOutcome(defect.defect_id, applied=False, correct=False, mode="noop")
