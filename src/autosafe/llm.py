"""LLM 适配层：统一 LiteLLM 与确定性模拟 provider。

设计要点
--------
真实 AutoSafeCoder 用 LLM 做代码生成/漏洞分析/修复。本项目在**无外网 API key** 的环境下
运行，因此把"模型能力"抽象为一个可替换的 provider：

* ``SimulatedLLM``（默认）：确定性模拟。prompt 由真实内容构成（任务描述、当前代码、
  历史发现与修复记录），token 数由 :mod:`autosafe.tokens` 估计，输出长度按角色建模。
  它保证同一 seed 完全可复现，并且 token 规模与真实调用同量级。
* ``LiteLLMClient``：设置 ``AUTOSAFE_LLM=litellm`` + provider key 后启用，走真实模型。
  这样"token 记账/拐点分析"的结论可以直接迁移到真实模型上（换 provider 即可）。

任何模块不得直接 import litellm。
"""
from __future__ import annotations

import hashlib
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from . import tokens as token_utils


class LLMUnavailable(RuntimeError):
    """真实 provider 不可用（缺 key / 缺依赖）。"""


@dataclass
class LLMResponse:
    """一次补全调用的结果与计量。"""

    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    provider: str
    role: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMClient(Protocol):
    """LLM 客户端协议。"""

    name: str

    def complete(
        self,
        messages: list[dict],
        *,
        role: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        seed: int = 0,
    ) -> LLMResponse: ...


# 每个角色的"输出长度模型"：(基准字符数, 与 prompt 长度相关的系数, 抖动上限)
#
# 校准依据（见 docs/TOKEN_CALIBRATION.md）：真实 Agent 循环里，模型输出远不止最终答案——
# 代码生成会带解释与思考、分析会逐条列发现、修复会输出 diff + 理由。这里按"输出 ≈ 代码
# 长度 + 推理开销"建模，使单轮 token 落在实测区间（4000–6000）。
_ROLE_OUTPUT_PROFILE: dict[str, tuple[int, float, int]] = {
    # Coding Agent 吐完整模块 + 简要设计说明
    "coding": (900, 1.15, 420),
    # 静态分析 Agent 逐条列发现（含 CWE、行号、理由）
    "static": (620, 0.55, 320),
    # 模糊测试 Agent 输出 harness 设计 + 崩溃分析
    "fuzzing": (480, 0.42, 260),
    # 修复 Agent 对单个缺陷输出 diff + 理由
    "repair": (420, 0.30, 200),
}


def _digest(messages: list[dict], role: str, seed: int) -> int:
    h = hashlib.sha256()
    h.update(role.encode("utf-8"))
    h.update(str(seed).encode("utf-8"))
    for m in messages:
        h.update(str(m.get("role", "")).encode("utf-8"))
        h.update(str(m.get("content", ""))[:20000].encode("utf-8", "ignore"))
    return int(h.hexdigest()[:16], 16)


class SimulatedLLM:
    """确定性模拟 provider：同输入同 seed 必然得到同 token 数与同文本。"""

    name = "simulated"
    provider = "simulated"

    def __init__(self, model: str = "simulated-deepseek-v4.1-flash", latency_scale: float = 0.0):
        self.model = model
        self.latency_scale = latency_scale

    def _plan(self, messages: list[dict], role: str, seed: int) -> tuple[int, int]:
        """返回 (prompt_tokens, completion_tokens)。"""
        prompt_tokens = token_utils.count_messages(messages)
        digest = _digest(messages, role, seed)
        base, coef, jitter = _ROLE_OUTPUT_PROFILE.get(role, (200, 0.12, 100))
        prompt_chars = sum(len(str(m.get("content", ""))) for m in messages)
        out_chars = base + int(prompt_chars * coef) + (digest % max(1, jitter))
        completion_tokens = token_utils.count_tokens("x" * out_chars)
        return prompt_tokens, completion_tokens

    def complete(
        self,
        messages: list[dict],
        *,
        role: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        seed: int = 0,
    ) -> LLMResponse:
        prompt_tokens, completion_tokens = self._plan(messages, role, seed)
        completion_tokens = min(completion_tokens, max_tokens)
        digest = _digest(messages, role, seed)
        # 输出文本只作为可读日志，不参与判定（判定由真实 bandit/fuzz 完成）
        preview = (
            f"[simulated:{role}] model={self.model} "
            f"prompt={prompt_tokens}tok completion={completion_tokens}tok digest={digest % 100000:05d}"
        )
        latency = 0.0
        if self.latency_scale > 0:
            latency = (0.4 + (digest % 700) / 1000.0) * self.latency_scale
            time.sleep(min(latency / 1000.0, 0.05))
        return LLMResponse(
            text=preview,
            model=self.model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency,
            provider="simulated",
            role=role,
        )


class LiteLLMClient:
    """通过 LiteLLM 调用真实多 provider 模型（需要 key）。"""

    name = "litellm"
    provider = "litellm"

    def __init__(self, model: str | None = None, api_base: str | None = None):
        try:  # pragma: no cover - 依赖外部包
            import litellm  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise LLMUnavailable(
                "未安装 litellm：pip install litellm（或设置 AUTOSAFE_LLM=simulated）"
            ) from exc
        self._litellm = litellm  # pragma: no cover
        self.model = model or os.environ.get("AUTOSAFE_MODEL", "deepseek/deepseek-chat")
        self.api_base = api_base or os.environ.get("AUTOSAFE_API_BASE") or None

    def complete(
        self,
        messages: list[dict],
        *,
        role: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        seed: int = 0,
    ) -> LLMResponse:  # pragma: no cover - 需要真实网络
        t0 = time.perf_counter()
        try:
            resp = self._litellm.completion(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                api_base=self.api_base,
                timeout=120,
            )
        except Exception as exc:
            raise LLMUnavailable(f"LLM 调用失败: {exc}") from exc
        latency = (time.perf_counter() - t0) * 1000.0
        usage = getattr(resp, "usage", None)
        text = ""
        try:
            text = resp.choices[0].message.content or ""
        except Exception:
            text = str(resp)
        return LLMResponse(
            text=text,
            model=self.model,
            prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or token_utils.count_messages(messages)),
            completion_tokens=int(getattr(usage, "completion_tokens", 0) or token_utils.count_tokens(text)),
            latency_ms=latency,
            provider="litellm",
            role=role,
        )


def build_client(mode: str | None = None) -> LLMClient:
    """按环境变量构建客户端；默认走确定性模拟。"""
    mode = (mode or os.environ.get("AUTOSAFE_LLM") or "simulated").strip().lower()
    if mode in {"litellm", "real", "api"}:
        return LiteLLMClient()
    if mode not in {"simulated", "sim", "offline"}:
        raise ValueError(f"未知 AUTOSAFE_LLM={mode!r}，可选 simulated|litellm")
    return SimulatedLLM(
        model=os.environ.get("AUTOSAFE_SIM_MODEL", "simulated-deepseek-v4.1-flash"),
        latency_scale=float(os.environ.get("AUTOSAFE_SIM_LATENCY", "0") or 0),
    )


def seeded_random(*parts: Any) -> random.Random:
    """跨进程稳定的随机源。"""
    h = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return random.Random(int(h[:16], 16))
