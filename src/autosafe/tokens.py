"""Token 估算：离线环境无 tiktoken，使用字符级校准估计器。

估计器对英文代码与中文说明混合的文本做加权，误差约 ±8%（见 docs/TOKEN_CALIBRATION.md）。
所有实验的 token 数字都来自这里，保证同一文本永远得到同一计数。
"""
from __future__ import annotations

import math

# 每 token 平均字符数（代码/英文提示实测校准值）
CHARS_PER_TOKEN = 3.62
# 每条 chat message 的结构开销（role 标记、分隔符）
MESSAGE_OVERHEAD = 4
# 回复结尾开销
REPLY_OVERHEAD = 3


def _cjk_ratio(text: str) -> float:
    if not text:
        return 0.0
    cjk = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff")
    return cjk / len(text)


def count_tokens(text: str) -> int:
    """估算一段文本的 token 数。

    中文按约 1 字 ≈ 1 token 计，英文/代码按 3.62 字符 ≈ 1 token 计。
    """
    if not text:
        return 0
    cjk = _cjk_ratio(text)
    if cjk > 0:
        n_cjk = int(len(text) * cjk)
        n_rest = len(text) - n_cjk
        est = n_cjk * 1.0 + n_rest / CHARS_PER_TOKEN
    else:
        est = len(text) / CHARS_PER_TOKEN
    return max(1, int(math.ceil(est)))


def count_messages(messages: list[dict]) -> int:
    """估算 chat messages 的 prompt token 数。"""
    total = 0
    for m in messages:
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(str(c.get("text", "")) for c in content)
        total += count_tokens(str(content)) + MESSAGE_OVERHEAD
    return total + REPLY_OVERHEAD


def estimate_round_tokens(code_chars: int, findings: int, round_index: int) -> int:
    """粗略预估某轮 token（用于规划与预算，不参与记账）。"""
    base = 900 + code_chars / CHARS_PER_TOKEN
    growth = 1.0 + 0.18 * (round_index - 1)
    return int(base * growth + 120 * findings)
