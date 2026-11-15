"""AutoSafe-Audit：多 Agent 代码安全审计的迭代深度与 token 边际收益分析。"""
from __future__ import annotations

import sys

from .bootstrap import ensure_deps

ensure_deps()


def _force_utf8_stdio() -> None:
    """让 CLI 的中文输出在 Windows GBK 终端下也不乱码。

    Windows 默认控制台编码常为 GBK/cp936，直接 print 中文会抛 UnicodeEncodeError
    或显示乱码。这里在导入时把标准流切到 UTF-8 并开启 errors="replace"，
    避免任何环境变量依赖（外部用户不需要设置 PYTHONIOENCODING）。
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:          # 已被重定向到非 TextIOWrapper 时跳过
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):     # pragma: no cover - 极少数环境
            pass


_force_utf8_stdio()

__version__ = "1.0.0"
__all__ = ["__version__"]

