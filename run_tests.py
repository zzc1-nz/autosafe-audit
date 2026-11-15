"""测试入口：注入 .pylibs 后调用 pytest。

本机 pytest 不在全局 site-packages，而在 workspace 根的 .pylibs 里，
且沙箱下 ``python -m pytest`` 无法直接找到它。统一用：

    python run_tests.py              # 全部
    python run_tests.py tests/test_pipeline.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for p in (str(ROOT / "src"), str(ROOT.parent / ".pylibs")):
    if p not in sys.path:
        sys.path.insert(0, p)

if __name__ == "__main__":
    import pytest

    args = sys.argv[1:] or ["tests"]
    if not any(a.startswith("-") for a in args):
        args = args + ["-q"]
    sys.exit(pytest.main(["-p", "no:cacheprovider", *args]))
