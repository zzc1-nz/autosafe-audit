"""pytest 配置：把 src 加入 sys.path。"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
for p in (str(SRC), str(ROOT.parent / ".pylibs")):
    if p not in sys.path:
        sys.path.insert(0, p)

import autosafe  # noqa: E402,F401
