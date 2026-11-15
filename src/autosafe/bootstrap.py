"""项目引导：注入依赖路径、提供沙箱安全的临时目录。"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
PYLIBS = WORKSPACE_ROOT / ".pylibs"
BUILD_TMP = PROJECT_ROOT / "build_tmp"


def ensure_deps() -> None:
    """把 workspace 级的 .pylibs 注入 sys.path（幂等）。"""
    if PYLIBS.is_dir():
        p = str(PYLIBS)
        if p not in sys.path:
            sys.path.insert(0, p)


def make_tempdir(prefix: str = "autosafe-") -> Path:
    """创建临时目录。

    本机沙箱下 ``tempfile.mkdtemp`` 创建的目录不可写，因此这里用显式 mkdir。
    """
    BUILD_TMP.mkdir(parents=True, exist_ok=True)
    for _ in range(50):
        d = BUILD_TMP / f"{prefix}{uuid.uuid4().hex[:10]}"
        try:
            d.mkdir(parents=False, exist_ok=False)
            return d
        except FileExistsError:  # pragma: no cover - 极小概率
            continue
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(BUILD_TMP)))


def cleanup(path: Path) -> None:
    """尽力删除临时目录，失败不抛异常。"""
    shutil.rmtree(path, ignore_errors=True)


def subprocess_env() -> dict[str, str]:
    """构造子进程环境：带上 .pylibs，去掉可能干扰的变量。"""
    env = dict(os.environ)
    parts = [str(PYLIBS)] if PYLIBS.is_dir() else []
    if env.get("PYTHONPATH"):
        parts.append(env["PYTHONPATH"])
    if parts:
        env["PYTHONPATH"] = os.pathsep.join(parts)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


ensure_deps()
