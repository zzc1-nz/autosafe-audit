"""模糊测试执行器：在隔离子进程里跑 harness，解析标记与覆盖率代理。

对齐 docs/CONTRACT.md §4：

* ``Task.fuzz_harness`` 是模块级源码，定义 ``fuzz(module) -> list[str]``；
* runner 把 ``code`` 写成 ``<tmp>/target.py``、harness 写成 ``<tmp>/harness.py``，
  用 ``subprocess.run([sys.executable, "harness.py"], cwd=<tmp>, timeout=...)`` 执行；
* harness 自己 ``import target`` 并打印 ``FUZZ_MARKERS:[...]``；可选打印
  ``FUZZ_COVERAGE:<float>``（0..1）作为覆盖率代理；
* 超时/异常/解析失败 → ``ok=False`` + ``error``，**绝不向调用方抛异常**；
* 临时目录用 ``bootstrap.make_tempdir``（本机 ``tempfile.mkdtemp`` 在沙箱下不可写），
  并在 ``finally`` 里清理，保证连续调用不泄漏。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..bootstrap import cleanup, make_tempdir, subprocess_env

# stdout/stderr 截断长度（防止死循环 harness 刷爆内存）
MAX_OUTPUT_CHARS = 4000

# harness 约定的输出行前缀
MARKERS_PREFIX = "FUZZ_MARKERS:"
COVERAGE_PREFIX = "FUZZ_COVERAGE:"

# 从 harness 源码里提取候选标记名（大写标识符字符串），用于没有显式覆盖率时的粗估
_MARKER_CANDIDATE_RE = re.compile(r"""["']([A-Z][A-Z0-9_]{2,})["']""")


@dataclass
class FuzzResult:
    """一次模糊测试执行的结果。"""

    markers: list[str] = field(default_factory=list)
    ok: bool = False
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    coverage_proxy: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """转成可 JSON 序列化的 dict。"""
        return {
            "markers": list(self.markers),
            "ok": self.ok,
            "error": self.error,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "coverage_proxy": self.coverage_proxy,
        }


# --------------------------------------------------------------------------- #
# 解析辅助
# --------------------------------------------------------------------------- #
def _clip(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    """截断过长输出（保留尾部，异常信息通常在尾部）。"""
    if len(text) <= limit:
        return text
    return "..." + text[-(limit - 3):]


def _to_text(raw: bytes | str | None) -> str:
    """把子进程原始输出安全转成 str。"""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return str(raw)


def _iter_lines(text: str) -> list[str]:
    """按行切分并去掉行尾空白。"""
    return [ln.strip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]


def _parse_markers(stdout: str) -> list[str] | None:
    """取最后一行以 ``FUZZ_MARKERS:`` 开头的 JSON 列表；解析失败返回 None。"""
    for line in reversed(_iter_lines(stdout)):
        if not line.startswith(MARKERS_PREFIX):
            continue
        payload = line[len(MARKERS_PREFIX):].strip()
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, list):
            return None
        markers: list[str] = []
        for item in data:
            marker = str(item).strip()
            if marker and marker not in markers:
                markers.append(marker)
        return markers
    return None


def _parse_coverage(stdout: str) -> float | None:
    """取最后一行 ``FUZZ_COVERAGE:<float>``，clamp 到 [0, 1]。"""
    for line in reversed(_iter_lines(stdout)):
        if not line.startswith(COVERAGE_PREFIX):
            continue
        payload = line[len(COVERAGE_PREFIX):].strip()
        try:
            value = float(payload)
        except (TypeError, ValueError):
            return None
        if value != value:  # NaN
            return None
        return max(0.0, min(1.0, value))
    return None


def _marker_candidates(harness_src: str) -> set[str]:
    """从 harness 源码里粗提取候选标记名，用于命中比例估算。"""
    return {m.group(1) for m in _MARKER_CANDIDATE_RE.finditer(harness_src)}


def _estimate_coverage(markers: list[str], harness_src: str) -> float:
    """没有显式覆盖率时，用标记命中比例粗估覆盖率代理。"""
    candidates = _marker_candidates(harness_src)
    if candidates:
        hit = len(set(markers) & candidates)
        return max(0.0, min(1.0, hit / len(candidates)))
    # 没有候选可参照时：执行到结束视为全覆盖，未命中任何标记则给一个低值
    return 1.0 if markers else 0.0


def _last_error_line(stderr: str) -> str:
    """取 stderr 里最后一条非空行，作为 error 摘要。"""
    lines = [ln for ln in _iter_lines(stderr) if ln]
    return lines[-1] if lines else ""


def _describe_failure(returncode: int, stdout: str, stderr: str) -> str:
    """根据返回码与输出生成人类可读的失败原因。"""
    tail = _last_error_line(stderr)
    # 坏代码（模型生成）在 import target 时就会 SyntaxError，必须显式标注
    if "SyntaxError" in stderr or "SyntaxError" in stdout:
        detail = tail or "invalid syntax"
        return f"target/harness SyntaxError: {detail}"
    if tail:
        return f"harness exited with code {returncode}: {tail}"
    if returncode < 0:
        return f"harness killed by signal {-returncode}"
    return f"harness exited with code {returncode}"


# --------------------------------------------------------------------------- #
# 主入口
# --------------------------------------------------------------------------- #
def run_fuzz(
    harness_src: str,
    code: str,
    *,
    timeout_s: float = 10.0,
    seed: int = 0,
) -> FuzzResult:
    """在子进程里执行 harness，返回 FuzzResult；任何异常都被吞掉。

    Args:
        harness_src: 模块级 harness 源码，需定义 ``fuzz(module)`` 并打印标记行。
        code: 被测目标模块源码（会写成 ``target.py``）。
        timeout_s: 子进程超时（秒）。
        seed: 通过环境变量 ``AUTOSAFE_FUZZ_SEED`` 传给 harness，保证可复现。
    """
    started = time.perf_counter()

    def _elapsed_ms() -> int:
        return max(0, int(round((time.perf_counter() - started) * 1000)))

    if not isinstance(harness_src, str) or not isinstance(code, str):
        return FuzzResult(
            ok=False,
            error="harness_src 与 code 必须是 str",
            duration_ms=_elapsed_ms(),
        )

    try:
        timeout = float(timeout_s)
    except (TypeError, ValueError):
        timeout = 10.0
    if timeout <= 0:
        timeout = 0.001

    tmp: Path | None = None
    try:
        tmp = make_tempdir("fuzz-")
        (tmp / "target.py").write_text(code, encoding="utf-8")
        (tmp / "harness.py").write_text(harness_src, encoding="utf-8")

        env = subprocess_env()
        env["AUTOSAFE_FUZZ_SEED"] = str(seed)
        # 固定 hash 顺序，保证同 seed 的可复现性
        env["PYTHONHASHSEED"] = str(abs(int(seed)) % (2**32))

        proc = subprocess.run(
            [sys.executable, "harness.py"],
            cwd=str(tmp),
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        stdout = _to_text(proc.stdout)
        stderr = _to_text(proc.stderr)
        duration_ms = _elapsed_ms()

        markers = _parse_markers(stdout)
        explicit_coverage = _parse_coverage(stdout)

        if proc.returncode != 0:
            return FuzzResult(
                markers=markers or [],
                ok=False,
                error=_describe_failure(proc.returncode, stdout, stderr),
                stdout=_clip(stdout),
                stderr=_clip(stderr),
                duration_ms=duration_ms,
                coverage_proxy=0.0,
            )

        if markers is None:
            return FuzzResult(
                markers=[],
                ok=False,
                error=f"harness 未输出合法的 {MARKERS_PREFIX}[...] 行",
                stdout=_clip(stdout),
                stderr=_clip(stderr),
                duration_ms=duration_ms,
                coverage_proxy=0.0,
            )

        coverage = (
            explicit_coverage
            if explicit_coverage is not None
            else _estimate_coverage(markers, harness_src)
        )
        return FuzzResult(
            markers=markers,
            ok=True,
            error=None,
            stdout=_clip(stdout),
            stderr=_clip(stderr),
            duration_ms=duration_ms,
            coverage_proxy=max(0.0, min(1.0, coverage)),
        )

    except subprocess.TimeoutExpired as exc:
        return FuzzResult(
            markers=[],
            ok=False,
            error=f"fuzz 超时（>{timeout_s}s）：harness 未在限定时间内结束",
            stdout=_clip(_to_text(exc.stdout)),
            stderr=_clip(_to_text(exc.stderr)),
            duration_ms=_elapsed_ms(),
            coverage_proxy=0.0,
        )
    except Exception as exc:  # noqa: BLE001 - fuzz 在真实世界会崩，不能传染给管线
        return FuzzResult(
            markers=[],
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            duration_ms=_elapsed_ms(),
            coverage_proxy=0.0,
        )
    finally:
        if tmp is not None:
            cleanup(tmp)
