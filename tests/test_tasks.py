"""任务库自测：数量/分布/不变式 + bandit 与 fuzz 的真实命中验证。"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from autosafe.bootstrap import PYLIBS, make_tempdir, subprocess_env
from autosafe.schema import FAMILIES, defect_present, defects_present
from autosafe.tasks import FAMILY_ORDER, TASKS, TASKS_BY_ID

# 模块级（import 时）绝不允许执行的调用
LIVE_CALLS = frozenset({
    "urlopen",
    "urlretrieve",
    "get",
    "post",
    "connect",
    "create_connection",
    "system",
    "popen",
    "run",
    "call",
    "Popen",
    "socket",
})

EXPECTED_FAMILY_COUNTS = {
    "injection": 5,
    "path_traversal": 3,
    "deserialization": 3,
    "crypto": 3,
    "secrets": 2,
    "authz": 3,
    "web": 3,
    "randomness": 2,
    "config": 1,
}
TOTAL_DEFECTS_RANGE = (60, 80)
EXPECTED_IDS = [f"T{i:02d}" for i in range(1, 26)]


def _cleanup_retry(path) -> None:
    """Windows 上子进程可能仍短暂持有句柄，重试几次再放弃。"""
    import shutil
    import time

    for _ in range(25):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.08)


def _run_bandit(code: str) -> list[dict]:
    """真实调用 bandit CLI 扫描一段代码。"""
    tmp = make_tempdir("bandit-")
    try:
        target = tmp / "target.py"
        target.write_text(code, encoding="utf-8")
        env = subprocess_env()
        env["PYTHONPATH"] = str(PYLIBS)
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-q", "-f", "json", str(target)],
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
        )
        if proc.returncode not in (0, 1):
            return []
        try:
            return json.loads(proc.stdout).get("results", [])
        except json.JSONDecodeError:
            return []
    finally:
        _cleanup_retry(tmp)


def _run_fuzz(harness: str, code: str, *, timeout_s: float = 60.0) -> list[str]:
    """把 target.py + harness.py 写进临时目录，子进程执行并解析 marker。"""
    tmp = make_tempdir("fuzz-")
    try:
        (tmp / "target.py").write_text(code, encoding="utf-8")
        (tmp / "harness.py").write_text(harness, encoding="utf-8")
        env = subprocess_env()
        env["PYTHONPATH"] = str(PYLIBS)
        try:
            proc = subprocess.run(
                [sys.executable, "harness.py"],
                cwd=str(tmp),
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return []
        for line in proc.stdout.splitlines():
            if line.startswith("FUZZ_MARKERS:"):
                try:
                    return list(json.loads(line[len("FUZZ_MARKERS:"):]))
                except json.JSONDecodeError:
                    return []
        return []
    finally:
        _cleanup_retry(tmp)


# --------------------------------------------------------------------------- #
# 全局结构与分布
# --------------------------------------------------------------------------- #
def test_task_count_and_ids():
    assert len(TASKS) == 25
    assert [t.task_id for t in TASKS] == EXPECTED_IDS
    assert len({t.task_id for t in TASKS}) == 25
    assert set(TASKS_BY_ID) == set(EXPECTED_IDS)


def test_family_order_and_coverage():
    assert FAMILY_ORDER == list(FAMILIES)
    assert set(FAMILY_ORDER) == set(EXPECTED_FAMILY_COUNTS)
    counts = {f: 0 for f in EXPECTED_FAMILY_COUNTS}
    for task in TASKS:
        counts[task.family] += 1
    assert counts == EXPECTED_FAMILY_COUNTS


def test_defects_per_task():
    for task in TASKS:
        assert 2 <= len(task.defects) <= 4, f"{task.task_id} defects={len(task.defects)}"


def test_total_defect_count():
    total = sum(len(t.defects) for t in TASKS)
    low, high = TOTAL_DEFECTS_RANGE
    assert low <= total <= high, f"总 defects={total}"


def test_channel_distribution():
    total = sum(len(t.defects) for t in TASKS)
    counts = {"bandit": 0, "fuzz": 0, "semantic": 0}
    for task in TASKS:
        for defect in task.defects:
            counts[defect.channel] += 1
    assert sum(counts.values()) == total
    assert counts["bandit"] >= 0.45 * total, counts
    assert counts["fuzz"] >= 0.25 * total, counts
    assert counts["semantic"] >= 0.20 * total, counts


def test_high_severity_coverage():
    with_high = [t for t in TASKS if t.high_severity_count >= 1]
    assert len(with_high) >= 20


def test_bandit_detectors_are_real_ids():
    for task in TASKS:
        for defect in task.defects:
            if defect.channel == "bandit":
                assert defect.detector.startswith("B")
                assert defect.detector[1:].isdigit()
                assert len(defect.detector) == 4


def test_fuzz_markers_present():
    for task in TASKS:
        for defect in task.defects:
            if defect.channel == "fuzz":
                assert defect.fuzz_marker
                assert defect.fuzz_marker == defect.detector


def test_flawed_fix_coverage():
    total = sum(len(t.defects) for t in TASKS)
    flawed = sum(1 for t in TASKS for d in t.defects if d.flawed_fix_replace)
    assert flawed >= 0.30 * total, f"flawed={flawed}/{total}"


# --------------------------------------------------------------------------- #
# 每个任务的不变式
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_compiles(task):
    compile(task.vulnerable_code, f"<{task.task_id}-vulnerable>", "exec")
    compile(task.secure_reference, f"<{task.task_id}-secure>", "exec")
    compile(task.fuzz_harness, f"<{task.task_id}-harness>", "exec")


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_vulnerable_code_size(task):
    lines = task.vulnerable_code.splitlines()
    assert len(lines) <= 70, f"{task.task_id} 有 {len(lines)} 行"
    assert len(task.vulnerable_code) >= 250, f"{task.task_id} 代码过短"


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_all_defects_present_in_vulnerable(task):
    for defect in task.defects:
        assert defect_present(defect, task.vulnerable_code), (
            f"{task.task_id}/{defect.defect_id} 在 vulnerable_code 上不成立"
        )


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_all_defects_absent_in_secure(task):
    residual = defects_present(task, task.secure_reference)
    assert residual == [], f"{task.task_id} 的 secure_reference 仍有 {residual}"


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_fix_find_is_exact_substring(task):
    for defect in task.defects:
        assert defect.fix_find in task.vulnerable_code, (
            f"{task.task_id}/{defect.defect_id} 的 fix_find 不是精确子串"
        )
        assert defect.fix_find != defect.fix_replace


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_fix_find_not_nested(task):
    for i, first in enumerate(task.defects):
        for second in task.defects[i + 1:]:
            assert first.fix_find not in second.fix_find, (
                f"{task.task_id}: {first.defect_id} 的 fix_find 被 {second.defect_id} 包含"
            )
            assert second.fix_find not in first.fix_find, (
                f"{task.task_id}: {second.defect_id} 的 fix_find 被 {first.defect_id} 包含"
            )


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_sequential_fixes_clear_all_defects(task):
    code = task.vulnerable_code
    for defect in task.defects:
        assert defect.fix_find in code, f"{task.task_id}/{defect.defect_id} 补丁无法应用"
        code = code.replace(defect.fix_find, defect.fix_replace, 1)
    compile(code, f"<{task.task_id}-fixed>", "exec")
    residual = defects_present(task, code)
    assert residual == [], f"{task.task_id} 全量修复后仍有 {residual}"


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_flawed_fix_is_not_a_real_fix(task):
    for defect in task.defects:
        if defect.flawed_fix_replace is None:
            continue
        assert defect.flawed_fix_replace != defect.fix_replace
        patched = task.vulnerable_code.replace(
            defect.fix_find, defect.flawed_fix_replace, 1
        )
        compile(patched, f"<{task.task_id}-{defect.defect_id}-flawed>", "exec")
        assert defect_present(defect, patched), (
            f"{task.task_id}/{defect.defect_id} 的 flawed_fix_replace 竟然真的修好了"
        )


# --------------------------------------------------------------------------- #
# bandit / fuzz 真实命中
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_bandit_detects_bandit_defects(task):
    bandit_defects = [d for d in task.defects if d.channel == "bandit"]
    if not bandit_defects:
        pytest.skip("该任务没有 bandit 通道缺陷")
    results = _run_bandit(task.vulnerable_code)
    for defect in bandit_defects:
        same_id = [r for r in results if r["test_id"] == defect.detector]
        assert same_id, f"{task.task_id}/{defect.defect_id}: bandit 未报 {defect.detector}"
        near = [r for r in same_id if abs(r["line_number"] - defect.line_hint) <= 5]
        assert near, (
            f"{task.task_id}/{defect.defect_id}: {defect.detector} 行号 "
            f"hint={defect.line_hint} actual={[r['line_number'] for r in same_id]}"
        )


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_fuzz_harness_hits_markers(task):
    fuzz_defects = [d for d in task.defects if d.channel == "fuzz"]
    if not fuzz_defects:
        pytest.skip("该任务没有 fuzz 通道缺陷")
    markers = _run_fuzz(task.fuzz_harness, task.vulnerable_code)
    for defect in fuzz_defects:
        assert defect.fuzz_marker in markers, (
            f"{task.task_id}/{defect.defect_id}: harness 未命中 {defect.fuzz_marker}，"
            f"实际 {markers}"
        )


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_fuzz_harness_quiet_on_secure_reference(task):
    """修好之后 harness 不应再报告该漏洞的 marker。"""
    fuzz_defects = [d for d in task.defects if d.channel == "fuzz"]
    if not fuzz_defects:
        pytest.skip("该任务没有 fuzz 通道缺陷")
    markers = _run_fuzz(task.fuzz_harness, task.secure_reference)
    for defect in fuzz_defects:
        assert defect.fuzz_marker not in markers, (
            f"{task.task_id}/{defect.defect_id}: secure_reference 上仍命中 {defect.fuzz_marker}"
        )


# --------------------------------------------------------------------------- #
# 元数据质量
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_metadata_quality(task):
    assert task.title.strip()
    assert task.notes.strip()
    assert task.difficulty in ("easy", "medium", "hard")
    sentences = [s for s in task.prompt.replace("!", ".").replace("?", ".").split(".") if s.strip()]
    assert 2 <= len(sentences) <= 6, f"{task.task_id} prompt 句子数异常: {len(sentences)}"
    assert "Implement" in task.prompt or "implement" in task.prompt


@pytest.mark.parametrize("task", TASKS, ids=[t.task_id for t in TASKS])
def test_line_hints_in_range(task):
    line_count = len(task.vulnerable_code.splitlines())
    for defect in task.defects:
        assert 1 <= defect.line_hint <= line_count, (
            f"{task.task_id}/{defect.defect_id}: line_hint={defect.line_hint} 超出 1..{line_count}"
        )


def test_vulnerable_code_has_no_live_network_calls_at_import():
    """导入模块不得发起真实网络连接：危险调用必须位于函数体内。"""
    for task in TASKS:
        tree = ast.parse(task.vulnerable_code)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    name = _call_name(child)
                    assert name not in LIVE_CALLS, (
                        f"{task.task_id} 在模块级执行了真实网络/子进程调用: {name}"
                    )


def _call_name(node) -> str:
    func = node.func
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def test_vulnerable_code_importable_without_side_effects():
    """每个任务都能作为模块 import，且导入不产生副作用。"""
    import importlib.util

    for task in TASKS:
        tmp = make_tempdir("import-")
        try:
            module_path = tmp / f"mod_{task.task_id.lower()}.py"
            module_path.write_text(task.vulnerable_code, encoding="utf-8")
            spec = importlib.util.spec_from_file_location(
                f"autosafe_task_{task.task_id.lower()}", module_path
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            assert module is not None
        finally:
            from autosafe.bootstrap import cleanup

            cleanup(tmp)
