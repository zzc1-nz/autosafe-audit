"""分析器自测：bandit 真实扫描 + 子进程 fuzz 执行器。

运行（项目根）：
    python -m pytest tests/test_analyzers.py -q
若 ``autosafe`` 不在 sys.path：``$env:PYTHONPATH='src'``。
"""
from __future__ import annotations

import contextlib
import sys
import time
from pathlib import Path

# 允许从项目根直接跑 pytest（不依赖外部 PYTHONPATH 配置）
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import pytest  # noqa: E402

from autosafe.analyzers import bandit_runner, fuzzer  # noqa: E402
from autosafe.analyzers.bandit_runner import (  # noqa: E402
    StaticFinding,
    clear_cache,
    detect_map,
    scan,
    scan_bandit,
    semantic_findings,
)
from autosafe.analyzers.fuzzer import FuzzResult, run_fuzz  # noqa: E402
from autosafe.schema import Defect  # noqa: E402

# --------------------------------------------------------------------------- #
# 测试夹具
# --------------------------------------------------------------------------- #

VULNERABLE_CODE = '''\
import subprocess


def run_command(cmd):
    """直接执行外部命令。"""
    subprocess.call(cmd, shell=True)


def find_user(conn, name):
    """按用户名查询。"""
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query)
'''

CLEAN_CODE = '''\
def add(a, b):
    """两数相加。"""
    return a + b


def greet(name):
    return "hello, " + str(name)
'''


def make_defect(
    defect_id: str = "D1",
    *,
    detector: str = "B608",
    line_hint: int = 10,
    channel: str = "bandit",
    severity: str = "HIGH",
    cwe: str = "CWE-89",
    description: str = "SQL 注入",
) -> Defect:
    """构造一个测试用 Defect（满足 schema 的字段约束）。"""
    return Defect(
        defect_id=defect_id,
        cwe=cwe,
        category="injection",
        severity=severity,
        subtlety=2,
        channel=channel,
        detector=detector,
        line_hint=line_hint,
        description=description,
        source_check="present:subprocess\\.call",
        fix_find="subprocess.call(cmd, shell=True)",
        fix_replace="subprocess.call([cmd])",
        flawed_fix_replace="subprocess.call(cmd)",
        fuzz_marker=None,
    )


@contextlib.contextmanager
def track_tempdirs():
    """记录本模块分析器创建的全部临时目录，用于精确检测泄漏。

    注意：``build_tmp/`` 是**全队共享**的（其他成员的测试也会在里面建目录），
    所以不能靠"目录总数前后一致"判断泄漏——必须跟踪自己实际创建的路径。
    这里临时替换 ``bandit_runner``/``fuzzer`` 模块内的 ``make_tempdir`` 引用。
    """
    created: list[Path] = []
    originals = {}
    for module in (bandit_runner, fuzzer):
        original = module.make_tempdir
        originals[module] = original

        def wrapper(prefix: str = "autosafe-", _original=original) -> Path:
            path = _original(prefix)
            created.append(path)
            return path

        module.make_tempdir = wrapper  # type: ignore[assignment]
    try:
        yield created
    finally:
        for module, original in originals.items():
            module.make_tempdir = original  # type: ignore[assignment]


def leaked(created: list[Path]) -> list[str]:
    """返回仍然存在的临时目录名。"""
    return [p.name for p in created if p.exists()]



# --------------------------------------------------------------------------- #
# bandit 通道
# --------------------------------------------------------------------------- #
def test_scan_bandit_detects_b602_and_b608():
    """含 shell=True 与字符串拼接 SQL 的代码应命中 B602 与 B608。"""
    findings = scan_bandit(VULNERABLE_CODE)
    ids = {f.test_id for f in findings}
    assert "B602" in ids, f"未命中 B602，实际: {sorted(ids)}"
    assert "B608" in ids, f"未命中 B608，实际: {sorted(ids)}"
    for f in findings:
        assert f.source == "bandit"
        assert f.line >= 1
        assert f.severity
        assert f.confidence
    # 按行号升序
    assert [f.line for f in findings] == sorted(f.line for f in findings)
    # (test_id, line) 去重
    keys = [(f.test_id, f.line) for f in findings]
    assert len(keys) == len(set(keys))


def test_scan_bandit_clean_code_returns_empty():
    """干净代码不应产生任何 finding。"""
    assert scan_bandit(CLEAN_CODE) == []


def test_scan_bandit_timeout_returns_empty_without_raising():
    """bandit 超时必须返回 [] 且不抛异常。"""
    clear_cache()  # 避免命中之前同 code 的缓存（缓存键含 timeout，这里仍然显式清一次）
    started = time.perf_counter()
    findings = scan_bandit(VULNERABLE_CODE, timeout_s=0.001)
    elapsed = time.perf_counter() - started
    assert findings == []
    assert elapsed < 30.0


def test_scan_bandit_empty_and_garbage_input_returns_empty():
    """空代码 / 非 str 输入返回 []，不抛异常。"""
    assert scan_bandit("") == []
    assert scan_bandit("   \n\n") == []
    assert scan_bandit(None) == []  # type: ignore[arg-type]


def test_scan_bandit_caches_repeated_scan():
    """同一代码重复扫描应走缓存，显著快于首次。"""
    clear_cache()
    t0 = time.perf_counter()
    first = scan_bandit(VULNERABLE_CODE)
    first_elapsed = time.perf_counter() - t0
    t1 = time.perf_counter()
    second = scan_bandit(VULNERABLE_CODE)
    second_elapsed = time.perf_counter() - t1
    assert first == second
    assert second_elapsed < first_elapsed
    assert bandit_runner._CACHE.hits >= 1
    clear_cache()


def test_scan_bandit_does_not_leak_tempdirs():
    """扫描自己创建的临时目录必须被清理（build_tmp 全队共享，只看自己建的）。"""
    with track_tempdirs() as created:
        scan_bandit(VULNERABLE_CODE + "\n# leak check\n")
    assert created, "未观察到临时目录创建，泄漏检查失效"
    assert leaked(created) == [], f"临时目录泄漏: {leaked(created)}"


# --------------------------------------------------------------------------- #
# detect_map
# --------------------------------------------------------------------------- #
def test_detect_map_line_tolerance():
    """行号 ±5 内匹配；超窗的 finding 视为噪声。"""
    defect = make_defect("D1", line_hint=10)
    findings = [
        StaticFinding("B608", 12, "HIGH", "HIGH", "near", "CWE-89", "bandit"),
        StaticFinding("B608", 40, "HIGH", "HIGH", "far", "CWE-89", "bandit"),
    ]
    assert detect_map(findings, [defect]) == ["D1"]

    # 边界：正好 5 行算命中，6 行不命中
    assert detect_map([StaticFinding("B608", 5, "H", "H", "", None, "bandit")], [defect]) == ["D1"]
    assert detect_map([StaticFinding("B608", 4, "H", "H", "", None, "bandit")], [defect]) == []


def test_detect_map_one_finding_maps_one_defect():
    """2 个同 test_id 的 finding 对 1 个 defect：只匹配一个（一对一）。"""
    defect = make_defect("D1", line_hint=10)
    findings = [
        StaticFinding("B608", 9, "HIGH", "HIGH", "a", "CWE-89", "bandit"),
        StaticFinding("B608", 11, "HIGH", "HIGH", "b", "CWE-89", "bandit"),
    ]
    matched = detect_map(findings, [defect])
    assert matched == ["D1"], f"应只匹配一次，实际: {matched}"
    assert len(matched) == len(set(matched))


def test_detect_map_prefers_nearest_defect():
    """1 个 finding 对 2 个 defect：只取行号最近的那个。"""
    near = make_defect("NEAR", line_hint=11)
    far = make_defect("FAR", line_hint=15)
    finding = StaticFinding("B608", 11, "HIGH", "HIGH", "x", "CWE-89", "bandit")
    assert detect_map([finding], [near, far]) == ["NEAR"]
    assert detect_map([finding], [far, near]) == ["NEAR"]


def test_detect_map_ignores_unknown_detector_and_noise():
    """test_id 不匹配任何 detector 的 finding 不算命中。"""
    defect = make_defect("D1", detector="B608", line_hint=10)
    noise = [
        StaticFinding("B101", 10, "LOW", "HIGH", "assert", None, "bandit"),
        StaticFinding("B404", 10, "LOW", "HIGH", "import subprocess", None, "bandit"),
    ]
    assert detect_map(noise, [defect]) == []
    assert detect_map([], [defect]) == []


# --------------------------------------------------------------------------- #
# 语义通道 + scan()
# --------------------------------------------------------------------------- #
def test_semantic_findings_converts_defects():
    """语义通道缺陷转 finding：test_id 带 SEM_ 前缀、source=semantic、line=line_hint。"""
    defects = [
        make_defect("SEM_01", detector="authz_check", line_hint=7, channel="semantic"),
        make_defect("SEM_02", detector="log_injection", line_hint=13, channel="semantic"),
    ]
    findings = semantic_findings(["SEM_01"], defects, VULNERABLE_CODE)
    assert len(findings) == 1
    f = findings[0]
    assert f.test_id == "SEM_authz_check"
    assert f.source == "semantic"
    assert f.line == 7
    assert f.severity == "HIGH"
    assert f.cwe == "CWE-89"

    # 未知 defect_id 被忽略；重复 id 只出一次
    assert semantic_findings(["NOPE"], defects, "") == []
    assert len(semantic_findings(["SEM_01", "SEM_01"], defects, "")) == 1


def test_scan_returns_findings_and_mapped_ids():
    """便利入口返回 (全部 findings, 命中的 defect_id)。"""
    defect = make_defect("SQLI_01", detector="B608", line_hint=10)
    findings, mapped = scan(VULNERABLE_CODE, defects=[defect])
    assert any(f.test_id == "B608" for f in findings)
    assert mapped == ["SQLI_01"]
    # findings 按行号升序
    assert [f.line for f in findings] == sorted(f.line for f in findings)


def test_scan_merges_semantic_and_bandit_channels():
    """scan() 应把语义 finding 与 bandit finding 合并并按行号排序。"""
    bandit_defect = make_defect("B_01", detector="B608", line_hint=10)
    semantic_defect = make_defect(
        "S_01", detector="authz_check", line_hint=1, channel="semantic", cwe="CWE-862"
    )
    findings, mapped = scan(
        VULNERABLE_CODE,
        defects=[bandit_defect, semantic_defect],
        semantic_ids=["S_01"],
    )
    sources = {f.source for f in findings}
    assert sources == {"bandit", "semantic"}
    assert "S_01" in mapped
    assert "B_01" in mapped
    assert findings[0].line <= findings[-1].line


# --------------------------------------------------------------------------- #
# fuzz 通道
# --------------------------------------------------------------------------- #
NORMAL_HARNESS = '''\
import json
import os
import target


def fuzz(module):
    markers = []
    spy = []

    def fake_run(cmd, *a, **kw):
        spy.append(cmd)
        return 0

    if hasattr(module, "run_command"):
        module.run_command("echo pwned")
        markers.append("CMD_EXEC")
    return markers


def main():
    markers = fuzz(target)
    print("FUZZ_MARKERS:" + json.dumps(markers))
    print("FUZZ_COVERAGE:0.75")


main()
'''

RAISING_HARNESS = '''\
import json
import target


def main():
    raise RuntimeError("harness blew up")


main()
'''

LOOPING_HARNESS = '''\
import target

while True:
    pass
'''

NO_MARKER_HARNESS = '''\
import target

print("hello")
'''


def test_run_fuzz_normal_marker_hit():
    """正常 harness 应命中 marker 并解析显式覆盖率。"""
    result = run_fuzz(NORMAL_HARNESS, VULNERABLE_CODE)
    assert isinstance(result, FuzzResult)
    assert result.ok is True, f"error={result.error!r} stderr={result.stderr[-500:]!r}"
    assert "CMD_EXEC" in result.markers
    assert result.error is None
    assert result.coverage_proxy == pytest.approx(0.75)
    assert result.duration_ms >= 0
    assert "FUZZ_MARKERS:" in result.stdout


def test_run_fuzz_harness_raises_returns_not_ok():
    """harness 抛异常时返回 ok=False + error，不抛异常。"""
    result = run_fuzz(RAISING_HARNESS, CLEAN_CODE)
    assert result.ok is False
    assert result.error
    assert "RuntimeError" in result.error or "exited with code" in result.error
    assert result.coverage_proxy == 0.0


def test_run_fuzz_infinite_loop_times_out_quickly():
    """harness 死循环：timeout_s=1，应在 ~1-3 秒内返回 ok=False。"""
    started = time.perf_counter()
    result = run_fuzz(LOOPING_HARNESS, CLEAN_CODE, timeout_s=1.0)
    elapsed = time.perf_counter() - started
    assert result.ok is False
    assert result.error and "超时" in result.error
    assert 0.5 <= elapsed <= 5.0, f"超时耗时异常: {elapsed:.2f}s"


def test_run_fuzz_target_syntax_error_reports_syntaxerror():
    """target 有 SyntaxError 时必须 ok=False 且 error 含 SyntaxError。"""
    broken_code = "def broken(:\n    return 1\n"
    result = run_fuzz(NORMAL_HARNESS, broken_code)
    assert result.ok is False
    assert result.error is not None
    assert "SyntaxError" in result.error, f"实际 error: {result.error!r}"
    assert result.markers == []


def test_run_fuzz_harness_missing_marker_line_is_not_ok():
    """harness 正常退出但没打印标记行：ok=False。"""
    result = run_fuzz(NO_MARKER_HARNESS, CLEAN_CODE)
    assert result.ok is False
    assert result.error and "FUZZ_MARKERS" in result.error


def test_run_fuzz_coverage_fallback_from_marker_ratio():
    """没有 FUZZ_COVERAGE 行时，用标记命中比例粗估覆盖率。"""
    harness = '''\
import json
import target


def main():
    print("FUZZ_MARKERS:" + json.dumps(["CMD_EXEC"]))


main()
'''
    result = run_fuzz(harness, CLEAN_CODE)
    assert result.ok is True
    assert result.markers == ["CMD_EXEC"]
    assert 0.0 < result.coverage_proxy <= 1.0


def test_run_fuzz_never_leaves_tempdirs():
    """各种失败路径的临时目录都必须清理干净。"""
    with track_tempdirs() as created:
        run_fuzz(NORMAL_HARNESS, VULNERABLE_CODE)
        run_fuzz(RAISING_HARNESS, CLEAN_CODE)
        run_fuzz(LOOPING_HARNESS, CLEAN_CODE, timeout_s=1.0)
        run_fuzz(NORMAL_HARNESS, "def broken(:\n    pass\n")
    assert len(created) == 4, f"预期 4 个临时目录，实际 {len(created)}"
    assert leaked(created) == [], f"临时目录泄漏: {leaked(created)}"


def test_run_fuzz_repeated_calls_no_leak_and_stable_timing():
    """连续 20 次 run_fuzz 不泄漏临时目录、耗时不显著增长。"""
    durations: list[float] = []
    with track_tempdirs() as created:
        for i in range(20):
            t0 = time.perf_counter()
            result = run_fuzz(NORMAL_HARNESS, VULNERABLE_CODE)
            durations.append(time.perf_counter() - t0)
            assert result.ok is True, f"第 {i + 1} 次失败: {result.error!r}"

    assert len(created) == 20, f"预期 20 个临时目录，实际 {len(created)}"
    assert leaked(created) == [], f"20 次调用后临时目录泄漏: {leaked(created)}"
    total = sum(durations)
    assert total < 30.0, f"20 次调用总耗时异常: {total:.2f}s"
    first_half = sum(durations[:10]) / 10
    second_half = sum(durations[10:]) / 10
    # 后半段不应显著变慢（放宽到 3 倍 + 100ms 余量，避免机器抖动误判）
    assert second_half <= first_half * 3 + 0.1, (
        f"重复调用变慢: first={first_half:.3f}s second={second_half:.3f}s"
    )


# --------------------------------------------------------------------------- #
# 输出截断
# --------------------------------------------------------------------------- #
def test_run_fuzz_clips_long_output():
    """超长输出必须被截断到 4000 字符以内。"""
    harness = '''\
import target

print("x" * 20000)
print('FUZZ_MARKERS:["BIG"]')
'''
    result = run_fuzz(harness, CLEAN_CODE)
    assert result.ok is True
    assert len(result.stdout) <= fuzzer.MAX_OUTPUT_CHARS
    assert len(result.stderr) <= fuzzer.MAX_OUTPUT_CHARS
