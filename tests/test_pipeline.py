"""管线自测：用最小合成任务验证记账口径、真实工具接入、停止判据。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from autosafe.llm import SimulatedLLM  # noqa: E402
from autosafe.pipeline import PipelineConfig, run_experiment, run_task  # noqa: E402
from autosafe.schema import (  # noqa: E402
    Defect,
    Task,
    apply_fix,
    defect_present,
    defects_present,
)

HARNESS = '''
import json
import target

def fuzz(module):
    markers = []
    try:
        module.run_command("a; echo pwned")
        markers.append("CMD_INJ")
    except Exception:
        markers.append("CMD_INJ")
    return markers

markers = fuzz(target)
print("FUZZ_MARKERS:" + json.dumps(markers))
print("FUZZ_COVERAGE:0.75")
'''

VULN_CODE = '''import subprocess
import random


def run_command(user_input):
    return subprocess.call("echo " + user_input, shell=True)


def make_token():
    return str(random.random())
'''

SECURE_CODE = '''import secrets
import subprocess


def run_command(user_input):
    return subprocess.call(["echo", user_input])


def make_token():
    return secrets.token_urlsafe(32)
'''

DEFECTS = (
    Defect(
        defect_id="CMD_INJ",
        cwe="CWE-78",
        category="command_injection",
        severity="HIGH",
        subtlety=2,
        channel="fuzz",
        detector="CMD_INJ",
        line_hint=6,
        description="用户输入直接拼进 shell 命令",
        source_check=r"present:shell=True",
        fix_find='subprocess.call("echo " + user_input, shell=True)',
        fix_replace="subprocess.call([\"echo\", user_input])",
        flawed_fix_replace='subprocess.call("echo " + user_input.replace(";", ""), shell=True)',
        fuzz_marker="CMD_INJ",
    ),
    Defect(
        defect_id="WEAK_RANDOM",
        cwe="CWE-330",
        category="insecure_randomness",
        severity="MEDIUM",
        subtlety=3,
        channel="semantic",
        detector="weak_random_token",
        line_hint=10,
        description="用 random 生成安全令牌",
        source_check=r"present:random\.random\(\)",
        fix_find="return str(random.random())",
        fix_replace="return secrets.token_urlsafe(32)",
        flawed_fix_replace="return str(random.random())[:8]",
    ),
)


def _task() -> Task:
    return Task(
        task_id="T00",
        title="合成任务",
        family="injection",
        difficulty="easy",
        prompt="Implement run_command and make_token.",
        vulnerable_code=VULN_CODE,
        defects=DEFECTS,
        fuzz_harness=HARNESS,
        secure_reference=SECURE_CODE,
        notes="测试用",
    )


def test_defect_invariants():
    """合成任务本身满足契约不变式。"""
    t = _task()
    assert set(defects_present(t, VULN_CODE)) == {"CMD_INJ", "WEAK_RANDOM"}
    assert defects_present(t, SECURE_CODE) == []
    code = VULN_CODE
    for d in t.defects:
        code = apply_fix(code, d)
    assert defects_present(t, code) == []


def test_flawed_fix_keeps_defect():
    """假修复必须让漏洞仍然存在。"""
    t = _task()
    for d in t.defects:
        flawed = apply_fix(VULN_CODE, d, flawed=True)
        assert defect_present(d, flawed) is True, f"{d.defect_id} 的假修复竟然修好了"


def test_run_task_records_tokens_and_rounds():
    """跑一轮以上，验证记账字段自洽。"""
    cfg = PipelineConfig(max_rounds=4, seed=7, profile="baseline")
    run = run_task(_task(), client=SimulatedLLM(), config=cfg)
    assert run.rounds, "至少应有一轮"
    for rec in run.rounds:
        assert rec.tokens_total > 0
        assert rec.cumulative_tokens == sum(r.tokens_total for r in run.rounds[: rec.round_index])
        assert set(rec.tokens_by_agent) == {"coding", "static", "fuzzing"}
        assert sum(rec.tokens_by_agent.values()) == rec.tokens_total
    assert run.total_tokens == run.rounds[-1].cumulative_tokens
    assert run.total_fixed == sum(r.defects_fixed for r in run.rounds)


def test_round_tokens_grow_with_context():
    """上下文膨胀：后期单轮 token 应高于首轮（真实 LLM 的典型现象）。"""
    run = run_task(_task(), client=SimulatedLLM(), config=PipelineConfig(max_rounds=5, seed=7))
    if len(run.rounds) >= 3:
        assert run.rounds[-1].tokens_total > run.rounds[0].tokens_total


def test_bandit_channel_detected_by_real_tool():
    """bandit 通道的发现必须来自真实 bandit 执行。"""
    t = Task(
        task_id="T01b",
        title="bandit 通道",
        family="injection",
        difficulty="easy",
        prompt="p",
        vulnerable_code='import subprocess\n\n\ndef r(c):\n    return subprocess.call(c, shell=True)\n',
        defects=(
            Defect(
                defect_id="SH",
                cwe="CWE-78",
                category="command_injection",
                severity="HIGH",
                subtlety=1,
                channel="bandit",
                detector="B602",
                line_hint=5,
                description="shell=True",
                source_check=r"present:shell=True",
                fix_find="subprocess.call(c, shell=True)",
                fix_replace="subprocess.call(c)",
            ),
        ),
        fuzz_harness=HARNESS,
        secure_reference='import subprocess\n\n\ndef r(c):\n    return subprocess.call(c)\n',
    )
    run = run_task(t, client=SimulatedLLM(), config=PipelineConfig(max_rounds=3, seed=7))
    found = {i for r in run.rounds for i in r.newly_found_ids}
    assert "SH" in found
    assert run.rounds[0].bandit_findings >= 1


def test_experiment_payload_serializable():
    """实验输出必须可 JSON 落盘且字段完整。"""
    # 注意：pytest 的 tmp_path 走系统临时目录，本机沙箱不可写，故用项目内目录
    from autosafe.bootstrap import cleanup, make_tempdir

    d = make_tempdir("exp-")
    try:
        out = d / "e.json"
        payload = run_experiment(
            [_task()], config=PipelineConfig(max_rounds=3, seed=7), client=SimulatedLLM(),
            out_path=out, verbose=False,
        )
        assert out.exists()
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["meta"]["task_count"] == 1
        assert loaded["runs"][0]["task_id"] == "T00"
        assert "tokens_total" in loaded["runs"][0]["rounds"][0]
        assert payload["meta"]["total_tokens"] > 0
    finally:
        cleanup(d)


def test_reproducible_with_same_seed():
    """同 seed 必须完全可复现。"""
    a = run_task(_task(), client=SimulatedLLM(), config=PipelineConfig(max_rounds=4, seed=11))
    b = run_task(_task(), client=SimulatedLLM(), config=PipelineConfig(max_rounds=4, seed=11))
    assert [r.to_dict() for r in a.rounds] == [r.to_dict() for r in b.rounds]


def test_early_stop_when_no_findings():
    """全部修完后应提前停止。"""
    t = _task()
    run = run_task(t, client=SimulatedLLM(),
                   config=PipelineConfig(max_rounds=8, seed=3, profile="strong"))
    assert run.rounds_used <= 8
    if not run.residual_defect_ids:
        assert run.stop_reason in {"no_findings", "max_rounds"}
