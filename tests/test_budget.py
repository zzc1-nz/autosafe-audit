"""预算分配自测：三种策略必须都遵守预算约束且投影自洽。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from autosafe.budget import (  # noqa: E402
    compare,
    plan_adaptive,
    plan_breadth,
    plan_depth,
    write_budget,
)


def make_runs(n: int = 10, rounds: int = 6, base_tokens: int = 4000) -> list[dict]:
    """造 n 个任务，每个有 rounds 轮，边际收益递减。"""
    runs = []
    for i in range(n):
        out_rounds = []
        cum_t = cum_f = 0
        for r in range(1, rounds + 1):
            rt = base_tokens + r * 500
            rf = max(0, 3 - (r - 1))          # 3,2,1,0,0,0
            cum_t += rt
            cum_f += rf
            out_rounds.append({
                "task_id": f"T{i:02d}", "round_index": r,
                "tokens_in": int(rt * 0.65), "tokens_out": rt - int(rt * 0.65),
                "tokens_by_agent": {}, "defects_found": 1 if rf else 0,
                "defects_fixed": rf, "defects_open": 0, "defects_known": cum_f,
                "newly_found_ids": [], "newly_fixed_ids": [],
                "bandit_findings": 1, "fuzz_markers": 0, "noise_findings": 0,
                "duplicate_findings": 0,
                "cumulative_tokens": cum_t, "cumulative_fixed": cum_f,
                "stopped_reason": "", "tokens_total": rt,
            })
        runs.append({
            "task_id": f"T{i:02d}", "family": "injection" if i % 2 else "authz",
            "difficulty": "easy", "rounds": out_rounds, "final_code": "",
            "residual_defect_ids": [], "undetected_defect_ids": [],
            "total_defects": 3, "total_tokens": cum_t, "total_fixed": cum_f,
            "total_found": cum_f, "rounds_used": rounds, "stop_reason": "max_rounds",
        })
    return runs


BUDGET = 150_000


def test_all_plans_within_budget():
    runs = make_runs()
    for plan in (plan_breadth(runs, BUDGET), plan_depth(runs, BUDGET),
                 plan_adaptive(runs, BUDGET)):
        assert plan.projected_tokens <= BUDGET, f"{plan.name} 超预算: {plan.projected_tokens}"
        assert all(0 <= v <= 8 for v in plan.allocations.values())


def test_breadth_covers_all_tasks():
    runs = make_runs()
    plan = plan_breadth(runs, BUDGET)
    assert plan.tasks_covered == len(runs)
    assert len(set(plan.allocations.values())) == 1, "广度策略应对所有任务用相同深度"


def test_depth_focuses_few_tasks_deep():
    """深度策略：覆盖任务数应远少于广度策略，且单任务深度明显更高。"""
    runs = make_runs()
    depth = plan_depth(runs, BUDGET, focus_tasks=3)
    breadth = plan_breadth(runs, BUDGET)
    assert depth.tasks_covered < breadth.tasks_covered, "深度策略覆盖应少于广度"
    assert depth.avg_depth > breadth.avg_depth, "深度策略平均深度应高于广度"
    assert max(depth.allocations.values()) >= 3


def test_adaptive_beats_breadth_projection():
    """在收益递减曲线上，自适应应至少不劣于广度。"""
    runs = make_runs()
    breadth = plan_breadth(runs, BUDGET)
    adaptive = plan_adaptive(runs, BUDGET)
    assert adaptive.projected_fixed >= breadth.projected_fixed - 1e-9


def test_prefix_constraint_respected():
    """自适应必须保持轮次前缀连续（不能出现深度 3 但没跑 1、2 轮）。"""
    runs = make_runs()
    plan = plan_adaptive(runs, BUDGET)
    for tid, depth in plan.allocations.items():
        assert isinstance(depth, int)
        assert depth >= 1
        assert depth <= 8


def test_compare_has_vs_breadth():
    runs = make_runs()
    plans = [plan_breadth(runs, BUDGET), plan_depth(runs, BUDGET), plan_adaptive(runs, BUDGET)]
    rows = compare(plans, runs)
    assert len(rows) == 3
    names = {r["name"] for r in rows}
    assert names == {"breadth", "depth", "adaptive"}
    for r in rows:
        assert "vs_breadth_pct" in r
        assert "within_budget" in r
        assert r["projected_cost_per_fix"] is None or r["projected_cost_per_fix"] >= 0
    base = next(r for r in rows if r["name"] == "breadth")
    assert base["vs_breadth_pct"] == 0.0


def test_tiny_budget_still_produces_plan():
    """极小预算：必须优雅降级，不能崩。"""
    runs = make_runs()
    plan = plan_breadth(runs, 100)
    assert plan.projected_tokens <= 100
    assert isinstance(plan.allocations, dict)


def test_write_budget_contract_keys():
    """输出必须符合契约 §7.2 的顶层 key。"""
    from autosafe.bootstrap import cleanup, make_tempdir

    runs = make_runs()
    plans = [plan_breadth(runs, BUDGET), plan_depth(runs, BUDGET), plan_adaptive(runs, BUDGET)]
    d = make_tempdir("budget-")
    try:
        out = d / "b.json"
        payload = write_budget(plans, runs, out, budget=BUDGET)
        assert set(payload) == {"meta", "plans", "comparison"}
        assert set(payload["meta"]) >= {"generated_at", "budget", "source_run"}
        for p in payload["plans"]:
            for f in ("name", "label", "allocations", "projected_tokens", "projected_fixed",
                      "tasks_covered", "avg_depth", "within_budget", "rationale"):
                assert f in p, f"plans 缺少字段 {f}"
        for c in payload["comparison"]:
            for f in ("name", "projected_tokens", "projected_fixed", "projected_cost_per_fix",
                      "tasks_covered", "avg_depth", "vs_breadth_pct"):
                assert f in c, f"comparison 缺少字段 {f}"
        json.dumps(payload, ensure_ascii=False)
    finally:
        cleanup(d)


def test_no_observed_data_beyond_window():
    """不能编造观测范围之外的轮次。"""
    runs = make_runs(n=3, rounds=2)
    plan = plan_adaptive(runs, 10_000_000)
    for tid, depth in plan.allocations.items():
        assert depth <= 2
