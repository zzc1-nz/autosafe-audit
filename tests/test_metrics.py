"""核心分析自测：合成曲线覆盖拐点判定的各种形状。"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from autosafe.metrics import (  # noqa: E402
    aggregate_curve,
    analyze,
    find_knee,
    recommend_depth,
    summary,
)


# ---------------------------------------------------------------- 曲线工厂
def make_curve(points: list[tuple[int, int, int]]) -> list[dict]:
    """points: [(round, round_tokens, round_fixed)] → 曲线（带累计与边际）。"""
    out = []
    cum_t = cum_f = 0
    prev_t = prev_f = 0
    for r, rt, rf in points:
        cum_t += rt
        cum_f += rf
        d_t = cum_t - prev_t
        d_f = cum_f - prev_f
        out.append({
            "round": r,
            "cum_tokens": cum_t,
            "cum_fixed": cum_f,
            "round_tokens": rt,
            "round_fixed": rf,
            "marginal_per_100k": round(d_f / d_t * 100_000, 4) if d_t else 0.0,
            "avg_fixed_per_100k": round(cum_f / cum_t * 100_000, 4) if cum_t else 0.0,
            "n_tasks": 25,
        })
        prev_t, prev_f = cum_t, cum_f
    return out


def make_run(task_id, family, difficulty, rounds, total_defects=3, fixed=None):
    """造一个符合 schema.to_dict() 形状的 run。"""
    out_rounds = []
    cum_t = cum_f = 0
    for i, (rt, rf) in enumerate(rounds, 1):
        cum_t += rt
        cum_f += rf
        out_rounds.append({
            "task_id": task_id, "round_index": i,
            "tokens_in": int(rt * 0.65), "tokens_out": rt - int(rt * 0.65),
            "tokens_by_agent": {"coding": rt // 3, "static": rt // 3, "fuzzing": rt - 2 * (rt // 3)},
            "defects_found": 1 if rf else 0, "defects_fixed": rf,
            "defects_open": max(0, total_defects - cum_f), "defects_known": cum_f,
            "newly_found_ids": [], "newly_fixed_ids": [f"D{j}" for j in range(rf)],
            "bandit_findings": 2, "fuzz_markers": 1, "noise_findings": 1,
            "duplicate_findings": 0,
            "cumulative_tokens": cum_t, "cumulative_fixed": cum_f,
            "stopped_reason": "", "tokens_total": rt,
        })
    return {
        "task_id": task_id, "family": family, "difficulty": difficulty,
        "rounds": out_rounds, "final_code": "",
        "residual_defect_ids": [], "undetected_defect_ids": [],
        "total_defects": total_defects,
        "total_tokens": cum_t, "total_fixed": cum_f,
        "total_found": cum_f, "rounds_used": len(rounds), "stop_reason": "max_rounds",
    }


def make_experiment() -> dict:
    runs = []
    fams = ["injection", "authz", "crypto"]
    for i in range(6):
        fam = fams[i % 3]
        runs.append(make_run(
            f"T{i:02d}", fam, "easy" if i % 2 else "hard",
            [(4000, 2), (4500, 1), (5000, 0), (5500, 0)],
        ))
    return {"meta": {"provider": "simulated", "model": "sim", "max_rounds": 4,
                     "task_count": len(runs), "seed": 7}, "runs": runs}


# ---------------------------------------------------------------- 拐点判定
def test_knee_monotonic_decreasing():
    """单调递减曲线：最后一个高于阈值的轮次 + 1 即拐点。"""
    # 边际: r1=2/4000*1e5=50, r2=1/4500=22.2, r3=0, r4=0
    curve = make_curve([(1, 4000, 2), (2, 4500, 1), (3, 5000, 0), (4, 5500, 0)])
    k = find_knee(curve)
    assert k["method"] == "observed"
    assert k["observed"] is True
    assert k["crossed"] is True
    assert k["knee_round"] == 3
    assert k["first_below_round"] == 3


def test_knee_all_below_threshold_from_start():
    """第一轮就低于阈值 → 拐点=第 1 轮。"""
    curve = make_curve([(1, 1_000_000, 0), (2, 1_000_000, 0)])
    k = find_knee(curve)
    assert k["observed"] is True
    assert k["knee_round"] == 1


def test_knee_non_monotonic_rebound():
    """中途反弹：拐点必须落在反弹**之后**，不能把反弹前的高收益轮次当拐点。"""
    # 边际: r1=50, r2=0(低于阈值), r3=50(反弹), r4=0, r5=0
    curve = make_curve([
        (1, 4000, 2),        # 50
        (2, 1_000_000, 0),   # 0     ← 首次低于
        (3, 4000, 2),        # 50    ← 反弹
        (4, 1_000_000, 0),   # 0
        (5, 1_000_000, 0),   # 0
    ])
    k = find_knee(curve)
    assert k["first_below_round"] == 2
    # 第 2 轮不能当拐点（因为紧接着就反弹了）；从第 4 轮起尾部无高值 → 拐点=4
    assert k["observed"] is True
    assert k["knee_round"] == 4
    assert k["knee_round"] > 3, "拐点必须晚于最后一次反弹"


def test_knee_tolerates_single_tail_rebound():
    """尾部孤立反弹（长尾缺陷很晚才修好）不应让拐点被判为未到达。

    这是真实数据里出现的情形（主实验实测）：
    边际 26.60 → 7.75 → 7.97 → 8.97 → 3.71 → 1.91 → 0.00 → **1.90（末轮反弹）**
    第 7 轮严格为 0，第 8 轮因一个长尾缺陷终于修好而反弹。
    拐点应被识别为第 7 轮，而不是"未到达"。
    """
    curve = make_curve([
        (1, 4000, 2),        # 50
        (2, 20_000, 1),      # 5
        (3, 20_000, 0),      # 0
        (4, 20_000, 0),      # 0  ← 拐点
        (5, 20_000, 0),      # 0
        (6, 20_000, 1),      # 5  末轮孤立反弹（长尾，允许）
    ])
    k = find_knee(curve)
    assert k["method"] == "observed"
    # 判据取"最早满足条件"的轮次：从第 3 轮起尾部只有第 6 轮一次末轮反弹，故拐点=3
    assert k["knee_round"] == 3
    assert k["isolated_rebounds"] == [6]


def test_knee_real_shape_from_main_experiment():
    """用主实验的真实边际序列回归测试：必须识别出第 7 轮。"""
    margs = [26.60, 7.75, 7.97, 8.97, 3.71, 1.91, 0.00, 1.90]
    curve = make_curve([(i + 1, 50_000, 0) for i in range(len(margs))])
    for i, m in enumerate(margs):
        curve[i]["marginal_per_100k"] = m
    k = find_knee(curve)
    assert k["method"] == "observed", f"应观测到拐点，实际 {k['method']}"
    assert k["knee_round"] == 7
    assert k["isolated_rebounds"] == [8]


def test_knee_multiple_tail_rebounds_not_a_knee():
    """尾部多次反弹（不是孤立事件）则不应判为拐点。"""
    curve = make_curve([
        (1, 4000, 2),        # 50
        (2, 20_000, 1),      # 5
        (3, 20_000, 0),      # 0
        (4, 4000, 2),        # 50 反弹
        (5, 20_000, 0),      # 0
        (6, 4000, 2),        # 50 反弹（第二次，非孤立）
    ])
    k = find_knee(curve)
    # 允许 1 次孤立反弹时，从第 4 轮起尾部有 2 次高于阈值 → 不是拐点
    assert k["knee_round"] != 4


def test_knee_reports_all_three_criteria():
    """三个判据（持续低于/尾部平均/相对阈值）都应给出结果。"""
    curve = make_curve([(1, 4000, 2), (2, 4500, 1), (3, 5000, 0), (4, 5500, 0)])
    k = find_knee(curve)
    for f in ("knee_round", "tail_avg_knee_round", "relative_knee_round",
              "first_below_round", "isolated_rebounds", "tail_marginal_series"):
        assert f in k, f"缺少判据字段 {f}"
    assert k["tail_avg_knee_round"] is not None
    assert len(k["tail_marginal_series"]) == len(curve)


def test_knee_extrapolation_when_never_crossed():
    """从未穿越但趋势显著下降 → 外推分支。"""
    # 每轮固定 4000 token，修复数 3,2,1（边际 75,50,25 都 > 0.1）
    # 改用大 token 让边际逐轮下降并逼近阈值
    curve = make_curve([(1, 100_000, 8), (2, 100_000, 6), (3, 100_000, 4), (4, 100_000, 3)])
    k = find_knee(curve, threshold_per_100k=0.1)
    assert k["method"] in {"loglinear_extrapolation", "not_reached"}
    if k["method"] == "loglinear_extrapolation":
        assert k["observed"] is False
        assert k["crossed"] is False
        assert k["interpolated_round"] is not None
        assert k["interpolated_round"] >= 1


def test_knee_not_reached_flat():
    """水平无趋势曲线 → not_reached。"""
    curve = make_curve([(1, 4000, 5), (2, 4000, 5), (3, 4000, 5), (4, 4000, 5)])
    k = find_knee(curve)
    assert k["method"] == "not_reached"
    assert k["knee_round"] is None
    assert k["crossed"] is False


def test_knee_empty_curve():
    k = find_knee([])
    assert k["n_rounds"] == 0
    assert k["method"] == "not_reached"


def test_knee_series_length_matches():
    curve = make_curve([(1, 4000, 2), (2, 4000, 1)])
    k = find_knee(curve)
    assert len(k["marginal_series"]) == len(curve) == k["n_rounds"]


# ---------------------------------------------------------------- 聚合
def test_aggregate_curve_sums_across_tasks():
    exp = make_experiment()
    curve = aggregate_curve(exp["runs"])
    assert len(curve) == 4
    assert curve[0]["cum_tokens"] == 4000 * 6
    assert curve[0]["cum_fixed"] == 2 * 6
    assert curve[-1]["cum_tokens"] == (4000 + 4500 + 5000 + 5500) * 6
    # 累计必须单调不减
    for a, b in zip(curve, curve[1:]):
        assert b["cum_tokens"] >= a["cum_tokens"]
        assert b["cum_fixed"] >= a["cum_fixed"]


def test_aggregate_curve_handles_different_lengths():
    runs = [
        make_run("A", "injection", "easy", [(4000, 2), (4500, 1)]),
        make_run("B", "authz", "hard", [(5000, 1)]),
    ]
    curve = aggregate_curve(runs)
    assert len(curve) == 2
    # 第 2 轮：B 已收敛，沿用其最终值；n_tasks 记录"仍活跃"的任务数
    assert curve[1]["n_tasks"] == 1
    assert curve[1]["n_tasks_total"] == 2


def test_aggregate_curve_always_monotonic():
    """累计曲线必须单调不减（已花的 token 不会退回来）。

    真实数据里任务会提前收敛，如果只对"还活着"的任务求和，总累计会下降，
    产生负边际收益——那既不符合现实，也会让 log 外推崩溃。此测试锁定该口径。
    """
    runs = [
        make_run("A", "injection", "easy", [(4000, 2), (4500, 1), (5000, 0)]),
        make_run("B", "authz", "hard", [(5000, 1)]),                     # 只跑 1 轮
        make_run("C", "crypto", "medium", [(6000, 1), (6000, 0)]),       # 只跑 2 轮
    ]
    curve = aggregate_curve(runs)
    assert len(curve) == 3
    for a, b in zip(curve, curve[1:]):
        assert b["cum_tokens"] >= a["cum_tokens"], "累计 token 出现下降"
        assert b["cum_fixed"] >= a["cum_fixed"], "累计修复数出现下降"
        assert b["delta_tokens"] >= 0
        assert b["delta_fixed"] >= 0
        assert b["marginal_per_100k"] >= 0


def test_find_knee_survives_negative_raw_marginal():
    """防御性测试：即使外部传入含负边际的曲线，也不能抛异常。"""
    curve = make_curve([(1, 4000, 2), (2, 4000, 0)])
    curve[1]["marginal_per_100k"] = -3.5     # 人为注入负值
    k = find_knee(curve)                     # 不应抛 ValueError
    assert "knee_round" in k


# ---------------------------------------------------------------- 建议深度
def test_recommend_depth_covers_all_families():
    exp = make_experiment()
    rows = recommend_depth(exp["runs"])
    fams = {r["family"] for r in exp["runs"]}
    assert {r["family"] for r in rows} == fams
    for r in rows:
        assert 1 <= r["recommended_depth"] <= 8
        assert r["rationale"]
        assert r["tasks"] >= 1
        assert r["rounds_to_90pct"] >= 1


def test_recommend_depth_prefers_early_stop_for_fast_families():
    """一轮就修完的 family，建议深度应很小。"""
    runs = [make_run(f"A{i}", "config", "easy", [(4000, 3), (4000, 0), (4000, 0)]) for i in range(3)]
    rows = recommend_depth(runs)
    assert rows[0]["recommended_depth"] <= 2


# ---------------------------------------------------------------- 汇总
def test_summary_totals():
    exp = make_experiment()
    s = summary(exp["runs"])
    assert s["tasks"] == 6
    assert s["total_tokens"] == sum(r["total_tokens"] for r in exp["runs"])
    assert s["total_fixed"] == sum(r["total_fixed"] for r in exp["runs"])
    assert s["tokens_per_fix"] > 0
    assert 0 <= s["fix_rate"] <= 1


def test_analyze_outputs_contract_keys():
    """analyze() 必须输出契约 §7.1 规定的顶层 key。"""
    result = analyze(make_experiment())
    for key in ("meta", "summary", "curve", "families", "knee", "family_knees",
                "depth_recommendations", "channel_breakdown", "difficulty_breakdown",
                "sensitivity"):
        assert key in result, f"缺少契约 key: {key}"
    assert set(result["sensitivity"]) == {"0.05", "0.1", "0.2"}
    # 必须可 JSON 序列化（无 numpy 类型泄漏）
    json.dumps(result, ensure_ascii=False)


def test_analyze_curve_has_required_fields():
    result = analyze(make_experiment())
    for p in result["curve"]:
        for f in ("round", "cum_tokens", "cum_fixed", "round_tokens", "round_fixed",
                  "marginal_per_100k", "avg_fixed_per_100k", "n_tasks"):
            assert f in p, f"curve 缺少字段 {f}"
