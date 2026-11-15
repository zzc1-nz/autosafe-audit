"""plotting.py / report.py 自测：用合成 fixture 跑通 5 张图与 REPORT.md。

fixture 的 dict 形状**严格按 docs/CONTRACT.md §6 / §7.1 / §7.2**，因此这份测试同时也是
"T4 是否遵守契约"的守门测试。

注意（本机沙箱）：
* 不能用 pytest 的 ``tmp_path``（PermissionError），统一用 ``autosafe.bootstrap.make_tempdir()``。
* 跑法：``python run_tests.py tests/test_plotting.py -q``
"""
from __future__ import annotations

import math
import random
from pathlib import Path

import pytest

from autosafe import bootstrap, plotting, report
from autosafe.schema import FAMILIES, FAMILY_LABELS

FAMILY_SIZES = {
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
MAX_ROUNDS = 8


# ---------------------------------------------------------------- fixture 构造

def _build_runs(seed: int = 7) -> list[dict]:
    """构造 25 个任务 × 最多 8 轮的 TaskRun dict（形状 = schema.TaskRun.to_dict()）。"""
    rng = random.Random(seed)
    runs: list[dict] = []
    tid = 0
    for family in FAMILIES:
        for _ in range(FAMILY_SIZES[family]):
            tid += 1
            task_id = f"T{tid:02d}"
            difficulty = rng.choice(["easy", "medium", "hard"])
            total_defects = rng.randint(2, 4)
            rounds: list[dict] = []
            cum_tok = cum_fixed = 0
            open_defects = total_defects
            fixed_total = 0
            for r in range(1, MAX_ROUNDS + 1):
                base_tok = 2600 + 420 * (r - 1) + rng.randint(-160, 160)
                round_tok = max(800, base_tok)
                # 修复数逐轮衰减：早期多、后期少（这正是边际收益递减的来源）
                rate = 1.0 / (1.0 + 0.85 * (r - 1))
                potential = open_defects * rate * rng.uniform(0.35, 1.0)
                round_fixed = min(open_defects, int(round(potential)))
                if r >= 3 and rng.random() < 0.35:
                    round_fixed = 0
                open_defects -= round_fixed
                fixed_total += round_fixed
                cum_tok += round_tok
                cum_fixed += round_fixed
                rounds.append(
                    {
                        "task_id": task_id,
                        "round_index": r,
                        "tokens_in": int(round_tok * 0.72),
                        "tokens_out": round_tok - int(round_tok * 0.72),
                        "tokens_total": round_tok,
                        "tokens_by_agent": {
                            "coding": int(round_tok * 0.5),
                            "static": int(round_tok * 0.32),
                            "fuzzing": round_tok - int(round_tok * 0.5) - int(round_tok * 0.32),
                        },
                        "defects_found": round_fixed if round_fixed else 0,
                        "defects_fixed": round_fixed,
                        "defects_open": open_defects,
                        "defects_known": max(0, open_defects),
                        "newly_found_ids": [f"{task_id}_D{k}" for k in range(round_fixed)],
                        "newly_fixed_ids": [f"{task_id}_D{k}" for k in range(round_fixed)],
                        "bandit_findings": rng.randint(1, 5),
                        "fuzz_markers": rng.randint(0, 2),
                        "noise_findings": rng.randint(0, 3),
                        "duplicate_findings": rng.randint(0, 2),
                        "cumulative_tokens": cum_tok,
                        "cumulative_fixed": cum_fixed,
                        "stopped_reason": "",
                    }
                )
                if open_defects == 0 or (r >= 3 and round_fixed == 0 and rng.random() < 0.5):
                    break
            stop_reason = "no_findings" if open_defects == 0 else "max_rounds"
            runs.append(
                {
                    "task_id": task_id,
                    "family": family,
                    "difficulty": difficulty,
                    "rounds": rounds,
                    "final_code": "# synthetic\n",
                    "residual_defect_ids": [f"{task_id}_R{k}" for k in range(open_defects)],
                    "undetected_defect_ids": [],
                    "total_defects": total_defects,
                    "total_tokens": cum_tok,
                    "total_fixed": cum_fixed,
                    "total_found": cum_fixed,
                    "rounds_used": len(rounds),
                    "stop_reason": stop_reason,
                }
            )
    return runs


def _aggregate(runs: list[dict], rounds_filter=None) -> list[dict]:
    """复刻 metrics.aggregate_curve 的语义（全库合计口径）。"""
    rows = [r for r in runs if rounds_filter is None or r["family"] in rounds_filter]
    max_round = max(len(r["rounds"]) for r in rows)
    curve: list[dict] = []
    cum_t = cum_f = 0
    for r in range(1, max_round + 1):
        rt = rf = 0
        for row in rows:
            for rec in row["rounds"]:
                if rec["round_index"] == r:
                    rt += rec["tokens_total"]
                    rf += rec["defects_fixed"]
                    break
        cum_t += rt
        cum_f += rf
        curve.append(
            {
                "round": r,
                "cum_tokens": cum_t,
                "cum_fixed": cum_f,
                "round_tokens": rt,
                "round_fixed": rf,
                "marginal_per_100k": (rf / rt * 1e5) if rt else 0.0,
                "avg_fixed_per_100k": (cum_f / cum_t * 1e5) if cum_t else 0.0,
                "n_tasks": len(rows),
            }
        )
    return curve


def _find_knee(curve: list[dict], threshold: float = 0.1) -> dict:
    """复刻 metrics.find_knee 的语义（观测优先，未达则 log-linear 外推）。"""
    knee_round = None
    for c in curve:
        if c["marginal_per_100k"] < threshold:
            knee_round = c["round"]
            break
    if knee_round is not None:
        return {
            "knee_round": knee_round,
            "crossed": True,
            "observed": True,
            "interpolated_round": float(knee_round),
            "threshold": threshold,
            "method": "observed",
            "fit": {"a": 0.0, "b": 0.0, "r2": 0.0},
        }
    return {
        "knee_round": None,
        "crossed": False,
        "observed": False,
        "interpolated_round": 6.4,
        "threshold": threshold,
        "method": "loglinear_extrapolation",
        "fit": {"a": -0.31, "b": 1.02, "r2": 0.93},
    }


def _recommend(runs: list[dict]) -> list[dict]:
    """复刻 metrics.recommend_depth 的语义。"""
    out: list[dict] = []
    for family in FAMILIES:
        fam_runs = [r for r in runs if r["family"] == family]
        if not fam_runs:
            continue
        curve = _aggregate(fam_runs)
        knee = _find_knee(curve)
        depth = knee["knee_round"] or max(1, int(round(knee["interpolated_round"] or 3)))
        total_fixed = curve[-1]["cum_fixed"] or 1
        total_tok = curve[-1]["cum_tokens"]
        cum = 0
        r90 = len(curve)
        for c in curve:
            cum = c["cum_fixed"]
            if cum >= 0.9 * total_fixed:
                r90 = c["round"]
                break
        out.append(
            {
                "family": family,
                "tasks": len(fam_runs),
                "recommended_depth": max(1, min(MAX_ROUNDS, depth)),
                "knee_round": knee["knee_round"],
                "rounds_to_90pct": r90,
                "marginal_at_knee": curve[max(0, depth - 1)]["marginal_per_100k"],
                "tokens_per_fix_at_recommended": total_tok / total_fixed,
                "rationale": f"{FAMILY_LABELS[family]}：边际收益在第 {depth} 轮附近跌破阈值。",
            }
        )
    return out


def _build_analysis(seed: int = 7) -> dict:
    """构造完整 analyze() 返回值（严格按 CONTRACT §7.1 的固定 key）。"""
    runs = _build_runs(seed)
    curve = _aggregate(runs)
    families = {f: _aggregate(runs, {f}) for f in FAMILIES if any(r["family"] == f for r in runs)}
    knee = _find_knee(curve)
    family_knees = {f: _find_knee(c) for f, c in families.items()}
    total_tokens = sum(r["total_tokens"] for r in runs)
    total_fixed = sum(r["total_fixed"] for r in runs)
    total_defects = sum(r["total_defects"] for r in runs)

    def _breakdown(key: str) -> dict:
        groups: dict[str, list[dict]] = {}
        for r in runs:
            groups.setdefault(str(r[key]), []).append(r)
        out: dict[str, dict] = {}
        for name, grp in groups.items():
            tok = sum(x["total_tokens"] for x in grp)
            fx = sum(x["total_fixed"] for x in grp)
            dfc = sum(x["total_defects"] for x in grp)
            n_rounds = sum(x["rounds_used"] for x in grp)
            out[name] = {
                "defects": dfc,
                "fixed": fx,
                "fix_rate": (fx / dfc) if dfc else 0.0,
                "avg_round_fixed": (fx / n_rounds) if n_rounds else 0.0,
                "tokens_per_fix": (tok / fx) if fx else 0.0,
            }
        return out

    return {
        "meta": {
            "generated_at": "2026-11-10T21:00:00+0800",
            "provider": "simulated",
            "model": "simulated-deepseek-v4.1-flash",
            "max_rounds": MAX_ROUNDS,
            "task_count": len(runs),
            "seed": seed,
            "threshold_per_100k": 0.1,
            "policy_version": "v1",
        },
        "summary": {
            "total_tokens": total_tokens,
            "total_fixed": total_fixed,
            "total_defects": total_defects,
            "total_rounds": sum(r["rounds_used"] for r in runs),
            "tasks": len(runs),
            "tokens_per_fix": (total_tokens / total_fixed) if total_fixed else 0.0,
            "fix_rate": (total_fixed / total_defects) if total_defects else 0.0,
            "residual_defects": sum(len(r["residual_defect_ids"]) for r in runs),
            "undetected_defects": sum(len(r["undetected_defect_ids"]) for r in runs),
            "avg_rounds_used": sum(r["rounds_used"] for r in runs) / len(runs),
            "stop_reason_counts": {"no_findings": 12, "max_rounds": 13},
        },
        "curve": curve,
        "families": families,
        "knee": knee,
        "family_knees": family_knees,
        "depth_recommendations": _recommend(runs),
        "channel_breakdown": {
            "bandit": {"defects": 40, "fixed": 32, "fix_rate": 0.80,
                       "avg_round_fixed": 1.6, "tokens_per_fix": 1800.0},
            "fuzz": {"defects": 18, "fixed": 13, "fix_rate": 0.72,
                     "avg_round_fixed": 0.9, "tokens_per_fix": 2600.0},
            "semantic": {"defects": 15, "fixed": 8, "fix_rate": 0.53,
                         "avg_round_fixed": 0.5, "tokens_per_fix": 4300.0},
        },
        "difficulty_breakdown": {
            "easy": {"defects": 26, "fixed": 23, "fix_rate": 0.88,
                     "avg_round_fixed": 1.9, "tokens_per_fix": 1500.0},
            "medium": {"defects": 30, "fixed": 22, "fix_rate": 0.73,
                       "avg_round_fixed": 1.2, "tokens_per_fix": 2400.0},
            "hard": {"defects": 17, "fixed": 8, "fix_rate": 0.47,
                     "avg_round_fixed": 0.6, "tokens_per_fix": 3900.0},
        },
        "sensitivity": {
            "0.05": {"knee_round": 5, "method": "observed", "threshold": 0.05},
            "0.1": {"knee_round": knee["knee_round"], "method": knee["method"],
                    "threshold": 0.1},
            "0.2": {"knee_round": 3, "method": "observed", "threshold": 0.2},
        },
        "_runs": runs,  # 测试内部用，正式 analysis.json 不含
    }


def _build_budget(runs: list[dict], budget: int = 600_000) -> dict:
    """构造 write_budget() 返回值（严格按 CONTRACT §7.2 的固定 key）。"""
    strategies = [
        ("breadth", "广度优先 breadth", 25, 1.0),
        ("depth", "深度优先 depth", 6, 6.5),
        ("adaptive", "自适应 adaptive", 18, 2.6),
    ]
    plans: list[dict] = []
    comparison: list[dict] = []
    base_fixed = None
    for i, (name, label, covered, depth) in enumerate(strategies):
        tok = int(budget * (0.94 + 0.02 * i))
        fixed = 41.0 + 9.5 * i + (2.5 if name == "adaptive" else 0.0)
        if base_fixed is None:
            base_fixed = fixed
        alloc = {f"T{j:02d}": int(depth) for j in range(1, covered + 1)}
        plans.append(
            {
                "name": name,
                "label": label,
                "allocations": alloc,
                "projected_tokens": tok,
                "projected_fixed": fixed,
                "tasks_covered": covered,
                "avg_depth": float(depth),
                "within_budget": tok <= budget,
                "rationale": f"{label}：覆盖 {covered} 个任务、平均深度 {depth} 轮。",
            }
        )
        comparison.append(
            {
                "name": name,
                "projected_tokens": tok,
                "projected_fixed": fixed,
                "projected_cost_per_fix": tok / fixed,
                "tasks_covered": covered,
                "avg_depth": float(depth),
                "vs_breadth_pct": (fixed - base_fixed) / base_fixed * 100.0,
            }
        )
    return {
        "meta": {
            "generated_at": "2026-11-10T21:05:00+0800",
            "budget": budget,
            "source_run": "results/runs/main_experiment.json",
            "provider": "simulated",
            "threshold_per_100k": 0.1,
        },
        "plans": plans,
        "comparison": comparison,
    }


# ---------------------------------------------------------------- 断言工具

def _assert_valid_png(path: str | Path, min_bytes: int = 20 * 1024) -> None:
    p = Path(path)
    assert p.is_file(), f"图未生成: {p}"
    size = p.stat().st_size
    assert size > min_bytes, f"{p.name} 只有 {size} 字节（< {min_bytes}），疑似空图"
    with p.open("rb") as fh:
        head = fh.read(8)
    assert head.startswith(b"\x89PNG\r\n\x1a\n"), f"{p.name} 不是合法 PNG: {head!r}"


# ---------------------------------------------------------------- 测试

@pytest.fixture(scope="module")
def workdir():
    d = bootstrap.make_tempdir("t4plot-")
    yield d
    bootstrap.cleanup(d)


@pytest.fixture(scope="module")
def analysis() -> dict:
    return _build_analysis()


@pytest.fixture(scope="module")
def budget_result(analysis: dict) -> dict:
    return _build_budget(analysis["_runs"])


def test_fig1_cumulative_curve(analysis: dict, workdir: Path) -> None:
    out = workdir / "fig1.png"
    path = plotting.fig_cumulative_curve(analysis, out)
    assert isinstance(path, str)
    _assert_valid_png(path)


def test_fig2_marginal_curve(analysis: dict, workdir: Path) -> None:
    path = plotting.fig_marginal_curve(analysis, workdir / "fig2.png")
    _assert_valid_png(path)


def test_fig3_family_depth(analysis: dict, workdir: Path) -> None:
    path = plotting.fig_family_depth(analysis, workdir / "fig3.png")
    _assert_valid_png(path)


def test_fig4_budget_compare(budget_result: dict, workdir: Path) -> None:
    path = plotting.fig_budget_compare(budget_result, workdir / "fig4.png")
    _assert_valid_png(path)


def test_fig5_task_heatmap(analysis: dict, workdir: Path) -> None:
    runs = {"meta": analysis["meta"], "runs": analysis["_runs"]}
    path = plotting.fig_task_heatmap(runs, workdir / "fig5.png")
    _assert_valid_png(path)


def test_make_all_figures(analysis: dict, budget_result: dict, workdir: Path) -> None:
    runs = {"meta": analysis["meta"], "runs": analysis["_runs"]}
    figs = plotting.make_all_figures(analysis, budget_result, runs, workdir / "figures")
    assert set(figs) == {"cumulative", "marginal", "family_depth", "budget", "heatmap"}
    for path in figs.values():
        _assert_valid_png(path)
    paths = plotting.figure_paths(figs)
    assert len(paths) == 5
    assert [Path(p).name for p in paths] == sorted(plotting.FIGURE_NAMES)


def test_build_report(analysis: dict, budget_result: dict, workdir: Path) -> None:
    runs = {"meta": analysis["meta"], "runs": analysis["_runs"]}
    figs = plotting.make_all_figures(analysis, budget_result, runs, workdir / "figs")
    out_md = workdir / "REPORT.md"
    path = report.build_report(analysis, budget_result, figs, out_md)

    assert Path(path).is_file()
    text = Path(path).read_text(encoding="utf-8")
    assert len(text) > 3000, "报告过短"

    # 3 张表（表 1 逐轮 / 表 2 family 深度 / 表 3 预算策略）
    assert text.count("| 轮次 |") >= 1, "缺表 1（逐轮汇总）"
    assert text.count("| 任务类型 |") >= 1, "缺表 2（family 深度建议）"
    assert text.count("| 策略 |") >= 1, "缺表 3（预算策略对比）"
    assert text.count("| ---") >= 3, "Markdown 表格分隔行不足 3 个"

    # 5 张图引用。注意：必须断言"路径能真正解析到文件"，
    # 而不是只检查文件名子串——曾经断言 `figures/{name}`，结果掩盖了
    # "REPORT.md 在项目根、图在 results/figures/，引用写成 figures/ 是死链" 的真实 bug。
    import re as _re

    links = _re.findall(r"!\[[^\]]*\]\(([^)]+)\)", text)
    assert len(links) >= 5, f"图片引用不足 5 个，实际 {len(links)}"
    for name in plotting.FIGURE_NAMES:
        assert any(name in ln for ln in links), f"报告缺少图片引用 {name}"

    # 只校验"由 make_all_figures 生成到本临时目录"的那些图必须可解析。
    # fig6 是敏感性分析图，指向项目根的真实文件，不属于本次临时输出，跳过。
    produced = {Path(p).name for p in (figs or {}).values()}
    for ln in links:
        if Path(ln).name not in produced:
            continue
        target = Path(path).parent / ln
        assert target.is_file(), f"图片引用是死链（相对 REPORT.md 解析失败）: {ln}"

    # 不允许出现 Python 的空值字面量漏进 Markdown
    assert "None" not in text, "报告中出现了 None 字面量"
    assert "nan" not in text.lower(), "报告中出现了 nan 字面量"

    # 诚实声明必须存在（Lead 验收硬指标）
    assert "模拟" in text and ("bandit" in text) and ("模糊测试" in text or "fuzz" in text)


def test_plotting_handles_missing_optional_fields(workdir: Path) -> None:
    """analysis 只有 curve 时也应能出图（容错兜底）。"""
    runs = _build_runs(11)
    minimal = {"meta": {"task_count": 25}, "curve": _aggregate(runs)}
    path = plotting.fig_cumulative_curve(minimal, workdir / "minimal1.png")
    _assert_valid_png(path)


def test_report_without_budget(analysis: dict, workdir: Path) -> None:
    """budget_result 为 None 时报告仍要能生成（只是表 3 降级）。"""
    out_md = workdir / "REPORT_nobudget.md"
    path = report.build_report(analysis, None, None, out_md)
    text = Path(path).read_text(encoding="utf-8")
    assert "| 轮次 |" in text
    assert "None" not in text
