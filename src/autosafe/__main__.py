"""统一 CLI 入口：一条命令跑完整个流程。

    python -m autosafe                     # 全部：主实验 → 分析 → 预算 → 图表 → 报告
    python -m autosafe main                # 只跑主实验
    python -m autosafe analyze             # 只做分析（需要已有主实验数据）
    python -m autosafe budget              # 只做预算对比
    python -m autosafe figures             # 只出图
    python -m autosafe report              # 只生成报告

所有子命令都从项目根运行即可，无需手动设置 PYTHONPATH。
"""
from __future__ import annotations

import argparse
import sys
import time

from .bootstrap import PROJECT_ROOT


def _stage_main(args) -> None:
    from .runner import run_main

    run_main(max_rounds=args.max_rounds, seed=args.seed, profile=args.profile)


def _stage_analyze(args) -> None:
    from .metrics import load_experiment, write_analysis

    exp = load_experiment(args.runs)
    result = write_analysis(exp, args.analysis)
    s, k = result["summary"], result["knee"]
    print(f"任务={s['tasks']} 总token={s['total_tokens']:,} 修复={s['total_fixed']}/{s['total_defects']}")
    print(f"拐点: {k['method']} @ 第 {k['knee_round']} 轮 (阈值 {k['threshold']}/10万token)")
    for row in result["depth_recommendations"]:
        print(f"  {row['family']:<16} 建议深度={row['recommended_depth']}")


def _stage_budget(args) -> None:
    from .budget import plan_adaptive, plan_breadth, plan_depth, write_budget
    from .metrics import load_experiment

    exp = load_experiment(args.runs)
    runs = exp.get("runs", [])
    plans = [plan_breadth(runs, args.budget), plan_depth(runs, args.budget),
             plan_adaptive(runs, args.budget)]
    payload = write_budget(plans, runs, args.budget_plan, budget=args.budget, source_run=args.runs)
    for row in payload["comparison"]:
        print(f"  {row['name']:<9} 覆盖={row['tasks_covered']:>2} "
              f"token={row['projected_tokens']:>8,} 修复={row['projected_fixed']:>6.1f} "
              f"vs广度={row['vs_breadth_pct']:+.1f}%")


def _stage_figures(args) -> None:
    from .metrics import load_experiment, write_analysis
    from .plotting import make_all_figures

    exp = load_experiment(args.runs)
    analysis = write_analysis(exp, args.analysis)
    budget = None
    try:
        import json

        bp = PROJECT_ROOT / args.budget_plan
        if bp.exists():
            budget = json.loads(bp.read_text(encoding="utf-8"))
    except Exception:
        budget = None
    paths = make_all_figures(analysis, budget, exp.get("runs", []),
                             PROJECT_ROOT / "results" / "figures")
    print(f"生成 {len(paths)} 张图")
    for name, p in (paths.items() if isinstance(paths, dict) else enumerate(paths)):
        print(f"  {name}: {p}")


def _stage_report(args) -> None:
    import json

    from .metrics import load_experiment, write_analysis
    from .plotting import make_all_figures
    from .report import build_report

    exp = load_experiment(args.runs)
    analysis = write_analysis(exp, args.analysis)
    budget = None
    bp = PROJECT_ROOT / args.budget_plan
    if bp.exists():
        budget = json.loads(bp.read_text(encoding="utf-8"))
    figures = make_all_figures(analysis, budget, exp.get("runs", []),
                               PROJECT_ROOT / "results" / "figures")
    out = build_report(analysis, budget, figures, PROJECT_ROOT / "REPORT.md")
    print(f"报告已生成: {out}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="autosafe", description="多 Agent 代码安全审计的迭代深度与 token 边际收益分析")
    ap.add_argument("stage", nargs="?", default="all",
                    choices=["all", "main", "analyze", "budget", "figures", "report"])
    ap.add_argument("--runs", default="results/runs/main_experiment.json")
    ap.add_argument("--analysis", default="results/analysis.json")
    ap.add_argument("--budget-plan", default="results/budget_plan.json")
    ap.add_argument("--max-rounds", type=int, default=8)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--profile", default="baseline")
    ap.add_argument("--budget", type=int, default=600_000)
    args = ap.parse_args(argv)

    t0 = time.time()
    if args.stage in {"all", "main"}:
        _stage_main(args)
    if args.stage in {"all", "analyze"}:
        _stage_analyze(args)
    if args.stage in {"all", "budget"}:
        _stage_budget(args)
    if args.stage in {"all", "figures"}:
        _stage_figures(args)
    if args.stage in {"all", "report"}:
        _stage_report(args)
    print(f"\n完成，用时 {time.time() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
