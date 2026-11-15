"""实验运行器：主实验（深度曲线）+ 预算对比实验 + 敏感性分析。

用法
----
    python -m autosafe.runner main          # 主实验：25 任务 × 8 轮
    python -m autosafe.runner budget        # 预算对比：breadth / depth / adaptive 真实执行
    python -m autosafe.runner sensitivity   # 敏感性：profile × 阈值 × max_rounds
    python -m autosafe.runner all           # 全部（默认）
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import agents as agent_model
from .llm import build_client
from .pipeline import PipelineConfig, run_experiment, run_task
from .schema import Task, TaskRun, experiment_to_dict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS = PROJECT_ROOT / "results"
RUNS_DIR = RESULTS / "runs"


def _load_tasks() -> list[Task]:
    from .tasks.library import TASKS

    return list(TASKS)


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  写入 {path.relative_to(PROJECT_ROOT)}")


# ---------------------------------------------------------------- 主实验


def run_main(
    *,
    max_rounds: int = 8,
    seed: int = 7,
    profile: str = "baseline",
    out: str = "results/runs/main_experiment.json",
    tasks: list[Task] | None = None,
) -> dict:
    tasks = tasks or _load_tasks()
    cfg = PipelineConfig(max_rounds=max_rounds, seed=seed, profile=profile, verbose=False)
    client = build_client()
    print(f"== 主实验 == 任务={len(tasks)} 轮次上限={max_rounds} profile={profile} "
          f"provider={getattr(client, 'provider', '?')}")
    payload = run_experiment(tasks, config=cfg, client=client,
                            out_path=PROJECT_ROOT / out, verbose=True)
    meta = payload["meta"]
    print(f"== 完成 == 总 token={meta['total_tokens']:,} 总修复={meta['total_fixed']}/"
          f"{meta['total_defects']} 用时={meta['wall_seconds']}s")
    return payload


# ---------------------------------------------------------------- 预算对比


def _run_plan(plan, tasks_by_id: dict[str, Task], *, seed: int, profile: str,
              client) -> dict:
    """按某个预算方案真实执行管线。"""
    runs: list[TaskRun] = []
    for tid, depth in plan.allocations.items():
        if depth <= 0:
            continue
        task = tasks_by_id[tid]
        cfg = PipelineConfig(max_rounds=int(depth), seed=seed, profile=profile)
        runs.append(run_task(task, client=client, config=cfg))
    return {
        "name": plan.name,
        "label": plan.label,
        "allocations": dict(plan.allocations),
        "projected_tokens": plan.projected_tokens,
        "projected_fixed": plan.projected_fixed,
        "actual_tokens": sum(r.total_tokens for r in runs),
        "actual_fixed": sum(r.total_fixed for r in runs),
        "tasks_covered": sum(1 for v in plan.allocations.values() if v > 0),
        "avg_depth": round(
            sum(v for v in plan.allocations.values() if v > 0)
            / max(1, sum(1 for v in plan.allocations.values() if v > 0)), 2),
        "runs": [r.to_dict() for r in runs],
    }


def run_budget(
    *,
    budget: int = 600_000,
    seed: int = 7,
    profile: str = "baseline",
    main_path: str = "results/runs/main_experiment.json",
    out: str = "results/budget_experiment.json",
) -> dict:
    from .budget import compare, plan_adaptive, plan_breadth, plan_depth

    main_file = PROJECT_ROOT / main_path
    if not main_file.exists():
        raise SystemExit(f"缺少主实验数据 {main_file}，请先运行 `python -m autosafe.runner main`")
    main = json.loads(main_file.read_text(encoding="utf-8"))
    from .schema import run_from_dict

    runs = [run_from_dict(r) for r in main["runs"]]
    tasks = _load_tasks()
    tasks_by_id = {t.task_id: t for t in tasks}

    plans = [plan_breadth(runs, budget), plan_depth(runs, budget), plan_adaptive(runs, budget)]
    client = build_client()
    print(f"== 预算对比 == 预算={budget:,} token 方案数={len(plans)}")
    results = []
    for plan in plans:
        print(f"  -> 执行 {plan.name}（覆盖 {sum(1 for v in plan.allocations.values() if v > 0)} 任务）")
        results.append(_run_plan(plan, tasks_by_id, seed=seed, profile=profile, client=client))

    # 用观测曲线投影 vs 真实执行对照
    proj = {row["name"]: row for row in compare(plans, runs)}
    for r in results:
        p = proj.get(r["name"], {})
        r["projected_fixed_from_curve"] = p.get("projected_fixed")
        r["projection_error"] = (
            round((r["actual_fixed"] - p.get("projected_fixed", 0)) / max(1e-9, p.get("projected_fixed", 1)), 4)
            if p else None
        )

    base = next((r for r in results if r["name"] == "breadth"), results[0])
    for r in results:
        r["vs_breadth_pct"] = round(
            (r["actual_fixed"] - base["actual_fixed"]) / max(1e-9, base["actual_fixed"]) * 100, 2
        )
        # 实际执行后的预算合规性（投影可能低估/高估，必须如实报告）
        r["within_budget_actual"] = r["actual_tokens"] <= budget
        r["budget_overshoot_pct"] = round(
            (r["actual_tokens"] - budget) / max(1, budget) * 100, 2
        )
        r["actual_cost_per_fix"] = round(
            r["actual_tokens"] / max(1, r["actual_fixed"]), 1
        )

    payload = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "budget": budget,
            "seed": seed,
            "profile": profile,
            "source_run": main_path,
            "provider": getattr(client, "provider", "?"),
            "note": "actual_* 为按方案真实执行管线的结果；projected_* 为用主实验观测曲线做的离线投影",
        },
        "plans": [
            {k: v for k, v in r.items() if k != "runs"} for r in results
        ],
        "comparison": compare(plans, runs),
        "runs": {r["name"]: r["runs"] for r in results},
    }
    _write(PROJECT_ROOT / out, payload)
    for r in results:
        print(f"  {r['name']:<9} 覆盖={r['tasks_covered']:>2} 深度={r['avg_depth']} "
              f"token={r['actual_tokens']:>7,} 修复={r['actual_fixed']:>3} "
              f"vs breadth={r['vs_breadth_pct']:+.1f}%")
    return payload


# ---------------------------------------------------------------- 敏感性


def run_sensitivity(
    *,
    seeds: tuple[int, ...] = (7, 11, 23),
    profiles: tuple[str, ...] = ("strong", "baseline", "weak"),
    max_rounds: int = 8,
    out: str = "results/sensitivity.json",
) -> dict:
    tasks = _load_tasks()
    client = build_client()
    rows = []
    total = len(seeds) * len(profiles)
    n = 0
    for prof in profiles:
        for seed in seeds:
            n += 1
            cfg = PipelineConfig(max_rounds=max_rounds, seed=seed, profile=prof)
            print(f"[{n}/{total}] profile={prof} seed={seed} ...", flush=True)
            payload = run_experiment(tasks, config=cfg, client=client, verbose=False)
            # 全局逐轮曲线：把所有任务按轮次聚合（缺失轮次按 0 补齐，累计值取和）
            by_round: dict[int, dict] = {}
            for run in payload["runs"]:
                for rr in run["rounds"]:
                    k = rr["round_index"]
                    slot = by_round.setdefault(
                        k, {"round": k, "tokens": 0, "fixed": 0, "cum_tokens": 0, "cum_fixed": 0}
                    )
                    slot["tokens"] += rr["tokens_total"]
                    slot["fixed"] += rr["defects_fixed"]
                    slot["cum_tokens"] += rr["cumulative_tokens"]
                    slot["cum_fixed"] += rr["cumulative_fixed"]
            rows.append({
                "profile": prof,
                "seed": seed,
                "total_tokens": payload["meta"]["total_tokens"],
                "total_fixed": payload["meta"]["total_fixed"],
                "total_defects": payload["meta"]["total_defects"],
                "rounds": [by_round[k] for k in sorted(by_round)],
                "runs": payload["runs"],
            })
    payload = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "seeds": list(seeds),
            "profiles": list(profiles),
            "max_rounds": max_rounds,
            "provider": getattr(client, "provider", "?"),
        },
        "rows": rows,
    }
    _write(PROJECT_ROOT / out, payload)
    return payload


# ---------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AutoSafe-Audit 实验运行器")
    ap.add_argument("stage", nargs="?", default="all",
                    choices=["main", "budget", "sensitivity", "all"])
    ap.add_argument("--max-rounds", type=int, default=8)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--profile", default="baseline", choices=sorted(agent_model.PROFILES))
    ap.add_argument("--budget", type=int, default=600_000)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    t0 = time.time()
    if args.stage in {"main", "all"}:
        run_main(max_rounds=args.max_rounds, seed=args.seed, profile=args.profile,
                 out=args.out or "results/runs/main_experiment.json")
    if args.stage in {"budget", "all"}:
        run_budget(budget=args.budget, seed=args.seed, profile=args.profile,
                   out=args.out or "results/budget_experiment.json")
    if args.stage in {"sensitivity", "all"}:
        run_sensitivity(max_rounds=args.max_rounds)
    print(f"\n全部完成，用时 {time.time() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
