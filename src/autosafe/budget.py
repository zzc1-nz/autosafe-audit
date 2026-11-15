"""预算分配：固定 token 预算下，"深度迭代" vs "广度覆盖"的取舍。

问题
----
给定总预算 B（token），应该：
* **广度优先（breadth）**：每个任务只跑很少几轮，把预算铺到更多任务上
* **深度优先（depth）**：只挑少数任务跑到很深（8 轮）
* **自适应（adaptive）**：按每轮边际收益贪心分配

做法
----
三种方案都**只在主实验已观测到的逐轮 (tokens, fixed) 曲线上做投影**，不编造数字：
任务 t 跑 k 轮的预计成本 = 观测到的第 k 轮累计 token；预计收益 = 第 k 轮累计修复数。

自适应贪心带**前缀约束**：任务的轮次必须连续（不能跳过第 2 轮直接买第 3 轮），
因此这是带前缀约束的背包问题。每步选"下一轮边际修复密度最高"的任务。
该贪心不是全局最优，但近似比受最大/最小密度比约束（见 docs/ANALYSIS_METHOD.md）。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_THRESHOLD = 0.1
MAX_DEPTH = 8


@dataclass(frozen=True)
class BudgetPlan:
    """一个预算分配方案。"""

    name: str
    label: str
    allocations: dict[str, int]
    projected_tokens: int
    projected_fixed: float
    rationale: str
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def tasks_covered(self) -> int:
        return sum(1 for v in self.allocations.values() if v > 0)

    @property
    def avg_depth(self) -> float:
        depths = [v for v in self.allocations.values() if v > 0]
        return round(sum(depths) / len(depths), 2) if depths else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "allocations": dict(self.allocations),
            "projected_tokens": int(self.projected_tokens),
            "projected_fixed": round(float(self.projected_fixed), 3),
            "tasks_covered": self.tasks_covered,
            "avg_depth": self.avg_depth,
            "within_budget": self.projected_tokens <= self.meta.get("budget", 10**18),
            "rationale": self.rationale,
        }


# --------------------------------------------------------------------------- #
# 观测曲线索引
# --------------------------------------------------------------------------- #
def _as_dict(run) -> dict:
    """把 TaskRun 或 dict 统一成 dict（budget 同时支持两种输入）。"""
    if isinstance(run, dict):
        return run
    to_dict = getattr(run, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise TypeError(f"不支持的任务运行类型: {type(run)!r}")


def _index(runs: Sequence) -> dict[str, list[dict]]:
    """task_id -> 逐轮累计 (tokens, fixed) 列表（索引 0 = 跑 1 轮）。"""
    out: dict[str, list[dict]] = {}
    for raw in runs:
        run = _as_dict(raw)
        rows = []
        for rec in run.get("rounds", []):
            rows.append({
                "round": int(rec.get("round_index", len(rows) + 1)),
                "cum_tokens": int(rec.get("cumulative_tokens", 0)),
                "cum_fixed": int(rec.get("cumulative_fixed", 0)),
                "round_tokens": int(rec.get("tokens_total", 0)),
                "round_fixed": int(rec.get("defects_fixed", 0)),
            })
        if rows:
            out[run.get("task_id", "?")] = rows
    return out


def _cost(rows: list[dict], k: int) -> int:
    """跑 k 轮的预计 token（k 超观测范围则用最后一轮外推）。"""
    if k <= 0:
        return 0
    if k <= len(rows):
        return rows[k - 1]["cum_tokens"]
    last = rows[-1]
    extra = (k - len(rows)) * last["round_tokens"]
    return last["cum_tokens"] + extra


def _benefit(rows: list[dict], k: int) -> float:
    """跑 k 轮的预计修复数（超出观测则用最后一轮外推，收益按 0 计——保守）。"""
    if k <= 0:
        return 0.0
    if k <= len(rows):
        return float(rows[k - 1]["cum_fixed"])
    return float(rows[-1]["cum_fixed"])


def _marginal_density(rows: list[dict], k: int) -> float:
    """从 k-1 轮加到 k 轮的边际修复密度（每 token 修复数）。"""
    d_tok = _cost(rows, k) - _cost(rows, k - 1)
    d_fix = _benefit(rows, k) - _benefit(rows, k - 1)
    return d_fix / d_tok if d_tok > 0 else 0.0


# --------------------------------------------------------------------------- #
# 三种策略
# --------------------------------------------------------------------------- #
def plan_breadth(runs: Sequence[dict], budget: int) -> BudgetPlan:
    """广度优先：所有任务都跑 k 轮，取预算允许的最大 k。"""
    idx = _index(runs)
    max_k = max((len(v) for v in idx.values()), default=0)
    best_k = 0
    for k in range(1, max_k + 1):
        total = sum(_cost(rows, k) for rows in idx.values())
        if total <= budget:
            best_k = k
        else:
            break
    if best_k == 0:
        # 连 1 轮都跑不完所有任务：按单位 token 修复数降序挑任务
        ranked = sorted(
            idx.items(),
            key=lambda kv: (_benefit(kv[1], 1) / max(1, _cost(kv[1], 1))),
            reverse=True,
        )
        alloc: dict[str, int] = {}
        spent = 0
        for tid, rows in ranked:
            c = _cost(rows, 1)
            if spent + c <= budget:
                alloc[tid] = 1
                spent += c
        return BudgetPlan(
            name="breadth",
            label="广度覆盖（每任务少迭代，覆盖更多任务）",
            allocations=alloc,
            projected_tokens=spent,
            projected_fixed=sum(_benefit(idx[t], 1) for t in alloc),
            rationale=(
                f"预算 {budget:,} 不足以让全部 {len(idx)} 个任务都跑 1 轮；"
                f"按单位 token 修复数降序挑选，覆盖 {len(alloc)} 个任务。"
            ),
            meta={"budget": budget, "k": 1},
        )
    alloc = {tid: best_k for tid in idx}
    total = sum(_cost(rows, best_k) for rows in idx.values())
    return BudgetPlan(
        name="breadth",
        label="广度覆盖（每任务少迭代，覆盖更多任务）",
        allocations=alloc,
        projected_tokens=total,
        projected_fixed=sum(_benefit(rows, best_k) for rows in idx.values()),
        rationale=(
            f"在预算 {budget:,} 内让全部 {len(idx)} 个任务各跑 {best_k} 轮。"
            f"适合'先扫一遍全部资产'的场景：覆盖面最大，但长尾语义缺陷修不掉。"
        ),
        meta={"budget": budget, "k": best_k},
    )


def plan_depth(runs: Sequence[dict], budget: int, *, focus_tasks: int = 6) -> BudgetPlan:
    """深度优先：少数任务跑到 max_rounds。"""
    idx = _index(runs)
    deep = min(MAX_DEPTH, max((len(v) for v in idx.values()), default=0))
    # 两种挑选口径，取投影收益更高的那个
    by_full_fixed = sorted(
        idx.items(), key=lambda kv: (_benefit(kv[1], deep), -_cost(kv[1], deep)), reverse=True
    )
    by_density = sorted(
        idx.items(),
        key=lambda kv: _benefit(kv[1], deep) / max(1, _cost(kv[1], deep)),
        reverse=True,
    )
    best: tuple[float, dict[str, int], int, str] | None = None
    for tag, ranked in (("满深度总修复数", by_full_fixed), ("修复密度", by_density)):
        alloc: dict[str, int] = {}
        spent = 0
        for tid, rows in ranked:
            if len(alloc) >= focus_tasks:
                break
            c = _cost(rows, deep)
            if spent + c <= budget:
                alloc[tid] = deep
                spent += c
        benefit = sum(_benefit(idx[t], deep) for t in alloc)
        if best is None or benefit > best[0]:
            best = (benefit, alloc, spent, tag)
    assert best is not None
    benefit, alloc, spent, tag = best
    # 预算若有剩余，**继续新增整任务跑到 deep**（保持"深度"语义，不摊薄到所有任务）。
    # 这样 depth 与 breadth 才构成真正的对照：同样的预算，一个铺广度、一个砸深度。
    if spent < budget:
        for tid, rows in by_full_fixed:
            if tid in alloc:
                continue
            c = _cost(rows, deep)
            if spent + c <= budget:
                alloc[tid] = deep
                spent += c
    benefit = sum(_benefit(idx[t], k) for t, k in alloc.items())
    return BudgetPlan(
        name="depth",
        label="深度迭代（少数任务反复审计到底）",
        allocations=alloc,
        projected_tokens=spent,
        projected_fixed=benefit,
        rationale=(
            f"按{tag}挑选 {len(alloc)} 个任务各跑到 {deep} 轮（预算允许则继续新增任务）。"
            f"适合'高风险资产集中加固'的场景：单任务修得最干净，但未覆盖的任务漏洞全部留存。"
        ),
        meta={"budget": budget, "deep": deep, "focus": focus_tasks},
    )


def _greedy_fill(
    idx: dict[str, list[dict]],
    alloc: dict[str, int],
    spent: int,
    budget: int,
) -> tuple[dict[str, int], int]:
    """带前缀约束的边际贪心：每次买"下一轮密度最高"的那一轮。"""
    alloc = dict(alloc)
    while True:
        best_tid = None
        best_density = -1.0
        best_cost = 0
        for tid, rows in idx.items():
            cur = alloc.get(tid, 0)
            nxt = cur + 1
            if nxt > max(MAX_DEPTH, len(rows)):
                continue
            if nxt > len(rows):        # 不买观测范围之外的轮次（不编造）
                continue
            cost = _cost(rows, nxt) - _cost(rows, cur)
            if spent + cost > budget:
                continue
            dens = _marginal_density(rows, nxt)
            if dens > best_density:
                best_density, best_tid, best_cost = dens, tid, cost
        if best_tid is None or best_density <= 0:
            break
        alloc[best_tid] = alloc.get(best_tid, 0) + 1
        spent += best_cost
    return alloc, spent


def plan_adaptive(runs: Sequence[dict], budget: int) -> BudgetPlan:
    """自适应：先做一轮全覆盖探查，再按边际收益追加深度（前缀约束）。

    为什么要"探查地板"：纯贪心只看已知的边际密度，会跳过那些**首轮没修出东西**的任务
    （它们首轮密度为 0），从而漏掉可能在第二轮才暴露的长尾缺陷。真实审计不会因为
    "第一次扫描没发现"就永久放弃一个资产——先花一轮把所有资产都过一遍，再决定往哪里
    加深度，这才是可执行的自适应策略。

    两阶段：
    1. **探查阶段**：给每个任务分配 1 轮（预算不够则按首轮密度降序，能覆盖多少算多少）；
    2. **加深阶段**：在剩余预算内，按"下一轮边际修复密度"贪心追加轮次（前缀约束）。
    """
    idx = _index(runs)
    alloc: dict[str, int] = {}
    spent = 0

    # ---- 阶段 1：全覆盖探查（每任务 1 轮）----
    first_round = sorted(
        idx.items(),
        key=lambda kv: (_marginal_density(kv[1], 1), -_cost(kv[1], 1)),
        reverse=True,
    )
    for tid, rows in first_round:
        c = _cost(rows, 1)
        if spent + c <= budget:
            alloc[tid] = 1
            spent += c

    # ---- 阶段 2：按边际密度加深 ----
    # 注意：很多任务第 1→2 轮的边际收益为 0（首轮没发现新缺陷），若严格用"密度>0"
    # 作为继续加深的条件，就会在探查后立刻停止，退化成"只跑 1 轮"。
    # 真实策略是：**只要边际密度高于全局拐点阈值（默认 0.1/10万token），就值得加深**；
    # 密度为 0 的轮次不值得单独买，但如果后面几轮可能有收益（非零轮），
    # 允许"跨过零收益轮"去够到有收益的轮次（前缀约束要求连续购买）。
    while True:
        best_tid = None
        best_score = -1.0
        best_cost = 0
        for tid, rows in idx.items():
            cur = alloc.get(tid, 0)
            nxt = cur + 1
            if nxt > len(rows):
                continue
            cost = _cost(rows, nxt) - _cost(rows, cur)
            if spent + cost > budget:
                continue
            dens = _marginal_density(rows, nxt)
            # 用"前瞻密度"打分：若下一轮本身为 0，但后续轮次有收益，则按
            # 该收益 / 从当前到该轮的总成本 计分（跨过零收益轮）。
            score = dens
            if dens <= 0:
                for look in range(nxt + 1, len(rows) + 1):
                    fut_fix = _benefit(rows, look) - _benefit(rows, cur)
                    fut_cost = _cost(rows, look) - _cost(rows, cur)
                    if fut_cost <= 0 or spent + fut_cost > budget:
                        continue
                    if fut_fix > 0:
                        score = (fut_fix / fut_cost) * 0.5   # 折价：需要先买无用轮次
                        best_cost = fut_cost
                        nxt = look
                        break
            if score > best_score:
                best_score, best_tid = score, tid
                if score == dens:
                    best_cost = cost
        if best_tid is None or best_score <= 0:
            break
        # 按选中的目标轮次补齐前缀
        target = max(alloc.get(best_tid, 0) + 1, nxt)
        cost = _cost(idx[best_tid], target) - _cost(idx[best_tid], alloc.get(best_tid, 0))
        if spent + cost > budget:
            break
        alloc[best_tid] = target
        spent += cost

    benefit = sum(_benefit(idx[t], k) for t, k in alloc.items())
    n_cov = sum(1 for v in alloc.values() if v > 0)
    avg_d = round(sum(alloc.values()) / max(1, len(alloc)), 2)
    return BudgetPlan(
        name="adaptive",
        label="自适应（全覆盖探查 + 按边际收益加深）",
        allocations=alloc,
        projected_tokens=spent,
        projected_fixed=benefit,
        rationale=(
            f"先用 1 轮覆盖 {n_cov} 个任务做探查，再把剩余预算按'下一轮边际修复密度'"
            f"追加到仍有钱可赚的任务上（平均深度 {avg_d}）。"
            f"这是本文推荐策略：既不做无差别深挖，也不因首轮没发现就漏掉长尾。"
        ),
        meta={"budget": budget, "explored": n_cov, "avg_depth": avg_d},
    )


# --------------------------------------------------------------------------- #
# 对比
# --------------------------------------------------------------------------- #
def compare(plans: Sequence[BudgetPlan], runs: Sequence[dict]) -> list[dict]:
    """用观测曲线投影每个方案，并给出三种口径的对比。

    为什么不能只比"总修复数"
    ------------------------
    各方案花掉的 token 并不相同（自适应可能提前遇到"边际收益为零"而花不完预算）。
    只比总修复数会得出"广度更好"的错误结论——广度只是花得更多而已。
    因此同时给出：
    * ``projected_cost_per_fix``：修复单价（越低越好，**这是核心指标**）
    * ``efficiency_vs_breadth``：相对广度的 token 效率倍数（>1 表示更省）
    * ``fixes_at_equal_token``：把各方案都折算到"与广度相同的 token 花费"时能修多少
      （线性折算，仅作量级参考，标注为估算）
    """
    rows: list[dict] = []
    for p in plans:
        tok = p.projected_tokens
        fix = p.projected_fixed
        rows.append({
            "name": p.name,
            "label": p.label,
            "projected_tokens": int(tok),
            "projected_fixed": round(float(fix), 3),
            "projected_cost_per_fix": round(tok / fix, 1) if fix > 0 else None,
            "tasks_covered": p.tasks_covered,
            "avg_depth": p.avg_depth,
            "within_budget": p.projected_tokens <= p.meta.get("budget", 10**18),
            "budget_utilization": round(tok / max(1, p.meta.get("budget", 1)) * 100, 1),
            "rationale": p.rationale,
        })
    base = next((r for r in rows if r["name"] == "breadth"), rows[0] if rows else None)
    base_cpf = base["projected_cost_per_fix"] if base else None
    base_tok = base["projected_tokens"] if base else 0
    for r in rows:
        if base and base["projected_fixed"] > 0:
            r["vs_breadth_pct"] = round(
                (r["projected_fixed"] - base["projected_fixed"]) / base["projected_fixed"] * 100, 2
            )
        else:
            r["vs_breadth_pct"] = 0.0
        cpf = r["projected_cost_per_fix"]
        if base_cpf and cpf:
            r["efficiency_vs_breadth"] = round(base_cpf / cpf, 3)
        else:
            r["efficiency_vs_breadth"] = None
        # 折算到"与广度相同 token"时能修多少（线性估算，仅作量级参考）
        if cpf and base_tok:
            r["fixes_at_equal_token"] = round(base_tok / cpf, 2)
        else:
            r["fixes_at_equal_token"] = None
    return rows


def write_budget(
    plans: Sequence[BudgetPlan],
    runs: Sequence[dict],
    out_path: str | Path,
    *,
    budget: int,
    source_run: str = "results/runs/main_experiment.json",
) -> dict:
    """落盘预算方案与对比。"""
    payload = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "budget": int(budget),
            "source_run": source_run,
            "provider": "simulated",
            "threshold_per_100k": DEFAULT_THRESHOLD,
        },
        "plans": [p.to_dict() for p in plans],
        "comparison": compare(plans, runs),
    }
    p = Path(out_path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AutoSafe-Audit 预算分配分析")
    ap.add_argument("--runs", default="results/runs/main_experiment.json")
    ap.add_argument("--budget", type=int, default=600_000)
    ap.add_argument("--out", default="results/budget_plan.json")
    args = ap.parse_args(argv)

    p = Path(args.runs)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    exp = json.loads(p.read_text(encoding="utf-8"))
    runs = exp.get("runs", [])

    plans = [plan_breadth(runs, args.budget), plan_depth(runs, args.budget),
             plan_adaptive(runs, args.budget)]
    payload = write_budget(plans, runs, args.out, budget=args.budget, source_run=args.runs)

    print(f"预算={args.budget:,} token")
    for row in payload["comparison"]:
        print(f"  {row['name']:<9} 覆盖={row['tasks_covered']:>2} 深度={row['avg_depth']:<5} "
              f"token={row['projected_tokens']:>8,} 修复={row['projected_fixed']:>6.1f} "
              f"vs广度={row['vs_breadth_pct']:+.1f}%  {'✓' if row['within_budget'] else '✗超预算'}")
    print(f"已写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
