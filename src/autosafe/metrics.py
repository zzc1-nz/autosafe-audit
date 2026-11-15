"""核心分析：边际 token 收益、拐点检测、建议迭代深度。

核心问题
--------
AutoSafeCoder 报告"漏洞减少 13%"，但没回答：**这个提升花了多少 token？迭代到第几轮之后
继续审计不再划算？**

本模块把每轮审计视为一次投资：
* 投入 = 该轮三个 Agent 的 token 消耗
* 回报 = 该轮**新发现并验证修复**的漏洞数（重复报告与假修复不算回报）
* 边际收益 = 该轮回报 / 该轮投入 × 100,000 —— 即"每额外消耗 10 万 token 能多修几个漏洞"

拐点定义（严格）
----------------
**拐点 = 第一个轮次 r，使得从 r 起（含 r）之后每一轮的边际收益都 < 阈值（默认 0.1）**。

用"持续低于"而不是"首次低于"，是因为真实曲线非单调：某一轮可能因为某个漏洞终于被修好
而反弹。只看首次穿越会把噪声当拐点。同时保留 `first_below_round` 作为对照。

若整个观测窗口内都没跌到阈值以下，但趋势显著下降（对 (round, log(边际收益+eps)) 做线性回归，
斜率 < 0 且 R² >= 0.6），用回归外推求穿越轮次 —— 明确标记 `method="loglinear_extrapolation"`，
绝不把外推值伪装成观测值。

为什么用"每 10 万 token"而不是"每轮"
------------------------------------
单轮 token 会随上下文膨胀而上涨，用"每轮修复数"会低估后期成本。以 token 为单位才能跨
任务类型、跨模型、跨预算规模比较。
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# 边际收益阈值：每 10 万 token 修复漏洞数
DEFAULT_THRESHOLD = 0.1
DEFAULT_MAX_ROUNDS = 8
# 外推时允许的最大轮次（防止荒谬外推）
EXTRAPOLATION_CAP = 20.0
_EPS = 1e-9


# --------------------------------------------------------------------------- #
# 数据加载
# --------------------------------------------------------------------------- #
def load_experiment(path: str | Path) -> dict:
    """读取实验 JSON。"""
    p = Path(path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    return json.loads(p.read_text(encoding="utf-8"))


def _run_rounds(run: dict) -> list[dict]:
    return list(run.get("rounds", []))


# --------------------------------------------------------------------------- #
# 曲线聚合
# --------------------------------------------------------------------------- #
def aggregate_curve(runs: Sequence[dict], max_rounds: int | None = None) -> list[dict]:
    """把所有任务的逐轮数据聚合成一条全局曲线。

    **口径**：第 r 轮的值 = 所有任务各自跑到 ``min(r, 该任务实际轮数)`` 时的累计值之和。

    即"把 N 个任务都审到第 r 轮"（提前收敛的任务沿用其最终值）。
    这样累计 token 与累计修复数**必然单调不减**——这是"累计"曲线的定义要求。
    如果只对"还活着"的任务求和，任务提前退出会让总和下降，产生负的边际收益，
    那既不符合现实（已花的 token 不会退回来），也会让 log-linear 外推失去意义。
    """
    if not runs:
        return []
    n_max = max_rounds or max((len(_run_rounds(r)) for r in runs), default=0)
    curve: list[dict] = []
    prev_cum_tokens = 0
    prev_cum_fixed = 0
    for r in range(1, n_max + 1):
        cum_tokens = 0
        cum_fixed = 0
        round_tokens = 0
        round_fixed = 0
        n_active = 0
        for run in runs:
            rounds = _run_rounds(run)
            if not rounds:
                continue
            idx = min(r, len(rounds)) - 1          # 提前收敛的任务沿用最终轮
            rec = rounds[idx]
            cum_tokens += int(rec.get("cumulative_tokens", 0))
            cum_fixed += int(rec.get("cumulative_fixed", 0))
            if len(rounds) >= r:
                n_active += 1
                round_tokens += int(rec.get("tokens_total", 0))
                round_fixed += int(rec.get("defects_fixed", 0))
        d_tokens = cum_tokens - prev_cum_tokens
        d_fixed = cum_fixed - prev_cum_fixed
        marginal = (d_fixed / d_tokens * 100_000) if d_tokens > 0 else 0.0
        curve.append({
            "round": r,
            "cum_tokens": cum_tokens,
            "cum_fixed": cum_fixed,
            "round_tokens": round_tokens,
            "round_fixed": round_fixed,
            "marginal_per_100k": round(marginal, 4),
            "avg_fixed_per_100k": round(cum_fixed / cum_tokens * 100_000, 4) if cum_tokens else 0.0,
            "n_tasks": n_active,
            "n_tasks_total": len(runs),
            "delta_tokens": d_tokens,
            "delta_fixed": d_fixed,
        })
        prev_cum_tokens = cum_tokens
        prev_cum_fixed = cum_fixed
    return curve


def family_curves(runs: Sequence[dict]) -> dict[str, list[dict]]:
    """按任务类型分别聚合曲线。"""
    by_family: dict[str, list[dict]] = {}
    for run in runs:
        by_family.setdefault(run.get("family", "unknown"), []).append(run)
    return {fam: aggregate_curve(rs) for fam, rs in sorted(by_family.items())}


# --------------------------------------------------------------------------- #
# 拐点检测
# --------------------------------------------------------------------------- #
def _linear_fit(xs: Sequence[float], ys: Sequence[float]) -> tuple[float, float, float]:
    """最小二乘 y = a + b*x，返回 (a, b, r2)。"""
    n = len(xs)
    if n < 2:
        return 0.0, 0.0, 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx <= _EPS:
        return my, 0.0, 0.0
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    b = sxy / sxx
    a = my - b * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
    r2 = 1.0 - ss_res / ss_tot if ss_tot > _EPS else 1.0
    return a, b, r2


def find_knee(
    curve: Sequence[dict],
    *,
    threshold_per_100k: float = DEFAULT_THRESHOLD,
    window: int = 100_000,
    max_isolated_rebounds: int = 1,
) -> dict:
    """在曲线上找"边际 token 收益趋零"的拐点。

    判据（三重，主判据是 A）
    ------------------------
    **A. 持续低于阈值（主判据）**：第一个轮次 r，使得从 r 起之后每一轮的边际收益
    都 < 阈值，**但允许尾部最多 ``max_isolated_rebounds`` 次孤立反弹**。

    为什么允许孤立反弹：真实数据里长尾缺陷会在很晚的某一轮才终于被修好，造成单点反弹
    （本项目实测第 8 轮就出现了 5.38/10万token 的反弹，而第 5-7 轮严格为 0）。
    若要求"之后每一轮都低于阈值"，这种孤立事件会让拐点被误判为"未到达"，
    与"绝大部分轮次已无收益"的事实相悖。允许 1 次孤立反弹后，判据既稳健又不掩盖长尾。

    **B. 尾部平均（对照）**：从 r 到最后一轮的总增量 / 总增量 token < 阈值。
    这是"在 r 之后每额外 10 万 token 多修复不到 X 个"的字面实现，抗单点噪声但会被
    极小的尾部样本稀释，故作为对照而非主判据。

    **C. 相对阈值（无标度对照）**：边际收益跌破首轮的 10%。
    不依赖绝对 token 规模，用于验证结论不是阈值尺度造成的假象。

    返回
    ----
    knee_round : int | None      主判据拐点；未观测到则 None
    crossed / observed : bool    是否穿越 / 是否由观测直接得到
    method : "observed" | "loglinear_extrapolation" | "not_reached"
    first_below_round : int|None 首次低于阈值（即使之后反弹）
    tail_avg_knee_round : int|None  判据 B
    relative_knee_round : int|None  判据 C
    marginal_series / tail_marginal_series : list[float]
    """
    marg = [float(p.get("marginal_per_100k", 0.0)) for p in curve]
    cum_tok = [int(p.get("cum_tokens", 0)) for p in curve]
    cum_fix = [int(p.get("cum_fixed", 0)) for p in curve]
    rounds = [int(p.get("round", i + 1)) for i, p in enumerate(curve)]
    n = len(marg)
    base = {
        "threshold": threshold_per_100k,
        "window": window,
        "n_rounds": n,
        "marginal_series": [round(m, 4) for m in marg],
        "tail_marginal_series": [],
        "knee_round": None,
        "crossed": False,
        "observed": False,
        "interpolated_round": None,
        "first_below_round": None,
        "tail_avg_knee_round": None,
        "relative_knee_round": None,
        "isolated_rebounds": [],
        "method": "not_reached",
        "fit": None,
    }
    if n == 0:
        return base

    base["first_below_round"] = next(
        (rounds[i] for i, m in enumerate(marg) if m < threshold_per_100k), None
    )

    # ---- 判据 B：尾部平均边际 ----
    tail_series: list[float] = []
    for i in range(n):
        if i == 0:
            d_tok = cum_tok[-1]
            d_fix = cum_fix[-1]
        else:
            d_tok = cum_tok[-1] - cum_tok[i - 1]
            d_fix = cum_fix[-1] - cum_fix[i - 1]
        tail_series.append(round(d_fix / d_tok * 100_000, 4) if d_tok > 0 else 0.0)
    base["tail_marginal_series"] = tail_series
    base["tail_avg_knee_round"] = next(
        (rounds[i] for i, t in enumerate(tail_series) if t < threshold_per_100k), None
    )

    # ---- 判据 C：相对阈值（首轮的 10%）----
    first = marg[0] if marg else 0.0
    rel_threshold = first * 0.10
    base["relative_threshold"] = round(rel_threshold, 4)
    if first > 0:
        base["relative_knee_round"] = next(
            (rounds[i] for i, m in enumerate(marg) if m < rel_threshold), None
        )

    # ---- 判据 A：持续低于阈值（允许尾部有限的孤立反弹）----
    def _tail_ok(start: int) -> bool:
        """从 start 起，高于阈值的轮次是否构成"尾部孤立反弹"。

        要求（缺一不可）：
        1. **start 那一轮本身必须低于阈值**（否则拐点没有意义）；
        2. 高于阈值的轮次数 <= max_isolated_rebounds（默认 1）；
        3. 反弹必须**晚于**拐点至少一轮，且反弹之后必须还有低值轮次——
           即"趋零 → 长尾偶发 → 继续趋零"的真实形态。
           这排除了"刚低于阈值就立刻反弹"的伪拐点。
        """
        if marg[start] >= threshold_per_100k:
            return False
        highs = [i for i in range(start, n) if marg[i] >= threshold_per_100k]
        if len(highs) > max_isolated_rebounds:
            return False
        for h in highs:
            # 末轮反弹是典型的长尾事件（某个难修缺陷直到最后才修好），
            # 它不可能是"持续产出"——因为观测窗口到此为止。故一律允许。
            if h == n - 1:
                continue
            # 非末轮的反弹必须与拐点之间至少隔一轮低值（"趋零 → 稳定 → 偶发长尾"），
            # 否则说明刚跌破阈值就反弹，那还没真正趋零，不能算拐点。
            if h <= start + 1:
                return False
            # 反弹之后必须还有低值轮次，否则是"尾部连续高收益"而非孤立事件
            if not any(marg[j] < threshold_per_100k for j in range(h + 1, n)):
                return False
        return True

    for start in range(n):
        if _tail_ok(start):
            highs = [rounds[i] for i in range(start, n) if marg[i] >= threshold_per_100k]
            base.update({
                "knee_round": rounds[start],
                "crossed": True,
                "observed": True,
                "interpolated_round": float(rounds[start]),
                "isolated_rebounds": highs,
                "method": "observed",
            })
            return base
    # ---- 未观测到：log-linear 外推 ----
    # 真实数据里边际收益可能为负（聚合口径修正后不应出现，但保留防御），
    # log 只接受正数，统一 clamp 到 eps 后再取对数。
    xs = [float(x) for x in rounds]
    ys = [math.log(max(m, 0.0) + _EPS) for m in marg]
    a, b, r2 = _linear_fit(xs, ys)
    base["fit"] = {"a": round(a, 6), "b": round(b, 6), "r2": round(r2, 4)}
    if b < 0 and r2 >= 0.6:
        x_cross = (math.log(threshold_per_100k + _EPS) - a) / b
        x_cross = max(float(rounds[0]), min(EXTRAPOLATION_CAP, x_cross))
        base.update({
            "knee_round": int(math.ceil(x_cross)),
            "crossed": False,
            "observed": False,
            "interpolated_round": round(x_cross, 2),
            "method": "loglinear_extrapolation",
        })
        return base

    base["method"] = "not_reached"
    return base


# --------------------------------------------------------------------------- #
# 建议迭代深度
# --------------------------------------------------------------------------- #
_FAMILY_RATIONALE_HINT = {
    "injection": "注入类缺陷特征明显（危险 sink 直接可见），通常 1-2 轮即被扫净，继续迭代只是重复报告。",
    "path_traversal": "路径遍历能被静态规则与恶意路径 fuzz 双重命中，修复后验证成本低。",
    "deserialization": "反序列化风险点多在调用链深处，需要 1-2 轮才能暴露完整。",
    "crypto": "弱算法/短密钥是局部模式，但'换库不改语义'的假修复常见，需要额外一轮验证。",
    "secrets": "硬编码凭据一轮即可定位，但密钥迁移涉及配置面，常需第二轮收尾。",
    "authz": "缺失鉴权属于语义缺陷，工具看不见，靠 LLM 反复提示逐轮逼近，是典型长尾。",
    "web": "输入校验/输出编码类问题需要多轮交叉验证（静态 + 动态）。",
    "randomness": "不安全随机数易被识别，但'换成 SystemRandom 仍不够'这类假修复会拖轮次。",
    "config": "调试开关/不安全默认值定位简单，一轮即可收敛。",
}


def recommend_depth(
    runs: Sequence[dict],
    *,
    threshold_per_100k: float = DEFAULT_THRESHOLD,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
) -> list[dict]:
    """按任务类型给出建议迭代深度。"""
    fams = family_curves(runs)
    # 每 family 的任务数
    fam_tasks: dict[str, int] = {}
    for run in runs:
        fam_tasks[run.get("family", "unknown")] = fam_tasks.get(run.get("family", "unknown"), 0) + 1

    rows: list[dict] = []
    for fam, curve in fams.items():
        if not curve:
            continue
        knee = find_knee(curve, threshold_per_100k=threshold_per_100k)
        total_fixed = curve[-1]["cum_fixed"] if curve else 0
        total_tokens = curve[-1]["cum_tokens"] if curve else 0

        # 达到 90% 最终收益所需轮次
        rounds_to_90 = len(curve)
        if total_fixed > 0:
            target = 0.9 * total_fixed
            for p in curve:
                if p["cum_fixed"] >= target:
                    rounds_to_90 = int(p["round"])
                    break

        # 建议深度：观测到拐点用拐点；否则用 90% 轮次与（外推）拐点的较小者
        knee_obs = knee.get("interpolated_round") if knee.get("interpolated_round") else None
        if knee.get("observed") and knee.get("knee_round"):
            rec = int(knee["knee_round"])
        elif knee_obs:
            rec = int(math.ceil(min(float(knee_obs), float(rounds_to_90))))
        else:
            rec = rounds_to_90
        rec = max(1, min(int(max_rounds), rec))

        # 建议深度处的边际收益与单价
        marg_at = next(
            (p["marginal_per_100k"] for p in curve if int(p["round"]) == rec),
            curve[-1]["marginal_per_100k"] if curve else 0.0,
        )
        cum_at = next((p for p in curve if int(p["round"]) == rec), curve[-1] if curve else None)
        tokens_per_fix = (
            cum_at["cum_tokens"] / cum_at["cum_fixed"]
            if cum_at and cum_at["cum_fixed"] > 0
            else (total_tokens / total_fixed if total_fixed > 0 else 0.0)
        )

        hint = _FAMILY_RATIONALE_HINT.get(fam, "")
        if knee.get("method") == "observed":
            rationale = f"第 {rec} 轮后边际收益已跌破 {threshold_per_100k}/10万token，{hint}"
        elif knee.get("method") == "loglinear_extrapolation":
            rationale = (
                f"观测窗口内未跌破阈值，按趋势外推约第 {knee.get('interpolated_round')} 轮趋零；"
                f"保守取 90% 收益轮次（{rounds_to_90}）与建议深度 {rec}。{hint}"
            )
        else:
            rationale = f"边际收益下降不显著，建议按 90% 收益轮次 {rounds_to_90} 迭代。{hint}"

        rows.append({
            "family": fam,
            "tasks": fam_tasks.get(fam, 0),
            "recommended_depth": rec,
            "knee_round": knee.get("interpolated_round"),
            "knee_observed": bool(knee.get("observed")),
            "rounds_to_90pct": int(rounds_to_90),
            "marginal_at_knee": round(float(marg_at), 4),
            "tokens_per_fix_at_recommended": round(float(tokens_per_fix), 1),
            "total_tokens_at_max": int(total_tokens),
            "total_fixed_at_max": int(total_fixed),
            "rationale": rationale,
        })
    rows.sort(key=lambda r: (-r["recommended_depth"], r["family"]))
    return rows


# --------------------------------------------------------------------------- #
# 维度拆解
# --------------------------------------------------------------------------- #
def _breakdown(runs: Sequence[dict], key: str, task_field) -> dict[str, dict]:
    """按某个维度（通道/难度）统计缺陷的发现与修复。"""
    out: dict[str, dict] = {}
    for run in runs:
        rounds = _run_rounds(run)
        tokens = sum(int(r.get("tokens_total", 0)) for r in rounds)
        fixed = sum(int(r.get("defects_fixed", 0)) for r in rounds)
        slot = out.setdefault(task_field(run), {
            "tasks": 0, "defects": 0, "fixed": 0, "tokens": 0, "rounds": 0,
        })
        slot["tasks"] += 1
        slot["defects"] += int(run.get("total_defects", 0))
        slot["fixed"] += fixed
        slot["tokens"] += tokens
        slot["rounds"] += len(rounds)
    for slot in out.values():
        d = slot["defects"] or 1
        slot["fix_rate"] = round(slot["fixed"] / d, 4)
        slot["avg_round_fixed"] = round(slot["fixed"] / max(1, slot["rounds"]), 4)
        slot["tokens_per_fix"] = round(slot["tokens"] / max(1, slot["fixed"]), 1)
    return out


def channel_breakdown(runs: Sequence[dict], tasks_meta: dict[str, dict] | None = None) -> dict[str, dict]:
    """按检测通道拆解（需要任务库提供每个 defect 的通道）。"""
    out: dict[str, dict] = {}
    for run in runs:
        tid = run.get("task_id", "")
        meta = (tasks_meta or {}).get(tid, {})
        defects = meta.get("defects", [])
        if not defects:
            continue
        fixed_ids = {i for r in _run_rounds(run) for i in r.get("newly_fixed_ids", [])}
        tokens = sum(int(r.get("tokens_total", 0)) for r in _run_rounds(run))
        for d in defects:
            ch = d.get("channel", "unknown")
            slot = out.setdefault(ch, {"defects": 0, "fixed": 0, "tokens": 0, "rounds": 0})
            slot["defects"] += 1
            slot["fixed"] += 1 if d.get("defect_id") in fixed_ids else 0
            slot["tokens"] += tokens
            slot["rounds"] += len(_run_rounds(run))
    for slot in out.values():
        slot["fix_rate"] = round(slot["fixed"] / max(1, slot["defects"]), 4)
        slot["avg_round_fixed"] = round(slot["fixed"] / max(1, slot["rounds"]), 4)
        slot["tokens_per_fix"] = round(slot["tokens"] / max(1, slot["fixed"]), 1)
    return out


# --------------------------------------------------------------------------- #
# 汇总与主入口
# --------------------------------------------------------------------------- #
def summary(runs: Sequence[dict]) -> dict:
    """全局汇总。"""
    total_tokens = sum(int(r.get("total_tokens", 0)) for r in runs)
    total_fixed = sum(int(r.get("total_fixed", 0)) for r in runs)
    total_defects = sum(int(r.get("total_defects", 0)) for r in runs)
    total_rounds = sum(len(_run_rounds(r)) for r in runs)
    residual = sum(len(r.get("residual_defect_ids", [])) for r in runs)
    undetected = sum(len(r.get("undetected_defect_ids", [])) for r in runs)
    stops: dict[str, int] = {}
    for r in runs:
        s = r.get("stop_reason", "unknown") or "unknown"
        stops[s] = stops.get(s, 0) + 1
    return {
        "total_tokens": total_tokens,
        "total_fixed": total_fixed,
        "total_defects": total_defects,
        "total_rounds": total_rounds,
        "tasks": len(runs),
        "tokens_per_fix": round(total_tokens / max(1, total_fixed), 1),
        "fix_rate": round(total_fixed / max(1, total_defects), 4),
        "residual_defects": residual,
        "undetected_defects": undetected,
        "avg_rounds_used": round(total_rounds / max(1, len(runs)), 2),
        "stop_reason_counts": stops,
    }


def _load_task_meta() -> dict[str, dict]:
    """尽力加载任务库元数据（通道拆解需要）；失败则返回空。"""
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "src"))
        from autosafe.tasks.library import TASKS  # type: ignore

        return {t.task_id: t.to_dict() for t in TASKS}
    except Exception:
        return {}


def analyze(experiment: dict) -> dict:
    """汇总全部分析结果，可直接 json.dump。"""
    runs = experiment.get("runs", [])
    meta_in = experiment.get("meta", {})
    curve = aggregate_curve(runs)
    fams = family_curves(runs)
    knee = find_knee(curve)
    fam_knees = {fam: find_knee(c) for fam, c in fams.items()}
    tasks_meta = _load_task_meta()

    # 阈值敏感性：同一份数据换阈值，看拐点怎么动
    sensitivity: dict[str, dict] = {}
    for thr in (0.05, 0.1, 0.2):
        k = find_knee(curve, threshold_per_100k=thr)
        sensitivity[str(thr)] = {
            "threshold": thr,
            "knee_round": k.get("knee_round"),
            "interpolated_round": k.get("interpolated_round"),
            "method": k.get("method"),
            "crossed": k.get("crossed"),
        }

    return {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "provider": meta_in.get("provider", "unknown"),
            "model": meta_in.get("model", "unknown"),
            "max_rounds": meta_in.get("max_rounds", DEFAULT_MAX_ROUNDS),
            "task_count": meta_in.get("task_count", len(runs)),
            "seed": meta_in.get("seed"),
            "threshold_per_100k": DEFAULT_THRESHOLD,
            "policy_version": "v1",
        },
        "summary": summary(runs),
        "curve": curve,
        "families": fams,
        "knee": knee,
        "family_knees": fam_knees,
        "depth_recommendations": recommend_depth(runs),
        "channel_breakdown": channel_breakdown(runs, tasks_meta),
        "difficulty_breakdown": _breakdown(runs, "difficulty", lambda r: r.get("difficulty", "unknown")),
        "sensitivity": sensitivity,
    }


def write_analysis(experiment: dict, out_path: str | Path) -> dict:
    """分析并落盘。"""
    result = analyze(experiment)
    p = Path(out_path)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AutoSafe-Audit 边际收益分析")
    ap.add_argument("--runs", default="results/runs/main_experiment.json")
    ap.add_argument("--out", default="results/analysis.json")
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    args = ap.parse_args(argv)

    exp = load_experiment(args.runs)
    result = write_analysis(exp, args.out)
    s = result["summary"]
    k = result["knee"]
    print(f"任务数={s['tasks']} 总token={s['total_tokens']:,} 总修复={s['total_fixed']}/{s['total_defects']}")
    print(f"每修复 token={s['tokens_per_fix']:,} 修复率={s['fix_rate']:.1%}")
    print(f"全局拐点: method={k['method']} knee_round={k['knee_round']} "
          f"interpolated={k['interpolated_round']} 阈值={k['threshold']}/10万token")
    print("按类型建议深度:")
    for row in result["depth_recommendations"]:
        print(f"  {row['family']:<16} 深度={row['recommended_depth']} "
              f"拐点={row['knee_round']} 90%轮次={row['rounds_to_90pct']} "
              f"修复单价={row['tokens_per_fix_at_recommended']:,.0f} token")
    print(f"已写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
