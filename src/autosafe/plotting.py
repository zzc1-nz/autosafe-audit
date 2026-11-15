"""五张核心图表：token 边际收益递减、拐点、建议深度与预算分配。

设计原则
--------
1. **每张图必须能独立看懂**：标题写结论、图内带"读图要点"、轴标签带单位。
2. **不重复实现分析逻辑**：拐点/建议深度一律从 ``analysis`` 的 ``knee`` /
   ``depth_recommendations`` 读取，保证图与 REPORT.md 的表格数字一致。
3. **中文字体**：``Microsoft YaHei`` / ``SimHei``，``axes.unicode_minus=False``。
4. **绝不 ``plt.show()``**：只 ``fig.savefig`` + ``plt.close(fig)``（无 GUI 环境下必须如此）。
5. **布局一律用 ``constrained_layout``**：注释框/图例/色标不允许互相遮挡，
   也不允许压住数据——"读图要点"统一放在坐标区之外的画布留白处。

所有 ``fig_*`` 函数返回 PNG 的绝对路径字符串。
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Mapping, Sequence

import matplotlib

matplotlib.use("Agg")  # 必须在 pyplot 之前设置，避免在无显示环境下崩溃

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib import ticker  # noqa: E402
from matplotlib.colors import Normalize  # noqa: E402

from .schema import FAMILIES, FAMILY_LABELS  # noqa: E402

# ---------------------------------------------------------------- 全局样式

DPI = 180

# 主色板（深蓝 + 强调红，打印与屏幕都清晰）
C_PRIMARY = "#1f4e79"
C_BLUE = "#2e6da4"
C_BLUE_LIGHT = "#8fb8d8"
C_RED = "#c0392b"
C_RED_LIGHT = "#e8a6a0"
C_GREEN = "#2e7d32"
C_ORANGE = "#e67e22"
C_PURPLE = "#6a3d9a"
C_GRAY = "#7f8c8d"
C_GRAY_LIGHT = "#d5dbdb"
C_INK = "#20313d"

# 3 条典型 family 的配色与 marker（曲线族要能一眼区分）
FAMILY_STYLE: dict[str, tuple[str, str]] = {
    "injection": (C_RED, "s"),
    "authz": (C_PURPLE, "^"),
    "crypto": (C_ORANGE, "D"),
    "path_traversal": (C_GREEN, "v"),
    "deserialization": (C_BLUE, "P"),
    "secrets": ("#16a085", "X"),
    "web": ("#8e44ad", "o"),
    "randomness": ("#d35400", "h"),
    # 注意：不要用 "*"，它与"广度覆盖点"的星形标记冲突，图例里会看起来被遮挡
    "config": (C_GRAY, "p"),
}

# 图例里用的短标签（完整标签太长，会挤爆图例）
FAMILY_SHORT: dict[str, str] = {
    "injection": "注入类",
    "path_traversal": "路径遍历",
    "deserialization": "反序列化",
    "crypto": "密码学",
    "secrets": "硬编码凭据",
    "authz": "鉴权/权限",
    "web": "Web 输入输出",
    "randomness": "随机性/令牌",
    "config": "配置/调试开关",
}


def _apply_style() -> None:
    """设置中文字体、网格与排版参数（幂等）。"""
    plt.rcParams.update(
        {
            "font.sans-serif": ["Microsoft YaHei", "SimHei", "DejaVu Sans"],
            "font.family": "sans-serif",
            "axes.unicode_minus": False,
            "figure.dpi": 120,
            "savefig.dpi": DPI,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.20,
            "axes.grid": True,
            "axes.grid.axis": "both",
            "grid.alpha": 0.26,
            "grid.linestyle": "-",
            "grid.linewidth": 0.6,
            "grid.color": "#9aa4ab",
            "axes.edgecolor": "#4a4a4a",
            "axes.linewidth": 0.9,
            "axes.titlesize": 12.5,
            "axes.titleweight": "bold",
            "axes.titlepad": 9,
            "axes.labelsize": 10.5,
            "axes.labelcolor": "#222222",
            "xtick.labelsize": 9.5,
            "ytick.labelsize": 9.5,
            "xtick.color": "#333333",
            "ytick.color": "#333333",
            "legend.fontsize": 8.8,
            "legend.framealpha": 0.94,
            "legend.edgecolor": "#bbbbbb",
            "figure.facecolor": "white",
            "axes.facecolor": "white",
        }
    )


# ---------------------------------------------------------------- 取数与兜底

def _num(value: Any, default: float = 0.0) -> float:
    """把任意值安全转成 float（None / 非数 / NaN → default）。"""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(v) or math.isinf(v):
        return default
    return v


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _run_dict(run: Any) -> dict[str, Any]:
    """TaskRun 对象或 dict 统一成 dict。"""
    if isinstance(run, Mapping):
        return dict(run)
    to_dict = getattr(run, "to_dict", None)
    if callable(to_dict):
        return dict(to_dict())
    return {}


def _runs_of(source: Any) -> list[dict[str, Any]]:
    """从 experiment dict / run 列表里取出 run dict 列表。"""
    if source is None:
        return []
    if isinstance(source, Mapping):
        runs = source.get("runs")
        if isinstance(runs, Sequence) and not isinstance(runs, (str, bytes)):
            return [_run_dict(r) for r in runs]
        return []
    if isinstance(source, Sequence) and not isinstance(source, (str, bytes)):
        return [_run_dict(r) for r in source]
    return []


def _curve_from_runs(runs: Sequence[Any]) -> list[dict[str, Any]]:
    """兜底：analysis 缺 curve 时，从原始 runs 现算逐轮聚合曲线。"""
    rows = [_run_dict(r) for r in runs]
    max_round = max((len(r.get("rounds") or []) for r in rows), default=0)
    curve: list[dict[str, Any]] = []
    cum_t = cum_f = 0
    for r in range(1, max_round + 1):
        rt = rf = 0
        for row in rows:
            for rec in row.get("rounds") or []:
                if int(_num(rec.get("round_index"))) != r:
                    continue
                rt += int(_num(rec.get("tokens_total"),
                               _num(rec.get("tokens_in")) + _num(rec.get("tokens_out"))))
                rf += int(_num(rec.get("defects_fixed")))
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


def _summary(analysis: Any) -> Mapping[str, Any]:
    return _mapping(_mapping(analysis).get("summary"))


def _meta(analysis: Any) -> Mapping[str, Any]:
    return _mapping(_mapping(analysis).get("meta"))


def _raw_curve(analysis: Any) -> list[dict[str, Any]]:
    """原始（未归一）逐轮曲线：优先 analysis.curve，缺失时从 runs 现算。"""
    data = _mapping(analysis)
    curve = data.get("curve")
    if isinstance(curve, Sequence) and len(curve) > 0 and isinstance(curve[0], Mapping):
        return [dict(c) for c in curve]
    return _curve_from_runs(_runs_of(data))


def _n_tasks(analysis: Any, curve: Sequence[Mapping[str, Any]] | None = None) -> int:
    """任务总数（用于把"全库合计"换算成"每任务平均"）。"""
    candidates: list[Mapping[str, Any]] = [_summary(analysis), _meta(analysis)]
    if curve:
        candidates.append(curve[-1])
    for src in candidates:
        for key in ("tasks", "task_count", "n_tasks"):
            v = _num(src.get(key))
            if v >= 1:
                return int(v)
    return 1


def _curve_is_totals(analysis: Any, curve: Sequence[Mapping[str, Any]]) -> bool:
    """判断 curve 的 token 是"全库合计"还是"每任务平均"。

    用 ``summary.total_tokens`` 与逐轮 round_tokens 之和做交叉校验：
    若两者量级一致 → 合计；若乘上任务数后才一致 → 平均。取不到证据时按合计处理
    （``aggregate_curve`` 的自然语义就是把所有 run 加起来）。
    """
    total = _num(_summary(analysis).get("total_tokens"))
    s = sum(_num(c.get("round_tokens")) for c in curve)
    if total <= 0 or s <= 0:
        return True
    n = _n_tasks(analysis, curve)
    if abs(s - total) <= 0.20 * total:
        return True
    if n > 1 and abs(s * n - total) <= 0.20 * total:
        return False
    return s > total * 1.2


def _normalize_curve(curve: Sequence[Mapping[str, Any]], divisor: float) -> list[dict[str, Any]]:
    """把曲线换算成"每任务平均"口径。

    口径必须分两种，否则数字会错：

    * **累计量**（cum_tokens / cum_fixed）除以**任务总数**：含义是"平均每个任务累计
      花了多少 token / 修了多少洞"，且保持单调（任务中途收敛不应让累计值跳动）。
    * **单轮量**（round_tokens / round_fixed）除以**该轮实际在跑的任务数 n_tasks**：
      含义是"该轮每个仍在迭代的任务花了多少"，这才是"单轮成本"。

    早期版本对两者都用同一个除数，当 n_tasks 逐轮下降（25→13）时，
    累计值会被系统性放大，单轮值会被低估。
    """
    total = divisor if divisor and divisor > 0 else 1.0
    out: list[dict[str, Any]] = []
    for c in curve:
        active = _num(c.get("n_tasks")) or total
        out.append(
            {
                "round": int(_num(c.get("round"))),
                "cum_tokens": _num(c.get("cum_tokens")) / total,
                "cum_fixed": _num(c.get("cum_fixed")) / total,
                "round_tokens": _num(c.get("round_tokens")) / active,
                "round_fixed": _num(c.get("round_fixed")) / active,
                "marginal_per_100k": _num(c.get("marginal_per_100k")),
                "avg_fixed_per_100k": _num(c.get("avg_fixed_per_100k")),
                "n_tasks": int(active),
            }
        )
    return out


def _curve(analysis: Any) -> list[dict[str, Any]]:
    """归一后的全库逐轮曲线（每任务平均口径）。"""
    raw = _raw_curve(analysis)
    if not raw:
        return []
    div = _n_tasks(analysis, raw) if _curve_is_totals(analysis, raw) else 1
    return _normalize_curve(raw, div)


def _families(analysis: Any) -> dict[str, list[dict[str, Any]]]:
    """family -> 原始曲线。"""
    data = _mapping(analysis)
    fams = data.get("families")
    if isinstance(fams, Mapping) and fams:
        out: dict[str, list[dict[str, Any]]] = {}
        for name, curve in fams.items():
            if isinstance(curve, Sequence) and len(curve) > 0 and isinstance(curve[0], Mapping):
                out[str(name)] = [dict(c) for c in curve]
        if out:
            return out
    # 兜底：从 runs 现算
    rows = _runs_of(data)
    by_family: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_family.setdefault(str(row.get("family") or "unknown"), []).append(row)
    return {k: _curve_from_runs(v) for k, v in by_family.items()}


def _raw_depth_rows(analysis: Any) -> list[dict[str, Any]]:
    """只读 analysis.depth_recommendations，不做任何兜底（避免与兜底逻辑互相递归）。"""
    rows = _mapping(analysis).get("depth_recommendations")
    if isinstance(rows, Sequence) and rows and isinstance(rows[0], Mapping):
        return [dict(r) for r in rows]
    return []


def _family_task_counts(analysis: Any) -> dict[str, int]:
    """每个 family 的任务数：优先 depth_recommendations.tasks，其次 runs 计数。"""
    counts: dict[str, int] = {}
    for row in _raw_depth_rows(analysis):
        fam = str(row.get("family") or "")
        if fam:
            counts[fam] = int(_num(row.get("tasks"), 1)) or 1
    if counts:
        return counts
    for row in _runs_of(_mapping(analysis)):
        fam = str(row.get("family") or "")
        if fam:
            counts[fam] = counts.get(fam, 0) + 1
    return counts


def _norm_family_curve(curve: Sequence[Mapping[str, Any]], n_tasks: int,
                       *, is_totals: bool) -> list[dict[str, Any]]:
    return _normalize_curve(curve, n_tasks if is_totals else 1)


def _knee(analysis: Any) -> dict[str, Any]:
    return dict(_mapping(_mapping(analysis).get("knee")))


def _knee_round(knee: Mapping[str, Any]) -> float | None:
    """拐点轮次：优先观测到的整轮，否则用外推的插值轮次。"""
    for key in ("knee_round", "interpolated_round"):
        v = knee.get(key)
        if v is not None and _num(v, -1) > 0:
            return _num(v)
    return None


def _interp(curve: Sequence[Mapping[str, Any]], round_value: float, key: str) -> float:
    """在曲线上按轮次线性插值取某个字段。"""
    if not curve:
        return 0.0
    xs = [_num(c.get("round")) for c in curve]
    ys = [_num(c.get(key)) for c in curve]
    if round_value <= xs[0]:
        return ys[0]
    if round_value >= xs[-1]:
        return ys[-1]
    for i in range(len(xs) - 1):
        if xs[i] <= round_value <= xs[i + 1]:
            span = xs[i + 1] - xs[i]
            t = 0.0 if span <= 0 else (round_value - xs[i]) / span
            return ys[i] + t * (ys[i + 1] - ys[i])
    return ys[-1]


def _depth_rows(analysis: Any) -> list[dict[str, Any]]:
    """建议深度行：优先 depth_recommendations，缺失时从 family 曲线兜底。"""
    rows = _raw_depth_rows(analysis)
    if rows:
        return rows
    # 兜底：用 family 曲线 + 阈值做一个保守估计（仅当 analysis 不完整时使用）
    threshold = _num(_meta(analysis).get("threshold_per_100k"), 0.1) or 0.1
    fams = _families(analysis)
    counts = _family_task_counts(analysis)
    fallback: list[dict[str, Any]] = []
    for fam, curve in fams.items():
        n = counts.get(fam, 1)
        total_fixed = _num(curve[-1].get("cum_fixed")) if curve else 0.0
        depth = len(curve)
        for c in curve:
            if _num(c.get("marginal_per_100k")) < threshold:
                depth = int(_num(c.get("round")))
                break
        cum_tok = _num(curve[-1].get("cum_tokens")) if curve else 0.0
        fallback.append(
            {
                "family": fam,
                "tasks": n,
                "recommended_depth": max(1, depth),
                "knee_round": float(depth),
                "rounds_to_90pct": max(1, depth),
                "marginal_at_knee": threshold,
                "tokens_per_fix_at_recommended": (cum_tok / total_fixed) if total_fixed else 0.0,
                "rationale": "由 family 曲线兜底估算（analysis 未提供 depth_recommendations）",
            }
        )
    return fallback


def _short_family(fam: str) -> str:
    return FAMILY_SHORT.get(fam, fam)


def _family_order_key(fam: str) -> int:
    try:
        return FAMILIES.index(fam)
    except ValueError:
        return len(FAMILIES)


def _save(fig: Any, out_png: str | Path) -> str:
    """保存并关闭图，返回绝对路径。"""
    path = Path(out_png)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=DPI, facecolor="white")
    plt.close(fig)
    return str(path.resolve())


def _tight(fig: Any, **kwargs: Any) -> None:
    """tight_layout 的容错包装（仅为兼容旧调用点；新图一律用 constrained_layout）。"""
    import warnings

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*tight_layout.*")
        try:
            fig.tight_layout(**kwargs)
        except Exception:  # pragma: no cover - 极端布局下退化为默认边距
            pass


def _read_note(fig: Any, text: str, *, y: float = -0.055, fontsize: float = 8.2,
               x: float = 0.5, ha: str = "center") -> None:
    """把"读图要点"写在坐标区之外的画布留白里，保证永远不压数据。

    用**负的 figure 坐标**（画布下沿之外）+ ``savefig.bbox="tight"``：
    matplotlib 计算 tight bbox 时会把这段文字纳入，画布自动向下扩展。
    这样既不需要预留空白（避免图内出现大片死区），也不会与 X 轴标签重叠。
    """
    fig.text(x, y, text, ha=ha, va="top", fontsize=fontsize, color=C_INK,
             linespacing=1.5, zorder=30,
             bbox=dict(boxstyle="round,pad=0.5", facecolor="#f4f7f9", edgecolor="#8aa0ae",
                       linewidth=0.8, alpha=0.97))


# ---------------------------------------------------------------- 图 1：累计曲线

def fig_cumulative_curve(analysis: Any, out_png: str | Path) -> str:
    """累计 token vs 累计修复漏洞数（全库平均 + 3 条典型 family + 拐点标注）。"""
    _apply_style()
    curve = _curve(analysis)
    if not curve:
        raise ValueError("analysis 缺少 curve 字段且无法从 runs 兜底，无法绘制累计曲线")

    n_tasks = _n_tasks(analysis, _raw_curve(analysis))
    xs = [c["cum_tokens"] / 1e4 for c in curve]
    ys = [c["cum_fixed"] for c in curve]

    fig, ax = plt.subplots(figsize=(10.4, 6.8), constrained_layout=True)

    # ---- 全库平均曲线（主视觉）
    ax.plot(xs, ys, color=C_PRIMARY, lw=3.0, marker="o", ms=6.8, mfc="white", mew=1.8,
            label=f"全库平均（{n_tasks} 个任务均值）", zorder=8)

    # ---- 全部 9 条 family 曲线：injection / authz / crypto 加粗（重点），
    #      其余用细点线补全（信息密度更高，也避免"只挑 3 条"的暗示）
    fams = _families(analysis)
    fam_counts = _family_task_counts(analysis)
    raw_curve = _raw_curve(analysis)
    fam_is_totals = _curve_is_totals(analysis, raw_curve) if raw_curve else True
    headline = ("injection", "authz", "crypto")
    ordered = sorted(fams, key=_family_order_key)
    others = [f for f in ordered if f not in headline]
    fam_pts: list[tuple[float, float]] = []      # 收集所有 family 点，用于算坐标范围
    for fam in others + [f for f in headline if f in fams]:
        n = fam_counts.get(fam, 1) or 1
        fc = _norm_family_curve(fams[fam], n, is_totals=fam_is_totals)
        if not fc:
            continue
        color, marker = FAMILY_STYLE.get(fam, (C_GRAY, "o"))
        is_key = fam in headline
        fx = [c["cum_tokens"] / 1e4 for c in fc]
        fy = [c["cum_fixed"] for c in fc]
        fam_pts.extend(zip(fx, fy))
        ax.plot(fx, fy, color=color, lw=2.0 if is_key else 1.2,
                ls="--" if is_key else ":",
                marker=marker, ms=5.4 if is_key else 3.8,
                alpha=0.98 if is_key else 0.72,
                label=f"{_short_family(fam)}（{n}）", zorder=6 if is_key else 4)

    # ---- 坐标范围：让数据铺满画布（X 轴自首个观测点起，非零起点在轴标签注明）
    # 范围必须把 family 曲线也算进去，否则高收益类型会被裁掉
    all_x = list(xs) + [p[0] for p in fam_pts]
    all_y = list(ys) + [p[1] for p in fam_pts]
    x_min, x_max = min(all_x), max(all_x)
    y_min, y_max = min(all_y), max(all_y)
    x_span = max(x_max - x_min, x_max * 0.05 or 1.0)
    y_span = max(y_max - y_min, y_max * 0.05 or 1.0)
    ax.set_xlim(x_min - x_span * 0.08, x_max + x_span * 0.14)
    ax.set_ylim(max(0.0, y_min - y_span * 0.45), y_max + y_span * 0.20)

    x_lo, x_hi = ax.get_xlim()
    y_lo, y_hi = ax.get_ylim()

    # ---- 拐点 / 建议停止点
    knee = _knee(analysis)
    kr = _knee_round(knee)
    threshold = _num(knee.get("threshold"),
                     _num(_meta(analysis).get("threshold_per_100k"), 0.1)) or 0.1

    if kr is not None:
        xk = _interp(curve, kr, "cum_tokens") / 1e4
        yk = _interp(curve, kr, "cum_fixed")
        method = str(knee.get("method") or "")
        observed = bool(knee.get("observed", method == "observed"))
        label = "建议停止点（观测拐点）" if observed else "建议停止点（趋势外推）"
        ax.axvline(xk, color=C_RED, ls=(0, (5, 3)), lw=1.9, zorder=5,
                   label=f"{label}：第 {kr:.1f} 轮 / {xk:.1f} 万 token")
        ax.axvspan(xk, x_hi, color=C_RED, alpha=0.06, zorder=1)
        # 阴影区文字：竖排靠右（不贴顶、不与说明框争位置）
        ax.text(x_hi - (x_hi - xk) * 0.16, y_lo + (y_hi - y_lo) * 0.50,
                "低收益区：继续迭代不划算",
                rotation=90, color="#a04030", fontsize=8.4, ha="center", va="center",
                alpha=0.95, zorder=12)
        # 说明框：放在左下角空白区，**不画长连接箭头**。
        # 曾用 arc3 弧形箭头从停止点连到说明框，结果那条粗弧线被误读成"累计修复数骤降到 0"
        # 的数据曲线（严重误导）。改为：在停止点画一个醒目的菱形标记 + 说明框里写明"见红色虚线"。
        ax.scatter([xk], [yk], marker="D", s=110, color=C_RED, edgecolor="white",
                   linewidth=1.6, zorder=23)
        ax.text(x_lo + (x_hi - x_lo) * 0.03, y_lo + (y_hi - y_lo) * 0.02,
                f"建议停止点：第 {kr:.1f} 轮 · 累计 {xk:.1f} 万 token\n"
                f"边际 {_num(_interp(curve, kr, 'marginal_per_100k')):.2f} 个/10 万 token"
                f"（阈值 {threshold}）\n"
                f"↑ 见红色竖线上的菱形标记",
                fontsize=8.4, color="#7b1e14", ha="left", va="bottom", zorder=21,
                bbox=dict(boxstyle="round,pad=0.4", facecolor="#fdf1ef", edgecolor=C_RED,
                          linewidth=1.0, alpha=0.97))

    # ---- 广度覆盖参考点（每任务 1 轮）
    # 同样不画弧形箭头（会被误读成数据曲线），改用橙色★标记 + 右侧紧邻的短标签。
    if xs and ys:
        ax.scatter([xs[0]], [ys[0]], marker="*", s=340, color=C_ORANGE, edgecolor="white",
                   linewidth=1.1, zorder=9, label="广度覆盖点（每任务 1 轮）")
        ax.annotate(
            "广度覆盖点\n（每任务 1 轮，预算基线）",
            xy=(xs[0], ys[0]),
            xytext=(xs[0] + x_span * 0.035, ys[0] - y_span * 0.13),
            textcoords="data",
            fontsize=8.2, color="#8a5200", ha="left", va="top", zorder=21,
            bbox=dict(boxstyle="round,pad=0.36", facecolor="#fff6e8", edgecolor=C_ORANGE,
                      linewidth=0.9, alpha=0.97),
        )

    # ---- 右上角结论框（结论先行）
    if kr is not None:
        xk = _interp(curve, kr, "cum_tokens") / 1e4
        headline = (f"拐点 ≈ 第 {kr:.1f} 轮\n累计 {xk:.1f} 万 token\n"
                    f"此后每 10 万 token 修复数 < {threshold}")
    else:
        headline = f"未在观测窗口内跌破阈值 {threshold}\n需要更多轮次或更低阈值"
    ax.text(x_hi - x_span * 0.03, y_hi - y_span * 0.06, headline,
            ha="right", va="top", fontsize=9.8, color="#7b1e14", fontweight="bold",
            linespacing=1.5, zorder=22,
            bbox=dict(boxstyle="round,pad=0.5", facecolor="#fff4e6", edgecolor=C_ORANGE,
                      linewidth=1.2, alpha=0.97))

    ax.set_xlabel("累计 token（万 / 任务，X 轴自首个观测点起）")
    ax.set_ylabel("累计修复漏洞数（个 / 任务）")
    ax.set_title("累计 token 与累计修复漏洞数：安全审计的 token 边际收益递减")
    # 图例放到坐标区下方（横向三列），既不压曲线也不压标题
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.115), fontsize=8.4, ncol=3,
              columnspacing=1.0, handlelength=2.2)
    _read_note(
        fig,
        f"读图要点：① 曲线斜率 = 每万 token 能买到几个修复　"
        f"② 拐点之后斜率趋平：token 还在烧、修复数几乎不涨　"
        f"③ 图中 {len(fams)} 条虚线为各任务类型曲线（粗虚线是注入/鉴权/密码学三条重点，"
        f"细点线是其余类型）\n"
        "→ 决策含义：按拐点设预算上限，而不是固定跑满轮次",
        y=-0.055, fontsize=8.0,
    )
    return _save(fig, out_png)

# ---------------------------------------------------------------- 图 2：边际收益

def _symlog_ticks(values: Sequence[float], threshold: float) -> list[float]:
    """为 symlog 轴挑一组可读刻度（含 0、阈值，以及负值时的对称刻度）。"""
    cand = [0.0, 0.01, 0.05, threshold, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0,
            50.0, 100.0, 200.0, 500.0, 1000.0]
    lo = min(list(values) + [0.0])
    hi = max(list(values) + [threshold])
    top = max(abs(hi), abs(lo)) * 3.0
    ticks = [t for t in cand if t <= top]
    if threshold not in ticks:
        ticks.append(threshold)
    if lo < 0:
        negs = [-t for t in ticks if t > 0 and t <= abs(lo) * 3.0]
        ticks = negs + ticks
    return sorted(set(ticks))


def _isolated_rebounds(analysis: Any, curve: Sequence[Mapping[str, Any]],
                       threshold: float) -> list[int]:
    """找出"孤立反弹"的轮次：已跌破阈值后，某一轮边际又回到阈值之上。

    优先读 ``analysis.knee.isolated_rebounds``（分析层判定），缺失时按曲线现算。
    这是本项目最重要的发现之一：深挖偶尔有惊喜，但**没有第二次持续收益**。
    """
    knee = _knee(analysis)
    declared = knee.get("isolated_rebounds")
    if isinstance(declared, Sequence) and not isinstance(declared, (str, bytes)):
        return sorted({int(_num(x)) for x in declared if _num(x) > 0})
    # 兜底：跌破阈值之后再回升的轮次
    out: list[int] = []
    crossed = False
    for c in curve:
        m = _num(c.get("marginal_per_100k"))
        r = int(_num(c.get("round")))
        if not crossed and m < threshold:
            crossed = True
            continue
        if crossed and m >= threshold:
            out.append(r)
    return out


def fig_marginal_curve(analysis: Any, out_png: str | Path) -> str:
    """每轮边际收益（每 10 万 token 修复数）与单轮 token 的"剪刀差"。

    上子图用 **symlog** 轴（linthresh=0.1）：0 映射到 0（不再是 1e-6 那种假高度），
    阈值附近保持线性、可读；为 0 的轮次在柱顶显式标 "0"。

    **"孤立反弹"是本图的核心信息**：边际跌破阈值后，某一轮又小幅回升（例如第 8 轮
    因一个长尾缺陷被修好）。这**不是**"深挖还有持续价值"的证据——它恰恰说明
    期望值极低：跑了 2~3 轮才碰到一次，且立刻又归零。反弹轮次用橙色高亮 + 注释。
    """
    _apply_style()
    curve = _curve(analysis)
    if not curve:
        raise ValueError("analysis 缺少 curve 字段且无法从 runs 兜底，无法绘制边际曲线")

    rounds = [c["round"] for c in curve]
    marginal = [c["marginal_per_100k"] for c in curve]
    average = [c["avg_fixed_per_100k"] for c in curve]
    tokens = [c["round_tokens"] for c in curve]
    fixed = [c["round_fixed"] for c in curve]
    has_negative = any(m < 0 for m in marginal)

    knee = _knee(analysis)
    kr = _knee_round(knee)
    threshold = _num(knee.get("threshold"),
                     _num(_meta(analysis).get("threshold_per_100k"), 0.1)) or 0.1
    rebounds = _isolated_rebounds(analysis, curve, threshold)

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(10.4, 8.4), sharex=True, constrained_layout=True,
        gridspec_kw={"height_ratios": [1.45, 1.0]},
    )

    # ---- 上：symlog 柱状 + 累计平均折线
    linthresh = max(threshold, 1e-3)
    ax1.set_yscale("symlog", linthresh=linthresh, linscale=1.15, base=10)
    pos_max = max([m for m in marginal if m > 0] + [a for a in average if a > 0] + [threshold])
    neg_min = min([m for m in marginal if m < 0] + [0.0])
    # 关键：只有真的存在负值时才给 0 以下留空间。
    # 否则 symlog 会在 0 以下画出无意义的负值区间，导致"0 值柱"被拉成一根尖刺，
    # 视觉上误读成某个很小的正数。
    if neg_min < 0:
        y_lo = neg_min * 1.45
    else:
        y_lo = 0.0
    y_hi = max(pos_max * 2.6, threshold * 4.0)
    ax1.set_ylim(y_lo, y_hi)

    # 上色：高于阈值=绿；低于阈值=浅红；孤立反弹=橙（视觉焦点）；负值=深红（若有）
    colors = []
    for r, m in zip(rounds, marginal):
        if m < 0:
            colors.append(C_RED)
        elif r in rebounds:
            colors.append(C_ORANGE)
        elif m >= threshold:
            colors.append(C_GREEN)
        else:
            colors.append(C_RED_LIGHT)
    ax1.bar(rounds, marginal, width=0.58, color=colors, edgecolor="white", linewidth=1.1,
            zorder=3, label="单轮边际：每 10 万 token 修复数")
    ax1.plot(rounds, average, color=C_PRIMARY, lw=2.1, marker="D", ms=5.8, mfc="white",
             mew=1.5, zorder=6, label="累计平均：每 10 万 token 修复数")
    ax1.axhline(threshold, color=C_RED, ls="--", lw=1.9, zorder=5,
                label=f"收益阈值 {threshold}（低于此线 = 低收益区）")
    ax1.axhline(0.0, color="#444444", lw=1.0, zorder=4)

    ticks = _symlog_ticks(marginal + average, threshold)
    ax1.set_yticks(ticks)
    ax1.set_yticklabels([("0" if t == 0 else f"{t:g}") for t in ticks])
    ax1.yaxis.set_minor_locator(ticker.NullLocator())

    # 柱顶标数值：0 写 "0"；负值写 "负"（保留对旧数据的兼容，正常数据不会出现）
    for r, m in zip(rounds, marginal):
        if m < 0:
            ax1.text(r, m, "负", ha="center", va="top", fontsize=7.8, color="#7b1e14",
                     fontweight="bold", zorder=8)
        elif m == 0:
            ax1.text(r, 0.0, "0", ha="center", va="bottom", fontsize=7.6, color="#8a5a52",
                     zorder=8)

    if kr is not None:
        ax1.axvline(kr, color=C_RED, ls=(0, (5, 3)), lw=1.8, zorder=7,
                    label=f"拐点：第 {kr:.1f} 轮")
        ax1.scatter([kr], [threshold], s=120, facecolor="none", edgecolor=C_RED,
                    linewidth=2.1, zorder=9)
        ax1.annotate(
            f"拐点 第 {kr:.1f} 轮\n边际跌破 {threshold}",
            xy=(kr, threshold),
            xytext=(0.985, 0.32), textcoords="axes fraction",
            fontsize=8.6, color="#7b1e14", ha="right", va="center", zorder=22,
            arrowprops=dict(arrowstyle="->", color=C_RED, lw=1.3,
                            connectionstyle="arc3,rad=0.28"),
            bbox=dict(boxstyle="round,pad=0.38", facecolor="#fdf1ef", edgecolor=C_RED,
                      linewidth=0.9),
        )

    # ---- 孤立反弹注释（核心发现）
    if rebounds:
        rb = rebounds[0]
        mv = _num(next((c["marginal_per_100k"] for c in curve
                        if int(_num(c.get("round"))) == rb), 0.0))
        # 找出反弹前连续的 0 值轮次，量化"等了多久才碰到一次"
        zero_before = sum(
            1 for c in curve
            if int(_num(c.get("round"))) < rb and _num(c.get("marginal_per_100k")) == 0.0
        )
        # 注释放在**左侧中部空白带**（第 1-2 轮的柱很高，但左侧上方有空间），
        # 并给反弹柱画一条短的竖直引线指明位置。
        # 不放右上角（会压图例），也不画弧形箭头（会横穿数据区）。
        ax1.annotate(
            f"孤立反弹：第 {rb} 轮边际回升到 {mv:.2f}\n"
            f"（前面有 {zero_before} 轮边际为 0，纯烧钱）\n"
            f"→ 深挖偶尔有惊喜，但期望值极低",
            xy=(rb, mv * 1.35),
            xytext=(1.02, 0.72), textcoords="axes fraction",
            fontsize=8.0, color="#8a5200", ha="left", va="top", zorder=23,
            arrowprops=dict(arrowstyle="-", color=C_ORANGE, lw=1.1, alpha=0.85,
                            connectionstyle="arc3,rad=0.0"),
            bbox=dict(boxstyle="round,pad=0.42", facecolor="#fff6e8", edgecolor=C_ORANGE,
                      linewidth=1.1, alpha=0.97),
        )

    ax1.set_ylabel("每 10 万 token 修复漏洞数（个，symlog 轴）")
    ax1.set_title("边际收益衰减：每轮新增修复的「性价比」逐轮下降")
    ax1.legend(loc="upper right", fontsize=8.2, ncol=1, framealpha=0.95)
    if has_negative:
        ax1.text(0.012, 0.965,
                 "深红柱 = 该轮边际收益为负（修复数倒退：回归或重新计入）",
                 transform=ax1.transAxes, fontsize=7.6, color="#7b1e14",
                 ha="left", va="top", zorder=12,
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="#fdf1ef",
                           edgecolor=C_RED, linewidth=0.7, alpha=0.95))

    # ---- 下：剪刀差（token 在涨、修复在跌）
    ax2.bar(rounds, tokens, width=0.58, color=C_BLUE_LIGHT, edgecolor=C_BLUE,
            linewidth=0.9, zorder=3, label="单轮 token 消耗（每任务平均）")
    ax2.set_ylabel("单轮 token 消耗（token / 任务）", color=C_BLUE)
    ax2.tick_params(axis="y", labelcolor=C_BLUE)
    ax2.set_xlabel("迭代轮次")

    ax2b = ax2.twinx()
    ax2b.plot(rounds, fixed, color=C_RED, lw=2.2, marker="o", ms=6, mfc="white", mew=1.5,
              zorder=7, label="单轮修复漏洞数（每任务平均）")
    ax2b.set_ylabel("单轮修复漏洞数（个 / 任务）", color=C_RED)
    ax2b.tick_params(axis="y", labelcolor=C_RED)
    ax2b.grid(False)

    # 说明框：放到右下角（token 柱与修复折线在那里都很低，是空的）；
    # 文字描述由数据决定，不预设"token 一定涨、修复一定跌"
    if len(rounds) >= 2:
        t_first, t_last = tokens[0], tokens[-1]
        f_first, f_last = fixed[0], fixed[-1]
        tok_word = "上升" if t_last >= t_first else "下降"
        fix_word = "下降" if f_last <= f_first else "上升"
        ax2.annotate(
            f"成本 vs 收益：单轮 token {tok_word}（{t_first:,.0f} → {t_last:,.0f}）\n"
            f"单轮修复 {fix_word}（{f_first:.1f} → {f_last:.1f} 个）\n"
            "→ 判断该不该停，看的是「每 10 万 token 修复数」，不是 token 绝对值",
            xy=(rounds[-1], tokens[-1]),
            xytext=(0.985, 0.96), textcoords="axes fraction",
            fontsize=8.0, color=C_INK, ha="right", va="top", zorder=22,
            bbox=dict(boxstyle="round,pad=0.42", facecolor="#f4f7f9", edgecolor="#8aa0ae",
                      linewidth=0.9, alpha=0.97),
        )
    ax2.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax2.set_xlim(min(rounds) - 0.55, max(rounds) + 0.85)
    ax2.set_ylim(0, max(tokens) * 1.42 if tokens else 1.0)
    ax2b.set_ylim(0, max(fixed) * 1.55 if fixed else 1.0)

    handles = [*ax2.get_legend_handles_labels()[0], *ax2b.get_legend_handles_labels()[0]]
    labels = [*ax2.get_legend_handles_labels()[1], *ax2b.get_legend_handles_labels()[1]]
    ax2.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, -0.19), ncol=2,
               fontsize=8.5, framealpha=0.96)
    _read_note(
        fig,
        "读图要点：① 绿色柱 = 该轮性价比仍高于阈值，浅红 = 已跌破，"
        "橙色 = 孤立反弹（跌破后又回升一次）\n"
        "② 柱顶标「0」的轮次确实一个都没修好——纯烧钱　"
        "③ 下图看成本与收益是否走成剪刀差：成本涨、收益跌 = 越深越不划算",
        y=-0.075, fontsize=7.9,
    )
    return _save(fig, out_png)


# ---------------------------------------------------------------- 图 3：family 深度

def fig_family_depth(analysis: Any, out_png: str | Path) -> str:
    """按任务类型的建议迭代深度（条形 + 修复单价热力 + 90% 收益轮次标注）。"""
    _apply_style()
    rows = _depth_rows(analysis)
    if not rows:
        raise ValueError("analysis 缺少 depth_recommendations 且无法兜底，无法绘制 family 深度图")

    rows = sorted(rows, key=lambda r: (_num(r.get("recommended_depth")),
                                       _family_order_key(str(r.get("family")))))
    families = [str(r.get("family") or "") for r in rows]
    depths = [max(1.0, _num(r.get("recommended_depth"), 1)) for r in rows]
    costs = [_num(r.get("tokens_per_fix_at_recommended")) for r in rows]
    r90 = [int(_num(r.get("rounds_to_90pct"), 1)) for r in rows]
    knees = [_num(r.get("knee_round")) for r in rows]
    tasks = [int(_num(r.get("tasks"), 1)) or 1 for r in rows]
    # 拐点是否真的观测到：observed=True 用实线红线；False（外推/未达）用空心/虚线标记，
    # 避免把"外推出来的轮次"画得跟"真的观测到"一样。
    knee_obs = [bool(r.get("knee_observed", True)) for r in rows]

    # 行高自适应：行数少时不要把条形撑得像色块，同时避免上下大片空白
    n_rows = len(rows)
    fig_h = max(3.4, min(7.0, 1.55 + 0.56 * n_rows))
    fig, ax = plt.subplots(figsize=(10.8, fig_h), constrained_layout=True)
    y = np.arange(n_rows)
    bar_h = 0.62 if n_rows >= 5 else 0.46
    cmin, cmax = min(costs), max(costs)
    degenerate = cmax <= cmin          # 所有单价相同 → 色标无信息量
    if degenerate:
        cmax = cmin + 1.0
    cmap = plt.get_cmap("YlOrRd")
    norm = Normalize(vmin=cmin, vmax=cmax)
    bar_colors = [cmap(norm(c)) for c in costs]

    ax.barh(y, depths, height=bar_h, color=bar_colors, edgecolor="#3b3b3b", linewidth=0.8,
            zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(
        [f"{FAMILY_LABELS.get(f, f)}\n（{t} 个任务）" for f, t in zip(families, tasks)],
        fontsize=8.8,
    )

    x_pad = max(depths) * 0.03
    half = bar_h / 2.0
    for yi, d, c, r, k, obs in zip(y, depths, costs, r90, knees, knee_obs):
        # 未观测到拐点的类型：明确写"未观测"，不要让人以为没有拐点或拐点在别处
        if not obs and k > 0:
            knee_txt = "拐点外推"
        elif not obs:
            knee_txt = "拐点未观测"
        else:
            knee_txt = ""
        ax.text(d + x_pad, yi,
                f"{int(d)} 轮　·　90% 收益 @ 第 {r} 轮　·　单价 {c:,.0f} token/个"
                + (f"　·　{knee_txt}" if knee_txt else ""),
                va="center", ha="left", fontsize=8.2, color=C_INK, zorder=5)
        if k > 0:
            if obs:
                ax.plot([k, k], [yi - half, yi + half], color=C_RED, lw=2.4, zorder=6,
                        solid_capstyle="butt")
            else:
                # 外推的拐点用虚线，视觉上与"真的观测到"区分开
                ax.plot([k, k], [yi - half, yi + half], color=C_RED, lw=2.0, ls=":",
                        zorder=6, solid_capstyle="butt")

    ax.plot([], [], color=C_RED, lw=2.4, label="拐点位置（实测观测到）")
    ax.plot([], [], color=C_RED, lw=2.0, ls=":", label="拐点位置（外推/未观测）")
    ax.barh([], [], color=cmap(norm(cmax)), edgecolor="#3b3b3b",
            label="条形长度 = 建议迭代深度（颜色越深 = 修复单价越高）")
    ax.set_xlim(0, max(depths) * 1.72)
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.set_xlabel("建议迭代深度（轮）")
    ax.set_title("按任务类型的建议迭代深度：颜色越深 = 每修一个漏洞越贵")
    ax.set_ylim(-0.55, n_rows - 0.45)

    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    # 单价全相同（如只有 1 个 family）时，色标没有信息量，画出来只会误导 —— 直接省略
    if not degenerate:
        cbar = fig.colorbar(sm, ax=ax, pad=0.012, fraction=0.030, aspect=30)
        cbar.set_label("每修复 1 个漏洞的平均 token 成本", fontsize=9)
        # 大数值用千分位而不是科学计数法偏移（避免出现 +1.383e4 这种看不懂的刻度）
        cbar.formatter = ticker.FuncFormatter(lambda v, _pos: f"{v:,.0f}")
        cbar.update_ticks()
    else:
        ax.text(0.985, 0.955,
                "只有 1 个任务类型，修复单价唯一\n→ 不画色标（避免误导为「有梯度」）",
                transform=ax.transAxes, ha="right", va="top", fontsize=7.8, color="#5b6b76",
                zorder=12,
                bbox=dict(boxstyle="round,pad=0.34", facecolor="#f4f7f9",
                          edgecolor="#8aa0ae", linewidth=0.7, alpha=0.95))

    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), fontsize=8.2, ncol=2,
              columnspacing=1.2, handlelength=2.0)
    ax.grid(True, axis="x", alpha=0.28)
    ax.grid(True, axis="y", alpha=0.0)
    ax.set_axisbelow(True)
    _read_note(
        fig,
        "读图要点：① 条形长度 = 该类型值得跑几轮（来自 metrics.recommend_depth）　"
        "② 红色竖线 = 观测拐点；条形长度 ≤ 拐点说明策略保守\n"
        "③ 颜色 = 修复单价：越深越贵，同样预算下越不值得加深　"
        "④ 注意随机性/鉴权这类「难查难修」的类型反而值得跑更深（拐点晚）",
        y=-0.055, fontsize=7.9,
    )
    return _save(fig, out_png)


# ---------------------------------------------------------------- 图 4：预算策略

def _comparison_rows(budget_result: Any) -> list[dict[str, Any]]:
    """从 budget_result 取三策略对比行。

    ``budget_experiment.json`` 里 **真实执行值只存在 ``plans`` 中**
    （``actual_tokens`` / ``actual_fixed`` / ``actual_cost_per_fix`` /
    ``projection_error``），而 ``comparison`` 只有投影值。
    因此这里以 ``plans`` 为主，再把 ``comparison`` 的补充字段按 name 合并进来。
    """
    data = _mapping(budget_result)
    plans = data.get("plans")
    comps = data.get("comparison")
    by_name: dict[str, dict[str, Any]] = {}
    if isinstance(plans, Sequence):
        for p in plans:
            if isinstance(p, Mapping):
                by_name[str(p.get("name") or "")] = dict(p)
    if isinstance(comps, Sequence):
        for c in comps:
            if not isinstance(c, Mapping):
                continue
            name = str(c.get("name") or "")
            merged = dict(c)
            merged.update(by_name.get(name, {}))   # plans 覆盖 comparison（含 actual_*）
            by_name[name] = merged
    if by_name:
        return list(by_name.values())
    return []


STRATEGY_STYLE: dict[str, tuple[str, str, str]] = {
    "breadth": (C_BLUE, "o", "广度优先 breadth"),
    "depth": (C_ORANGE, "s", "深度优先 depth"),
    "adaptive": (C_GREEN, "D", "自适应 adaptive"),
}


def _budget_row_values(row: Mapping[str, Any]) -> dict[str, Any]:
    """统一取出一个策略的主值 / 对照值。

    **优先用真实执行值**（``actual_tokens`` / ``actual_fixed``，来自
    ``budget_experiment.json``），``projected_*`` 仅作为对照（画成空心投影点）。
    只有投影数据时，主值就退回投影值，并标记 ``has_actual=False``。
    """
    proj_tok = _num(row.get("projected_tokens"))
    proj_fix = _num(row.get("projected_fixed"))
    act_tok_raw = row.get("actual_tokens")
    act_fix_raw = row.get("actual_fixed")
    has_actual = act_tok_raw is not None and act_fix_raw is not None
    tok = _num(act_tok_raw) if has_actual else proj_tok
    fix = _num(act_fix_raw) if has_actual else proj_fix
    cost = (tok / fix) if fix else 0.0
    return {
        "name": str(row.get("name") or ""),
        "label": str(row.get("label") or ""),
        "tokens": tok,
        "fixed": fix,
        "cost_per_fix": cost,
        "proj_tokens": proj_tok,
        "proj_fixed": proj_fix,
        "has_actual": has_actual,
        "proj_error": _num(row.get("projection_error")) if has_actual else 0.0,
        "tasks_covered": int(_num(row.get("tasks_covered"))),
        "avg_depth": _num(row.get("avg_depth")),
        "vs_breadth_pct": _num(row.get("vs_breadth_pct")),
    }


def fig_budget_compare(budget_result: Any, out_png: str | Path) -> str:
    """三种预算策略：总修复数 vs 总 token（左）与 覆盖任务 × 平均深度（右）。

    若 ``budget_result`` 含真实执行值（``actual_tokens``/``actual_fixed``），
    **以真实值为实心主点**，投影值画成空心参考点并用虚线连接，
    直观展示"投影 vs 实际"的偏差——这比只画投影更有说服力。
    """
    _apply_style()
    rows = [_budget_row_values(r) for r in _comparison_rows(budget_result)]
    if not rows:
        raise ValueError("budget_result 缺少 comparison/plans，无法绘制预算对比图")

    meta = _mapping(_mapping(budget_result).get("meta"))
    budget = _num(meta.get("budget"))
    any_actual = any(r["has_actual"] for r in rows)

    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(12.6, 6.4), constrained_layout=True,
        gridspec_kw={"width_ratios": [1.22, 1.0]},
    )

    # ---- 左：总 token vs 总修复
    # 数值细节全部写进图例标签，图上只留点 —— 避免三个框互相压住
    base_cost = None
    for row in rows:
        name = row["name"]
        color, marker, label = STRATEGY_STYLE.get(name, (C_GRAY, "o", name or "策略"))
        tok = row["tokens"] / 1e4
        fix = row["fixed"]
        cost = row["cost_per_fix"]
        if base_cost is None:
            base_cost = cost
        # 投影值：空心点 + 虚线连到实际值（仅当两者都有且不同）
        if row["has_actual"]:
            ptok, pfix = row["proj_tokens"] / 1e4, row["proj_fixed"]
            ax1.scatter([ptok], [pfix], s=95, facecolor="none", edgecolor=color,
                        linewidth=1.4, marker=marker, alpha=0.75, zorder=5)
            if abs(ptok - tok) > 1e-9 or abs(pfix - fix) > 1e-9:
                ax1.plot([ptok, tok], [pfix, fix], color=color, ls=":", lw=1.2,
                         alpha=0.7, zorder=3)
        ax1.scatter([tok], [fix], s=240, color=color, marker=marker, edgecolor="white",
                    linewidth=1.6, zorder=7,
                    label=f"{label}：{fix:,.1f} 个 / {cost:,.0f} token 每个")

    # 等成本线（穿过第一个策略点）：线上任意点 token/修复 相同
    if base_cost and base_cost > 0:
        x_line = np.array([0.0, max(r["tokens"] for r in rows) / 1e4 * 1.22])
        ax1.plot(x_line, x_line * 1e4 / base_cost, color=C_GRAY, ls=":", lw=1.3, zorder=2,
                 label=f"等成本线（{base_cost:,.0f} token/修复）")

    if budget > 0:
        ax1.axvline(budget / 1e4, color=C_RED, ls="--", lw=1.6, zorder=3,
                    label=f"预算上限 {budget / 1e4:,.1f} 万 token")

    # 图例里加一条"空心点=投影值"的说明（仅当有实际值时）
    if any_actual:
        ax1.scatter([], [], s=95, facecolor="none", edgecolor=C_GRAY, linewidth=1.4,
                    label="空心点 = 投影值（用于对照）")

    ax1.set_xlabel("总 token 消耗（万）")
    ax1.set_ylabel("总修复漏洞数（个）")
    ax1.set_title("花同样的 token，谁修得更多？" if any_actual
                  else "投影结果：总 token vs 总修复数")
    tok_max = max(r["tokens"] for r in rows) / 1e4
    fix_max = max(r["fixed"] for r in rows)
    ax1.set_xlim(0, tok_max * 1.28)
    ax1.set_ylim(0, fix_max * 1.20)
    ax1.legend(loc="upper left", fontsize=7.9, labelspacing=0.5)

    # ---- "投影 vs 实际"的吻合度（离线预算规划是否可靠，这是本图的关键加分项）
    if any_actual:
        errs = [abs(r["proj_error"]) for r in rows if r["has_actual"]]
        max_err = max(errs) if errs else 0.0
        if max_err < 0.05:
            verdict = "投影与实际修复数完全一致 → 离线规划可靠，可先规划再执行"
            box_color, edge_color = "#eef7ee", C_GREEN
        elif max_err < 0.20:
            verdict = f"投影偏差 ≤ {max_err * 100:.1f}% → 离线规划基本可用"
            box_color, edge_color = "#fff6e8", C_ORANGE
        else:
            verdict = f"投影偏差达 {max_err * 100:.1f}% → 离线规划需保守打折"
            box_color, edge_color = "#fdf1ef", C_RED
        ax1.text(0.985, 0.035,
                 f"投影 vs 实际：{verdict}",
                 transform=ax1.transAxes, ha="right", va="bottom", fontsize=7.9,
                 color=C_INK, zorder=12,
                 bbox=dict(boxstyle="round,pad=0.38", facecolor=box_color,
                           edgecolor=edge_color, linewidth=0.9, alpha=0.96))

    # ---- 右：堆叠柱（覆盖任务数 + 额外加深轮次）
    labels, covered, extra, total_rounds = [], [], [], []
    for row in rows:
        name = row["name"]
        _, _, label = STRATEGY_STYLE.get(name, (C_GRAY, "o", name or "策略"))
        tc = row["tasks_covered"]
        ad = row["avg_depth"]
        tr = tc * ad
        labels.append(label)
        covered.append(tc)
        extra.append(max(0.0, tr - tc))
        total_rounds.append(tr)

    x = np.arange(len(labels))
    colors_cov = [STRATEGY_STYLE.get(r["name"], (C_GRAY, "", ""))[0] for r in rows]
    ax2.bar(x, covered, width=0.56, color=colors_cov, edgecolor="white", linewidth=1.2,
            zorder=3, label="覆盖任务数（每任务 ≥1 轮）")
    ax2.bar(x, extra, bottom=covered, width=0.56, color=colors_cov, alpha=0.40,
            edgecolor="white", linewidth=1.2, hatch="//", zorder=3,
            label="额外加深轮次（覆盖数 × 平均深度 − 覆盖数）")
    for xi, tr, tc, ad in zip(x, total_rounds, covered, [r["avg_depth"] for r in rows]):
        ax2.text(xi, tr + max(total_rounds) * 0.025, f"{tr:,.0f} 轮次",
                 ha="center", va="bottom", fontsize=8.8, color=C_INK, fontweight="bold")
        ax2.text(xi, tc / 2, f"{tc:.0f} 任务\n×{ad:.1f} 轮", ha="center", va="center",
                 fontsize=7.6, color="white", fontweight="bold", zorder=5)

    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, fontsize=8.6)
    ax2.set_ylabel("任务数 / 迭代轮次")
    ax2.set_title("覆盖面 vs 深度：两种花预算的方式")
    ax2.legend(loc="upper left", fontsize=7.6)
    ax2.set_ylim(0, max(total_rounds + [1.0]) * 1.32)

    _read_note(
        fig,
        "读图要点：① 左图越靠左上越好（同样的 token 修更多漏洞）　"
        "② 等成本线以下 = 比基线更划算" + ("　③ 空心点 = 投影值，实心 = 真实执行值"
                                          if any_actual else "") + "\n"
        "→ 右图：广度 = 条矮而宽，深度 = 条高而窄，自适应 = 两者折中",
        y=-0.055, fontsize=7.9,
    )
    return _save(fig, out_png)


# ---------------------------------------------------------------- 图 5：任务热力图

def fig_task_heatmap(runs: Any, out_png: str | Path) -> str:
    """25 任务 × 8 轮热力图（值=累计修复数），行按 family 分组。"""
    _apply_style()
    rows = _runs_of(runs)
    if not rows:
        raise ValueError("fig_task_heatmap 需要 runs（experiment dict 或 TaskRun 列表）")

    rows = sorted(rows, key=lambda r: (_family_order_key(str(r.get("family") or "")),
                                       str(r.get("task_id") or "")))
    max_round = max((len(r.get("rounds") or []) for r in rows), default=1)
    max_round = max(1, max_round)

    matrix = np.zeros((len(rows), max_round), dtype=float)
    stopped = np.zeros((len(rows), max_round), dtype=bool)
    for i, row in enumerate(rows):
        last = 0.0
        by_round = {int(_num(rec.get("round_index"))): rec for rec in (row.get("rounds") or [])}
        for r in range(1, max_round + 1):
            rec = by_round.get(r)
            if rec is None:
                matrix[i, r - 1] = last  # 提前停止：沿用最后累计值
                stopped[i, r - 1] = True
            else:
                last = _num(rec.get("cumulative_fixed"), _num(rec.get("defects_fixed")))
                matrix[i, r - 1] = last

    families = [str(r.get("family") or "") for r in rows]
    task_ids = [str(r.get("task_id") or f"T{i + 1:02d}") for i, r in enumerate(rows)]
    n_tasks, n_rounds = len(rows), max_round

    # 三行：热力图 / 色标 / 读图要点（说明写在坐标区外，绝不压数据）
    # 画布尺寸随数据自适应：宽随轮次、高随任务数，避免"任务少时被拉成一条横带"
    fig_w = max(7.4, min(11.0, 4.6 + 0.34 * n_rounds))
    fig_h = max(4.6, min(9.6, 2.9 + 0.30 * n_tasks))
    fig = plt.figure(figsize=(fig_w, fig_h), constrained_layout=True)
    gs = fig.add_gridspec(3, 2, width_ratios=[26, 4.6], height_ratios=[26, 1.3, 3.4])
    ax = fig.add_subplot(gs[0, 0])
    strip = fig.add_subplot(gs[0, 1], sharey=ax)
    cax = fig.add_subplot(gs[1, 0])

    cmap = plt.get_cmap("viridis")
    vmax = max(1.0, float(matrix.max()))
    im = ax.imshow(matrix, aspect="auto", cmap=cmap, interpolation="nearest",
                   vmin=0, vmax=vmax)

    ax.set_xticks(np.arange(max_round))
    ax.set_xticklabels([f"第 {r} 轮" for r in range(1, max_round + 1)],
                       fontsize=8.4 if n_rounds > 6 else 9)
    ax.set_yticks(np.arange(len(rows)))
    ax.set_yticklabels(task_ids, fontsize=7.8)
    ax.set_xlabel("迭代轮次")
    ax.set_ylabel("任务（按 family 分组排序）")
    ax.set_title(f"{n_tasks} 任务 × {n_rounds} 轮：每个任务的累计修复轨迹"
                 f"（颜色越亮 = 修得越多）", pad=16)
    ax.grid(False)

    # 已停止的格子用白色 × 标出（避免"假持续"的误读）
    ys, xs = np.where(stopped)
    if len(xs):
        ax.scatter(xs, ys, marker="x", s=14, color="white", alpha=0.55, linewidths=1.0,
                   zorder=4)
    # 数值写进格子（信息密度高，截图可读）
    if len(rows) <= 30 and max_round <= 10:
        for i in range(len(rows)):
            for j in range(max_round):
                val = matrix[i, j]
                ax.text(j, i, f"{val:.0f}", ha="center", va="center", fontsize=6.5,
                        color="white" if val < vmax * 0.55 else "#102030", zorder=5)

    # family 分隔线
    for i in range(1, len(rows)):
        if families[i] != families[i - 1]:
            ax.axhline(i - 0.5, color="white", lw=1.7, alpha=0.95, zorder=6)
            strip.axhline(i - 0.5, color="white", lw=1.7, alpha=0.95)

    # ---- 右侧 family 色带 + 分组名
    fam_list = list(dict.fromkeys(families))
    fam_colors = plt.get_cmap("tab20")(np.linspace(0, 1, max(2, len(fam_list))))
    fam_index = {f: i for i, f in enumerate(fam_list)}
    strip.set_xlim(0, 10)
    strip.set_ylim(len(rows) - 0.5, -0.5)
    centers: dict[str, list[int]] = {}
    for i, fam in enumerate(families):
        centers.setdefault(fam, []).append(i)
    # 每个 family 只画**一段**连续色块（不是逐行画小方块，否则看起来像一堆格子）
    for fam, idxs in centers.items():
        strip.add_patch(
            plt.Rectangle((0, min(idxs) - 0.5), 1.0, len(idxs),
                          facecolor=fam_colors[fam_index[fam]], edgecolor="white",
                          linewidth=0.8)
        )
        strip.text(1.35, (min(idxs) + max(idxs)) / 2, f"{_short_family(fam)}（{len(idxs)}）",
                   va="center", ha="left", fontsize=8.0, color=C_INK, clip_on=False)
    # 注意：strip 与 ax 共享 y 轴，**不能**对 strip 调用 set_yticks([])，
    # 否则会把 ax 的任务 ID 刻度也一起清掉（共享的是 locator）。
    # 用 tick_params 关掉 strip 自己的刻度显示即可。
    strip.tick_params(left=False, labelleft=False, bottom=False, labelbottom=False)
    for spine in strip.spines.values():
        spine.set_visible(False)
    strip.grid(False)
    strip.set_title("family", fontsize=8.6, color="#555555", pad=4)

    # ---- 色标（水平，放在热力图下方独立一行，标签不会被 X 轴刻度挡住）
    cbar = fig.colorbar(im, cax=cax, orientation="horizontal")
    cbar.set_label("累计修复漏洞数（× = 已提前停止，沿用上一轮值）", fontsize=8.4, labelpad=5)

    # ---- 读图要点（占满第三行；换行写，避免长单行把画布撑宽）
    note_ax = fig.add_subplot(gs[2, :])
    note_ax.axis("off")
    note_ax.text(
        0.0, 0.5,
        "读图要点：① 每一行的颜色在前 2~3 列就基本定型 → 修复主要发生在早期轮次，"
        "后面几列是平的（烧 token 换不到修复）\n"
        "② 右侧按 family 分组，同类任务轨迹形状相似 → 深度应按类型分化　"
        "③ × = 该任务已提前停止　④ 格内数字 = 该轮累计修复数",
        ha="left", va="center", fontsize=8.2, color=C_INK, linespacing=1.6,
        bbox=dict(boxstyle="round,pad=0.5", facecolor="#f4f7f9", edgecolor="#8aa0ae",
                  linewidth=0.8, alpha=0.97),
    )
    return _save(fig, out_png)


# ---------------------------------------------------------------- 汇总入口

FIGURE_NAMES: tuple[str, ...] = (
    "fig1_cumulative_token_vs_fixes.png",
    "fig2_marginal_benefit.png",
    "fig3_depth_by_family.png",
    "fig4_budget_allocation.png",
    "fig5_task_round_heatmap.png",
)


def make_all_figures(
    analysis: Any,
    budget_result: Any = None,
    runs: Any = None,
    out_dir: str | Path = "results/figures",
) -> dict[str, str]:
    """一次生成全部 5 张图，返回 {逻辑名: 路径}。

    ``runs`` 可以是 experiment dict（含 ``runs``）或 TaskRun 列表；fig5 必需。
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if runs is None:
        runs = _runs_of(_mapping(analysis)) or None
    figs: dict[str, str] = {}
    figs["cumulative"] = fig_cumulative_curve(analysis, out / FIGURE_NAMES[0])
    figs["marginal"] = fig_marginal_curve(analysis, out / FIGURE_NAMES[1])
    figs["family_depth"] = fig_family_depth(analysis, out / FIGURE_NAMES[2])
    if budget_result is not None:
        figs["budget"] = fig_budget_compare(budget_result, out / FIGURE_NAMES[3])
    if runs is not None:
        figs["heatmap"] = fig_task_heatmap(runs, out / FIGURE_NAMES[4])
    return figs


def figure_paths(figures: Any) -> list[str]:
    """把 make_all_figures 的返回值 / 路径列表统一成按文件名排序的路径列表。"""
    if figures is None:
        return []
    if isinstance(figures, Mapping):
        paths = [str(v) for v in figures.values() if v]
    elif isinstance(figures, Sequence) and not isinstance(figures, (str, bytes)):
        paths = [str(v) for v in figures if v]
    else:
        paths = [str(figures)]
    return sorted(paths, key=lambda p: Path(p).name)


__all__ = [
    "DPI",
    "FIGURE_NAMES",
    "fig_cumulative_curve",
    "fig_marginal_curve",
    "fig_family_depth",
    "fig_budget_compare",
    "fig_task_heatmap",
    "make_all_figures",
    "figure_paths",
]
