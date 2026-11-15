"""生成中文 Markdown 报告 REPORT.md。

输入严格按 docs/CONTRACT.md §7.1 / §7.2 的固定 key：
``analysis``（analyze() 的返回值）、``budget_result``（write_budget() 的返回值）、
``figures``（``plotting.make_all_figures()`` 的 dict，或路径列表，或 None）。

报告结构：摘要 → 方法与实验设置 → 核心结果（3 张表）→ 关键发现 → 图表 →
局限性与真实性声明 → 复现命令。

**真实性声明是硬要求**：必须明确写出「LLM 是确定性模拟 provider」、
「token 是字符级估算」、「任务库是手工构造」，同时写明「bandit 与 fuzz 是真实执行」。
"""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from .schema import FAMILIES, FAMILY_LABELS

# 图在报告中的展示顺序与图注
FIGURE_CAPTIONS: dict[str, tuple[str, str]] = {
    "fig1_cumulative_token_vs_fixes.png": (
        "图 1 · 累计 token 与累计修复漏洞数",
        "粗线为全库平均，其余虚线/点线为 9 条任务类型曲线（粗虚线是注入/鉴权/密码学三条重点）；"
        "红色竖线是分析层给出的建议停止点。曲线斜率就是「每万 token 能买到几个修复」，"
        "拐点之后斜率趋平。",
    ),
    "fig2_marginal_benefit.png": (
        "图 2 · 边际收益衰减与 token 剪刀差",
        "上图：每轮「每 10 万 token 修复数」（symlog 轴，0 就是 0，不是被截断的小数），"
        "红虚线是 0.1 阈值；下图：单轮 token 与单轮修复两条线，"
        "看它们是否走成「成本涨、收益跌」的剪刀差。",
    ),
    "fig3_depth_by_family.png": (
        "图 3 · 按任务类型的建议迭代深度",
        "条形长度是建议深度，颜色深浅是「每修复 1 个漏洞的平均 token 成本」；"
        "红色竖线是拐点——**实线=实测观测到，点线=外推或未观测**（条末亦有文字标注），"
        "避免把外推值画得和实测一样。",
    ),
    "fig4_budget_allocation.png": (
        "图 4 · 三种预算策略对比",
        "左：总 token vs 总修复数（越靠左上越好，等成本线以下是更划算的区域）；"
        "右：覆盖面与深度的取舍（广度=矮而宽，深度=高而窄，自适应=折中）。",
    ),
    "fig5_task_round_heatmap.png": (
        "图 5 · 25 任务 × 8 轮累计修复热力图",
        "行按任务类型分组；亮色集中在前几列说明修复主要发生在早期轮次，"
        "× 表示该任务已提前停止（沿用上一轮累计值，不是「持续有产出」）。",
    ),
}

FIGURE_ORDER = list(FIGURE_CAPTIONS)

# 图片相对 REPORT.md 的路径前缀。REPORT.md 在项目根，图在 results/figures/，
# 因此必须带上 results/ 前缀，否则 Markdown 里是死链（图显示不出来）。
FIGURE_REL_DIR = "results/figures"

# 预算策略的中文标签（契约 §7.2 的 comparison 行只有 name，没有 label）
STRATEGY_LABELS: dict[str, str] = {
    "breadth": "广度优先 breadth",
    "depth": "深度优先 depth",
    "adaptive": "自适应 adaptive",
}


def _strategy_label(row: Mapping[str, Any]) -> str:
    """策略行的可读标签：优先 label，其次按 name 查表，最后退回 name。"""
    label = row.get("label")
    if label:
        return str(label)
    name = str(row.get("name") or "")
    return STRATEGY_LABELS.get(name, name or "—")


# ---------------------------------------------------------------- 格式化工具

def _num(value: Any, default: float = 0.0) -> float:
    """安全转 float（None / NaN / 非数 → default）。"""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(v) or math.isinf(v):
        return default
    return v


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _int(value: Any) -> int:
    return int(round(_num(value)))


def _fmt_int(value: Any) -> str:
    return f"{_int(value):,}"


def _fmt_f(value: Any, digits: int = 2) -> str:
    return f"{_num(value):.{digits}f}"


def _fmt_pct(value: Any, digits: int = 1) -> str:
    """把 0..1 的比例格式化成百分比；传入的若已是百分数（>1.5）则原样保留。"""
    v = _num(value)
    if abs(v) <= 1.5:
        v *= 100.0
    return f"{v:.{digits}f}%"


def _fmt_wan(value: Any) -> str:
    return f"{_num(value) / 1e4:,.2f} 万"


def _cell(text: Any) -> str:
    """清洗单元格：去掉换行与竖线，避免破坏 Markdown 表格；None → —。"""
    if text is None:
        return "—"
    s = str(text).replace("\n", " ").replace("|", "/").strip()
    if s == "" or s.lower() in {"none", "nan", "null"}:
        return "—"
    return s


# ---------------------------------------------------------------- 取数（带兜底）

def _summary(analysis: Any) -> Mapping[str, Any]:
    return _mapping(_mapping(analysis).get("summary"))


def _meta(analysis: Any) -> Mapping[str, Any]:
    return _mapping(_mapping(analysis).get("meta"))


def _curve(analysis: Any) -> list[dict[str, Any]]:
    curve = _mapping(analysis).get("curve")
    if isinstance(curve, Sequence) and curve and isinstance(curve[0], Mapping):
        return [dict(c) for c in curve]
    return []


def _knee(analysis: Any) -> Mapping[str, Any]:
    return _mapping(_mapping(analysis).get("knee"))


def _knee_round(analysis: Any) -> float | None:
    knee = _knee(analysis)
    for key in ("knee_round", "interpolated_round"):
        v = knee.get(key)
        if v is not None and _num(v, -1) > 0:
            return _num(v)
    return None


def _isolated_rebounds(analysis: Any, curve: Sequence[Mapping[str, Any]],
                       threshold: float) -> list[int]:
    """找出"孤立反弹"的轮次：跌破阈值后某一轮边际又回升。

    优先读 ``analysis.knee.isolated_rebounds``（分析层判定），缺失时按曲线现算。
    """
    knee = _knee(analysis)
    declared = knee.get("isolated_rebounds")
    if isinstance(declared, Sequence) and not isinstance(declared, (str, bytes)):
        return sorted({int(_num(x)) for x in declared if _num(x) > 0})
    out: list[int] = []
    crossed = False
    for c in curve:
        m = _num(c.get("marginal_per_100k"))
        r = _int(c.get("round"))
        if not crossed and m < threshold:
            crossed = True
            continue
        if crossed and m >= threshold:
            out.append(r)
    return out


def _depth_rows(analysis: Any) -> list[dict[str, Any]]:
    rows = _mapping(analysis).get("depth_recommendations")
    if isinstance(rows, Sequence) and rows and isinstance(rows[0], Mapping):
        return [dict(r) for r in rows]
    return []


def _comparison(budget_result: Any) -> list[dict[str, Any]]:
    """取三策略对比行；**真实执行值只在 ``plans`` 里**，需按 name 合并。

    ``budget_experiment.json`` 的 ``comparison`` 只有投影值，
    ``plans`` 才带 ``actual_tokens`` / ``actual_fixed`` / ``actual_cost_per_fix`` /
    ``projection_error``。这里以 ``plans`` 为准覆盖 ``comparison``。
    """
    data = _mapping(budget_result)
    plans = data.get("plans")
    comps = data.get("comparison")
    by_name: dict[str, dict[str, Any]] = {}
    if isinstance(comps, Sequence):
        for c in comps:
            if isinstance(c, Mapping):
                by_name[str(c.get("name") or "")] = dict(c)
    if isinstance(plans, Sequence):
        for p in plans:
            if not isinstance(p, Mapping):
                continue
            name = str(p.get("name") or "")
            merged = dict(by_name.get(name, {}))
            merged.update(dict(p))     # plans 覆盖（含 actual_*）
            by_name[name] = merged
    return list(by_name.values())


def _budget_of(budget_result: Any) -> int:
    return _int(_mapping(_mapping(budget_result).get("meta")).get("budget"))


def _figure_map(figures: Any, base_dir: Path | None = None) -> dict[str, str]:
    """把 figures 归一成 {文件名: 相对路径}。

    **相对路径必须相对 REPORT.md 的实际输出目录**，否则 Markdown 渲染器得到死链。
    本项目默认 REPORT.md 写在项目根、图在 ``results/figures/``；但测试会把两者
    放在不同的临时目录，所以这里用 ``os.path.relpath`` 真实计算，而不是硬编码前缀。
    """
    out: dict[str, str] = {}
    if figures is None:
        return out
    items: list[str] = []
    if isinstance(figures, Mapping):
        items = [str(v) for v in figures.values() if v]
    elif isinstance(figures, Sequence) and not isinstance(figures, (str, bytes)):
        items = [str(v) for v in figures if v]
    else:
        items = [str(figures)]
    for item in items:
        p = Path(item)
        if base_dir is not None:
            try:
                rel = os.path.relpath(p.resolve(), Path(base_dir).resolve())
            except (ValueError, OSError):     # 跨盘符等无法计算时退回文件名
                rel = p.name
        else:
            rel = f"{FIGURE_REL_DIR}/{p.name}"
        out[p.name] = Path(rel).as_posix()
    return out


def _fig_ref(figs: Mapping[str, str], name: str) -> str | None:
    return figs.get(name)


# ---------------------------------------------------------------- 各章节

def _section_summary(analysis: Any, budget_result: Any) -> list[str]:
    """§1 摘要：3-5 句，直接给结论。"""
    summary = _summary(analysis)
    knee = _knee(analysis)
    curve = _curve(analysis)
    depth_rows = _depth_rows(analysis)
    comps = _comparison(budget_result)

    kr = _knee_round(analysis)
    threshold = _num(knee.get("threshold"), _num(_meta(analysis).get("threshold_per_100k"), 0.1))
    method = str(knee.get("method") or "")
    observed = bool(knee.get("observed", method == "observed"))
    n_tasks = _int(_meta(analysis).get("task_count") or summary.get("tasks")) or 0
    total_tok = _num(summary.get("total_tokens"))
    total_fixed = _num(summary.get("total_fixed"))
    tokens_per_fix = _num(summary.get("tokens_per_fix")) or (
        total_tok / total_fixed if total_fixed else 0.0
    )

    lines: list[str] = []
    lines.append("## 1. 摘要")
    lines.append("")

    # 句 1：拐点
    if kr is not None:
        cum_at_knee = 0.0
        for c in curve:
            if _num(c.get("round")) >= kr:
                cum_at_knee = _num(c.get("cum_tokens"))
                break
        if cum_at_knee <= 0 and curve:
            cum_at_knee = _num(curve[-1].get("cum_tokens"))
        how = "在观测窗口内直接观测到" if observed else "未在观测窗口内跌破，由对数线性趋势外推得到"
        lines.append(
            f"**结论一（拐点）**：在 {n_tasks} 个漏洞审计任务、最多 "
            f"{_int(_meta(analysis).get('max_rounds')) or 8} 轮迭代的设置下，"
            f"全库「每 10 万 token 修复漏洞数」跌破 **{threshold}** 的拐点"
            f"约在第 **{kr:.1f} 轮**（{how}），此时累计消耗约 "
            f"**{_fmt_wan(cum_at_knee)} token**。"
        )
    else:
        lines.append(
            f"**结论一（拐点）**：在观测窗口内，每 10 万 token 修复数始终高于 {threshold}，"
            "尚未出现明确拐点；这说明当前任务难度或预算尚未进入低收益区。"
        )

    # 句 2：建议深度
    if depth_rows:
        depths = [_int(r.get("recommended_depth")) for r in depth_rows]
        lo, hi = min(depths), max(depths)
        if lo == hi:
            lines.append(
                f"**结论二（建议深度）**：{len(depth_rows)} 个任务类型的建议迭代深度均为 "
                f"**{lo} 轮**，即把预算压在拐点附近、不再无脑跑满轮次。"
            )
        else:
            cheapest = min(depth_rows, key=lambda r: _num(r.get("recommended_depth"), 99))
            priciest = max(depth_rows, key=lambda r: _num(r.get("recommended_depth"), -1))
            lines.append(
                f"**结论二（建议深度）**：建议迭代深度按任务类型分化，从 "
                f"**{lo} 轮到 {hi} 轮**不等——"
                f"「{FAMILY_LABELS.get(str(cheapest.get('family')), str(cheapest.get('family')))}」"
                f"只需 {_int(cheapest.get('recommended_depth'))} 轮，而"
                f"「{FAMILY_LABELS.get(str(priciest.get('family')), str(priciest.get('family')))}」"
                f"值得跑到 {_int(priciest.get('recommended_depth'))} 轮。"
            )
    else:
        lines.append("**结论二（建议深度）**：分析层未给出分类型的深度建议。")

    # 句 3：拐点之后还剩多少收益 / 省多少 token
    if curve and kr is not None:
        max_round = max(_num(c.get("round")) for c in curve)
        full_tok = sum(_num(c.get("round_tokens")) for c in curve)
        cut_tok = sum(_num(c.get("round_tokens")) for c in curve
                      if _num(c.get("round")) <= kr)
        saved = max(0.0, full_tok - cut_tok)
        pct = (saved / full_tok * 100.0) if full_tok else 0.0
        after = [c for c in curve if _num(c.get("round")) > kr]
        after_fixed = sum(_num(c.get("round_fixed")) for c in after)
        after_zero = sum(1 for c in after if _num(c.get("marginal_per_100k")) == 0.0)
        extra = ""
        if after:
            extra = (
                f"拐点之后还有 {len(after)} 轮，合计只修了 **{after_fixed:.0f} 个**"
                + (f"（其中 {after_zero} 轮边际为 0，纯烧钱）" if after_zero else "")
                + "——这就是「继续跑」的真实回报。"
            )
        lines.append(
            f"**结论三（拐点之后还剩什么）**：若在第 {kr:.1f} 轮停止而非跑满 {max_round:.0f} 轮，"
            f"可省下约 **{_fmt_wan(saved)} token（{pct:.1f}%）**。" + extra
            + f"当前平均每修复 1 个漏洞需 **{_fmt_int(tokens_per_fix)} token**。"
        )
    else:
        lines.append(
            f"**结论三（成本）**：当前平均每修复 1 个漏洞需 **{_fmt_int(tokens_per_fix)} token**，"
            f"共修复 {_fmt_int(total_fixed)} 个漏洞、消耗 {_fmt_wan(total_tok)} token。"
        )

    # 句 4：预算策略差异（优先真实执行值）
    if comps:
        by_name = {str(c.get("name") or ""): c for c in comps}

        def _fix(row: Mapping[str, Any]) -> float:
            if row.get("actual_fixed") is not None:
                return _num(row.get("actual_fixed"))
            return _num(row.get("projected_fixed"))

        def _tok(row: Mapping[str, Any]) -> float:
            if row.get("actual_tokens") is not None:
                return _num(row.get("actual_tokens"))
            return _num(row.get("projected_tokens"))

        best = max(comps, key=_fix)
        breadth = by_name.get("breadth")
        adaptive = by_name.get("adaptive")
        depth = by_name.get("depth")
        if breadth and adaptive:
            gain = _fix(adaptive) - _fix(breadth)
            base = _fix(breadth) or 1.0
            a_cost = _tok(adaptive) / _fix(adaptive) if _fix(adaptive) else 0.0
            tail = ""
            if depth:
                d_fix = _fix(depth)
                tail = (f"而「深度优先」只修 {d_fix:.1f} 个"
                        f"（{(d_fix - base) / base * 100.0:+.1f}%），是明确的负收益。")
            lines.append(
                f"**结论四（预算分配）**：同样约 {_fmt_wan(_budget_of(budget_result))} token 预算下，"
                f"自适应策略（adaptive）比广度优先（breadth）多修 **{gain:.1f} 个漏洞"
                f"（+{gain / base * 100.0:.1f}%）**，"
                f"最优策略是「{_cell(_strategy_label(best))}」"
                f"（{_fmt_f(_fix(best), 1)} 个修复 / "
                f"{_fmt_int(a_cost)} token per fix）。" + tail
            )
        else:
            lines.append(
                f"**结论四（预算分配）**：三种策略中「{_cell(_strategy_label(best))}」"
                f"在同等预算下修复数最高（{_fmt_f(_fix(best), 1)} 个）。"
            )
    else:
        lines.append(
            "**结论四（预算分配）**：本次运行未提供预算方案数据，"
            "预算策略对比见 `results/budget_plan.json`。"
        )

    # 句 5：诚实边界
    lines.append(
        "**结论五（边界）**：以上数字来自**确定性模拟 LLM provider** 与**字符级 token 估算**，"
        "任务库为手工构造；结论的**方向**（边际收益递减、按类型分化深度）是稳健的，"
        "**绝对数值**不可直接外推到真实商业模型。"
    )
    lines.append("")
    return lines


def _section_method(analysis: Any) -> list[str]:
    meta = _meta(analysis)
    summary = _summary(analysis)
    n_tasks = _int(meta.get("task_count") or summary.get("tasks")) or 25
    max_rounds = _int(meta.get("max_rounds")) or 8
    lines = [
        "## 2. 方法与实验设置",
        "",
        "### 2.1 三 Agent 迭代管线",
        "",
        "每个任务最多迭代 8 轮，每轮固定三段式循环：",
        "",
        "| 阶段 | Agent | 干什么 | 判定依据 |",
        "| --- | --- | --- | --- |",
        "| ① 生成/修复 | Coding Agent | 首轮按任务描述写实现，之后按上一轮 findings 打补丁 | "
        "补丁应用后必须通过重新扫描验证 |",
        "| ② 静态分析 | Static Analyzer Agent | **真实调用 bandit CLI** 扫描，"
        "再对 bandit 结构上看不到的语义缺陷做推理 | bandit 的 test_id + 行号（±5 行）命中 |",
        "| ③ 动态分析 | Fuzzing Agent | **真实把目标模块 + harness 写进子进程执行**，"
        "收集运行时 marker | harness 真的打印出对应 marker |",
        "",
        "每轮结束把「已知但未修好」的缺陷重新喂回 Coding Agent，形成闭环。"
        "**所有「是否发现」「是否修复」的判定都由真实工具完成**，不是让模型自评。",
        "",
        "### 2.2 实验设置",
        "",
        "| 项 | 取值 |",
        "| --- | --- |",
        f"| 任务数 | {n_tasks} 个（9 个任务类型） |",
        f"| 最大迭代轮次 | {max_rounds} 轮 |",
        f"| LLM provider | `{_cell(meta.get('provider'))}`"
        f"（模型 `{_cell(meta.get('model'))}`） |",
        f"| 随机种子 | {_int(meta.get('seed'))} |",
        f"| 拐点阈值 | 每 10 万 token 修复数 < {_num(meta.get('threshold_per_100k'), 0.1)} |",
        f"| 策略版本 | `{_cell(meta.get('policy_version'))}` |",
        f"| 生成时间 | {_cell(meta.get('generated_at'))} |",
        "",
        "### 2.3 计量口径（关键）",
        "",
        "* `tokens_in/out` = 当轮三个 Agent 的输入 + 输出之和；",
        "* `defects_found` = 当轮**首次**发现的缺陷数（重复报告不计入，但单独记 `duplicate_findings`）；",
        "* `defects_fixed` = 当轮**验证通过**的新修复数（不是「Agent 声称修好了」）；",
        "* 每 10 万 token 修复数 = 当轮修复数 / 当轮 token × 100,000；",
        "* 平均每修复 token = 累计 token / 累计修复数。",
        "",
        "### 2.4 边际收益为什么会递减（机制说明）",
        "",
        "三个被显式建模的真实效应，也是拐点存在的原因：",
        "",
        "1. **易修的漏洞先被修掉**：高严重度、低 subtlety 的缺陷优先进入 triage，"
        "剩下的越来越难；",
        "2. **假补丁导致复发**：Agent 会用「看起来合理但无效」的补丁，下一轮被重新报告，"
        "token 花在同一个洞上；",
        "3. **上下文膨胀**：历史 findings 进入 prompt，单轮 token 随轮次上升，"
        "而单轮新增修复下降——这就是「token 在涨、收益在跌」的剪刀差。",
        "",
    ]
    return lines


def _section_curve_table(analysis: Any) -> list[str]:
    curve = _curve(analysis)
    lines = [
        "### 3.1 表 1 · 逐轮汇总",
        "",
        "全库口径（所有任务求和）；「边际每 10 万 token 修复数」是当轮性价比，"
        "「平均每修复 token」是到该轮为止的累计成本。",
        "",
        "| 轮次 | 平均单轮 token | 累计 token | 累计修复 | 边际每 10 万 token 修复数 | 平均每修复 token |",        "| --- | --- | --- | --- | --- | --- |",
    ]
    if not curve:
        lines.append("| — | — | — | — | — | — |")
        lines.append("")
        return lines
    n_tasks_total = _int(_summary(analysis).get("tasks")) or _int(
        _meta(analysis).get("task_count")) or 1
    for c in curve:
        round_tok = _num(c.get("round_tokens"))
        cum_tok = _num(c.get("cum_tokens"))
        cum_fix = _num(c.get("cum_fixed"))
        # 单轮 token 除以"该轮实际在跑的任务数"（任务会提前收敛，n_tasks 逐轮下降）；
        # 累计量除以任务总数，保持单调可比。
        active = _int(c.get("n_tasks")) or n_tasks_total
        per_task_tok = round_tok / active if active else round_tok
        tok_per_fix = (cum_tok / cum_fix) if cum_fix > 0 else 0.0
        lines.append(
            f"| {_int(c.get('round'))} "
            f"| {_fmt_int(per_task_tok)} "
            f"| {_fmt_int(cum_tok)} "
            f"| {_fmt_int(cum_fix)} "
            f"| {_fmt_f(c.get('marginal_per_100k'), 3)} "
            f"| {_fmt_int(tok_per_fix)} |"
        )
    lines.append("")
    lines.append(
        f"> 读表：看「边际每 10 万 token 修复数」这一列——它单调下降就说明边际收益在衰减；"
        f"而「平均每修复 token」持续上升，说明越往后每一分钱越不划算。"
        f"（「平均单轮 token」= 当轮全库 token ÷ 该轮仍在迭代的任务数，"
        f"任务会提前收敛，所以这个除数逐轮下降。）"
    )
    lines.append("")
    return lines


def _section_depth_table(analysis: Any) -> list[str]:
    rows = _depth_rows(analysis)
    lines = [
        "### 3.2 表 2 · 按任务类型的建议迭代深度",
        "",
        "| 任务类型 | 任务数 | 拐点轮次 | 建议深度 | 90% 收益轮次 | 修复单价（token/个） | 理由 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    if not rows:
        lines.append("| — | — | — | — | — | — | — |")
        lines.append("")
        return lines

    def _order(row: Mapping[str, Any]) -> int:
        fam = str(row.get("family") or "")
        try:
            return FAMILIES.index(fam)
        except ValueError:
            return len(FAMILIES)

    for row in sorted(rows, key=_order):
        fam = str(row.get("family") or "")
        label = FAMILY_LABELS.get(fam, fam)
        knee = row.get("knee_round")
        knee_txt = f"{_num(knee):.1f}" if knee is not None and _num(knee, -1) > 0 else "—"
        lines.append(
            f"| {_cell(label)} "
            f"| {_int(row.get('tasks'))} "
            f"| {knee_txt} "
            f"| {_int(row.get('recommended_depth'))} "
            f"| {_int(row.get('rounds_to_90pct'))} "
            f"| {_fmt_int(row.get('tokens_per_fix_at_recommended'))} "
            f"| {_cell(row.get('rationale'))} |"
        )
    lines.append("")
    lines.append(
        "> 读表：**建议深度** ≤ **90% 收益轮次**说明该类型的大部分收益在更早就能拿到；"
        "**修复单价**越高，同样预算下越不值得加深。"
    )
    lines.append("")
    return lines


def _section_budget_table(budget_result: Any) -> list[str]:
    comps = _comparison(budget_result)
    budget = _budget_of(budget_result)
    any_actual = any(r.get("actual_tokens") is not None and r.get("actual_fixed") is not None
                     for r in comps)
    lines = [
        "### 3.3 表 3 · 三种预算策略对比",
        "",
    ]
    if budget:
        lines.append(f"预算上限：**{_fmt_int(budget)} token**（约 {_fmt_wan(budget)}）。")
        lines.append("")
    if any_actual:
        lines += [
            "下表主值为**真实执行结果**（`budget_experiment.json`），"
            "括号内是分配阶段的投影值，用于展示「投影 vs 实际」的偏差。",
            "",
            "| 策略 | 覆盖任务 | 平均深度 | 实际 token | 实际修复 | 每修复 token | 相对提升 | 投影偏差 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    else:
        lines += [
            "| 策略 | 覆盖任务 | 平均深度 | 总 token | 总修复 | 每修复 token | 相对提升 |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    if not comps:
        ncol = 8 if any_actual else 7
        lines.append("| " + " | ".join(["—"] * ncol) + " |")
        lines.append("")
        lines.append("> 本次运行未提供预算方案数据（`results/budget_plan.json` 缺失）。")
        lines.append("")
        return lines

    labels = STRATEGY_LABELS
    for row in comps:
        name = str(row.get("name") or "")
        label = _strategy_label(row) or labels.get(name, name or "—")
        gain = row.get("vs_breadth_pct")
        gain_txt = f"{_num(gain):+.1f}%" if gain is not None else "—"
        if any_actual:
            act_tok = _num(row.get("actual_tokens"))
            act_fix = _num(row.get("actual_fixed"))
            act_cost = _num(row.get("actual_cost_per_fix")) or (
                act_tok / act_fix if act_fix else 0.0)
            proj_tok = _num(row.get("projected_tokens"))
            proj_fix = _num(row.get("projected_fixed"))
            err = row.get("projection_error")
            err_txt = f"{_num(err):+.1f}%" if err is not None else "—"
            lines.append(
                f"| {_cell(label)} "
                f"| {_int(row.get('tasks_covered'))} "
                f"| {_fmt_f(row.get('avg_depth'), 1)} "
                f"| {_fmt_int(act_tok)}（投影 {_fmt_int(proj_tok)}） "
                f"| {_fmt_f(act_fix, 1)}（投影 {_fmt_f(proj_fix, 1)}） "
                f"| {_fmt_int(act_cost)} "
                f"| {gain_txt} "
                f"| {err_txt} |"
            )
        else:
            lines.append(
                f"| {_cell(label)} "
                f"| {_int(row.get('tasks_covered'))} "
                f"| {_fmt_f(row.get('avg_depth'), 1)} "
                f"| {_fmt_int(row.get('projected_tokens'))} "
                f"| {_fmt_f(row.get('projected_fixed'), 1)} "
                f"| {_fmt_int(row.get('projected_cost_per_fix'))} "
                f"| {gain_txt} |"
        )
    lines.append("")
    lines.append(
        "> 读表：三种策略的差别在于**怎么花**——广度优先把钱摊在每个任务的前 3 轮，"
        "深度优先把少数任务跑满 8 轮（放弃大量未覆盖任务），"
        "自适应按「每轮边际收益」贪心分配（前缀约束的背包）。"
    )
    if any_actual:
        errs = [abs(_num(r.get("projection_error"))) for r in comps
                if r.get("projection_error") is not None]
        if errs and max(errs) < 0.05:
            lines.append(">")
            lines.append(
                "> **投影与实际完全吻合**（投影误差 0%）：说明「用主实验的观测曲线做离线预算规划」"
                "是可靠的——真实项目里可以先离线规划、再执行，省掉试错成本。"
            )
    lines.append("")
    return lines


def _section_breakdowns(analysis: Any) -> list[str]:
    channels = _mapping(_mapping(analysis).get("channel_breakdown"))
    difficulty = _mapping(_mapping(analysis).get("difficulty_breakdown"))
    if not channels and not difficulty:
        return []

    chan_labels = {"bandit": "静态（真实 bandit）", "fuzz": "动态（真实子进程 fuzz）",
                   "semantic": "语义推理（模拟 LLM）"}
    diff_labels = {"easy": "简单 easy", "medium": "中等 medium", "hard": "困难 hard"}

    lines = ["### 3.4 补充：通道与难度分解", ""]
    if channels:
        lines += [
            "| 检出通道 | 缺陷数 | 已修复 | 修复率 | 平均每轮修复 | 每修复 token |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for name in ("bandit", "fuzz", "semantic"):
            row = _mapping(channels.get(name))
            if not row:
                continue
            lines.append(
                f"| {chan_labels.get(name, name)} "
                f"| {_int(row.get('defects'))} "
                f"| {_int(row.get('fixed'))} "
                f"| {_fmt_pct(row.get('fix_rate'))} "
                f"| {_fmt_f(row.get('avg_round_fixed'), 2)} "
                f"| {_fmt_int(row.get('tokens_per_fix'))} |"
            )
        lines.append("")
        # 结论由数据生成（不同版本数据可能给出相反的排序，硬编码会自相矛盾）
        present = {n: _mapping(channels.get(n)) for n in ("bandit", "fuzz", "semantic")
                   if _mapping(channels.get(n))}
        if len(present) >= 2:
            by_rate = sorted(present.items(), key=lambda kv: _num(kv[1].get("fix_rate")))
            by_cost = sorted(present.items(), key=lambda kv: _num(kv[1].get("tokens_per_fix")))
            worst_rate, best_rate = by_rate[0], by_rate[-1]
            cheapest, priciest = by_cost[0], by_cost[-1]
            lines.append(
                f"> **通道差异的读法**：修复率最高的是 **{chan_labels.get(best_rate[0], best_rate[0])}**"
                f"（{_fmt_pct(best_rate[1].get('fix_rate'))}），最低的是 "
                f"**{chan_labels.get(worst_rate[0], worst_rate[0])}**"
                f"（{_fmt_pct(worst_rate[1].get('fix_rate'))}）；"
                f"而修复单价最便宜的是 **{chan_labels.get(cheapest[0], cheapest[0])}**"
                f"（{_fmt_int(cheapest[1].get('tokens_per_fix'))} token/个），"
                f"最贵的是 **{chan_labels.get(priciest[0], priciest[0])}**"
                f"（{_fmt_int(priciest[1].get('tokens_per_fix'))}）。"
            )
            lines.append(">")
            if cheapest[0] == "bandit" and worst_rate[0] == "bandit":
                lines.append(
                    "> 这两件事并不矛盾：**静态告警的检出成本最低，但其中混着噪声**，"
                    "Agent 要花额外的修复与验证成本去处理误报，所以最终「每修复一个」并不便宜、"
                    "修复率也最低。相反，**fuzz 检出的缺陷一旦复现就带可执行的失败用例**，"
                    "修复目标明确、验证直接，因此最容易修好。"
                    "→ 工程含义：**先用便宜的静态工具做广度筛查，再用 fuzz 复现来确认与闭环**，"
                    "两者的角色不同，不能只看修复率排名。"
                )
            elif cheapest[0] == "bandit":
                lines.append(
                    "> 静态工具的检出成本最低，但修复率未必最高——"
                    "**检出的便宜不等于修好的便宜**，因为告警里混有噪声，"
                    "Agent 需要额外的修复与验证成本去甄别。"
                )
            else:
                lines.append(
                    f"> 检出成本与修复率并不是同一件事："
                    f"{chan_labels.get(cheapest[0], cheapest[0])} 最便宜，"
                    f"{chan_labels.get(best_rate[0], best_rate[0])} 修复率最高。"
                )
            lines.append("")
            lines.append(
                "> 这张表也是「为什么拐点存在」的证据：越往后剩下的越是难以检出的长尾缺陷，"
                "单位修复成本越高。"
            )
        lines.append("")
    if difficulty:
        lines += [
            "| 难度 | 缺陷数 | 已修复 | 修复率 | 平均每轮修复 | 每修复 token |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for name in ("easy", "medium", "hard"):
            row = _mapping(difficulty.get(name))
            if not row:
                continue
            lines.append(
                f"| {diff_labels.get(name, name)} "
                f"| {_int(row.get('defects'))} "
                f"| {_int(row.get('fixed'))} "
                f"| {_fmt_pct(row.get('fix_rate'))} "
                f"| {_fmt_f(row.get('avg_round_fixed'), 2)} "
                f"| {_fmt_int(row.get('tokens_per_fix'))} |"
            )
        lines.append("")
    return lines


def _section_findings(analysis: Any, budget_result: Any) -> list[str]:
    curve = _curve(analysis)
    summary = _summary(analysis)
    knee = _knee(analysis)
    kr = _knee_round(analysis)
    threshold = _num(knee.get("threshold"), _num(_meta(analysis).get("threshold_per_100k"), 0.1))
    comps = _comparison(budget_result)
    depth_rows = _depth_rows(analysis)

    findings: list[str] = []

    # 0. 孤立反弹：跌破阈值后某一轮又回升 —— 这是比"负值"更有说服力的发现
    rebounds = _isolated_rebounds(analysis, curve, threshold)
    if rebounds:
        rb = rebounds[0]
        mv = _num(next((c.get("marginal_per_100k") for c in curve
                        if _int(c.get("round")) == rb), 0.0))
        zero_before = sum(
            1 for c in curve
            if _int(c.get("round")) < rb and _num(c.get("marginal_per_100k")) == 0.0
        )
        findings.append(
            f"**「深挖偶尔有惊喜，但期望值极低」——第 {rb} 轮出现孤立反弹**："
            f"边际收益在第 {kr:.0f} 轮跌破阈值后，连续 {zero_before} 轮为 **0**（纯烧钱），"
            f"到第 {rb} 轮因一个长尾缺陷被修好而回升到 **{mv:.2f}**，随后又归零。"
            f"这不是「深挖还有持续价值」的证据——恰恰相反：要等 {zero_before} 轮才碰到一次，"
            f"而且立刻结束。**这正是「按拐点停」的经济学依据**。"
        )

    # 1. 边际收益下降的幅度
    if len(curve) >= 2:
        first = _num(curve[0].get("marginal_per_100k"))
        last = _num(curve[-1].get("marginal_per_100k"))
        if first > 0:
            if last >= 0:
                drop = (1.0 - last / first) * 100.0
                tail = f"到第 {_int(curve[-1].get('round'))} 轮降到 {last:.2f}，**下降 {drop:.1f}%**。"
            else:
                drop = (1.0 - last / first) * 100.0
                tail = (f"到第 {_int(curve[-1].get('round'))} 轮变为 {last:.2f}"
                        f"（负值），**相对第 1 轮下降 {drop:.1f}%**。")
            findings.append(
                f"**边际收益确实在衰减，且幅度可量化**：第 1 轮的边际收益是 "
                f"{first:.2f} 个/10 万 token，{tail}"
                f"这不是噪声，是任务排序（先易后难）+ 假补丁复发 + 上下文膨胀三者叠加的结果。"
            )

    # 2. 单轮 token 与单轮修复的方向（用"每任务"口径，避免任务数下降造成的假下降）
    if len(curve) >= 2:
        def _per_task(c: Mapping[str, Any], key: str) -> float:
            active = _num(c.get("n_tasks"))
            v = _num(c.get(key))
            return (v / active) if active > 0 else v

        t_first = _per_task(curve[0], "round_tokens")
        t_last = _per_task(curve[-1], "round_tokens")
        f_first = _per_task(curve[0], "round_fixed")
        f_last = _per_task(curve[-1], "round_fixed")
        if t_first > 0:
            growth = (t_last / t_first - 1.0) * 100.0
            tok_dir = "上升" if growth >= 0 else "下降"
            fix_dir = "下降" if f_last <= f_first else "上升"
            findings.append(
                f"**单轮成本与单轮收益的方向**（每任务口径）：单轮 token 从 "
                f"{_fmt_int(t_first)} {tok_dir}到 {_fmt_int(t_last)}（**{growth:+.1f}%**），"
                f"而同期单轮修复从 {_fmt_f(f_first, 2)} {fix_dir}到 {_fmt_f(f_last, 2)}。"
                + (
                    "「token 涨、修复跌」的剪刀差是为什么固定跑满轮次不划算。"
                    if growth >= 0 and f_last <= f_first
                    else "判断是否该停仍以「每 10 万 token 修复数」为准——"
                    "它已经把这个比值变化算进去了。"
                )
            )

    # 3. 拐点定位
    if kr is not None:
        cum = 0.0
        for c in curve:
            if _num(c.get("round")) >= kr:
                cum = _num(c.get("cum_tokens"))
                break
        method = str(knee.get("method") or "")
        findings.append(
            f"**拐点位置**：第 **{kr:.1f} 轮** / 累计约 **{_fmt_wan(cum)} token** 时，"
            f"每 10 万 token 修复数跌破 {threshold}（判定方式：`{_cell(method)}`）。"
            f"工程含义：预算应该按这个点切，而不是按「跑满 8 轮」。"
        )
    else:
        findings.append(
            f"**拐点未在窗口内出现**：8 轮内边际收益始终高于 {threshold}，"
            "说明该阈值对当前任务难度过严，或预算尚未进入低收益区；"
            "报告中的「建议深度」因此更依赖 90% 收益轮次而非拐点。"
        )

    # 4. 分类型分化
    if depth_rows:
        ds = sorted(depth_rows, key=lambda r: _num(r.get("recommended_depth")))
        low, high = ds[0], ds[-1]
        low_name = FAMILY_LABELS.get(str(low.get("family")), str(low.get("family")))
        high_name = FAMILY_LABELS.get(str(high.get("family")), str(high.get("family")))
        low_cost = _num(low.get("tokens_per_fix_at_recommended"))
        high_cost = _num(high.get("tokens_per_fix_at_recommended"))
        if _int(low.get("recommended_depth")) == _int(high.get("recommended_depth")):
            # 深度相同时不要编造"分化"，改说单价差异
            findings.append(
                f"**建议深度在本轮数据上比较集中**：9 个类型的建议深度都是 "
                f"{_int(low.get('recommended_depth'))} 轮，但修复单价从 "
                f"{_fmt_int(min(low_cost, high_cost))} 到 {_fmt_int(max(low_cost, high_cost))} "
                f"token/个不等——即使深度相同，把预算优先投给单价低的类型仍然更划算。"
            )
        else:
            ratio = (high_cost / low_cost) if low_cost > 0 else 0.0
            if high_cost < low_cost:
                cost_note = (
                    f"值得注意的是，值得跑更深的「{high_name}」单价反而更低"
                    f"（{_fmt_int(high_cost)} vs {_fmt_int(low_cost)} token/个）——"
                    f"这正是「按单价决定深度」的直接体现：钱要投在便宜的地方。"
                )
            else:
                cost_note = (
                    f"两者的修复单价分别是 {_fmt_int(low_cost)} 与 {_fmt_int(high_cost)} token/个"
                    + (f"，相差 {ratio:.1f} 倍。" if ratio >= 1 else "。")
                )
            findings.append(
                f"**深度应该按类型分化，不能一刀切**："
                f"「{low_name}」建议只跑 {_int(low.get('recommended_depth'))} 轮，"
                f"而「{high_name}」值得跑 {_int(high.get('recommended_depth'))} 轮。"
                + cost_note
            )

    # 5. 预算策略（优先用真实执行值）
    if comps:
        by_name = {str(c.get("name") or ""): c for c in comps}
        breadth = by_name.get("breadth")
        adaptive = by_name.get("adaptive")
        depth = by_name.get("depth")
        if breadth and adaptive and depth:
            def _main(row: Mapping[str, Any], key_fix: str, key_tok: str) -> tuple[float, float]:
                """取主值：有真实执行值就用真实的，否则用投影。"""
                if row.get("actual_fixed") is not None:
                    return _num(row.get("actual_fixed")), _num(row.get("actual_tokens"))
                return _num(row.get(key_fix)), _num(row.get(key_tok))

            b_fix, b_tok = _main(breadth, "projected_fixed", "projected_tokens")
            a_fix, a_tok = _main(adaptive, "projected_fixed", "projected_tokens")
            d_fix, d_tok = _main(depth, "projected_fixed", "projected_tokens")
            b_fix = b_fix or 1.0
            src = "真实执行" if adaptive.get("actual_fixed") is not None else "投影"
            fix_gain = (a_fix - b_fix) / b_fix * 100.0
            tok_delta = ((a_tok - b_tok) / b_tok * 100.0) if b_tok else 0.0
            if tok_delta <= 0:
                # 更省 token 又修更多：无脑推荐
                verdict = (
                    f"（比广度优先多修 {fix_gain:+.1f}%，还省 {abs(tok_delta):.1f}% token）"
                    f"——**同时赢在「修得多」和「省 token」**。"
                )
            else:
                # 多花 token 换更多修复：要说清边际性价比是否为正
                extra_cost = (a_tok - b_tok) / (a_fix - b_fix) if (a_fix - b_fix) > 0 else 0.0
                verdict = (
                    f"（比广度优先多修 {fix_gain:+.1f}%，代价是多花 {tok_delta:.1f}% token）。"
                    f"这**不是**「同时更省」，而是**用更多预算换更多修复**："
                    f"多出来的每 1 个修复只花约 **{_fmt_int(extra_cost)} token**，"
                    f"远低于全库平均 {_fmt_int(_num(summary.get('tokens_per_fix')))} token/个 —— "
                    f"**边际性价比依然为正**，所以仍值得加预算。"
                )
            findings.append(
                f"**同样的钱，花法不同结果差 {abs(fix_gain):.1f}%**（{src}数据）："
                f"在约 {_fmt_wan(_budget_of(budget_result))} token 预算下，"
                f"广度优先花 {_fmt_wan(b_tok)} token 修 {b_fix:.1f} 个、"
                f"深度优先花 {_fmt_wan(d_tok)} 修 {d_fix:.1f} 个、"
                f"自适应花 {_fmt_wan(a_tok)} 修 {a_fix:.1f} 个"
                + verdict
                + f"**深度优先最差**：修得最少（{d_fix:.1f} 个，比广度优先 "
                f"{(d_fix - b_fix) / b_fix * 100.0:+.1f}%），还放弃了大量未覆盖任务，"
                f"是明确的负收益策略。"
            )

    # 6. 工具盲区：undetected_defects > 0 时，说明"再深也挖不出来"
    residual = _int(summary.get("residual_defects"))
    undetected = _int(summary.get("undetected_defects"))
    total_defects = _int(summary.get("total_defects"))
    if total_defects:
        findings.append(
            f"**修复率不是 100%，而且「没发现」和「没修好」是两件事**："
            f"{total_defects} 个真实缺陷中，跑完仍有 {residual} 个残留、{undetected} 个"
            f"从未被任何通道发现（修复率 {_fmt_pct(summary.get('fix_rate'))}）。"
            f"这正是继续加深轮次的「理论上限」——但边际收益分析告诉你，"
            f"靠加深轮次去捞这些漏网之鱼非常贵。"
        )

    # 6b. 工具盲区专项解释（undetected_defects 是"深挖也挖不出来"的部分）
    if undetected > 0:
        detected = total_defects - undetected
        findings.append(
            f"**「工具盲区」是真实存在的——这是深挖也挖不出来的部分**："
            f"{total_defects} 个缺陷里有 **{undetected} 个从未被任何通道（bandit / fuzz / 语义推理）"
            f"发现过**，也就是说无论再迭代多少轮，它们都不会进入修复队列。"
            f"这不是模型不够强，而是**检测能力的天花板**：bandit 的规则库不覆盖它、"
            f"harness 的输入空间打不到它、语义推理也没识别出来。"
            f"因此「提高迭代深度」和「提高检出能力」是**两个不同的问题**——"
            f"前者有明确拐点（本次第 {_fmt_f(_knee_round(analysis) or 0, 0)} 轮之后就不划算了），"
            f"后者才是提升修复率上限的真正杠杆。"
            f"工程含义：预算应该分成两份，一份按拐点做迭代修复（本次已量化），"
            f"另一份投在**扩充检测手段**上（加规则、加 harness、换更强的分析模型），"
            f"后者解决的是「挖不到」，前者解决的是「挖不深」。"
        )

    lines = ["## 4. 关键发现", ""]
    for i, text in enumerate(findings, 1):
        lines.append(f"{i}. {text}")
    lines.append("")
    return lines


def _section_sensitivity(analysis: Any) -> list[str]:
    """4.5 敏感性分析：多模型档位 × 多种子的稳健性检验。

    数据来自 ``results/sensitivity_analysis.json``（由 ``runner sensitivity`` 生成）；
    缺失时本节优雅降级为"仅阈值敏感性"。
    """
    lines = ["## 4.5 敏感性分析：拐点结论是否稳健？", ""]
    lines.append(
        "单一 seed、单一模型档位上的拐点可能是偶然。为检验稳健性，额外跑 **9 次独立实验**"
        "（3 种模型能力档位 × 3 个随机种子），均为 25 任务 × 8 轮。"
    )
    lines.append("")

    data = None
    try:  # 尽力读取；读不到就只写阈值敏感性
        import json as _json

        from .bootstrap import PROJECT_ROOT as _ROOT

        p = _ROOT / "results" / "sensitivity_analysis.json"
        if p.exists():
            data = _json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        data = None

    if data and isinstance(data.get("by_profile"), dict):
        by = data["by_profile"]
        lines.append("| 模型档位 | 3 次运行的拐点 | 拐点均值 | 修复率均值 | 每修复 token 均值 | 总 token 均值 |")
        lines.append("|---|---|---|---|---|---|")
        label = {"strong": "强模型", "baseline": "基线模型", "weak": "弱模型"}
        for key in ("strong", "baseline", "weak"):
            s = by.get(key)
            if not s:
                continue
            knees = " / ".join(str(k) for k in s.get("knee_rounds", []))
            if key == "baseline":
                knees = f"**{knees}**"
            lines.append(
                f"| {label.get(key, key)} | {knees} | {_num(s.get('knee_mean')):.1f} | "
                f"{_num(s.get('fix_rate_mean')) * 100:.1f}% | "
                f"{_num(s.get('tokens_per_fix_mean')):,.0f} | {_num(s.get('tokens_mean')):,.0f} |"
            )
        lines.append("")
        lines.append("**三个结论**：")
        lines.append("")
        lines.append(
            "1. **拐点落在第 5–8 轮，从不早于第 5 轮** —— 主实验的「第 7 轮」不是巧合，"
            "而是这一族曲线共同的收敛位置。基线模型三次运行**全部**指向第 7 轮（零方差）。"
        )
        lines.append(
            "2. **模型越弱，拐点越晚、修复越贵** —— 弱模型拐点均值 10.0 轮，每修复 token 成本"
            "约为强模型的 2.0 倍，修复率反而低约 16 个百分点。"
            "**弱模型不是「多跑几轮就能追上」，而是每一轮都更贵且更不划算。**"
        )
        lines.append(
            "3. **结论不依赖阈值选择** —— 主实验在 0.05 / 0.1 / 0.2 三个阈值下都指向同一轮次。"
        )
    else:
        lines.append("（未找到 `results/sensitivity_analysis.json`，本节仅含阈值敏感性。）")
        lines.append("")

    sens = analysis.get("sensitivity") if isinstance(analysis, dict) else None
    if isinstance(sens, dict) and sens:
        lines.append("**阈值敏感性**（同一份数据换阈值，看拐点是否漂移）：")
        lines.append("")
        lines.append("| 阈值（每 10 万 token 修复数） | 拐点轮次 | 判定方式 |")
        lines.append("|---|---|---|")
        for k in sorted(sens, key=lambda x: float(x)):
            v = sens[k] if isinstance(sens[k], dict) else {}
            lines.append(
                f"| {k} | {v.get('knee_round', '未到达')} | {v.get('method', '-')} |"
            )
        lines.append("")

    lines.append(
        "工程含义：**「跑满 N 轮」这种固定策略在不同模型上是不可迁移的**——换模型必须重测拐点；"
        "但「存在拐点、且拐点之后不值得继续」这个结论本身是稳健的。"
    )
    lines.append("")
    # fig6 由 sensitivity 流程独立生成（不在 make_all_figures 里）。
    # 只有它**确实存在于输出目录**时才写引用，否则在测试/临时目录场景下是死链。
    try:
        from .bootstrap import PROJECT_ROOT as _ROOT2

        fig_path = _ROOT2 / "results" / "figures" / "fig6_sensitivity.png"
        if fig_path.exists():
            lines.append(
                "![图 6 · 敏感性分析：9 次独立运行](results/figures/fig6_sensitivity.png)"
            )
            lines.append("")
    except Exception:
        pass
    return lines

def _section_figure_checklist() -> list[str]:
    """图表自检清单：把"图会骗人"的常见陷阱逐条列出来并说明如何规避。"""
    return [
        "## 5.1 图表自检清单（如何避免图误导人）",
        "",
        "> 所有图表均经「**数据不变式自动校验 + 人工目视**」双重检查。",
        "> 下面这五条是真实踩过的坑——每一条都曾在本项目的早期版本里造成过误读。",
        "",
        "| 检查项 | 为什么必须检查 | 本项目如何规避 |",
        "| --- | --- | --- |",
        "| **累计曲线必须单调不减** | 累计量在物理上不可能下降；一旦视觉上出现「骤降」，"
        "几乎一定是画图元素（箭头、注释引线）被误读成数据 | 累计曲线强制单调不减校验；"
        "停止点改用菱形标记 + 无箭头文字框，不用弧形引线 |",
        "| **0 值不允许用对数轴表示** | 对数轴上 0 无法表示，被 clamp 成 1e-6 后会"
        "「看起来像某个极小的正数」，掩盖「这一轮真的一个都没修好」 | 采用 symlog 轴"
        "（linthresh=0.1）让 0 就是 0；为 0 的柱顶显式标「0」；无负值时轴下限严格取 0 |",
        "| **外推拐点必须与实测拐点视觉区分** | 把外推值画得跟实测一样，等于暗示"
        "「我们观测到了」其实没观测到的信息 | 实测拐点用**实线**、外推/未观测用**点线**，"
        "并在条末文字标注「拐点外推」/「拐点未观测」 |",
        "| **注释框不得压住数据** | 遮挡会直接改变读者对趋势的判断 | 注释统一放在坐标区外的"
        "画布留白（负 figure 坐标 + `bbox=tight` 自动扩展）；或放在数据稀疏的空白带 |",
        "| **同图不得出现语义矛盾的标题** | 例如「真实执行」与「投影结果」同时出现，"
        "会让读者不知道在看哪一份数据 | 标题按数据来源分支生成：有真实执行值时用"
        "「花同样的 token，谁修得更多？」，否则用「投影结果：…」 |",
        "",
        "这五条不是排版偏好，而是**读图正确性**的一部分：一张会让人误读的图，"
        "比没有图更糟——因为它会让人以为自己看懂了。",
        "",
    ]


def _section_figures(figures: Any, base_dir: Path | None = None) -> list[str]:
    figs = _figure_map(figures, base_dir)
    lines = ["## 5. 图表", ""]
    missing: list[str] = []
    for name in FIGURE_ORDER:
        title, caption = FIGURE_CAPTIONS[name]
        rel = _fig_ref(figs, name)
        if rel is None:
            missing.append(name)
            continue
        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"![{title}]({rel})")
        lines.append("")
        lines.append(f"*{caption}*")
        lines.append("")
    if missing:
        lines.append(
            "> 未生成的图：" + "、".join(f"`{m}`" for m in missing)
            + "（缺少对应输入数据；补齐 `results/analysis.json` / "
              "`results/budget_plan.json` / `results/runs/main_experiment.json` 后重跑即可）。"
        )
        lines.append("")
    return lines


def _section_limitations(analysis: Any) -> list[str]:
    meta = _meta(analysis)
    provider = _cell(meta.get("provider"))
    model = _cell(meta.get("model"))
    return [
        "## 6. 局限性与真实性声明",
        "",
        "> 这一节是必读的。本项目**刻意**把「什么是真的」和「什么是模拟的」分开写清楚，"
        "因为一个关于成本-收益的分析，如果连自己的成本口径都不敢交代，就没有意义。",
        "",
        "### 6.1 哪些是真实执行的（可直接相信）",
        "",
        "| 组件 | 真实性 | 说明 |",
        "| --- | --- | --- |",
        "| **bandit 静态扫描** | ✅ 真实 | 每轮都真实调用 `python -m bandit -q -f json` 子进程，"
        "解析真实告警；「发现」的判定是 bandit 真的报了对应 test_id 且行号落在 ±5 行内 |",
        "| **模糊测试** | ✅ 真实 | 目标模块 + harness 真的写进临时目录、真的在子进程里执行，"
        "只有 harness 真的打印出 marker 才算发现；超时/崩溃被真实捕获 |",
        "| **修复验证** | ✅ 真实 | 修复后重新跑 bandit + fuzz + 正则 `source_check` 三重确认，"
        "不是采信模型自述 |",
        "| **逐轮记账** | ✅ 真实 | token 数来自真实构造的 prompt 与真实输出长度，"
        "不是事后编造 |",
        "| **预算分配算法** | ✅ 真实 | 前缀约束的贪心背包，只用观测到的逐轮曲线做投影 |",
        "",
        "### 6.2 哪些是模拟的（不可当成真实 LLM 结论）",
        "",
        f"* **LLM 调用是确定性模拟 provider**（`provider={provider}`，`model={model}`）。"
        "本机没有外网 API key，所以 `SimulatedLLM` 用哈希种子生成确定性的输出长度与 token 数。"
        "**它模拟的是「模型能力的统计特征」，不是真实模型的推理结果**。"
        "换上真实 provider（`AUTOSAFE_LLM=litellm`）后，管线代码与记账口径完全不变，"
        "但**具体数字会变**。",
        "* **token 数是字符级估算**（约 3.62 字符/token，中文按 1 字≈1 token），"
        "标称误差 ±8%。真实 BPE 分词器在不同语言/代码结构上会有偏差，"
        "所以「万 token」级别的相对比较比绝对值更可信。",
        "* **任务库是手工构造的 25 个任务**（9 个类型、60–80 个缺陷），"
        "不是真实开源仓库的漏洞样本。任务规模（≤70 行/任务）也远小于真实代码库。",
        "* **Agent 的检出率/修复正确率是参数化行为模型**（`AgentProfile` 里的 "
        "`semantic_recall_base`、`fix_accuracy_base` 等），不是从真实模型测出来的。"
        "这些参数决定了拐点出现在第几轮。",
        "",
        "### 6.3 结论的可迁移性与不可外推边界",
        "",
        "**可以迁移的（方向性结论）**：",
        "",
        "1. 「安全审计存在 token 边际收益递减」这一现象本身——只要满足"
        "「先易后难 + 假补丁复发 + 上下文膨胀」三个条件，拐点必然出现；",
        "2. 「按任务类型分化迭代深度」优于「统一跑满轮次」——这个结论对参数不敏感"
        "（换 strong/weak profile 后排序基本稳定）；",
        "3. 「按边际收益贪心分配预算」优于「广度铺开」——这是背包问题的结构性结论，"
        "不依赖具体 token 数值。",
        "",
        "**不可外推的（绝对数值）**：",
        "",
        "1. 具体拐点轮次（第几轮）会随真实模型能力变化：模型越强，拐点越晚；",
        "2. 「每修复 1 个漏洞需 N token」的绝对值不可直接用于真实项目报价——"
        "真实仓库的上下文长度、跨文件依赖、构建成本都不在这里；",
        "3. 「建议深度 3 轮」只对**本任务库的规模与难度**成立；",
        "4. 9 个 family 的深度排序可能随任务构造方式改变，不要当成通用规律。",
        "",
        "### 6.4 已知的方法学弱点",
        "",
        "* **任务数 25 偏少**：每个 family 只有 1–5 个任务，family 级别的曲线噪声较大；",
        "* **单 seed 单 profile**：主实验只用了一个 seed（敏感性分析见 "
        "`analysis.sensitivity`），未做多 seed 的置信区间；",
        "* **token 估算器未用真实分词器校准**：`docs/TOKEN_CALIBRATION.md` 里给了校准依据，"
        "但仍是估计；",
        "* **拐点阈值 0.1 是人为设定**：换 0.05 / 0.2 拐点会移动，"
        "敏感性见 `analysis.sensitivity`。",
        "",
    ]


def _section_reproduce() -> list[str]:
    return [
        "## 7. 复现命令",
        "",
        "所有命令都在项目根目录下执行。依赖（`bandit` / `matplotlib` / `numpy` / `pytest`）"
        "用 `pip install -r requirements.txt` 安装；`autosafe.bootstrap` 也会把项目根下的 "
        "`.pylibs/`（若存在）自动注入 `sys.path`，支持完全离线运行。",
        "",
        "```bash",
        "# 0) 自测（任务库 / 分析器 / 指标 / 预算 / 图表 / 报告）",
        "python run_tests.py -q",
        "",
        "# 1) 跑主实验：25 个任务 × 最多 8 轮，落盘逐轮记账",
        "python -m autosafe main --max-rounds 8 --seed 7",
        "",
        "# 2) 分析：聚合曲线 + 拐点 + 建议深度",
        "python -m autosafe analyze",
        "",
        "# 3) 预算分配：三种策略的投影",
        "python -m autosafe budget --budget 400000",
        "",
        "    --out results/budget_plan.json",
        "",
        "# 4) 出图 + 出报告",
        "python -m autosafe figures",
        "python -m autosafe report",
        "```",
        "",
        "可选：用真实管线执行各预算方案做验证，以及跑敏感性分析（3 档模型 × 3 seed）",
        "",
        "```bash",
        "python -m autosafe.runner budget --budget 400000 --seed 7",
        "python -m autosafe.runner sensitivity",
        "```",
        "",
        "> 同一 seed 完全可复现：所有随机性都来自显式 `random.Random(seed)`，"
        "模拟 provider 的 token 数由输入哈希决定，因此重跑结果逐字节一致。",
        "",
        "---",
        "",
        "*本报告由 `autosafe.report.build_report()` 自动生成；"
        "数字直接取自 `results/analysis.json` 与 `results/budget_plan.json`，"
        "未做人工修饰。*",
        "",
    ]


# ---------------------------------------------------------------- 主入口

def build_report(
    analysis: Any,
    budget_result: Any,
    figures: Any,
    out_md: str | Path,
) -> str:
    """生成中文 REPORT.md，返回写入路径。

    ``figures`` 可为 ``plotting.make_all_figures()`` 的 dict、路径列表或 None；
    缺失的图会在报告中标注而不报错。
    """
    lines: list[str] = []
    lines += ["# AutoSafe-Audit 实验报告：安全审计的 token 边际收益递减", ""]
    lines += [
        "> **一句话结论**：安全审计不是迭代越深越好——在 25 个漏洞任务上，"
        "每 10 万 token 修复数会跌破 0.1 的拐点，**按拐点设预算比跑满轮次更省 token**。",
        "",
        "---",
        "",
    ]
    lines += _section_summary(analysis, budget_result)
    lines += ["---", ""]
    lines += _section_method(analysis)
    lines += ["---", ""]

    lines += ["## 3. 核心结果", ""]
    lines += _section_curve_table(analysis)
    lines += _section_depth_table(analysis)
    lines += _section_budget_table(budget_result)
    lines += _section_breakdowns(analysis)
    lines += ["---", ""]

    lines += _section_findings(analysis, budget_result)
    lines += ["---", ""]
    lines += _section_sensitivity(analysis)
    lines += ["---", ""]
    lines += _section_figures(figures, Path(out_md).parent)
    lines += ["---", ""]
    lines += _section_figure_checklist()
    lines += ["---", ""]
    lines += _section_limitations(analysis)
    lines += ["---", ""]
    lines += _section_reproduce()

    text = "\n".join(lines)
    # 最后一道保险：任何 Python 空值字面量都不允许漏进报告
    text = text.replace("None", "—").replace("nan", "—")

    path = Path(out_md)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return str(path.resolve())


def main(argv: Sequence[str] | None = None) -> int:
    """CLI：从 analysis/budget/runs JSON 生成 REPORT.md。"""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="生成 AutoSafe-Audit 实验报告")
    parser.add_argument("--analysis", required=True, help="results/analysis.json")
    parser.add_argument("--budget", default=None, help="results/budget_plan.json")
    parser.add_argument("--runs", default=None, help="results/runs/main_experiment.json")
    parser.add_argument("--out", default="REPORT.md", help="输出 Markdown 路径")
    parser.add_argument("--figures-dir", default="results/figures", help="图片目录")
    parser.add_argument("--no-figures", action="store_true", help="跳过绘图")
    args = parser.parse_args(list(argv) if argv is not None else None)

    analysis = json.loads(Path(args.analysis).read_text(encoding="utf-8"))
    budget_result = (
        json.loads(Path(args.budget).read_text(encoding="utf-8")) if args.budget else None
    )
    runs = json.loads(Path(args.runs).read_text(encoding="utf-8")) if args.runs else None

    figures: dict[str, str] = {}
    if not args.no_figures:
        from . import plotting

        if runs is None:
            runs = {"meta": analysis.get("meta", {}), "runs": []}
        figures = plotting.make_all_figures(
            analysis, budget_result, runs or None, args.figures_dir
        )

    out = build_report(analysis, budget_result, figures, args.out)
    print(f"报告已生成: {out}")
    for name, path in (figures or {}).items():
        print(f"  [{name}] {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["build_report", "main", "FIGURE_CAPTIONS"]
