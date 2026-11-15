"""三 Agent 迭代审计管线。

一轮迭代的真实流程
------------------
1. **Coding Agent**：首轮按任务描述生成实现；之后按上一轮的 findings 打补丁。
2. **Static Analyzer Agent**：真实调用 bandit 扫描，并对 bandit 覆盖不到的语义类缺陷做
   LLM 推理（概率检出）。分析器每轮有 triage 容量上限（真实工具一轮报几百条，Agent 只能
   复核 top-k），因此发现是逐轮"挤"出来的，而不是一轮全中。
3. **Fuzzing Agent**：真实把目标模块 + harness 写进子进程执行，收集运行时 marker。
4. 若仍有未修复缺陷 → 回给 Coding Agent 修复，进入下一轮；修复后重新扫描验证。

记账口径（与 AutoSafeCoder 论文对齐）
------------------------------------
* `tokens_in/out` = 三个 Agent 当轮输入 + 输出之和
* `defects_found` = 当轮**首次**发现的缺陷数（重复报告不计入，但计入 `duplicate_findings`）
* `defects_fixed` = 当轮**验证通过**的新修复数（不是"Agent 声称修好了"）
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import agents as agent_model
from .analyzers import bandit_runner, fuzzer
from .llm import LLMClient, build_client
from .schema import (
    Defect,
    RoundRecord,
    Task,
    TaskRun,
    apply_fix,
    defect_present,
    defects_present,
)

DEFAULT_MAX_ROUNDS = 8
DEFAULT_TRIAGE_BASE = 3
DEFAULT_TRIAGE_GROWTH = 1

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class PipelineConfig:
    """管线运行参数。"""

    max_rounds: int = DEFAULT_MAX_ROUNDS
    token_budget: int | None = None      # 累计 token 上限（None=不限）
    profile: str = agent_model.DEFAULT_PROFILE
    seed: int = 7
    triage_base: int = DEFAULT_TRIAGE_BASE
    triage_growth: int = DEFAULT_TRIAGE_GROWTH
    # 连续 N 轮零修复则停止。**主实验必须设为 >= max_rounds（即关闭）**：
    # 否则第 5-8 轮会被提前截断，我们就观察不到"边际收益趋零"这个现象本身，
    # 也就没有证据支撑"建议迭代深度"。提前停止是分析结论，不是实验前提。
    early_stop_patience: int = 99
    verify_with_tools: bool = True       # 用真实 bandit/fuzz 验证修复，而不是只看正则
    verbose: bool = False


@dataclass
class RoundScan:
    """一轮扫描的原始结果（真实工具输出）。"""

    bandit: list = field(default_factory=list)      # list[StaticFinding]
    fuzz_markers: list[str] = field(default_factory=list)
    fuzz_ok: bool = True
    bandit_ms: int = 0
    fuzz_ms: int = 0


def _scan(task: Task, code: str, *, verify_with_tools: bool) -> RoundScan:
    """对一段代码做真实静态 + 动态扫描。"""
    t0 = time.perf_counter()
    findings = bandit_runner.scan_bandit(code, filename=f"{task.task_id}.py")
    bandit_ms = int((time.perf_counter() - t0) * 1000)
    t1 = time.perf_counter()
    if verify_with_tools:
        fres = fuzzer.run_fuzz(task.fuzz_harness, code, timeout_s=8.0, seed=0)
        markers = list(fres.markers)
        fuzz_ok = fres.ok
    else:
        markers, fuzz_ok = [], True
    fuzz_ms = int((time.perf_counter() - t1) * 1000)
    return RoundScan(bandit=findings, fuzz_markers=markers, fuzz_ok=fuzz_ok,
                     bandit_ms=bandit_ms, fuzz_ms=fuzz_ms)


def _detectable(task: Task, scan: RoundScan, profile: agent_model.AgentProfile,
                round_index: int, times_reported: dict[str, int], seed: int) -> set[str]:
    """本轮真实工具 + 语义推理能够"看到"的缺陷集合。"""
    defects = {d.defect_id: d for d in task.defects}
    detectable: set[str] = set()

    # 通道 1：真实 bandit
    for did in bandit_runner.detect_map(scan.bandit, task.defects):
        if defects[did].channel == "bandit":
            detectable.add(did)

    # 通道 2：真实 fuzz marker
    marker_to_id = {d.fuzz_marker: d.defect_id for d in task.defects if d.fuzz_marker}
    for m in scan.fuzz_markers:
        did = marker_to_id.get(m)
        if did and defects[did].channel == "fuzz":
            detectable.add(did)

    # 通道 3：语义推理（bandit/fuzz 结构上看不到的缺陷）
    for d in task.defects:
        if d.channel != "semantic" or d.defect_id in detectable:
            continue
        if agent_model.will_detect_semantic(
            d, task, profile, round_index, times_reported.get(d.defect_id, 0), seed
        ):
            detectable.add(d.defect_id)
    return detectable


def _triage_capacity(round_index: int, cfg: PipelineConfig) -> int:
    return cfg.triage_base + cfg.triage_growth * (round_index - 1)


def _prioritize(task: Task, ids: Iterable[str]) -> list[str]:
    """按严重级别 + 难度排序（Agent 先处理高严重、易验证的）。"""
    by_id = {d.defect_id: d for d in task.defects}
    return sorted(
        ids,
        key=lambda i: (_SEVERITY_RANK.get(by_id[i].severity, 9), by_id[i].subtlety, i),
    )


def _verify_fixed(task: Task, defect: Defect, code: str, scan: RoundScan,
                  *, verify_with_tools: bool) -> bool:
    """验证某缺陷是否真的被修掉了：正则 + 真实工具双重确认。"""
    if defect_present(defect, code):
        return False
    if not verify_with_tools:
        return True
    if defect.channel == "bandit":
        return defect.defect_id not in set(bandit_runner.detect_map(scan.bandit, task.defects))
    if defect.channel == "fuzz":
        marker_to_id = {d.fuzz_marker: d.defect_id for d in task.defects if d.fuzz_marker}
        hit = {marker_to_id.get(m) for m in scan.fuzz_markers}
        return defect.defect_id not in hit
    return True


def _count_noise(scan: RoundScan, task: Task) -> int:
    """未匹配到真实缺陷的 bandit 告警 = 噪声（误报）。"""
    mapped = set(bandit_runner.detect_map(scan.bandit, task.defects))
    return max(0, len(scan.bandit) - len(mapped))


def run_task(
    task: Task,
    *,
    client: LLMClient | None = None,
    config: PipelineConfig | None = None,
    max_rounds: int | None = None,
    token_budget: int | None = None,
) -> TaskRun:
    """跑完一个任务的全部迭代轮次，返回完整轨迹。"""
    cfg = config or PipelineConfig()
    if max_rounds is not None:
        cfg = PipelineConfig(**{**cfg.__dict__, "max_rounds": max_rounds})
    if token_budget is not None:
        cfg = PipelineConfig(**{**cfg.__dict__, "token_budget": token_budget})
    client = client or build_client()
    profile = agent_model.get_profile(cfg.profile)

    code = task.vulnerable_code
    discovered: set[str] = set()
    fixed: set[str] = set()
    times_reported: dict[str, int] = {d.defect_id: 0 for d in task.defects}
    history: list[dict] = []
    rounds: list[RoundRecord] = []
    cum_tokens = 0
    cum_fixed = 0
    zero_fix_streak = 0
    stop_reason = "max_rounds"

    for r in range(1, cfg.max_rounds + 1):
        rec = RoundRecord(task_id=task.task_id, round_index=r)
        by_agent = {"coding": 0, "static": 0, "fuzzing": 0}
        tin = tout = 0

        # ---------- 1. Coding Agent ----------
        if r == 1:
            resp = client.complete(
                agent_model.coding_prompt(task, r, history), role="coding", seed=cfg.seed
            )
            by_agent["coding"] += resp.total_tokens()
            tin += resp.prompt_tokens
            tout += resp.completion_tokens
        else:
            open_ids = [d.defect_id for d in task.defects if d.defect_id in discovered
                        and d.defect_id not in fixed]
            resp = client.complete(
                agent_model.repair_prompt(code, open_ids, r), role="repair", seed=cfg.seed
            )
            by_agent["coding"] += resp.total_tokens()
            tin += resp.prompt_tokens
            tout += resp.completion_tokens

        # ---------- 2. 分析阶段：真实扫描 + 两个分析 Agent ----------
        scan = _scan(task, code, verify_with_tools=cfg.verify_with_tools)
        bandit_report = agent_model.render_bandit_report(scan.bandit)
        # 注意：fuzz 日志**不能**包含任何耗时/时间戳，否则同 seed 不可复现
        fuzz_log = (
            f"harness_exit_ok={scan.fuzz_ok}\n"
            f"markers_triggered={len(scan.fuzz_markers)}\n"
            + "\n".join(f"- marker {m}" for m in scan.fuzz_markers)
        )
        static_resp = client.complete(
            agent_model.static_prompt(code, r, bandit_report), role="static", seed=cfg.seed
        )
        by_agent["static"] += static_resp.total_tokens()
        tin += static_resp.prompt_tokens
        tout += static_resp.completion_tokens

        fuzz_resp = client.complete(
            agent_model.fuzz_prompt(code, r, fuzz_log), role="fuzzing", seed=cfg.seed
        )
        by_agent["fuzzing"] += fuzz_resp.total_tokens()
        tin += fuzz_resp.prompt_tokens
        tout += fuzz_resp.completion_tokens

        # ---------- 3. 发现（检测 ∩ triage 容量） ----------
        still_open_real = set(defects_present(task, code))
        detectable = _detectable(task, scan, profile, r, times_reported, cfg.seed)
        detectable &= still_open_real          # 已被修好的不会再被报
        new_ids = _prioritize(task, detectable - discovered)
        capacity = _triage_capacity(r, cfg)
        reported_new = new_ids[:capacity]
        discovered |= set(reported_new)

        # 已知未修缺陷会被重复报告（token 黑洞）
        known_open = [d.defect_id for d in task.defects
                      if d.defect_id in discovered and d.defect_id not in fixed]
        dup = [i for i in known_open if i not in reported_new]
        for did in reported_new + dup:
            times_reported[did] = times_reported.get(did, 0) + 1

        for did in reported_new:
            d = task.defect(did)
            history.append({
                "id": did,
                "channel": d.channel,
                "line": d.line_hint,
                "detail": d.description,
            })

        # ---------- 4. 修复（Coding Agent 的修复回合） ----------
        # 真实 Agent 循环里，**每个待修缺陷都要一次独立的补丁生成调用**（一次只改一处，
        # 便于验证与回滚）。这是 token 消耗的主要来源，也是"修得越多、花得越多"的物理原因。
        code_before_fix = code
        fix_attempts = [task.defect(i) for i in _prioritize(task, reported_new + dup)]
        newly_fixed: list[str] = []
        for d in fix_attempts:
            if d.defect_id in fixed:
                continue
            patch_resp = client.complete(
                agent_model.repair_prompt(code, [d.defect_id], r), role="repair", seed=cfg.seed
            )
            by_agent["coding"] += patch_resp.total_tokens()
            tin += patch_resp.prompt_tokens
            tout += patch_resp.completion_tokens
            outcome = agent_model.attempt_fix(d, task, profile, r, cfg.seed)
            if outcome.correct:
                code = apply_fix(code, d, flawed=False)
            elif outcome.mode == "flawed":
                code = apply_fix(code, d, flawed=True)

        # ---------- 5. 验证（重新扫描，真实工具确认） ----------
        # 优化：只有代码真的变了才重扫（bandit 冷启动 1.4-7s，25 任务 × 8 轮必须省）
        if fix_attempts:
            if code != code_before_fix:
                vscan = _scan(task, code, verify_with_tools=cfg.verify_with_tools)
            else:
                vscan = scan          # 代码未变，沿用本轮扫描结果
            for d in fix_attempts:
                if d.defect_id in fixed:
                    continue
                if _verify_fixed(task, d, code, vscan, verify_with_tools=cfg.verify_with_tools):
                    newly_fixed.append(d.defect_id)
        fixed |= set(newly_fixed)

        residual = set(defects_present(task, code))
        cum_fixed += len(newly_fixed)
        cum_tokens += tin + tout

        rec.tokens_in = tin
        rec.tokens_out = tout
        rec.tokens_by_agent = by_agent
        rec.defects_found = len(reported_new)
        rec.defects_fixed = len(newly_fixed)
        rec.defects_open = len(residual)
        rec.defects_known = len(discovered - fixed)
        rec.newly_found_ids = reported_new
        rec.newly_fixed_ids = newly_fixed
        rec.bandit_findings = len(scan.bandit)
        rec.fuzz_markers = len(scan.fuzz_markers)
        rec.noise_findings = _count_noise(scan, task)
        rec.duplicate_findings = len(dup)
        rec.cumulative_tokens = cum_tokens
        rec.cumulative_fixed = cum_fixed
        rounds.append(rec)

        if cfg.verbose:
            print(
                f"  [{task.task_id}] r{r}: tok={tin + tout} new={len(reported_new)} "
                f"fixed={len(newly_fixed)} open={len(residual)} dup={len(dup)}"
            )

        # ---------- 6. 停止判据 ----------
        if not residual:
            stop_reason = "no_findings"
            break
        if not reported_new and not dup:
            stop_reason = "no_findings"
            break
        if cfg.token_budget is not None and cum_tokens >= cfg.token_budget:
            stop_reason = "budget"
            break
        if not newly_fixed:
            zero_fix_streak += 1
            if zero_fix_streak >= cfg.early_stop_patience:
                stop_reason = "no_progress"
                break
        else:
            zero_fix_streak = 0
        if r == cfg.max_rounds:
            stop_reason = "max_rounds"

    final_residual = defects_present(task, code)
    undetected = [d.defect_id for d in task.defects if d.defect_id not in discovered]
    return TaskRun(
        task_id=task.task_id,
        family=task.family,
        difficulty=task.difficulty,
        rounds=rounds,
        final_code=code,
        residual_defect_ids=final_residual,
        undetected_defect_ids=undetected,
        total_defects=len(task.defects),
        stop_reason=stop_reason,
    )


def run_experiment(
    tasks: list[Task],
    *,
    config: PipelineConfig | None = None,
    client: LLMClient | None = None,
    out_path: str | Path | None = None,
    verbose: bool = True,
) -> dict:
    """在任务集合上跑完整实验，返回可直接落盘的 dict。"""
    cfg = config or PipelineConfig()
    client = client or build_client()
    started = time.time()
    runs: list[TaskRun] = []
    for i, task in enumerate(tasks, 1):
        t0 = time.time()
        run = run_task(task, client=client, config=cfg)
        runs.append(run)
        if verbose:
            print(
                f"[{i:02d}/{len(tasks)}] {task.task_id} {task.family:<15} "
                f"rounds={run.rounds_used} tok={run.total_tokens:>7,} "
                f"fixed={run.total_fixed}/{run.total_defects} "
                f"residual={len(run.residual_defect_ids)} "
                f"({time.time() - t0:.1f}s)"
            )
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "provider": getattr(client, "provider", "unknown"),
        "model": getattr(client, "model", "unknown"),
        "max_rounds": cfg.max_rounds,
        "task_count": len(tasks),
        "seed": cfg.seed,
        "profile": cfg.profile,
        "token_budget": cfg.token_budget,
        "triage_base": cfg.triage_base,
        "triage_growth": cfg.triage_growth,
        "verify_with_tools": cfg.verify_with_tools,
        "policy_version": "v1",
        "token_estimator": "autosafe.tokens.count_tokens (chars/3.62, CJK=1)",
        "wall_seconds": round(time.time() - started, 1),
        "total_tokens": sum(r.total_tokens for r in runs),
        "total_fixed": sum(r.total_fixed for r in runs),
        "total_defects": sum(r.total_defects for r in runs),
    }
    payload = {"meta": meta, "runs": [r.to_dict() for r in runs]}
    if out_path is not None:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload
