"""核心数据模型：漏洞、任务、逐轮记录、任务运行结果。"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

# 任务家族（任务类型），顺序即报告中的展示顺序
FAMILIES: tuple[str, ...] = (
    "injection",
    "path_traversal",
    "deserialization",
    "crypto",
    "secrets",
    "authz",
    "web",
    "randomness",
    "config",
)

FAMILY_LABELS: dict[str, str] = {
    "injection": "注入类 (SQL/命令/模板)",
    "path_traversal": "路径遍历/文件操作",
    "deserialization": "反序列化/动态执行",
    "crypto": "密码学误用",
    "secrets": "硬编码凭据",
    "authz": "鉴权/权限绕过",
    "web": "Web 输入与输出",
    "randomness": "随机性与令牌",
    "config": "配置与调试开关",
}

CHANNELS: tuple[str, ...] = ("bandit", "fuzz", "semantic")

SEVERITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW")

DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")


@dataclass(frozen=True)
class Defect:
    """一个可被检出、可被修复、可被验证的真实漏洞。"""

    defect_id: str
    cwe: str
    category: str
    severity: str
    subtlety: int
    channel: str
    detector: str
    line_hint: int
    description: str
    source_check: str
    fix_find: str
    fix_replace: str
    flawed_fix_replace: str | None = None
    fuzz_marker: str | None = None

    def __post_init__(self) -> None:
        if self.channel not in CHANNELS:
            raise ValueError(f"未知通道: {self.channel}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"未知严重级别: {self.severity}")
        if not 1 <= self.subtlety <= 5:
            raise ValueError(f"subtlety 必须在 1..5: {self.subtlety}")
        if not (self.source_check.startswith("present:") or self.source_check.startswith("absent:")):
            raise ValueError(f"source_check 格式错误: {self.source_check}")

    @property
    def check_mode(self) -> str:
        return self.source_check.split(":", 1)[0]

    @property
    def check_pattern(self) -> str:
        return self.source_check.split(":", 1)[1]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Task:
    """一个代码安全审计任务。"""

    task_id: str
    title: str
    family: str
    difficulty: str
    prompt: str
    vulnerable_code: str
    defects: tuple[Defect, ...]
    fuzz_harness: str
    secure_reference: str
    notes: str = ""

    def __post_init__(self) -> None:
        if self.family not in FAMILIES:
            raise ValueError(f"未知 family: {self.family}")
        if self.difficulty not in DIFFICULTIES:
            raise ValueError(f"未知难度: {self.difficulty}")
        ids = [d.defect_id for d in self.defects]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{self.task_id} 存在重复 defect_id")
        if not 1 <= len(self.defects) <= 6:
            raise ValueError(f"{self.task_id} 的 defects 数量异常: {len(self.defects)}")

    @property
    def high_severity_count(self) -> int:
        return sum(1 for d in self.defects if d.severity == "HIGH")

    def defect(self, defect_id: str) -> Defect:
        for d in self.defects:
            if d.defect_id == defect_id:
                return d
        raise KeyError(f"{self.task_id} 无漏洞 {defect_id}")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["defects"] = [x.to_dict() for x in self.defects]
        return d


def defect_present(defect: Defect, code: str) -> bool:
    """判断漏洞是否仍存在于代码中（True=仍存在）。"""
    hit = re.search(defect.check_pattern, code, re.MULTILINE) is not None
    return hit if defect.check_mode == "present" else (not hit)


def defects_present(task: Task, code: str) -> list[str]:
    """返回代码中仍然存在的漏洞 id 列表。"""
    return [d.defect_id for d in task.defects if defect_present(d, code)]


def defects_present_set(task: Task, code: str) -> set[str]:
    return set(defects_present(task, code))


def apply_fix(code: str, defect: Defect, *, flawed: bool = False) -> str:
    """把某个漏洞的补丁应用到代码上；无法应用时原样返回。"""
    replace = defect.flawed_fix_replace if flawed else defect.fix_replace
    if replace is None:
        return code
    if defect.fix_find not in code:
        return code
    return code.replace(defect.fix_find, replace, 1)


def task_from_dict(d: dict[str, Any]) -> Task:
    """从 dict 还原 Task（defects 为 dict 列表）。"""
    payload = dict(d)
    payload["defects"] = tuple(Defect(**x) for x in d["defects"])
    return Task(**payload)


@dataclass
class RoundRecord:
    """一轮迭代的完整记账。"""

    task_id: str
    round_index: int
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_by_agent: dict[str, int] = field(default_factory=dict)
    defects_found: int = 0
    defects_fixed: int = 0
    defects_open: int = 0
    defects_known: int = 0
    newly_found_ids: list[str] = field(default_factory=list)
    newly_fixed_ids: list[str] = field(default_factory=list)
    bandit_findings: int = 0
    fuzz_markers: int = 0
    noise_findings: int = 0
    duplicate_findings: int = 0
    cumulative_tokens: int = 0
    cumulative_fixed: int = 0
    stopped_reason: str = ""

    @property
    def tokens_total(self) -> int:
        return self.tokens_in + self.tokens_out

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tokens_total"] = self.tokens_total
        return d


@dataclass
class TaskRun:
    """单个任务从第 1 轮到停止的完整轨迹。"""

    task_id: str
    family: str
    difficulty: str
    rounds: list[RoundRecord] = field(default_factory=list)
    final_code: str = ""
    residual_defect_ids: list[str] = field(default_factory=list)
    undetected_defect_ids: list[str] = field(default_factory=list)
    total_defects: int = 0
    stop_reason: str = ""

    @property
    def total_tokens(self) -> int:
        return sum(r.tokens_total for r in self.rounds)

    @property
    def total_fixed(self) -> int:
        return sum(r.defects_fixed for r in self.rounds)

    @property
    def total_found(self) -> int:
        return sum(r.defects_found for r in self.rounds)

    @property
    def rounds_used(self) -> int:
        return len(self.rounds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "family": self.family,
            "difficulty": self.difficulty,
            "rounds": [r.to_dict() for r in self.rounds],
            "final_code": self.final_code,
            "residual_defect_ids": list(self.residual_defect_ids),
            "undetected_defect_ids": list(self.undetected_defect_ids),
            "total_defects": self.total_defects,
            "total_tokens": self.total_tokens,
            "total_fixed": self.total_fixed,
            "total_found": self.total_found,
            "rounds_used": self.rounds_used,
            "stop_reason": self.stop_reason,
        }


def run_from_dict(d: dict[str, Any]) -> TaskRun:
    """从 dict 还原 TaskRun（容忍 to_dict() 添加的派生字段）。"""
    # RoundRecord.to_dict() 会额外写入 tokens_total（派生属性，非构造参数），
    # 还原时必须过滤掉，否则 RoundRecord(**r) 会因未知关键字参数而失败。
    _derived = {"tokens_total"}
    rounds: list[RoundRecord] = []
    for r in d.get("rounds", []):
        payload = {k: v for k, v in r.items() if k not in _derived}
        payload["tokens_in"] = int(payload.get("tokens_in", 0))
        payload["tokens_out"] = int(payload.get("tokens_out", 0))
        rounds.append(RoundRecord(**payload))
    return TaskRun(
        task_id=d["task_id"],
        family=d["family"],
        difficulty=d["difficulty"],
        rounds=rounds,
        final_code=d.get("final_code", ""),
        residual_defect_ids=list(d.get("residual_defect_ids", [])),
        undetected_defect_ids=list(d.get("undetected_defect_ids", [])),
        total_defects=int(d.get("total_defects", 0)),
        stop_reason=d.get("stop_reason", ""),
    )


def experiment_to_dict(meta: dict[str, Any], runs: Iterable[TaskRun]) -> dict[str, Any]:
    return {"meta": dict(meta), "runs": [r.to_dict() for r in runs]}


def experiment_from_dict(d: dict[str, Any]) -> tuple[dict[str, Any], list[TaskRun]]:
    return dict(d.get("meta", {})), [run_from_dict(r) for r in d.get("runs", [])]
