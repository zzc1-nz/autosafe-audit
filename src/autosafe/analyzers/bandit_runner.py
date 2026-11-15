"""静态分析：真实调用 bandit CLI，并把语义通道缺陷统一成 finding。

设计要点（对齐 docs/CONTRACT.md §3）：

* ``scan_bandit`` 必须真实起子进程跑 ``python -m bandit -q -f json``；
* bandit 退出码 1 表示"有发现"，不算失败；超时/其他退出码/JSON 解析失败一律返回 ``[]``
  且不抛异常（真实世界里扫描器经常崩）；
* 本机沙箱下 ``tempfile.mkdtemp`` 不可写，临时目录统一走 ``bootstrap.make_tempdir``；
* bandit 输出可能带 UTF-8 BOM，解析用 ``utf-8-sig``；
* bandit 冷启动约 1.4s，同一轮里同一份代码常被扫多次，故按 ``code`` 的 sha256 做进程内
  LRU 缓存（只缓存成功结果，失败/超时不缓存）。
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from ..bootstrap import cleanup, make_tempdir, subprocess_env

# 语义通道 finding 的 test_id 前缀（见 CONTRACT §3）
SEMANTIC_PREFIX = "SEM_"

# detect_map 的行号容错窗口（CONTRACT §3）
LINE_TOLERANCE = 5

# 缓存容量：足够覆盖一轮里所有任务的代码
_CACHE_MAXSIZE = 128


@dataclass(frozen=True)
class StaticFinding:
    """一条静态分析发现（bandit 或语义通道）。"""

    test_id: str
    line: int
    severity: str
    confidence: str
    text: str
    cwe: str | None = None
    source: str = "bandit"


# --------------------------------------------------------------------------- #
# 缓存
# --------------------------------------------------------------------------- #
class _LRUCache:
    """极简 LRU：按 key 缓存不可变结果，容量固定。"""

    def __init__(self, maxsize: int = _CACHE_MAXSIZE) -> None:
        self._maxsize = maxsize
        self._data: OrderedDict[str, tuple[StaticFinding, ...]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> tuple[StaticFinding, ...] | None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self.hits += 1
                return self._data[key]
            self.misses += 1
            return None

    def put(self, key: str, value: Sequence[StaticFinding]) -> None:
        with self._lock:
            self._data[key] = tuple(value)
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.hits = 0
            self.misses = 0

    def __len__(self) -> int:  # pragma: no cover - 仅调试用
        with self._lock:
            return len(self._data)


_CACHE = _LRUCache()


def clear_cache() -> None:
    """清空 bandit 结果缓存（测试/换环境时用）。"""
    _CACHE.clear()


def _cache_key(code: str, filename: str, timeout_s: float) -> str:
    """缓存键：代码 sha256 + 文件名 + 超时（超时影响结果，必须入键）。"""
    digest = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()
    return f"{digest}:{filename}:{timeout_s!r}"


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #
def _cwe_of(raw: object) -> str | None:
    """把 bandit 的 ``issue_cwe`` 结构转成 ``"CWE-89"``。"""
    if isinstance(raw, dict):
        cid = raw.get("id")
        if isinstance(cid, int) and cid > 0:
            return f"CWE-{cid}"
        if isinstance(cid, str) and cid.strip():
            return f"CWE-{cid.strip()}"
    return None


def _parse_bandit_json(raw: bytes | str) -> list[StaticFinding]:
    """解析 bandit JSON 输出；结构异常时返回 ``[]``。"""
    text = raw.decode("utf-8-sig", "replace") if isinstance(raw, bytes) else raw
    text = text.strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(payload, dict):
        return []

    findings: dict[tuple[str, int], StaticFinding] = {}
    for item in payload.get("results") or []:
        if not isinstance(item, dict):
            continue
        test_id = str(item.get("test_id") or "").strip()
        try:
            line = int(item.get("line_number") or 0)
        except (TypeError, ValueError):
            continue
        if not test_id or line <= 0:
            continue
        finding = StaticFinding(
            test_id=test_id,
            line=line,
            severity=str(item.get("issue_severity") or "UNDEFINED"),
            confidence=str(item.get("issue_confidence") or "UNDEFINED"),
            text=str(item.get("issue_text") or ""),
            cwe=_cwe_of(item.get("issue_cwe")),
            source="bandit",
        )
        findings.setdefault((test_id, line), finding)

    return sorted(findings.values(), key=lambda f: (f.line, f.test_id))


# --------------------------------------------------------------------------- #
# bandit 调用
# --------------------------------------------------------------------------- #
def _safe_filename(filename: str) -> str:
    """只取 basename，避免把临时目录写到别处。"""
    name = Path(str(filename)).name.strip()
    return name or "target.py"


def scan_bandit(
    code: str,
    *,
    filename: str = "target.py",
    timeout_s: float = 60.0,
) -> list[StaticFinding]:
    """真实调用 bandit 扫描 ``code``，返回去重并按行升序的发现列表。

    任何失败（超时、非 0/1 退出码、JSON 解析失败、OS 异常）都返回 ``[]``，绝不抛异常。
    """
    if not isinstance(code, str) or not code.strip():
        return []

    name = _safe_filename(filename)
    key = _cache_key(code, name, timeout_s)
    cached = _CACHE.get(key)
    if cached is not None:
        return list(cached)

    tmp: Path | None = None
    try:
        tmp = make_tempdir("bandit-")
        target = tmp / name
        target.write_text(code, encoding="utf-8")

        cmd = [sys.executable, "-m", "bandit", "-q", "-f", "json", str(target)]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout_s,
            env=subprocess_env(),
        )
        # 0=无发现，1=有发现；其余视为失败
        if proc.returncode not in (0, 1):
            return []
        findings = _parse_bandit_json(proc.stdout)
        # 只缓存成功解析的结果；超时/失败不缓存，避免污染后续调用
        _CACHE.put(key, findings)
        return list(findings)
    except subprocess.TimeoutExpired:
        return []
    except Exception:  # noqa: BLE001 - 扫描器任何异常都不能打断管线
        return []
    finally:
        if tmp is not None:
            cleanup(tmp)


# --------------------------------------------------------------------------- #
# 映射
# --------------------------------------------------------------------------- #
def _detector_matches(test_id: str, detector: str) -> bool:
    """finding 的 test_id 是否对应缺陷的 detector（兼容语义通道前缀）。"""
    if test_id == detector:
        return True
    if test_id == SEMANTIC_PREFIX + detector:
        return True
    return False


def detect_map(
    findings: Iterable[StaticFinding],
    defects: Iterable[object],
) -> list[str]:
    """把 findings 一对一映射到 defect_id，返回被命中的 defect_id 列表。

    规则（CONTRACT §3）：``test_id == defect.detector`` 且
    ``|finding.line - defect.line_hint| <= 5``；同一 finding 只匹配一个 defect，
    同一 defect 只被匹配一次；按距离最近贪心分配。未匹配的 finding 属于噪声。
    返回顺序按 ``defects`` 的输入顺序，保证确定性。
    """
    finding_list = list(findings)
    defect_list = list(defects)

    # 候选对：(距离, finding 下标, defect 下标)，距离优先、下标做稳定 tie-break
    pairs: list[tuple[int, int, int]] = []
    for fi, finding in enumerate(finding_list):
        test_id = getattr(finding, "test_id", "")
        line = getattr(finding, "line", 0)
        for di, defect in enumerate(defect_list):
            detector = getattr(defect, "detector", None)
            line_hint = getattr(defect, "line_hint", None)
            if not detector or line_hint is None:
                continue
            if not _detector_matches(str(test_id), str(detector)):
                continue
            distance = abs(int(line) - int(line_hint))
            if distance <= LINE_TOLERANCE:
                pairs.append((distance, fi, di))

    pairs.sort()
    used_findings: set[int] = set()
    matched_defects: set[int] = set()
    for _distance, fi, di in pairs:
        if fi in used_findings or di in matched_defects:
            continue
        used_findings.add(fi)
        matched_defects.add(di)

    ordered = sorted(matched_defects)
    return [str(getattr(defect_list[di], "defect_id")) for di in ordered]


# --------------------------------------------------------------------------- #
# 语义通道
# --------------------------------------------------------------------------- #
def semantic_findings(
    defect_ids: Iterable[str],
    defects: Iterable[object],
    code: str = "",
) -> list[StaticFinding]:
    """把（已由策略判定发现的）语义通道缺陷转成 ``StaticFinding``。

    ``test_id = "SEM_" + defect.detector``、``source="semantic"``、``line = defect.line_hint``。
    ``code`` 仅为签名兼容保留，用于确认行号不越界（越界仍按契约保留 line_hint）。
    """
    wanted: list[str] = []
    for did in defect_ids:
        sid = str(did)
        if sid and sid not in wanted:
            wanted.append(sid)

    by_id: dict[str, object] = {}
    for defect in defects:
        did = getattr(defect, "defect_id", None)
        if did is not None:
            by_id[str(did)] = defect

    out: list[StaticFinding] = []
    for did in wanted:
        defect = by_id.get(did)
        if defect is None:
            continue
        detector = str(getattr(defect, "detector", "") or "")
        if not detector:
            continue
        try:
            line = int(getattr(defect, "line_hint", 0) or 0)
        except (TypeError, ValueError):
            continue
        if line <= 0:
            continue
        out.append(
            StaticFinding(
                test_id=SEMANTIC_PREFIX + detector,
                line=line,
                severity=str(getattr(defect, "severity", "MEDIUM") or "MEDIUM"),
                confidence="HIGH",
                text=str(getattr(defect, "description", "") or ""),
                cwe=getattr(defect, "cwe", None),
                source="semantic",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 便利入口（pipeline 用）
# --------------------------------------------------------------------------- #
def scan(
    code: str,
    *,
    filename: str = "target.py",
    semantic_ids: Iterable[str] = (),
    defects: Iterable[object] = (),
) -> tuple[list[StaticFinding], list[str]]:
    """一次拿到 (全部 findings, 命中的 defect_id 列表)。

    findings = bandit 发现 + 语义通道发现（按行号排序）；命中列表由 ``detect_map``
    一对一映射得到，语义 finding 通过 ``SEM_`` 前缀同样参与映射。
    """
    defect_list = list(defects)
    findings = scan_bandit(code, filename=filename)
    semantic = semantic_findings(semantic_ids, defect_list, code)
    merged = sorted(findings + semantic, key=lambda f: (f.line, f.test_id))
    mapped = detect_map(merged, defect_list)
    return merged, mapped
