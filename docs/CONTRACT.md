# AutoSafe-Audit 接口契约 v1（所有模块必须遵守）

> 本文件是并行开发的唯一契约来源。改动契约必须先改本文件并由 Lead 通知所有成员。
> 项目根：`autosafe-audit/`，包名 `autosafe`，源码在 `src/autosafe/`，`sys.path` 由 `autosafe.bootstrap` 处理。

## 0. 运行环境（重要）

- Python 3.14，**无外网 LLM API key**。第三方库装在 `../.pylibs`（workspace 根），通过
  `autosafe.bootstrap.ensure_deps()` 注入 `sys.path`（在 `autosafe/__init__.py` 里已自动调用）。
- 已有：`bandit 1.9.4`、`matplotlib 3.10.9`（含 `Microsoft YaHei` 字体）、`numpy`、`pytest 9.2.0`。
- **禁止**联网安装依赖、禁止调用真实 LLM API、禁止访问网络。
- 所有随机性必须来自显式 `random.Random(seed)`，同一 seed 必须完全可复现。
- 脚本/模块用 `python -m ...` 或 `python xxx.py` 从项目根运行；禁止 `cd` 依赖。

## 1. 数据模型（`autosafe/schema.py`，已由 Lead 实现，只读）

```python
@dataclass(frozen=True)
class Defect:
    defect_id: str        # 任务内唯一，形如 "SQLI_01"
    cwe: str              # "CWE-89"
    category: str         # 见 CATEGORIES
    severity: str         # "HIGH" | "MEDIUM" | "LOW"
    subtlety: int         # 1..5，越大越难发现
    channel: str          # "bandit" | "fuzz" | "semantic"
    detector: str         # bandit: test_id（如 "B608"）；fuzz: 标记名；semantic: 检查名
    line_hint: int        # vulnerable_code 中 1-based 行号
    description: str      # 中文一句话
    source_check: str     # "present:<regex>" | "absent:<regex>"，匹配=漏洞仍存在
    fix_find: str         # 必须在 vulnerable_code 中出现的精确片段
    fix_replace: str      # 正确修复后的片段
    flawed_fix_replace: str | None  # 貌似合理但无效的补丁（可为 None）
    fuzz_marker: str | None         # 与 fuzz 通道对应时给出

@dataclass(frozen=True)
class Task:
    task_id: str          # "T01".."T25"
    title: str
    family: str           # FAMILIES 之一
    difficulty: str       # "easy" | "medium" | "hard"
    prompt: str           # 给 Coding Agent 的任务描述（英文，2-4 句）
    vulnerable_code: str  # 初始（不安全）实现，可执行、可被 bandit/fuzz 分析
    defects: tuple[Defect, ...]
    fuzz_harness: str     # 见 §4
    secure_reference: str # 全部修复后的参考实现
    notes: str
```

辅助函数：`defect_present(defect, code) -> bool`、`defects_present(task, code) -> list[str]`、
`Task.to_dict()` / `task_from_dict()`。

## 2. 任务库契约（`autosafe/tasks/library.py`，T1 负责）

- 导出 `TASKS: list[Task]`，**恰好 25 个**，`task_id` = `T01`..`T25`，不可重复。
- family 覆盖全部 9 类：`injection`(5)、`path_traversal`(3)、`deserialization`(3)、`crypto`(3)、
  `secrets`(2)、`authz`(3)、`web`(3)、`randomness`(2)、`config`(1)。合计 25。
- 每个任务 2–4 个 defects，全库总 defects 数在 60–80 之间；`severity` 至少 1 个 HIGH 的任务 ≥ 20 个。
- `vulnerable_code` 必须是**可 import、无副作用、无网络/无真实文件写**的 Python 模块级代码（≤ 70 行）。
- 通道分布要求：`bandit` 通道 ≥ 45%，`fuzz` ≥ 25%，`semantic` ≥ 20%（同一 defect 只属于一个通道）。
- `source_check` 用 `present:` / `absent:` + 正则（`re.MULTILINE`，可内联 `(?s)`）。
  必须满足：在 `vulnerable_code` 上全部为“存在”，在 `secure_reference` 上全部为“不存在”。
- `fix_find` 必须是对 `vulnerable_code` 的精确子串；把所有 defects 的 `(fix_find, fix_replace)`
  依次应用后，必须得到与 `secure_reference` 语义一致、且全部 `source_check` 为“不存在”的代码。
- `flawed_fix_replace`（若给出）必须**不能**让对应 `source_check` 变为“不存在”（即假修复）。
- 任务库自测（`tests/test_tasks.py`）：数量/家族分布/ID 唯一/上述不变式 + bandit 与 fuzz 实际能命中。
- 另导出 `TASKS_BY_ID: dict[str, Task]` 和 `FAMILY_ORDER: list[str]`。

## 3. 静态分析（`autosafe/analyzers/bandit_runner.py`，T2 负责）

```python
@dataclass(frozen=True)
class StaticFinding:
    test_id: str          # 如 "B608"；语义通道用 "SEM_<name>"
    line: int
    severity: str         # HIGH/MEDIUM/LOW
    confidence: str
    text: str
    cwe: str | None
    source: str           # "bandit" | "semantic"

def scan_bandit(code: str, *, filename: str = "target.py", timeout_s: float = 60.0) -> list[StaticFinding]
```
- 必须**真实调用 bandit CLI**（`python -m bandit -q -f json`，用 `sys.executable`，`PYTHONPATH` 注入
  `.pylibs`），写到临时目录（**注意：本机 `tempfile.mkdtemp` 在沙箱下会失败，必须用
  `autosafe.bootstrap.make_tempdir()`**）。
- 解析 stdout JSON；bandit 退出码 1（有发现）不算错误；非 0/1 或解析失败时返回 `[]` 且不抛异常。
- 结果按 `(test_id, line)` 去重，按 `line` 升序。
- 另提供 `def detect_map(findings, defects) -> list[str]`：把 findings 映射到 defect_id，
  规则：`test_id == defect.detector` 且 `|finding.line - defect.line_hint| <= 5`，一对一取最近；
  未匹配的 finding 就是噪声（不返回）。
- `def semantic_findings(defect_ids, defects, code) -> list[StaticFinding]`：把（由策略判定已发现的）
  语义缺陷转成 finding，`test_id = "SEM_" + defect.detector`，`source="semantic"`。

## 4. 模糊测试（`autosafe/analyzers/fuzzer.py`，T2 负责）

`Task.fuzz_harness` 是**模块级** Python 源码，定义：

```python
def fuzz(module) -> list[str]:
    """对已导入的目标模块施加恶意/边界输入，返回命中的 fuzz_marker 列表。
    必须无害：不联网、不写真实文件、不删除文件、不做真实数据库/子进程调用。
    通过依赖注入（spy 对象）观察行为。"""
```

- `def run_fuzz(harness_src: str, code: str, *, timeout_s: float = 10.0, seed: int = 0) -> FuzzResult`
- `FuzzResult`: `markers: list[str]`、`ok: bool`、`error: str | None`、`stdout: str`、`stderr: str`、
  `duration_ms: int`、`coverage_proxy: float`（0..1，用 `sys.settrace`/行覆盖近似，可选）。
- 实现：把 `code` 写入 `<tmp>/target.py`，`harness_src` 写入 `<tmp>/harness.py`，
  用 `subprocess.run([sys.executable, "harness.py"], cwd=<tmp>, timeout=...)` 执行；
  harness 自己负责 `import target` 与打印 `FUZZ_MARKERS:["ID1","ID2"]`；runner 解析该行。
- 超时/异常必须被吞掉并返回 `ok=False`，**绝不向调用方抛异常**（真实世界里 fuzz 会崩）。

## 5. LLM 适配层（`autosafe/llm.py`，Lead 负责，只读使用）

```python
@dataclass
class LLMResponse:
    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    provider: str          # "simulated" | "litellm"
    def total_tokens(self) -> int

class LLMClient:                       # 协议
    def complete(self, messages: list[dict], *, role: str, temperature: float = 0.2,
                 max_tokens: int = 2048, seed: int = 0) -> LLMResponse
```
- `SimulatedLLM`：确定性（同 seed 同输入 → 同输出与同 token 数），token 数由 `tokens.count_tokens`
  估算 + 角色相关的固定开销。
- `LiteLLMClient`：`AUTOSAFE_LLM=litellm` 时启用，走真实 provider；未配置 key 时抛 `LLMUnavailable`。
- 任何模块**不得**直接 import litellm；只能通过 `autosafe.llm.build_client()`。

## 6. 管线输出（`autosafe/schema.py` 中的 `RoundRecord` / `TaskRun`，Lead 负责）

```python
@dataclass
class RoundRecord:
    task_id: str; round_index: int            # 1-based
    tokens_in: int; tokens_out: int           # 三个 Agent 之和
    tokens_by_agent: dict[str, int]           # {"coding":..., "static":..., "fuzzing":...}
    defects_found: int                        # 本轮"新发现"（不含重复）
    defects_fixed: int                        # 本轮"新修复并经验证"
    defects_open: int; defects_known: int
    newly_found_ids: list[str]; newly_fixed_ids: list[str]
    bandit_findings: int; fuzz_markers: int; noise_findings: int
    cumulative_tokens: int; cumulative_fixed: int
    duplicate_findings: int                   # 重复报告数（token 黑洞）
    stopped_reason: str                       # "" 或 "no_findings"|"max_rounds"|"budget"|"no_progress"

@dataclass
class TaskRun:
    task_id: str; family: str; difficulty: str
    rounds: list[RoundRecord]
    final_code: str
    residual_defect_ids: list[str]            # 跑完后仍存在的真实漏洞
    undetected_defect_ids: list[str]          # 从未被任何通道发现的漏洞
    total_tokens: int; total_fixed: int; total_defects: int
    stop_reason: str
```

JSON 落盘格式（`results/runs/main_experiment.json`）：

```json
{"meta": {"generated_at": "...", "provider": "simulated", "model": "...", "max_rounds": 8,
          "task_count": 25, "seed": 7, "policy_version": "v1", "token_estimator": "..."},
 "runs": [TaskRun.to_dict(), ...]}
```

## 7. 分析层（`autosafe/metrics.py`，T3 负责）

必须实现（签名固定，供 Lead 的 runner 与 T4 的报告调用）：

```python
def load_experiment(path: str | Path) -> dict            # {"meta":..., "runs":[...]}
def aggregate_curve(runs, max_rounds=None) -> list[dict]
    # 每个元素: {"round": r, "cum_tokens": int, "cum_fixed": int,
    #            "round_tokens": int, "round_fixed": int,
    #            "marginal_per_100k": float,   # round_fixed / round_tokens * 100_000
    #            "avg_fixed_per_100k": float}  # cum_fixed / cum_tokens * 100_000
def family_curves(runs) -> dict[str, list[dict]]         # family -> 同结构
def find_knee(curve, *, threshold_per_100k=0.1, window=100_000) -> dict
    # {"knee_round": int|None, "crossed": bool, "observed": bool,
    #  "interpolated_round": float|None, "threshold": 0.1,
    #  "method": "observed"|"loglinear_extrapolation"|"not_reached",
    #  "fit": {"a":..., "b":..., "r2":...}}
def recommend_depth(runs, *, threshold_per_100k=0.1, max_rounds=8) -> list[dict]
    # 每行: {"family":..., "tasks": n, "recommended_depth": int, "knee_round": float|None,
    #        "rounds_to_90pct": int, "marginal_at_knee": float,
    #        "tokens_per_fix_at_recommended": float, "rationale": "..."}
def summary(runs) -> dict                                 # 全局汇总（总 token/总修复/平均每修复 token/残余漏洞）
def analyze(experiment: dict) -> dict                     # 汇总上面所有结果，可直接 json.dump
def write_analysis(experiment: dict, out_path) -> dict
```
CLI：`python -m autosafe.metrics --runs results/runs/main_experiment.json --out results/analysis.json`

### 7.1 `analyze()` 返回值的**固定顶层 key**（T3/T4 必须一致）

```python
{
  "meta": {                      # 回显 experiment meta + 分析参数
      "generated_at": str, "provider": str, "model": str,
      "max_rounds": int, "task_count": int, "seed": int,
      "threshold_per_100k": float,        # 默认 0.1
      "policy_version": str,
  },
  "summary": {                   # 全局汇总
      "total_tokens": int, "total_fixed": int, "total_defects": int,
      "total_rounds": int, "tasks": int,
      "tokens_per_fix": float,           # 总 token / 总修复
      "fix_rate": float,                 # total_fixed / total_defects
      "residual_defects": int, "undetected_defects": int,
      "avg_rounds_used": float, "stop_reason_counts": dict[str, int],
  },
  "curve": [ ... ],              # = aggregate_curve(runs)：全库逐轮聚合曲线
  "families": { "<family>": [ ... ] },   # = family_curves(runs)
  "knee": { ... },               # = find_knee(curve)：全局拐点
  "family_knees": { "<family>": {...} }, # 每个 family 的 find_knee 结果
  "depth_recommendations": [ ... ],      # = recommend_depth(runs)
  "channel_breakdown": { "<bandit|fuzz|semantic>": {...} },
      # {"defects": int, "fixed": int, "fix_rate": float,
      #  "avg_round_fixed": float, "tokens_per_fix": float}
  "difficulty_breakdown": { "<easy|medium|hard>": {...} },   # 同上结构
  "sensitivity": {               # 阈值敏感性（同一份数据换阈值看拐点怎么动）
      "0.05": {...}, "0.1": {...}, "0.2": {...}
  },
}
```

### 7.2 `budget.write_budget()` / CLI 输出的**固定顶层 key**

```python
{
  "meta": {"generated_at": str, "budget": int, "source_run": str,
           "provider": str, "threshold_per_100k": float},
  "plans": [ {"name": str, "label": str, "allocations": {task_id: int},
              "projected_tokens": int, "projected_fixed": float,
              "tasks_covered": int, "avg_depth": float,
              "within_budget": bool, "rationale": str}, ... ],
  "comparison": [ {"name": str, "projected_tokens": int, "projected_fixed": float,
                   "projected_cost_per_fix": float, "tasks_covered": int,
                   "avg_depth": float, "vs_breadth_pct": float}, ... ],
}
```

## 8. 预算分配（`autosafe/budget.py`，T3 负责）

```python
@dataclass(frozen=True)
class BudgetPlan:
    name: str                      # "breadth" | "depth" | "adaptive"
    label: str                     # 中文标签
    allocations: dict[str, int]    # task_id -> max_rounds（0 表示不跑）
    projected_tokens: int
    projected_fixed: float
    rationale: str

def plan_breadth(runs, budget: int) -> BudgetPlan
def plan_depth(runs, budget: int, *, focus_tasks: int = 6) -> BudgetPlan
def plan_adaptive(runs, budget: int) -> BudgetPlan   # 按边际收益贪心（前缀约束的背包）
def compare(plans, runs) -> list[dict]               # 用观测曲线投影每个方案
def write_budget(plans, runs, out_path) -> dict
```
- `plan_*` 只能使用 `runs` 里已观测到的每任务逐轮 (tokens, fixed) 曲线做投影，不得编造数字。
- 预算约束：`projected_tokens <= budget`，且 `allocations` 里每个值 ∈ [0, 8]。
- CLI：`python -m autosafe.budget --runs results/runs/main_experiment.json --budget 600000 --out results/budget_plan.json`
  （输出所有方案 + 投影；Lead 的 runner 会用真实管线执行这些方案再对比。）

## 9. 图表与报告（`autosafe/plotting.py` + `autosafe/report.py`，T4 负责）

- `plotting.py`：
  - `fig_cumulative_curve(analysis, out_png)`：累计 token vs 累计修复漏洞（全库 + 3 条典型 family），
    标注拐点、阈值线、以及“广度覆盖”参考点。
  - `fig_marginal_curve(analysis, out_png)`：每轮边际“每 10 万 token 修复数”，双轴或双面板，
    含 0.1 阈值水平线与拐点标记。
  - `fig_family_depth(analysis, out_png)`：按任务类型的建议迭代深度（条形图 + 90% 收益轮次）。
  - `fig_budget_compare(budget_result, out_png)`：三种预算策略的“总修复数 vs 总 token”与柱状对比。
  - `fig_task_heatmap(runs, out_png)`：25 任务 × 8 轮的累计修复热力图。
  - 所有图必须设置中文字体（`Microsoft YaHei`，`axes.unicode_minus=False`），DPI ≥ 160，
    保存到 `results/figures/`，返回路径列表。**不得**调用 `plt.show()`。
- `report.py`：`build_report(analysis, budget_result, figures, out_md)` 生成 `REPORT.md`（中文），
  包含：方法、实验设置、核心表格（逐轮汇总/按 family 的深度建议/预算对比）、关键结论、
  局限性与真实性声明（模拟 provider、模型参数、不可外推的边界）。
- `README.md`：项目定位、架构图（ASCII）、快速开始、目录结构、结果复现命令、简历要点（中文）。

## 10. 协作规则

- 只写自己 scope 内的文件；需要改别人文件先发消息给 Lead。
- 每完成一个模块，跑自己的 pytest，并在完成消息里给出：改动文件、测试命令、测试结果摘要。
- 不得修改 `schema.py` / `llm.py` / `pipeline.py`（Lead 所有）。
- 代码风格：`from __future__ import annotations`、类型标注、docstring 中文一句话、无第三方
  （matplotlib/numpy/pytest/bandit 除外）。
