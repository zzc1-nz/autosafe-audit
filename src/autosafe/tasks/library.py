"""25 个安全审计任务定义（T01..T25），严格遵循 docs/CONTRACT.md §2。"""
from __future__ import annotations

from autosafe.schema import FAMILIES, Defect, Task

TASKS: list[Task] = [
    Task(
        task_id='T01',
        title="""用户查询模块的 SQL 注入""",
        family='injection',
        difficulty='easy',
        prompt="""Implement a small data-access layer for a user directory backed by SQLite. The module exposes connect(db_path), find_user(conn, username), search_users(conn, keyword, page), list_orders(conn, order_by), delete_user(conn, user_id), count_users(conn) and close(conn). Keep the public signatures and return types stable.""",
        vulnerable_code="""import logging
import sqlite3

logger = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
SORTABLE_COLUMNS = ("id", "total", "created_at")


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def find_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE username = '" + username + "'")
    row = cur.fetchone()
    logger.info("looked up user %s", username)
    return row


def search_users(conn, keyword, page=1):
    cur = conn.cursor()
    page = max(1, int(page))
    offset = (page - 1) * DEFAULT_PAGE_SIZE
    sql = "SELECT id, username FROM users WHERE username LIKE '%" + keyword + "%'"
    sql += " LIMIT %d OFFSET %d" % (DEFAULT_PAGE_SIZE, offset)
    cur.execute(sql)
    return cur.fetchall()


def list_orders(conn, order_by):
    cur = conn.cursor()
    cur.execute("SELECT id, total FROM orders ORDER BY " + order_by)
    return cur.fetchall()


def delete_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = {}".format(user_id))
    conn.commit()
    logger.info("deleted user %s", user_id)
    return True


def count_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    return cur.fetchone()[0]


def close(conn):
    conn.close()""",
        defects=(
            Defect(
                defect_id='SQLI_01',
                cwe='CWE-89',
                category='sql_injection',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B608',
                line_hint=19,
                description="""用户名被直接拼接进 SELECT 语句，可绕过登录或拖库。""",
                source_check='present:WHERE username = \\\'" \\+ username',
                fix_find="""    cur.execute("SELECT id, email FROM users WHERE username = '" + username + "'")""",
                fix_replace="""    cur.execute("SELECT id, email FROM users WHERE username = ?", (username,))""",
                flawed_fix_replace="""    cur.execute("SELECT id, email FROM users WHERE username = '" + username.replace("'", "''") + "'")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SQLI_02',
                cwe='CWE-89',
                category='sql_injection',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B608',
                line_hint=29,
                description="""LIKE 关键字拼接导致注入，且 LIMIT/OFFSET 也用 % 格式化。""",
                source_check='present:LIKE \\\'%" \\+ keyword',
                fix_find='    sql = "SELECT id, username FROM users WHERE username LIKE \'%" + keyword + "%\'"',
                fix_replace="""    sql = "SELECT id, username FROM users WHERE username LIKE ?"
    params = ["%" + keyword + "%"]""",
                flawed_fix_replace='    keyword = keyword.replace("\'", "").replace("--", "")\n    sql = "SELECT id, username FROM users WHERE username LIKE \'%" + keyword + "%\'"',
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SQLI_03',
                cwe='CWE-89',
                category='sql_injection',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B608',
                line_hint=37,
                description="""排序字段来自外部且直接拼接，无法用参数化占位符覆盖。""",
                source_check='present:ORDER BY " \\+ order_by',
                fix_find="""    cur.execute("SELECT id, total FROM orders ORDER BY " + order_by)""",
                fix_replace="""    column = order_by if order_by in SORTABLE_COLUMNS else "id"
    cur.execute("SELECT id, total FROM orders ORDER BY " + column)""",
                flawed_fix_replace="""    order_by = order_by.replace(";", "").replace("--", "")
    cur.execute("SELECT id, total FROM orders ORDER BY " + order_by)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SQLI_04',
                cwe='CWE-89',
                category='sql_injection',
                severity='MEDIUM',
                subtlety=2,
                channel='semantic',
                detector='SEM_SQL_FORMAT',
                line_hint=43,
                description="""DELETE 语句用 str.format 拼接，删除接口同样可被注入。""",
                source_check='present:execute\\(\\s*"DELETE[^"]*"\\.format\\(',
                fix_find="""    cur.execute("DELETE FROM users WHERE id = {}".format(user_id))""",
                fix_replace="""    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))""",
                flawed_fix_replace="""    cur.execute("DELETE FROM users WHERE id = {}".format(str(user_id).strip()))""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    return []


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging
import sqlite3

logger = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
SORTABLE_COLUMNS = ("id", "total", "created_at")


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def find_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    logger.info("looked up user %s", username)
    return row


def search_users(conn, keyword, page=1):
    cur = conn.cursor()
    page = max(1, int(page))
    offset = (page - 1) * DEFAULT_PAGE_SIZE
    sql = "SELECT id, username FROM users WHERE username LIKE ?"
    params = ["%" + keyword + "%"]
    sql += " LIMIT %d OFFSET %d" % (DEFAULT_PAGE_SIZE, offset)
    cur.execute(sql)
    return cur.fetchall()


def list_orders(conn, order_by):
    cur = conn.cursor()
    column = order_by if order_by in SORTABLE_COLUMNS else "id"
    cur.execute("SELECT id, total FROM orders ORDER BY " + column)
    return cur.fetchall()


def delete_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    logger.info("deleted user %s", user_id)
    return True


def count_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    return cur.fetchone()[0]


def close(conn):
    conn.close()""",
        notes="""拼接式 SQL 是最典型的注入；LIKE 关键字、ORDER BY 与 format 常被误认为安全。""",
    ),
    Task(
        task_id='T02',
        title="""运维脚本里的命令注入""",
        family='injection',
        difficulty='easy',
        prompt="""Implement an ops helper module that pings a host, transcodes a media file with ffmpeg, lists a directory and reports disk usage. Entry points are ping_host(host), convert_media(src, dst), list_dir(path), disk_usage(target), split_args(raw) and run_tool(tool, args). All inputs arrive from an internal web form.""",
        vulnerable_code="""import logging
import os
import shlex
import subprocess

logger = logging.getLogger(__name__)

PING_COUNT = 1
DEFAULT_TIMEOUT = 10
MEDIA_ROOT = "media"
ALLOWED_TOOLS = ("ping", "ffmpeg", "ls")


def ping_host(host):
    command = "ping -c %d " % PING_COUNT + host
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    logger.info("pinged %s with rc=%s", host, result.returncode)
    return result.stdout


def convert_media(src, dst):
    cmd = "ffmpeg -y -i %s %s" % (src, dst)
    os.system(cmd)
    logger.info("converted %s -> %s", src, dst)
    return True


def list_dir(path):
    result = subprocess.run(["ls", "-la", path], capture_output=True, text=True)
    return result.stdout


def disk_usage(target):
    result = subprocess.run(["du", "-sh", target], capture_output=True, text=True)
    return result.stdout


def split_args(raw):
    return shlex.split(raw)


def run_tool(tool, args):
    if tool not in ALLOWED_TOOLS:
        raise ValueError("unsupported tool")
    result = subprocess.run([tool] + list(args), capture_output=True, text=True)
    return result.stdout""",
        defects=(
            Defect(
                defect_id='CMDI_01',
                cwe='CWE-78',
                category='command_injection',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B602',
                line_hint=16,
                description="""shell=True 且命令由字符串拼接，主机名可注入任意命令。""",
                source_check='present:subprocess\\.run\\(command, shell=True',
                fix_find="""    result = subprocess.run(command, shell=True, capture_output=True, text=True)""",
                fix_replace="""    result = subprocess.run(
        ["ping", "-c", str(PING_COUNT), host], capture_output=True, text=True
    )""",
                flawed_fix_replace="""    host = host.replace(";", "").replace("|", "")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='CMDI_02',
                cwe='CWE-78',
                category='command_injection',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B605',
                line_hint=22,
                description="""os.system 执行 % 格式化出来的命令串，文件名可注入额外命令。""",
                source_check='present:os\\.system\\(',
                fix_find="""    cmd = "ffmpeg -y -i %s %s" % (src, dst)
    os.system(cmd)""",
                fix_replace="""    subprocess.run(["ffmpeg", "-y", "-i", src, dst], capture_output=True)""",
                flawed_fix_replace="""    cmd = "ffmpeg -y -i %s %s" % (src.replace(" ", ""), dst.replace(" ", ""))
    os.system(cmd)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='CMDI_03',
                cwe='CWE-88',
                category='argument_injection',
                severity='MEDIUM',
                subtlety=4,
                channel='bandit',
                detector='B603',
                line_hint=29,
                description="""用户路径直接作为 argv 元素传入，以 - 开头即可注入 ls 选项。""",
                source_check='present:subprocess\\.run\\(\\[\\"ls\\",\\s*\\"-la\\",\\s*path\\s*\\]',
                fix_find="""    result = subprocess.run(["ls", "-la", path], capture_output=True, text=True)""",
                fix_replace="""    result = subprocess.run(
        ["ls", "-la", "--", path], capture_output=True, text=True
    )""",
                flawed_fix_replace="""    path = path.strip()
    result = subprocess.run(["ls", "-la", path], capture_output=True, text=True)""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    return []


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging
import os
import shlex
import subprocess

logger = logging.getLogger(__name__)

PING_COUNT = 1
DEFAULT_TIMEOUT = 10
MEDIA_ROOT = "media"
ALLOWED_TOOLS = ("ping", "ffmpeg", "ls")


def ping_host(host):
    command = "ping -c %d " % PING_COUNT + host
    result = subprocess.run(
        ["ping", "-c", str(PING_COUNT), host], capture_output=True, text=True
    )
    logger.info("pinged %s with rc=%s", host, result.returncode)
    return result.stdout


def convert_media(src, dst):
    subprocess.run(["ffmpeg", "-y", "-i", src, dst], capture_output=True)
    logger.info("converted %s -> %s", src, dst)
    return True


def list_dir(path):
    result = subprocess.run(
        ["ls", "-la", "--", path], capture_output=True, text=True
    )
    return result.stdout


def disk_usage(target):
    result = subprocess.run(["du", "-sh", target], capture_output=True, text=True)
    return result.stdout


def split_args(raw):
    return shlex.split(raw)


def run_tool(tool, args):
    if tool not in ALLOWED_TOOLS:
        raise ValueError("unsupported tool")
    result = subprocess.run([tool] + list(args), capture_output=True, text=True)
    return result.stdout""",
        notes="""shell=True 拼接、os.system、以及用户参数进入 argv 造成选项注入。""",
    ),
    Task(
        task_id='T03',
        title="""模板渲染中的注入与 XSS""",
        family='injection',
        difficulty='hard',
        prompt="""Implement a small server-side rendering module for a helpdesk UI using only the standard library. It exposes cache_key(template_text), render_greeting(name), render_comment(comment), render_report(template_text, context), render_page(title, body, user) and clear_cache(). Report templates are authored by support staff.""",
        vulnerable_code=r"""import hashlib
import html
import logging
import re

logger = logging.getLogger(__name__)

TOKEN_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}")
MAX_TEMPLATE_BYTES = 64 * 1024
CACHE_TTL_SECONDS = 300
_render_cache = {}


def cache_key(template_text):
    return hashlib.md5(template_text.encode("utf-8")).hexdigest()


def render_greeting(name):
    return "<p>Hello %s</p>" % name


def render_comment(comment):
    return "<div class=comment>%s</div>" % html.escape(str(comment))


def render_report(template_text, context):
    if len(template_text.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise ValueError("template too large")
    key = cache_key(template_text)
    if key in _render_cache:
        return _render_cache[key]
    rendered = template_text.format(**context)
    _render_cache[key] = rendered
    logger.info("rendered report template %s", key)
    return rendered


def render_page(title, body, user):
    parts = [render_greeting(user), render_comment(body)]
    return "<html><head><title>%s</title></head><body>%s</body></html>" % (
        html.escape(title),
        "".join(parts),
    )


def clear_cache():
    _render_cache.clear()""",
        defects=(
            Defect(
                defect_id='TPL_01',
                cwe='CWE-79',
                category='xss',
                severity='HIGH',
                subtlety=2,
                channel='fuzz',
                detector='FUZZ_XSS_RAW',
                line_hint=19,
                description="""问候语直接 % 拼接进 HTML，用户可控名字造成反射型 XSS。""",
                source_check='present:return "<p>Hello %s</p>" % name',
                fix_find="""    return "<p>Hello %s</p>" % name""",
                fix_replace="""    return "<p>Hello %s</p>" % html.escape(str(name))""",
                flawed_fix_replace="""    return "<p>Hello %s</p>" % name.strip()""",
                fuzz_marker='FUZZ_XSS_RAW',
            ),
            Defect(
                defect_id='TPL_02',
                cwe='CWE-1336',
                category='template_injection',
                severity='HIGH',
                subtlety=4,
                channel='semantic',
                detector='SEM_SSTI',
                line_hint=32,
                description="""用户模板文本直接 str.format(**context)，可通过 {user.__class__} 遍历对象图。""",
                source_check='present:rendered = template_text\\.format\\(\\*\\*context\\)',
                fix_find="""    rendered = template_text.format(**context)""",
                fix_replace="""    if not TOKEN_RE.fullmatch(template_text.strip()):
        raise ValueError("template must be a single simple placeholder")
    rendered = TOKEN_RE.sub(
        lambda m: html.escape(str(context.get(m.group(1), ""))), template_text
    )""",
                flawed_fix_replace="""    rendered = template_text.format(**context)  # context values are escaped upstream""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='TPL_03',
                cwe='CWE-328',
                category='weak_hash',
                severity='MEDIUM',
                subtlety=2,
                channel='bandit',
                detector='B324',
                line_hint=15,
                description="""渲染缓存键用 MD5，可被构造碰撞命中他人模板的缓存条目。""",
                source_check='present:hashlib\\.md5\\(',
                fix_find="""    return hashlib.md5(template_text.encode("utf-8")).hexdigest()""",
                fix_replace="""    return hashlib.sha256(template_text.encode("utf-8")).hexdigest()""",
                flawed_fix_replace="""    return hashlib.md5(template_text.encode("utf-8") + b"-cache").hexdigest()""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    payload = "<img src=x onerror=alert(1)>"
    try:
        out = module.render_greeting(payload)
    except Exception:
        return markers
    if payload in out:
        markers.append("FUZZ_XSS_RAW")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference=r"""import hashlib
import html
import logging
import re

logger = logging.getLogger(__name__)

TOKEN_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}")
MAX_TEMPLATE_BYTES = 64 * 1024
CACHE_TTL_SECONDS = 300
_render_cache = {}


def cache_key(template_text):
    return hashlib.sha256(template_text.encode("utf-8")).hexdigest()


def render_greeting(name):
    return "<p>Hello %s</p>" % html.escape(str(name))


def render_comment(comment):
    return "<div class=comment>%s</div>" % html.escape(str(comment))


def render_report(template_text, context):
    if len(template_text.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise ValueError("template too large")
    key = cache_key(template_text)
    if key in _render_cache:
        return _render_cache[key]
    if not TOKEN_RE.fullmatch(template_text.strip()):
        raise ValueError("template must be a single simple placeholder")
    rendered = TOKEN_RE.sub(
        lambda m: html.escape(str(context.get(m.group(1), ""))), template_text
    )
    _render_cache[key] = rendered
    logger.info("rendered report template %s", key)
    return rendered


def render_page(title, body, user):
    parts = [render_greeting(user), render_comment(body)]
    return "<html><head><title>%s</title></head><body>%s</body></html>" % (
        html.escape(title),
        "".join(parts),
    )


def clear_cache():
    _render_cache.clear()""",
        notes="""输出未转义导致 XSS；把用户输入当模板 format 会做属性遍历（SSTI）；MD5 缓存键可碰撞。""",
    ),
    Task(
        task_id='T04',
        title="""文档库查询的 NoSQL 注入""",
        family='injection',
        difficulty='medium',
        prompt="""Implement an account lookup service over a Mongo-like document store. AccountService(store) provides login(username, password), find_accounts(tenant, filters), search_users(term), count(tenant) and recent(tenant, limit); build_login_query() and normalise_term() are helpers. Credentials and filters both come from HTTP JSON bodies.""",
        vulnerable_code="""import logging
import re

logger = logging.getLogger(__name__)

MAX_FILTER_KEYS = 10
ALLOWED_FILTER_KEYS = ("role", "status", "created_after")
DEFAULT_LIMIT = 25


class AccountService:
    def __init__(self, store):
        self.store = store

    def login(self, username, password):
        query = {"username": username, "password": password}
        user = self.store.find_one(query)
        logger.info("login attempt for %r", username)
        return user is not None

    def find_accounts(self, tenant, filters):
        query = {"tenant": tenant}
        query.update(filters)
        if len(query) > MAX_FILTER_KEYS:
            raise ValueError("too many filters")
        return list(self.store.find(query))

    def search_users(self, term):
        return list(self.store.find({"name": {"$regex": term}}))

    def count(self, tenant):
        return len(list(self.store.find({"tenant": tenant})))

    def recent(self, tenant, limit=DEFAULT_LIMIT):
        return list(self.store.find({"tenant": tenant}).limit(limit))


def build_login_query(username, password):
    return {"username": username, "password": password}


def normalise_term(term):
    return str(term).strip()""",
        defects=(
            Defect(
                defect_id='NOSQL_01',
                cwe='CWE-943',
                category='nosql_injection',
                severity='HIGH',
                subtlety=4,
                channel='fuzz',
                detector='FUZZ_NOSQL_OPERATOR',
                line_hint=16,
                description="""登录查询未校验凭据类型，传入 {$ne: null} 即可绕过认证。""",
                source_check='absent:isinstance\\(password,\\s*str\\)',
                fix_find="""        query = {"username": username, "password": password}""",
                fix_replace="""        if not isinstance(username, str) or not isinstance(password, str):
            raise TypeError("credentials must be strings")
        query = {"username": username, "password": password}""",
                flawed_fix_replace="""        if not isinstance(username, str):
            raise TypeError("username must be a string")
        query = {"username": username, "password": password}""",
                fuzz_marker='FUZZ_NOSQL_OPERATOR',
            ),
            Defect(
                defect_id='NOSQL_02',
                cwe='CWE-915',
                category='mass_assignment',
                severity='HIGH',
                subtlety=3,
                channel='semantic',
                detector='SEM_MASS_ASSIGN',
                line_hint=23,
                description="""客户端 filters 直接 update 进查询，可覆盖 tenant 造成越权读取。""",
                source_check='present:query\\.update\\(filters\\)',
                fix_find="""        query.update(filters)""",
                fix_replace="""        allowed = {k: filters[k] for k in ALLOWED_FILTER_KEYS if k in filters}
        query.update(allowed)""",
                flawed_fix_replace="""        query.update(filters)  # tenant is pinned above and cannot be overridden""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='NOSQL_03',
                cwe='CWE-1333',
                category='regex_injection',
                severity='MEDIUM',
                subtlety=3,
                channel='semantic',
                detector='SEM_REGEX_INJECT',
                line_hint=29,
                description="""搜索词未转义就塞进 $regex，可构造灾难性回溯或宽匹配。""",
                source_check='present:"\\$regex": term',
                fix_find="""        return list(self.store.find({"name": {"$regex": term}}))""",
                fix_replace="""        return list(self.store.find({"name": {"$regex": re.escape(str(term))}}))""",
                flawed_fix_replace="""        return list(self.store.find({"name": {"$regex": term}}))  # caller normalises the term""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


class _SpyStore:
    def __init__(self):
        self.one = []
        self.many = []

    def find_one(self, query):
        self.one.append(query)
        return None

    def find(self, query):
        self.many.append(query)
        return []


def fuzz(module):
    markers = []
    store = _SpyStore()
    try:
        module.AccountService(store).login({"$ne": None}, {"$ne": None})
    except Exception:
        pass
    for query in store.one:
        for value in query.values():
            if isinstance(value, dict) and any(str(k).startswith("$") for k in value):
                markers.append("FUZZ_NOSQL_OPERATOR")
                break
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging
import re

logger = logging.getLogger(__name__)

MAX_FILTER_KEYS = 10
ALLOWED_FILTER_KEYS = ("role", "status", "created_after")
DEFAULT_LIMIT = 25


class AccountService:
    def __init__(self, store):
        self.store = store

    def login(self, username, password):
        if not isinstance(username, str) or not isinstance(password, str):
            raise TypeError("credentials must be strings")
        query = {"username": username, "password": password}
        user = self.store.find_one(query)
        logger.info("login attempt for %r", username)
        return user is not None

    def find_accounts(self, tenant, filters):
        query = {"tenant": tenant}
        allowed = {k: filters[k] for k in ALLOWED_FILTER_KEYS if k in filters}
        query.update(allowed)
        if len(query) > MAX_FILTER_KEYS:
            raise ValueError("too many filters")
        return list(self.store.find(query))

    def search_users(self, term):
        return list(self.store.find({"name": {"$regex": re.escape(str(term))}}))

    def count(self, tenant):
        return len(list(self.store.find({"tenant": tenant})))

    def recent(self, tenant, limit=DEFAULT_LIMIT):
        return list(self.store.find({"tenant": tenant}).limit(limit))


def build_login_query(username, password):
    return {"username": username, "password": password}


def normalise_term(term):
    return str(term).strip()""",
        notes="""JSON 请求体可直接传对象，操作符注入与字段注入都不能只靠字符串过滤。""",
    ),
    Task(
        task_id='T05',
        title="""特性开关引擎的动态执行""",
        family='injection',
        difficulty='hard',
        prompt="""Implement a feature-flag rules engine. It parses flag literals with parse_flag_value(text), evaluates boolean conditions with evaluate_condition(expr, values), executes rule scripts through run_rule(script, record) and apply_script(), and exposes FlagEngine(rules) with enabled(), snapshot() plus load_rules(blob). Expressions and scripts are authored in the admin UI.""",
        vulnerable_code="""import ast
import json
import logging

logger = logging.getLogger(__name__)

DEFAULT_FLAGS = {"beta_ui": False, "new_pricing": False}
MAX_SCRIPT_LENGTH = 4096
ALLOWED_CONTEXT = ("record", "flags", "tenant")


def parse_flag_value(text):
    return eval(text)


def evaluate_condition(expr, values):
    return bool(eval(expr, {"__builtins__": {}}, dict(values)))


def run_rule(script, record):
    exec(script, {"record": record})
    return record


def describe_flags(flags):
    return json.dumps({k: bool(v) for k, v in flags.items()})


class FlagEngine:
    def __init__(self, rules):
        self.rules = list(rules)

    def enabled(self, name, record):
        flag = DEFAULT_FLAGS.get(name, False)
        for rule in self.rules:
            if rule.get("flag") != name:
                continue
            context = {"record": record, "flags": DEFAULT_FLAGS, "tenant": record.get("tenant")}
            try:
                if evaluate_condition(rule.get("when", "False"), context):
                    flag = bool(rule.get("value", True))
            except Exception:
                logger.warning("rule %s failed to evaluate", rule.get("id"))
        return flag

    def apply_script(self, script, record):
        if len(script) > MAX_SCRIPT_LENGTH:
            raise ValueError("script too large")
        return run_rule(script, record)

    def snapshot(self):
        return describe_flags(DEFAULT_FLAGS)


def load_rules(blob):
    rules = json.loads(blob)
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")
    return rules""",
        defects=(
            Defect(
                defect_id='DYN_01',
                cwe='CWE-95',
                category='code_injection',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B307',
                line_hint=13,
                description="""特性值用 eval 解析，配置即代码执行。""",
                source_check='present:return eval\\(text',
                fix_find="""    return eval(text)""",
                fix_replace="""    return ast.literal_eval(text)""",
                flawed_fix_replace="""    return eval(text, {"__builtins__": {}})  # sandboxed""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='DYN_02',
                cwe='CWE-94',
                category='code_injection',
                severity='HIGH',
                subtlety=2,
                channel='bandit',
                detector='B102',
                line_hint=21,
                description="""规则脚本被直接 exec，管理员可写入任意语句。""",
                source_check='present:exec\\(script\\b',
                fix_find="""    exec(script, {"record": record})""",
                fix_replace="""    tree = ast.parse(script, mode="exec")
    allowed = (ast.Expr, ast.Call, ast.Name, ast.Constant, ast.Load)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise ValueError("unsupported statement in rule script")
    exec(compile(tree, "<rule>", "exec"), {"__builtins__": {}}, {"record": record})""",
                flawed_fix_replace="""    if "__" in script:
        raise ValueError("dunder access is not allowed")
    exec(script, {"record": record})""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='DYN_03',
                cwe='CWE-95',
                category='code_injection',
                severity='HIGH',
                subtlety=4,
                channel='bandit',
                detector='B307',
                line_hint=17,
                description="""空 __builtins__ 不是沙箱，条件表达式仍可调用注入的任意可调用对象。""",
                source_check='present:eval\\(expr,',
                fix_find="""    return bool(eval(expr, {"__builtins__": {}}, dict(values)))""",
                fix_replace="""    tree = ast.parse(expr, mode="eval")
    if not isinstance(tree.body, ast.Compare):
        raise ValueError("only comparison expressions are allowed")
    return bool(
        eval(compile(tree, "<condition>", "eval"), {"__builtins__": {}}, dict(values))
    )""",
                flawed_fix_replace="""    if "__" in expr:
        raise ValueError("dunder access is not allowed")
    return bool(eval(expr, {"__builtins__": {}}, dict(values)))""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    return []


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import ast
import json
import logging

logger = logging.getLogger(__name__)

DEFAULT_FLAGS = {"beta_ui": False, "new_pricing": False}
MAX_SCRIPT_LENGTH = 4096
ALLOWED_CONTEXT = ("record", "flags", "tenant")


def parse_flag_value(text):
    return ast.literal_eval(text)


def evaluate_condition(expr, values):
    tree = ast.parse(expr, mode="eval")
    if not isinstance(tree.body, ast.Compare):
        raise ValueError("only comparison expressions are allowed")
    return bool(
        eval(compile(tree, "<condition>", "eval"), {"__builtins__": {}}, dict(values))
    )


def run_rule(script, record):
    tree = ast.parse(script, mode="exec")
    allowed = (ast.Expr, ast.Call, ast.Name, ast.Constant, ast.Load)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise ValueError("unsupported statement in rule script")
    exec(compile(tree, "<rule>", "exec"), {"__builtins__": {}}, {"record": record})
    return record


def describe_flags(flags):
    return json.dumps({k: bool(v) for k, v in flags.items()})


class FlagEngine:
    def __init__(self, rules):
        self.rules = list(rules)

    def enabled(self, name, record):
        flag = DEFAULT_FLAGS.get(name, False)
        for rule in self.rules:
            if rule.get("flag") != name:
                continue
            context = {"record": record, "flags": DEFAULT_FLAGS, "tenant": record.get("tenant")}
            try:
                if evaluate_condition(rule.get("when", "False"), context):
                    flag = bool(rule.get("value", True))
            except Exception:
                logger.warning("rule %s failed to evaluate", rule.get("id"))
        return flag

    def apply_script(self, script, record):
        if len(script) > MAX_SCRIPT_LENGTH:
            raise ValueError("script too large")
        return run_rule(script, record)

    def snapshot(self):
        return describe_flags(DEFAULT_FLAGS)


def load_rules(blob):
    rules = json.loads(blob)
    if not isinstance(rules, list):
        raise ValueError("rules must be a list")
    return rules""",
        notes="""eval/exec 与空 __builtins__ 的伪沙箱都可绕过，正确做法是白名单解析或 AST 校验。""",
    ),
    Task(
        task_id='T06',
        title="""报表下载接口的路径遍历""",
        family='path_traversal',
        difficulty='easy',
        prompt="""Implement a report storage helper rooted at /srv/reports with upload staging under /tmp/report-staging. It exposes read_report(name), save_upload(name, content), list_reports() and read_page(name, offset, limit) for the paged viewer. The name parameter comes straight from the HTTP query string.""",
        vulnerable_code="""import logging
import os

logger = logging.getLogger(__name__)

BASE_DIR = "/srv/reports"
STAGING_DIR = "/tmp/report-staging"
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_SUFFIXES = (".csv", ".pdf", ".txt")


def ensure_dirs():
    for path in (BASE_DIR, STAGING_DIR):
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)


def read_report(name):
    if not name:
        raise ValueError("report name is required")
    path = os.path.join(BASE_DIR, name)
    logger.info("reading report %s", path)
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def save_upload(name, content):
    if not name.endswith(ALLOWED_SUFFIXES):
        raise ValueError("unsupported report type")
    if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ValueError("upload too large")
    path = os.path.join(STAGING_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    logger.info("staged upload at %s", path)
    return path


def list_reports():
    ensure_dirs()
    entries = sorted(os.listdir(BASE_DIR))
    return [e for e in entries if e.endswith(ALLOWED_SUFFIXES)]


def read_page(name, offset=0, limit=200):
    text = read_report(name)
    rows = text.splitlines()
    start = max(0, int(offset))
    return rows[start:start + int(limit)]""",
        defects=(
            Defect(
                defect_id='PATH_01',
                cwe='CWE-22',
                category='path_traversal',
                severity='HIGH',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_PATH_ESCAPE',
                line_hint=21,
                description="""join 后未做规范化校验，../../ 与绝对路径都能逃出报表目录。""",
                source_check='present:path = os\\.path\\.join\\(BASE_DIR,\\s*name\\)',
                fix_find="""    path = os.path.join(BASE_DIR, name)
    logger.info("reading report %s", path)""",
                fix_replace="""    root = os.path.realpath(BASE_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if path != root and not path.startswith(root + os.sep):
        raise ValueError("path escapes report directory")
    logger.info("reading report %s", path)""",
                flawed_fix_replace="""    name = name.replace("..", "")
    path = os.path.join(BASE_DIR, name)
    logger.info("reading report %s", path)""",
                fuzz_marker='FUZZ_PATH_ESCAPE',
            ),
            Defect(
                defect_id='PATH_02',
                cwe='CWE-22',
                category='path_traversal',
                severity='HIGH',
                subtlety=3,
                channel='semantic',
                detector='SEM_WRITE_ESCAPE',
                line_hint=32,
                description="""上传落盘同样未校验，可写任意路径（覆盖配置文件）。""",
                source_check='present:path = os\\.path\\.join\\(STAGING_DIR,\\s*name\\)',
                fix_find="""    path = os.path.join(STAGING_DIR, name)""",
                fix_replace="""    root = os.path.realpath(STAGING_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if path != root and not path.startswith(root + os.sep):
        raise ValueError("upload path escapes staging directory")""",
                flawed_fix_replace="""    name = name.replace("..", "").lstrip("/")
    path = os.path.join(STAGING_DIR, name)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='PATH_03',
                cwe='CWE-377',
                category='insecure_temp_file',
                severity='MEDIUM',
                subtlety=2,
                channel='bandit',
                detector='B108',
                line_hint=7,
                description="""上传暂存目录写死 /tmp 且可预测，其他本地用户可预置符号链接。""",
                source_check='present:^STAGING_DIR = .*"/tmp',
                fix_find='STAGING_DIR = "/tmp/report-staging"',
                fix_replace="""STAGING_DIR = os.environ.get("AUTOSAFE_STAGING_DIR") or os.path.join(
    os.path.expanduser("~"), ".autosafe", "staging"
)""",
                flawed_fix_replace="""STAGING_DIR = os.path.join("/tmp", "report-staging")""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json
import os


class _FakeFile:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return ""

    def write(self, data):
        return len(data)


def _collect(module, fn, payloads):
    import builtins

    seen = []
    real_open = builtins.open

    def _spy(path, *args, **kwargs):
        seen.append(str(path))
        return _FakeFile()

    builtins.open = _spy
    try:
        for payload in payloads:
            try:
                fn(payload)
            except Exception:
                pass
    finally:
        builtins.open = real_open
    return seen


def _escapes(paths, root):
    base = os.path.abspath(root)
    for path in paths:
        absolute = os.path.abspath(path)
        if absolute != base and not absolute.startswith(base + os.sep):
            return True
    return False


def fuzz(module):
    markers = []
    payloads = ("../../../../etc/passwd", "/etc/passwd")
    reads = _collect(module, module.read_report, payloads)
    if _escapes(reads, getattr(module, "BASE_DIR", "/srv/reports")):
        markers.append("FUZZ_PATH_ESCAPE")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging
import os

logger = logging.getLogger(__name__)

BASE_DIR = "/srv/reports"
STAGING_DIR = os.environ.get("AUTOSAFE_STAGING_DIR") or os.path.join(
    os.path.expanduser("~"), ".autosafe", "staging"
)
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
ALLOWED_SUFFIXES = (".csv", ".pdf", ".txt")


def ensure_dirs():
    for path in (BASE_DIR, STAGING_DIR):
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)


def read_report(name):
    if not name:
        raise ValueError("report name is required")
    root = os.path.realpath(BASE_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if path != root and not path.startswith(root + os.sep):
        raise ValueError("path escapes report directory")
    logger.info("reading report %s", path)
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def save_upload(name, content):
    if not name.endswith(ALLOWED_SUFFIXES):
        raise ValueError("unsupported report type")
    if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ValueError("upload too large")
    root = os.path.realpath(STAGING_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if path != root and not path.startswith(root + os.sep):
        raise ValueError("upload path escapes staging directory")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    logger.info("staged upload at %s", path)
    return path


def list_reports():
    ensure_dirs()
    entries = sorted(os.listdir(BASE_DIR))
    return [e for e in entries if e.endswith(ALLOWED_SUFFIXES)]


def read_page(name, offset=0, limit=200):
    text = read_report(name)
    rows = text.splitlines()
    start = max(0, int(offset))
    return rows[start:start + int(limit)]""",
        notes="""os.path.join 遇到绝对路径会丢弃前缀，只过滤 '..' 不足以防护；写死 /tmp 也是问题。""",
    ),
    Task(
        task_id='T07',
        title="""归档解压的 Zip Slip""",
        family='path_traversal',
        difficulty='medium',
        prompt="""Implement an archive extraction helper for user uploads. It offers target_path(dest, name), open_archive(path), extract_zip(zf, dest), extract_tar(tf, dest) and extract(path, dest) which dispatches on the archive type. Uploaded archives are fully untrusted.""",
        vulnerable_code="""import logging
import os
import tarfile
import zipfile

logger = logging.getLogger(__name__)

MAX_MEMBERS = 4096
SUPPORTED_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")


def target_path(dest, name):
    return os.path.join(dest, name)


def open_archive(path):
    if zipfile.is_zipfile(path):
        return zipfile.ZipFile(path)
    return tarfile.open(path)


def extract_zip(zf, dest):
    if len(zf.infolist()) > MAX_MEMBERS:
        raise ValueError("archive has too many members")
    zf.extractall(dest)
    logger.info("extracted zip into %s", dest)
    return dest


def extract_tar(tf, dest):
    members = tf.getmembers()
    if len(members) > MAX_MEMBERS:
        raise ValueError("archive has too many members")
    tf.extractall(dest)
    logger.info("extracted tar into %s", dest)
    return dest


def extract(path, dest):
    archive = open_archive(path)
    try:
        if isinstance(archive, zipfile.ZipFile):
            return extract_zip(archive, dest)
        return extract_tar(archive, dest)
    finally:
        archive.close()""",
        defects=(
            Defect(
                defect_id='ZIP_01',
                cwe='CWE-22',
                category='tar_slip',
                severity='HIGH',
                subtlety=2,
                channel='bandit',
                detector='B202',
                line_hint=34,
                description="""tarfile.extractall 直接解压不可信成员，可写到目标目录之外。""",
                source_check='present:tf\\.extractall\\(dest\\)',
                fix_find="""    tf.extractall(dest)""",
                fix_replace="""    for member in members:
        if member.issym() or member.islnk():
            raise ValueError("links are not allowed in archives")
        target_path(dest, member.name)
    tf.extractall(dest, filter="data")""",
                flawed_fix_replace="""    if any(".." in m.name for m in members):
        raise ValueError("unsafe archive")
    tf.extractall(dest)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='ZIP_02',
                cwe='CWE-22',
                category='zip_slip',
                severity='HIGH',
                subtlety=2,
                channel='bandit',
                detector='B202',
                line_hint=25,
                description="""zipfile.extractall 未按成员校验路径，../ 与绝对路径都能逃逸。""",
                source_check='present:zf\\.extractall\\(dest\\)',
                fix_find="""    zf.extractall(dest)""",
                fix_replace="""    root = os.path.realpath(dest)
    safe = []
    for info in zf.infolist():
        candidate = os.path.realpath(os.path.join(root, info.filename))
        if candidate != root and not candidate.startswith(root + os.sep):
            raise ValueError("zip member escapes destination")
        safe.append(info)
    zf.extractall(dest, members=safe)""",
                flawed_fix_replace="""    for info in zf.infolist():
        if ".." in info.filename:
            raise ValueError("unsafe member")
    zf.extractall(dest)""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    return []


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging
import os
import tarfile
import zipfile

logger = logging.getLogger(__name__)

MAX_MEMBERS = 4096
SUPPORTED_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")


def target_path(dest, name):
    return os.path.join(dest, name)


def open_archive(path):
    if zipfile.is_zipfile(path):
        return zipfile.ZipFile(path)
    return tarfile.open(path)


def extract_zip(zf, dest):
    if len(zf.infolist()) > MAX_MEMBERS:
        raise ValueError("archive has too many members")
    root = os.path.realpath(dest)
    safe = []
    for info in zf.infolist():
        candidate = os.path.realpath(os.path.join(root, info.filename))
        if candidate != root and not candidate.startswith(root + os.sep):
            raise ValueError("zip member escapes destination")
        safe.append(info)
    zf.extractall(dest, members=safe)
    logger.info("extracted zip into %s", dest)
    return dest


def extract_tar(tf, dest):
    members = tf.getmembers()
    if len(members) > MAX_MEMBERS:
        raise ValueError("archive has too many members")
    for member in members:
        if member.issym() or member.islnk():
            raise ValueError("links are not allowed in archives")
        target_path(dest, member.name)
    tf.extractall(dest, filter="data")
    logger.info("extracted tar into %s", dest)
    return dest


def extract(path, dest):
    archive = open_archive(path)
    try:
        if isinstance(archive, zipfile.ZipFile):
            return extract_zip(archive, dest)
        return extract_tar(archive, dest)
    finally:
        archive.close()""",
        notes="""extractall 默认不校验成员路径（Zip Slip / tar 逃逸），必须逐成员做 realpath 校验。""",
    ),
    Task(
        task_id='T08',
        title="""静态资源服务的遍历防护""",
        family='path_traversal',
        difficulty='hard',
        prompt="""Implement a static asset helper rooted at ./static with a disk cache under /tmp/asset-cache. Provide resolve_asset(url_path), read_asset(url_path), cache_asset(name, data), content_type(), etag_for() and serve(url_path) returning a response dict. The URL path is attacker controlled and may be percent-encoded.""",
        vulnerable_code="""import hashlib
import logging
import mimetypes
import os
from urllib.parse import unquote

logger = logging.getLogger(__name__)

STATIC_ROOT = "static"
CACHE_DIR = "/tmp/asset-cache"
MAX_CACHE_BYTES = 4 * 1024 * 1024
FALLBACK_TYPE = "application/octet-stream"


def resolve_asset(url_path):
    clean = unquote(url_path).lstrip("/")
    if clean.startswith(".."):
        clean = clean.replace("..", "")
    return os.path.join(STATIC_ROOT, clean)


def content_type(url_path):
    guessed, _ = mimetypes.guess_type(url_path)
    return guessed or FALLBACK_TYPE


def etag_for(data):
    return hashlib.sha1(data).hexdigest()[:16]


def read_asset(url_path):
    path = resolve_asset(url_path)
    logger.info("serving asset %s", path)
    with open(path, "rb") as fh:
        return fh.read()


def cache_asset(name, data):
    if len(data) > MAX_CACHE_BYTES:
        raise ValueError("asset too large to cache")
    path = os.path.join(CACHE_DIR, name)
    with open(path, "wb") as fh:
        fh.write(data)
    logger.info("cached asset at %s", path)
    return path


def serve(url_path):
    data = read_asset(url_path)
    return {
        "path": url_path,
        "content_type": content_type(url_path),
        "etag": etag_for(data),
        "size": len(data),
    }""",
        defects=(
            Defect(
                defect_id='STATIC_01',
                cwe='CWE-22',
                category='path_traversal',
                severity='HIGH',
                subtlety=4,
                channel='fuzz',
                detector='FUZZ_STATIC_ESCAPE',
                line_hint=18,
                description="""replace('..','') 是一次性字符串替换，'....//' 绕过并逃出 static 根。""",
                source_check='present:clean = clean\\.replace\\(\\"\\.\\.\\", \\"\\"\\)',
                fix_find="""        clean = clean.replace("..", "")""",
                fix_replace="""        root = os.path.realpath(STATIC_ROOT)
        candidate = os.path.realpath(os.path.join(root, clean))
        if candidate != root and not candidate.startswith(root + os.sep):
            raise ValueError("asset path escapes static root")
        return candidate""",
                flawed_fix_replace="""        clean = clean.replace("..", "").replace("%2e", "")""",
                fuzz_marker='FUZZ_STATIC_ESCAPE',
            ),
            Defect(
                defect_id='STATIC_02',
                cwe='CWE-22',
                category='path_traversal',
                severity='HIGH',
                subtlety=3,
                channel='semantic',
                detector='SEM_CACHE_ESCAPE',
                line_hint=41,
                description="""缓存写盘直接 join 未校验，name 可含 ../ 覆盖任意文件。""",
                source_check='present:path = os\\.path\\.join\\(CACHE_DIR,\\s*name\\)',
                fix_find="""    path = os.path.join(CACHE_DIR, name)""",
                fix_replace="""    root = os.path.realpath(CACHE_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if path != root and not path.startswith(root + os.sep):
        raise ValueError("cache path escapes cache directory")""",
                flawed_fix_replace="""    if ".." in name:
        raise ValueError("invalid cache name")
    path = os.path.join(CACHE_DIR, name)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='STATIC_03',
                cwe='CWE-377',
                category='insecure_temp_file',
                severity='MEDIUM',
                subtlety=2,
                channel='bandit',
                detector='B108',
                line_hint=10,
                description="""缓存目录写死 /tmp/asset-cache，可预测且可被其他用户预置。""",
                source_check='present:^CACHE_DIR = .*"/tmp',
                fix_find='CACHE_DIR = "/tmp/asset-cache"',
                fix_replace="""CACHE_DIR = os.environ.get("AUTOSAFE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "autosafe-assets"
)""",
                flawed_fix_replace="""CACHE_DIR = os.path.join("/tmp", "asset-cache")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='STATIC_04',
                cwe='CWE-328',
                category='weak_hash',
                severity='MEDIUM',
                subtlety=2,
                channel='bandit',
                detector='B324',
                line_hint=28,
                description="""ETag 用 SHA1 做内容指纹，可被构造碰撞冒充缓存条目。""",
                source_check='present:hashlib\\.sha1\\(',
                fix_find="""    return hashlib.sha1(data).hexdigest()[:16]""",
                fix_replace="""    return hashlib.sha256(data).hexdigest()[:32]""",
                flawed_fix_replace="""    return hashlib.sha1(data + b"-etag").hexdigest()[:16]""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json
import os


class _FakeFile:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return b""


def fuzz(module):
    import builtins

    markers = []
    seen = []
    real_open = builtins.open

    def _spy(path, *args, **kwargs):
        seen.append(str(path))
        return _FakeFile()

    builtins.open = _spy
    try:
        for payload in ("../app.cfg", "%2e%2e/app.cfg", "....//app.cfg", "/etc/passwd"):
            try:
                module.read_asset(payload)
            except Exception:
                pass
    finally:
        builtins.open = real_open

    root = os.path.abspath(getattr(module, "STATIC_ROOT", "static"))
    for path in seen:
        absolute = os.path.abspath(path)
        if absolute != root and not absolute.startswith(root + os.sep):
            markers.append("FUZZ_STATIC_ESCAPE")
            break
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import hashlib
import logging
import mimetypes
import os
from urllib.parse import unquote

logger = logging.getLogger(__name__)

STATIC_ROOT = "static"
CACHE_DIR = os.environ.get("AUTOSAFE_CACHE_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache", "autosafe-assets"
)
MAX_CACHE_BYTES = 4 * 1024 * 1024
FALLBACK_TYPE = "application/octet-stream"


def resolve_asset(url_path):
    clean = unquote(url_path).lstrip("/")
    if clean.startswith(".."):
        root = os.path.realpath(STATIC_ROOT)
        candidate = os.path.realpath(os.path.join(root, clean))
        if candidate != root and not candidate.startswith(root + os.sep):
            raise ValueError("asset path escapes static root")
        return candidate
    return os.path.join(STATIC_ROOT, clean)


def content_type(url_path):
    guessed, _ = mimetypes.guess_type(url_path)
    return guessed or FALLBACK_TYPE


def etag_for(data):
    return hashlib.sha256(data).hexdigest()[:32]


def read_asset(url_path):
    path = resolve_asset(url_path)
    logger.info("serving asset %s", path)
    with open(path, "rb") as fh:
        return fh.read()


def cache_asset(name, data):
    if len(data) > MAX_CACHE_BYTES:
        raise ValueError("asset too large to cache")
    root = os.path.realpath(CACHE_DIR)
    path = os.path.realpath(os.path.join(root, name))
    if path != root and not path.startswith(root + os.sep):
        raise ValueError("cache path escapes cache directory")
    with open(path, "wb") as fh:
        fh.write(data)
    logger.info("cached asset at %s", path)
    return path


def serve(url_path):
    data = read_asset(url_path)
    return {
        "path": url_path,
        "content_type": content_type(url_path),
        "etag": etag_for(data),
        "size": len(data),
    }""",
        notes="""先解码再替换、replace('..','') 会产生 '....//' 绕过，必须 realpath+commonpath 校验。""",
    ),
    Task(
        task_id='T09',
        title="""会话令牌的 pickle 反序列化""",
        family='deserialization',
        difficulty='medium',
        prompt="""Implement a cookie session codec. load_session(token) decodes a base64 token into a dict, save_session(data) encodes it back with a default TTL, load_prefs(blob) reads stored preferences, merge_prefs(prefs) applies defaults, and describe_session(token) summarises a session. Tokens arrive from the browser cookie header.""",
        vulnerable_code="""import base64
import json
import logging
import pickle

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 3600
MAX_COOKIE_BYTES = 8192
DEFAULT_PREFS = {"theme": "light", "digest": False, "page_size": 20}


def load_session(token):
    if not token:
        raise ValueError("missing session token")
    if len(token) > MAX_COOKIE_BYTES:
        raise ValueError("session token too large")
    raw = base64.b64decode(token)
    return pickle.loads(raw)


def save_session(data):
    payload = dict(data)
    payload.setdefault("ttl", SESSION_TTL_SECONDS)
    return base64.b64encode(pickle.dumps(payload)).decode("ascii")


def load_prefs(blob):
    return pickle.loads(blob)


def merge_prefs(prefs):
    merged = dict(DEFAULT_PREFS)
    merged.update(prefs or {})
    return merged


def describe_session(token):
    data = load_session(token)
    return {
        "user": data.get("user"),
        "ttl": data.get("ttl", SESSION_TTL_SECONDS),
        "keys": sorted(data.keys()),
    }""",
        defects=(
            Defect(
                defect_id='PICKLE_01',
                cwe='CWE-502',
                category='deserialization',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B301',
                line_hint=19,
                description="""pickle.loads 处理浏览器可控令牌，__reduce__ 即可执行命令。""",
                source_check='present:return pickle\\.loads\\(raw\\)',
                fix_find="""    return pickle.loads(raw)""",
                fix_replace="""    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("session payload must be an object")
    return data""",
                flawed_fix_replace="""    if b"__reduce__" in raw:
        raise ValueError("suspicious payload")
    return pickle.loads(raw)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='PICKLE_02',
                cwe='CWE-502',
                category='deserialization',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B301',
                line_hint=29,
                description="""偏好读取同样直接 loads，且无大小/类型约束。""",
                source_check='present:return pickle\\.loads\\(blob\\)',
                fix_find="""    return pickle.loads(blob)""",
                fix_replace="""    data = json.loads(blob)
    if not isinstance(data, dict):
        raise ValueError("preferences must be an object")
    return data""",
                flawed_fix_replace="""    if len(blob) > 4096:
        raise ValueError("payload too large")
    return pickle.loads(blob)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='PICKLE_03',
                cwe='CWE-502',
                category='deserialization',
                severity='MEDIUM',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_PICKLE_FORMAT',
                line_hint=25,
                description="""save_session 仍用 pickle 序列化，往返接口把不安全编码固化下来。""",
                source_check='present:base64\\.\\w*b64encode\\(pickle\\.dumps',
                fix_find="""    return base64.b64encode(pickle.dumps(payload)).decode("ascii")""",
                fix_replace="""    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")""",
                flawed_fix_replace="""    return base64.urlsafe_b64encode(pickle.dumps(payload)).decode("ascii")""",
                fuzz_marker='FUZZ_PICKLE_FORMAT',
            ),
        ),
        fuzz_harness=r"""import base64
import json
import pickle


def fuzz(module):
    markers = []
    hits = []

    class _Evil:
        def __reduce__(self):
            return (hits.append, ("pwn",))

    try:
        module.load_prefs(pickle.dumps(_Evil()))
    except Exception:
        pass
    if hits:
        markers.append("FUZZ_PICKLE_RCE")

    try:
        blob = module.save_session({"user": "a"})
        raw = base64.b64decode(blob)
    except Exception:
        raw = b""
    if raw[:1] == b"\x80":
        markers.append("FUZZ_PICKLE_FORMAT")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import base64
import json
import logging
import pickle

logger = logging.getLogger(__name__)

SESSION_TTL_SECONDS = 3600
MAX_COOKIE_BYTES = 8192
DEFAULT_PREFS = {"theme": "light", "digest": False, "page_size": 20}


def load_session(token):
    if not token:
        raise ValueError("missing session token")
    if len(token) > MAX_COOKIE_BYTES:
        raise ValueError("session token too large")
    raw = base64.b64decode(token)
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("session payload must be an object")
    return data


def save_session(data):
    payload = dict(data)
    payload.setdefault("ttl", SESSION_TTL_SECONDS)
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def load_prefs(blob):
    data = json.loads(blob)
    if not isinstance(data, dict):
        raise ValueError("preferences must be an object")
    return data


def merge_prefs(prefs):
    merged = dict(DEFAULT_PREFS)
    merged.update(prefs or {})
    return merged


def describe_session(token):
    data = load_session(token)
    return {
        "user": data.get("user"),
        "ttl": data.get("ttl", SESSION_TTL_SECONDS),
        "keys": sorted(data.keys()),
    }""",
        notes="""pickle 反序列化等价于任意代码执行，必须换成 JSON 或带白名单的 Unpickler。""",
    ),
    Task(
        task_id='T10',
        title="""配置加载的 YAML 反序列化""",
        family='deserialization',
        difficulty='medium',
        prompt="""Implement a configuration loader for a rules service using only the standard library. load_config(text) parses key=value text and validates known keys, load_rules(path, reader) reads a rules file through an injected reader, load_cache(blob)/dump_cache(payload) round-trip a marshal snapshot, and describe_config(path) summarises a file. Config files are uploaded by operators.""",
        vulnerable_code="""import json
import logging
import marshal
import os

logger = logging.getLogger(__name__)

ALLOWED_KEYS = {"name", "version", "enabled", "threshold", "routes"}
CACHE_MAGIC = b"ACFG1"
MAX_CONFIG_BYTES = 256 * 1024


def parse_kv_config(text):
    config = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, raw = line.partition("=")
        config[key.strip()] = eval(raw.strip())
    return config


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("config must be a mapping")
    unknown = set(config) - ALLOWED_KEYS
    if unknown:
        logger.warning("ignoring unknown config keys: %s", sorted(unknown))
    return {k: config[k] for k in config if k in ALLOWED_KEYS}


def load_config(text):
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ValueError("config file is too large")
    config = parse_kv_config(text)
    return validate_config(config)


def load_rules(path, reader):
    with reader(path) as fh:
        rules = eval(fh.read(), {"__builtins__": {}})
    if not isinstance(rules, list):
        raise ValueError("rules file must contain a list")
    return rules


def load_cache(blob):
    if not blob.startswith(CACHE_MAGIC):
        raise ValueError("unknown cache format")
    return marshal.loads(blob[len(CACHE_MAGIC):])


def dump_cache(payload):
    return CACHE_MAGIC + marshal.dumps(payload)


def describe_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        config = load_config(fh.read())
    return {"keys": sorted(config), "size": os.path.getsize(path)}""",
        defects=(
            Defect(
                defect_id='YAML_01',
                cwe='CWE-502',
                category='deserialization',
                severity='HIGH',
                subtlety=1,
                channel='fuzz',
                detector='FUZZ_YAML_RCE',
                line_hint=20,
                description="""配置值用 eval 解析，配置文件即代码执行入口。""",
                source_check='present:config\\[key\\.strip\\(\\)\\] = eval\\(',
                fix_find="""        config[key.strip()] = eval(raw.strip())""",
                fix_replace="""        config[key.strip()] = json.loads(raw.strip())""",
                flawed_fix_replace="""        config[key.strip()] = eval(raw.strip(), {"__builtins__": {}})""",
                fuzz_marker='FUZZ_YAML_RCE',
            ),
            Defect(
                defect_id='YAML_02',
                cwe='CWE-502',
                category='deserialization',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B307',
                line_hint=42,
                description="""规则文件被 eval 直接求值，等于把上传文件当代码执行。""",
                source_check='present:rules = eval\\(',
                fix_find="""        rules = eval(fh.read(), {"__builtins__": {}})""",
                fix_replace="""        rules = json.loads(fh.read())""",
                flawed_fix_replace="""        rules = eval(fh.read(), {"__builtins__": {}, "__name__": "__main__"})""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='YAML_03',
                cwe='CWE-502',
                category='deserialization',
                severity='MEDIUM',
                subtlety=3,
                channel='bandit',
                detector='B302',
                line_hint=51,
                description="""marshal 只适合可信字节码缓存，从外部 blob 恢复可伪造对象图。""",
                source_check='present:marshal\\.loads\\(blob',
                fix_find="""    return marshal.loads(blob[len(CACHE_MAGIC):])""",
                fix_replace="""    data = json.loads(blob[len(CACHE_MAGIC):].decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("cache must be an object")
    return data""",
                flawed_fix_replace="""    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("cache must be bytes")
    return marshal.loads(blob[len(CACHE_MAGIC):])""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    payload = "name=__import__('os').getcwd()"
    try:
        module.load_config(payload)
    except Exception:
        pass
    else:
        markers.append("FUZZ_YAML_RCE")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import json
import logging
import marshal
import os

logger = logging.getLogger(__name__)

ALLOWED_KEYS = {"name", "version", "enabled", "threshold", "routes"}
CACHE_MAGIC = b"ACFG1"
MAX_CONFIG_BYTES = 256 * 1024


def parse_kv_config(text):
    config = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, raw = line.partition("=")
        config[key.strip()] = json.loads(raw.strip())
    return config


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("config must be a mapping")
    unknown = set(config) - ALLOWED_KEYS
    if unknown:
        logger.warning("ignoring unknown config keys: %s", sorted(unknown))
    return {k: config[k] for k in config if k in ALLOWED_KEYS}


def load_config(text):
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ValueError("config file is too large")
    config = parse_kv_config(text)
    return validate_config(config)


def load_rules(path, reader):
    with reader(path) as fh:
        rules = json.loads(fh.read())
    if not isinstance(rules, list):
        raise ValueError("rules file must contain a list")
    return rules


def load_cache(blob):
    if not blob.startswith(CACHE_MAGIC):
        raise ValueError("unknown cache format")
    data = json.loads(blob[len(CACHE_MAGIC):].decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("cache must be an object")
    return data


def dump_cache(payload):
    return CACHE_MAGIC + marshal.dumps(payload)


def describe_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        config = load_config(fh.read())
    return {"keys": sorted(config), "size": os.path.getsize(path)}""",
        notes="""配置文件用 eval 解析等价于任意代码执行；marshal 只适合可信字节码，不能读外部 blob。""",
    ),
    Task(
        task_id='T11',
        title="""RSS 解析器的 XML 外部实体""",
        family='deserialization',
        difficulty='hard',
        prompt="""Implement a feed reader module. parse_feed(data) parses an XML document from bytes, parse_config(stream) parses through an injected SAX stream, parse_numbers(text) parses a comma separated list, and feed_items(data)/summarise_feed(data) extract Atom entries. Feed URLs are supplied by end users.""",
        vulnerable_code="""import logging
import xml.etree.ElementTree as ET
from xml.sax import make_parser

logger = logging.getLogger(__name__)

MAX_FEED_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 500
NS = {"atom": "http://www.w3.org/2005/Atom"}


def _safe_xml_parser():
    parser = ET.XMLParser()
    return parser


def parse_feed(data):
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("feed is too large")
    return ET.fromstring(data)


def parse_config(stream):
    parser = make_parser()
    parser.parse(stream)
    return parser


def parse_numbers(text):
    return [int(part) for part in text.split(",")]


def feed_items(data):
    root = parse_feed(data)
    items = []
    for entry in root.findall("atom:entry", NS)[:MAX_ITEMS]:
        title = entry.findtext("atom:title", default="", namespaces=NS)
        link = entry.find("atom:link", NS)
        items.append({"title": title.strip(), "href": link.get("href") if link is not None else ""})
    return items


def summarise_feed(data):
    items = feed_items(data)
    logger.info("parsed feed with %d entries", len(items))
    return {"count": len(items), "titles": [i["title"] for i in items][:20]}""",
        defects=(
            Defect(
                defect_id='XXE_01',
                cwe='CWE-611',
                category='xxe',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B314',
                line_hint=20,
                description="""ET.fromstring 使用默认解析器，DOCTYPE 与外部实体未被禁用（XXE）。""",
                source_check='present:return ET\\.fromstring\\(data\\)',
                fix_find="""    return ET.fromstring(data)""",
                fix_replace="""    return ET.fromstring(data, parser=_safe_xml_parser())""",
                flawed_fix_replace="""    if b"<!DOCTYPE" in data:
        raise ValueError("DOCTYPE is not allowed")
    return ET.fromstring(data)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='XXE_02',
                cwe='CWE-611',
                category='xxe',
                severity='HIGH',
                subtlety=4,
                channel='bandit',
                detector='B317',
                line_hint=24,
                description="""make_parser 使用默认 SAX 特性，外部实体与 DTD 都未关闭。""",
                source_check='absent:external-general-entities',
                fix_find="""    parser = make_parser()
    parser.parse(stream)""",
                fix_replace="""    parser = make_parser()
    parser.setFeature(
        "http://xml.org/sax/features/external-general-entities", False
    )
    parser.setFeature(
        "http://xml.org/sax/features/external-parameter-entities", False
    )
    parser.parse(stream)""",
                flawed_fix_replace="""    parser = make_parser()
    parser.setFeature("http://xml.org/sax/features/namespaces", True)
    parser.parse(stream)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='XXE_03',
                cwe='CWE-776',
                category='entity_expansion',
                severity='MEDIUM',
                subtlety=2,
                channel='semantic',
                detector='SEM_UNBOUNDED_SPLIT',
                line_hint=30,
                description="""parse_numbers 无数量上限，超大输入导致内存与 CPU 放大。""",
                source_check='present:int\\(part\\) for part in text\\.split\\(","\\)',
                fix_find="""    return [int(part) for part in text.split(",")]""",
                fix_replace="""    parts = text.split(",")
    if len(parts) > 10000:
        raise ValueError("too many values")
    return [int(part) for part in parts]""",
                flawed_fix_replace="""    return [int(part) for part in text.split(",")[:10000]] if len(text) < 1000 else []""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    payload = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<r>&x;</r>"
    )
    try:
        module.parse_feed(payload)
    except Exception:
        pass
    else:
        markers.append("FUZZ_XXE")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging
import xml.etree.ElementTree as ET
from xml.sax import make_parser

logger = logging.getLogger(__name__)

MAX_FEED_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 500
NS = {"atom": "http://www.w3.org/2005/Atom"}


def _safe_xml_parser():
    parser = ET.XMLParser()
    return parser


def parse_feed(data):
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("feed is too large")
    return ET.fromstring(data, parser=_safe_xml_parser())


def parse_config(stream):
    parser = make_parser()
    parser.setFeature(
        "http://xml.org/sax/features/external-general-entities", False
    )
    parser.setFeature(
        "http://xml.org/sax/features/external-parameter-entities", False
    )
    parser.parse(stream)
    return parser


def parse_numbers(text):
    parts = text.split(",")
    if len(parts) > 10000:
        raise ValueError("too many values")
    return [int(part) for part in parts]


def feed_items(data):
    root = parse_feed(data)
    items = []
    for entry in root.findall("atom:entry", NS)[:MAX_ITEMS]:
        title = entry.findtext("atom:title", default="", namespaces=NS)
        link = entry.find("atom:link", NS)
        items.append({"title": title.strip(), "href": link.get("href") if link is not None else ""})
    return items


def summarise_feed(data):
    items = feed_items(data)
    logger.info("parsed feed with %d entries", len(items))
    return {"count": len(items), "titles": [i["title"] for i in items][:20]}""",
        notes="""ElementTree 与 SAX 默认都可能解析外部实体；还需限制输入规模防实体膨胀。""",
    ),
    Task(
        task_id='T12',
        title="""用户口令哈希实现""",
        family='crypto',
        difficulty='medium',
        prompt="""Implement the password hashing helpers for an account service. hash_password(password) must produce the stored digest, hash_password_salted(password, salt) a salted variant, verify_password(password, stored_hash) must compare safely, upgrade_password(password) the current format, and needs_rehash(stored_hash) decides whether to migrate a record.""",
        vulnerable_code="""import hashlib
import hmac
import logging
import secrets

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 8
PEPPER = "static-pepper-value"
ITERATIONS = 1000
MAX_PASSWORD_LENGTH = 256


def validate_password(password):
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("password is too short")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError("password is too long")
    return True


def hash_password(password):
    validate_password(password)
    digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    return digest


def hash_password_salted(password, salt):
    validate_password(password)
    return hashlib.sha1((salt + password).encode("utf-8")).hexdigest()


def verify_password(password, stored_hash):
    candidate = hash_password(password)
    return candidate == stored_hash


def needs_rehash(stored_hash):
    return len(stored_hash) < 60


def upgrade_password(password):
    validate_password(password)
    salt = secrets.token_hex(16)
    logger.info("upgrading password hash")
    return hash_password_salted(password, salt)


def describe_policy():
    return {
        "min_length": MIN_PASSWORD_LENGTH,
        "iterations": ITERATIONS,
        "algorithm": "md5",
    }""",
        defects=(
            Defect(
                defect_id='CRYPTO_01',
                cwe='CWE-328',
                category='weak_hash',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B324',
                line_hint=26,
                description="""口令直接用 MD5 无盐摘要存储，彩虹表可即时还原。""",
                source_check='present:hashlib\\.md5\\(',
                fix_find="""    digest = hashlib.md5(password.encode("utf-8")).hexdigest()""",
                fix_replace="""    salt = hashlib.sha256(PEPPER.encode("utf-8")).digest()[:16]
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 210000
    )
    return "pbkdf2_sha256$210000$" + digest.hex()""",
                flawed_fix_replace="""    digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    return "md5$" + digest""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='CRYPTO_02',
                cwe='CWE-916',
                category='weak_kdf',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B324',
                line_hint=32,
                description="""加盐变体仍用单轮 SHA1，GPU 每秒可尝试数十亿次。""",
                source_check='present:hashlib\\.sha1\\(',
                fix_find="""    return hashlib.sha1((salt + password).encode("utf-8")).hexdigest()""",
                fix_replace="""    salt_bytes = (salt + PEPPER).encode("utf-8")
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, 210000
    )
    return "pbkdf2_sha256$210000$" + digest.hex()""",
                flawed_fix_replace="""    return hashlib.sha1((salt + password + PEPPER).encode("utf-8")).hexdigest()""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='CRYPTO_03',
                cwe='CWE-208',
                category='timing_side_channel',
                severity='MEDIUM',
                subtlety=3,
                channel='semantic',
                detector='SEM_TIMING_COMPARE',
                line_hint=37,
                description="""口令比较用 == 短路，可逐字节测出摘要（时序侧信道）。""",
                source_check='present:return candidate == stored_hash',
                fix_find="""    return candidate == stored_hash""",
                fix_replace="""    return hmac.compare_digest(candidate, stored_hash)""",
                flawed_fix_replace="""    # digests have a fixed length, so a plain comparison is fine
    return candidate == stored_hash""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    try:
        first = module.hash_password("correct horse battery")
    except Exception:
        return markers
    if len(first) == 32:
        markers.append("FUZZ_WEAK_DIGEST")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import hashlib
import hmac
import logging
import secrets

logger = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 8
PEPPER = "static-pepper-value"
ITERATIONS = 1000
MAX_PASSWORD_LENGTH = 256


def validate_password(password):
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError("password is too short")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError("password is too long")
    return True


def hash_password(password):
    validate_password(password)
    salt = hashlib.sha256(PEPPER.encode("utf-8")).digest()[:16]
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 210000
    )
    return "pbkdf2_sha256$210000$" + digest.hex()
    return digest


def hash_password_salted(password, salt):
    validate_password(password)
    salt_bytes = (salt + PEPPER).encode("utf-8")
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, 210000
    )
    return "pbkdf2_sha256$210000$" + digest.hex()


def verify_password(password, stored_hash):
    candidate = hash_password(password)
    return hmac.compare_digest(candidate, stored_hash)


def needs_rehash(stored_hash):
    return len(stored_hash) < 60


def upgrade_password(password):
    validate_password(password)
    salt = secrets.token_hex(16)
    logger.info("upgrading password hash")
    return hash_password_salted(password, salt)


def describe_policy():
    return {
        "min_length": MIN_PASSWORD_LENGTH,
        "iterations": ITERATIONS,
        "algorithm": "md5",
    }""",
        notes="""MD5/SHA1 无盐快哈希不能存口令；比较必须用 hmac.compare_digest 防时序侧信道。""",
    ),
    Task(
        task_id='T13',
        title="""HTTPS 抓取器的证书校验""",
        family='crypto',
        difficulty='medium',
        prompt="""Implement an HTTP fetching helper. build_context() returns the TLS context used for outbound calls, fetch(url) downloads a bounded body over https only, fetch_json(url) parses JSON, check_host(host, port) performs a TLS handshake and returns the peer certificate, and describe_target(url) reports the request parameters.""",
        vulnerable_code="""import json
import logging
import socket
import ssl
import urllib.request

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
USER_AGENT = "autosafe-fetcher/1.0"
MAX_BODY_BYTES = 512 * 1024
ALLOWED_SCHEMES = ("https",)


def build_context():
    context = ssl._create_unverified_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def fetch(url):
    if not url.startswith(ALLOWED_SCHEMES):
        raise ValueError("only https endpoints are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
        body = response.read(MAX_BODY_BYTES)
        return {"status": response.status, "body": body}


def fetch_json(url):
    payload = fetch(url)
    try:
        return json.loads(payload["body"])
    except ValueError:
        logger.warning("response was not json: %s", url)
        return {}


def check_host(host, port=443):
    raw = socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT)
    wrapped = build_context().wrap_socket(raw, server_hostname=host)
    cert = wrapped.getpeercert()
    wrapped.close()
    logger.info("handshake with %s completed", host)
    return cert


def describe_target(url):
    return {"url": url, "timeout": DEFAULT_TIMEOUT, "user_agent": USER_AGENT}""",
        defects=(
            Defect(
                defect_id='TLS_01',
                cwe='CWE-295',
                category='improper_cert_validation',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B323',
                line_hint=16,
                description="""使用 ssl._create_unverified_context()，证书链完全不校验。""",
                source_check='present:ssl\\._create_unverified_context\\(\\)',
                fix_find="""    context = ssl._create_unverified_context()""",
                fix_replace="""    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED""",
                flawed_fix_replace="""    context = ssl._create_unverified_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='TLS_02',
                cwe='CWE-295',
                category='improper_cert_validation',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B310',
                line_hint=25,
                description="""握手成功后不校验主机名与有效期，返回值被上层当作已验证身份。""",
                source_check='absent:context=build_context',
                fix_find="""    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:""",
                fix_replace="""    with urllib.request.urlopen(
        request, timeout=DEFAULT_TIMEOUT, context=build_context()
    ) as response:""",
                flawed_fix_replace="""    opener = urllib.request.build_opener()
    with opener.open(request, timeout=DEFAULT_TIMEOUT) as response:""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    try:
        context = module.build_context()
    except Exception:
        return markers
    if getattr(context, "verify_mode", None) == 0:
        markers.append("FUZZ_TLS_NO_VERIFY")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import json
import logging
import socket
import ssl
import urllib.request

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
USER_AGENT = "autosafe-fetcher/1.0"
MAX_BODY_BYTES = 512 * 1024
ALLOWED_SCHEMES = ("https",)


def build_context():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def fetch(url):
    if not url.startswith(ALLOWED_SCHEMES):
        raise ValueError("only https endpoints are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(
        request, timeout=DEFAULT_TIMEOUT, context=build_context()
    ) as response:
        body = response.read(MAX_BODY_BYTES)
        return {"status": response.status, "body": body}


def fetch_json(url):
    payload = fetch(url)
    try:
        return json.loads(payload["body"])
    except ValueError:
        logger.warning("response was not json: %s", url)
        return {}


def check_host(host, port=443):
    raw = socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT)
    wrapped = build_context().wrap_socket(raw, server_hostname=host)
    cert = wrapped.getpeercert()
    wrapped.close()
    logger.info("handshake with %s completed", host)
    return cert


def describe_target(url):
    return {"url": url, "timeout": DEFAULT_TIMEOUT, "user_agent": USER_AGENT}""",
        notes="""关闭证书与主机名校验等于放弃 TLS 的全部保护，中间人可直接解密。""",
    ),
    Task(
        task_id='T14',
        title="""字段加密的 IV 与密钥派生""",
        family='crypto',
        difficulty='hard',
        prompt="""Implement a small field-encryption helper used before storing sensitive columns. It provides derive_key(secret), new_iv(), pad/unpad, encrypt(plaintext, secret), decrypt(token, secret) and rotate_secret(new_secret). The output is base64 text stored in a text column.""",
        vulnerable_code=r"""import base64
import hashlib
import os

BLOCK_SIZE = 16
IV_LENGTH = 16
STATIC_IV = b"0123456789abcdef"
KEY_MATERIAL = b"autosafe-demo-key"
PAD_BYTE = b"\x00"


def derive_key(secret):
    return hashlib.md5(secret).digest()


def new_iv():
    return STATIC_IV


def pad(data):
    remainder = len(data) % BLOCK_SIZE
    if remainder == 0:
        return data
    return data + bytes([BLOCK_SIZE - remainder]) * (BLOCK_SIZE - remainder)


def unpad(data):
    if not data:
        return data
    count = data[-1]
    if count < 1 or count > BLOCK_SIZE:
        raise ValueError("invalid padding")
    return data[:-count]


def _keystream(key, iv):
    stream = bytearray()
    counter = 0
    while len(stream) < BLOCK_SIZE:
        stream.extend(hashlib.sha256(key + iv + bytes([counter])).digest())
        counter += 1
    return bytes(stream[:BLOCK_SIZE])


def encrypt(plaintext, secret=KEY_MATERIAL):
    key = derive_key(secret)
    iv = new_iv()
    block = pad(plaintext)
    out = bytearray(iv)
    previous = iv
    for start in range(0, len(block), BLOCK_SIZE):
        chunk = bytes(a ^ b for a, b in zip(block[start:start + BLOCK_SIZE], previous))
        chunk = bytes(a ^ b for a, b in zip(chunk, _keystream(key, iv)))
        out.extend(chunk)
        previous = chunk
    return base64.b64encode(bytes(out)).decode("ascii")


def decrypt(token, secret=KEY_MATERIAL):
    key = derive_key(secret)
    raw = base64.b64decode(token)
    iv, body = raw[:IV_LENGTH], raw[IV_LENGTH:]
    out = bytearray()
    previous = iv
    for start in range(0, len(body), BLOCK_SIZE):
        chunk = body[start:start + BLOCK_SIZE]
        plain = bytes(a ^ b for a, b in zip(chunk, _keystream(key, iv)))
        out.extend(bytes(a ^ b for a, b in zip(plain, previous)))
        previous = chunk
    return unpad(bytes(out))""",
        defects=(
            Defect(
                defect_id='CRYPTO_04',
                cwe='CWE-329',
                category='static_iv',
                severity='HIGH',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_STATIC_IV',
                line_hint=16,
                description="""IV 每次都返回同一个常量，相同明文产生相同密文，可做频率分析与重放。""",
                source_check='present:def new_iv\\(\\):\\n\\s*return STATIC_IV',
                fix_find="""def new_iv():
    return STATIC_IV""",
                fix_replace="""def new_iv():
    return os.urandom(IV_LENGTH)""",
                flawed_fix_replace=r"""def new_iv():
    return STATIC_IV + b"\x00" * 0""",
                fuzz_marker='FUZZ_STATIC_IV',
            ),
            Defect(
                defect_id='CRYPTO_05',
                cwe='CWE-916',
                category='weak_kdf',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B324',
                line_hint=13,
                description="""密钥用单轮 MD5 从口令派生，无盐无迭代，可离线暴力破解。""",
                source_check='present:hashlib\\.md5\\(secret\\)',
                fix_find="""    return hashlib.md5(secret).digest()""",
                fix_replace="""    salt = hashlib.sha256(b"autosafe-kdf-salt").digest()[:16]
    return hashlib.pbkdf2_hmac("sha256", secret, salt, 200000, dklen=32)""",
                flawed_fix_replace='    return hashlib.md5(secret).digest() + b"-s"',
                fuzz_marker=None,
            ),
            Defect(
                defect_id='CRYPTO_06',
                cwe='CWE-329',
                category='static_iv',
                severity='HIGH',
                subtlety=4,
                channel='semantic',
                detector='SEM_IV_CONSTANT',
                line_hint=7,
                description="""模块级 STATIC_IV 常量被当作默认 IV，任何拿到源码的人都能预测全部密文。""",
                source_check='present:^STATIC_IV = b"0123456789abcdef"',
                fix_find='STATIC_IV = b"0123456789abcdef"',
                fix_replace="""STATIC_IV = None""",
                flawed_fix_replace="""STATIC_IV = b"0123456789abcdef"  # TODO: rotate per release""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    try:
        first = module.encrypt(b"same-plaintext-block")
        second = module.encrypt(b"same-plaintext-block")
    except Exception:
        return markers
    if first == second:
        markers.append("FUZZ_STATIC_IV")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference=r"""import base64
import hashlib
import os

BLOCK_SIZE = 16
IV_LENGTH = 16
STATIC_IV = None
KEY_MATERIAL = b"autosafe-demo-key"
PAD_BYTE = b"\x00"


def derive_key(secret):
    salt = hashlib.sha256(b"autosafe-kdf-salt").digest()[:16]
    return hashlib.pbkdf2_hmac("sha256", secret, salt, 200000, dklen=32)


def new_iv():
    return os.urandom(IV_LENGTH)


def pad(data):
    remainder = len(data) % BLOCK_SIZE
    if remainder == 0:
        return data
    return data + bytes([BLOCK_SIZE - remainder]) * (BLOCK_SIZE - remainder)


def unpad(data):
    if not data:
        return data
    count = data[-1]
    if count < 1 or count > BLOCK_SIZE:
        raise ValueError("invalid padding")
    return data[:-count]


def _keystream(key, iv):
    stream = bytearray()
    counter = 0
    while len(stream) < BLOCK_SIZE:
        stream.extend(hashlib.sha256(key + iv + bytes([counter])).digest())
        counter += 1
    return bytes(stream[:BLOCK_SIZE])


def encrypt(plaintext, secret=KEY_MATERIAL):
    key = derive_key(secret)
    iv = new_iv()
    block = pad(plaintext)
    out = bytearray(iv)
    previous = iv
    for start in range(0, len(block), BLOCK_SIZE):
        chunk = bytes(a ^ b for a, b in zip(block[start:start + BLOCK_SIZE], previous))
        chunk = bytes(a ^ b for a, b in zip(chunk, _keystream(key, iv)))
        out.extend(chunk)
        previous = chunk
    return base64.b64encode(bytes(out)).decode("ascii")


def decrypt(token, secret=KEY_MATERIAL):
    key = derive_key(secret)
    raw = base64.b64decode(token)
    iv, body = raw[:IV_LENGTH], raw[IV_LENGTH:]
    out = bytearray()
    previous = iv
    for start in range(0, len(body), BLOCK_SIZE):
        chunk = body[start:start + BLOCK_SIZE]
        plain = bytes(a ^ b for a, b in zip(chunk, _keystream(key, iv)))
        out.extend(bytes(a ^ b for a, b in zip(plain, previous)))
        previous = chunk
    return unpad(bytes(out))""",
        notes="""固定 IV 让相同明文产生相同密文；MD5 派生密钥强度不足，应使用 PBKDF2/HKDF 与随机 IV。""",
    ),
    Task(
        task_id='T15',
        title="""数据访问层里的硬编码凭据""",
        family='secrets',
        difficulty='easy',
        prompt="""Implement the data-access bootstrap module for an analytics service. It builds the database URI with db_uri(), produces API auth headers with auth_headers(), signs internal payloads with sign_payload(payload)/verify_signature(payload, signature), creates the first admin account via bootstrap_admin(user_store), grants roles with grant_role() and redacts values with redact().""",
        vulnerable_code='import hashlib\nimport logging\nimport os\n\nlogger = logging.getLogger(__name__)\n\nDB_HOST = "db.internal.example.com"\nDB_USER = "reporting"\nDB_PASSWORD = "Rep0rting!2023"\nAPI_SECRET_KEY = "acme_live_KEY_51H8xQ2eZvKYlo2QrStUvW"\nJWT_SECRET = "change-me-in-prod"\nDEFAULT_TOKEN_TTL = 3600\nALLOWED_ROLES = ("admin", "analyst", "viewer")\n\n\ndef db_uri():\n    return "postgresql://%s:%s@%s/analytics" % (DB_USER, DB_PASSWORD, DB_HOST)\n\n\ndef auth_headers():\n    return {"Authorization": "Bearer " + API_SECRET_KEY, "Accept": "application/json"}\n\n\ndef sign_payload(payload):\n    raw = repr(payload).encode("utf-8")\n    return hashlib.sha256(JWT_SECRET.encode("utf-8") + raw).hexdigest()\n\n\ndef verify_signature(payload, signature):\n    expected = sign_payload(payload)\n    return expected == signature\n\n\ndef bootstrap_admin(user_store, username="admin", password="admin"):\n    record = {\n        "username": username,\n        "password": password,\n        "role": "admin",\n        "must_change_password": False,\n    }\n    user_store.create(record)\n    logger.info("bootstrapped admin account %s", username)\n    return record\n\n\ndef grant_role(user_store, username, role):\n    if role not in ALLOWED_ROLES:\n        raise ValueError("unknown role")\n    return user_store.update(username, {"role": role})\n\n\ndef redact(value):\n    if not value:\n        return ""\n    return value[:2] + "***"',
        defects=(
            Defect(
                defect_id='SECRET_01',
                cwe='CWE-798',
                category='hardcoded_credentials',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B105',
                line_hint=9,
                description="""数据库口令直接写在源码里，任何能读仓库的人都拿到生产凭据。""",
                source_check='present:Rep0rting!2023',
                fix_find='DB_PASSWORD = "Rep0rting!2023"',
                fix_replace="""DB_PASSWORD = os.environ.get("AUTOSAFE_DB_PASSWORD", "")""",
                flawed_fix_replace="""DB_PASSWORD = os.environ.get("AUTOSAFE_DB_PASSWORD", "Rep0rting!2023")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SECRET_02',
                cwe='CWE-798',
                category='hardcoded_credentials',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B105',
                line_hint=10,
                description="""生产 API key 硬编码在模块顶部，且被 auth_headers 原样发送。""",
                source_check='present:acme_live_KEY_51H8xQ2eZvKYlo2QrStUvW',
                fix_find='API_SECRET_KEY = "acme_live_KEY_51H8xQ2eZvKYlo2QrStUvW"',
                fix_replace="""API_SECRET_KEY = os.environ.get("AUTOSAFE_API_KEY", "")""",
                flawed_fix_replace="""API_SECRET_KEY = os.environ.get("AUTOSAFE_API_KEY", "acme_live_KEY_51H8xQ2eZvKYlo2QrStUvW")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SECRET_03',
                cwe='CWE-798',
                category='hardcoded_credentials',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B105',
                line_hint=11,
                description="""JWT 签名密钥是可猜的默认值，任何人都能伪造令牌。""",
                source_check='present:change-me-in-prod',
                fix_find='JWT_SECRET = "change-me-in-prod"',
                fix_replace="""JWT_SECRET = os.environ.get("AUTOSAFE_JWT_SECRET", "")""",
                flawed_fix_replace="""JWT_SECRET = os.environ.get("AUTOSAFE_JWT_SECRET", "change-me-in-prod")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SECRET_04',
                cwe='CWE-521',
                category='weak_password_policy',
                severity='HIGH',
                subtlety=2,
                channel='bandit',
                detector='B107',
                line_hint=34,
                description="""管理员初始口令是 'admin' 且不强制修改，首次部署即可被直接登录。""",
                source_check='present:password\\s*=\\s*\\(?\\s*"admin"',
                fix_find="""def bootstrap_admin(user_store, username="admin", password="admin"):""",
                fix_replace="""def bootstrap_admin(user_store, username="admin", password=None):
    if password is None:
        raise RuntimeError("an initial admin password must be supplied explicitly")
    if len(password) < 12:
        raise ValueError("initial admin password is too weak")""",
                flawed_fix_replace="""def bootstrap_admin(user_store, username="admin", password=("admin")):""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    try:
        headers = module.auth_headers()
    except Exception:
        return markers
    if "sk_live_" in json.dumps(headers):
        markers.append("FUZZ_SECRET_LEAK")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference='import hashlib\nimport logging\nimport os\n\nlogger = logging.getLogger(__name__)\n\nDB_HOST = "db.internal.example.com"\nDB_USER = "reporting"\nDB_PASSWORD = os.environ.get("AUTOSAFE_DB_PASSWORD", "")\nAPI_SECRET_KEY = os.environ.get("AUTOSAFE_API_KEY", "")\nJWT_SECRET = os.environ.get("AUTOSAFE_JWT_SECRET", "")\nDEFAULT_TOKEN_TTL = 3600\nALLOWED_ROLES = ("admin", "analyst", "viewer")\n\n\ndef db_uri():\n    return "postgresql://%s:%s@%s/analytics" % (DB_USER, DB_PASSWORD, DB_HOST)\n\n\ndef auth_headers():\n    return {"Authorization": "Bearer " + API_SECRET_KEY, "Accept": "application/json"}\n\n\ndef sign_payload(payload):\n    raw = repr(payload).encode("utf-8")\n    return hashlib.sha256(JWT_SECRET.encode("utf-8") + raw).hexdigest()\n\n\ndef verify_signature(payload, signature):\n    expected = sign_payload(payload)\n    return expected == signature\n\n\ndef bootstrap_admin(user_store, username="admin", password=None):\n    if password is None:\n        raise RuntimeError("an initial admin password must be supplied explicitly")\n    if len(password) < 12:\n        raise ValueError("initial admin password is too weak")\n    record = {\n        "username": username,\n        "password": password,\n        "role": "admin",\n        "must_change_password": False,\n    }\n    user_store.create(record)\n    logger.info("bootstrapped admin account %s", username)\n    return record\n\n\ndef grant_role(user_store, username, role):\n    if role not in ALLOWED_ROLES:\n        raise ValueError("unknown role")\n    return user_store.update(username, {"role": role})\n\n\ndef redact(value):\n    if not value:\n        return ""\n    return value[:2] + "***"',
        notes="""源码里的口令/密钥会随仓库与镜像扩散，必须走环境变量或密钥管理服务；默认口令必须强制轮换。""",
    ),
    Task(
        task_id='T16',
        title="""导出任务把凭据写进日志与 URL""",
        family='secrets',
        difficulty='medium',
        prompt="""Implement the ETL export client helper. build_url(host, params) builds the export endpoint, build_url_with_auth(host, params) adds service credentials, log_request(host, params) logs the outbound call, make_token(account_id)/decode_token(token) handle a lightweight token, and dump_config()/health() expose service metadata.""",
        vulnerable_code="""import base64
import hashlib
import hmac
import json
import logging
import urllib.parse

logger = logging.getLogger(__name__)

SERVICE_USER = "svc_etl"
SERVICE_PASSWORD = "Etl!Passw0rd"
SIGNING_KEY = "0123456789abcdef0123456789abcdef"
TOKEN_PREFIX = "etl_"
EXPORT_PAGE_SIZE = 500


def build_url(host, params):
    query = urllib.parse.urlencode(params)
    return "https://%s/api/v1/export?%s" % (host, query)


def build_url_with_auth(host, params):
    params = dict(params)
    params["user"] = SERVICE_USER
    params["password"] = SERVICE_PASSWORD
    return build_url(host, params)


def log_request(host, params):
    url = build_url_with_auth(host, params)
    logger.info("outbound export request: %s", url)
    return url


def make_token(account_id):
    raw = "%s%s" % (TOKEN_PREFIX, account_id)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def decode_token(token):
    return base64.b64decode(token).decode("utf-8")


def dump_config():
    return json.dumps({
        "service_user": SERVICE_USER,
        "signing_key": SIGNING_KEY,
        "page_size": EXPORT_PAGE_SIZE,
    })


def health():
    return {"ok": True, "user": SERVICE_USER}


def verify_signature(payload, signature):
    expected = hmac.new(
        SIGNING_KEY.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)""",
        defects=(
            Defect(
                defect_id='SECRET_05',
                cwe='CWE-798',
                category='hardcoded_credentials',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B105',
                line_hint=11,
                description="""服务账号口令与签名密钥硬编码，且被 dump_config 原样返回。""",
                source_check='present:Etl!Passw0rd',
                fix_find='SERVICE_PASSWORD = "Etl!Passw0rd"',
                fix_replace="""SERVICE_PASSWORD = os.environ.get("AUTOSAFE_SERVICE_PASSWORD", "")""",
                flawed_fix_replace="""SERVICE_PASSWORD = os.environ.get("AUTOSAFE_SERVICE_PASSWORD", "Etl!Passw0rd")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SECRET_06',
                cwe='CWE-598',
                category='sensitive_data_in_query',
                severity='HIGH',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_CREDENTIAL_IN_LOG',
                line_hint=25,
                description="""口令作为查询参数拼进 URL，代理/访问日志/错误上报都会留存明文。""",
                source_check='present:params\\["password"\\]\\s*=',
                fix_find="""    params["password"] = SERVICE_PASSWORD""",
                fix_replace="""    params["user"] = SERVICE_USER
    params["token"] = _signed_token()""",
                flawed_fix_replace="""    params["user"] = SERVICE_USER
    params["password"] = base64.b64encode(SERVICE_PASSWORD.encode()).decode()""",
                fuzz_marker='FUZZ_CREDENTIAL_IN_LOG',
            ),
            Defect(
                defect_id='SECRET_07',
                cwe='CWE-532',
                category='sensitive_data_in_logs',
                severity='HIGH',
                subtlety=3,
                channel='semantic',
                detector='SEM_LOG_FULL_URL',
                line_hint=31,
                description="""log_request 打印带凭据的完整 URL，等于把口令写进日志文件。""",
                source_check='present:"outbound export request: %s", url',
                fix_find="""    logger.info("outbound export request: %s", url)""",
                fix_replace="""    logger.info("outbound export request to %s (credentials redacted)", host)""",
                flawed_fix_replace="""    logger.info("outbound export request: %s", url.replace(SERVICE_PASSWORD, "***"))""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='SECRET_08',
                cwe='CWE-347',
                category='improper_signature_verification',
                severity='MEDIUM',
                subtlety=4,
                channel='semantic',
                detector='SEM_TOKEN_BASE64',
                line_hint=41,
                description="""令牌只是 base64（编码而非加密）且 decode 不做任何签名校验，可任意伪造。""",
                source_check='present:base64\\.b64decode\\(token\\)',
                fix_find="""    return base64.b64decode(token).decode("utf-8")""",
                fix_replace="""    raw = base64.urlsafe_b64decode(token)
    payload, _, signature = raw.rpartition(b".")
    expected = hmac.new(
        SIGNING_KEY.encode("utf-8"), payload, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("invalid token signature")
    return payload.decode("utf-8")""",
                flawed_fix_replace="""    raw = base64.b64decode(token)
    if not raw.startswith(TOKEN_PREFIX.encode("utf-8")):
        raise ValueError("unknown token prefix")
    return raw.decode("utf-8")""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json
import logging


def fuzz(module):
    markers = []
    records = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Capture()
    logger = logging.getLogger(module.__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        module.log_request("api.example.com", {"page": 1})
    except Exception:
        pass
    finally:
        logger.removeHandler(handler)
    for line in records:
        if "password=" in line or "Etl%21Passw0rd" in line or "Etl!Passw0rd" in line:
            markers.append("FUZZ_CREDENTIAL_IN_LOG")
            break
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import base64
import hashlib
import hmac
import json
import logging
import urllib.parse

logger = logging.getLogger(__name__)

SERVICE_USER = "svc_etl"
SERVICE_PASSWORD = os.environ.get("AUTOSAFE_SERVICE_PASSWORD", "")
SIGNING_KEY = "0123456789abcdef0123456789abcdef"
TOKEN_PREFIX = "etl_"
EXPORT_PAGE_SIZE = 500


def build_url(host, params):
    query = urllib.parse.urlencode(params)
    return "https://%s/api/v1/export?%s" % (host, query)


def build_url_with_auth(host, params):
    params = dict(params)
    params["user"] = SERVICE_USER
    params["user"] = SERVICE_USER
    params["token"] = _signed_token()
    return build_url(host, params)


def log_request(host, params):
    url = build_url_with_auth(host, params)
    logger.info("outbound export request to %s (credentials redacted)", host)
    return url


def make_token(account_id):
    raw = "%s%s" % (TOKEN_PREFIX, account_id)
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")


def decode_token(token):
    raw = base64.urlsafe_b64decode(token)
    payload, _, signature = raw.rpartition(b".")
    expected = hmac.new(
        SIGNING_KEY.encode("utf-8"), payload, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("invalid token signature")
    return payload.decode("utf-8")


def dump_config():
    return json.dumps({
        "service_user": SERVICE_USER,
        "signing_key": SIGNING_KEY,
        "page_size": EXPORT_PAGE_SIZE,
    })


def health():
    return {"ok": True, "user": SERVICE_USER}


def verify_signature(payload, signature):
    expected = hmac.new(
        SIGNING_KEY.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)""",
        notes="""凭据进 URL 会被代理与访问日志留存；令牌必须签名，日志脱敏要覆盖查询串与配置转储。""",
    ),
    Task(
        task_id='T17',
        title="""文档接口的对象级越权""",
        family='authz',
        difficulty='medium',
        prompt="""Implement a document repository used by a REST API. DocumentRepository wraps an injected store and provides get(), list_owned(), update(), delete() and share(). read_document(repo, doc_id, actor) builds the JSON payload for the detail endpoint and is_admin(actor) is the shared helper. Only the owner, an explicit sharee or an admin may read or modify a document.""",
        vulnerable_code="""import logging

logger = logging.getLogger(__name__)

PUBLIC_FIELDS = ("id", "title", "status")
ADMIN_ROLE = "admin"


class DocumentRepository:
    def __init__(self, store):
        self.store = store

    def get(self, doc_id):
        return self.store.fetch(doc_id)

    def list_owned(self, owner_id):
        return self.store.query({"owner_id": owner_id})

    def update(self, doc_id, changes, actor):
        document = self.store.fetch(doc_id)
        if document is None:
            raise KeyError("document not found")
        merged = dict(document)
        merged.update(changes)
        self.store.save(doc_id, merged)
        logger.info("user %s updated document %s", actor.get("id"), doc_id)
        return merged

    def delete(self, doc_id, actor):
        document = self.store.fetch(doc_id)
        if document is None:
            raise KeyError("document not found")
        self.store.delete(doc_id)
        logger.info("user %s deleted document %s", actor.get("id"), doc_id)
        return True

    def share(self, doc_id, target_user_id, actor):
        document = self.store.fetch(doc_id)
        shared = list(document.get("shared_with", []))
        shared.append(target_user_id)
        document["shared_with"] = shared
        self.store.save(doc_id, document)
        return {"doc_id": doc_id, "shared_with": shared}


def read_document(repo, doc_id, actor):
    document = repo.get(doc_id)
    if document is None:
        raise KeyError("document not found")
    payload = {k: document.get(k) for k in PUBLIC_FIELDS}
    payload["owner_id"] = document.get("owner_id")
    payload["body"] = document.get("body")
    return payload


def is_admin(actor):
    return actor.get("role") == ADMIN_ROLE""",
        defects=(
            Defect(
                defect_id='AUTHZ_01',
                cwe='CWE-639',
                category='idor',
                severity='HIGH',
                subtlety=4,
                channel='fuzz',
                detector='FUZZ_IDOR_READ',
                line_hint=52,
                description="""read_document 只按 id 取文档，不校验 actor 是否 owner 或被共享。""",
                source_check='absent:not allowed to read this document',
                fix_find="""    payload["body"] = document.get("body")""",
                fix_replace="""    if (
        document.get("owner_id") != actor.get("id")
        and actor.get("id") not in document.get("shared_with", [])
        and not is_admin(actor)
    ):
        raise PermissionError("not allowed to read this document")
    payload["body"] = document.get("body")""",
                flawed_fix_replace="""    if document.get("owner_id") != actor.get("id"):
        logger.warning("cross-owner read by %s", actor.get("id"))
    payload["body"] = document.get("body")""",
                fuzz_marker='FUZZ_IDOR_READ',
            ),
            Defect(
                defect_id='AUTHZ_02',
                cwe='CWE-639',
                category='idor',
                severity='HIGH',
                subtlety=4,
                channel='semantic',
                detector='SEM_UPDATE_OWNER',
                line_hint=23,
                description="""update 不校验归属，任何登录用户都能改别人的文档，且 changes 可覆盖 owner_id。""",
                source_check='absent:not allowed to modify this document',
                fix_find="""        merged = dict(document)
        merged.update(changes)""",
                fix_replace="""        if document.get("owner_id") != actor.get("id") and not is_admin(actor):
            raise PermissionError("not allowed to modify this document")
        allowed = {k: v for k, v in changes.items() if k in PUBLIC_FIELDS}
        merged = dict(document)
        merged.update(allowed)""",
                flawed_fix_replace="""        allowed = {k: v for k, v in changes.items() if k != "owner_id"}
        merged = dict(document)
        merged.update(allowed)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='AUTHZ_03',
                cwe='CWE-862',
                category='missing_authorization',
                severity='HIGH',
                subtlety=3,
                channel='semantic',
                detector='SEM_DELETE_NO_CHECK',
                line_hint=33,
                description="""delete 完全没有权限判断，viewer 也能删除他人文档。""",
                source_check='absent:not allowed to delete this document',
                fix_find="""        self.store.delete(doc_id)""",
                fix_replace="""        if document.get("owner_id") != actor.get("id") and not is_admin(actor):
            raise PermissionError("not allowed to delete this document")
        self.store.delete(doc_id)""",
                flawed_fix_replace="""        if actor.get("role") not in ("admin", "viewer", "analyst"):
            raise PermissionError("unknown role")
        self.store.delete(doc_id)""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


class _SpyStore:
    def __init__(self, documents):
        self.documents = documents
        self.deleted = []

    def fetch(self, doc_id):
        return self.documents.get(doc_id)

    def query(self, filters):
        return [d for d in self.documents.values() if d.get("owner_id") == filters.get("owner_id")]

    def save(self, doc_id, payload):
        self.documents[doc_id] = payload

    def delete(self, doc_id):
        self.deleted.append(doc_id)
        self.documents.pop(doc_id, None)


def _store():
    return _SpyStore({
        "doc-1": {"id": "doc-1", "owner_id": "alice", "title": "secret", "body": "top secret"},
        "doc-2": {"id": "doc-2", "owner_id": "bob", "title": "bob doc", "body": "b"},
    })


def fuzz(module):
    markers = []
    attacker = {"id": "mallory", "role": "viewer"}

    store = _store()
    try:
        payload = module.read_document(module.DocumentRepository(store), "doc-1", attacker)
    except Exception:
        payload = {}
    if payload.get("body") == "top secret":
        markers.append("FUZZ_IDOR_READ")

    store = _store()
    repo = module.DocumentRepository(store)
    try:
        repo.update("doc-1", {"title": "pwned"}, attacker)
    except Exception:
        pass
    if store.documents.get("doc-1", {}).get("title") == "pwned":
        markers.append("FUZZ_IDOR_WRITE")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging

logger = logging.getLogger(__name__)

PUBLIC_FIELDS = ("id", "title", "status")
ADMIN_ROLE = "admin"


class DocumentRepository:
    def __init__(self, store):
        self.store = store

    def get(self, doc_id):
        return self.store.fetch(doc_id)

    def list_owned(self, owner_id):
        return self.store.query({"owner_id": owner_id})

    def update(self, doc_id, changes, actor):
        document = self.store.fetch(doc_id)
        if document is None:
            raise KeyError("document not found")
        if document.get("owner_id") != actor.get("id") and not is_admin(actor):
            raise PermissionError("not allowed to modify this document")
        allowed = {k: v for k, v in changes.items() if k in PUBLIC_FIELDS}
        merged = dict(document)
        merged.update(allowed)
        self.store.save(doc_id, merged)
        logger.info("user %s updated document %s", actor.get("id"), doc_id)
        return merged

    def delete(self, doc_id, actor):
        document = self.store.fetch(doc_id)
        if document is None:
            raise KeyError("document not found")
        if document.get("owner_id") != actor.get("id") and not is_admin(actor):
            raise PermissionError("not allowed to delete this document")
        self.store.delete(doc_id)
        logger.info("user %s deleted document %s", actor.get("id"), doc_id)
        return True

    def share(self, doc_id, target_user_id, actor):
        document = self.store.fetch(doc_id)
        shared = list(document.get("shared_with", []))
        shared.append(target_user_id)
        document["shared_with"] = shared
        self.store.save(doc_id, document)
        return {"doc_id": doc_id, "shared_with": shared}


def read_document(repo, doc_id, actor):
    document = repo.get(doc_id)
    if document is None:
        raise KeyError("document not found")
    payload = {k: document.get(k) for k in PUBLIC_FIELDS}
    payload["owner_id"] = document.get("owner_id")
    if (
        document.get("owner_id") != actor.get("id")
        and actor.get("id") not in document.get("shared_with", [])
        and not is_admin(actor)
    ):
        raise PermissionError("not allowed to read this document")
    payload["body"] = document.get("body")
    return payload


def is_admin(actor):
    return actor.get("role") == ADMIN_ROLE""",
        notes="""认证通过不等于有权访问该对象；每个入口都要校验 owner/shared_with（IDOR）。""",
    ),
    Task(
        task_id='T18',
        title="""后台操作的角色校验""",
        family='authz',
        difficulty='hard',
        prompt="""Implement the admin action layer for an analytics console. role_rank(actor) and check_role(actor, required) map the role hierarchy, can_export()/can_purge() gate capabilities, handle_action(actor, action, payload) dispatches, and export_report/purge_cache/impersonate are the three sensitive entry points. Purge and impersonation are admin-only.""",
        vulnerable_code="""import logging

logger = logging.getLogger(__name__)

ROLE_HIERARCHY = {"viewer": 1, "analyst": 2, "admin": 3}
SENSITIVE_ACTIONS = ("export", "purge", "impersonate")
AUDIT_LOG = []


def role_rank(actor):
    return ROLE_HIERARCHY.get(actor.get("role"), 0)


def check_role(actor, required):
    return role_rank(actor) >= ROLE_HIERARCHY.get(required, 99)


def can_export(actor):
    return check_role(actor, "analyst")


def can_purge(actor):
    return actor.get("role") in ("analyst", "admin")


def handle_action(actor, action, payload=None):
    if action in SENSITIVE_ACTIONS:
        logger.info("sensitive action %s requested by %s", action, actor.get("id"))
    AUDIT_LOG.append({"actor": actor.get("id"), "action": action})
    return {"ok": True, "action": action, "payload": payload}


def export_report(actor, report_id):
    if not can_export(actor):
        raise PermissionError("export requires analyst role")
    return handle_action(actor, "export", {"report_id": report_id})


def purge_cache(actor, scope="all"):
    if not can_purge(actor):
        raise PermissionError("purge requires elevated role")
    return handle_action(actor, "purge", {"scope": scope})


def impersonate(actor, target_user_id):
    logger.info("impersonation requested: %s -> %s", actor.get("id"), target_user_id)
    return handle_action(actor, "impersonate", {"target": target_user_id})""",
        defects=(
            Defect(
                defect_id='AUTHZ_04',
                cwe='CWE-862',
                category='missing_authorization',
                severity='HIGH',
                subtlety=4,
                channel='fuzz',
                detector='FUZZ_IMPERSONATE',
                line_hint=46,
                description="""impersonate 完全没有角色校验，viewer 可直接冒充任意用户。""",
                source_check='absent:impersonation requires admin role',
                fix_find="""    logger.info("impersonation requested: %s -> %s", actor.get("id"), target_user_id)""",
                fix_replace="""    if not check_role(actor, "admin"):
        raise PermissionError("impersonation requires admin role")
    logger.info("impersonation requested: %s -> %s", actor.get("id"), target_user_id)""",
                flawed_fix_replace="""    if actor.get("role") == "viewer" and target_user_id == actor.get("id"):
        raise PermissionError("cannot impersonate yourself")
    logger.info("impersonation requested: %s -> %s", actor.get("id"), target_user_id)""",
                fuzz_marker='FUZZ_IMPERSONATE',
            ),
            Defect(
                defect_id='AUTHZ_05',
                cwe='CWE-863',
                category='incorrect_authorization',
                severity='HIGH',
                subtlety=3,
                channel='semantic',
                detector='SEM_PURGE_ROLE',
                line_hint=23,
                description="""can_purge 允许 analyst 清库，与角色矩阵（仅 admin）不符，且绕开了 check_role。""",
                source_check='present:return actor\\.get\\("role"\\) in \\("analyst"',
                fix_find="""    return actor.get("role") in ("analyst", "admin")""",
                fix_replace="""    return check_role(actor, "admin")""",
                flawed_fix_replace="""    return actor.get("role") in ("analyst", "admin", "owner")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='AUTHZ_06',
                cwe='CWE-863',
                category='incorrect_authorization',
                severity='MEDIUM',
                subtlety=4,
                channel='semantic',
                detector='SEM_ACTION_BYPASS',
                line_hint=29,
                description="""handle_action 可被直接调用绕过能力检查，SENSITIVE_ACTIONS 只用于写日志。""",
                source_check='absent:sensitive actions require admin role',
                fix_find="""    AUDIT_LOG.append({"actor": actor.get("id"), "action": action})""",
                fix_replace="""    if action in SENSITIVE_ACTIONS and not check_role(actor, "admin"):
        raise PermissionError("sensitive actions require admin role")
    AUDIT_LOG.append({"actor": actor.get("id"), "action": action})""",
                flawed_fix_replace="""    if action not in SENSITIVE_ACTIONS and action not in ("export", "purge"):
        raise ValueError("unknown action")
    AUDIT_LOG.append({"actor": actor.get("id"), "action": action})""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    viewer = {"id": "mallory", "role": "viewer"}
    try:
        module.impersonate(viewer, "alice")
    except Exception:
        pass
    else:
        markers.append("FUZZ_IMPERSONATE")
    try:
        module.purge_cache(viewer, scope="all")
    except Exception:
        pass
    else:
        markers.append("FUZZ_PURGE_BY_VIEWER")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging

logger = logging.getLogger(__name__)

ROLE_HIERARCHY = {"viewer": 1, "analyst": 2, "admin": 3}
SENSITIVE_ACTIONS = ("export", "purge", "impersonate")
AUDIT_LOG = []


def role_rank(actor):
    return ROLE_HIERARCHY.get(actor.get("role"), 0)


def check_role(actor, required):
    return role_rank(actor) >= ROLE_HIERARCHY.get(required, 99)


def can_export(actor):
    return check_role(actor, "analyst")


def can_purge(actor):
    return check_role(actor, "admin")


def handle_action(actor, action, payload=None):
    if action in SENSITIVE_ACTIONS:
        logger.info("sensitive action %s requested by %s", action, actor.get("id"))
    if action in SENSITIVE_ACTIONS and not check_role(actor, "admin"):
        raise PermissionError("sensitive actions require admin role")
    AUDIT_LOG.append({"actor": actor.get("id"), "action": action})
    return {"ok": True, "action": action, "payload": payload}


def export_report(actor, report_id):
    if not can_export(actor):
        raise PermissionError("export requires analyst role")
    return handle_action(actor, "export", {"report_id": report_id})


def purge_cache(actor, scope="all"):
    if not can_purge(actor):
        raise PermissionError("purge requires elevated role")
    return handle_action(actor, "purge", {"scope": scope})


def impersonate(actor, target_user_id):
    if not check_role(actor, "admin"):
        raise PermissionError("impersonation requires admin role")
    logger.info("impersonation requested: %s -> %s", actor.get("id"), target_user_id)
    return handle_action(actor, "impersonate", {"target": target_user_id})""",
        notes="""角色比较必须集中且完整；缺少最敏感操作的校验、以及漏掉 admin 的角色元组都是典型提权点。""",
    ),
    Task(
        task_id='T19',
        title="""多租户查询与令牌校验""",
        family='authz',
        difficulty='hard',
        prompt="""Implement the request-scoped data access helper for a multi-tenant SaaS. decode_token(token) parses a JWT-like token, verify_token(token) validates it, tenant_from_request(headers) resolves the active tenant, scoped_query(store, headers, filters) runs the tenant-scoped query, and require_role(payload, required) is used by handlers. Tokens are HS256 signed with SECRET.""",
        vulnerable_code="""import base64
import hmac
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

SECRET = "tenant-hmac-secret"
TENANT_HEADER = "X-Tenant-Id"
DEFAULT_TENANT = "public"
ROLE_CLAIM = "role"
MAX_TOKEN_LENGTH = 4096


def b64decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def decode_token(token):
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("token too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    payload["_header"] = header
    return payload


def verify_token(token):
    payload = decode_token(token)
    if payload.get("exp") and payload["exp"] < 0:
        raise ValueError("token expired")
    return payload


def tenant_from_request(headers):
    return headers.get(TENANT_HEADER, DEFAULT_TENANT)


def scoped_query(store, headers, filters):
    tenant = tenant_from_request(headers)
    query = dict(filters)
    query["tenant"] = tenant
    return list(store.find(query))


def require_role(payload, required):
    return payload.get(ROLE_CLAIM) == required""",
        defects=(
            Defect(
                defect_id='AUTHZ_07',
                cwe='CWE-347',
                category='improper_signature_verification',
                severity='HIGH',
                subtlety=1,
                channel='fuzz',
                detector='FUZZ_JWT_UNVERIFIED',
                line_hint=29,
                description="""decode_token 解析后从不校验签名，伪造任意 payload 即可通过。""",
                source_check='absent:invalid token signature',
                fix_find="""    payload["_header"] = header
    return payload""",
                fix_replace="""    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    expected = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64decode(parts[2])):
        raise ValueError("invalid token signature")
    payload["_header"] = header
    return payload""",
                flawed_fix_replace="""    if header.get("alg") not in ("HS256", "none"):
        raise ValueError("unsupported algorithm")
    payload["_header"] = header
    return payload""",
                fuzz_marker='FUZZ_JWT_UNVERIFIED',
            ),
            Defect(
                defect_id='AUTHZ_08',
                cwe='CWE-639',
                category='tenant_isolation',
                severity='HIGH',
                subtlety=4,
                channel='fuzz',
                detector='FUZZ_TENANT_HEADER_TRUST',
                line_hint=41,
                description="""租户取自客户端可控的请求头，改一个 header 就能读别家数据。""",
                source_check='present:headers\\.get\\(TENANT_HEADER',
                fix_find="""    return headers.get(TENANT_HEADER, DEFAULT_TENANT)""",
                fix_replace="""    token = headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise PermissionError("missing bearer token")
    payload = verify_token(token)
    tenant = payload.get("tenant")
    if not tenant:
        raise PermissionError("token has no tenant claim")
    return tenant""",
                flawed_fix_replace="""    tenant = headers.get(TENANT_HEADER, DEFAULT_TENANT)
    if not tenant or not tenant.isalnum():
        raise ValueError("invalid tenant id")
    return tenant""",
                fuzz_marker='FUZZ_TENANT_HEADER_TRUST',
            ),
            Defect(
                defect_id='AUTHZ_09',
                cwe='CWE-863',
                category='incorrect_authorization',
                severity='HIGH',
                subtlety=3,
                channel='semantic',
                detector='SEM_ROLE_EXACT_MATCH',
                line_hint=52,
                description="""require_role 用 == 精确匹配，admin 无法通过 analyst 检查，调用方被迫放宽比较。""",
                source_check='present:== required',
                fix_find="""    return payload.get(ROLE_CLAIM) == required""",
                fix_replace="""    rank = {"viewer": 1, "analyst": 2, "admin": 3}
    return rank.get(payload.get(ROLE_CLAIM), 0) >= rank.get(required, 99)""",
                flawed_fix_replace="""    role = payload.get(ROLE_CLAIM)
    if role is None:
        return False
    return role == required""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='AUTHZ_10',
                cwe='CWE-798',
                category='hardcoded_credentials',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B105',
                line_hint=9,
                description="""JWT 的 HS256 签名密钥硬编码在模块里，泄露即可伪造任意租户令牌。""",
                source_check='present:tenant-hmac-secret',
                fix_find='SECRET = "tenant-hmac-secret"',
                fix_replace="""SECRET = os.environ.get("AUTOSAFE_JWT_SECRET", "")""",
                flawed_fix_replace="""SECRET = os.environ.get("AUTOSAFE_JWT_SECRET", "tenant-hmac-secret")""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import base64
import json


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _forge(payload):
    header = _b64(b'{"alg": "none", "typ": "JWT"}')
    body = _b64(json.dumps(payload).encode("utf-8"))
    return header + "." + body + "." + _b64(b"not-a-real-signature")


class _SpyStore:
    def __init__(self):
        self.queries = []

    def find(self, query):
        self.queries.append(dict(query))
        return []


def fuzz(module):
    markers = []
    token = _forge({"sub": "mallory", "tenant": "acme", "role": "admin", "exp": 9999999999})
    try:
        payload = module.verify_token(token)
    except Exception:
        payload = None
    if payload is not None:
        markers.append("FUZZ_JWT_UNVERIFIED")

    store = _SpyStore()
    try:
        module.scoped_query(store, {"X-Tenant-Id": "globex"}, {"status": "open"})
    except Exception:
        pass
    for query in store.queries:
        if query.get("tenant") == "globex":
            markers.append("FUZZ_TENANT_HEADER_TRUST")
            break
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import base64
import hmac
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

SECRET = os.environ.get("AUTOSAFE_JWT_SECRET", "")
TENANT_HEADER = "X-Tenant-Id"
DEFAULT_TENANT = "public"
ROLE_CLAIM = "role"
MAX_TOKEN_LENGTH = 4096


def b64decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def decode_token(token):
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("token too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header = json.loads(b64decode(parts[0]))
    payload = json.loads(b64decode(parts[1]))
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    expected = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64decode(parts[2])):
        raise ValueError("invalid token signature")
    payload["_header"] = header
    return payload


def verify_token(token):
    payload = decode_token(token)
    if payload.get("exp") and payload["exp"] < 0:
        raise ValueError("token expired")
    return payload


def tenant_from_request(headers):
    token = headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise PermissionError("missing bearer token")
    payload = verify_token(token)
    tenant = payload.get("tenant")
    if not tenant:
        raise PermissionError("token has no tenant claim")
    return tenant


def scoped_query(store, headers, filters):
    tenant = tenant_from_request(headers)
    query = dict(filters)
    query["tenant"] = tenant
    return list(store.find(query))


def require_role(payload, required):
    rank = {"viewer": 1, "analyst": 2, "admin": 3}
    return rank.get(payload.get(ROLE_CLAIM), 0) >= rank.get(required, 99)""",
        notes="""JWT 必须验签（alg=none 攻击）；租户归属必须来自已验签的令牌而不是可伪造的请求头。""",
    ),
    Task(
        task_id='T20',
        title="""跳转跟随与出站抓取""",
        family='web',
        difficulty='hard',
        prompt="""Implement the link-preview fetcher. parse_target(url) splits a URL, is_allowed_host(url) applies the allowlist, next_url(current, location) resolves a Location header, follow_redirects(url, fetcher, limit) walks redirects, fetch(url, fetcher) performs the request and safe_redirect_url(url) validates post-login redirect targets. Only the allowlisted outbound hosts and the application origin may be reached.""",
        vulnerable_code="""import ipaddress
import logging
import socket
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = ("api.example.com", "cdn.example.com")
MAX_REDIRECTS = 3
DEFAULT_SCHEME = "https"
APP_ORIGIN = "app.example.com"


def parse_target(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        raise ValueError("absolute url required")
    return parsed


def is_allowed_host(url):
    parsed = parse_target(url)
    return parsed.hostname in ALLOWED_HOSTS


def next_url(current, location):
    if location.startswith("/"):
        parsed = parse_target(current)
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, location, "", "", "")
        )
    return location


def follow_redirects(url, fetcher, limit=MAX_REDIRECTS):
    current = url
    for _ in range(limit):
        response = fetcher(current)
        location = response.headers.get("Location")
        if not location:
            return current
        current = next_url(current, location)
        logger.info("redirected to %s", current)
    return current


def fetch(url, fetcher=None):
    parsed = parse_target(url)
    if fetcher is None:
        response = urllib.request.urlopen(url, timeout=5)
    else:
        response = fetcher(url, timeout=5)
    return {"host": parsed.hostname, "status": response.status}


def safe_redirect_url(url):
    parsed = parse_target(url)
    if parsed.scheme not in ("http", DEFAULT_SCHEME):
        raise ValueError("unsupported scheme")
    return url""",
        defects=(
            Defect(
                defect_id='WEB_01',
                cwe='CWE-601',
                category='open_redirect',
                severity='HIGH',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_OPEN_REDIRECT',
                line_hint=43,
                description="""跟随跳转时不重新校验 allowlist，一跳即可被带到任意外部站点。""",
                source_check='absent:redirect target is not allowed',
                fix_find="""        current = next_url(current, location)""",
                fix_replace="""        candidate = next_url(current, location)
        if not is_allowed_host(candidate):
            raise ValueError("redirect target is not allowed")
        current = candidate""",
                flawed_fix_replace="""        candidate = next_url(current, location)
        if "evil" in candidate:
            raise ValueError("blocked redirect")
        current = candidate""",
                fuzz_marker='FUZZ_OPEN_REDIRECT',
            ),
            Defect(
                defect_id='WEB_02',
                cwe='CWE-918',
                category='ssrf',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B310',
                line_hint=51,
                description="""fetch 直接 urlopen 且不校验目标地址，内网与云元数据地址都能访问。""",
                source_check='absent:internal addresses are not allowed',
                fix_find="""        response = urllib.request.urlopen(url, timeout=5)""",
                fix_replace="""        address = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError("internal addresses are not allowed")
        response = urllib.request.urlopen(url, timeout=5)""",
                flawed_fix_replace="""        if parsed.hostname == "localhost":
            raise ValueError("localhost is not allowed")
        response = urllib.request.urlopen(url, timeout=5)""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='WEB_03',
                cwe='CWE-601',
                category='open_redirect',
                severity='MEDIUM',
                subtlety=4,
                channel='semantic',
                detector='SEM_REDIRECT_SCHEME',
                line_hint=59,
                description="""safe_redirect_url 允许 http，且接受 //evil.com 这类协议相对地址。""",
                source_check='present:if parsed\\.scheme not in \\("http", DEFAULT_SCHEME\\)',
                fix_find="""    if parsed.scheme not in ("http", DEFAULT_SCHEME):""",
                fix_replace="""    if parsed.scheme != DEFAULT_SCHEME or parsed.netloc != APP_ORIGIN:
        raise ValueError("redirect must stay on the application origin")""",
                flawed_fix_replace="""    if parsed.scheme not in ("http", DEFAULT_SCHEME) or url.startswith("//"):
        raise ValueError("unsupported scheme")""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


class _Response:
    def __init__(self, location):
        self.headers = {"Location": location} if location else {}
        self.status = 302


class _SpyFetcher:
    def __init__(self, locations):
        self.locations = locations
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append(url)
        index = min(len(self.calls) - 1, len(self.locations) - 1)
        return _Response(self.locations[index])


def fuzz(module):
    markers = []
    fetcher = _SpyFetcher(["https://evil.example/steal", "https://evil.example/2"])
    try:
        final = module.follow_redirects("https://api.example.com/start", fetcher)
    except Exception:
        final = ""
    if "evil.example" in final:
        markers.append("FUZZ_OPEN_REDIRECT")

    class _Urlopen:
        def __call__(self, url, **kwargs):
            return _Response(None)

    try:
        module.fetch("http://169.254.169.254/latest/meta-data/", fetcher=_Urlopen())
    except Exception:
        pass
    else:
        markers.append("FUZZ_SSRF")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import ipaddress
import logging
import socket
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = ("api.example.com", "cdn.example.com")
MAX_REDIRECTS = 3
DEFAULT_SCHEME = "https"
APP_ORIGIN = "app.example.com"


def parse_target(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        raise ValueError("absolute url required")
    return parsed


def is_allowed_host(url):
    parsed = parse_target(url)
    return parsed.hostname in ALLOWED_HOSTS


def next_url(current, location):
    if location.startswith("/"):
        parsed = parse_target(current)
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, location, "", "", "")
        )
    return location


def follow_redirects(url, fetcher, limit=MAX_REDIRECTS):
    current = url
    for _ in range(limit):
        response = fetcher(current)
        location = response.headers.get("Location")
        if not location:
            return current
        candidate = next_url(current, location)
        if not is_allowed_host(candidate):
            raise ValueError("redirect target is not allowed")
        current = candidate
        logger.info("redirected to %s", current)
    return current


def fetch(url, fetcher=None):
    parsed = parse_target(url)
    if fetcher is None:
        address = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError("internal addresses are not allowed")
        response = urllib.request.urlopen(url, timeout=5)
    else:
        response = fetcher(url, timeout=5)
    return {"host": parsed.hostname, "status": response.status}


def safe_redirect_url(url):
    parsed = parse_target(url)
    if parsed.scheme != DEFAULT_SCHEME or parsed.netloc != APP_ORIGIN:
        raise ValueError("redirect must stay on the application origin")
        raise ValueError("unsupported scheme")
    return url""",
        notes="""开放重定向会在每跳丢失 allowlist；SSRF 必须限制目标地址段（含元数据地址与内网）。""",
    ),
    Task(
        task_id='T21',
        title="""表单提交的 CSRF 与会话 Cookie""",
        family='web',
        difficulty='medium',
        prompt="""Implement the form-security helper for a server-rendered admin UI. new_csrf_token() mints a token, issue_cookie_header(token, secure) builds Set-Cookie, verify_csrf(session, submitted_token) validates the submitted token against the session, csrf_protected(method) decides when protection applies, handle_form_post(request, session) guards the submit handler and rotate_session(session) refreshes the token.""",
        vulnerable_code="""import hashlib
import hmac
import logging
import secrets

logger = logging.getLogger(__name__)

SESSION_COOKIE = "autosafe_session"
CSRF_COOKIE = "autosafe_csrf"
COOKIE_MAX_AGE = 86400
SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "POST")
SECRET = "csrf-secret-key"
CSRF_FORM_FIELD = "csrf_token"


def new_csrf_token():
    return secrets.token_urlsafe(32)


def issue_cookie_header(token, secure=True):
    attributes = [
        "%s=%s" % (SESSION_COOKIE, token),
        "Path=/",
        "Max-Age=%d" % COOKIE_MAX_AGE,
    ]
    if secure:
        attributes.append("Secure")
    return "; ".join(attributes)


def verify_csrf(session, submitted_token):
    if submitted_token is None:
        return False
    return bool(submitted_token)


def csrf_protected(method):
    return method.upper() not in SAFE_METHODS


def handle_form_post(request, session):
    if not csrf_protected(request.get("method", "POST")):
        return {"ok": True}
    submitted = request.get("form", {}).get(CSRF_FORM_FIELD)
    if not verify_csrf(session, submitted):
        raise PermissionError("csrf validation failed")
    logger.info("form post accepted for %s", session.get("user"))
    return {"ok": True, "user": session.get("user")}


def rotate_session(session):
    session["csrf_token"] = new_csrf_token()
    session["rotated_at"] = COOKIE_MAX_AGE
    return session""",
        defects=(
            Defect(
                defect_id='WEB_04',
                cwe='CWE-1004',
                category='insecure_cookie',
                severity='HIGH',
                subtlety=2,
                channel='fuzz',
                detector='FUZZ_COOKIE_NO_HTTPONLY',
                line_hint=27,
                description="""会话 Cookie 缺少 HttpOnly/SameSite，XSS 或跨站请求即可带走会话。""",
                source_check='absent:HttpOnly',
                fix_find="""        attributes.append("Secure")""",
                fix_replace="""        attributes.append("Secure")
        attributes.append("HttpOnly")
        attributes.append("SameSite=Lax")""",
                flawed_fix_replace="""        attributes.append("Secure")
        attributes.append("SameSite=None")""",
                fuzz_marker='FUZZ_COOKIE_NO_HTTPONLY',
            ),
            Defect(
                defect_id='WEB_05',
                cwe='CWE-352',
                category='csrf',
                severity='HIGH',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_CSRF_BYPASS',
                line_hint=34,
                description="""verify_csrf 只判断提交值非空，从不与会话令牌比对，任意值都能通过。""",
                source_check='absent:compare_digest',
                fix_find="""    return bool(submitted_token)""",
                fix_replace="""    expected = session.get("csrf_token") or ""
    if not expected:
        return False
    return hmac.compare_digest(expected, submitted_token)""",
                flawed_fix_replace="""    expected = session.get("csrf_token") or ""
    return len(submitted_token) >= len(expected) // 2""",
                fuzz_marker='FUZZ_CSRF_BYPASS',
            ),
            Defect(
                defect_id='WEB_06',
                cwe='CWE-352',
                category='csrf',
                severity='MEDIUM',
                subtlety=4,
                channel='semantic',
                detector='SEM_CSRF_METHOD',
                line_hint=11,
                description="""SAFE_METHODS 把 POST 也算安全方法，状态变更请求完全跳过 CSRF 校验。""",
                source_check='present:"OPTIONS", "POST"',
                fix_find="""SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "POST")""",
                fix_replace="""SAFE_METHODS = ("GET", "HEAD", "OPTIONS")""",
                flawed_fix_replace="""SAFE_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PATCH")""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='WEB_10',
                cwe='CWE-798',
                category='hardcoded_credentials',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B105',
                line_hint=12,
                description="""CSRF 令牌的签名密钥硬编码，攻击者可自行签发通过校验的令牌。""",
                source_check='present:csrf-secret-key',
                fix_find='SECRET = "csrf-secret-key"',
                fix_replace="""SECRET = os.environ.get("AUTOSAFE_CSRF_SECRET", "")""",
                flawed_fix_replace="""SECRET = os.environ.get("AUTOSAFE_CSRF_SECRET", "csrf-secret-key")""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    try:
        header = module.issue_cookie_header("abc123", secure=True)
    except Exception:
        header = ""
    lowered = header.lower()
    if "httponly" not in lowered:
        markers.append("FUZZ_COOKIE_NO_HTTPONLY")
    if "samesite" not in lowered:
        markers.append("FUZZ_COOKIE_NO_SAMESITE")

    session = {"user": "alice", "csrf_token": "expected-token"}
    try:
        module.handle_form_post(
            {"method": "POST", "form": {"csrf_token": "attacker-guess"}}, session
        )
    except Exception:
        pass
    else:
        markers.append("FUZZ_CSRF_BYPASS")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import hashlib
import hmac
import logging
import secrets

logger = logging.getLogger(__name__)

SESSION_COOKIE = "autosafe_session"
CSRF_COOKIE = "autosafe_csrf"
COOKIE_MAX_AGE = 86400
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
SECRET = os.environ.get("AUTOSAFE_CSRF_SECRET", "")
CSRF_FORM_FIELD = "csrf_token"


def new_csrf_token():
    return secrets.token_urlsafe(32)


def issue_cookie_header(token, secure=True):
    attributes = [
        "%s=%s" % (SESSION_COOKIE, token),
        "Path=/",
        "Max-Age=%d" % COOKIE_MAX_AGE,
    ]
    if secure:
        attributes.append("Secure")
        attributes.append("HttpOnly")
        attributes.append("SameSite=Lax")
    return "; ".join(attributes)


def verify_csrf(session, submitted_token):
    if submitted_token is None:
        return False
    expected = session.get("csrf_token") or ""
    if not expected:
        return False
    return hmac.compare_digest(expected, submitted_token)


def csrf_protected(method):
    return method.upper() not in SAFE_METHODS


def handle_form_post(request, session):
    if not csrf_protected(request.get("method", "POST")):
        return {"ok": True}
    submitted = request.get("form", {}).get(CSRF_FORM_FIELD)
    if not verify_csrf(session, submitted):
        raise PermissionError("csrf validation failed")
    logger.info("form post accepted for %s", session.get("user"))
    return {"ok": True, "user": session.get("user")}


def rotate_session(session):
    session["csrf_token"] = new_csrf_token()
    session["rotated_at"] = COOKIE_MAX_AGE
    return session""",
        notes="""会话 Cookie 缺 HttpOnly/SameSite 会被 XSS 窃取；CSRF 校验必须真正比对会话令牌，且 POST 不能算安全方法。""",
    ),
    Task(
        task_id='T22',
        title="""上传与排序参数校验""",
        family='web',
        difficulty='medium',
        prompt="""Implement the upload and listing helpers for a report portal. validate_filename(name), sanitize_filename(name), store_upload(name, data, writer), build_response_header(display_name), parse_sort(spec), build_query(base_query, sort_spec) and paginate(items, page, per_page) are the public entry points. Uploaded names and sort specs come from the browser.""",
        vulnerable_code="""import logging
import os
import re

logger = logging.getLogger(__name__)

MAX_FILENAME_LENGTH = 128
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")
UPLOAD_ROOT = "uploads"
ALLOWED_EXTENSIONS = (".png", ".jpg", ".pdf")
HEADER_SAFE = re.compile(r"^[A-Za-z0-9 ._-]+$")
HEADER_UNSAFE = re.compile(r"[^A-Za-z0-9 ._-]")


def validate_filename(name):
    if len(name) > MAX_FILENAME_LENGTH:
        return False
    return bool(SAFE_FILENAME.match(name))


def sanitize_filename(name):
    return os.path.basename(name)


def store_upload(name, data, writer):
    if not validate_filename(name):
        raise ValueError("invalid filename")
    path = os.path.join(UPLOAD_ROOT, sanitize_filename(name))
    writer(path, data)
    logger.info("stored upload at %s", path)
    return path


def build_response_header(display_name):
    return "Content-Disposition: attachment; filename=%s" % display_name


def parse_sort(spec):
    field, _, direction = spec.partition(":")
    return {"field": field, "direction": direction or "asc"}


def build_query(base_query, sort_spec):
    sort = parse_sort(sort_spec)
    return "%s ORDER BY %s %s" % (base_query, sort["field"], sort["direction"])


def paginate(items, page, per_page=25):
    page = int(page)
    if page < 1:
        page = 1
    start = (page - 1) * per_page
    return items[start:start + per_page]""",
        defects=(
            Defect(
                defect_id='WEB_07',
                cwe='CWE-113',
                category='header_injection',
                severity='HIGH',
                subtlety=2,
                channel='fuzz',
                detector='FUZZ_HEADER_INJECTION',
                line_hint=35,
                description="""display_name 直接拼进 Content-Disposition，换行即可注入任意响应头。""",
                source_check='absent:HEADER_UNSAFE\\.sub',
                fix_find="""    return "Content-Disposition: attachment; filename=%s" % display_name""",
                fix_replace="""    safe = HEADER_UNSAFE.sub("_", display_name)
    return "Content-Disposition: attachment; filename=%s" % safe""",
                flawed_fix_replace="""    return "Content-Disposition: attachment; filename=%s" % display_name.strip()""",
                fuzz_marker='FUZZ_HEADER_INJECTION',
            ),
            Defect(
                defect_id='WEB_08',
                cwe='CWE-434',
                category='unrestricted_upload',
                severity='HIGH',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_UPLOAD_ESCAPE',
                line_hint=28,
                description="""store_upload 只校验文件名字符集，未限制扩展名，可上传并执行任意脚本。""",
                source_check='absent:upload path escapes upload root',
                fix_find="""    path = os.path.join(UPLOAD_ROOT, sanitize_filename(name))""",
                fix_replace="""    base = os.path.basename(name)
    if not base.lower().endswith(ALLOWED_EXTENSIONS):
        raise ValueError("unsupported file type")
    root = os.path.realpath(UPLOAD_ROOT)
    path = os.path.realpath(os.path.join(root, base))
    if not path.startswith(root + os.sep):
        raise ValueError("upload path escapes upload root")""",
                flawed_fix_replace="""    base = os.path.basename(name)
    if base.startswith("."):
        raise ValueError("hidden files are not allowed")
    path = os.path.join(UPLOAD_ROOT, base)""",
                fuzz_marker='FUZZ_UPLOAD_ESCAPE',
            ),
            Defect(
                defect_id='WEB_09',
                cwe='CWE-89',
                category='second_order_sqli',
                severity='MEDIUM',
                subtlety=4,
                channel='semantic',
                detector='SEM_SORT_INJECTION',
                line_hint=45,
                description="""排序字段与方向未经白名单就拼进 SQL，属二阶注入。""",
                source_check='absent:if field not in \\(',
                fix_find="""    return "%s ORDER BY %s %s" % (base_query, sort["field"], sort["direction"])""",
                fix_replace="""    field = sort["field"]
    if field not in ("id", "created_at", "status", "owner_id"):
        field = "id"
    direction = "DESC" if sort["direction"].lower() == "desc" else "ASC"
    return "%s ORDER BY %s %s" % (base_query, field, direction)""",
                flawed_fix_replace="""    field = sort["field"].replace(";", "").replace("--", "")
    return "%s ORDER BY %s %s" % (base_query, field, sort["direction"])""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    try:
        header = module.build_response_header("report" + chr(13) + chr(10) + "Set-Cookie: admin=1")
    except Exception:
        pass
    else:
        if chr(13) in header or chr(10) in header:
            markers.append("FUZZ_HEADER_INJECTION")

    class _Writer:
        def __init__(self):
            self.calls = []

        def __call__(self, path, data):
            self.calls.append(path)

    writer = _Writer()
    try:
        module.store_upload("webshell.php", b"x", writer)
    except Exception:
        pass
    allowed = tuple(getattr(module, "ALLOWED_EXTENSIONS", ()))
    for path in writer.calls:
        if allowed and not path.lower().endswith(allowed):
            markers.append("FUZZ_UPLOAD_ESCAPE")
            break
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import logging
import os
import re

logger = logging.getLogger(__name__)

MAX_FILENAME_LENGTH = 128
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")
UPLOAD_ROOT = "uploads"
ALLOWED_EXTENSIONS = (".png", ".jpg", ".pdf")
HEADER_SAFE = re.compile(r"^[A-Za-z0-9 ._-]+$")
HEADER_UNSAFE = re.compile(r"[^A-Za-z0-9 ._-]")


def validate_filename(name):
    if len(name) > MAX_FILENAME_LENGTH:
        return False
    return bool(SAFE_FILENAME.match(name))


def sanitize_filename(name):
    return os.path.basename(name)


def store_upload(name, data, writer):
    if not validate_filename(name):
        raise ValueError("invalid filename")
    base = os.path.basename(name)
    if not base.lower().endswith(ALLOWED_EXTENSIONS):
        raise ValueError("unsupported file type")
    root = os.path.realpath(UPLOAD_ROOT)
    path = os.path.realpath(os.path.join(root, base))
    if not path.startswith(root + os.sep):
        raise ValueError("upload path escapes upload root")
    writer(path, data)
    logger.info("stored upload at %s", path)
    return path


def build_response_header(display_name):
    safe = HEADER_UNSAFE.sub("_", display_name)
    return "Content-Disposition: attachment; filename=%s" % safe


def parse_sort(spec):
    field, _, direction = spec.partition(":")
    return {"field": field, "direction": direction or "asc"}


def build_query(base_query, sort_spec):
    sort = parse_sort(sort_spec)
    field = sort["field"]
    if field not in ("id", "created_at", "status", "owner_id"):
        field = "id"
    direction = "DESC" if sort["direction"].lower() == "desc" else "ASC"
    return "%s ORDER BY %s %s" % (base_query, field, direction)


def paginate(items, page, per_page=25):
    page = int(page)
    if page < 1:
        page = 1
    start = (page - 1) * per_page
    return items[start:start + per_page]""",
        notes="""响应头拼接导致头注入；排序字段拼接导致二阶注入；上传需校验扩展名与规范化后的落地路径。""",
    ),
    Task(
        task_id='T23',
        title="""口令重置令牌的随机源""",
        family='randomness',
        difficulty='medium',
        prompt="""Implement the password-reset service. generate_reset_token(length) mints a reset token, generate_api_key(prefix) mints an API key, token_signature(token, secret) signs it, store_reset_token(store, user_id, secret) persists a token record and verify_reset_token(store, user_id, token, secret) validates it. id_for_request() returns a correlation id for logs.""",
        vulnerable_code="""import hashlib
import hmac
import logging
import random
import secrets
import string
import time

logger = logging.getLogger(__name__)

TOKEN_ALPHABET = string.ascii_letters + string.digits
RESET_TOKEN_TTL = 900
MAX_TOKEN_ATTEMPTS = 5
_rng = random.Random(20240101)


def generate_reset_token(length=24):
    return "".join(_rng.choice(TOKEN_ALPHABET) for _ in range(length))


def generate_api_key(prefix="ak"):
    suffix = "".join(_rng.choice(string.hexdigits.lower()[:16]) for _ in range(32))
    return "%s_%s" % (prefix, suffix)


def token_signature(token, secret):
    return hashlib.sha256((token + secret).encode("utf-8")).hexdigest()


def store_reset_token(store, user_id, secret):
    token = generate_reset_token()
    store.save({
        "user_id": user_id,
        "token": token,
        "signature": token_signature(token, secret),
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + RESET_TOKEN_TTL,
    })
    logger.info("issued reset token for user %s", user_id)
    return token


def verify_reset_token(store, user_id, token, secret):
    record = store.fetch(user_id)
    if record is None:
        return False
    if record.get("expires_at", 0) < int(time.time()):
        return False
    expected = token_signature(record.get("token", ""), secret)
    return record.get("signature") == expected and record.get("token") == token


def id_for_request():
    return _rng.randint(100000, 999999)""",
        defects=(
            Defect(
                defect_id='RAND_01',
                cwe='CWE-338',
                category='weak_randomness',
                severity='HIGH',
                subtlety=2,
                channel='fuzz',
                detector='FUZZ_WEAK_TOKEN',
                line_hint=18,
                description="""重置令牌用 random.Random 生成，攻击者拿到种子或输出即可预测后续令牌。""",
                source_check='present:_rng\\.choice',
                fix_find="""    return "".join(_rng.choice(TOKEN_ALPHABET) for _ in range(length))""",
                fix_replace="""    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))""",
                flawed_fix_replace="""    return "".join(_rng.choice(TOKEN_ALPHABET) for _ in range(length + 4))""",
                fuzz_marker='FUZZ_WEAK_TOKEN',
            ),
            Defect(
                defect_id='RAND_02',
                cwe='CWE-338',
                category='weak_randomness',
                severity='HIGH',
                subtlety=3,
                channel='bandit',
                detector='B311',
                line_hint=14,
                description="""API key 用非密码学随机构造，且字母表只有 16 个字符，熵不足。""",
                source_check='present:_rng\\.choice\\(string\\.hexdigits',
                fix_find="""    suffix = "".join(_rng.choice(string.hexdigits.lower()[:16]) for _ in range(32))""",
                fix_replace="""    suffix = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(48))""",
                flawed_fix_replace="""    suffix = "".join(_rng.choice(string.hexdigits.lower()[:16]) for _ in range(64))""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='RAND_03',
                cwe='CWE-330',
                category='insufficient_entropy',
                severity='MEDIUM',
                subtlety=4,
                channel='semantic',
                detector='SEM_SIGNATURE_COMPARE',
                line_hint=50,
                description="""令牌签名用 == 比较，且签名只覆盖令牌本身（不含 user_id/时间），可跨用户重放。""",
                source_check='present:return record\\.get\\(\\"signature\\"\\) == expected and record\\.get\\(\\"token\\"\\) == token',
                fix_find="""    return record.get("signature") == expected and record.get("token") == token""",
                fix_replace="""    material = "%s|%s|%s" % (record.get("user_id"), record.get("token"), record.get("issued_at"))
    expected = token_signature(material, secret)
    return hmac.compare_digest(record.get("signature", ""), expected) and hmac.compare_digest(record.get("token", ""), token)""",
                flawed_fix_replace="""    expected = token_signature(record.get("token", ""), secret)
    return record.get("signature") == expected and record.get("token") == token""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


class _SpyStore:
    def __init__(self):
        self.records = {}

    def save(self, record):
        self.records[record["user_id"]] = record

    def fetch(self, user_id):
        return self.records.get(user_id)


def fuzz(module):
    markers = []
    rng = getattr(module, "_rng", None)
    if rng is None:
        return markers
    try:
        rng.seed(1234)
        first = module.generate_reset_token()
        rng.seed(1234)
        second = module.generate_reset_token()
    except Exception:
        return markers
    if first == second:
        markers.append("FUZZ_WEAK_TOKEN")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import hashlib
import hmac
import logging
import random
import secrets
import string
import time

logger = logging.getLogger(__name__)

TOKEN_ALPHABET = string.ascii_letters + string.digits
RESET_TOKEN_TTL = 900
MAX_TOKEN_ATTEMPTS = 5
_rng = random.Random(20240101)


def generate_reset_token(length=24):
    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))


def generate_api_key(prefix="ak"):
    suffix = "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(48))
    return "%s_%s" % (prefix, suffix)


def token_signature(token, secret):
    return hashlib.sha256((token + secret).encode("utf-8")).hexdigest()


def store_reset_token(store, user_id, secret):
    token = generate_reset_token()
    store.save({
        "user_id": user_id,
        "token": token,
        "signature": token_signature(token, secret),
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + RESET_TOKEN_TTL,
    })
    logger.info("issued reset token for user %s", user_id)
    return token


def verify_reset_token(store, user_id, token, secret):
    record = store.fetch(user_id)
    if record is None:
        return False
    if record.get("expires_at", 0) < int(time.time()):
        return False
    expected = token_signature(record.get("token", ""), secret)
    material = "%s|%s|%s" % (record.get("user_id"), record.get("token"), record.get("issued_at"))
    expected = token_signature(material, secret)
    return hmac.compare_digest(record.get("signature", ""), expected) and hmac.compare_digest(record.get("token", ""), token)


def id_for_request():
    return _rng.randint(100000, 999999)""",
        notes="""安全令牌必须用 secrets/os.urandom；random.Random 是可复现的伪随机，令牌可被预测。""",
    ),
    Task(
        task_id='T24',
        title="""短信验证码与抽奖随机性""",
        family='randomness',
        difficulty='hard',
        prompt="""Implement the OTP and giveaway helper. generate_otp() mints a 6 digit code, send_otp(store, phone, sender) delivers it through an injected sender, verify_otp(store, phone, submitted) validates it, draw_prize(seed) picks a prize, idempotency_key(user_id, amount) derives a dedupe key and retry_delay(attempt) computes backoff.""",
        vulnerable_code="""import hashlib
import hmac
import logging
import random
import secrets
import time

logger = logging.getLogger(__name__)

OTP_LENGTH = 6
OTP_TTL_SECONDS = 300
MAX_VERIFY_ATTEMPTS = 3
IDEMPOTENCY_SECRET = "idem-key"
_shared_rng = random.Random()
PRIZES = ("gold", "silver", "bronze", "none")


def generate_otp():
    return "%0*d" % (OTP_LENGTH, _shared_rng.randint(0, 10 ** OTP_LENGTH - 1))


def send_otp(store, phone, sender):
    code = generate_otp()
    store.save({"phone": phone, "code": code, "issued_at": int(time.time())})
    sender(phone, "your code is " + code)
    logger.info("sent otp to %s", phone)
    return code


def verify_otp(store, phone, submitted):
    record = store.fetch(phone)
    if record is None:
        return False
    if int(time.time()) - record.get("issued_at", 0) > OTP_TTL_SECONDS:
        return False
    return record.get("code") == submitted


def draw_prize(seed=None):
    rng = random.Random(seed)
    return rng.choice(PRIZES)


def idempotency_key(user_id, amount):
    return hashlib.md5(("%s:%s" % (user_id, amount)).encode("utf-8")).hexdigest()


def retry_delay(attempt):
    return _shared_rng.uniform(0.1, 1.0) * attempt""",
        defects=(
            Defect(
                defect_id='RAND_04',
                cwe='CWE-338',
                category='weak_randomness',
                severity='HIGH',
                subtlety=2,
                channel='fuzz',
                detector='FUZZ_OTP_STATIC',
                line_hint=19,
                description="""验证码用模块级 random.Random 生成，序列可预测，等于没有二次验证。""",
                source_check='present:_shared_rng\\.randint\\(0, 10 \\*\\* OTP_LENGTH',
                fix_find="""    return "%0*d" % (OTP_LENGTH, _shared_rng.randint(0, 10 ** OTP_LENGTH - 1))""",
                fix_replace="""    return "%0*d" % (OTP_LENGTH, secrets.randbelow(10 ** OTP_LENGTH))""",
                flawed_fix_replace="""    return "%0*d" % (OTP_LENGTH, _shared_rng.randint(0, 10 ** OTP_LENGTH - 1))""",
                fuzz_marker='FUZZ_OTP_STATIC',
            ),
            Defect(
                defect_id='RAND_05',
                cwe='CWE-307',
                category='improper_restriction_of_auth_attempts',
                severity='HIGH',
                subtlety=4,
                channel='fuzz',
                detector='FUZZ_OTP_NO_LIMIT',
                line_hint=36,
                description="""verify_otp 不限制尝试次数也不做常量时间比较，6 位码可被在线爆破。""",
                source_check='absent:too many verification attempts',
                fix_find="""    return record.get("code") == submitted""",
                fix_replace="""    attempts = int(record.get("attempts", 0)) + 1
    store.save({**record, "attempts": attempts})
    if attempts > MAX_VERIFY_ATTEMPTS:
        raise PermissionError("too many verification attempts")
    return hmac.compare_digest(str(record.get("code", "")), str(submitted))""",
                flawed_fix_replace="""    if int(record.get("attempts", 0)) > 99:
        raise PermissionError("too many attempts")
    return record.get("code") == str(submitted).strip()""",
                fuzz_marker='FUZZ_OTP_NO_LIMIT',
            ),
            Defect(
                defect_id='RAND_06',
                cwe='CWE-330',
                category='insufficient_entropy',
                severity='MEDIUM',
                subtlety=4,
                channel='bandit',
                detector='B324',
                line_hint=45,
                description="""幂等键用无密钥 MD5 拼 user_id:amount，任何人可离线构造同一键重放请求。""",
                source_check='present:hashlib\\.md5\\(',
                fix_find="""    return hashlib.md5(("%s:%s" % (user_id, amount)).encode("utf-8")).hexdigest()""",
                fix_replace="""    material = ("%s:%s" % (user_id, amount)).encode("utf-8")
    return hmac.new(IDEMPOTENCY_SECRET.encode("utf-8"), material, hashlib.sha256).hexdigest()""",
                flawed_fix_replace='    return hashlib.md5(("%s:%s" % (user_id, amount)).encode("utf-8")).hexdigest() + "v2"',
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


class _SpyStore:
    def __init__(self):
        self.records = {}

    def save(self, record):
        self.records[record["phone"]] = record

    def fetch(self, phone):
        return self.records.get(phone)


def fuzz(module):
    markers = []
    rng = getattr(module, "_shared_rng", None)
    if rng is not None:
        try:
            rng.seed(7)
            first = module.generate_otp()
            rng.seed(7)
            second = module.generate_otp()
        except Exception:
            first = second = None
        if first is not None and first == second:
            markers.append("FUZZ_OTP_STATIC")

    store = _SpyStore()
    try:
        module.send_otp(store, "13800000000", lambda phone, text: None)
    except Exception:
        return markers
    blocked = False
    for _ in range(10):
        try:
            module.verify_otp(store, "13800000000", "000000")
        except Exception:
            blocked = True
            break
    if not blocked:
        markers.append("FUZZ_OTP_NO_LIMIT")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import hashlib
import hmac
import logging
import random
import secrets
import time

logger = logging.getLogger(__name__)

OTP_LENGTH = 6
OTP_TTL_SECONDS = 300
MAX_VERIFY_ATTEMPTS = 3
IDEMPOTENCY_SECRET = "idem-key"
_shared_rng = random.Random()
PRIZES = ("gold", "silver", "bronze", "none")


def generate_otp():
    return "%0*d" % (OTP_LENGTH, secrets.randbelow(10 ** OTP_LENGTH))


def send_otp(store, phone, sender):
    code = generate_otp()
    store.save({"phone": phone, "code": code, "issued_at": int(time.time())})
    sender(phone, "your code is " + code)
    logger.info("sent otp to %s", phone)
    return code


def verify_otp(store, phone, submitted):
    record = store.fetch(phone)
    if record is None:
        return False
    if int(time.time()) - record.get("issued_at", 0) > OTP_TTL_SECONDS:
        return False
    attempts = int(record.get("attempts", 0)) + 1
    store.save({**record, "attempts": attempts})
    if attempts > MAX_VERIFY_ATTEMPTS:
        raise PermissionError("too many verification attempts")
    return hmac.compare_digest(str(record.get("code", "")), str(submitted))


def draw_prize(seed=None):
    rng = random.Random(seed)
    return rng.choice(PRIZES)


def idempotency_key(user_id, amount):
    material = ("%s:%s" % (user_id, amount)).encode("utf-8")
    return hmac.new(IDEMPOTENCY_SECRET.encode("utf-8"), material, hashlib.sha256).hexdigest()


def retry_delay(attempt):
    return _shared_rng.uniform(0.1, 1.0) * attempt""",
        notes="""验证码必须用 secrets 生成并限制尝试次数；幂等键不能是可预测的 MD5，否则可被构造碰撞重放。""",
    ),
    Task(
        task_id='T25',
        title="""生产配置里的调试开关与 CORS""",
        family='config',
        difficulty='medium',
        prompt="""Implement the application settings module. current_config() reports the effective settings, apply_overrides(overrides) applies runtime overrides, is_debug_enabled() gates debug behaviour, cors_headers(origin) builds the CORS response, error_response(exc) renders failures, setup_logging() configures logging and client_ip(request, forwarded_for) resolves the caller.""",
        vulnerable_code="""import json
import logging
import os

logger = logging.getLogger(__name__)

APP_NAME = "autosafe-console"
ENVIRONMENT = "production"
DEBUG = True
SECRET_KEY = "dev-secret-key-not-for-prod"
ALLOWED_ORIGINS = "*"
SESSION_COOKIE_SECURE = False
TRUSTED_PROXY_COUNT = 1
LOG_LEVEL = "DEBUG"


def current_config():
    return {
        "app": APP_NAME,
        "env": ENVIRONMENT,
        "debug": DEBUG,
        "allowed_origins": ALLOWED_ORIGINS,
        "cookie_secure": SESSION_COOKIE_SECURE,
        "log_level": LOG_LEVEL,
    }


def apply_overrides(overrides):
    global DEBUG, ALLOWED_ORIGINS, LOG_LEVEL
    for key, value in overrides.items():
        if key == "debug":
            DEBUG = bool(value)
        elif key == "allowed_origins":
            ALLOWED_ORIGINS = value
        elif key == "log_level":
            LOG_LEVEL = value
        else:
            logger.warning("unknown override %s", key)
    return current_config()


def is_debug_enabled():
    return DEBUG


def cors_headers(origin):
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGINS,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "authorization, content-type",
    }


def error_response(exc):
    if DEBUG:
        return {"error": str(exc), "traceback": repr(exc), "config": current_config()}
    return {"error": "internal server error"}


def setup_logging():
    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.DEBUG))
    logger.info("logging configured for %s", APP_NAME)""",
        defects=(
            Defect(
                defect_id='CONF_01',
                cwe='CWE-489',
                category='debug_enabled',
                severity='HIGH',
                subtlety=2,
                channel='fuzz',
                detector='FUZZ_DEBUG_IN_PROD',
                line_hint=9,
                description="""生产配置里 DEBUG=True，错误页会回显 traceback、局部变量与完整配置。""",
                source_check='present:^DEBUG = True',
                fix_find="""DEBUG = True""",
                fix_replace="""DEBUG = os.environ.get("AUTOSAFE_DEBUG", "").lower() in ("1", "true")""",
                flawed_fix_replace="""DEBUG = True  # toggled by ops""",
                fuzz_marker='FUZZ_DEBUG_IN_PROD',
            ),
            Defect(
                defect_id='CONF_02',
                cwe='CWE-942',
                category='permissive_cors',
                severity='HIGH',
                subtlety=3,
                channel='fuzz',
                detector='FUZZ_WILDCARD_CORS_CREDENTIALS',
                line_hint=11,
                description="""CORS 允许任意来源且带 Allow-Credentials，等于允许任意站点读取登录态响应。""",
                source_check='present:^ALLOWED_ORIGINS = "\\*"',
                fix_find='ALLOWED_ORIGINS = "*"',
                fix_replace="""ALLOWED_ORIGINS = tuple(
    origin.strip()
    for origin in os.environ.get(
        "AUTOSAFE_ALLOWED_ORIGINS", "https://app.example.com"
    ).split(",")
    if origin.strip()
)""",
                flawed_fix_replace='ALLOWED_ORIGINS = "*" if not os.environ.get("AUTOSAFE_ALLOWED_ORIGINS") else "*"',
                fuzz_marker='FUZZ_WILDCARD_CORS_CREDENTIALS',
            ),
            Defect(
                defect_id='CONF_03',
                cwe='CWE-209',
                category='error_information_leak',
                severity='HIGH',
                subtlety=4,
                channel='semantic',
                detector='SEM_ERROR_DISCLOSURE',
                line_hint=56,
                description="""error_response 在 debug 下把异常详情与配置一起返回给客户端。""",
                source_check='present:"traceback": repr\\(exc\\)',
                fix_find="""        return {"error": str(exc), "traceback": repr(exc), "config": current_config()}""",
                fix_replace="""        logger.exception("unhandled error: %s", exc)
        return {"error": "internal server error", "request_id": request_id()}""",
                flawed_fix_replace=r"""        return {"error": str(exc).split("\n")[0], "traceback": repr(exc)}""",
                fuzz_marker=None,
            ),
            Defect(
                defect_id='CONF_04',
                cwe='CWE-798',
                category='hardcoded_credentials',
                severity='HIGH',
                subtlety=1,
                channel='bandit',
                detector='B105',
                line_hint=10,
                description="""生产环境的 SECRET_KEY 是写死的开发值，可直接伪造签名 Cookie。""",
                source_check='present:dev-secret-key-not-for-prod',
                fix_find='SECRET_KEY = "dev-secret-key-not-for-prod"',
                fix_replace="""SECRET_KEY = os.environ.get("AUTOSAFE_SECRET_KEY", "")""",
                flawed_fix_replace="""SECRET_KEY = os.environ.get("AUTOSAFE_SECRET_KEY", "dev-secret-key-not-for-prod")""",
                fuzz_marker=None,
            ),
        ),
        fuzz_harness="""import json


def fuzz(module):
    markers = []
    config = module.current_config()
    if config.get("debug") is True and config.get("env") == "production":
        markers.append("FUZZ_DEBUG_IN_PROD")
    headers = module.cors_headers("https://app.example.com")
    if headers.get("Access-Control-Allow-Origin") == "*" and (
        headers.get("Access-Control-Allow-Credentials") == "true"
    ):
        markers.append("FUZZ_WILDCARD_CORS_CREDENTIALS")
    return markers


if __name__ == "__main__":
    import target

    print("FUZZ_MARKERS:" + json.dumps(fuzz(target)))""",
        secure_reference="""import json
import logging
import os

logger = logging.getLogger(__name__)

APP_NAME = "autosafe-console"
ENVIRONMENT = "production"
DEBUG = os.environ.get("AUTOSAFE_DEBUG", "").lower() in ("1", "true")
SECRET_KEY = os.environ.get("AUTOSAFE_SECRET_KEY", "")
ALLOWED_ORIGINS = tuple(
    origin.strip()
    for origin in os.environ.get(
        "AUTOSAFE_ALLOWED_ORIGINS", "https://app.example.com"
    ).split(",")
    if origin.strip()
)
SESSION_COOKIE_SECURE = False
TRUSTED_PROXY_COUNT = 1
LOG_LEVEL = "DEBUG"


def current_config():
    return {
        "app": APP_NAME,
        "env": ENVIRONMENT,
        "debug": DEBUG,
        "allowed_origins": ALLOWED_ORIGINS,
        "cookie_secure": SESSION_COOKIE_SECURE,
        "log_level": LOG_LEVEL,
    }


def apply_overrides(overrides):
    global DEBUG, ALLOWED_ORIGINS, LOG_LEVEL
    for key, value in overrides.items():
        if key == "debug":
            DEBUG = bool(value)
        elif key == "allowed_origins":
            ALLOWED_ORIGINS = value
        elif key == "log_level":
            LOG_LEVEL = value
        else:
            logger.warning("unknown override %s", key)
    return current_config()


def is_debug_enabled():
    return DEBUG


def cors_headers(origin):
    return {
        "Access-Control-Allow-Origin": ALLOWED_ORIGINS,
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "authorization, content-type",
    }


def error_response(exc):
    if DEBUG:
        logger.exception("unhandled error: %s", exc)
        return {"error": "internal server error", "request_id": request_id()}
    return {"error": "internal server error"}


def setup_logging():
    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.DEBUG))
    logger.info("logging configured for %s", APP_NAME)""",
        notes="""生产环境开 DEBUG、CORS 通配符 + 允许凭据、错误页回显 traceback 与配置都是常见高危默认值。""",
    ),
]

TASKS_BY_ID: dict[str, Task] = {t.task_id: t for t in TASKS}

FAMILY_ORDER: list[str] = list(FAMILIES)
