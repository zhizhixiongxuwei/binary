#!/usr/bin/env python3
"""BinaryScan Python Checker。

该进程接收 scanner 通过 checker-v1 发送的反编译 Python 源码，使用标准库 ``ast`` 完成
结构化规则检测，并返回可定位到 Monaco 编辑器的 Finding。服务刻意保持无数据库、无业务卷；
任务状态、重试、源码制品和报告均由主系统负责。这里的分析范围是单文件 AST 与导入别名解析，
不宣称拥有跨模块调用图或运行时污点传播能力。
"""

import ast
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 128 * 1024 * 1024
MAX_FILES = 3000
MAX_FINDINGS = 10000


def rule_definition(rule_id, name, description, cwe, severity, limitation):
    return {"id": rule_id, "name": name, "description": description, "cwes": [cwe],
            "severity": severity, "language": "python", "default_enabled": True,
            "limitations": ["基于单文件 Python AST 和导入别名，不提供跨模块调用图或运行时污点传播。", limitation]}


RULES = tuple(sorted([
    rule_definition("python-dynamic-code-execution", "动态执行 Python 代码", "检测 eval、exec 动态代码执行接口。", "CWE-95", "high", "接口使用提示，不证明执行文本一定由外部输入控制。"),
    rule_definition("python-command-injection", "操作系统命令执行", "检测 os、subprocess 命令接口以及开启 shell 的 Popen。", "CWE-78", "high", "部分命令接口直接提示使用风险，不推导输入可信度或完整参数净化。"),
    rule_definition("python-unsafe-deserialization", "不安全的对象反序列化", "检测 pickle、shelve 模块导入及已实现的对象反序列化调用。", "CWE-502", "high", "模块导入本身也可能触发提示；不能据此认定存在可利用的反序列化入口。"),
    rule_definition("python-weak-message-digest", "弱消息摘要算法", "检测 hashlib.md5、hashlib.sha1 的使用。", "CWE-328", "medium", "未区分安全认证用途和普通非安全校验用途。"),
    rule_definition("python-insecure-request", "关闭 HTTPS 证书校验", "检测 requests 调用中 verify=False，包括受支持的 pycdc 参数形态。", "CWE-295", "medium", "不检查全局会话配置、所有 HTTP 库或运行时动态参数。"),
], key=lambda rule: rule["id"]))
RULE_BY_ID = {rule["id"]: rule for rule in RULES}
RULE_IDS = frozenset(RULE_BY_ID)
CATALOG_BYTES = json.dumps(RULES, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
CATALOG_VERSION = "sha256:" + hashlib.sha256(CATALOG_BYTES).hexdigest()


def rule_catalog():
    return {"version": "checker-v1", "language": "python", "catalogVersion": CATALOG_VERSION,
            "rules": json.loads(CATALOG_BYTES)}


def selected_rules(request):
    if "catalogVersion" in request and request["catalogVersion"] != CATALOG_VERSION:
        raise ValueError("catalog version mismatch")
    if "ruleIds" not in request:
        return sorted(RULE_IDS)
    ids = request["ruleIds"]
    if (not isinstance(ids, list) or not ids or len(ids) > 100
            or any(not isinstance(rule_id, str) or rule_id not in RULE_IDS for rule_id in ids)):
        raise ValueError("invalid rule selection")
    return sorted(set(ids))


class Analyzer(ast.NodeVisitor):
    """单个源码文件的 AST 访问器，集中维护导入别名和 Finding 输出。"""

    def __init__(self, path, content, enabled_rules=None):
        self.path = path
        self.lines = content.split("\n")
        self.findings = []
        self.module_aliases = {}
        self.imported_symbols = {}
        self.enabled_rules = RULE_IDS if enabled_rules is None else frozenset(enabled_rules)
        if not self.enabled_rules <= RULE_IDS:
            raise ValueError("unknown rule")

    def visit_Import(self, node):
        for alias in node.names:
            module = alias.name.split(".")[0]
            local_name = alias.asname or module
            self.module_aliases[local_name] = module
            if "python-unsafe-deserialization" in self.enabled_rules and module in {"pickle", "shelve"}:
                self.add_finding(
                    node,
                    "python-unsafe-deserialization",
                    "high",
                    "CWE-502",
                    "Unsafe deserialization module",
                    f"importing {module} exposes object deserialization that may execute code",
                    {"module": module},
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = (node.module or "").split(".")[0]
        for alias in node.names:
            self.imported_symbols[alias.asname or alias.name] = (module, alias.name)
        if "python-unsafe-deserialization" in self.enabled_rules and module in {"pickle", "shelve"}:
            self.add_finding(
                node,
                "python-unsafe-deserialization",
                "high",
                "CWE-502",
                "Unsafe deserialization module",
                f"importing from {module} exposes object deserialization that may execute code",
                {"module": module},
            )
        self.generic_visit(node)

    def visit_Call(self, node):
        # 先把 ``import x as y`` / ``from x import y as z`` 还原成稳定的限定名，
        # 规则无需为每种别名写重复分支，也能匹配 pycdc 常见的反编译结果。
        name = self.resolved_call_name(node.func)
        rule = None
        if "python-dynamic-code-execution" in self.enabled_rules and name in {"eval", "exec"}:
            rule = ("python-dynamic-code-execution", "high", "CWE-95", "Dynamic code execution",
                    f"{name} executes dynamic Python code")
        elif "python-command-injection" in self.enabled_rules and name in {"os.system", "os.popen", "subprocess.call", "subprocess.check_call",
                      "subprocess.check_output", "subprocess.run"}:
            rule = ("python-command-injection", "high", "CWE-78", "Command injection",
                    f"{name} executes an operating-system command")
        elif "python-command-injection" in self.enabled_rules and name == "subprocess.Popen" and has_shell_true(node):
            rule = ("python-command-injection", "high", "CWE-78", "Subprocess shell enabled",
                    "subprocess.Popen with shell=True may execute attacker-controlled shell syntax")
        elif "python-unsafe-deserialization" in self.enabled_rules and name in {"pickle.load", "pickle.loads", "yaml.loads", "shelve.open"}:
            rule = ("python-unsafe-deserialization", "high", "CWE-502", "Unsafe deserialization",
                    f"{name} may construct attacker-controlled Python objects")
        elif "python-weak-message-digest" in self.enabled_rules and name in {"hashlib.md5", "hashlib.sha1"}:
            algorithm = name.rsplit(".", 1)[1]
            rule = ("python-weak-message-digest", "medium", "CWE-328", "Weak message digest",
                    f"hashlib.{algorithm} selects a collision-prone digest algorithm")
        elif "python-insecure-request" in self.enabled_rules and name.startswith("requests.") and has_keyword_false(node, "verify"):
            rule = ("python-insecure-request", "medium", "CWE-295", "TLS verification disabled",
                    f"{name} disables certificate verification with verify=False")
        if rule:
            rule_id, severity, cwe, title, message = rule
            self.add_finding(node, rule_id, severity, cwe, title, message, {"call": name})
        self.generic_visit(node)

    def resolved_call_name(self, node):
        raw = call_name(node)
        if isinstance(node, ast.Name):
            imported = self.imported_symbols.get(node.id)
            return ".".join(imported) if imported else raw
        if isinstance(node, ast.Attribute):
            parts = raw.split(".")
            if parts and parts[0] in self.module_aliases:
                parts[0] = self.module_aliases[parts[0]]
            return ".".join(parts)
        return raw

    def add_finding(self, node, rule_id, severity, cwe, title, message, evidence):
        if rule_id not in self.enabled_rules:
            raise AssertionError("disabled rule evaluated")
        definition = RULE_BY_ID[rule_id]
        if cwe not in definition["cwes"]:
            raise AssertionError("rule CWE differs from registry")
        line = getattr(node, "lineno", 1)
        self.findings.append({
            "ruleId": rule_id,
            "severity": definition["severity"],
            "cwe": cwe,
            "path": self.path,
            "line": line,
            "column": utf16_column(self.lines, line, getattr(node, "col_offset", 0)),
            "title": title,
            "message": message,
            "evidence": evidence,
        })


def utf16_column(lines, line_number, utf8_byte_offset):
    """把 CPython 的零基 UTF-8 字节偏移转换为 Monaco 的一基 UTF-16 列号。

    Python AST 与浏览器编辑器使用的列坐标单位不同；中文、emoji 等字符会放大差异，若不转换，
    报告中的行列虽然存在，点击后却会落在错误字符上。
    """
    if line_number < 1 or line_number > len(lines) or utf8_byte_offset < 0:
        return 1
    line = lines[line_number - 1]
    consumed_bytes = 0
    utf16_units = 0
    for character in line:
        if consumed_bytes == utf8_byte_offset:
            break
        consumed_bytes += len(character.encode("utf-8"))
        utf16_units += 2 if ord(character) > 0xFFFF else 1
    if consumed_bytes != utf8_byte_offset:
        # ast positions are guaranteed to be UTF-8 character boundaries. Keep
        # a defensive fallback for a future parser returning malformed data.
        return 1
    return utf16_units + 1


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def has_shell_true(node):
    return has_boolean_keyword(node, "shell", True)


def has_keyword_false(node, name):
    return has_boolean_keyword(node, name, False)


def has_boolean_keyword(node, name, expected):
    if any(keyword.arg == name and isinstance(keyword.value, ast.Constant)
           and keyword.value.value is expected for keyword in node.keywords):
        return True
    # pycdc 3.9 可能把关键字参数反编译为“位置值 + 字典展开元组”，例如：
    # requests.get(url, False, **('verify',))。兼容该形态才能避免反编译后漏报。
    for keyword in node.keywords:
        if keyword.arg is not None or not isinstance(keyword.value, (ast.Tuple, ast.List)):
            continue
        names = [item.value for item in keyword.value.elts
                 if isinstance(item, ast.Constant) and isinstance(item.value, str)]
        if len(names) != len(keyword.value.elts) or len(node.args) < len(names):
            continue
        values = node.args[-len(names):]
        for keyword_name, value in zip(names, values):
            if keyword_name == name and isinstance(value, ast.Constant) and value.value is expected:
                return True
    return False


def valid_path(path):
    return isinstance(path, str) and path and not path.startswith("/") and ".." not in path and "\\" not in path


def analyze(request):
    """校验一个 checker-v1 项目批次并返回稳定、有上限的检测结果。"""
    if not isinstance(request, dict) or request.get("version") != "checker-v1" or request.get("language") != "python":
        raise ValueError("unsupported contract or language")
    applied = selected_rules(request)
    project_id = request.get("projectId")
    files = request.get("files")
    if not isinstance(project_id, str) or not isinstance(files, list) or len(files) > MAX_FILES:
        raise ValueError("invalid project or file list")
    findings = []
    diagnostics = []
    for source in files:
        path = source.get("path") if isinstance(source, dict) else None
        content = source.get("content") if isinstance(source, dict) else None
        if not valid_path(path) or not isinstance(content, str) or len(content.encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("invalid source file")
        try:
            tree = ast.parse(content, filename=path)
            analyzer = Analyzer(path, content, applied)
            analyzer.visit(tree)
            findings.extend(analyzer.findings)
        except SyntaxError as error:
            # 单个反编译文件不完整时保留诊断并继续处理其他文件，最终状态标记为 partial。
            diagnostics.append(f"{path}:{error.lineno or 1}: parser rejected decompiled source")
        if len(findings) > MAX_FINDINGS:
            findings = findings[:MAX_FINDINGS]
            diagnostics.append("finding limit reached")
            break
    return {
        "version": "checker-v1",
        "projectId": project_id,
        "status": "partial" if diagnostics else "complete",
        "findings": findings,
        "diagnostics": diagnostics[:1000],
        "catalogVersion": CATALOG_VERSION,
        "appliedRuleIds": applied,
    }


class Handler(BaseHTTPRequestHandler):
    """最小内部 HTTP 适配层；业务编排、鉴权与持久化不放入 Checker。"""

    server_version = "BinaryScanPythonChecker/1"

    def do_GET(self):
        if self.path == "/v1/rules":
            self.respond(200, rule_catalog())
            return
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.respond(200, {"status": "ok", "checker": "python"})

    def do_POST(self):
        if self.path != "/v1/check":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            # 在读取请求体之前先执行硬上限，避免恶意或错误调用占满进程内存。
            if size <= 0 or size > MAX_BODY:
                raise ValueError("invalid body size")
            request = json.loads(self.rfile.read(size))
            self.respond(200, analyze(request))
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.respond(400, {"error": "invalid_request", "message": str(error)})

    def respond(self, status, body):
        encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        print(json.dumps({"component": "python-checker", "message": fmt % args}), flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
