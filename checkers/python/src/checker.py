#!/usr/bin/env python3
import ast
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 128 * 1024 * 1024
MAX_FILES = 3000
MAX_FINDINGS = 10000


class Analyzer(ast.NodeVisitor):
    def __init__(self, path):
        self.path = path
        self.findings = []

    def visit_Call(self, node):
        name = call_name(node.func)
        rule = None
        if name in {"eval", "exec"}:
            rule = ("PY001", "high", "CWE-95", "Dynamic code execution", f"{name} executes dynamic Python code")
        elif name == "os.system":
            rule = ("PY002", "high", "CWE-78", "Shell command execution", "os.system executes through the host shell")
        elif name in {"subprocess.run", "subprocess.call", "subprocess.Popen"} and has_shell_true(node):
            rule = ("PY003", "high", "CWE-78", "Subprocess shell enabled", "shell=True may execute attacker-controlled shell syntax")
        elif name in {"pickle.load", "pickle.loads"}:
            rule = ("PY004", "medium", "CWE-502", "Unsafe deserialization", "pickle may execute code while deserializing")
        if rule:
            rule_id, severity, cwe, title, message = rule
            self.findings.append({
                "ruleId": rule_id,
                "severity": severity,
                "cwe": cwe,
                "path": self.path,
                "line": getattr(node, "lineno", 1),
                "column": getattr(node, "col_offset", 0) + 1,
                "title": title,
                "message": message,
                "evidence": {"call": name},
            })
        self.generic_visit(node)


def call_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def has_shell_true(node):
    return any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
               for keyword in node.keywords)


def valid_path(path):
    return isinstance(path, str) and path and not path.startswith("/") and ".." not in path and "\\" not in path


def analyze(request):
    if request.get("version") != "checker-v1" or request.get("language") != "python":
        raise ValueError("unsupported contract or language")
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
            analyzer = Analyzer(path)
            analyzer.visit(tree)
            findings.extend(analyzer.findings)
        except SyntaxError as error:
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
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "BinaryScanPythonChecker/1"

    def do_GET(self):
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
