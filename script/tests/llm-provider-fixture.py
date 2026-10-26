#!/usr/bin/env python3
"""Local OpenAI-chat compatible fixture. Never contacts an external model."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

state = {"mode": "normal", "calls": 0, "active": 0, "cancelled": 0, "lastPrompt": ""}
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        with lock:
            snapshot = dict(state)
        self.send_json(200, snapshot)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if self.path == "/mode":
            with lock:
                state["mode"] = body.get("mode", "normal")
            self.send_json(200, {"ok": True})
            return
        if self.path not in ("/chat/completions", "/v1/chat/completions"):
            self.send_json(404, {"error": {"message": "unknown fixture endpoint"}})
            return
        if self.headers.get("Authorization") != "Bearer fixture-key":
            self.send_json(401, {"error": {"message": "fixture authentication failed"}})
            return
        with lock:
            state["calls"] += 1
            mode = state["mode"]
            state["lastPrompt"] = "\n".join(item.get("content", "") for item in body.get("messages", []))
        if mode == "rate":
            self.send_json(429, {"error": {"message": "fixture rate limit"}})
            return
        if mode == "error":
            self.send_json(503, {"error": {"message": "fixture unavailable"}})
            return
        text = "功能概述\n该函数累加输入数值。\n\n关键函数与参数\nL1–L8 接收输入并返回累加结果。\n\n执行流程\n初始化后逐项相加，再返回结果。\n\n推断说明\n变量名来自反编译，推断需要结合调用方验证。"
        if not body.get("stream"):
            self.send_json(200, {"choices": [{"message": {"content": text}}]})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        with lock:
            state["active"] += 1
        try:
            if mode == "timeout":
                # Keep emitting SSE comments, but no answer tokens. This still
                # exercises the App's overall deadline while letting this
                # fixture promptly observe the upstream connection closing.
                for _ in range(200):
                    self.wfile.write(b': waiting\n\n')
                    self.wfile.flush()
                    time.sleep(0.1)
            parts = list(text) if mode == "slow" else [text[index:index + 8] for index in range(0, len(text), 8)]
            for part in parts:
                payload = json.dumps({"choices": [{"delta": {"content": part}}]}, ensure_ascii=False)
                self.wfile.write(("data: " + payload + "\n\n").encode())
                self.wfile.flush()
                time.sleep(0.1 if mode == "slow" else 0.02)
            self.wfile.write(b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            with lock:
                state["cancelled"] += 1
        finally:
            with lock:
                state["active"] -= 1


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
