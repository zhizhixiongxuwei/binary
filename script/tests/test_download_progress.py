"""Exercise download reporting and cleanup against local, controllable HTTP responses."""

import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
from pathlib import Path
import re
import socket
import tempfile
import threading
import unittest
from unittest import mock
import urllib.request
import zipfile


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("binaryscan_progress_tools", REPO / "script/tools/prepare-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)


class CapturedOutput:
    """Wait for actual progress writes instead of relying on scheduler-sensitive sleeps."""

    def __init__(self, terminal=False):
        self.terminal = terminal
        self.parts = []
        self.condition = threading.Condition()

    def isatty(self):
        return self.terminal

    def write(self, value):
        with self.condition:
            self.parts.append(value)
            self.condition.notify_all()
        return len(value)

    def flush(self):
        pass

    def getvalue(self):
        with self.condition:
            return "".join(self.parts)

    def wait_for(self, predicate, timeout=4):
        with self.condition:
            return self.condition.wait_for(lambda: predicate("".join(self.parts)), timeout)


class DownloadProgressTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="binaryscan-progress-test-")
        self.addCleanup(temporary.cleanup)
        self.target = Path(temporary.name) / "cache/asset.zip"
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as contents:
            contents.writestr("payload.bin", bytes(range(256)) * 1024)
        self.payload = archive.getvalue()
        self.output = CapturedOutput()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.enterContext(mock.patch.object(TOOLS, "PROGRESS_INTERVAL", 0.025))
        self.enterContext(mock.patch.object(TOOLS, "LOG_PROGRESS_INTERVAL", 0.025))
        # These tests must never consult a machine's configured external proxy.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.urlopen = opener.open
        self.enterContext(mock.patch.object(TOOLS.urllib.request, "urlopen", side_effect=self.urlopen))
        self.original_progress_threads = {
            thread for thread in threading.enumerate() if thread.name == "download-progress"
        }

    def serve(self, respond):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                handler.server.requests += 1
                respond(handler, handler.server.requests)

            def log_message(self, *_arguments):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        server.requests = 0
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(3)

        self.addCleanup(stop)
        return "http://127.0.0.1:{}/asset.zip?token=test-secret".format(server.server_port), server

    def send_headers(self, handler, with_length=True):
        handler.send_response(200)
        if with_length:
            handler.send_header("Content-Length", str(len(self.payload)))
        handler.end_headers()

    def assert_cleaned_up(self):
        self.assertFalse(list(self.target.parent.glob(".download-*")))
        remaining = {thread for thread in threading.enumerate() if thread.name == "download-progress"}
        self.assertEqual(remaining, self.original_progress_threads)

    @contextlib.contextmanager
    def background_download(self, url, release):
        result, errors = [], []

        def run():
            try:
                result.append(TOOLS.download(url, self.target, "zip", len(self.payload), None))
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        try:
            yield worker, result, errors
        finally:
            release.set()
            worker.join(5)
            self.assertFalse(worker.is_alive(), "local download did not finish after releasing response")

    def test_partial_chunk_is_reported_and_stalled_read_keeps_heartbeats(self):
        release = threading.Event()

        def respond(handler, _attempt):
            self.send_headers(handler)
            handler.wfile.write(self.payload[:1024])
            handler.wfile.flush()
            if release.wait(5):
                handler.wfile.write(self.payload[1024:])

        url, _server = self.serve(respond)
        with self.background_download(url, release) as (worker, result, errors):
            # A 1 KiB write must become visible even though the requested read is 64 KiB.
            partial = r"asset\.zip \[[#-]+\]\s+[\d.]+% 1\.0 KiB/"
            self.assertTrue(self.output.wait_for(lambda text: len(re.findall(partial, text)) >= 3),
                            self.output.getvalue())
            self.assertTrue(worker.is_alive(), "server should still be withholding the rest of the file")
            self.assertIn("0.0 B/s", self.output.getvalue())
        self.assertFalse(errors, errors)
        self.assertEqual(result[0]["size"], len(self.payload))
        self.assertEqual(self.target.read_bytes(), self.payload)
        output = self.output.getvalue()
        self.assertIn("100.0%", output)
        self.assertIn("ETA", output)
        self.assertIn("elapsed", output)
        self.assertLess(output.index("| downloaded"), output.index("==> validating asset.zip"))
        self.assertLess(output.index("==> validating asset.zip"), output.index("==> ready asset.zip"))
        self.assert_cleaned_up()

    def test_connecting_to_slow_headers_keeps_heartbeats(self):
        release, connected = threading.Event(), threading.Event()

        def respond(handler, _attempt):
            connected.set()
            if release.wait(5):
                self.send_headers(handler)
                handler.wfile.write(self.payload)

        url, _server = self.serve(respond)
        with self.background_download(url, release) as (_worker, result, errors):
            self.assertTrue(connected.wait(3))
            self.assertTrue(self.output.wait_for(lambda text: text.count("asset.zip connecting") >= 3))
        self.assertFalse(errors, errors)
        self.assertEqual(result[0]["size"], len(self.payload))
        self.assert_cleaned_up()

    def test_unknown_size_does_not_invent_percentages_or_total(self):
        def respond(handler, _attempt):
            self.send_headers(handler, with_length=False)
            handler.wfile.write(self.payload)

        url, _server = self.serve(respond)
        record = TOOLS.download(url, self.target, "zip", 0, None)
        self.assertEqual(record["size"], len(self.payload))
        self.assertIn("unknown size", self.output.getvalue())
        self.assertNotIn("%", self.output.getvalue())
        self.assertNotIn("\r", self.output.getvalue())
        self.assert_cleaned_up()

    def test_terminal_updates_one_line_and_ends_with_newline(self):
        output = CapturedOutput(terminal=True)
        with TOOLS.DownloadProgress("asset.zip", total=100, stream=output, interval=0.025) as progress:
            progress.set_total(100)
            progress.advance(25)
            self.assertTrue(output.wait_for(lambda text: text.count("25.0%") >= 2))
            self.assertNotIn("\n", output.getvalue())
            progress.advance(75)
        text = output.getvalue()
        self.assertGreaterEqual(text.count("\r"), 4)
        self.assertEqual(text.count("\n"), 1)
        self.assertTrue(text.endswith("\n"))
        self.assertIn("100.0%", text)
        self.assertIn("downloaded", text)
        text.encode("ascii")
        self.assert_cleaned_up()

    def test_truncated_response_retries_and_promotes_only_complete_archive(self):
        def respond(handler, attempt):
            self.send_headers(handler)
            handler.wfile.write(self.payload[:1024] if attempt == 1 else self.payload)

        url, server = self.serve(respond)
        with mock.patch.object(TOOLS.time, "sleep"):
            record = TOOLS.download(url, self.target, "zip", len(self.payload), None)
        self.assertEqual(server.requests, 2)
        self.assertEqual(record["sha256"], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.target.read_bytes(), self.payload)
        self.assertIn("incomplete download", self.output.getvalue())
        self.assertIn("attempt 2/3", self.output.getvalue())
        self.assert_cleaned_up()

    def test_http_failure_has_bounded_retries_safe_reason_and_no_partial_file(self):
        responses = []

        def respond(handler, _attempt):
            handler.send_error(503, "private URL http://secret.example/?token=test-secret")

        def track_response(*arguments, **keywords):
            try:
                return self.urlopen(*arguments, **keywords)
            except TOOLS.urllib.error.HTTPError as error:
                responses.append(error)
                self.addCleanup(error.close)
                raise

        url, server = self.serve(respond)
        with (mock.patch.object(TOOLS.time, "sleep"),
              mock.patch.object(TOOLS.urllib.request, "urlopen", side_effect=track_response),
              self.assertRaises(TOOLS.PreparationError) as failure):
            TOOLS.download(url, self.target, "zip", 0, None)
        self.assertEqual(server.requests, 3)
        self.assertTrue(all(response.fp.closed for response in responses), "HTTP error responses must be closed")
        self.assertIn("HTTP 503", str(failure.exception))
        output = self.output.getvalue() + str(failure.exception)
        self.assertNotIn("test-secret", output)
        self.assertNotIn("http://", output)
        self.assertFalse(self.target.exists())
        self.assert_cleaned_up()

    def test_connection_refused_reports_failure_without_url_or_thread_leak(self):
        # Hold the local port without listening so no other process can claim it.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            url = "http://127.0.0.1:{}/?token=test-secret".format(reserved.getsockname()[1])
            with mock.patch.object(TOOLS.time, "sleep"), self.assertRaises(TOOLS.PreparationError) as failure:
                TOOLS.download(url, self.target, "zip", 0, None)
        self.assertIn("after 3 attempts", str(failure.exception))
        self.assertEqual(self.output.getvalue().count("==> downloading asset.zip"), 3)
        self.assertNotIn("test-secret", self.output.getvalue() + str(failure.exception))
        self.assertFalse(self.target.exists())
        self.assert_cleaned_up()

    def test_stalled_read_times_out_and_removes_temporary_file(self):
        release = threading.Event()

        def respond(handler, _attempt):
            self.send_headers(handler)
            handler.wfile.write(self.payload[:1024])
            handler.wfile.flush()
            release.wait(3)

        url, server = self.serve(respond)
        try:
            with (mock.patch.object(TOOLS, "DOWNLOAD_TIMEOUT", 0.15),
                  mock.patch.object(TOOLS, "DOWNLOAD_ATTEMPTS", 1),
                  self.assertRaises(TOOLS.PreparationError) as failure):
                TOOLS.download(url, self.target, "zip", len(self.payload), None)
        finally:
            release.set()
        self.assertEqual(server.requests, 1)
        self.assertIn("timed out", str(failure.exception))
        self.assertFalse(self.target.exists())
        self.assert_cleaned_up()

    def test_keyboard_interrupt_during_read_stops_progress_and_removes_partial_file(self):
        class InterruptedResponse:
            headers = {"Content-Length": "2000"}

            def __init__(self):
                self.reads = 0

            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                pass

            def read(self, _size):
                self.reads += 1
                if self.reads == 1:
                    return b"partial response"
                raise KeyboardInterrupt

        with (mock.patch.object(TOOLS.urllib.request, "urlopen", return_value=InterruptedResponse()) as request,
              self.assertRaises(KeyboardInterrupt)):
            TOOLS.download("http://unused.example/?token=test-secret", self.target, "zip", 0, None)
        request.assert_called_once()
        self.assertIn("interrupted", self.output.getvalue())
        self.assertNotIn("test-secret", self.output.getvalue())
        self.assertFalse(self.target.exists())
        self.assert_cleaned_up()

    def test_valid_download_is_reused_without_network_or_progress_thread(self):
        def respond(handler, _attempt):
            self.send_headers(handler)
            handler.wfile.write(self.payload)

        url, server = self.serve(respond)
        record = TOOLS.download(url, self.target, "zip", len(self.payload), None)
        modified = self.target.stat().st_mtime_ns
        with mock.patch.object(TOOLS.urllib.request, "urlopen", side_effect=AssertionError("unexpected download")):
            cached = TOOLS.download(url, self.target, "zip", len(self.payload), record)
        self.assertEqual(record, cached)
        self.assertEqual(server.requests, 1)
        self.assertEqual(self.target.stat().st_mtime_ns, modified)
        self.assertIn("using validated cached asset.zip", self.output.getvalue())
        self.assert_cleaned_up()


if __name__ == "__main__":
    unittest.main()
