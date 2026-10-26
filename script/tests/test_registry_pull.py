"""Registry failover contracts; all Docker calls and retry delays are mocked."""

from __future__ import annotations

from collections import deque
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("binary_registry_pull_tests", ROOT / "script/lib/build.py")
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
PRIMARY = "public.ecr.aws/docker/library/alpine:3.22.5"
FALLBACK = "docker.io/library/alpine:3.22.5"
PLATFORM = "linux/amd64"


class RegistryDocker:
    def __init__(self, *, local=None, results=None):
        self.images = dict(local or {})
        self.results = {ref: deque(values) for ref, values in (results or {}).items()}
        self.calls = []
        self.events = []

    def __call__(self, args, *, capture=False, check=True, **kwargs):
        self.calls.append(args)
        status, stdout, stderr = 0, "", ""
        if args[:2] == ["image", "inspect"]:
            ref = args[-1]
            if ref not in self.images:
                status, stderr = 1, "No such image"
            else:
                operating_system, architecture = self.images[ref].split("/")
                stdout = json.dumps({"Os": operating_system, "Architecture": architecture, "Id": "sha256:verified-image"})
        elif args[0] == "pull":
            self.events.append(("pull", args[-1]))
            self.assert_capture(capture, check)
            ref = args[-1]
            if ref not in self.results or not self.results[ref]:
                raise AssertionError(f"unexpected pull attempt: {args}")
            reason = self.results[ref].popleft()
            if reason:
                status, stderr = 1, reason
            else:
                self.images[ref] = args[args.index("--platform") + 1]
                stdout = f"Downloaded {ref}"
        elif args[0] == "tag":
            self.events.append(("tag", args[1], args[2]))
            self.images[args[2]] = self.images[args[1]]
        else:
            raise AssertionError(f"unexpected Docker invocation: {args}")
        return subprocess.CompletedProcess(["docker", *args], status, stdout, stderr)

    @staticmethod
    def assert_capture(capture, check):
        if not capture or check:
            raise AssertionError("pull errors must be captured for classification and diagnostics")


class RegistryPullTests(unittest.TestCase):
    def run_pull(self, docker, ref=PRIMARY):
        with mock.patch.object(BUILD, "docker", docker), mock.patch("time.sleep", side_effect=lambda delay: docker.events.append(("sleep", delay))), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return BUILD.pull_image(ref, PLATFORM)

    def test_reuses_correct_platform_local_image_without_network(self):
        docker = RegistryDocker(local={PRIMARY: PLATFORM})
        image = self.run_pull(docker)
        self.assertEqual(image["reference"], PRIMARY)
        self.assertEqual(docker.events, [])

    def test_reuses_local_official_fallback_and_restores_configured_tag(self):
        docker = RegistryDocker(local={FALLBACK: PLATFORM})
        image = self.run_pull(docker)
        self.assertEqual(image["reference"], PRIMARY)
        self.assertEqual(docker.events, [("tag", FALLBACK, PRIMARY)])
        self.assertEqual(docker.images[PRIMARY], PLATFORM)

    def test_wrong_platform_local_image_is_replaced(self):
        docker = RegistryDocker(local={PRIMARY: "linux/arm64"}, results={PRIMARY: [None]})
        image = self.run_pull(docker)
        self.assertEqual(image["platform"], PLATFORM)
        self.assertEqual(docker.events, [("pull", PRIMARY)])

    def test_rate_limited_primary_tries_fallback_before_any_delay(self):
        docker = RegistryDocker(results={PRIMARY: ["toomanyrequests: Rate exceeded"], FALLBACK: [None]})
        image = self.run_pull(docker)
        self.assertEqual(image["reference"], PRIMARY)
        self.assertEqual(docker.events, [("pull", PRIMARY), ("pull", FALLBACK), ("tag", FALLBACK, PRIMARY)])

    def test_transient_failures_retry_three_times_with_bounded_backoff(self):
        docker = RegistryDocker(results={
            PRIMARY: ["429 Too Many Requests"] * 3,
            FALLBACK: ["503 Service Unavailable", "connection reset by peer", None],
        })
        self.run_pull(docker)
        self.assertEqual(docker.events, [
            ("pull", PRIMARY), ("pull", FALLBACK), ("sleep", 5),
            ("pull", PRIMARY), ("pull", FALLBACK), ("sleep", 10),
            ("pull", PRIMARY), ("pull", FALLBACK), ("tag", FALLBACK, PRIMARY),
        ])

    def test_permanent_primary_error_is_not_retried_but_fallback_can_recover(self):
        docker = RegistryDocker(results={PRIMARY: ["manifest unknown"], FALLBACK: ["TLS handshake timeout", None]})
        self.run_pull(docker)
        self.assertEqual(docker.events, [("pull", PRIMARY), ("pull", FALLBACK), ("sleep", 5), ("pull", FALLBACK), ("tag", FALLBACK, PRIMARY)])

    def test_failure_lists_each_source_and_all_attempts(self):
        docker = RegistryDocker(results={PRIMARY: ["toomanyrequests: Rate exceeded"] * 3, FALLBACK: ["unauthorized: authentication required"]})
        with self.assertRaises(BUILD.BuildError) as raised:
            self.run_pull(docker)
        message = str(raised.exception)
        self.assertIn(PRIMARY, message)
        self.assertIn(FALLBACK, message)
        self.assertIn("Rate exceeded", message)
        self.assertIn("unauthorized", message)
        self.assertIn("attempt 3", message)
        self.assertEqual(docker.events.count(("pull", PRIMARY)), 3)
        self.assertEqual(docker.events.count(("pull", FALLBACK)), 1)

    def test_unknown_private_registry_never_falls_back(self):
        ref = "private.example.com/company/alpine:3.22.5"
        docker = RegistryDocker(results={ref: ["connection reset by peer"] * 3})
        with self.assertRaises(BUILD.BuildError):
            self.run_pull(docker, ref)
        self.assertEqual([event for event in docker.events if event[0] == "pull"], [("pull", ref)] * 3)

    def test_auth_and_missing_versions_are_not_retried(self):
        for reason in ("manifest unknown", "no matching manifest for linux/amd64", "unauthorized: authentication required", "denied: requested access to the resource is denied", "invalid reference format"):
            with self.subTest(reason=reason):
                ref = "docker.io/library/alpine:does-not-exist"
                docker = RegistryDocker(results={ref: [reason]})
                with self.assertRaises(BUILD.BuildError):
                    self.run_pull(docker, ref)
                self.assertEqual(docker.events, [("pull", ref)])

    def test_official_mapping_preserves_exact_tag_and_digest(self):
        suffix = "alpine:3.22.5@sha256:" + "a" * 64
        ref = "public.ecr.aws/docker/library/" + suffix
        fallback = "docker.io/library/" + suffix
        self.assertEqual(BUILD._official_registry_fallback(ref), fallback)
        docker = RegistryDocker(results={ref: ["429 Too Many Requests"], fallback: [None]})
        with self.assertRaisesRegex(BUILD.BuildError, "cannot safely alias a digest reference"):
            self.run_pull(docker, ref)
        self.assertEqual(docker.events, [("pull", ref), ("pull", fallback)])
        self.assertFalse(any(call[0] == "tag" for call in docker.calls))

    def test_direct_digest_pull_keeps_digest(self):
        ref = PRIMARY + "@sha256:" + "b" * 64
        docker = RegistryDocker(results={ref: [None]})
        image = self.run_pull(docker, ref)
        self.assertEqual(image["reference"], ref)
        self.assertEqual(docker.events, [("pull", ref)])

    def test_cached_fallback_digest_does_not_prevent_original_digest_pull(self):
        digest = "@sha256:" + "c" * 64
        ref, fallback = PRIMARY + digest, FALLBACK + digest
        docker = RegistryDocker(local={fallback: PLATFORM}, results={ref: [None]})
        image = self.run_pull(docker, ref)
        self.assertEqual(image["reference"], ref)
        self.assertEqual(docker.events, [("pull", ref)])

    def test_numeric_image_tag_is_not_mistaken_for_retryable_http_status(self):
        self.assertFalse(BUILD._retryable_registry_error("failed to resolve image docker.io/library/example:500: unsupported media type"))
        self.assertTrue(BUILD._retryable_registry_error("unexpected status code:503"))
        self.assertTrue(BUILD._retryable_registry_error("received unexpected HTTP status: 500"))

    def test_fallback_mapping_is_restricted_to_official_single_component_names(self):
        for ref in ("public.ecr.aws/customer/alpine:3.22.5", "public.ecr.aws/docker/library/custom/alpine:3.22.5", "docker.io/library/alpine:3.22.5", "public.ecr.aws.example.com/docker/library/alpine:3.22.5", "private.example.com/docker/library/alpine:3.22.5"):
            with self.subTest(ref=ref):
                self.assertIsNone(BUILD._official_registry_fallback(ref))

    def test_successful_pull_is_verified_before_it_can_be_used(self):
        docker = RegistryDocker(results={PRIMARY: [None]})
        self.run_pull(docker)
        self.assertEqual(docker.calls[-1], ["image", "inspect", "--format", "{{json .}}", PRIMARY])


if __name__ == "__main__":
    unittest.main()
