"""Exercise Trivy database timeout, retry and cache recovery without Docker or network."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("binaryscan_trivy_tools", REPO / "script/tools/prepare-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)

DBS = {
    "--download-db-only": ("db", "trivy.db", 2),
    "--download-java-db-only": ("java-db", "trivy-java.db", 1),
}


class TrivyDatabaseDownloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="binaryscan-trivy-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {"TRIVY_SOURCE_IMAGE": "trivy:test"}
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.enterContext(mock.patch.dict(TOOLS.os.environ))
        for key in ("TRIVY_DB_DOWNLOAD_TIMEOUT", "TRIVY_DB_DOWNLOAD_ATTEMPTS"):
            TOOLS.os.environ.pop(key, None)
        self.sleep = self.enterContext(mock.patch.object(TOOLS.time, "sleep"))
        self.ensure_image = self.enterContext(mock.patch.object(TOOLS, "ensure_image"))
        self.commands = []
        self.staging_paths = []

    def write_database(self, cache, argument):
        relative, filename, schema = DBS[argument]
        destination = cache / relative
        destination.mkdir(parents=True, exist_ok=True)
        database = destination / filename
        if argument == "--download-java-db-only":
            if database.exists():
                database.unlink()
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    "CREATE TABLE artifacts (id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT);"
                    "CREATE TABLE indices (artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT);"
                )
        else:
            database.write_bytes(bytes(16) + b"\xed\xda\x0c\xed\x02\x00\x00\x00" + bytes(8))
        metadata = {"Version": schema, "UpdatedAt": "2026-10-23T00:00:00Z", "NextUpdate": "2026-10-24T00:00:00Z"}
        (destination / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    def write_pair(self, cache):
        for argument in DBS:
            self.write_database(cache, argument)

    def inspect_command(self, command):
        self.commands.append(list(command))
        self.assertEqual(command[:2], ["docker", "run"])
        self.assertIn("--rm", command)
        self.assertIn("--platform", command)
        self.assertEqual(command[command.index("--platform") + 1], "linux/amd64")
        mount = command[command.index("--volume") + 1]
        self.assertTrue(mount.endswith(":/cache"))
        staging = Path(mount[:-len(":/cache")])
        self.assertTrue(staging.is_absolute())
        self.assertNotIn(staging, self.staging_paths, "each attempt must receive a fresh cache directory")
        self.assertFalse(list(staging.iterdir()), "a retry must not consume a partial database")
        self.staging_paths.append(staging)
        arguments = [argument for argument in DBS if argument in command]
        self.assertEqual(len(arguments), 1)
        return staging, arguments[0]

    def successful_run(self, command):
        staging, argument = self.inspect_command(command)
        self.write_database(staging, argument)

    def assert_temporary_directories_removed(self, cache=None):
        self.assertFalse(list((cache or self.root).glob(".trivy-*")))
        self.assertTrue(all(not path.exists() for path in self.staging_paths))

    def assert_timeout(self, expected):
        self.assertTrue(self.commands)
        for command in self.commands:
            self.assertIn("--timeout", command)
            self.assertEqual(command[command.index("--timeout") + 1], expected)

    def test_default_timeout_is_explicit_for_both_databases(self):
        with mock.patch.object(TOOLS, "run", side_effect=self.successful_run):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 2)
        self.assertIn("--download-db-only", self.commands[0])
        self.assertIn("--download-java-db-only", self.commands[1])
        self.assert_timeout("60m")
        self.assertTrue(all("--no-progress" not in command for command in self.commands))
        self.assertTrue(TOOLS.valid_databases(self.root / "trivy"))
        self.assert_temporary_directories_removed()

    def test_configuration_controls_timeout_and_attempt_limit(self):
        self.config.update(TRIVY_DB_DOWNLOAD_TIMEOUT="25m", TRIVY_DB_DOWNLOAD_ATTEMPTS="1")

        def fail(command):
            self.inspect_command(command)
            raise TOOLS.PreparationError("docker failed (exit 1)")

        with mock.patch.object(TOOLS, "run", side_effect=fail), self.assertRaises(TOOLS.PreparationError):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 1)
        self.assert_timeout("25m")
        self.sleep.assert_not_called()
        self.assert_temporary_directories_removed()

    def test_environment_overrides_configuration_for_timeout_and_attempt_limit(self):
        self.config.update(TRIVY_DB_DOWNLOAD_TIMEOUT="25m", TRIVY_DB_DOWNLOAD_ATTEMPTS="1")
        TOOLS.os.environ.update(TRIVY_DB_DOWNLOAD_TIMEOUT="90m", TRIVY_DB_DOWNLOAD_ATTEMPTS="2")

        def retry_once(command):
            staging, argument = self.inspect_command(command)
            if len(self.commands) == 1:
                raise TOOLS.PreparationError("docker failed (exit 1)")
            self.write_database(staging, argument)

        with mock.patch.object(TOOLS, "run", side_effect=retry_once):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 3)
        self.assert_timeout("90m")
        self.assertTrue(TOOLS.valid_databases(self.root / "trivy"))
        self.assert_temporary_directories_removed()

    def test_invalid_configuration_fails_before_any_docker_operation(self):
        invalid = {
            "TRIVY_DB_DOWNLOAD_TIMEOUT": ("", "0m", "-1m", "5", "abc"),
            "TRIVY_DB_DOWNLOAD_ATTEMPTS": ("", "0", "6", "-1", "1.5", "abc"),
        }
        for key, values in invalid.items():
            for value in values:
                with self.subTest(key=key, value=value), mock.patch.object(TOOLS, "run") as run:
                    config = dict(self.config, **{key: value})
                    with self.assertRaises(TOOLS.PreparationError) as failure:
                        TOOLS.download_trivy_databases(self.root, config)
                    self.assertIn(key, str(failure.exception))
                    run.assert_not_called()
                    self.ensure_image.assert_not_called()

    def test_invalid_environment_is_rejected_instead_of_falling_back_to_configuration(self):
        self.config.update(TRIVY_DB_DOWNLOAD_TIMEOUT="60m", TRIVY_DB_DOWNLOAD_ATTEMPTS="3")
        for key in ("TRIVY_DB_DOWNLOAD_TIMEOUT", "TRIVY_DB_DOWNLOAD_ATTEMPTS"):
            with self.subTest(key=key), mock.patch.dict(TOOLS.os.environ, {key: "invalid"}):
                with mock.patch.object(TOOLS, "run") as run, self.assertRaises(TOOLS.PreparationError):
                    TOOLS.download_trivy_databases(self.root, self.config)
                run.assert_not_called()
                self.ensure_image.assert_not_called()

    def test_retry_discards_partial_database_then_promotes_valid_result(self):
        def retry_once(command):
            staging, argument = self.inspect_command(command)
            if len(self.commands) == 1:
                (staging / "db").mkdir()
                (staging / "db/trivy.db").write_bytes(b"partial download")
                raise TOOLS.PreparationError("docker failed (exit 1)")
            self.write_database(staging, argument)

        with mock.patch.object(TOOLS, "run", side_effect=retry_once):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 3)
        self.assertTrue(TOOLS.valid_databases(self.root / "trivy"))
        self.assert_temporary_directories_removed()

    def test_default_retry_limit_is_three_and_failed_attempts_leave_no_partial_cache(self):
        def fail(command):
            staging, _argument = self.inspect_command(command)
            (staging / "db").mkdir()
            (staging / "db/trivy.db").write_bytes(b"partial download")
            raise TOOLS.PreparationError("docker failed (exit 1)")

        with mock.patch.object(TOOLS, "run", side_effect=fail), self.assertRaises(TOOLS.PreparationError):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 3)
        self.assertTrue(all("--download-db-only" in command for command in self.commands))
        self.assertFalse((self.root / "trivy/db/trivy.db").exists())
        self.assertFalse(TOOLS.valid_databases(self.root / "trivy"))
        self.assert_temporary_directories_removed()

    def test_java_failure_keeps_completed_vulnerability_database_for_next_run(self):
        def fail_java(command):
            staging, argument = self.inspect_command(command)
            if argument == "--download-java-db-only":
                (staging / "java-db").mkdir()
                (staging / "java-db/trivy-java.db").write_bytes(b"partial Java download")
                raise TOOLS.PreparationError("docker failed (exit 1)")
            self.write_database(staging, argument)

        with mock.patch.object(TOOLS, "run", side_effect=fail_java), self.assertRaises(TOOLS.PreparationError):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 4)
        database = self.root / "trivy/db/trivy.db"
        self.assertTrue(database.is_file())
        before = (database.read_bytes(), database.stat().st_mtime_ns)
        self.assertFalse(TOOLS.valid_databases(self.root / "trivy"))
        self.assert_temporary_directories_removed()
        self.commands.clear()
        with mock.patch.object(TOOLS, "run", side_effect=self.successful_run):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 1)
        self.assertIn("--download-java-db-only", self.commands[0])
        self.assertEqual((database.read_bytes(), database.stat().st_mtime_ns), before)
        self.assertTrue(TOOLS.valid_databases(self.root / "trivy"))
        self.assert_temporary_directories_removed()

    def test_complete_valid_cache_needs_no_docker_image_or_download(self):
        self.write_pair(self.root / "trivy")
        before = {path.relative_to(self.root): path.stat().st_mtime_ns
                  for path in (self.root / "trivy").rglob("*") if path.is_file()}
        with mock.patch.object(TOOLS, "run") as run:
            TOOLS.download_trivy_databases(self.root, self.config)
        run.assert_not_called()
        self.ensure_image.assert_not_called()
        after = {path.relative_to(self.root): path.stat().st_mtime_ns
                 for path in (self.root / "trivy").rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assert_temporary_directories_removed()

    def test_downloaded_sqlite_java_database_is_cached_and_reused_without_docker(self):
        with mock.patch.object(TOOLS, "run", side_effect=self.successful_run):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 2)
        java_database = self.root / "trivy/java-db/trivy-java.db"
        self.assertEqual(java_database.read_bytes()[:16], b"SQLite format 3\x00")
        self.assertTrue(TOOLS.valid_databases(self.root / "trivy"))
        before = (java_database.read_bytes(), java_database.stat().st_mtime_ns)
        self.ensure_image.reset_mock()
        with mock.patch.object(TOOLS, "run", side_effect=AssertionError("unexpected Docker operation")) as run:
            TOOLS.download_trivy_databases(self.root, self.config)
        run.assert_not_called()
        self.ensure_image.assert_not_called()
        self.assertEqual((java_database.read_bytes(), java_database.stat().st_mtime_ns), before)
        self.assert_temporary_directories_removed()

    def test_corrupt_database_is_replaced_without_redownloading_other_valid_database(self):
        cases = (
            ("db/trivy.db", b"wrong bbolt magic" * 3, "--download-db-only"),
            ("db/metadata.json", b"{", "--download-db-only"),
            ("java-db/trivy-java.db", b"short", "--download-java-db-only"),
            ("java-db/metadata.json", b'{"Version":99,"UpdatedAt":"2026-10-23","NextUpdate":"2026-10-24"}',
             "--download-java-db-only"),
            ("java-db/metadata.json", None, "--download-java-db-only"),
        )
        for index, (relative, content, expected_argument) in enumerate(cases):
            with self.subTest(relative=relative, content=content):
                cache = self.root / str(index)
                self.write_pair(cache / "trivy")
                target = cache / "trivy" / relative
                if content is None:
                    target.unlink()
                else:
                    target.write_bytes(content)
                self.commands.clear()
                with mock.patch.object(TOOLS, "run", side_effect=self.successful_run):
                    TOOLS.download_trivy_databases(cache, self.config)
                self.assertEqual(len(self.commands), 1)
                self.assertIn(expected_argument, self.commands[0])
                self.assertTrue(TOOLS.valid_databases(cache / "trivy"))
                self.assert_temporary_directories_removed(cache)

    def test_docker_success_with_invalid_database_is_retried_before_promotion(self):
        def incomplete_once(command):
            staging, argument = self.inspect_command(command)
            self.write_database(staging, argument)
            if len(self.commands) == 1:
                (staging / "db/metadata.json").write_text("{}", encoding="utf-8")

        with mock.patch.object(TOOLS, "run", side_effect=incomplete_once):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 3)
        self.assertTrue(TOOLS.valid_databases(self.root / "trivy"))
        self.assert_temporary_directories_removed()

    def test_keyboard_interrupt_is_not_retried_and_cleans_partial_download(self):
        def interrupt(command):
            staging, _argument = self.inspect_command(command)
            (staging / "db").mkdir()
            (staging / "db/trivy.db").write_bytes(b"partial download")
            raise KeyboardInterrupt

        with mock.patch.object(TOOLS, "run", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            TOOLS.download_trivy_databases(self.root, self.config)
        self.assertEqual(len(self.commands), 1)
        self.sleep.assert_not_called()
        self.assertFalse((self.root / "trivy/db/trivy.db").exists())
        self.assert_temporary_directories_removed()


if __name__ == "__main__":
    unittest.main()
