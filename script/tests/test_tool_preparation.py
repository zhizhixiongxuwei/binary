"""Offline tests for tool preparation; fixtures use file:// URLs and mocked Docker."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("binaryscan_tools", REPO / "script/tools/prepare-tools.py")
TOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOLS)


class ToolPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="binaryscan-tools-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def make_zip(self, destination, entries):
        with zipfile.ZipFile(destination, "w") as archive:
            for name, payload, mode in entries:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = mode << 16
                archive.writestr(entry, payload)
        return destination

    def make_tar(self, destination):
        with tarfile.open(destination, "w:gz") as archive:
            entry = tarfile.TarInfo("pycdc-source/README")
            entry.size = 7
            archive.addfile(entry, io.BytesIO(b"payload"))
        return destination

    def make_databases(self, root):
        for relative, filename, schema in (("db", "trivy.db", 2), ("java-db", "trivy-java.db", 1)):
            directory = root / relative
            directory.mkdir(parents=True, exist_ok=True)
            database = directory / filename
            if relative == "java-db":
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
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")

    def test_invalid_trivy_limits_fail_before_docker_or_tool_downloads(self):
        errors = io.StringIO()
        with mock.patch.object(sys, "argv", ["prepare-tools.py", "all", str(self.root / "cache")]), \
                mock.patch.object(TOOLS, "read_config", return_value={"TRIVY_DB_DOWNLOAD_TIMEOUT": "0m"}), \
                mock.patch.dict(TOOLS.os.environ, {}, clear=True), \
                mock.patch.object(TOOLS, "run") as run, \
                mock.patch.object(TOOLS, "download_tools") as download, \
                contextlib.redirect_stderr(errors):
            self.assertEqual(TOOLS.main(), 1)
        run.assert_not_called()
        download.assert_not_called()
        self.assertIn("TRIVY_DB_DOWNLOAD_TIMEOUT", errors.getvalue())

    def test_run_capture_returns_stdout_without_stderr_by_default(self):
        result = TOOLS.subprocess.CompletedProcess(
            ["docker", "info"], 0, stdout='{"OSType":"linux"}\n', stderr="diagnostic warning\n"
        )
        with mock.patch.object(TOOLS.subprocess, "run", return_value=result) as execute:
            output = TOOLS.run(["docker", "info"], capture=True)
        self.assertEqual(output, '{"OSType":"linux"}\n')
        self.assertEqual(execute.call_args.kwargs["stdout"], TOOLS.subprocess.PIPE)
        self.assertEqual(execute.call_args.kwargs["stderr"], TOOLS.subprocess.PIPE)

    def test_run_capture_can_merge_stdout_and_stderr_for_tool_banners(self):
        def execute(arguments, **options):
            self.assertEqual(options["stdout"], TOOLS.subprocess.PIPE)
            self.assertEqual(options["stderr"], TOOLS.subprocess.STDOUT)
            return TOOLS.subprocess.CompletedProcess(
                arguments, 0, stdout="startup banner\nCFR 0.152\n", stderr=None
            )

        with mock.patch.object(TOOLS.subprocess, "run", side_effect=execute):
            output = TOOLS.run(["docker", "run", "cfr"], capture=True, combine_output=True)
        self.assertEqual(output, "startup banner\nCFR 0.152\n")

    def test_run_capture_still_rejects_failed_exit_codes_with_combined_output(self):
        for combined in (False, True):
            with self.subTest(combined=combined):
                result = TOOLS.subprocess.CompletedProcess(
                    ["docker", "run"], 7,
                    stdout="version probe failed\n" if combined else "",
                    stderr=None if combined else "version probe failed\n",
                )
                errors = io.StringIO()
                with mock.patch.object(TOOLS.subprocess, "run", return_value=result), \
                        contextlib.redirect_stderr(errors), \
                        self.assertRaises(TOOLS.PreparationError) as failure:
                    TOOLS.run(["docker", "run"], capture=True, combine_output=combined)
                self.assertIn("exit 7", str(failure.exception))
                self.assertIn("version probe failed", errors.getvalue())

    def test_verify_tools_accepts_cfr_version_on_stderr_without_polluting_trivy_json(self):
        config = {
            "JVM_TOOLS_IMAGE": "jvm:test", "GHIDRA_RUNTIME_IMAGE": "ghidra:test",
            "PYCDC_TOOLS_IMAGE": "pycdc:test", "TRIVY_RUNTIME_DB_IMAGE": "trivy-bundled:test",
            "TRIVY_SOURCE_IMAGE": "trivy:0.74.0", "VINEFLOWER_VERSION": "1.11.2",
            "CFR_VERSION": "0.152", "JADX_VERSION": "1.5.6", "GHIDRA_VERSION": "12.1.3",
            "PYCDC_COMMIT": "0123456789abcdef",
        }
        images = {
            config[key]: {"Os": "linux", "Architecture": "amd64", "Config": {"Labels": {}}}
            for key in TOOLS.TOOL_KEYS
        }
        images[config["PYCDC_TOOLS_IMAGE"]]["Config"]["Labels"] = {
            "com.binaryscan.pycdc-commit": config["PYCDC_COMMIT"]
        }
        images[config["TRIVY_RUNTIME_DB_IMAGE"]]["Config"]["Labels"] = {
            "com.binaryscan.trivy-version": "0.74.0"
        }
        probes = []

        def execute(arguments, **options):
            probes.append(arguments)
            stdout, stderr = "", ""
            if config["JVM_TOOLS_IMAGE"] in arguments:
                self.assertEqual(options["stderr"], TOOLS.subprocess.STDOUT)
                if "/opt/bytecode-tools/cfr/cfr.jar" in arguments:
                    stderr = "CFR 0.152\n"
                elif "/opt/bytecode-tools/vineflower/vineflower.jar" in arguments:
                    stdout = "Vineflower 1.11.2\n"
                else:
                    self.assertIn("jadx.cli.JadxCLI", arguments)
                    stdout = "1.5.6\n"
            elif config["GHIDRA_RUNTIME_IMAGE"] in arguments:
                stdout = "application.version=12.1.3\n"
            elif config["PYCDC_TOOLS_IMAGE"] in arguments:
                stdout = "Usage: pycdc [options]\n"
            elif config["TRIVY_RUNTIME_DB_IMAGE"] in arguments:
                self.assertEqual(options["stderr"], TOOLS.subprocess.PIPE)
                stdout = json.dumps({
                    "Version": "0.74.0", "VulnerabilityDB": {"Version": 2}, "JavaDB": {"Version": 1}
                })
                stderr = "warning: diagnostic output must not enter JSON\n"
            else:
                self.fail("unexpected command: " + repr(arguments))
            if options["stderr"] == TOOLS.subprocess.STDOUT:
                stdout, stderr = stdout + stderr, None
            return TOOLS.subprocess.CompletedProcess(arguments, 0, stdout=stdout, stderr=stderr)

        with mock.patch.object(TOOLS, "require_platform", side_effect=lambda image: images[image]), \
                mock.patch.object(TOOLS.subprocess, "run", side_effect=execute):
            TOOLS.verify_tools(config)
        self.assertEqual(len(probes), 6)

    def test_download_cache_reuse_and_corruption_recovery(self):
        source = self.make_zip(self.root / "source.zip", [("file", b"payload", stat.S_IFREG | 0o644)])
        target = self.root / "cache/asset.zip"
        record = TOOLS.download(source.as_uri(), target, "zip", source.stat().st_size, None)
        self.assertEqual(record["sha256"], TOOLS.sha256(source))
        with mock.patch.object(TOOLS.urllib.request, "urlopen", side_effect=AssertionError("unexpected network")):
            self.assertEqual(TOOLS.download(source.as_uri(), target, "zip", 0, record), record)
        target.write_bytes(b"broken")
        TOOLS.download(source.as_uri(), target, "zip", 0, record)
        self.assertEqual(target.read_bytes(), source.read_bytes())
        self.make_zip(target, [("file", b"changed", stat.S_IFREG | 0o644)])
        TOOLS.download(source.as_uri(), target, "zip", 0, record)
        self.assertEqual(target.read_bytes(), source.read_bytes())

    def test_zip_rejects_unsafe_paths_and_bad_crc(self):
        path = self.root / "archive.zip"
        for filename in ("../escape", "/absolute", "C:/drive", "folder/../escape"):
            with self.subTest(filename=filename):
                self.make_zip(path, [(filename, b"payload", stat.S_IFREG | 0o644)])
                with self.assertRaises(TOOLS.PreparationError):
                    TOOLS.validate_archive(path, "zip")
        # ZipInfo normalizes backslashes on Windows; exercise the raw-path guard directly.
        with self.assertRaises(TOOLS.PreparationError):
            TOOLS.safe_member("folder\\escape")
        self.make_zip(path, [("file", b"payload", stat.S_IFREG | 0o644)])
        path.write_bytes(path.read_bytes().replace(b"payload", b"payloaX"))
        with self.assertRaises(TOOLS.PreparationError):
            TOOLS.validate_archive(path, "zip")

    def test_tar_rejects_corrupted_gzip_trailer(self):
        path = self.make_tar(self.root / "source.tar.gz")
        TOOLS.validate_archive(path, "tar")
        contents = bytearray(path.read_bytes())
        contents[-8] ^= 1
        path.write_bytes(contents)
        with self.assertRaises(TOOLS.PreparationError):
            TOOLS.validate_archive(path, "tar")

    def test_asset_layout_ghidra_modes_jadx_and_checksums(self):
        source = self.root / "source"
        source.mkdir()
        jar = io.BytesIO()
        self.make_zip(jar, [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", stat.S_IFREG | 0o644)])
        (source / "vineflower.jar").write_bytes(jar.getvalue())
        (source / "cfr.jar").write_bytes(jar.getvalue())
        self.make_zip(source / "jadx.zip", [("lib/jadx-1.5.6-all.jar", jar.getvalue(), stat.S_IFREG | 0o644)])
        self.make_zip(source / "ghidra.zip", [
            ("ghidra_12.1.3_PUBLIC/support/analyzeHeadless", b"#!/bin/sh\n", stat.S_IFREG | 0o755),
            ("ghidra_12.1.3_PUBLIC/readme", b"readme", stat.S_IFREG | 0o644),
            ("ghidra_12.1.3_PUBLIC/link", b"readme", stat.S_IFLNK | 0o777),
        ])
        self.make_tar(source / "source.tar.gz")
        config = {key: (source / filename).as_uri() for key, filename in (
            ("VINEFLOWER_URL", "vineflower.jar"), ("CFR_URL", "cfr.jar"), ("JADX_URL", "jadx.zip"),
            ("GHIDRA_URL", "ghidra.zip"), ("PYCDC_URL", "source.tar.gz"),
        )}
        config.update(JADX_ASSET_SIZE=str((source / "jadx.zip").stat().st_size),
                      GHIDRA_ASSET_SIZE=str((source / "ghidra.zip").stat().st_size))
        cache = self.root / "cache"
        TOOLS.download_tools(cache, config)
        self.assertEqual((cache / "ghidra/executable-files.txt").read_text(), "support/analyzeHeadless\n")
        self.assertEqual((cache / "jvm/jadx-all.jar").read_bytes(), jar.getvalue())
        checksums = (cache / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksums), 5)
        for line in checksums:
            digest, relative = line.split("  ", 1)
            self.assertEqual(digest, TOOLS.sha256(cache / relative))
        self.assertFalse((cache / "lib").exists())

    def test_only_complete_valid_database_pairs_are_reused(self):
        root = self.root / "databases"
        self.make_databases(root)
        self.assertTrue(TOOLS.valid_databases(root))
        invalid_contents = (
            ("java-db/metadata.json", b"{}"), ("db/metadata.json", b"{"),
            ("db/trivy.db", b"invalid-header" * 5), ("java-db/trivy-java.db", b""),
        )
        for relative, content in invalid_contents:
            with self.subTest(relative=relative, content=content):
                self.make_databases(root)
                (root / relative).write_bytes(content)
                self.assertFalse(TOOLS.valid_databases(root))
        self.make_databases(root)
        (root / "java-db/metadata.json").unlink()
        self.assertFalse(TOOLS.valid_databases(root))

    def test_sqlite_java_database_and_bbolt_vulnerability_database_are_accepted(self):
        root = self.root / "databases"
        self.make_databases(root)
        self.assertEqual((root / "java-db/trivy-java.db").read_bytes()[:16], b"SQLite format 3\x00")
        self.assertEqual((root / "db/trivy.db").read_bytes()[16:24], b"\xed\xda\x0c\xed\x02\x00\x00\x00")
        self.assertTrue(TOOLS.valid_database(root, "java-db", "trivy-java.db", 1))
        self.assertTrue(TOOLS.valid_database(root, "db", "trivy.db", 2))
        self.assertTrue(TOOLS.valid_databases(root))

    def test_bbolt_header_cannot_masquerade_as_java_database(self):
        root = self.root / "databases"
        self.make_databases(root)
        (root / "java-db/trivy-java.db").write_bytes((root / "db/trivy.db").read_bytes())
        self.assertFalse(TOOLS.valid_database(root, "java-db", "trivy-java.db", 1))
        self.assertTrue(TOOLS.valid_database(root, "db", "trivy.db", 2))
        self.assertFalse(TOOLS.valid_databases(root))

    def test_sqlite_database_cannot_masquerade_as_vulnerability_database(self):
        root = self.root / "databases"
        self.make_databases(root)
        (root / "db/trivy.db").write_bytes((root / "java-db/trivy-java.db").read_bytes())
        self.assertFalse(TOOLS.valid_database(root, "db", "trivy.db", 2))
        self.assertTrue(TOOLS.valid_database(root, "java-db", "trivy-java.db", 1))
        self.assertFalse(TOOLS.valid_databases(root))

    def test_truncated_or_damaged_sqlite_java_database_is_rejected(self):
        root = self.root / "databases"
        self.make_databases(root)
        database = root / "java-db/trivy-java.db"
        valid_bytes = database.read_bytes()
        corrupted = bytearray(valid_bytes)
        corrupted[100] = 0  # An invalid page type corrupts sqlite_schema's b-tree root.
        cases = {
            "header-only": valid_bytes[:16],
            "truncated-first-page": valid_bytes[:100],
            "damaged-schema-page": bytes(corrupted),
        }
        for kind, content in cases.items():
            with self.subTest(kind=kind):
                database.write_bytes(content)
                self.assertFalse(TOOLS.valid_database(root, "java-db", "trivy-java.db", 1))
                self.assertFalse(TOOLS.valid_databases(root))

    def test_sqlite_database_without_java_artifact_tables_is_rejected(self):
        root = self.root / "databases"
        self.make_databases(root)
        database = root / "java-db/trivy-java.db"
        database.unlink()
        with contextlib.closing(sqlite3.connect(database)) as connection:
            connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY, value TEXT)")
        self.assertEqual(database.read_bytes()[:16], b"SQLite format 3\x00")
        self.assertFalse(TOOLS.valid_database(root, "java-db", "trivy-java.db", 1))
        self.assertFalse(TOOLS.valid_databases(root))

    def test_sqlite_java_tables_missing_required_columns_are_rejected(self):
        root = self.root / "databases"
        self.make_databases(root)
        database = root / "java-db/trivy-java.db"
        definitions = (
            ("id INTEGER PRIMARY KEY, artifact_id TEXT",
             "artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT"),
            ("id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT",
             "artifact_id INTEGER, version TEXT, archive_type TEXT"),
        )
        for artifacts, indices in definitions:
            with self.subTest(artifacts=artifacts, indices=indices):
                database.unlink()
                with contextlib.closing(sqlite3.connect(database)) as connection:
                    connection.executescript(
                        "CREATE TABLE artifacts ({}); CREATE TABLE indices ({});".format(artifacts, indices)
                    )
                self.assertFalse(TOOLS.valid_database(root, "java-db", "trivy-java.db", 1))
                self.assertFalse(TOOLS.valid_databases(root))

    def test_wrong_image_platform_and_windows_engine_are_rejected(self):
        with self.assertRaises(TOOLS.PreparationError):
            TOOLS.require_platform("image", {"Os": "linux", "Architecture": "arm64"})
        TOOLS.require_platform("image", {"Os": "linux", "Architecture": "amd64"})
        with (mock.patch.object(sys, "argv", ["prepare-tools.py", "verify", str(self.root / "cache")]),
              mock.patch.object(TOOLS, "read_config", return_value={}),
              mock.patch.object(TOOLS, "run", return_value="windows\n"),
              mock.patch.object(TOOLS.shutil, "which", return_value="docker"),
              contextlib.redirect_stderr(io.StringIO()) as output):
            self.assertEqual(TOOLS.main(), 1)
        self.assertIn("Linux containers", output.getvalue())

    def test_shared_config_parser_supports_comments_and_rejects_interpolation(self):
        path = self.root / ".env"
        path.write_text("VALUE='literal$dollar' # comment\nSECOND=\"value\" # comment\n", encoding="utf-8")
        self.assertEqual(TOOLS.load_env(path), {"VALUE": "literal$dollar", "SECOND": "value"})
        for content in ("VALUE=${SECRET}", "VALUE=first\nVALUE=second", "invalid-line"):
            with self.subTest(content=content):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(TOOLS.BuildError):
                    TOOLS.load_env(path)

    def test_trivy_download_mounts_absolute_path_and_promotes_both_databases(self):
        commands = []

        def fake_run(command):
            commands.append(command)
            mount = command[command.index("--volume") + 1]
            self.assertTrue(mount.endswith(":/cache"))
            staging = Path(mount[:-len(":/cache")])
            self.assertTrue(staging.is_absolute())
            self.make_databases(staging)

        with mock.patch.object(TOOLS, "ensure_image"), mock.patch.object(TOOLS, "run", side_effect=fake_run):
            TOOLS.download_trivy_databases(self.root, {"TRIVY_SOURCE_IMAGE": "trivy:test"})
        self.assertEqual(len(commands), 2)
        self.assertIn("--download-db-only", commands[0])
        self.assertIn("--download-java-db-only", commands[1])
        self.assertTrue(all("--no-progress" not in command for command in commands))
        self.assertTrue(all("--tty" not in command for command in commands))
        self.assertTrue(TOOLS.valid_databases(self.root / "trivy"))

    def test_trivy_allocates_a_terminal_for_interactive_progress(self):
        commands = []

        def fake_run(command):
            commands.append(command)
            mount = command[command.index("--volume") + 1]
            self.make_databases(Path(mount[:-len(":/cache")]))

        with (mock.patch.object(TOOLS.sys.stdout, "isatty", return_value=True),
              mock.patch.object(TOOLS, "ensure_image"),
              mock.patch.object(TOOLS, "run", side_effect=fake_run)):
            TOOLS.download_trivy_databases(self.root, {"TRIVY_SOURCE_IMAGE": "trivy:test"})
        self.assertEqual(len(commands), 2)
        self.assertTrue(all("--tty" in command and "--no-progress" not in command for command in commands))


if __name__ == "__main__":
    unittest.main()
