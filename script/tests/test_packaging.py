"""Packaging contract tests; Docker commands are mocked, Compose parsing is optional.

Run from any directory: python -m unittest discover -s script/tests -p test_packaging.py -v
No images are built, imported, started, or pulled by these tests.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("binaryscan_packaging", REPO / "script/lib/build.py")
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)

SERVICE_IMAGES = {
    "mysql": "MYSQL_IMAGE",
    "app": "APP_IMAGE",
    "scanner": "SCANNER_IMAGE",
    "native-decompiler": "NATIVE_DECOMPILER_IMAGE",
    "jvm-decompiler": "JVM_DECOMPILER_IMAGE",
    "pyc-decompiler": "PYC_DECOMPILER_IMAGE",
    "c-checker": "C_CHECKER_IMAGE",
    "java-checker": "JAVA_CHECKER_IMAGE",
    "python-checker": "PYTHON_CHECKER_IMAGE",
}


class DockerDouble:
    """Models local images and archive export without an actual Docker daemon."""

    def __init__(self, test: "PackagingTests", *, real_compose: bool = False):
        self.test = test
        self.calls: list[list[str]] = []
        self.real_compose = real_compose
        self.missing: set[str] = set()
        self.fail_save = False
        self.bad_compose = False
        self.online_compose = False

    def __call__(self, args, *, capture=False, check=True, env=None):
        args = [str(item) for item in args]
        self.calls.append(args)
        result = ""
        code = 0
        if args[:2] == ["image", "inspect"]:
            ref = args[-1]
            if ref in self.missing:
                code = 1
            else:
                result = json.dumps({
                    "Id": "sha256:" + hashlib.sha256(ref.encode()).hexdigest(),
                    "Os": "linux",
                    "Architecture": "amd64",
                    "RepoTags": [ref],
                })
        elif args[:1] == ["info"]:
            result = "linux\n"
        elif args[:2] == ["compose", "version"]:
            result = "2.30.3\n"
        elif args[:1] == ["compose"] and "config" in args:
            if self.real_compose:
                return subprocess.run(
                    ["docker", *args], check=check, capture_output=True,
                    text=True, env=env,
                )
            config = BUILD.load_env(Path(args[args.index("--env-file") + 1]))
            services = {
                service: {"image": config[key], "pull_policy": "never"}
                for service, key in SERVICE_IMAGES.items()
            }
            if self.bad_compose:
                services["scanner"]["build"] = "."
            if self.online_compose:
                services["mysql"]["pull_policy"] = "always"
            result = json.dumps({"services": services})
        elif args[:1] == ["save"]:
            flag = "--output" if "--output" in args else "-o"
            output_index = args.index(flag) + 1
            archive = Path(args[output_index])
            archive.write_text("mock image archive\n" + "\n".join(args[output_index + 1:]), encoding="utf-8")
            if self.fail_save:
                raise RuntimeError("simulated docker save failure")
        elif args[:1] in (["run"], ["build"], ["pull"], ["version"]):
            pass
        else:
            raise AssertionError(f"Unexpected Docker invocation: {args!r}")
        completed = subprocess.CompletedProcess(["docker", *args], code, result, "" if code == 0 else "missing image")
        if check and code:
            raise subprocess.CalledProcessError(code, completed.args, completed.stdout, completed.stderr)
        return completed


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="binary packaging test ")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "source with spaces"
        self.repo.mkdir()
        shutil.copyfile(REPO / "docker-compose.yml", self.repo / "docker-compose.yml")
        shutil.copytree(REPO / "deploy/delivery", self.repo / "deploy/delivery")
        (self.repo / "deploy/docker").mkdir(parents=True)
        shutil.copyfile(REPO / "deploy/docker/images.lock.env", self.repo / "deploy/docker/images.lock.env")
        source = (REPO / "deploy/delivery/common/package.env").read_text(encoding="utf-8")
        source = (source.replace("__COMPOSE_PROJECT_NAME__", "source-project")
                  .replace("__MYSQL_PASSWORD__", "source-database-password")
                  .replace("__MYSQL_ROOT_PASSWORD__", "source-root-password")
                  .replace("__ADMIN_PASSWORD__", "source-admin-password"))
        (self.repo / ".env").write_text(source, encoding="utf-8")
        self.source_config = BUILD.load_env(self.repo / ".env")
        self.docker = DockerDouble(self)

    def build(self, mode="release", *, skip_build=True, docker=None):
        with mock.patch.object(BUILD, "docker", docker or self.docker):
            return BUILD.build_bundle(self.repo, mode, skip_build=skip_build)

    def assert_no_online_commands(self):
        self.assertFalse([args for args in self.docker.calls if args[0] in {"build", "pull"}])

    def assert_checksums(self, bundle):
        manifest = bundle / "manifests/package.sha256"
        self.assertTrue(manifest.is_file())
        files = []
        for line in manifest.read_text(encoding="utf-8").splitlines():
            expected, relative = line.split(maxsplit=1)
            relative = relative.lstrip("*")
            files.append(relative)
            content = (bundle / relative).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), expected, relative)
        self.assertIn("docker-compose.yml", files)
        self.assertIn("manifests/images.json", files)
        self.assertFalse(any(name.startswith("data/") for name in files))

    def test_release_exports_all_nine_images_and_integrity_metadata(self):
        bundle = self.build()
        self.assertEqual(bundle, self.repo / "release")
        archive = bundle / "images/runtime-images.tar"
        self.assertTrue(archive.is_file())
        save = next(args for args in self.docker.calls if args[0] == "save")
        for key in SERVICE_IMAGES.values():
            self.assertIn(self.source_config[key], save)
        self.assertEqual(len({ref for ref in save if ref in self.source_config.values()}), 9)
        self.assertEqual(
            hashlib.sha256(archive.read_bytes()).hexdigest(),
            Path(str(archive) + ".sha256").read_text().split()[0],
        )
        inventory = json.dumps(json.loads((bundle / "manifests/images.json").read_text(encoding="utf-8")))
        for key in SERVICE_IMAGES.values():
            self.assertIn(self.source_config[key], inventory)
        self.assertNotIn("source-database-password", inventory)
        self.assert_checksums(bundle)
        self.assert_no_online_commands()

    def test_default_build_uses_working_tree_for_all_eight_product_images(self):
        bundle = self.build(skip_build=False)
        builds = [args for args in self.docker.calls if args[0] == "build"]
        self.assertEqual(len(builds), 8)
        expected = set(self.source_config[key] for key in SERVICE_IMAGES.values() if key != "MYSQL_IMAGE")
        self.assertEqual({args[args.index("-t") + 1] for args in builds}, expected)
        for args in builds:
            dockerfile = Path(args[args.index("-f") + 1])
            context = Path(args[-1])
            self.assertTrue(dockerfile.is_relative_to(self.repo))
            self.assertTrue(context.is_relative_to(self.repo))
            self.assertEqual(args[args.index("--platform") + 1], "linux/amd64")
        inventory = json.loads((bundle / "manifests/images.json").read_text(encoding="utf-8"))
        self.assertTrue(inventory["source"]["built_from_working_tree"])

    def test_local_initializes_data_without_exporting_images(self):
        bundle = self.build("local")
        config = BUILD.load_env(bundle / ".env")
        self.assertEqual(bundle, self.repo / "local")
        self.assertEqual(config["BINARY_DATA_ROOT"], "./data")
        for relative in (
            "mysql", "storage/uploads", "storage/blobs", "storage/artifacts",
            "storage/reports", "storage/projects/native", "storage/projects/jvm",
            "storage/projects/pyc", "work/scanner", "work/native-decompiler",
            "work/jvm-decompiler", "work/pyc-decompiler",
        ):
            self.assertTrue((bundle / "data" / relative).is_dir(), relative)
        sentinel = (bundle / "data/.binaryscan-data-root").read_text().strip()
        self.assertEqual(sentinel, "binaryscan-data:" + config["COMPOSE_PROJECT_NAME"])
        self.assertFalse(any(args[0] == "save" for args in self.docker.calls))
        self.assertFalse((bundle / "images/runtime-images.tar").exists())
        self.assert_checksums(bundle)
        self.assert_no_online_commands()

    def test_custom_configuration_and_template_content_are_preserved(self):
        env_file = self.repo / ".env"
        custom = env_file.read_text(encoding="utf-8")
        replacements = {
            "APP_PORT=8080": "APP_PORT=19090",
            "APP_IMAGE=binaryscan/app:0.1.0-dev": "APP_IMAGE=private.example/binary-app:review",
            "MYSQL_DATABASE=binaryscan": "MYSQL_DATABASE=customer_scan",
            "MYSQL_USER=binaryscan": "MYSQL_USER=customer_user",
            "UPLOAD_MAX_BYTES=2147483648": "UPLOAD_MAX_BYTES=1073741824",
            "INITIAL_ADMIN_USERNAME=admin": "INITIAL_ADMIN_USERNAME=customer_admin",
        }
        for old, new in replacements.items():
            self.assertIn(old, custom)
            custom = custom.replace(old, new)
        env_file.write_text(custom, encoding="utf-8")
        template = self.repo / "deploy/delivery/common/manage.sh"
        template.write_text(template.read_text(encoding="utf-8") + "\n# delivery-template-marker\n", encoding="utf-8")
        bundle = self.build()
        generated = BUILD.load_env(bundle / ".env")
        for entry in replacements.values():
            key, expected = entry.split("=", 1)
            self.assertEqual(generated[key], expected)
        self.assertIn("delivery-template-marker", (bundle / "manage.sh").read_text(encoding="utf-8"))
        for key in ("MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD", "INITIAL_ADMIN_PASSWORD"):
            self.assertNotEqual(generated[key], self.source_config[key])
            self.assertGreaterEqual(len(generated[key]), 32)
        self.assertEqual(env_file.read_text(encoding="utf-8"), custom)

    def test_existing_output_and_runtime_data_are_not_overwritten(self):
        target = self.repo / "local"
        (target / "data/mysql").mkdir(parents=True)
        saved_data = target / "data/mysql/user-records"
        saved_data.write_bytes(b"preserve running customer data")
        with self.assertRaises(Exception):
            self.build("local")
        self.assertEqual(saved_data.read_bytes(), b"preserve running customer data")
        self.assertEqual(list(target.iterdir()), [target / "data"])
        self.assertEqual(self.docker.calls, [])

    def test_failed_archive_export_does_not_publish_partial_bundle(self):
        self.docker.fail_save = True
        with self.assertRaises(Exception):
            self.build()
        self.assertFalse((self.repo / "release").exists())
        self.assertEqual(list(self.repo.glob(".release-*")), [])
        self.assertEqual(BUILD.load_env(self.repo / ".env"), self.source_config)

    def test_skip_build_rejects_missing_runtime_image_without_pulling(self):
        self.docker.missing.add(self.source_config["PYTHON_CHECKER_IMAGE"])
        with self.assertRaises(Exception):
            self.build()
        self.assertFalse((self.repo / "release").exists())
        self.assert_no_online_commands()

    def test_compose_with_build_section_is_rejected(self):
        self.docker.bad_compose = True
        with self.assertRaises(Exception):
            self.build()
        self.assertFalse((self.repo / "release").exists())

    def test_compose_with_online_pull_policy_is_rejected(self):
        self.docker.online_compose = True
        with self.assertRaises(BUILD.BuildError):
            self.build()
        self.assertFalse((self.repo / "release").exists())

    def test_linux_data_initialization_uses_existing_scanner_without_network(self):
        with mock.patch.object(BUILD.sys, "platform", "linux"):
            bundle = self.build("local")
        helper = next(args for args in self.docker.calls if args[0] == "run")
        self.assertIn("--network=none", helper)
        self.assertIn("--pull=never", helper)
        self.assertIn(self.source_config["SCANNER_IMAGE"], helper)
        self.assertIn(self.source_config["PRODUCT_UID"], helper)
        self.assertIn(self.source_config["PRODUCT_GID"], helper)
        self.assertTrue((bundle / "data/storage/projects/native").is_dir())
        self.assert_no_online_commands()

    @unittest.skipUnless(shutil.which("docker"), "Docker CLI is unavailable")
    def test_generated_compose_parses_with_real_compose_cli(self):
        probe = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        if probe.returncode != 0:
            self.skipTest("Docker Compose v2 is unavailable")
        self.docker.real_compose = True
        for mode in ("local", "release"):
            with self.subTest(mode=mode):
                bundle = self.build(mode)
                env = {**os.environ, **BUILD.load_env(bundle / ".env")}
                parsed = subprocess.run(
                    ["docker", "compose", "--env-file", str(bundle / ".env"),
                     "-f", str(bundle / "docker-compose.yml"), "config", "--format", "json"],
                    check=True, capture_output=True, text=True, env=env,
                )
                services = json.loads(parsed.stdout)["services"]
                self.assertEqual(set(services), set(SERVICE_IMAGES))
                for service in services.values():
                    self.assertNotIn("build", service)
                    self.assertEqual(service["pull_policy"], "never")
                self.assertEqual(
                    {name for name, service in services.items() if service.get("ports")}, {"app"},
                )
        self.assert_no_online_commands()


if __name__ == "__main__":
    unittest.main()
