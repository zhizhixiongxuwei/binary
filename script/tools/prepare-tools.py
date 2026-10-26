#!/usr/bin/env python3
"""Prepare pinned tool images using Python's standard library and Docker."""

import argparse
import contextlib
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
import zlib


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "script/lib"))
from build import BuildError, load_env, pull_image

PLATFORM = "linux/amd64"
TOOL_KEYS = ("JVM_TOOLS_IMAGE", "GHIDRA_RUNTIME_IMAGE", "PYCDC_TOOLS_IMAGE", "TRIVY_RUNTIME_DB_IMAGE")
DOWNLOAD_TIMEOUT = 120
DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_BUFFER_SIZE = 64 * 1024
PROGRESS_INTERVAL = 1.0
LOG_PROGRESS_INTERVAL = 5.0
TRIVY_DATABASES = (
    ("db", "trivy.db", 2, "--download-db-only", "vulnerability database"),
    ("java-db", "trivy-java.db", 1, "--download-java-db-only", "Java database"),
)


class PreparationError(Exception):
    pass


def note(message):
    print("==> " + message, flush=True)


def format_bytes(value):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return "{:.1f} {}".format(value, unit)
        value /= 1024


def format_duration(seconds):
    seconds = max(0, int(seconds))
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return ("{}:{:02d}:{:02d}".format(hours, minutes, seconds) if hours
            else "{:02d}:{:02d}".format(minutes, seconds))


class DownloadProgress:
    """Report even while urlopen/read is blocked; never wait for a full MiB."""

    def __init__(self, name, total=0, stream=None, interval=None):
        self.name = name
        self.total = total
        self.stream = stream if stream is not None else sys.stdout
        self.terminal = self.stream.isatty()
        self.interval = interval if interval is not None else (
            PROGRESS_INTERVAL if self.terminal else LOG_PROGRESS_INTERVAL)
        self.received = 0
        self.connected = False
        self.started = self.updated = self.reported = time.monotonic()
        self.reported_bytes = 0
        self.line_width = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, name="download-progress", daemon=True)

    def __enter__(self):
        self._report()
        self._thread.start()
        return self

    def set_total(self, total):
        with self._lock:
            self.total = total
            self.connected = True
            self.updated = time.monotonic()

    def advance(self, size):
        with self._lock:
            self.received += size
            self.updated = time.monotonic()

    def _watch(self):
        while not self._stop.wait(self.interval):
            self._report()

    def _report(self, status=None):
        now = time.monotonic()
        with self._lock:
            received, total = self.received, self.total
            idle, connected = now - self.updated, self.connected
        elapsed = now - self.started
        speed = (received - self.reported_bytes) / max(now - self.reported, 0.001)
        self.reported, self.reported_bytes = now, received
        if total:
            fraction = min(received / total, 1)
            filled = int(fraction * 16)
            amount = "[{}{}] {:5.1f}% {}/{}".format(
                "#" * filled, "-" * (16 - filled), fraction * 100,
                format_bytes(received), format_bytes(total))
        else:
            amount = "{} / unknown size".format(format_bytes(received))
        eta = format_duration((total - received) / speed) if total and speed > 0 else "--:--"
        if status == "downloaded":
            speed = received / max(elapsed, 0.001)
            eta = "00:00"
        message = "  {} {} | {}/s | ETA {} | elapsed {}".format(
            self.name, amount, format_bytes(speed), eta, format_duration(elapsed))
        if status:
            message += " | " + status
        elif not connected:
            message = "  {} connecting | elapsed {} | socket timeout {}s".format(
                self.name, format_duration(elapsed), DOWNLOAD_TIMEOUT)
        elif idle >= 5:
            message += " | waiting for data {:.0f}s".format(idle)
        if self.terminal:
            # Avoid wrapping a carriage-return progress line in small terminals.
            width = max(20, shutil.get_terminal_size(fallback=(120, 24)).columns - 1)
            if len(message) > width:
                if connected and not status and idle >= 5:
                    message = "  {} waiting for data {:.0f}s | {} | elapsed {}".format(
                        self.name, idle, format_bytes(received), format_duration(elapsed))
                else:
                    message = message.replace(" | elapsed " + format_duration(elapsed), "")
                message = message[:width]
            self.line_width = min(self.line_width, width)
            self.stream.write("\r" + message.ljust(self.line_width) + ("\n" if status else ""))
            self.line_width = len(message)
        else:
            self.stream.write(message + "\n")
        self.stream.flush()

    def __exit__(self, exception_type, exception, traceback):
        self._stop.set()
        self._thread.join()
        status = "downloaded" if exception_type is None else (
            "interrupted" if issubclass(exception_type, KeyboardInterrupt) else "failed")
        self._report(status)


def download_error_reason(error):
    """Describe the failure without exposing signed URLs, credentials or proxies."""
    if isinstance(error, urllib.error.HTTPError):
        return "HTTP {}".format(error.code)
    cause = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(cause, TimeoutError):
        return "connection/read timed out ({}s socket timeout)".format(DOWNLOAD_TIMEOUT)
    if isinstance(error, PreparationError):
        return str(error)
    if isinstance(cause, str):
        return "network connection failed"
    return type(cause).__name__


def read_config():
    values = {}
    for path in (REPO / ".env", REPO / "deploy/docker/images.lock.env"):
        if not path.is_file():
            raise PreparationError("missing configuration file: " + str(path))
        try:
            values.update(load_env(path))
        except BuildError as error:
            raise PreparationError(str(error)) from error
    if values.get("BINARY_PLATFORM", PLATFORM) != PLATFORM:
        raise PreparationError("tool images require BINARY_PLATFORM=" + PLATFORM)
    required = TOOL_KEYS + (
        "JAVA_RUNTIME_IMAGE", "GHIDRA_JDK_IMAGE", "PYCDC_BUILD_IMAGE", "PYCDC_RUNTIME_IMAGE",
        "TRIVY_SOURCE_IMAGE", "GHIDRA_VERSION", "VINEFLOWER_VERSION", "CFR_VERSION", "JADX_VERSION",
        "PYCDC_COMMIT", "VINEFLOWER_URL", "CFR_URL", "JADX_URL", "GHIDRA_URL", "PYCDC_URL",
        "JADX_ASSET_SIZE", "GHIDRA_ASSET_SIZE",
    )
    for key in required:
        if not values.get(key):
            raise PreparationError("missing configuration key: " + key)
    for key in ("JADX_ASSET_SIZE", "GHIDRA_ASSET_SIZE"):
        if not values[key].isdigit() or int(values[key]) < 1:
            raise PreparationError("invalid positive size: " + key)
    return values


def run(arguments, capture=False, *, combine_output=False):
    result = subprocess.run(arguments, check=False, text=True, encoding="utf-8", errors="replace",
                            stdout=subprocess.PIPE if capture else None,
                            stderr=(subprocess.STDOUT if combine_output else subprocess.PIPE) if capture else None)
    if result.returncode:
        details = result.stdout if combine_output else result.stderr
        if capture and details:
            print(details.strip(), file=sys.stderr)
        raise PreparationError("{} failed (exit {})".format(arguments[0], result.returncode))
    return result.stdout or ""


def image_details(image):
    result = subprocess.run(["docker", "image", "inspect", "--format", "{{json .}}", image],
                            check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        return None
    try:
        details = json.loads(result.stdout)
        if not isinstance(details, dict):
            raise ValueError("expected image metadata object")
        return details
    except ValueError as error:
        raise PreparationError("Docker returned invalid image metadata") from error


def require_platform(image, details=None):
    details = details if details is not None else image_details(image)
    if details is None:
        raise PreparationError("tool image is not loaded: " + image)
    if details.get("Os") != "linux" or details.get("Architecture") != "amd64":
        raise PreparationError("image must target {}: {}".format(PLATFORM, image))
    return details


def ensure_image(image):
    details = image_details(image)
    if details and details.get("Os") == "linux" and details.get("Architecture") == "amd64":
        note("using loaded image " + image)
        return
    try:
        pull_image(image, PLATFORM)
    except BuildError as error:
        raise PreparationError(str(error)) from error
    require_platform(image)


def safe_member(name):
    path = PurePosixPath(name)
    if (not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name
            or any(ord(character) < 32 for character in name) or ".." in path.parts):
        raise PreparationError("archive contains an unsafe member path")
    return path


def validate_archive(path, kind, expected_size=0):
    if not path.is_file() or path.stat().st_size == 0:
        raise PreparationError("asset is missing or empty: " + path.name)
    if expected_size and path.stat().st_size != expected_size:
        raise PreparationError("asset size does not match images.lock.env: " + path.name)
    try:
        if kind == "zip":
            with zipfile.ZipFile(path) as archive:
                if not archive.infolist():
                    raise PreparationError("archive is empty: " + path.name)
                for item in archive.infolist():
                    safe_member(item.filename)
                if archive.testzip() is not None:
                    raise PreparationError("ZIP checksum check failed: " + path.name)
        else:
            with tarfile.open(path, "r:gz") as archive:
                count = 0
                for item in archive:
                    count += 1
                    member_path = safe_member(item.name)
                    if item.isfile():
                        with archive.extractfile(item) as source:
                            while source.read(1024 * 1024):
                                pass
                    elif item.issym() or item.islnk():
                        target = safe_member(item.linkname)
                        if item.issym():
                            safe_member(str(member_path.parent / target))
                    elif not item.isdir():
                        raise PreparationError("archive contains a special file: " + path.name)
                if not count:
                    raise PreparationError("archive is empty: " + path.name)
            # Reading through EOF also checks gzip's trailer, which tar's end marker can precede.
            with gzip.open(path, "rb") as source:
                while source.read(1024 * 1024):
                    pass
    except (OSError, EOFError, ValueError, RuntimeError, zipfile.BadZipFile, tarfile.TarError, zlib.error) as error:
        raise PreparationError("archive integrity check failed: " + path.name) from error


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".prepare-", dir=str(path.parent))
    try:
        with os.fdopen(handle, "wb") as destination:
            destination.write(data)
        # Legacy prepare-tools.sh cached assets may be read-only on Windows.
        if path.exists():
            path.chmod(stat.S_IREAD | stat.S_IWRITE)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def download(url, path, kind, expected_size, previous):
    source_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
    if path.is_file() and (not previous or previous.get("source_sha256") == source_hash):
        try:
            note("validating cached " + path.name + " (archive integrity + SHA-256)")
            validate_archive(path, kind, expected_size)
            digest = sha256(path)
            if previous and previous.get("sha256") != digest:
                raise PreparationError("cached checksum mismatch")
            note("using validated cached " + path.name)
            return {"sha256": digest, "size": path.stat().st_size, "source_sha256": source_hash}
        except PreparationError:
            note("replacing invalid cached " + path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(DOWNLOAD_ATTEMPTS):
        note("downloading {} (attempt {}/{}, socket timeout {}s)".format(
            path.name, attempt + 1, DOWNLOAD_ATTEMPTS, DOWNLOAD_TIMEOUT))
        handle, temporary = tempfile.mkstemp(prefix=".download-", dir=str(path.parent))
        temporary = Path(temporary)
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "BinaryScan-tool-preparation/1.0"})
            with os.fdopen(handle, "wb") as destination:
                with DownloadProgress(path.name, expected_size) as progress, \
                        urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as source:
                    content_length = source.headers.get("Content-Length")
                    response_size = int(content_length) if content_length and content_length.isdigit() else 0
                    progress.set_total(expected_size or response_size)
                    total = 0
                    # HTTPResponse.read1 returns available bytes instead of waiting
                    # to fill a large buffer on a slow connection. file:// also works.
                    read = getattr(source, "read1", source.read)
                    for block in iter(lambda: read(DOWNLOAD_BUFFER_SIZE), b""):
                        total += len(block)
                        if expected_size and total > expected_size:
                            raise PreparationError("download exceeds pinned size: " + path.name)
                        destination.write(block)
                        progress.advance(len(block))
                    if response_size and total != response_size:
                        raise PreparationError("incomplete download: " + path.name)
            note("validating " + path.name + " (archive integrity + SHA-256)")
            validate_archive(temporary, kind, expected_size)
            digest = sha256(temporary)
            if path.exists():
                path.chmod(stat.S_IREAD | stat.S_IWRITE)
            os.replace(temporary, path)
            note("ready " + path.name + " (" + format_bytes(path.stat().st_size) + ")")
            return {"sha256": digest, "size": path.stat().st_size, "source_sha256": source_hash}
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException, PreparationError) as error:
            reason = download_error_reason(error)
            if isinstance(error, urllib.error.HTTPError):
                # HTTPError also owns the rejected response body/socket. It is
                # raised before the response context manager can close it.
                error.close()
            if attempt == DOWNLOAD_ATTEMPTS - 1:
                # Avoid printing URLs, which could contain authentication data.
                raise PreparationError("download/validation failed for {} after {} attempts: {}".format(
                    path.name, DOWNLOAD_ATTEMPTS, reason)) from error
            note("{} failed: {}; retrying in 2s from the beginning".format(path.name, reason))
            time.sleep(2)
        finally:
            if temporary.exists():
                temporary.unlink()


def download_tools(cache, config):
    manifest_path = cache / "download-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
        if not isinstance(manifest, dict) or any(not isinstance(entry, dict) for entry in manifest.values()):
            raise ValueError("invalid manifest")
    except (OSError, ValueError) as error:
        raise PreparationError("invalid download-manifest.json; remove it and retry") from error
    assets = (
        ("VINEFLOWER_URL", "jvm/vineflower.jar", "zip", 0),
        ("CFR_URL", "jvm/cfr.jar", "zip", 0),
        ("JADX_URL", "jvm/jadx.zip", "zip", int(config["JADX_ASSET_SIZE"])),
        ("GHIDRA_URL", "ghidra/ghidra.zip", "zip", int(config["GHIDRA_ASSET_SIZE"])),
        ("PYCDC_URL", "pycdc/source.tar.gz", "tar", 0),
    )
    for key, relative, kind, size in assets:
        manifest[relative] = download(config[key], cache / relative, kind, size, manifest.get(relative))
        atomic_write(manifest_path, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    atomic_write(cache / "SHA256SUMS", "".join("{}  {}\n".format(manifest[relative]["sha256"], relative)
                 for _, relative, _, _ in assets).encode())

    with zipfile.ZipFile(cache / "ghidra/ghidra.zip") as archive:
        executable_files = []
        roots = set()
        for item in archive.infolist():
            parts = safe_member(item.filename).parts
            roots.add(parts[0])
            mode = item.external_attr >> 16
            if len(parts) > 1 and stat.S_ISREG(mode) and (mode & stat.S_IXUSR):
                executable_files.append("/".join(parts[1:]))
        if len(roots) != 1 or not next(iter(roots)).startswith("ghidra_") or not executable_files:
            raise PreparationError("Ghidra archive has an unexpected layout or no executables")
        atomic_write(cache / "ghidra/executable-files.txt", ("\n".join(sorted(executable_files)) + "\n").encode())
    with zipfile.ZipFile(cache / "jvm/jadx.zip") as archive:
        jars = [item for item in archive.infolist() if not item.is_dir()
                and re.fullmatch(r"jadx-.+-all\.jar", PurePosixPath(item.filename).name)]
        if len(jars) != 1:
            raise PreparationError("JADX archive must contain exactly one jadx-*-all.jar")
        output = cache / "jvm/jadx-all.jar"
        handle, temporary = tempfile.mkstemp(prefix=".jadx-", dir=str(output.parent))
        try:
            with os.fdopen(handle, "wb") as destination, archive.open(jars[0]) as source:
                shutil.copyfileobj(source, destination, 1024 * 1024)
            validate_archive(Path(temporary), "zip")
            if output.exists():
                output.chmod(stat.S_IREAD | stat.S_IWRITE)
            os.replace(temporary, output)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    note("official tool assets and SHA256SUMS are ready in " + str(cache))


def database_validation_error(cache, relative, filename, schema):
    """Return a diagnostic for invalid metadata or storage format, otherwise None."""
    directory = cache / relative
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        if (not isinstance(metadata, dict) or metadata.get("Version") != schema
                or not metadata.get("UpdatedAt") or not metadata.get("NextUpdate")):
            return "metadata.json must contain Version={}, UpdatedAt and NextUpdate".format(schema)
        database = directory / filename
        if not database.is_file() or database.stat().st_size < 32:
            return filename + " is missing or truncated"
        with database.open("rb") as source:
            header = source.read(32)
        if relative == "java-db":
            # Trivy's Java index uses SQLite; only the vulnerability DB is bbolt.
            if header[:16] != b"SQLite format 3\x00":
                return filename + " must be a SQLite database"
            # Open read-only and inspect the schema without scanning a multi-GiB DB.
            uri = database.resolve().as_uri() + "?mode=ro"
            with contextlib.closing(sqlite3.connect(uri, uri=True)) as connection:
                for table, required in (
                    ("artifacts", {"id", "group_id", "artifact_id"}),
                    ("indices", {"artifact_id", "version", "sha1", "archive_type"}),
                ):
                    if connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
                    ).fetchone() is None:
                        return filename + " is missing the SQLite table " + table
                    columns = {row[1] for row in connection.execute("PRAGMA table_info({})".format(table))}
                    missing = required - columns
                    if missing:
                        return "{} table {} is missing columns: {}".format(filename, table, ", ".join(sorted(missing)))
            return None
        # bbolt magic and format version in the first metadata page.
        if header[16:24] != b"\xed\xda\x0c\xed\x02\x00\x00\x00":
            return filename + " must be a bbolt database"
    except (OSError, ValueError, sqlite3.Error) as error:
        return "{}: {}".format(filename, error)
    return None


def valid_database(cache, relative, filename, schema):
    return database_validation_error(cache, relative, filename, schema) is None


def valid_databases(cache):
    return all(valid_database(cache, relative, filename, schema)
               for relative, filename, schema, _, _ in TRIVY_DATABASES)


def trivy_download_settings(config):
    timeout = os.environ.get("TRIVY_DB_DOWNLOAD_TIMEOUT", config.get("TRIVY_DB_DOWNLOAD_TIMEOUT", "60m")).strip()
    if not re.fullmatch(r"[1-9][0-9]*(?:s|m|h)", timeout):
        raise PreparationError("TRIVY_DB_DOWNLOAD_TIMEOUT must be a positive integer with s, m or h (for example 60m or 2h)")
    attempts = os.environ.get("TRIVY_DB_DOWNLOAD_ATTEMPTS", config.get("TRIVY_DB_DOWNLOAD_ATTEMPTS", "3")).strip()
    if not re.fullmatch(r"[1-5]", attempts):
        raise PreparationError("TRIVY_DB_DOWNLOAD_ATTEMPTS must be an integer from 1 to 5")
    return timeout, int(attempts)


def download_trivy_databases(cache, config):
    timeout, attempts = trivy_download_settings(config)
    trivy_cache = cache / "trivy"
    if valid_databases(trivy_cache):
        note("using validated cached Trivy databases")
        return
    ensure_image(config["TRIVY_SOURCE_IMAGE"])
    trivy_cache.mkdir(parents=True, exist_ok=True)
    note("Trivy DB downloads: timeout={}, max attempts={} per database".format(timeout, attempts))
    for relative, filename, schema, argument, label in TRIVY_DATABASES:
        if valid_database(trivy_cache, relative, filename, schema):
            note("using validated cached Trivy " + label)
            continue
        for attempt in range(attempts):
            note("downloading Trivy {} (attempt {}/{}, timeout {})".format(
                label, attempt + 1, attempts, timeout))
            try:
                # Each attempt starts clean. Never reuse an incomplete database.
                with tempfile.TemporaryDirectory(prefix=".trivy-", dir=str(cache)) as temporary:
                    staging = Path(temporary).resolve()
                    command = ["docker", "run", "--rm", "--platform", PLATFORM]
                    if sys.stdout.isatty():
                        # Trivy detects its container's terminal, not the host's console.
                        command.append("--tty")
                    if os.name != "nt":
                        command.extend(["--user", "{}:{}".format(os.getuid(), os.getgid())])
                    run(command + [
                        "--volume", str(staging) + ":/cache", "--entrypoint", "/usr/local/bin/trivy",
                        config["TRIVY_SOURCE_IMAGE"], "--cache-dir", "/cache", "image",
                        "--timeout", timeout, argument])
                    note("validating downloaded Trivy " + label)
                    validation_error = database_validation_error(staging, relative, filename, schema)
                    if validation_error is not None:
                        raise PreparationError("Trivy download completed but {} validation failed: {}".format(
                            label, validation_error))
                    destination = trivy_cache / relative
                    destination.mkdir(parents=True, exist_ok=True)
                    # Metadata is the completion marker. Invalidate any broken
                    # old pair before replacing files, then publish metadata last.
                    metadata = destination / "metadata.json"
                    if metadata.exists():
                        metadata.chmod(stat.S_IREAD | stat.S_IWRITE)
                        metadata.unlink()
                    for name in (filename, "metadata.json"):
                        target = destination / name
                        if target.exists():
                            target.chmod(stat.S_IREAD | stat.S_IWRITE)
                        os.replace(staging / relative / name, target)
                note("cached Trivy " + label)
                break
            except PreparationError as error:
                if attempt + 1 == attempts:
                    raise PreparationError(
                        "Trivy {} failed after {} attempts (timeout {} each). "
                        "Completed databases remain cached. See the preceding download or validation output "
                        "for the cause. Last error: {}".format(
                            label, attempts, timeout, error)) from error
                delay = 5 * (2 ** attempt)
                note("Trivy {} attempt failed ({}); retrying in {}s with a fresh download".format(
                    label, error, delay))
                time.sleep(delay)
    if not valid_databases(trivy_cache):
        raise PreparationError("Trivy database cache is incomplete after preparation")


def build_tools(cache, config):
    download_tools(cache, config)
    download_trivy_databases(cache, config)
    for key in ("JAVA_RUNTIME_IMAGE", "GHIDRA_JDK_IMAGE", "PYCDC_BUILD_IMAGE", "PYCDC_RUNTIME_IMAGE", "TRIVY_SOURCE_IMAGE"):
        ensure_image(config[key])
    builds = (
        ("jvm-runtime", "JVM_TOOLS_IMAGE", ("JAVA_RUNTIME_IMAGE",)),
        ("ghidra-runtime", "GHIDRA_RUNTIME_IMAGE", ("GHIDRA_JDK_IMAGE",)),
        ("pycdc-runtime", "PYCDC_TOOLS_IMAGE", ("PYCDC_BUILD_IMAGE", "PYCDC_RUNTIME_IMAGE")),
        ("trivy-runtime-db", "TRIVY_RUNTIME_DB_IMAGE", ("TRIVY_SOURCE_IMAGE",)),
    )
    for dockerfile, image_key, arguments in builds:
        note("building " + config[image_key])
        command = ["docker", "build", "--pull=false", "--platform", PLATFORM,
                   "--file", str(REPO / "deploy/tools" / (dockerfile + ".Dockerfile")), "--tag", config[image_key]]
        for key in arguments:
            command.extend(["--build-arg", key + "=" + config[key]])
        run(command + [str(cache)])
        require_platform(config[image_key])


def verify_tools(config):
    images = {key: require_platform(config[key]) for key in TOOL_KEYS}
    java = "/opt/java/openjdk/bin/java"
    commands = (
        ("JVM_TOOLS_IMAGE", [java, "-jar", "/opt/bytecode-tools/vineflower/vineflower.jar", "--help"], "VINEFLOWER_VERSION"),
        ("JVM_TOOLS_IMAGE", [java, "-jar", "/opt/bytecode-tools/cfr/cfr.jar", "--version"], "CFR_VERSION"),
        ("JVM_TOOLS_IMAGE", [java, "-cp", "/opt/bytecode-tools/jadx/lib/jadx-all.jar", "jadx.cli.JadxCLI", "--version"], "JADX_VERSION"),
    )
    for image_key, arguments, version_key in commands:
        # CFR writes a successful --version response to stderr. Keep both streams
        # for CLI version checks; JSON and Docker engine queries stay stdout-only.
        output = run(["docker", "run", "--rm", "--pull=never", "--network=none", "--platform", PLATFORM,
                      config[image_key]] + arguments, capture=True, combine_output=True)
        if config[version_key] not in output:
            raise PreparationError("tool version check failed: {} (expected {}, output {!r})".format(
                version_key, config[version_key], output.strip()[:500]))
    output = run(["docker", "run", "--rm", "--platform", PLATFORM, config["GHIDRA_RUNTIME_IMAGE"],
                  "/bin/bash", "-ec", "test -x /opt/ghidra/support/analyzeHeadless; cat /opt/ghidra/Ghidra/application.properties"], capture=True)
    if "application.version=" + config["GHIDRA_VERSION"] not in output.splitlines():
        raise PreparationError("Ghidra version check failed")
    labels = (images["PYCDC_TOOLS_IMAGE"].get("Config") or {}).get("Labels") or {}
    if labels.get("com.binaryscan.pycdc-commit") != config["PYCDC_COMMIT"]:
        raise PreparationError("pycdc commit label does not match images.lock.env")
    run(["docker", "run", "--rm", "--platform", PLATFORM, config["PYCDC_TOOLS_IMAGE"],
         "/opt/bytecode-tools/pycdc/pycdc", "--help"], capture=True)
    output = run(["docker", "run", "--rm", "--platform", PLATFORM, config["TRIVY_RUNTIME_DB_IMAGE"],
                  "--cache-dir", "/opt/trivy-cache", "version", "--format", "json"], capture=True)
    try:
        details = json.loads(output)
        labels = (images["TRIVY_RUNTIME_DB_IMAGE"].get("Config") or {}).get("Labels") or {}
        expected_version = config["TRIVY_SOURCE_IMAGE"].rsplit(":", 1)[-1]
        if (not isinstance(details, dict) or details.get("Version") != expected_version
                or details.get("Version") != labels.get("com.binaryscan.trivy-version")
                or not details.get("VulnerabilityDB") or not details.get("JavaDB")):
            raise ValueError("missing version or databases")
    except ValueError as error:
        raise PreparationError("Trivy version or bundled database check failed") from error
    note("four linux/amd64 tool images passed version and layout checks")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("download", "build", "verify", "all"))
    parser.add_argument("cache_dir", type=Path, help="absolute path, or a path relative to the repository root")
    arguments = parser.parse_args()
    try:
        config = read_config()
        if arguments.action in ("build", "all"):
            trivy_download_settings(config)
        cache = (arguments.cache_dir if arguments.cache_dir.is_absolute() else REPO / arguments.cache_dir).resolve()
        if cache == REPO or cache in REPO.parents:
            raise PreparationError("CACHE_DIR must not be the repository root or one of its parents")
        if arguments.action != "download":
            if shutil.which("docker") is None:
                raise PreparationError("required command is missing: docker")
            if run(["docker", "info", "--format", "{{.OSType}}"], capture=True).strip() != "linux":
                raise PreparationError("Docker must use Linux containers")
        if arguments.action in ("download", "build", "all"):
            cache.mkdir(parents=True, exist_ok=True)
        if arguments.action == "download":
            download_tools(cache, config)
        elif arguments.action in ("build", "all"):
            build_tools(cache, config)
        if arguments.action in ("verify", "all"):
            verify_tools(config)
    except (PreparationError, OSError) as error:
        print("error: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
