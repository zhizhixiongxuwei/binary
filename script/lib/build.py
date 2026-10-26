#!/usr/bin/env python3
"""Build BinaryScan from the working tree and assemble a standalone deployment.

Only the build host needs Python. Delivered scripts require Docker Compose and
either a POSIX shell or PowerShell. Configuration has one source: the root .env.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


IMAGE_KEYS = (
    "MYSQL_IMAGE", "APP_IMAGE", "SCANNER_IMAGE", "NATIVE_DECOMPILER_IMAGE",
    "JVM_DECOMPILER_IMAGE", "PYC_DECOMPILER_IMAGE", "C_CHECKER_IMAGE",
    "JAVA_CHECKER_IMAGE", "PYTHON_CHECKER_IMAGE",
)
TOOL_KEYS = (
    "TRIVY_RUNTIME_DB_IMAGE", "GHIDRA_RUNTIME_IMAGE", "JVM_TOOLS_IMAGE", "PYCDC_TOOLS_IMAGE",
)
# image variable, Dockerfile, context, build arguments
BUILDS = (
    ("APP_IMAGE", "app/Dockerfile", ".", ("GO_BUILD_IMAGE", "NODE_BUILD_IMAGE", "APP_RUNTIME_IMAGE", "BINARY_VERSION")),
    ("SCANNER_IMAGE", "deploy/docker/scanner.Dockerfile", ".", ("GO_BUILD_IMAGE", "TRIVY_RUNTIME_DB_IMAGE", "SCANNER_RUNTIME_IMAGE", "BINARY_VERSION")),
    ("NATIVE_DECOMPILER_IMAGE", "deploy/docker/native-decompiler.Dockerfile", ".", ("GO_BUILD_IMAGE", "GHIDRA_RUNTIME_IMAGE", "BINARY_VERSION")),
    ("JVM_DECOMPILER_IMAGE", "deploy/docker/jvm-decompiler.Dockerfile", ".", ("GO_BUILD_IMAGE", "JVM_TOOLS_IMAGE", "BINARY_VERSION")),
    ("PYC_DECOMPILER_IMAGE", "deploy/docker/pyc-decompiler.Dockerfile", ".", ("GO_BUILD_IMAGE", "PYCDC_TOOLS_IMAGE", "BINARY_VERSION")),
    ("C_CHECKER_IMAGE", "checkers/c/Dockerfile", "checkers/c", ("JAVA_BUILD_IMAGE", "JAVA_RUNTIME_IMAGE")),
    ("JAVA_CHECKER_IMAGE", "checkers/java/Dockerfile", "checkers/java", ("JAVA_BUILD_IMAGE", "JAVA_RUNTIME_IMAGE")),
    ("PYTHON_CHECKER_IMAGE", "checkers/python/Dockerfile", "checkers/python", ("PYTHON_RUNTIME_IMAGE",)),
)
DATA_DIRS = (
    "mysql", "storage/uploads", "storage/blobs", "storage/artifacts",
    "storage/projects/native", "storage/projects/jvm", "storage/projects/pyc",
    "storage/reports", "work/scanner", "work/native-decompiler", "work/jvm-decompiler", "work/pyc-decompiler",
)
TEMPLATES = tuple(f"{name}.{ext}" for name in ("manage", "verify", "load-images", "install") for ext in ("sh", "ps1"))


class BuildError(RuntimeError):
    pass


def load_env(path: Path) -> dict[str, str]:
    """Read simple dotenv assignments without executing shell code.

    Values are literal; use single quotes when a value contains a dollar sign.
    This intentionally rejects interpolation so shell, Compose and PowerShell
    cannot quietly resolve a build parameter differently.
    """
    result = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match:
            raise BuildError(f"{path}:{number}: expected KEY=value")
        key, value = match.groups()
        if key in result:
            raise BuildError(f"{path}:{number}: duplicate variable {key}")
        literal = value.startswith("'")
        if literal:
            quoted = re.fullmatch(r"'([^']*)'\s*(?:#.*)?", value)
            if not quoted:
                raise BuildError(f"{path}:{number}: invalid single-quoted value")
            value = quoted.group(1)
        elif value.startswith('"'):
            quoted = re.fullmatch(r'"((?:[^"\\]|\\.)*)"\s*(?:#.*)?', value)
            if not quoted:
                raise BuildError(f"{path}:{number}: invalid double-quoted value")
            value = re.sub(r'\\([\\"nrt])', lambda m: {"n": "\n", "r": "\r", "t": "\t"}.get(m[1], m[1]), quoted.group(1))
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if "$" in value and not literal:
            raise BuildError(f"{path}:{number}: interpolation is unsupported; single-quote literal dollar signs")
        if any(char in value for char in ("\n", "\r", "\0", "'")):
            raise BuildError(f"{path}:{number}: multiline values and apostrophes are unsupported")
        result[key] = value
    return result


def docker(args: list[str], *, capture: bool = False, check: bool = True, env=None) -> subprocess.CompletedProcess:
    result = subprocess.run(["docker", *map(str, args)], text=True, encoding="utf-8",
                            capture_output=capture, env=env)
    if check and result.returncode:
        details = (result.stderr or result.stdout or "").strip() if capture else ""
        raise BuildError(f"docker {args[0]} failed (exit {result.returncode})" + (f": {details}" if details else ""))
    return result


def inspect_image(ref: str, platform: str, required: bool = True) -> dict | None:
    result = docker(["image", "inspect", "--format", "{{json .}}", ref], capture=True, check=False)
    if result.returncode:
        if required:
            raise BuildError(f"required image is not available locally: {ref}")
        return None
    try:
        info = json.loads(result.stdout)
        actual = f"{info['Os']}/{info['Architecture']}"
        image_id = info["Id"]
    except (ValueError, KeyError, TypeError) as error:
        raise BuildError(f"invalid Docker image inspection result for {ref}") from error
    if actual != platform:
        raise BuildError(f"platform mismatch for {ref}: expected {platform}, got {actual}")
    return {"reference": ref, "id": image_id, "platform": actual}


def _official_registry_fallback(ref: str) -> str | None:
    """Map only ECR's Docker Official Images mirror, preserving tag and digest."""
    prefix = "public.ecr.aws/docker/library/"
    if not ref.startswith(prefix):
        return None
    image = ref[len(prefix):]
    # A Docker Hub library repository has one name component. Never interpret a
    # nested repository, a different ECR namespace or a private registry as Hub.
    if not re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?(?:@sha256:[0-9a-fA-F]{64})?", image):
        return None
    return "docker.io/library/" + image


def _retryable_registry_error(message: str) -> bool:
    message = message.lower()
    # A missing version, invalid reference or denied credential will not recover
    # with a delay. An official mirror may still be attempted once in that case.
    permanent = (
        "manifest unknown", "manifest_unknown", "no matching manifest",
        "unauthorized", "authentication required", "access denied", "access is denied",
        "requested access to the resource is denied", "denied:", "forbidden",
        "repository does not exist", "invalid reference format", "name unknown",
        "certificate signed by unknown authority", "certificate has expired",
    )
    if any(token in message for token in permanent):
        return False
    transient = (
        "toomanyrequests", "too many requests", "rate exceeded", "rate limit",
        "timeout", "timed out", "temporary failure", "temporarily unavailable",
        "connection reset", "connection refused", "connection aborted",
        "network is unreachable", "no route to host", "unexpected eof", "tls handshake",
        "server misbehaving", "i/o timeout", "service unavailable", "bad gateway",
        "internal server error", "gateway timeout",
    )
    # Numeric image tags (for example image:500) are not HTTP status codes.
    status = r"\b(?:status(?: code)?|http(?:/\d(?:\.\d)?)?)[^\r\n]{0,20}\b(?:429|5[0-9]{2})\b|(?<![\w:./-])(?:429|5[0-9]{2})(?![\w./-])"
    return any(token in message for token in transient) or bool(re.search(status, message))


def _matching_local_image(ref: str, platform: str) -> dict | None:
    try:
        return inspect_image(ref, platform, required=False)
    except BuildError as error:
        if str(error).startswith("platform mismatch for "):
            return None
        raise


def _restore_configured_image(source: str, ref: str, platform: str) -> dict:
    image = inspect_image(source, platform)
    if source == ref:
        return image
    if "@" in ref:
        # Docker cannot tag an image with a digest target. Some image stores can
        # resolve an already-present canonical digest after the alternate pull;
        # otherwise fail explicitly rather than silently weakening a digest pin.
        existing = _matching_local_image(ref, platform)
        if existing:
            return existing
        raise BuildError(
            f"pulled {source}, but Docker cannot safely alias a digest reference to {ref}; "
            "restore access to the configured registry or explicitly configure the alternate "
            "reference with the same digest (the configured digest has not been changed)"
        )
    docker(["tag", source, ref], capture=True)
    return inspect_image(ref, platform)


def pull_image(ref: str, platform: str) -> dict:
    """Ensure an exact image locally, with bounded transient retries and failover.

    Local images are reused only when their platform matches. Each registry gets
    at most three pull attempts, with 5/10 second delays between retry rounds.
    The alternate registry is tried immediately after the first source failure.
    """
    import time

    existing = _matching_local_image(ref, platform)
    if existing:
        return existing
    fallback = _official_registry_fallback(ref)
    sources = [ref] + ([fallback] if fallback else [])
    if fallback and "@" not in ref and _matching_local_image(fallback, platform):
        return _restore_configured_image(fallback, ref, platform)
    pending = sources[:]
    failures = {source: [] for source in sources}
    for attempt in range(1, 4):
        retry = []
        for source in pending:
            print(f"Pulling {source} for {platform} (attempt {attempt}/3)", flush=True)
            result = docker(["pull", "--platform", platform, source], capture=True, check=False)
            if result.returncode == 0:
                return _restore_configured_image(source, ref, platform)
            reason = "\n".join(part.strip() for part in (result.stderr, result.stdout) if part and part.strip())
            reason = reason or f"docker pull exited with code {result.returncode} without error details"
            failures[source].append(f"attempt {attempt}: {reason}")
            print(f"Image pull failed for {source}: {reason}", file=sys.stderr, flush=True)
            if _retryable_registry_error(reason):
                retry.append(source)
        if not retry or attempt == 3:
            break
        delay = 5 * 2 ** (attempt - 1)
        print(f"Retrying temporary registry failures in {delay} seconds", flush=True)
        time.sleep(delay)
        pending = retry
    details = "\n".join(f"- {source}: " + "\n  ".join(failures[source]) for source in sources)
    raise BuildError(f"could not obtain {ref} for {platform}; registry failures:\n{details}")


def require_values(config: dict[str, str], keys) -> None:
    missing = sorted(key for key in set(keys) if not config.get(key))
    if missing:
        raise BuildError("missing configuration: " + ", ".join(missing))


def build_images(repo: Path, config: dict[str, str]) -> None:
    require_values(config, TOOL_KEYS)
    require_values(config, [key for _, _, _, args in BUILDS for key in args])
    platform = config["BINARY_PLATFORM"]
    # Resolve every external base before downloading assets or compiling. The
    # shared pull helper reuses local images and handles official registry failover.
    base_keys = ["MYSQL_IMAGE"] + [
        argument for _, _, _, arguments in BUILDS for argument in arguments
        if argument.endswith("_IMAGE") and argument not in TOOL_KEYS
    ]
    for image in dict.fromkeys(config[key] for key in base_keys):
        pull_image(image, platform)
    missing = [key for key in TOOL_KEYS if inspect_image(config[key], platform, required=False) is None]
    if missing:
        print("Preparing missing offline tool images: " + ", ".join(missing), flush=True)
        subprocess.run([sys.executable, str(repo / "script/tools/prepare-tools.py"), "all", str(repo / ".cache/tools")],
                       cwd=repo, check=True)
    for key in TOOL_KEYS:
        inspect_image(config[key], platform)
    for key, dockerfile, context, arguments in BUILDS:
        print(f"Building {config[key]} from the current working tree", flush=True)
        command = ["build", "--pull=false", "--platform", platform, "-f", str(repo / dockerfile), "-t", config[key]]
        for argument in arguments:
            command.extend(["--build-arg", f"{argument}={config[argument]}"])
        docker([*command, str(repo / context)])


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_state(repo: Path, skip_build: bool) -> dict:
    def git(*args):
        try:
            result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8")
            return result.stdout.strip() if result.returncode == 0 else None
        except FileNotFoundError:
            return None
    status = git("status", "--porcelain", "--untracked-files=normal")
    return {
        "revision": git("rev-parse", "HEAD"),
        "dirty": None if status is None else bool(status),
        "input": "existing local images; correspondence to this working tree is not guaranteed" if skip_build else "current working tree, including uncommitted files",
        "built_from_working_tree": not skip_build,
    }


def runtime_config(config: dict[str, str], keys: set[str], mode: str) -> dict[str, str]:
    result = {key: value for key, value in config.items() if key in keys}
    result.update(COMPOSE_PROJECT_NAME=f"binary-{mode}", BINARY_DATA_ROOT="./data")
    for key in ("MYSQL_PASSWORD", "MYSQL_ROOT_PASSWORD", "INITIAL_ADMIN_PASSWORD"):
        result[key] = secrets.token_hex(24)
    return result


def validate_compose(stage: Path, config: dict[str, str]) -> None:
    # Environment variables otherwise override --env-file. Pin every runtime
    # value here, so the package is validated against the files we actually ship.
    environment = os.environ.copy()
    environment.update(config)
    result = docker(["compose", "--project-directory", str(stage), "--env-file", str(stage / ".env"),
                     "-f", str(stage / "docker-compose.yml"), "config", "--format", "json"],
                    capture=True, env=environment)
    try:
        services = json.loads(result.stdout)["services"]
        if len(services) != len(IMAGE_KEYS):
            raise BuildError("deployment must contain exactly nine runtime services")
        for name, service in services.items():
            if "build" in service or service.get("pull_policy") != "never":
                raise BuildError(f"runtime service {name} must have no build and must use pull_policy: never")
        if sorted(service.get("image", "") for service in services.values()) != sorted(config[key] for key in IMAGE_KEYS):
            raise BuildError("Compose runtime images do not match the nine exported image references")
    except (ValueError, KeyError, TypeError) as error:
        raise BuildError("could not validate rendered Docker Compose configuration") from error


def data_helper(data_root: Path, config: dict[str, str], command: str, *args: str) -> None:
    # scanner is already shipped and has /bin/sh; initialization never pulls an
    # auxiliary image or starts an application service. --mount fails if absent.
    docker(["run", "--rm", "--pull=never", "--network=none", "--user", "0:0", "--entrypoint", "/bin/sh",
            "--mount", f"type=bind,source={data_root},target=/package-data", config["SCANNER_IMAGE"],
            "-ec", command, "init-data", *args])


def init_data(data_root: Path, config: dict[str, str]) -> None:
    for directory in DATA_DIRS:
        (data_root / directory).mkdir(parents=True, exist_ok=True)
    write_text(data_root / ".binaryscan-data-root", f"binaryscan-data:{config['COMPOSE_PROJECT_NAME']}\n")
    if sys.platform.startswith("linux"):
        data_helper(data_root, config,
                    'chown -R "$1:$2" /package-data/storage /package-data/work; '
                    'find /package-data/storage /package-data/work -type d -exec chmod 0750 {} +',
                    config["PRODUCT_UID"], config["PRODUCT_GID"])


def write_readme(stage: Path, mode: str) -> None:
    if mode == "local":
        start = """在本机构建使用的 Docker 引擎上启动（镜像已构建、数据目录已初始化）：

```sh
cd local
docker compose up -d --wait
```

也可使用 `./manage.sh start` 或 `powershell -ExecutionPolicy Bypass -File .\\manage.ps1 start`。
本地包不包含镜像归档，不能直接复制到尚未导入镜像的另一台机器；离线交付请构建 release。
"""
    else:
        start = """将整个 release 目录复制到客户机器。客户只需安装支持 Linux 容器的 Docker Engine / Docker Desktop
和 Compose v2，无需 Python、源码、构建工具或外网。首次安装会校验文件、离线导入九个运行镜像、
初始化数据目录并等待服务健康；不会下载镜像。

Linux：

```sh
cd release
sudo sh ./install.sh
```

Windows PowerShell（Docker Desktop 使用 Linux containers）：

```powershell
cd release
powershell -ExecutionPolicy Bypass -File .\\install.ps1
```

macOS：`cd release && sh ./install.sh`。
将目录整体复制即可，保持 images、manifests 与所有脚本的相对位置。
"""
    write_text(stage / "README.md", f"""# BinaryScan {mode}

{start}

运行配置在 `.env`，来自构建时仓库根目录配置；版本和镜像引用原样保留。
数据库密码、MySQL root 密码和初始管理员密码已为本包随机生成，请从 `.env` 读取并妥善保管。
`.env` 和 `data/` 可变，不计入包校验清单；修改镜像、平台或项目名称前应先停止服务。
管理员账号由 `INITIAL_ADMIN_USERNAME` 指定，初始密码仅在首次创建用户时使用。
访问地址见 `PUBLIC_BASE_URL`；默认绑定 `127.0.0.1`。需要远程访问时同步配置
`APP_BIND_IP`、`PUBLIC_BASE_URL` 与 `APP_ALLOWED_ORIGINS`。

Linux/macOS 常用命令：`sh ./manage.sh status`、`sh ./manage.sh logs app`、
`sh ./manage.sh stop`、`sh ./manage.sh start`。PowerShell 使用对应的 `manage.ps1`。
Linux release 使用 sudo 安装后，管理命令也请加上 `sudo`，以读取已设置容器用户权限的数据目录。
`stop` 与 `down` 保留 data；`reset --yes`（PowerShell：`reset -Yes`）会永久删除业务数据。
升级或迁移前先停止全部服务，再备份整个 data 目录与 .env；运行中的 MySQL 数据目录不能直接
作为一致性备份复制，如需不停机备份请使用数据库一致性备份方案。构建脚本不会覆盖已存在的 local/release。

`sh ./verify.sh` / `.\\verify.ps1` 校验交付文件；`manifests/images.json` 记录镜像 ID、平台、
构建时间及源码修订。默认使用当前工作区（含未提交修改）构建；使用 `--skip-build` 时只打包现有
镜像，清单会明确记录其与当前源码的对应关系未经保证。运行平台限定为 linux/amd64。
""")


def write_manifest(stage: Path) -> None:
    records = []
    for path in sorted(stage.rglob("*")):
        relative = path.relative_to(stage)
        if not path.is_file() or relative.parts[0] in (".env", "data") or relative.as_posix() == "manifests/package.sha256":
            continue
        records.append(f"{checksum(path)}  {relative.as_posix()}\n")
    write_text(stage / "manifests/package.sha256", "".join(records))


def build_bundle(repo: Path, mode: str, skip_build: bool = False) -> Path:
    if mode not in ("local", "release"):
        raise BuildError("mode must be local or release")
    repo = repo.resolve()
    output = repo / mode
    if os.path.lexists(output):
        raise BuildError(f"refusing to overwrite {output}; preserve or move the existing directory first")
    compose_path = repo / "docker-compose.yml"
    compose_text = compose_path.read_text(encoding="utf-8-sig")
    keys = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^}]*\}", compose_text))
    config = load_env(repo / ".env")
    require_values(config, keys | set(IMAGE_KEYS) | {"BINARY_VERSION", "BINARY_PLATFORM", "PRODUCT_UID", "PRODUCT_GID"})
    if config["BINARY_PLATFORM"] != "linux/amd64":
        raise BuildError("only linux/amd64 is supported by the pinned offline tools")
    if not all(re.fullmatch(r"[1-9][0-9]*", config[key]) for key in ("PRODUCT_UID", "PRODUCT_GID")):
        raise BuildError("PRODUCT_UID and PRODUCT_GID must be positive numeric IDs")
    if len({config[key] for key in IMAGE_KEYS}) != len(IMAGE_KEYS):
        raise BuildError("the nine runtime services must have distinct image references")
    for name in TEMPLATES:
        if not (repo / "deploy/delivery/common" / name).is_file():
            raise BuildError(f"missing delivery template: {name}")
    if docker(["info", "--format", "{{.OSType}}"], capture=True).stdout.strip() != "linux":
        raise BuildError("Docker must run Linux containers")
    docker(["compose", "version", "--short"], capture=True)
    source = source_state(repo, skip_build)
    if not skip_build:
        build_config = {**config, **load_env(repo / "deploy/docker/images.lock.env")}
        build_images(repo, build_config)
    images = [inspect_image(config[key], config["BINARY_PLATFORM"]) for key in IMAGE_KEYS]
    stage = Path(tempfile.mkdtemp(prefix=f".{mode}-build-", dir=repo))
    runtime = runtime_config(config, keys, mode)
    try:
        write_text(stage / "docker-compose.yml", compose_text)
        write_text(stage / ".env", "# Generated from repository .env; keep credentials private.\n" +
                   "".join(f"{key}='{value}'\n" for key, value in runtime.items()))
        (stage / ".env").chmod(0o600)
        for name in TEMPLATES:
            write_text(stage / name, (repo / "deploy/delivery/common" / name).read_text(encoding="utf-8-sig"))
            if name.endswith(".sh"):
                (stage / name).chmod(0o755)
        write_readme(stage, mode)
        validate_compose(stage, runtime)
        write_text(stage / "manifests/images.json", json.dumps({
            "schema_version": 1, "mode": mode, "version": config["BINARY_VERSION"],
            "created_at": datetime.now(timezone.utc).isoformat(), "source": source, "images": images,
        }, indent=2, ensure_ascii=False) + "\n")
        if mode == "release":
            archive = stage / "images/runtime-images.tar"
            archive.parent.mkdir()
            docker(["save", "--output", str(archive), *[config[key] for key in IMAGE_KEYS]])
            write_text(archive.with_suffix(".tar.sha256"), f"{checksum(archive)}  {archive.name}\n")
        write_manifest(stage)
        if mode == "local":
            init_data(stage / "data", runtime)
        if os.path.lexists(output):
            raise BuildError(f"output appeared during build; refusing to overwrite {output}")
        stage.rename(output)
    except BaseException:
        # Only the exact temporary directory allocated above is eligible for
        # cleanup. Existing outputs and their application data are never touched.
        if stage.parent == repo and stage.name.startswith(f".{mode}-build-") and stage.is_dir() and not stage.is_symlink():
            if sys.platform.startswith("linux") and (stage / "data").is_dir():
                try:
                    data_helper(stage / "data", runtime, 'chown -R "$1:$2" /package-data', str(os.getuid()), str(os.getgid()))
                except (BuildError, OSError):
                    print(f"Could not restore temporary data ownership; remove {stage} manually", file=sys.stderr)
            try:
                shutil.rmtree(stage)
            except OSError as error:
                print(f"Could not remove temporary directory {stage}: {error}", file=sys.stderr)
        raise
    print(f"Created {output}", flush=True)
    print("Credentials: " + str(output / ".env"), flush=True)
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("local", "release"))
    parser.add_argument("--skip-build", action="store_true", help="package existing runtime images; do not build, pull, or prepare tools")
    args = parser.parse_args(argv)
    try:
        build_bundle(Path(__file__).resolve().parents[2], args.mode, args.skip_build)
    except (BuildError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("error: build interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
