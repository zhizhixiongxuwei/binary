#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
env_file="$repo_dir/.env"
image_lock="$repo_dir/deploy/docker/images.lock.env"

[ -f "$env_file" ] || { echo "missing $env_file" >&2; exit 1; }
[ -f "$image_lock" ] || { echo "missing $image_lock" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
. "$env_file"
# shellcheck disable=SC1090
. "$image_lock"
set +a

checksum_create() {
  archive_dir=$(dirname -- "$1")
  archive_name=$(basename -- "$1")
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$archive_dir" && sha256sum "$archive_name" > "$archive_name.sha256")
  else
    (cd "$archive_dir" && shasum -a 256 "$archive_name" > "$archive_name.sha256")
  fi
}

checksum_verify() {
  archive_dir=$(dirname -- "$1")
  checksum_name=$(basename -- "$1.sha256")
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$archive_dir" && sha256sum -c "$checksum_name")
  else
    (cd "$archive_dir" && shasum -a 256 -c "$checksum_name")
  fi
}

require_image() {
  docker image inspect "$1" >/dev/null 2>&1 || {
    echo "missing required image: $1" >&2
    echo "run python script/tools/prepare-tools.py all CACHE_DIR or load the prepared image" >&2
    exit 1
  }
}

build_app() {
  # App 镜像在多阶段构建中先编译 Vue，再将静态资源嵌入 Go 可执行文件；最终镜像无需 Node。
  docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/app/Dockerfile" -t "$APP_IMAGE" \
    --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
    --build-arg "NODE_BUILD_IMAGE=$NODE_BUILD_IMAGE" \
    --build-arg "APP_RUNTIME_IMAGE=$APP_RUNTIME_IMAGE" \
    --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
}

build_scanner() {
  # Trivy 数据库来自预制离线镜像，构建阶段不临时联网下载，便于封存环境复现。
  docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/scanner.Dockerfile" -t "$SCANNER_IMAGE" \
    --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
    --build-arg "TRIVY_RUNTIME_DB_IMAGE=$TRIVY_RUNTIME_DB_IMAGE" \
    --build-arg "SCANNER_RUNTIME_IMAGE=$SCANNER_RUNTIME_IMAGE" \
    --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
}

build_native_decompiler() {
  docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/native-decompiler.Dockerfile" -t "$NATIVE_DECOMPILER_IMAGE" \
    --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
    --build-arg "GHIDRA_RUNTIME_IMAGE=$GHIDRA_RUNTIME_IMAGE" \
    --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
}

build_jvm_decompiler() {
  docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/jvm-decompiler.Dockerfile" -t "$JVM_DECOMPILER_IMAGE" \
    --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
    --build-arg "JVM_TOOLS_IMAGE=$JVM_TOOLS_IMAGE" \
    --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
}

build_pyc_decompiler() {
  docker build --platform "$BINARY_PLATFORM" -f "$repo_dir/deploy/docker/pyc-decompiler.Dockerfile" -t "$PYC_DECOMPILER_IMAGE" \
    --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
    --build-arg "PYCDC_TOOLS_IMAGE=$PYCDC_TOOLS_IMAGE" \
    --build-arg "BINARY_VERSION=$BINARY_VERSION" "$repo_dir"
}

build_c_checker() {
  docker build --platform "$BINARY_PLATFORM" -t "$C_CHECKER_IMAGE" \
    --build-arg "JAVA_BUILD_IMAGE=$JAVA_BUILD_IMAGE" \
    --build-arg "JAVA_RUNTIME_IMAGE=$JAVA_RUNTIME_IMAGE" "$repo_dir/checkers/c"
}

build_java_checker() {
  docker build --platform "$BINARY_PLATFORM" -t "$JAVA_CHECKER_IMAGE" \
    --build-arg "JAVA_BUILD_IMAGE=$JAVA_BUILD_IMAGE" \
    --build-arg "JAVA_RUNTIME_IMAGE=$JAVA_RUNTIME_IMAGE" "$repo_dir/checkers/java"
}

build_python_checker() {
  docker build --platform "$BINARY_PLATFORM" -t "$PYTHON_CHECKER_IMAGE" \
    --build-arg "PYTHON_RUNTIME_IMAGE=$PYTHON_RUNTIME_IMAGE" "$repo_dir/checkers/python"
}

build_checkers() {
  build_c_checker
  build_java_checker
  build_python_checker
}

build_all() {
  # 先检查体积大、准备成本高的工具镜像，避免产品构建到一半才发现离线依赖缺失。
  require_image "$TRIVY_RUNTIME_DB_IMAGE"
  require_image "$GHIDRA_RUNTIME_IMAGE"
  require_image "$JVM_TOOLS_IMAGE"
  require_image "$PYCDC_TOOLS_IMAGE"
  build_app
  build_scanner
  build_native_decompiler
  build_jvm_decompiler
  build_pyc_decompiler
  build_checkers
}

build_core() {
  require_image "$TRIVY_RUNTIME_DB_IMAGE"
  build_app
  build_scanner
}

usage() {
  echo "usage: $0 {build|build-core|build-app|build-scanner|build-checkers|build-c-checker|build-java-checker|build-python-checker|package OUTPUT.tar|load FILE}" >&2
  exit 2
}

case "${1:-}" in
  build) build_all ;;
  build-core) build_core ;;
  build-app) build_app ;;
  build-scanner)
    require_image "$TRIVY_RUNTIME_DB_IMAGE"
    build_scanner
    ;;
  build-checkers) build_checkers ;;
  build-c-checker) build_c_checker ;;
  build-java-checker) build_java_checker ;;
  build-python-checker) build_python_checker ;;
  package)
    # 产品包只导出九个运行镜像；自主验收所需的构建镜像由 create-deliveries.sh 单独封装。
    output=${2:?usage: build-images.sh package OUTPUT.tar}
    [ -d "$(dirname -- "$output")" ] || {
      echo "output directory does not exist: $(dirname -- "$output")" >&2
      exit 1
    }
    for image in "$MYSQL_IMAGE" "$APP_IMAGE" "$SCANNER_IMAGE" \
      "$NATIVE_DECOMPILER_IMAGE" "$JVM_DECOMPILER_IMAGE" "$PYC_DECOMPILER_IMAGE" \
      "$C_CHECKER_IMAGE" "$JAVA_CHECKER_IMAGE" "$PYTHON_CHECKER_IMAGE"; do
      docker image inspect "$image" >/dev/null 2>&1 || {
        echo "missing product image: $image" >&2
        exit 1
      }
    done
    docker save -o "$output" \
      "$MYSQL_IMAGE" "$APP_IMAGE" "$SCANNER_IMAGE" \
      "$NATIVE_DECOMPILER_IMAGE" "$JVM_DECOMPILER_IMAGE" "$PYC_DECOMPILER_IMAGE" \
      "$C_CHECKER_IMAGE" "$JAVA_CHECKER_IMAGE" "$PYTHON_CHECKER_IMAGE"
    checksum_create "$output"
    echo "created $output"
    ;;
  load)
    archive=${2:?usage: build-images.sh load ARCHIVE.tar}
    checksum_verify "$archive"
    docker load -i "$archive"
    ;;
  *) usage ;;
esac
