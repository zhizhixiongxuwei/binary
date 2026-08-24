#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
env_file="$repo_dir/.env"
image_lock="$repo_dir/deploy/docker/images.lock.env"
template_root="$repo_dir/deploy/delivery"
output_parent=${1:-/Users/chenzhe/Documents}
deploy_target="$output_parent/binary-deploy"
demo_target="$output_parent/binary-demo"

die() {
  echo "error: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  else
    die "sha256sum or shasum is required"
  fi
}

checksum_create() {
  archive=$1
  archive_dir=$(dirname -- "$archive")
  archive_name=$(basename -- "$archive")
  (cd "$archive_dir" && sha256_file "$archive_name" > "$archive_name.sha256")
}

dependency_digest() {
  manifest=$1
  (
    cd "$repo_dir/app"
    for file in backend/go.mod backend/go.sum frontend/package.json frontend/package-lock.json; do
      sha256_file "$file"
    done
  ) > "$manifest"
  sha256_file "$manifest" | awk '{print $1}'
}

write_source_manifest() {
  bundle=$1
  manifest="$bundle/manifests/source.sha256"
  (
    cd "$bundle"
    find app -type f | LC_ALL=C sort | while IFS= read -r file; do
      sha256_file "$file"
    done
  ) > "$manifest"
}

write_package_manifest() {
  bundle=$1
  manifest="$bundle/manifests/package.sha256"
  (
    cd "$bundle"
    find . -type f \
      ! -path './manifests/package.sha256' \
      ! -path './data/*' \
      ! -path './build-output/*' |
      LC_ALL=C sort |
      while IFS= read -r file; do
        file=${file#./}
        sha256_file "$file"
      done
  ) > "$manifest"
}

write_image_inventory() {
  output=$1
  shift
  : > "$output"
  for image in "$@"; do
    docker image inspect --format '{{index .RepoTags 0}}|{{.Id}}|{{.Os}}/{{.Architecture}}' \
      "$image" >> "$output"
  done
}

render_env() {
  output=$1
  project=$2
  mysql_password=$(openssl rand -hex 24)
  mysql_root_password=$(openssl rand -hex 24)
  admin_password=$(openssl rand -hex 16)
  sed \
    -e "s/__COMPOSE_PROJECT_NAME__/$project/g" \
    -e "s/__MYSQL_PASSWORD__/$mysql_password/g" \
    -e "s/__MYSQL_ROOT_PASSWORD__/$mysql_root_password/g" \
    -e "s/__ADMIN_PASSWORD__/$admin_password/g" \
    "$template_root/common/package.env" > "$output"
  chmod 0600 "$output"
  printf '%s|%s\n' "$project" "$admin_password"
}

copy_archive() {
  source=$1
  destination=$2
  if [ "$(uname -s)" = "Darwin" ]; then
    cp -c "$source" "$destination"
  else
    cp "$source" "$destination"
  fi
  cp "$source.sha256" "$destination.sha256"
}

[ -f "$env_file" ] || die "missing $env_file"
[ -f "$image_lock" ] || die "missing $image_lock"
[ -d "$output_parent" ] || die "output parent does not exist: $output_parent"
[ ! -e "$deploy_target" ] || die "target already exists: $deploy_target"
[ ! -e "$demo_target" ] || die "target already exists: $demo_target"
command -v docker >/dev/null 2>&1 || die "docker is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
docker version >/dev/null

if ! git -C "$repo_dir" diff --quiet HEAD -- app/backend app/frontend; then
  die "app/backend or app/frontend has uncommitted changes; commit them before sealing source"
fi
if [ -n "$(git -C "$repo_dir" ls-files --others --exclude-standard -- app/backend app/frontend)" ]; then
  die "app/backend or app/frontend contains untracked source; commit it before sealing source"
fi

set -a
# shellcheck disable=SC1090
. "$env_file"
# shellcheck disable=SC1090
. "$image_lock"
set +a

APP_BUILD_DEPS_IMAGE="binaryscan/app-build-deps:${BINARY_VERSION}"
export APP_BUILD_DEPS_IMAGE

runtime_images="
$MYSQL_IMAGE
$APP_IMAGE
$SCANNER_IMAGE
$NATIVE_DECOMPILER_IMAGE
$JVM_DECOMPILER_IMAGE
$PYC_DECOMPILER_IMAGE
$C_CHECKER_IMAGE
$JAVA_CHECKER_IMAGE
$PYTHON_CHECKER_IMAGE
"

for image in $runtime_images; do
  docker image inspect "$image" >/dev/null 2>&1 || die "missing runtime image: $image"
  platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
  [ "$platform" = "$BINARY_PLATFORM" ] ||
    die "runtime image $image is $platform, expected $BINARY_PLATFORM"
done

stage=$(mktemp -d "$output_parent/.binary-delivery.XXXXXX")
cleanup() {
  if [ -n "${stage:-}" ] && [ -d "$stage" ]; then
    rm -rf -- "$stage"
  fi
}
trap cleanup EXIT HUP INT TERM

deploy_stage="$stage/binary-deploy"
demo_stage="$stage/binary-demo"
shared_stage="$stage/shared"
mkdir -p \
  "$deploy_stage/images/runtime" "$deploy_stage/manifests" "$deploy_stage/data" \
  "$demo_stage/images/runtime" "$demo_stage/images/build" "$demo_stage/manifests" \
  "$demo_stage/data" "$demo_stage/build-output" "$shared_stage"

for bundle in "$deploy_stage" "$demo_stage"; do
  cp "$repo_dir/docker-compose.yml" "$bundle/docker-compose.yml"
  cp "$template_root/common/manage.sh" "$bundle/manage.sh"
  cp "$template_root/common/manage.ps1" "$bundle/manage.ps1"
  cp "$template_root/common/load-images.sh" "$bundle/load-images.sh"
  cp "$template_root/common/load-images.ps1" "$bundle/load-images.ps1"
  cp "$template_root/common/verify.sh" "$bundle/verify.sh"
  cp "$template_root/common/verify.ps1" "$bundle/verify.ps1"
  chmod 0755 "$bundle/manage.sh" "$bundle/load-images.sh" "$bundle/verify.sh"
done

deploy_credentials=$(render_env "$deploy_stage/.env" binary-deploy)
demo_credentials=$(render_env "$demo_stage/.env" binary-demo)

echo "copying sealed backend and frontend source from Git HEAD"
git -C "$repo_dir" archive --format=tar HEAD app/backend app/frontend | tar -xf - -C "$demo_stage"
cp "$template_root/demo/Dockerfile" "$demo_stage/app/Dockerfile"
cp "$template_root/demo/.dockerignore" "$demo_stage/app/.dockerignore"
cp "$template_root/demo/build-app.sh" "$demo_stage/build-app.sh"
cp "$template_root/demo/build-app.ps1" "$demo_stage/build-app.ps1"
chmod 0755 "$demo_stage/build-app.sh"

dependency_manifest="$shared_stage/dependencies.sha256"
dependency_sha=$(dependency_digest "$dependency_manifest")

echo "preparing pinned linux/amd64 images for a disconnected App build"
for image in "$GO_BUILD_IMAGE" "$NODE_BUILD_IMAGE" "$APP_RUNTIME_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull --platform "$BINARY_PLATFORM" "$image"
  platform=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
  [ "$platform" = "$BINARY_PLATFORM" ] ||
    die "build image $image is $platform, expected $BINARY_PLATFORM"
done

docker build \
  --platform "$BINARY_PLATFORM" \
  --pull=false \
  --provenance=false \
  --progress=plain \
  -f "$repo_dir/deploy/docker/app-build-deps.Dockerfile" \
  -t "$APP_BUILD_DEPS_IMAGE" \
  --build-arg "GO_BUILD_IMAGE=$GO_BUILD_IMAGE" \
  --build-arg "NODE_BUILD_IMAGE=$NODE_BUILD_IMAGE" \
  --build-arg "DEPENDENCY_LOCK_SHA256=$dependency_sha" \
  "$repo_dir"

echo "exporting nine runtime images"
runtime_archive="$shared_stage/runtime-images-linux-amd64.tar"
# shellcheck disable=SC2086
docker save -o "$runtime_archive" $runtime_images
checksum_create "$runtime_archive"
copy_archive "$runtime_archive" "$deploy_stage/images/runtime/runtime-images-linux-amd64.tar"
copy_archive "$runtime_archive" "$demo_stage/images/runtime/runtime-images-linux-amd64.tar"

echo "exporting offline App build images"
build_archive="$demo_stage/images/build/app-build-images-linux-amd64.tar"
docker save -o "$build_archive" \
  "$APP_BUILD_DEPS_IMAGE" "$GO_BUILD_IMAGE" "$NODE_BUILD_IMAGE" "$APP_RUNTIME_IMAGE"
checksum_create "$build_archive"

# shellcheck disable=SC2086
write_image_inventory "$deploy_stage/manifests/images.txt" $runtime_images
# shellcheck disable=SC2086
write_image_inventory "$demo_stage/manifests/runtime-images.txt" $runtime_images
write_image_inventory "$demo_stage/manifests/build-images.txt" \
  "$APP_BUILD_DEPS_IMAGE" "$GO_BUILD_IMAGE" "$NODE_BUILD_IMAGE" "$APP_RUNTIME_IMAGE"
printf 'git_commit=%s\ngit_branch=%s\n' \
  "$(git -C "$repo_dir" rev-parse HEAD)" \
  "$(git -C "$repo_dir" branch --show-current)" > "$demo_stage/manifests/source-git.txt"

write_source_manifest "$demo_stage"
write_package_manifest "$deploy_stage"
write_package_manifest "$demo_stage"

mv "$deploy_stage" "$deploy_target"
mv "$demo_stage" "$demo_target"
stage=""

echo "created $deploy_target"
echo "created $demo_target"
echo "initial administrator credentials (also recorded in each protected .env):"
printf '  %s\n  %s\n' "$deploy_credentials" "$demo_credentials"
echo "record these manifest hashes outside the delivery directories:"
sha256_file "$deploy_target/manifests/package.sha256"
sha256_file "$demo_target/manifests/package.sha256"
