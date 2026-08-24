#!/usr/bin/env python3
"""Build deterministic Docker-save and OCI-layout fixture archives."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import tarfile
import zipfile


EPOCH = 946684800  # 2000-01-01T00:00:00Z
CREATED = "2000-01-01T00:00:00Z"
IMAGE_REFERENCE = "binaryscan/vulnerable-fixture:latest"
BINARY_NAMES = (
    "vulnerable-macho",
    "VulnerableFixture.class",
    "vulnerable.jar",
    "vulnerable.pyc",
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def tar_bytes(entries: list[tuple[str, bytes, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body, mode in entries:
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = mode
            info.mtime = EPOCH
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(body))
    return output.getvalue()


def vulnerable_dependency_jar() -> bytes:
    output = io.BytesIO()
    members = (
        (
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\nImplementation-Title: log4j-core\nImplementation-Version: 2.14.1\n\n",
        ),
        (
            "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
            b"groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
        ),
    )
    with zipfile.ZipFile(
        output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, body in members:
            info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, body)
    return output.getvalue()


def build_layer(binary_dir: pathlib.Path) -> bytes:
    entries: list[tuple[str, bytes, int]] = []
    for name in BINARY_NAMES:
        source = binary_dir / name
        if not source.is_file():
            raise SystemExit(f"missing binary fixture: {source}")
        mode = 0o755 if name == "vulnerable-macho" else 0o644
        entries.append((f"opt/binaryscan-fixtures/{name}", source.read_bytes(), mode))
    entries.append(
        (
            "opt/binaryscan-fixtures/log4j-core-2.14.1.jar",
            vulnerable_dependency_jar(),
            0o644,
        )
    )
    return tar_bytes(entries)


def build_config(layer_digest: str) -> bytes:
    return json_bytes(
        {
            "architecture": "amd64",
            "config": {
                "Labels": {
                    "org.opencontainers.image.created": CREATED,
                    "org.opencontainers.image.description": (
                        "Offline BinaryScan fixture; contains synthetic Log4j 2.14.1 metadata"
                    ),
                    "org.opencontainers.image.title": "BinaryScan vulnerable image fixture",
                },
                "WorkingDir": "/opt/binaryscan-fixtures",
            },
            "created": CREATED,
            "history": [
                {
                    "created": CREATED,
                    "created_by": "BinaryScan deterministic fixture generator",
                }
            ],
            "os": "linux",
            "rootfs": {
                "diff_ids": [f"sha256:{layer_digest}"],
                "type": "layers",
            },
        }
    )


def build_docker_archive(layer: bytes, config: bytes) -> bytes:
    layer_digest = digest(layer)
    config_digest = digest(config)
    layer_name = f"{layer_digest}/layer.tar"
    manifest = json_bytes(
        [
            {
                "Config": f"{config_digest}.json",
                "Layers": [layer_name],
                "RepoTags": [IMAGE_REFERENCE],
            }
        ]
    )
    return tar_bytes(
        [
            ("manifest.json", manifest, 0o644),
            (f"{config_digest}.json", config, 0o644),
            (layer_name, layer, 0o644),
        ]
    )


def build_oci_archive(layer: bytes, config: bytes) -> bytes:
    config_digest = digest(config)
    layer_digest = digest(layer)
    manifest_media_type = "application/vnd.oci.image.manifest.v1+json"
    manifest = json_bytes(
        {
            "config": {
                "digest": f"sha256:{config_digest}",
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config),
            },
            "layers": [
                {
                    "digest": f"sha256:{layer_digest}",
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "size": len(layer),
                }
            ],
            "mediaType": manifest_media_type,
            "schemaVersion": 2,
        }
    )
    manifest_digest = digest(manifest)
    index = json_bytes(
        {
            "manifests": [
                {
                    "annotations": {
                        "org.opencontainers.image.ref.name": "latest",
                    },
                    "digest": f"sha256:{manifest_digest}",
                    "mediaType": manifest_media_type,
                    "platform": {"architecture": "amd64", "os": "linux"},
                    "size": len(manifest),
                }
            ],
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2,
        }
    )
    layout = json_bytes({"imageLayoutVersion": "1.0.0"})
    return tar_bytes(
        [
            ("oci-layout", layout, 0o644),
            ("index.json", index, 0o644),
            (f"blobs/sha256/{config_digest}", config, 0o644),
            (f"blobs/sha256/{manifest_digest}", manifest, 0o644),
            (f"blobs/sha256/{layer_digest}", layer, 0o644),
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-dir", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    layer = build_layer(arguments.binary_dir)
    config = build_config(digest(layer))
    (arguments.output_dir / "docker-save.tar").write_bytes(
        build_docker_archive(layer, config)
    )
    (arguments.output_dir / "oci-layout.tar").write_bytes(
        build_oci_archive(layer, config)
    )


if __name__ == "__main__":
    main()
