#!/usr/bin/env python3
"""Build deterministic one-layer archive fixtures from result-producing binaries."""

from __future__ import annotations

import argparse
import gzip
import io
import lzma
import pathlib
import shutil
import tarfile
import zipfile


EPOCH = 946684800  # 2000-01-01T00:00:00Z
ZIP_TIME = (2000, 1, 1, 0, 0, 0)


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


def zip_bytes(entries: list[tuple[str, bytes, int]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, body, mode in entries:
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, body)
    return output.getvalue()


def ar_member(name: str, body: bytes) -> bytes:
    if len(name) > 15:
        raise ValueError(f"ar member name is too long: {name}")
    header = (
        f"{name + '/':<16}{EPOCH:<12}{0:<6}{0:<6}{0o100644:<8o}{len(body):<10}`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise AssertionError("invalid ar member header")
    return header + body + (b"\n" if len(body) % 2 else b"")


def gzip_bytes(body: bytes, original_name: str = "") -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename=original_name, mode="wb", fileobj=output, mtime=EPOCH, compresslevel=9
    ) as stream:
        stream.write(body)
    return output.getvalue()


def build_deb(elf: bytes) -> bytes:
    control = tar_bytes(
        [
            (
                "./control",
                b"Package: binaryscan-vulnerable-binaries\n"
                b"Version: 1.0\nArchitecture: amd64\nMaintainer: BinaryScan\n"
                b"Description: offline static-analysis fixture\n",
                0o644,
            )
        ]
    )
    data = tar_bytes([("./usr/bin/vulnerable-elf", elf, 0o755)])
    return (
        b"!<arch>\n"
        + ar_member("debian-binary", b"2.0\n")
        + ar_member("control.tar.gz", gzip_bytes(control))
        + ar_member("data.tar.gz", gzip_bytes(data))
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary-dir", required=True, type=pathlib.Path)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    arguments = parser.parse_args()

    elf = (arguments.binary_dir / "vulnerable-elf").read_bytes()
    exe = (arguments.binary_dir / "vulnerable.exe").read_bytes()
    entries = [("vulnerable-elf", elf, 0o755), ("vulnerable.exe", exe, 0o755)]
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    (arguments.output_dir / "vulnerable-binaries.zip").write_bytes(zip_bytes(entries))
    (arguments.output_dir / "vulnerable-binaries.tar").write_bytes(tar_bytes(entries))
    (arguments.output_dir / "vulnerable-elf.gz").write_bytes(
        gzip_bytes(elf, "vulnerable-elf")
    )
    (arguments.output_dir / "vulnerable-elf.xz").write_bytes(
        lzma.compress(elf, format=lzma.FORMAT_XZ, preset=9)
    )
    (arguments.output_dir / "vulnerable-binaries.deb").write_bytes(build_deb(elf))
    shutil.copyfile(
        arguments.binary_dir / "vulnerable.jar",
        arguments.output_dir / "vulnerable-binaries.jar",
    )
    shutil.copyfile(
        arguments.binary_dir / "vulnerable.apk",
        arguments.output_dir / "vulnerable-binaries.apk",
    )


if __name__ == "__main__":
    main()
