#!/usr/bin/env python3
import pathlib
import struct
import sys
import zlib


def header(kind: int, flags: int, body: bytes) -> bytes:
    size = 7 + len(body)
    payload = struct.pack("<BHH", kind, flags, size) + body
    return struct.pack("<H", zlib.crc32(payload) & 0xFFFF) + payload


def file_header(name: str, value: bytes) -> bytes:
    encoded_name = name.encode("utf-8")
    body = struct.pack(
        "<IIBIIBBHI",
        len(value),
        len(value),
        3,
        zlib.crc32(value) & 0xFFFFFFFF,
        0,
        20,
        0x30,
        len(encoded_name),
        0o100755,
    ) + encoded_name
    return header(0x74, 0x8000, body) + value


def main() -> None:
    if len(sys.argv) < 4 or len(sys.argv[2:]) % 2:
        raise SystemExit("usage: build-rar-fixture.py OUTPUT NAME INPUT [NAME INPUT ...]")
    output = pathlib.Path(sys.argv[1])
    members = list(zip(sys.argv[2::2], sys.argv[3::2]))
    archive = bytearray(b"Rar!\x1a\x07\x00")
    archive.extend(header(0x73, 0, b"\x00" * 6))
    for name, source in members:
        archive.extend(file_header(name, pathlib.Path(source).read_bytes()))
    archive.extend(header(0x7B, 0, b""))
    output.write_bytes(archive)


if __name__ == "__main__":
    main()
