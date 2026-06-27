#!/usr/bin/env python3
"""
Extract qy_acc embedded MQTT TLS material for authorized lab validation.

The script does not contain the PEMs. It decrypts the encrypted blobs embedded
in qy_acc using the same AES-CBC wrapper used by n_carr_dec().
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import tempfile
from pathlib import Path


LOAD2_VA = 0x84590
LOAD2_OFF = 0x74590

CONST_A = bytes.fromhex("c5ccd8908efa1a54144d15569c1cf468")
CONST_B = bytes.fromhex("f0ea8ae8d0a03b3b3a1f3608f931d83f")

PROFILES = {
    "LCL": 0x8AFF8,
    "DBG": 0x8B070,
    "LJB": 0x8B0E8,
}

FIELDS = {
    "username": (0x00, 0x08, 0x10, ".txt"),
    "password": (0x18, 0x20, 0x28, ".txt"),
    "ca": (0x30, 0x38, 0x40, ".pem"),
    "cert": (0x48, 0x50, 0x58, ".pem"),
    "pkey": (0x60, 0x68, 0x70, ".pem"),
}


def va_to_off(va: int) -> int:
    if va >= LOAD2_VA:
        return va - LOAD2_VA + LOAD2_OFF
    return va


def read_at(blob: bytes, va: int, size: int) -> bytes:
    off = va_to_off(va)
    if off < 0 or off + size > len(blob):
        raise ValueError(f"VA 0x{va:x} size 0x{size:x} is outside the binary")
    return blob[off : off + size]


def qword_at(blob: bytes, base_va: int, offset: int) -> int:
    off = va_to_off(base_va) + offset
    return struct.unpack_from("<Q", blob, off)[0]


def derive_key(blob: bytes, key_va: int) -> bytes:
    material = read_at(blob, key_va, 16)
    return bytes(material[i] ^ CONST_A[i] ^ CONST_B[i] for i in range(16))


def aes_cbc_decrypt_with_openssl(ciphertext: bytes, key: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as src:
        src.write(ciphertext)
        src_path = Path(src.name)
    out_path = src_path.with_suffix(".out")

    try:
        subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-128-cbc",
                "-d",
                "-K",
                key.hex(),
                "-iv",
                key.hex(),
                "-nopad",
                "-in",
                str(src_path),
                "-out",
                str(out_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        plaintext = out_path.read_bytes()
    finally:
        for path in (src_path, out_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    pad = plaintext[-1]
    if pad < 1 or pad > 16:
        raise ValueError(f"bad PKCS#7 padding byte: {pad}")
    return plaintext[:-pad]


def extract_profile(blob: bytes, profile: str, out_dir: Path) -> None:
    table_va = PROFILES[profile]
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, (ptr_off, len_off, key_off, suffix) in FIELDS.items():
        data_va = qword_at(blob, table_va, ptr_off)
        enc_len = qword_at(blob, table_va, len_off)
        key_va = qword_at(blob, table_va, key_off)
        if data_va == 0 or enc_len == 0:
            continue

        key = derive_key(blob, key_va)
        plaintext = aes_cbc_decrypt_with_openssl(read_at(blob, data_va, enc_len), key)
        if suffix == ".pem" and not plaintext.endswith(b"\n"):
            plaintext += b"\n"

        out_path = out_dir / f"{profile}_{name}{suffix}"
        out_path.write_bytes(plaintext)
        if name == "pkey":
            os.chmod(out_path, 0o600)
        print(f"[+] {name:8s} -> {out_path} ({len(plaintext)} bytes)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        default="opt/game_acc/qiyou/app/bin/qy/bin/qy_acc",
        help="path to qy_acc",
    )
    parser.add_argument("--profile", choices=sorted(PROFILES), default="LJB")
    parser.add_argument("--out", default="/tmp/qy_mqtt_tls_material")
    args = parser.parse_args()

    blob = Path(args.binary).read_bytes()
    extract_profile(blob, args.profile, Path(args.out))


if __name__ == "__main__":
    main()
