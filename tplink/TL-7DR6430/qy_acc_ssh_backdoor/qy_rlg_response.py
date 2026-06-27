#!/usr/bin/env python3
"""
Decode qy_acc rlg SSH challenge.

The qy_acc rlg path prints:

    ENC------
    <base64 RSA ciphertext>
    END------

Static analysis shows:

    ENC = base64(RSA_public_encrypt(md5_random, rlg_public_key))

So a matching private key is needed to recover the 32-byte MD5 response.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def openssl_stdout(args: list[str], input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        args,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout


def public_der_hash_from_private(private_key: Path) -> str:
    der = openssl_stdout(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-outform",
            "DER",
        ]
    )
    return hashlib.sha256(der).hexdigest()


def public_der_hash(public_key: Path) -> str:
    der = openssl_stdout(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-pubout",
            "-outform",
            "DER",
        ]
    )
    return hashlib.sha256(der).hexdigest()


def decrypt_challenge(private_key: Path, enc_b64: str) -> bytes:
    ciphertext = base64.b64decode("".join(enc_b64.split()), validate=True)
    with tempfile.NamedTemporaryFile(delete=False) as src:
        src.write(ciphertext)
        src_path = Path(src.name)
    try:
        return openssl_stdout(
            [
                "openssl",
                "pkeyutl",
                "-decrypt",
                "-inkey",
                str(private_key),
                "-in",
                str(src_path),
                "-pkeyopt",
                "rsa_padding_mode:pkcs1",
            ]
        )
    finally:
        try:
            src_path.unlink()
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private", required=True, help="candidate RSA private key")
    parser.add_argument("--enc", required=True, help="base64 text between ENC------ and END------")
    parser.add_argument(
        "--public",
        default="artifacts/s030_ssh_material/rlg_challenge_rsa_public.pem",
        help="rlg public key extracted from qy_acc",
    )
    parser.add_argument("--skip-key-check", action="store_true")
    args = parser.parse_args()

    private_key = Path(args.private)
    public_key = Path(args.public)

    if not args.skip_key_check:
        expected = public_der_hash(public_key)
        actual = public_der_hash_from_private(private_key)
        if actual != expected:
            print("[-] private key does not match qy_acc rlg public key", file=sys.stderr)
            print(f"    expected public DER sha256: {expected}", file=sys.stderr)
            print(f"    actual   public DER sha256: {actual}", file=sys.stderr)
            return 2

    response = decrypt_challenge(private_key, args.enc)
    text = response.decode("ascii", "replace").strip()
    print(text)
    if len(text) != 32 or any(c not in "0123456789abcdefABCDEF" for c in text):
        print(
            "[!] decrypted response is not a 32-byte hex MD5 string; verify padding/key",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
