#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build and run the P25 crypto and encrypted-voice loopback tests, then diff the ciphers against OpenSSL.

DES, AES-256 and RC4 are compared on random inputs. The P25 keystream schedule
(IV from MI, lead-in bytes, per-LDU stride) has no independent oracle here;
see the validation note in src/p25/crypto.h.
"""
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/crypto-host"
EXE = OUT / "test_crypto"


def run(args, **kw):
    return subprocess.run([str(a) for a in args], cwd=ROOT, check=True, capture_output=True, text=True, **kw).stdout


def openssl(args, data):
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    run([cc, "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1", "-g",
         "-fsanitize=address,undefined", "-Isrc/p25", "src/p25/crypto.c",
         "tests/crypto/test_crypto.c", "-o", EXE])
    print(run([EXE]).strip())
    loop = OUT / "test_voice_crypto"
    run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-fsanitize=address,undefined",
         "-fno-omit-frame-pointer", "-Isrc/p25", "-Isrc/codec", "src/p25/p25.c", "src/p25/crypto.c",
         "src/p25/voice.c", "tests/crypto/test_voice_crypto.c", "-o", loop])
    print(run([loop]).strip())
    if not shutil.which("openssl"):
        print("openssl not found; skipping differential checks")
        return
    rng = random.Random(0x25DE5)
    checks = 0
    for _ in range(200):
        key8, blk8 = rng.randbytes(8), rng.randbytes(8)
        key32, blk16 = rng.randbytes(32), rng.randbytes(16)
        want = openssl(["enc", "-des-ecb", "-provider", "legacy", "-provider", "default", "-nopad", "-K", key8.hex()], blk8)
        assert run([EXE, "vec", "des", key8.hex(), blk8.hex()]).strip() == want.hex(), ("DES", key8.hex(), blk8.hex())
        want = openssl(["enc", "-aes-256-ecb", "-nopad", "-K", key32.hex()], blk16)
        assert run([EXE, "vec", "aes", key32.hex(), blk16.hex()]).strip() == want.hex(), ("AES", key32.hex(), blk16.hex())
        # OpenSSL fixes the RC4 key size per cipher name: rc4 = 16 bytes, rc4-40 = 5 bytes.
        cipher, klen = rng.choice([("rc4-40", 5), ("rc4", 16)])
        skip, key = rng.choice([0, 1, 267, 368]), rng.randbytes(klen)
        stream = openssl(["enc", f"-{cipher}", "-provider", "legacy", "-provider", "default", "-K", key.hex()], bytes(skip + 32))
        assert run([EXE, "vec", "rc4", key.hex(), "00", str(skip)]).strip() == stream[skip:skip + 32].hex(), ("RC4", cipher, key.hex(), skip)
        checks += 3
    print(f"openssl differential: {checks} comparisons matched")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, AssertionError) as exc:
        detail = getattr(exc, "stderr", "") or getattr(exc, "stdout", "") or ""
        print("FAILED:", exc, detail)
        sys.exit(1)
