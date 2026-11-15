#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build and run the key store / key load / nonce tests, then drive the real firmware handler from the Python loader.

The C handler is compiled for the host (tests/keys/harness.c) and fed the loader's own encoded requests, so the wire
format, CRC, key check values and the flash image are checked end to end. KCVs are compared with OpenSSL.
"""
from pathlib import Path
import os
import random
import shutil
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import p25_keyload as kl  # noqa: E402

OUT = ROOT / "build/keys-host"
SRC = ["src/p25/crypto.c", "src/p25/keystore.c", "src/p25/keyload.c", "src/p25/nonce.c"]
FLASH_OK, PERSISTED, NONCE = 4, 1, 2


def run(args, **kw):
    return subprocess.run([str(a) for a in args], cwd=ROOT, check=True, capture_output=True, text=True, **kw).stdout


def openssl(args, data):
    return subprocess.run(["openssl", *args], input=data, check=True, capture_output=True).stdout


class Harness:
    def __init__(self, exe):
        self.p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, cwd=ROOT)

    def ask(self, line):
        self.p.stdin.write(line + "\n"); self.p.stdin.flush()
        return self.p.stdout.readline().strip()

    def req(self, payload):
        cls, _, body = self.ask("req " + payload.hex()).partition(" ")
        return int(cls), bytes.fromhex(body)

    def blob(self):
        return bytes.fromhex(self.ask("blob"))

    def close(self):
        self.p.stdin.close(); self.p.wait()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    san = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    unit = OUT / "test_keys"
    run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", *san, "-Isrc/p25", "-Isrc/codec",
         "src/p25/p25.c", "src/p25/voice.c", *SRC, "tests/keys/test_keys.c", "-o", unit])
    print(run([unit]).strip())
    exe = OUT / "harness"
    run([cc, "-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1", "-g", *san, "-Isrc/p25",
         *SRC, "tests/keys/harness.c", "-o", exe])

    # AES, RC4 and CRC helpers against known answers
    assert kl.aes256_encrypt_block(bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == \
        "8ea2b7ca516745bfeafc49904b496089", "FIPS 197 C.3"
    assert kl.rc4_keystream(b"Key", 4).hex() == "eb9f7781", "RC4 known answer"

    rng = random.Random(0x25DE5)
    h = Harness(exe)
    checks = 0
    try:
        for slot, (name, kid) in enumerate([("aes256", 0x0102), ("des", 0x0102), ("adp", 7), ("aes256", 0xFFFF)], 1):
            alg, klen = kl.ALGS[name]
            key, salt = rng.randbytes(klen), rng.randbytes(4)
            cls, body = h.req(kl.encode_set(slot, alg, kid, key, salt))
            assert cls == 0 and len(body) == 3, ("set", name, cls)
            # independent KCV: OpenSSL encrypting a zero block
            if name == "aes256":
                want = openssl(["enc", "-aes-256-ecb", "-nopad", "-K", key.hex()], bytes(16))[:3]
            elif name == "des":
                want = openssl(["enc", "-des-ecb", "-provider", "legacy", "-provider", "default", "-nopad", "-K", key.hex()], bytes(8))[:3]
            else:
                want = openssl(["enc", "-rc4-40", "-provider", "legacy", "-provider", "default", "-K", key.hex()], bytes(3))
            assert body == want, (name, body.hex(), want.hex())
            mine = kl.local_kcv(alg, key)
            assert mine is None or mine == body, ("loader KCV", name, mine and mine.hex(), body.hex())
            checks += 1

        cls, body = h.req(bytes([kl.OP_STATUS]))
        st = kl.parse_status(body)
        assert cls == 0 and [s["alg"] for s in st["slots"]] == [0x84, 0x81, 0xAA, 0x84]
        assert st["flags"] == FLASH_OK | PERSISTED | NONCE and st["tx_slot"] == 0

        # the flash image: documented layout, CRC, and (stated plainly) keys held in plaintext
        blob = h.blob()
        assert blob[:4] == b"P25K" and blob[4] == 1 and len(blob) == 256
        assert int.from_bytes(blob[252:], "little") == zlib.crc32(blob[:252]) & 0xFFFFFFFF
        assert h.req(kl.encode_tx(2))[0] == 0 and h.blob()[5] == 2
        assert h.req(kl.encode_tx(0))[0] == 0

        # no single-bit corruption of any SET changes the store
        before = h.blob()
        req = kl.encode_set(2, 0x84, 0x0555, rng.randbytes(32), b"\x01\x02\x03\x04")
        for bit in range(8, 8 * len(req)):
            bad = bytearray(req); bad[bit // 8] ^= 1 << (bit % 8)
            cls, _ = h.req(bytes(bad))
            assert h.blob() == before, ("corrupt SET changed the store", bit, cls)
            checks += 1

        # the same image loads into a fresh radio
        h2 = Harness(exe)
        assert h2.ask("load " + before.hex()) == "0"
        assert h2.req(bytes([kl.OP_STATUS]))[1] == h.req(bytes([kl.OP_STATUS]))[1]
        assert h2.ask("load " + ("ff" * 256)) == "1", "blank flash"
        h2.close()

        # no flash: reads still work, writes refused
        h.ask("flags 0")
        assert h.req(bytes([kl.OP_STATUS]))[0] == 0
        assert h.req(kl.encode_clear(1))[0] == 2
        h.ask(f"flags {FLASH_OK | PERSISTED | NONCE}")

        # zeroize: every key byte, id and salt gone from the image; the boot counter survives
        assert h.req(kl.encode_zeroize())[0] == 0
        blob = h.blob()
        assert not any(blob[12:12 + 4 * 39]) and blob[5] == 0
        assert blob[8:12] == before[8:12], "boot count must survive zeroize"
        assert h.req(bytes([kl.OP_ZEROIZE]) + b"NOPE")[0] == 1
    finally:
        h.close()

    # encode_set refuses what the firmware would
    for args in [(0, 0x84, 1, bytes(32), b"1234"), (1, 0x84, 1, bytes(16), b"1234"), (1, 0x84, 1, bytes(32), bytes(4)),
                 (1, 0x83, 1, bytes(32), b"1234")]:
        try:
            kl.encode_set(*args); raise AssertionError(("accepted", args))
        except kl.KeyloadError:
            pass
    print(f"loader <-> firmware handler tests passed ({checks} checks, KCVs match OpenSSL)")


if __name__ == "__main__":
    main()
