#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Load P25 voice-encryption keys into a radio over its programming cable.

    p25_keyload.py [--port DEV] status
    p25_keyload.py [--port DEV] set SLOT --alg aes256|des|adp --kid N [--key-file FILE] [--tx]
    p25_keyload.py [--port DEV] set SLOT --alg aes256 --kid N --generate --save-key-file FILE [--tx]
    p25_keyload.py [--port DEV] tx SLOT|clear
    p25_keyload.py [--port DEV] clear SLOT
    p25_keyload.py [--port DEV] zeroize --yes

Keys are only ever sent TO the radio. Nothing here, and nothing in the firmware, can read one back; the radio
answers with a 3-byte key check value (KCV), which this tool compares with its own calculation.

A key never goes on the command line (shell history and process lists would keep it). Give --key-file, or type it at
the hidden prompt, as hex: 64 digits for AES-256, 16 for DES, 10 for ADP. Every load carries a fresh random salt that
keeps the radio's message indicators from repeating; do not reuse a salt, and reload keys after restoring a flash
backup. Load the same key and key ID into every radio that must talk to each other.

Protocol: src/p25/keyload.h (debug-link private command 0x23). Needs pyserial (pip install pyserial) and, for the
port discovery and framing, the RadioFoundry tools directory ($RFOUNDRY_TOOLS, or research/upstream/radiofoundry/tools
after `make radiofoundry`).
"""
import argparse
import getpass
import os
import struct
import sys
import time
import zlib
from pathlib import Path

CMD = 0x23
OP_STATUS, OP_SET, OP_CLEAR, OP_ZEROIZE, OP_TX = 1, 2, 3, 4, 5
SLOTS = 4
FLAG_PERSISTED, FLAG_NONCE_READY, FLAG_FLASH_OK, FLAG_STORED_CORRUPT = 1, 2, 4, 8

ALGS = {"des": (0x81, 8), "aes256": (0x84, 32), "adp": (0xAA, 5)}
ALG_NAMES = {v[0]: k for k, v in ALGS.items()}

# Error detail byte of a refused request (src/p25/keyload.h, keystore.h)
DETAIL = {1: "slot must be 1-4", 2: "unsupported algorithm or wrong key length", 3: "key is all zero",
          4: "that algorithm and key ID are already loaded in another slot", 5: "salt is all zero",
          6: "that slot is empty", 100: "request length", 101: "request failed its CRC (cable error?)",
          102: "unknown operation", 103: "zeroize confirmation wrong", 104: "the radio's flash is not usable for keys"}


class KeyloadError(Exception):
    pass


# ── pure protocol helpers (tested against the firmware's own handler in tools/test_keys.py) ──
def encode_set(slot, alg, kid, key, salt):
    if not 1 <= slot <= SLOTS:
        raise KeyloadError(f"slot must be 1-{SLOTS}")
    if alg not in ALG_NAMES:
        raise KeyloadError("unknown algorithm")
    if len(key) != ALGS[ALG_NAMES[alg]][1]:
        raise KeyloadError(f"{ALG_NAMES[alg]} needs a {ALGS[ALG_NAMES[alg]][1]}-byte key, got {len(key)}")
    if not 0 <= kid <= 0xFFFF:
        raise KeyloadError("key ID must be 0-65535")
    if len(salt) != 4 or not any(salt):
        raise KeyloadError("salt must be 4 nonzero-random bytes")
    body = bytes([slot, alg]) + struct.pack("<H", kid) + bytes([len(key)]) + bytes(salt) + bytes(key)
    return bytes([OP_SET]) + body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def encode_clear(slot):
    return bytes([OP_CLEAR, slot])


def encode_tx(slot):
    return bytes([OP_TX, slot])


def encode_zeroize():
    return bytes([OP_ZEROIZE]) + b"ZERO"


def parse_status(body):
    if len(body) < 8 + SLOTS * 6:
        raise KeyloadError("short status reply")
    version, nslots, tx, flags, boot = struct.unpack("<BBBBI", body[:8])
    slots = []
    for i in range(nslots):
        alg, kid = struct.unpack("<BH", body[8 + i * 6:8 + i * 6 + 3])
        slots.append({"slot": i + 1, "alg": alg, "kid": kid, "kcv": body[8 + i * 6 + 3:8 + i * 6 + 6]})
    return {"version": version, "tx_slot": tx, "flags": flags, "boot_count": boot, "slots": slots}


# ── key check value: first 3 bytes of the key encrypting a zero block (ADP: RC4 keystream) ──
def _aes_tables():
    sbox, p, q = [0] * 256, 1, 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) & 0xFF ^ (q << 2 | q >> 6) & 0xFF ^ (q << 3 | q >> 5) & 0xFF ^ (q << 4 | q >> 4) & 0xFF
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


def aes256_encrypt_block(key, block):
    """Single-block AES-256 (FIPS 197), pure Python so the key never reaches another process."""
    sbox = _aes_tables()
    xt = lambda a: ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else a << 1
    w = [list(key[4 * i:4 * i + 4]) for i in range(8)]
    rcon = 1
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [sbox[t[1]] ^ rcon, sbox[t[2]], sbox[t[3]], sbox[t[0]]]
            rcon = xt(rcon)
        elif i % 8 == 4:
            t = [sbox[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    rk = [sum(w[4 * r:4 * r + 4], []) for r in range(15)]
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 15):
        s = [sbox[b] for b in s]
        s = [s[row + 4 * ((col + row) % 4)] for col in range(4) for row in range(4)]   # ShiftRows
        if r < 14:
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [xt(a[0]) ^ xt(a[1]) ^ a[1] ^ a[2] ^ a[3], a[0] ^ xt(a[1]) ^ xt(a[2]) ^ a[2] ^ a[3],
                        a[0] ^ a[1] ^ xt(a[2]) ^ xt(a[3]) ^ a[3], xt(a[0]) ^ a[0] ^ a[1] ^ a[2] ^ xt(a[3])]
            s = out
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


def rc4_keystream(key, n):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0; out = []
    for _ in range(n):
        i = (i + 1) & 0xFF; j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def local_kcv(alg, key):
    """The KCV the radio should report, or None where this machine can't compute it (DES needs the
    `cryptography` package with legacy ciphers)."""
    if alg == 0x84:
        return aes256_encrypt_block(key, bytes(16))[:3]
    if alg == 0xAA:
        return rc4_keystream(key, 3)
    try:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        enc = Cipher(TripleDES(bytes(key) * 3), modes.ECB()).encryptor()   # k,k,k is single DES
        return (enc.update(bytes(8)) + enc.finalize())[:3]
    except Exception:
        return None


# ── radio access ──
def open_link(port):
    tools = os.environ.get("RFOUNDRY_TOOLS") or str(Path(__file__).resolve().parents[1] / "research/upstream/radiofoundry/tools")
    if not Path(tools, "rfoundry_debug.py").exists():
        raise KeyloadError("can't find rfoundry_debug.py; run `make sources` or set RFOUNDRY_TOOLS to the RadioFoundry tools directory")
    sys.path.insert(0, tools)
    import rfoundry_debug as rd
    try:
        return rd.DebugLink(port), rd.DebugLinkError
    except rd.DebugLinkError as e:
        raise KeyloadError(str(e))


def send(link, err, payload):
    try:
        _, data = link.request(CMD, payload)
        return bytes(data)
    except err as e:
        detail = DETAIL.get(e.data[0], f"code {e.data[0]}") if getattr(e, "data", b"") else ""
        raise KeyloadError(f"{e}" + (f" ({detail})" if detail else ""))


def read_hex_key(alg_name, path):
    want = ALGS[alg_name][1]
    if path:
        text = Path(path).read_text()
    else:
        text = getpass.getpass(f"{alg_name} key as {want * 2} hex digits (hidden): ")
    text = "".join(text.split())
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise KeyloadError("the key must be hex digits only")
    if len(key) != want:
        raise KeyloadError(f"{alg_name} needs {want * 2} hex digits, got {len(text)}")
    return key


def show_status(st):
    f = st["flags"]
    print(f"boot count {st['boot_count']}   transmit: " +
          (f"encrypted with slot {st['tx_slot']}" if st["tx_slot"] else "clear (no encryption)"))
    print(" slot  algorithm  key ID   KCV")
    for s in st["slots"]:
        if s["alg"]:
            print(f"  {s['slot']}    {ALG_NAMES.get(s['alg'], hex(s['alg'])):<9} {s['kid']:<7} {s['kcv'].hex()}" +
                  ("   <- transmit" if s["slot"] == st["tx_slot"] else ""))
        else:
            print(f"  {s['slot']}    (empty)")
    if not f & FLAG_FLASH_OK:
        print("WARNING: the radio's flash is not usable for keys; nothing can be loaded or saved.")
    if f & FLAG_STORED_CORRUPT:
        print("WARNING: the stored key record was damaged at power-up and was discarded. Reload every key.")
    if not f & FLAG_PERSISTED:
        print("WARNING: the current keys are NOT saved to flash yet; they will be lost at power-off. Run status again.")
    if st["tx_slot"] and not f & FLAG_NONCE_READY:
        print("WARNING: encrypted transmit is BLOCKED (the radio could not secure its message-indicator counter). "
              "It will refuse to transmit rather than send clear.")


def get_status(link, err):
    return parse_status(send(link, err, bytes([OP_STATUS])))


def wait_persisted(link, err, seconds=5.0):
    end = time.monotonic() + seconds
    while True:
        st = get_status(link, err)
        if st["flags"] & FLAG_PERSISTED or time.monotonic() > end:
            return st
        time.sleep(0.3)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--port")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    p = sub.add_parser("set")
    p.add_argument("slot", type=int)
    p.add_argument("--alg", choices=sorted(ALGS), required=True)
    p.add_argument("--kid", type=lambda s: int(s, 0), required=True, help="key ID, 0-65535 (0x... allowed)")
    p.add_argument("--key-file")
    p.add_argument("--generate", action="store_true", help="make a random key instead of reading one")
    p.add_argument("--save-key-file", help="with --generate: write the new key here (mode 0600) to load the other radios")
    p.add_argument("--tx", action="store_true", help="also make this the transmit key")
    p = sub.add_parser("tx"); p.add_argument("slot", help="1-4, or 'clear' for clear transmit")
    p = sub.add_parser("clear"); p.add_argument("slot", type=int)
    p = sub.add_parser("zeroize"); p.add_argument("--yes", action="store_true", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "set":
            alg, klen = ALGS[a.alg]
            if a.generate:
                if not a.save_key_file:
                    raise KeyloadError("--generate needs --save-key-file; the key is never shown on screen")
                key = os.urandom(klen)
                fd = os.open(a.save_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(key.hex() + "\n")
                print(f"New key written to {a.save_key_file}. Load it into every radio, then store the file safely.")
            else:
                key = read_hex_key(a.alg, a.key_file)
            salt = os.urandom(4)
            while not any(salt):
                salt = os.urandom(4)
            payload = encode_set(a.slot, alg, a.kid, key, salt)
        link, err = open_link(a.port)
        try:
            if a.cmd == "status":
                show_status(get_status(link, err))
            elif a.cmd == "set":
                kcv = send(link, err, payload)
                want = local_kcv(alg, key)
                print(f"Slot {a.slot} loaded. Radio KCV {kcv.hex()}" +
                      ("" if want is None else "  (matches)" if want == kcv else "  MISMATCH, expected " + want.hex()))
                if want is not None and want != kcv:
                    raise KeyloadError("the radio stored something other than the key sent; clear the slot and retry")
                if a.tx:
                    send(link, err, encode_tx(a.slot))
                show_status(wait_persisted(link, err))
            elif a.cmd == "tx":
                slot = 0 if a.slot == "clear" else int(a.slot)
                send(link, err, encode_tx(slot))
                show_status(wait_persisted(link, err))
            elif a.cmd == "clear":
                send(link, err, encode_clear(a.slot))
                show_status(wait_persisted(link, err))
            elif a.cmd == "zeroize":
                send(link, err, encode_zeroize())
                show_status(wait_persisted(link, err))
        finally:
            link.close()
    except KeyloadError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
