# P25 voice encryption

Encrypted conventional P25 Phase 1 voice for the DM-32UV Classic build, with keys loaded
over the programming cable and saved in the radio.

**Status: host-tested, never built or run on a radio.** Read "What is not verified" before flashing.

## What it does

- **Algorithms:** AES-256-OFB (ALGID 0x84), DES-OFB (0x81), ADP/RC4 (0xAA). Prefer AES-256.
  DES is a 56-bit key and ADP a 40-bit key; both are weak and are here for compatibility with
  existing fleets.
- **Keys:** four slots, each an algorithm, a 16-bit key ID and a key. One slot (or none) is the
  radio-wide **transmit** slot. Every loaded key is tried on **receive**, matched by
  (algorithm, key ID) from the call's header. An encrypted call with no matching key stays muted.
- **Transmit selection is radio-wide, not per channel.** The channel editor is unchanged.
  Transmit slot 0 sends in the clear.
- **Clear calls are unchanged** and are still received while keys are loaded. There is no
  "secure only" mode and **no on-screen indication that a call is encrypted**.
- **Fails closed:** if a transmit slot is selected but the key or the message-indicator counter
  is not ready, the radio refuses to transmit (the call aborts before the PA is keyed). It never
  falls back to clear.
- **When changes apply:** the transmit key at the next PTT; receive keys at the next PTT or
  channel change (never in the middle of a call).

## Loading keys

```sh
python3 tools/p25_keyload.py status
python3 tools/p25_keyload.py set 1 --alg aes256 --kid 0x0101 --generate --save-key-file fleet.key --tx
python3 tools/p25_keyload.py set 1 --alg aes256 --kid 0x0101 --key-file fleet.key --tx   # every other radio
python3 tools/p25_keyload.py tx clear        # stop encrypting
python3 tools/p25_keyload.py clear 1
python3 tools/p25_keyload.py zeroize --yes
```

Load the same algorithm, key ID and key into every radio that must talk. The tool needs
pyserial and the RadioFoundry tools directory (`make sources`, or set `RFOUNDRY_TOOLS`).
Keys are taken from a file or a hidden prompt, never the command line. After each load the
radio returns a 3-byte key check value (KCV) that the tool compares with its own; the same KCV
on two radios means the same key. `status` warns if keys are not yet saved to flash, if the
stored record was damaged, or if encrypted transmit is blocked.

Key material only travels to the radio. No command reads a key back. There is **no password** on
the cable: whoever holds it can replace, change or erase keys, but not read them.

## Design notes

| Piece | Where |
| --- | --- |
| Ciphers, MI advance, keystream schedule | `src/p25/crypto.c` |
| HDU/LDU1/LDU2 encoding, key lookup, per-frame crypt | `src/p25/p25.c`, `src/p25/voice.c` |
| Key table, 256-byte flash image with CRC-32, key check value | `src/p25/keystore.c` |
| Cable protocol (debug-link private command 0x23) | `src/p25/keyload.c`, `src/p25/keyload.h` |
| Message-indicator source | `src/p25/nonce.c` |
| Flash, boot counter, wiring into the lab/TX paths | `integration/radiofoundry/p25_keys.c`, `p25_lab.c` |
| Host loader | `tools/p25_keyload.py` |

**Message indicators.** OFB mode must never reuse a (key, MI) pair. The radio has no hardware
random-number generator, so the MI is a counter through a bijective 64-bit mixer, seeded from the
chip's unique ID, a boot counter saved in flash, and a random salt the loader supplies with each
key load. It is unique, not random, which is all OFB needs. Within one boot no MI repeats for a
given seed; across radios, boots and loads uniqueness is probabilistic (64 bits). See `nonce.h`.

**Storage.** The last erase sector of the native codeplug area (`0xFFF000` on the DM-32), which
nothing else in Classic writes. **A factory reset does not clear the keys:** the reset's native-area
erase leaves an area that is not blank and has no native-codeplug header alone (it reports "foreign"
and the reset carries on), so use `zeroize`. The same effect means the area no longer reads as blank
to upstream code; a future native-codeplug feature would have to account for the key sector. Writes go
through the storage layer's power-cut-safe journal. A record that fails its magic, version,
CRC or any structural check is discarded whole.

## What is not verified

- **Never built for the radio.** No C-SKY toolchain was available. The new files compile cleanly
  against the real RadioFoundry headers with the host compiler (`-fsyntax-only`, warnings on), and
  all patches apply to the pinned upstream. The target compiler, ABI, the builder's `--stack-check`
  and real RAM/timing have not been run. The glue adds roughly 600 bytes of static RAM and a
  ~200 byte stack snapshot to the P25 worker; `make radiofoundry` re-checks the stack margin.
- **Never run on a radio.** Nothing here has been flashed. Test on a spare unit first, after a
  verified full backup of both flash chips.
- **Interoperability.** The ciphers are verified (FIPS 197, DES, RFC 6229, 600 cross-checks against
  OpenSSL). The P25 key-stream *schedule* (IV from the 72-bit MI, discarded lead-in bytes, 101-byte
  stride per LDU, MI advance) follows published OP25 behavior from memory and has not been checked
  against a recording from a Motorola, Kenwood, BK or similar radio. Two radios running this code
  interoperate with each other; other vendors' encrypted calls are unproven. Every schedule constant
  is in `crypto.h`/`crypto.c`.
- **Whether the key sector can be read by other means.** The debug link's flash-read whitelist does
  not include it, and both CPS protocols (`cps_openfw.c`, `cps_fast.c`) refuse any block that touches
  the native area. A TFTP codeplug read and any physical flash access were not audited; a full-chip
  backup does contain the keys.
- **Cross-task flash job.** `storage_job_post` is a bare check-then-set. The key store posts it with
  preemption off, but a post by another task in the same few instructions could drop one job. The
  loader's `status` shows whether a save landed and retries one that did not.
- **The audio is a stand-in in tests.** The host tests use a fake IMBE codec. They prove the cipher
  and framing round-trip, not audio quality.

## Security limits

- **Keys are stored in plaintext in flash,** and so are in any full-radio backup (the Firmware
  Utility's backup copies both complete chips). Protect backups like keys. There is no secure
  element, no front-panel zeroize and no tamper response.
- **Restoring an old flash backup rewinds the boot counter,** which weakens the MI guarantee. Each
  key load carries a fresh salt for that reason: **reload your keys after restoring a backup.**
- This is not a certified product. P25 encryption in commercial radios is certified and managed with
  a key-management facility; this is a manual, per-radio loader.

## Tests

`make crypto-test` (ciphers, encrypted voice loopback, OpenSSL differential) and `make keys-test`
(key store, serialization, nonce uniqueness against the real voice code, the cable protocol driven
from the Python loader against the actual C handler, key check values against OpenSSL).
Both pass. I also broke the code on purpose in eight places (repeated MIs, MI replay after a key
switch, an unchecked request CRC, an ignored flash-image CRC, zeroize not wiping, duplicate key IDs
allowed, clearing the transmit slot leaving it selected, zeroize resetting the boot counter) and
confirmed each is caught.
`make voice-test` and `make classic-test` need fetched upstream sources and a clang with the
AddressSanitizer runtime, which this development machine lacked; run them where available.

## Still to do

- Per-channel algorithm / key ID in the channel editor and CPS (needs a change to the saved-channel
  format, which was deliberately not done blind).
- Front-panel indication of encrypted calls and a "secure only" receive mode.
- Front-panel zeroize.
- A recorded encrypted call from another vendor to settle the key-stream schedule.
