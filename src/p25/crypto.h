/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DM32_P25_CRYPTO_H
#define DM32_P25_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P25 Phase 1 voice encryption: DES-OFB (0x81), AES-256-OFB (0x84) and
 * ADP/RC4 (0xAA). No allocation, no I/O, no globals except one lazily built
 * 256-byte AES S-box. Callers serialize access.
 *
 * VALIDATION STATUS. The ciphers themselves (DES, AES-256, RC4) are checked
 * against FIPS 46/197 and RFC 6229 vectors and against OpenSSL in
 * tests/crypto. The P25 keystream SCHEDULE below (IV construction from the
 * 72-bit MI, discarded lead-in bytes, per-LDU stride, MI advance) follows the
 * commonly published OP25 behavior but has NOT been checked against a capture
 * from a commercial P25 radio. Two radios running this code interoperate with
 * each other; interoperability with other vendors' encrypted calls is
 * unverified. Every schedule constant is defined here and nowhere else.
 */
enum {
    P25_ALG_CLEAR = 0x80,
    P25_ALG_DES_OFB = 0x81,
    P25_ALG_AES256 = 0x84,
    P25_ALG_ADP = 0xaa,

    P25_MI_BYTES = 9,
    P25_KEY_MAX_BYTES = 32,
    P25_KS_VOICE_BYTES = 11,        /* one 88-bit IMBE frame */
    P25_KS_LDU_BYTES = 101,         /* 9 voice frames + 2 low-speed-data bytes */
    P25_KS_LEAD_OFB = 8,            /* keystream discarded before LDU1 (DES/AES) */
    P25_KS_LEAD_ADP = 267           /* RC4 keystream discarded before LDU1 */
};

typedef struct {
    uint8_t algorithm_id;           /* P25_ALG_DES_OFB / AES256 / ADP */
    uint16_t key_id;
    uint8_t key[P25_KEY_MAX_BYTES]; /* DES 8, ADP 5, AES-256 32 bytes used */
} p25_key;

/* Key length in bytes for an algorithm, or 0 if unsupported. */
size_t p25_key_length(uint8_t algorithm_id);

/* Next message indicator: 64-bit LFSR x^64+x^62+x^46+x^38+x^27+x^15+1 stepped
 * 64 times over MI bytes 0..7; byte 8 is cleared. */
void p25_mi_advance(uint8_t mi[P25_MI_BYTES]);

/* Keystream for the nine voice frames (plus two spare bytes) of one LDU.
 * ldu is 0 for LDU1 and 1 for LDU2 of a superframe sharing one MI.
 * Returns 0 on success, -1 for an unsupported algorithm or null argument. */
int p25_keystream_ldu(const p25_key *key, const uint8_t mi[P25_MI_BYTES],
                      unsigned ldu, uint8_t out[P25_KS_LDU_BYTES]);

/* XOR an 88-bit keystream into IMBE vector u[0..7] (widths 12,12,12,12,11,
 * 11,11,7, MSB first). Applying it twice restores the input. */
void p25_crypt_imbe(uint16_t u[8], const uint8_t ks[P25_KS_VOICE_BYTES]);

/* Raw primitives, exported for known-answer tests. */
void p25_des_encrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);
void p25_aes256_encrypt_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16]);
void p25_rc4_keystream(const uint8_t *key, size_t key_len, size_t skip,
                       uint8_t *out, size_t count);

#ifdef __cplusplus
}
#endif
#endif
