/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "crypto.h"
#include <string.h>

/* ---------------------------------------------------------------- DES ---- */

static const uint8_t des_ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
static const uint8_t des_fp[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
static const uint8_t des_e[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
static const uint8_t des_p[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
static const uint8_t des_pc1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
static const uint8_t des_pc2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
static const uint8_t des_shift[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
static const uint8_t des_sbox[8][64] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

/* Output bit i (MSB first) is input bit table[i] (1-based, MSB first). */
static uint64_t permute(uint64_t in, const uint8_t *table, unsigned in_bits, unsigned out_bits)
{
    uint64_t out = 0;
    unsigned i;
    for (i = 0; i < out_bits; ++i)
        out = (out << 1) | ((in >> (in_bits - table[i])) & 1u);
    return out;
}

static uint32_t des_f(uint32_t r, uint64_t subkey)
{
    uint64_t e = permute(r, des_e, 32, 48) ^ subkey;
    uint32_t s = 0;
    unsigned i;
    for (i = 0; i < 8; ++i) {
        unsigned b = (unsigned)(e >> (42 - 6 * i)) & 63u;
        unsigned row = ((b >> 4) & 2u) | (b & 1u);
        unsigned col = (b >> 1) & 15u;
        s = (s << 4) | des_sbox[i][row * 16 + col];
    }
    return (uint32_t)permute(s, des_p, 32, 32);
}

void p25_des_encrypt_block(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    uint64_t k = 0, b = 0, cd, pre;
    uint32_t c, d, l, r, t;
    uint64_t sub[16];
    unsigned i, n;
    for (i = 0; i < 8; ++i) { k = (k << 8) | key[i]; b = (b << 8) | in[i]; }
    cd = permute(k, des_pc1, 64, 56);
    c = (uint32_t)(cd >> 28) & 0x0fffffffu;
    d = (uint32_t)cd & 0x0fffffffu;
    for (n = 0; n < 16; ++n) {
        for (i = 0; i < des_shift[n]; ++i) {
            c = ((c << 1) | (c >> 27)) & 0x0fffffffu;
            d = ((d << 1) | (d >> 27)) & 0x0fffffffu;
        }
        sub[n] = permute(((uint64_t)c << 28) | d, des_pc2, 56, 48);
    }
    b = permute(b, des_ip, 64, 64);
    l = (uint32_t)(b >> 32);
    r = (uint32_t)b;
    for (n = 0; n < 16; ++n) {
        t = r;
        r = l ^ des_f(r, sub[n]);
        l = t;
    }
    pre = ((uint64_t)r << 32) | l;
    pre = permute(pre, des_fp, 64, 64);
    for (i = 0; i < 8; ++i) out[i] = (uint8_t)(pre >> (56 - 8 * i));
}

/* ---------------------------------------------------------------- AES ---- */

static uint8_t aes_sbox[256];
static uint8_t aes_sbox_ready;

static uint8_t rotl8(uint8_t x, unsigned s) { return (uint8_t)((x << s) | (x >> (8 - s))); }

static void aes_sbox_init(void)
{
    uint8_t p = 1, q = 1, x;
    if (aes_sbox_ready) return;
    do {
        p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1b : 0));
        q ^= (uint8_t)(q << 1); q ^= (uint8_t)(q << 2); q ^= (uint8_t)(q << 4);
        if (q & 0x80) q ^= 0x09;
        x = (uint8_t)(q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4));
        aes_sbox[p] = (uint8_t)(x ^ 0x63);
    } while (p != 1);
    aes_sbox[0] = 0x63;
    aes_sbox_ready = 1;
}

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

void p25_aes256_encrypt_block(const uint8_t key[32], const uint8_t in[16], uint8_t out[16])
{
    uint8_t rk[240], s[16], t[16], tmp[4], rcon = 1;
    unsigned i, r, c;
    aes_sbox_init();
    memcpy(rk, key, 32);
    for (i = 8; i < 60; ++i) {
        memcpy(tmp, rk + 4 * (i - 1), 4);
        if (i % 8 == 0) {
            uint8_t u = tmp[0];
            tmp[0] = (uint8_t)(aes_sbox[tmp[1]] ^ rcon); tmp[1] = aes_sbox[tmp[2]];
            tmp[2] = aes_sbox[tmp[3]]; tmp[3] = aes_sbox[u];
            rcon = xtime(rcon);
        } else if (i % 8 == 4) {
            for (c = 0; c < 4; ++c) tmp[c] = aes_sbox[tmp[c]];
        }
        for (c = 0; c < 4; ++c) rk[4 * i + c] = (uint8_t)(rk[4 * (i - 8) + c] ^ tmp[c]);
    }
    for (i = 0; i < 16; ++i) s[i] = (uint8_t)(in[i] ^ rk[i]);
    for (r = 1; r <= 14; ++r) {
        for (i = 0; i < 16; ++i) t[i] = aes_sbox[s[i]];
        for (c = 0; c < 4; ++c)       /* ShiftRows: row n moves left by n */
            for (i = 0; i < 4; ++i) s[i + 4 * c] = t[i + 4 * ((c + i) % 4)];
        if (r < 14) {
            for (c = 0; c < 4; ++c) {
                uint8_t *col = s + 4 * c, a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                col[0] = (uint8_t)(a0 ^ all ^ xtime((uint8_t)(a0 ^ a1)));
                col[1] = (uint8_t)(a1 ^ all ^ xtime((uint8_t)(a1 ^ a2)));
                col[2] = (uint8_t)(a2 ^ all ^ xtime((uint8_t)(a2 ^ a3)));
                col[3] = (uint8_t)(a3 ^ all ^ xtime((uint8_t)(a3 ^ a0)));
            }
        }
        for (i = 0; i < 16; ++i) s[i] ^= rk[16 * r + i];
    }
    memcpy(out, s, 16);
}

/* ---------------------------------------------------------------- RC4 ---- */

void p25_rc4_keystream(const uint8_t *key, size_t key_len, size_t skip, uint8_t *out, size_t count)
{
    uint8_t s[256], t;
    unsigned i, j = 0, a = 0;
    size_t n;
    for (i = 0; i < 256; ++i) s[i] = (uint8_t)i;
    for (i = 0; i < 256; ++i) {
        j = (j + s[i] + key[i % key_len]) & 255u;
        t = s[i]; s[i] = s[j]; s[j] = t;
    }
    i = j = 0;
    for (n = 0; n < skip + count; ++n) {
        i = (i + 1) & 255u;
        a = (a + s[i]) & 255u;
        t = s[i]; s[i] = s[a]; s[a] = t;
        if (n >= skip) out[n - skip] = s[(s[i] + s[a]) & 255u];
    }
}

/* ----------------------------------------------------- P25 schedule ------ */

size_t p25_key_length(uint8_t algorithm_id)
{
    switch (algorithm_id) {
    case P25_ALG_DES_OFB: return 8;
    case P25_ALG_AES256: return 32;
    case P25_ALG_ADP: return 5;
    default: return 0;
    }
}

void p25_mi_advance(uint8_t mi[P25_MI_BYTES])
{
    uint64_t lfsr = 0;
    unsigned i, step;
    for (i = 0; i < 8; ++i) lfsr = (lfsr << 8) | mi[i];
    for (step = 0; step < 64; ++step) {
        uint64_t fb = ((lfsr >> 63) ^ (lfsr >> 61) ^ (lfsr >> 45) ^
                       (lfsr >> 37) ^ (lfsr >> 26) ^ (lfsr >> 14)) & 1u;
        lfsr = (lfsr << 1) | fb;
    }
    for (i = 0; i < 8; ++i) mi[i] = (uint8_t)(lfsr >> (56 - 8 * i));
    mi[8] = 0;
}

/* OFB: block_i = E(block_{i-1}), block_0 = E(IV); the stream is the
 * concatenated blocks. Emit bytes [skip, skip+count). */
static void ofb_stream(uint8_t algorithm_id, const uint8_t *key, const uint8_t mi[P25_MI_BYTES],
                       size_t skip, uint8_t *out, size_t count)
{
    uint8_t iv[16];
    size_t bs = algorithm_id == P25_ALG_DES_OFB ? 8 : 16, pos;
    if (bs == 8) memcpy(iv, mi, 8);
    else { memcpy(iv, mi, 9); memcpy(iv + 9, mi, 7); }
    for (pos = 0; pos < skip + count; ++pos) {
        if (pos % bs == 0) {
            uint8_t next[16];
            if (bs == 8) p25_des_encrypt_block(key, iv, next);
            else p25_aes256_encrypt_block(key, iv, next);
            memcpy(iv, next, bs);
        }
        if (pos >= skip) out[pos - skip] = iv[pos % bs];
    }
}

int p25_keystream_ldu(const p25_key *key, const uint8_t mi[P25_MI_BYTES], unsigned ldu,
                      uint8_t out[P25_KS_LDU_BYTES])
{
    if (!key || !mi || !out || ldu > 1) return -1;
    switch (key->algorithm_id) {
    case P25_ALG_DES_OFB:
    case P25_ALG_AES256:
        ofb_stream(key->algorithm_id, key->key, mi,
                   P25_KS_LEAD_OFB + (size_t)P25_KS_LDU_BYTES * ldu, out, P25_KS_LDU_BYTES);
        return 0;
    case P25_ALG_ADP: {
        uint8_t rc4_key[13];
        memcpy(rc4_key, key->key, 5);
        memcpy(rc4_key + 5, mi, 8);
        p25_rc4_keystream(rc4_key, sizeof rc4_key,
                          P25_KS_LEAD_ADP + (size_t)P25_KS_LDU_BYTES * ldu, out, P25_KS_LDU_BYTES);
        return 0;
    }
    default:
        return -1;
    }
}

void p25_crypt_imbe(uint16_t u[8], const uint8_t ks[P25_KS_VOICE_BYTES])
{
    static const uint8_t width[8] = {12, 12, 12, 12, 11, 11, 11, 7};
    unsigned i, bit, pos = 0;
    for (i = 0; i < 8; ++i) {
        for (bit = 0; bit < width[i]; ++bit, ++pos) {
            unsigned k = (ks[pos / 8] >> (7 - pos % 8)) & 1u;
            u[i] = (uint16_t)(u[i] ^ (k << (width[i] - 1 - bit)));
        }
    }
}
