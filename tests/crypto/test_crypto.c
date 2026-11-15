/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Known-answer and invariant tests for src/p25/crypto.c. Host only.
 * `test_crypto vec <des|aes|rc4> KEYHEX DATAHEX [SKIP]` prints the cipher
 * output for differential testing against OpenSSL (see tools/test_crypto.py). */
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(cond, ...) do { if (!(cond)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static size_t unhex(const char *s, uint8_t *out, size_t max)
{
    size_t n = strlen(s) / 2, i;
    if (n > max) n = max;
    for (i = 0; i < n; ++i) { unsigned v; sscanf(s + 2 * i, "%2x", &v); out[i] = (uint8_t)v; }
    return n;
}

static void hexprint(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) printf("%02x", p[i]);
    printf("\n");
}

static int cli(int argc, char **argv)
{
    uint8_t key[32], data[16], out[64];
    size_t klen = unhex(argv[3], key, sizeof key);
    if (!strcmp(argv[2], "des")) { unhex(argv[4], data, 8); p25_des_encrypt_block(key, data, out); hexprint(out, 8); }
    else if (!strcmp(argv[2], "aes")) { unhex(argv[4], data, 16); p25_aes256_encrypt_block(key, data, out); hexprint(out, 16); }
    else if (!strcmp(argv[2], "rc4")) {
        size_t skip = argc > 5 ? (size_t)atol(argv[5]) : 0;
        p25_rc4_keystream(key, klen, skip, out, 32); hexprint(out, 32);
    } else return 2;
    return 0;
}

static void test_known_answers(void)
{
    uint8_t key[32], in[16], out[32], want[32], i;

    /* FIPS-197 C.3, AES-256. */
    for (i = 0; i < 32; ++i) key[i] = i;
    unhex("00112233445566778899aabbccddeeff", in, 16);
    unhex("8ea2b7ca516745bfeafc49904b496089", want, 16);
    p25_aes256_encrypt_block(key, in, out);
    CHECK(!memcmp(out, want, 16), "AES-256 FIPS-197 C.3");

    /* Classic worked DES example (Stallings / FIPS 46 derivations). */
    unhex("133457799bbcdff1", key, 8);
    unhex("0123456789abcdef", in, 8);
    unhex("85e813540f0ab405", want, 8);
    p25_des_encrypt_block(key, in, out);
    CHECK(!memcmp(out, want, 8), "DES 133457799BBCDFF1");

    /* RFC 6229, 40-bit key, offset 0. */
    unhex("0102030405", key, 5);
    unhex("b2396305f03dc027ccc3524a0a1118a8", want, 16);
    p25_rc4_keystream(key, 5, 0, out, 16);
    CHECK(!memcmp(out, want, 16), "RC4 RFC 6229 40-bit offset 0");
    /* Skipping must equal discarding from a longer run. */
    p25_rc4_keystream(key, 5, 5, out, 11);
    CHECK(!memcmp(out, want + 5, 11), "RC4 skip equals discard");

    /* Widely published RC4 vector: key "Key", plaintext "Plaintext". */
    p25_rc4_keystream((const uint8_t *)"Key", 3, 0, out, 9);
    unhex("eb9f7781b734ca72a7", want, 9);
    CHECK(!memcmp(out, want, 9), "RC4 key 'Key'");
}

static void test_mi_and_imbe(void)
{
    uint8_t mi[9] = {1, 2, 3, 4, 5, 6, 7, 8, 0xff}, a[9], b[9];
    uint16_t u[8] = {0xabc, 0x123, 0xfff, 0x000, 0x7ff, 0x555, 0x2aa, 0x7f}, orig[8];
    uint8_t ks[11] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd};
    unsigned i;

    memcpy(a, mi, 9); p25_mi_advance(a);
    memcpy(b, mi, 9); p25_mi_advance(b);
    CHECK(!memcmp(a, b, 9), "MI advance deterministic");
    CHECK(a[8] == 0, "MI byte 8 cleared");
    CHECK(memcmp(a, mi, 8) != 0, "MI advance changes MI");
    memset(a, 0, 9); p25_mi_advance(a);
    CHECK(!memcmp(a, "\0\0\0\0\0\0\0\0\0", 9), "all-zero MI is a fixed point");

    memcpy(orig, u, sizeof u);
    p25_crypt_imbe(u, ks);
    CHECK(memcmp(u, orig, sizeof u) != 0, "imbe XOR changes frame");
    for (i = 0; i < 4; ++i) CHECK(u[i] <= 0xfff, "u%u stays 12 bits", i);
    for (i = 4; i < 7; ++i) CHECK(u[i] <= 0x7ff, "u%u stays 11 bits", i);
    CHECK(u[7] <= 0x7f, "u7 stays 7 bits");
    p25_crypt_imbe(u, ks);
    CHECK(!memcmp(u, orig, sizeof u), "imbe XOR is an involution");
}

static void test_keystreams(void)
{
    static const uint8_t algs[3] = {P25_ALG_DES_OFB, P25_ALG_AES256, P25_ALG_ADP};
    uint8_t mi[9] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00};
    uint8_t mi2[9], k1[101], k2[101], k3[101];
    p25_key key;
    unsigned a, i;

    for (a = 0; a < 3; ++a) {
        memset(&key, 0, sizeof key);
        key.algorithm_id = algs[a]; key.key_id = 7;
        for (i = 0; i < p25_key_length(algs[a]); ++i) key.key[i] = (uint8_t)(0x40 + i);
        CHECK(p25_key_length(algs[a]) > 0, "alg %02x length", algs[a]);
        CHECK(!p25_keystream_ldu(&key, mi, 0, k1), "alg %02x ldu1", algs[a]);
        CHECK(!p25_keystream_ldu(&key, mi, 1, k2), "alg %02x ldu2", algs[a]);
        CHECK(memcmp(k1, k2, 101) != 0, "alg %02x LDU1 != LDU2", algs[a]);
        CHECK(!p25_keystream_ldu(&key, mi, 0, k3) && !memcmp(k1, k3, 101), "alg %02x repeatable", algs[a]);
        memcpy(mi2, mi, 9); p25_mi_advance(mi2);
        CHECK(!p25_keystream_ldu(&key, mi2, 0, k3) && memcmp(k1, k3, 101) != 0, "alg %02x MI changes stream", algs[a]);
        key.key[0] ^= 2; /* bit 0 of a DES key byte is parity and ignored */
        CHECK(!p25_keystream_ldu(&key, mi, 0, k3) && memcmp(k1, k3, 101) != 0, "alg %02x key changes stream", algs[a]);
    }
    key.algorithm_id = P25_ALG_CLEAR;
    CHECK(p25_keystream_ldu(&key, mi, 0, k1) == -1, "clear has no keystream");
    CHECK(p25_keystream_ldu(&key, mi, 2, k1) == -1, "bad ldu rejected");
    CHECK(p25_key_length(0x80) == 0 && p25_key_length(0x7f) == 0, "unsupported length 0");
}

int main(int argc, char **argv)
{
    if (argc >= 5 && !strcmp(argv[1], "vec")) return cli(argc, argv);
    test_known_answers();
    test_mi_and_imbe();
    test_keystreams();
    if (failures) { printf("%d failure(s)\n", failures); return 1; }
    printf("crypto tests passed\n");
    return 0;
}
