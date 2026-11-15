/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Key store, key-load protocol, message-indicator uniqueness and a keystore-driven
 * encrypted call. Host only. The IMBE codec is a stand-in (see test_voice_crypto.c);
 * nothing here says anything about audio quality or interoperability. */
#include "voice.h"
#include "keystore.h"
#include "keyload.h"
#include "nonce.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(cond, ...) do { if (!(cond)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static const uint16_t vmask[8] = {0xfff, 0xfff, 0xfff, 0xfff, 0x7ff, 0x7ff, 0x7ff, 0x7e};
void dm32_imbe_init(dm32_imbe_context *c) { (void)c; }
int dm32_imbe_encode(dm32_imbe_context *c, int16_t pcm[160], uint16_t u[8])
{ unsigned j; (void)c; for (j = 0; j < 8; ++j) u[j] = (uint16_t)pcm[j] & vmask[j]; return 1; }
int dm32_imbe_decode(dm32_imbe_context *c, const uint16_t u[8], int16_t pcm[160])
{ unsigned j; (void)c; memset(pcm, 0, 160 * sizeof *pcm); for (j = 0; j < 8; ++j) pcm[j] = (int16_t)(u[j] & vmask[j]); return 1; }

static const uint8_t SALT[4] = {1, 2, 3, 4};
static const uint8_t SALT2[4] = {9, 8, 7, 6};

static void fill(uint8_t *k, size_t n, uint8_t seed) { size_t i; for (i = 0; i < n; ++i) k[i] = (uint8_t)(seed + 7 * i); }

static void blob_fix_crc(uint8_t blob[P25_KS_BLOB_BYTES])
{
    uint32_t c = p25_crc32(0, blob, P25_KS_BLOB_BYTES - 4);
    blob[252] = (uint8_t)c; blob[253] = (uint8_t)(c >> 8); blob[254] = (uint8_t)(c >> 16); blob[255] = (uint8_t)(c >> 24);
}

static void test_crc32(void)
{
    /* zlib.crc32(b"123456789") */
    CHECK(p25_crc32(0, "123456789", 9) == 0xCBF43926u, "crc32 check value");
    CHECK(p25_crc32(p25_crc32(0, "1234", 4), "56789", 5) == 0xCBF43926u, "crc32 incremental");
}

static void test_store(void)
{
    p25_keystore ks;
    uint8_t aes[32], des[8], adp[5], zero[32] = {0};
    p25_key rx[P25_KS_SLOTS];
    fill(aes, 32, 0x10); fill(des, 8, 0x20); fill(adp, 5, 0x30);
    p25_ks_init(&ks);
    ks.boot_count = 41;

    CHECK(p25_ks_set(&ks, 0, P25_ALG_AES256, 1, aes, 32, SALT) == P25_KS_ERR_SLOT, "slot 0");
    CHECK(p25_ks_set(&ks, 5, P25_ALG_AES256, 1, aes, 32, SALT) == P25_KS_ERR_SLOT, "slot 5");
    CHECK(p25_ks_set(&ks, 1, 0x80, 1, aes, 32, SALT) == P25_KS_ERR_ALG, "clear is not a key algorithm");
    CHECK(p25_ks_set(&ks, 1, 0x99, 1, aes, 32, SALT) == P25_KS_ERR_ALG, "unknown algorithm");
    CHECK(p25_ks_set(&ks, 1, P25_ALG_AES256, 1, aes, 16, SALT) == P25_KS_ERR_ALG, "short AES key");
    CHECK(p25_ks_set(&ks, 1, P25_ALG_DES_OFB, 1, aes, 32, SALT) == P25_KS_ERR_ALG, "long DES key");
    CHECK(p25_ks_set(&ks, 1, P25_ALG_AES256, 1, zero, 32, SALT) == P25_KS_ERR_KEY, "zero key");
    CHECK(p25_ks_set(&ks, 1, P25_ALG_AES256, 1, aes, 32, (const uint8_t[4]){0}) == P25_KS_ERR_SALT, "zero salt");
    CHECK(p25_ks_rx_keys(&ks, rx) == 0 && !p25_ks_tx(&ks), "rejected loads leave the store empty");

    CHECK(p25_ks_set(&ks, 1, P25_ALG_AES256, 0x0102, aes, 32, SALT) == P25_KS_OK, "aes");
    CHECK(p25_ks_set(&ks, 2, P25_ALG_DES_OFB, 0x0102, des, 8, SALT2) == P25_KS_OK, "same kid, other algorithm");
    CHECK(p25_ks_set(&ks, 3, P25_ALG_AES256, 0x0102, aes, 32, SALT) == P25_KS_ERR_DUP, "duplicate (alg, kid)");
    CHECK(p25_ks_set(&ks, 1, P25_ALG_AES256, 0x0102, aes, 32, SALT2) == P25_KS_OK, "replace a slot with its own id");
    CHECK(p25_ks_set(&ks, 4, P25_ALG_ADP, 7, adp, 5, SALT) == P25_KS_OK, "adp");
    CHECK(p25_ks_rx_keys(&ks, rx) == 3 && rx[0].algorithm_id == P25_ALG_AES256 &&
          rx[1].algorithm_id == P25_ALG_DES_OFB && rx[2].algorithm_id == P25_ALG_ADP, "rx keys packed in slot order");

    CHECK(p25_ks_set_tx(&ks, 3) == P25_KS_ERR_EMPTY, "tx on empty slot");
    CHECK(p25_ks_set_tx(&ks, 5) == P25_KS_ERR_SLOT, "tx slot 5");
    CHECK(p25_ks_set_tx(&ks, 2) == P25_KS_OK && p25_ks_tx(&ks) && p25_ks_tx(&ks)->key.algorithm_id == P25_ALG_DES_OFB, "tx slot 2");
    CHECK(p25_ks_clear(&ks, 2) == P25_KS_OK && !p25_ks_tx(&ks) && ks.tx_slot == 0, "clearing the tx slot returns to clear");
    CHECK(p25_ks_set_tx(&ks, 1) == P25_KS_OK && p25_ks_set_tx(&ks, 0) == P25_KS_OK && !p25_ks_tx(&ks), "tx back to clear");

    p25_ks_set_tx(&ks, 1);
    p25_ks_zeroize(&ks);
    CHECK(p25_ks_rx_keys(&ks, rx) == 0 && !p25_ks_tx(&ks), "zeroize removes everything");
    CHECK(ks.boot_count == 41, "zeroize keeps boot_count");
    {
        uint8_t raw[sizeof ks.slot], z[sizeof ks.slot];
        memcpy(raw, ks.slot, sizeof raw); memset(z, 0, sizeof z);
        CHECK(!memcmp(raw, z, sizeof raw), "zeroize wipes key bytes, salts and ids");
    }
}

static void test_kcv(void)
{
    uint8_t k1[32], k2[32], a[3], b[3], c[3];
    p25_key key1 = {P25_ALG_AES256, 1, {0}}, key2 = {P25_ALG_AES256, 1, {0}}, d = {P25_ALG_DES_OFB, 1, {0}}, r = {P25_ALG_ADP, 1, {0}};
    fill(k1, 32, 1); fill(k2, 32, 2);
    memcpy(key1.key, k1, 32); memcpy(key2.key, k2, 32);
    p25_ks_kcv(&key1, a); p25_ks_kcv(&key1, b); p25_ks_kcv(&key2, c);
    CHECK(!memcmp(a, b, 3), "kcv deterministic");
    CHECK(memcmp(a, c, 3), "kcv differs between keys");
    fill(d.key, 8, 5); fill(r.key, 5, 6);
    p25_ks_kcv(&d, a); p25_ks_kcv(&r, b);
    CHECK((a[0] | a[1] | a[2]) && (b[0] | b[1] | b[2]), "des and adp kcv computed");
}

static p25_keystore sample_store(void)
{
    p25_keystore ks;
    uint8_t aes[32], des[8];
    fill(aes, 32, 0x44); fill(des, 8, 0x55);
    p25_ks_init(&ks);
    ks.boot_count = 7;
    p25_ks_set(&ks, 1, P25_ALG_AES256, 0x1234, aes, 32, SALT);
    p25_ks_set(&ks, 3, P25_ALG_DES_OFB, 0x0009, des, 8, SALT2);
    p25_ks_set_tx(&ks, 1);
    return ks;
}

static void test_blob(void)
{
    uint8_t blob[P25_KS_BLOB_BYTES], t[P25_KS_BLOB_BYTES];
    p25_keystore ks = sample_store(), out, before;
    unsigned bit, i;
    int rc;

    p25_ks_serialize(&ks, blob);
    p25_ks_init(&out);
    CHECK(p25_ks_parse(&out, blob) == 0 && !memcmp(&out, &ks, sizeof ks), "round trip");

    memset(t, 0xFF, sizeof t);
    p25_ks_init(&out); out.boot_count = 99; before = out;
    CHECK(p25_ks_parse(&out, t) == 1 && !memcmp(&out, &before, sizeof out), "erased flash reads as blank and changes nothing");

    memset(t, 0, sizeof t);
    CHECK(p25_ks_parse(&out, t) == -1, "all zero is corrupt, not blank");

    /* every single-bit flip is caught */
    for (bit = 0; bit < 8 * P25_KS_BLOB_BYTES; ++bit) {
        memcpy(t, blob, sizeof t); t[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        out = before;
        rc = p25_ks_parse(&out, t);
        if (rc != -1 || memcmp(&out, &before, sizeof out)) { CHECK(0, "bit flip %u not rejected cleanly (rc %d)", bit, rc); break; }
    }
    /* a program cut short: first bytes written, the rest still erased */
    for (i = 1; i < P25_KS_BLOB_BYTES; i += 7) {
        memcpy(t, blob, sizeof t); memset(t + i, 0xFF, sizeof t - i);
        out = before;
        if (p25_ks_parse(&out, t) != -1 || memcmp(&out, &before, sizeof out)) { CHECK(0, "torn write at %u accepted", i); break; }
    }
    /* well-formed CRC but semantically wrong records are still rejected */
    memcpy(t, blob, sizeof t); t[5] = 2; blob_fix_crc(t);                       /* tx slot names an empty slot */
    CHECK(p25_ks_parse(&out, t) == -1, "tx slot on empty slot");
    memcpy(t, blob, sizeof t); t[5] = 9; blob_fix_crc(t);
    CHECK(p25_ks_parse(&out, t) == -1, "tx slot out of range");
    memcpy(t, blob, sizeof t); memset(t + 12 + 3 + 4, 0, 32); blob_fix_crc(t);   /* slot 1 key all zero */
    CHECK(p25_ks_parse(&out, t) == -1, "zero key");
    memcpy(t, blob, sizeof t); t[12 + 3] = t[12 + 4] = t[12 + 5] = t[12 + 6] = 0; blob_fix_crc(t); /* zero salt */
    CHECK(p25_ks_parse(&out, t) == -1, "zero salt");
    memcpy(t, blob, sizeof t); t[12 + 39 * 2 + 3 + 4 + 20] = 0xAA; blob_fix_crc(t); /* DES key slot with junk past 8 bytes */
    CHECK(p25_ks_parse(&out, t) == -1, "bytes past the key length");
    memcpy(t, blob, sizeof t); t[12 + 39 * 1] = 0; t[12 + 39 * 1 + 1] = 5; blob_fix_crc(t); /* empty slot with leftover data */
    CHECK(p25_ks_parse(&out, t) == -1, "empty slot with data");
    memcpy(t, blob, sizeof t); memcpy(t + 12 + 39 * 3, t + 12, 39); blob_fix_crc(t); /* duplicate (alg, kid) */
    CHECK(p25_ks_parse(&out, t) == -1, "duplicate key id");
    memcpy(t, blob, sizeof t); t[4] = 2; blob_fix_crc(t);
    CHECK(p25_ks_parse(&out, t) == -1, "unknown version");
    memcpy(t, blob, sizeof t); t[200] = 1; blob_fix_crc(t);
    CHECK(p25_ks_parse(&out, t) == -1, "nonzero padding");
}

/* ---- message indicators against the real voice code ---- */
static int cmp64(const void *a, const void *b) { return memcmp(a, b, 8); }

static unsigned collect_mis(p25_voice *tx, unsigned n, uint8_t (*mis)[8])
{
    static const p25_call call = {0x293, 1234, 4321, 0, 0, 0};
    unsigned i, nonzero = 0;
    for (i = 0; i < n; ++i) {
        if (!p25_voice_tx_begin(tx, &call)) return 0;
        memcpy(mis[i], tx->tx_mi, 8);
        nonzero += (tx->tx_mi[8] == 0);
        p25_voice_tx_abort(tx);
    }
    return nonzero;
}

static void test_nonce(void)
{
    enum { N = 3000 };
    static uint8_t a[N][8], b[N][8], c[2 * N][8];
    uint32_t uid1[3] = {0x11111111, 0x22222222, 0x33333333}, uid2[3] = {0x11111111, 0x22222222, 0x33333334};
    p25_voice tx;
    p25_key key;
    unsigned i, dup = 0;
    memset(&key, 0, sizeof key); key.algorithm_id = P25_ALG_AES256; key.key_id = 5; fill(key.key, 32, 3);
    memset(&tx, 0, sizeof tx);
    p25_voice_init(&tx, 0x293, 0, NULL, NULL);
    CHECK(p25_voice_set_tx_key(&tx, &key, p25_nonce_random32), "set tx key");

    p25_nonce_reset();
    p25_nonce_set_domain(uid1, 1, SALT, key.algorithm_id, key.key_id);
    CHECK(collect_mis(&tx, N, a) == N, "every MI ends with a cleared byte 8");
    qsort(a, N, 8, cmp64);
    for (i = 1; i < N; ++i) dup += !memcmp(a[i - 1], a[i], 8);
    CHECK(dup == 0, "%u repeated MIs in one boot", dup);

    /* a new boot of the same radio, key and salt must not replay the first boot */
    p25_nonce_reset();
    p25_nonce_set_domain(uid1, 2, SALT, key.algorithm_id, key.key_id);
    collect_mis(&tx, N, b);
    memcpy(c, a, sizeof a); memcpy(c + N, b, sizeof b);
    qsort(c, 2 * N, 8, cmp64);
    for (dup = 0, i = 1; i < 2 * N; ++i) dup += !memcmp(c[i - 1], c[i], 8);
    CHECK(dup == 0, "%u MIs repeated across boots", dup);

    /* another radio, same key, same boot count and salt */
    p25_nonce_reset();
    p25_nonce_set_domain(uid2, 1, SALT, key.algorithm_id, key.key_id);
    collect_mis(&tx, N, b);
    memcpy(c, a, sizeof a); memcpy(c + N, b, sizeof b);
    qsort(c, 2 * N, 8, cmp64);
    for (dup = 0, i = 1; i < 2 * N; ++i) dup += !memcmp(c[i - 1], c[i], 8);
    CHECK(dup == 0, "%u MIs repeated across radios", dup);

    /* same radio and boot, key reloaded with a fresh salt (what a backup restore would look like) */
    p25_nonce_reset();
    p25_nonce_set_domain(uid1, 1, SALT2, key.algorithm_id, key.key_id);
    collect_mis(&tx, N, b);
    memcpy(c, a, sizeof a); memcpy(c + N, b, sizeof b);
    qsort(c, 2 * N, 8, cmp64);
    for (dup = 0, i = 1; i < 2 * N; ++i) dup += !memcmp(c[i - 1], c[i], 8);
    CHECK(dup == 0, "%u MIs repeated after a salted reload", dup);

    /* switching away from a key and back within one boot must not replay its MIs */
    p25_nonce_reset();
    p25_nonce_set_domain(uid1, 5, SALT, key.algorithm_id, key.key_id);
    collect_mis(&tx, 500, a);
    p25_nonce_set_domain(uid1, 5, SALT2, key.algorithm_id, 6);
    collect_mis(&tx, 500, b);
    p25_nonce_set_domain(uid1, 5, SALT, key.algorithm_id, key.key_id);
    collect_mis(&tx, 500, c);
    memcpy(b, a, 500 * 8);              /* a and the third run, side by side */
    memcpy(b + 500, c, 500 * 8);
    qsort(b, 1000, 8, cmp64);
    for (dup = 0, i = 1; i < 1000; ++i) dup += !memcmp(b[i - 1], b[i], 8);
    CHECK(dup == 0, "%u MIs replayed after switching keys and back", dup);
}

/* ---- key load protocol ---- */
static size_t build_set(uint8_t *r, uint8_t slot, uint8_t alg, uint16_t kid, const uint8_t *key, uint8_t klen, const uint8_t salt[4])
{
    size_t n = 0;
    uint32_t c;
    r[n++] = P25_KL_OP_SET; r[n++] = slot; r[n++] = alg; r[n++] = (uint8_t)kid; r[n++] = (uint8_t)(kid >> 8); r[n++] = klen;
    memcpy(r + n, salt, 4); n += 4;
    memcpy(r + n, key, klen); n += klen;
    c = p25_crc32(0, r + 1, n - 1);
    r[n++] = (uint8_t)c; r[n++] = (uint8_t)(c >> 8); r[n++] = (uint8_t)(c >> 16); r[n++] = (uint8_t)(c >> 24);
    return n;
}

static int call(p25_keystore *ks, uint8_t flags, const uint8_t *req, size_t len, uint8_t *body, size_t *bl, int *changed)
{
    return p25_keyload_handle(ks, flags, req, len, body, 64, bl, changed);
}

static void test_keyload(void)
{
    const uint8_t FLAGS = P25_KL_F_FLASH_OK | P25_KL_F_PERSISTED | P25_KL_F_NONCE_READY;
    p25_keystore ks, snapshot;
    uint8_t req[P25_KL_REQ_MAX], body[64], aes[32], kcv[3];
    size_t n, bl;
    int changed, rc;
    unsigned bit, i;

    p25_ks_init(&ks); ks.boot_count = 12;
    fill(aes, 32, 0x61);

    req[0] = P25_KL_OP_STATUS;
    rc = call(&ks, FLAGS, req, 1, body, &bl, &changed);
    CHECK(rc == P25_KL_OK && bl == P25_KL_STATUS_BODY && !changed, "status on empty store");
    CHECK(body[0] == 1 && body[1] == P25_KS_SLOTS && body[2] == 0 && body[3] == FLAGS && body[4] == 12, "status header");

    n = build_set(req, 2, P25_ALG_AES256, 0x00A1, aes, 32, SALT);
    rc = call(&ks, FLAGS, req, n, body, &bl, &changed);
    CHECK(rc == P25_KL_OK && bl == 3 && changed, "set ok");
    p25_ks_kcv(&ks.slot[1].key, kcv);
    CHECK(!memcmp(body, kcv, 3), "set returns the kcv");
    CHECK(ks.slot[1].key.key_id == 0xA1 && !memcmp(ks.slot[1].key.key, aes, 32) && !memcmp(ks.slot[1].salt, SALT, 4), "set stored fields");

    req[0] = P25_KL_OP_STATUS;
    call(&ks, FLAGS, req, 1, body, &bl, &changed);
    CHECK(body[8 + 6] == P25_ALG_AES256 && body[8 + 7] == 0xA1 && !memcmp(body + 8 + 9, kcv, 3), "status lists slot 2 with its kcv");
    for (i = 0; i + 8 <= bl; ++i)
        if (!memcmp(body + i, aes, 8)) { CHECK(0, "status leaked key bytes"); break; }
    CHECK(body[8] == 0 && !memcmp(body + 8 + 3, "\0\0\0", 3), "empty slot reports zeros");

    /* no single-bit corruption of a SET request can modify the store */
    n = build_set(req, 3, P25_ALG_AES256, 0x00A2, aes, 32, SALT2);
    snapshot = ks;
    for (bit = 8; bit < 8 * n; ++bit) {
        uint8_t t[P25_KL_REQ_MAX];
        memcpy(t, req, n); t[bit / 8] ^= (uint8_t)(1u << (bit % 8));
        rc = call(&ks, FLAGS, t, n, body, &bl, &changed);
        if (changed || memcmp(&ks, &snapshot, sizeof ks)) { CHECK(0, "corrupted SET changed the store (bit %u, rc %d)", bit, rc); break; }
    }
    /* length errors */
    rc = call(&ks, FLAGS, req, n - 1, body, &bl, &changed);
    CHECK(rc == P25_KL_BAD_ARG && !changed && !memcmp(&ks, &snapshot, sizeof ks), "truncated SET refused");
    rc = call(&ks, FLAGS, req, 0, body, &bl, &changed);
    CHECK(rc == P25_KL_BAD_ARG, "empty request refused");
    /* semantic errors, with a valid CRC, report the reason and change nothing */
    n = build_set(req, 3, P25_ALG_AES256, 0x00A1, aes, 32, SALT);
    rc = call(&ks, FLAGS, req, n, body, &bl, &changed);
    CHECK(rc == P25_KL_BAD_ARG && body[0] == (uint8_t)-P25_KS_ERR_DUP && !changed && !memcmp(&ks, &snapshot, sizeof ks), "duplicate id reported");
    n = build_set(req, 3, P25_ALG_AES256, 0x00A3, aes, 31, SALT);
    rc = call(&ks, FLAGS, req, n, body, &bl, &changed);
    CHECK(rc == P25_KL_BAD_ARG && body[0] == (uint8_t)-P25_KS_ERR_ALG && !changed, "wrong key length reported");

    /* flash not usable: reads work, every write is refused */
    n = build_set(req, 3, P25_ALG_AES256, 0x00A4, aes, 32, SALT2);
    snapshot = ks;
    rc = call(&ks, 0, req, n, body, &bl, &changed);
    CHECK(rc == P25_KL_UNAVAILABLE && !changed && !memcmp(&ks, &snapshot, sizeof ks), "set refused without flash");
    req[0] = P25_KL_OP_STATUS;
    CHECK(call(&ks, 0, req, 1, body, &bl, &changed) == P25_KL_OK, "status still works without flash");

    req[0] = P25_KL_OP_TX; req[1] = 2;
    CHECK(call(&ks, FLAGS, req, 2, body, &bl, &changed) == P25_KL_OK && changed && ks.tx_slot == 2, "tx select");
    req[1] = 3;
    CHECK(call(&ks, FLAGS, req, 2, body, &bl, &changed) == P25_KL_BAD_ARG && ks.tx_slot == 2, "tx on empty slot refused");
    req[1] = 0;
    CHECK(call(&ks, FLAGS, req, 2, body, &bl, &changed) == P25_KL_OK && ks.tx_slot == 0, "tx clear");

    req[0] = P25_KL_OP_ZEROIZE; memcpy(req + 1, "ZEro", 4);
    snapshot = ks;
    CHECK(call(&ks, FLAGS, req, 5, body, &bl, &changed) == P25_KL_BAD_ARG && !changed && !memcmp(&ks, &snapshot, sizeof ks), "zeroize needs the exact confirmation");
    memcpy(req + 1, "ZERO", 4);
    CHECK(call(&ks, FLAGS, req, 5, body, &bl, &changed) == P25_KL_OK && changed && !ks.slot[1].key.algorithm_id && ks.boot_count == 12, "zeroize");

    n = build_set(req, 1, P25_ALG_AES256, 1, aes, 32, SALT);
    call(&ks, FLAGS, req, n, body, &bl, &changed);
    req[0] = P25_KL_OP_CLEAR; req[1] = 1;
    CHECK(call(&ks, FLAGS, req, 2, body, &bl, &changed) == P25_KL_OK && changed && !ks.slot[0].key.algorithm_id, "clear slot");
    req[1] = 9;
    CHECK(call(&ks, FLAGS, req, 2, body, &bl, &changed) == P25_KL_BAD_ARG, "clear bad slot");
    req[0] = 77;
    CHECK(call(&ks, FLAGS, req, 1, body, &bl, &changed) == P25_KL_BAD_ARG && body[0] == P25_KL_E_OP, "unknown op");
}

/* ---- an encrypted call from keystore-selected keys ---- */
enum { HDU_DIBITS = 396, LDU_DIBITS = 864, TDU_DIBITS = 72, STREAM_MAX = HDU_DIBITS + 4 * LDU_DIBITS + TDU_DIBITS };
static int16_t sunk[64][160];
static unsigned sunk_count;
static void sink(void *ctx, const int16_t pcm[160]) { (void)ctx; if (sunk_count < 64) memcpy(sunk[sunk_count++], pcm, sizeof sunk[0]); }
static void plain_pcm(unsigned f, int16_t pcm[160])
{ unsigned j; memset(pcm, 0, 160 * sizeof *pcm); for (j = 0; j < 8; ++j) pcm[j] = (int16_t)((f * 37 + j * 101 + 7) & vmask[j]); }

static size_t transmit(p25_voice *tx, uint8_t *dibits)
{
    static const p25_call call = {0x293, 1234, 4321, 0, 0, 0};
    size_t n = 0, got;
    unsigned f;
    int16_t pcm[160];
    CHECK(p25_voice_tx_begin(tx, &call), "tx_begin");
    for (f = 0; f < 36; ++f) {
        plain_pcm(f, pcm);
        CHECK(p25_voice_tx_pcm(tx, pcm), "tx_pcm");
        if (f % 9 == 8) {
            if (f == 8) { got = p25_voice_tx_read(tx, dibits + n, HDU_DIBITS); n += got; }
            got = p25_voice_tx_read(tx, dibits + n, LDU_DIBITS); n += got;
        }
    }
    CHECK(p25_voice_tx_end(tx), "tx_end");
    got = p25_voice_tx_read(tx, dibits + n, TDU_DIBITS); n += got;
    return n;
}

static unsigned matching(unsigned first, unsigned count)
{
    unsigned f, ok = 0;
    int16_t want[160];
    for (f = first; f < first + count && f < sunk_count; ++f) { plain_pcm(f, want); ok += !memcmp(want, sunk[f], sizeof want); }
    return ok;
}

static void test_call_from_keystore(void)
{
    static uint8_t stream[STREAM_MAX];
    uint32_t uid[3] = {1, 2, 3};
    uint8_t k1[32], k2[32];
    p25_keystore a, b, c;
    p25_voice tx, rx;
    p25_key keys[P25_KS_SLOTS];
    const p25_ks_slot *t;
    size_t n, i;

    fill(k1, 32, 0x70); fill(k2, 32, 0x90);
    p25_ks_init(&a); p25_ks_init(&b); p25_ks_init(&c);
    a.boot_count = 1;
    p25_ks_set(&a, 1, P25_ALG_AES256, 0x0A0A, k1, 32, SALT);
    p25_ks_set(&a, 2, P25_ALG_AES256, 0x0B0B, k2, 32, SALT2);
    p25_ks_set_tx(&a, 2);
    /* receiver: the same two keys in the opposite slots, plus a third */
    p25_ks_set(&b, 1, P25_ALG_AES256, 0x0B0B, k2, 32, SALT2);
    p25_ks_set(&b, 2, P25_ALG_AES256, 0x0A0A, k1, 32, SALT);
    p25_ks_set(&b, 3, P25_ALG_DES_OFB, 0x0001, k1, 8, SALT);
    /* a radio with only the other key */
    p25_ks_set(&c, 1, P25_ALG_AES256, 0x0A0A, k1, 32, SALT);

    memset(&tx, 0, sizeof tx); memset(&rx, 0, sizeof rx);
    p25_voice_init(&tx, 0x293, 0, sink, NULL);
    p25_voice_init(&rx, 0x293, 0, sink, NULL);
    t = p25_ks_tx(&a);
    CHECK(t != NULL, "tx slot present");
    p25_nonce_reset();
    p25_nonce_set_domain(uid, a.boot_count, t->salt, t->key.algorithm_id, t->key.key_id);
    CHECK(p25_voice_set_tx_key(&tx, &t->key, p25_nonce_random32), "tx key from keystore");
    n = transmit(&tx, stream);

    p25_voice_set_keys(&rx, keys, p25_ks_rx_keys(&b, keys));
    sunk_count = 0;
    for (i = 0; i < n; ++i) p25_voice_rx_dibit(&rx, stream[i]);
    CHECK(matching(0, 36) == 36, "receiver with both keys decrypts (%u/36)", matching(0, 36));

    p25_voice_rx_reset(&rx);
    p25_voice_set_keys(&rx, keys, p25_ks_rx_keys(&c, keys));
    sunk_count = 0;
    for (i = 0; i < n; ++i) p25_voice_rx_dibit(&rx, stream[i]);
    CHECK(matching(0, 36) == 0, "receiver without the call's key stays muted");

    p25_voice_tx_abort(&tx);
    CHECK(p25_voice_set_tx_key(&tx, NULL, NULL), "transmit back to clear");
}

int main(void)
{
    test_crc32();
    test_store();
    test_kcv();
    test_blob();
    test_nonce();
    test_keyload();
    test_call_from_keystore();
    if (failures) { printf("%d key tests FAILED\n", failures); return 1; }
    printf("key store, key load, nonce and keystore-driven call tests passed\n");
    return 0;
}
