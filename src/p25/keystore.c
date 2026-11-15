/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>
#include "keystore.h"

static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    while (n--) acc |= *p++;
    return acc == 0;
}

uint32_t p25_crc32(uint32_t crc, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    crc = ~crc;
    while (len--) {
        crc ^= *p++;
        for (unsigned i = 0; i < 8; i++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

void p25_ks_init(p25_keystore *ks)
{
    memset(ks, 0, sizeof *ks);
}

static int duplicate(const p25_keystore *ks, unsigned skip, uint8_t alg, uint16_t kid)
{
    for (unsigned i = 1; i <= P25_KS_SLOTS; i++)
        if (i != skip && ks->slot[i - 1].key.algorithm_id == alg && ks->slot[i - 1].key.key_id == kid)
            return 1;
    return 0;
}

int p25_ks_set(p25_keystore *ks, unsigned slot, uint8_t algorithm_id, uint16_t key_id,
               const uint8_t *key, size_t key_len, const uint8_t salt[P25_KS_SALT_BYTES])
{
    if (slot < 1 || slot > P25_KS_SLOTS) return P25_KS_ERR_SLOT;
    size_t want = p25_key_length(algorithm_id);
    if (!want || !key || key_len != want) return P25_KS_ERR_ALG;
    if (all_zero(key, key_len)) return P25_KS_ERR_KEY;
    if (!salt || all_zero(salt, P25_KS_SALT_BYTES)) return P25_KS_ERR_SALT;
    if (duplicate(ks, slot, algorithm_id, key_id)) return P25_KS_ERR_DUP;
    p25_ks_slot *s = &ks->slot[slot - 1];
    wipe(s, sizeof *s);
    s->key.algorithm_id = algorithm_id;
    s->key.key_id = key_id;
    memcpy(s->key.key, key, key_len);
    memcpy(s->salt, salt, P25_KS_SALT_BYTES);
    return P25_KS_OK;
}

int p25_ks_clear(p25_keystore *ks, unsigned slot)
{
    if (slot < 1 || slot > P25_KS_SLOTS) return P25_KS_ERR_SLOT;
    wipe(&ks->slot[slot - 1], sizeof ks->slot[slot - 1]);
    if (ks->tx_slot == slot) ks->tx_slot = 0;
    return P25_KS_OK;
}

void p25_ks_zeroize(p25_keystore *ks)
{
    wipe(ks->slot, sizeof ks->slot);
    ks->tx_slot = 0;
}

int p25_ks_set_tx(p25_keystore *ks, unsigned slot)
{
    if (slot > P25_KS_SLOTS) return P25_KS_ERR_SLOT;
    if (slot && !ks->slot[slot - 1].key.algorithm_id) return P25_KS_ERR_EMPTY;
    ks->tx_slot = (uint8_t)slot;
    return P25_KS_OK;
}

unsigned p25_ks_rx_keys(const p25_keystore *ks, p25_key out[P25_KS_SLOTS])
{
    unsigned n = 0;
    for (unsigned i = 0; i < P25_KS_SLOTS; i++)
        if (ks->slot[i].key.algorithm_id) out[n++] = ks->slot[i].key;
    return n;
}

const p25_ks_slot *p25_ks_tx(const p25_keystore *ks)
{
    if (!ks->tx_slot || ks->tx_slot > P25_KS_SLOTS) return NULL;
    const p25_ks_slot *s = &ks->slot[ks->tx_slot - 1];
    return s->key.algorithm_id ? s : NULL;
}

void p25_ks_kcv(const p25_key *key, uint8_t out[3])
{
    uint8_t zero[16], o[16];
    memset(zero, 0, sizeof zero);
    memset(o, 0, sizeof o);
    switch (key->algorithm_id) {
    case P25_ALG_DES_OFB: p25_des_encrypt_block(key->key, zero, o); break;
    case P25_ALG_AES256: p25_aes256_encrypt_block(key->key, zero, o); break;
    case P25_ALG_ADP: p25_rc4_keystream(key->key, 5, 0, o, sizeof o); break;
    default: break;
    }
    memcpy(out, o, 3);
    wipe(o, sizeof o);
}

/* Blob layout, little endian:
 *  0..3   'P' '2' '5' 'K'
 *  4      version
 *  5      tx_slot
 *  6..7   zero
 *  8..11  boot_count
 *  12..   P25_KS_SLOTS x { algorithm 1, key ID 2, salt 4, key 32 } = 39 bytes
 *  ...    zero padding
 *  252..255 CRC-32 of bytes 0..251 */
#define BLOB_SLOT_BYTES (1 + 2 + P25_KS_SALT_BYTES + P25_KEY_MAX_BYTES)
#define BLOB_HDR 12
#define BLOB_CRC (P25_KS_BLOB_BYTES - 4)

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void p25_ks_serialize(const p25_keystore *ks, uint8_t blob[P25_KS_BLOB_BYTES])
{
    memset(blob, 0, P25_KS_BLOB_BYTES);
    memcpy(blob, "P25K", 4);
    blob[4] = P25_KS_VERSION;
    blob[5] = ks->tx_slot;
    put32(blob + 8, ks->boot_count);
    for (unsigned i = 0; i < P25_KS_SLOTS; i++) {
        uint8_t *p = blob + BLOB_HDR + i * BLOB_SLOT_BYTES;
        const p25_ks_slot *s = &ks->slot[i];
        p[0] = s->key.algorithm_id;
        p[1] = (uint8_t)s->key.key_id;
        p[2] = (uint8_t)(s->key.key_id >> 8);
        memcpy(p + 3, s->salt, P25_KS_SALT_BYTES);
        memcpy(p + 3 + P25_KS_SALT_BYTES, s->key.key, P25_KEY_MAX_BYTES);
    }
    put32(blob + BLOB_CRC, p25_crc32(0, blob, BLOB_CRC));
}

int p25_ks_parse(p25_keystore *ks, const uint8_t blob[P25_KS_BLOB_BYTES])
{
    unsigned erased = 0;
    for (unsigned i = 0; i < P25_KS_BLOB_BYTES; i++) erased += blob[i] == 0xFF;
    if (erased == P25_KS_BLOB_BYTES) return 1;

    if (memcmp(blob, "P25K", 4) || blob[4] != P25_KS_VERSION) return -1;
    if (get32(blob + BLOB_CRC) != p25_crc32(0, blob, BLOB_CRC)) return -1;
    if (blob[5] > P25_KS_SLOTS || blob[6] || blob[7]) return -1;
    if (!all_zero(blob + BLOB_HDR + P25_KS_SLOTS * BLOB_SLOT_BYTES,
                  (size_t)(BLOB_CRC - BLOB_HDR - P25_KS_SLOTS * BLOB_SLOT_BYTES))) return -1;

    p25_keystore t;
    p25_ks_init(&t);
    t.tx_slot = blob[5];
    t.boot_count = get32(blob + 8);
    for (unsigned i = 0; i < P25_KS_SLOTS; i++) {
        const uint8_t *p = blob + BLOB_HDR + i * BLOB_SLOT_BYTES;
        if (!p[0]) {
            if (!all_zero(p, BLOB_SLOT_BYTES)) { wipe(&t, sizeof t); return -1; }
            continue;
        }
        size_t len = p25_key_length(p[0]);
        uint16_t kid = (uint16_t)(p[1] | p[2] << 8);
        const uint8_t *key = p + 3 + P25_KS_SALT_BYTES;
        /* bytes past the key's length must be zero, as p25_ks_set leaves them */
        if (!len || p25_ks_set(&t, i + 1, p[0], kid, key, len, p + 3) != P25_KS_OK ||
            !all_zero(key + len, P25_KEY_MAX_BYTES - len)) { wipe(&t, sizeof t); return -1; }
    }
    if (t.tx_slot && !t.slot[t.tx_slot - 1].key.algorithm_id) { wipe(&t, sizeof t); return -1; }
    *ks = t;
    wipe(&t, sizeof t);
    return 0;
}
