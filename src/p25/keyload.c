/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <string.h>
#include "keyload.h"

static int fail(uint8_t *body, size_t cap, size_t *body_len, int cls, int detail)
{
    *body_len = 0;
    if (cap) { body[0] = (uint8_t)(detail < 0 ? -detail : detail); *body_len = 1; }
    return cls;
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int status(const p25_keystore *ks, uint8_t flags, uint8_t *body, size_t cap, size_t *body_len)
{
    if (cap < P25_KL_STATUS_BODY) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
    body[0] = P25_KS_VERSION;
    body[1] = P25_KS_SLOTS;
    body[2] = ks->tx_slot;
    body[3] = flags;
    body[4] = (uint8_t)ks->boot_count; body[5] = (uint8_t)(ks->boot_count >> 8);
    body[6] = (uint8_t)(ks->boot_count >> 16); body[7] = (uint8_t)(ks->boot_count >> 24);
    for (unsigned i = 0; i < P25_KS_SLOTS; i++) {
        uint8_t *p = body + 8 + i * 6;
        const p25_key *k = &ks->slot[i].key;
        p[0] = k->algorithm_id;
        p[1] = (uint8_t)k->key_id;
        p[2] = (uint8_t)(k->key_id >> 8);
        if (k->algorithm_id) p25_ks_kcv(k, p + 3); else memset(p + 3, 0, 3);
    }
    *body_len = P25_KL_STATUS_BODY;
    return P25_KL_OK;
}

int p25_keyload_handle(p25_keystore *ks, uint8_t flags, const uint8_t *req, size_t len,
                       uint8_t *body, size_t cap, size_t *body_len, int *changed)
{
    *body_len = 0;
    *changed = 0;
    if (!req || !len) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);

    if (req[0] == P25_KL_OP_STATUS) {
        if (len != 1) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
        return status(ks, flags, body, cap, body_len);
    }
    if (req[0] < P25_KL_OP_STATUS || req[0] > P25_KL_OP_TX)
        return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_OP);
    /* Every other operation writes flash. */
    if (!(flags & P25_KL_F_FLASH_OK)) return fail(body, cap, body_len, P25_KL_UNAVAILABLE, P25_KL_E_NO_FLASH);

    int rc = P25_KS_OK;
    switch (req[0]) {
    case P25_KL_OP_SET: {
        if (len < 1 + 1 + 1 + 2 + 1 + P25_KS_SALT_BYTES + 4) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
        size_t klen = req[5];
        if (len != 1 + 1 + 1 + 2 + 1 + P25_KS_SALT_BYTES + klen + 4)
            return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
        if (get32(req + len - 4) != p25_crc32(0, req + 1, len - 5))
            return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_CRC);
        if (cap < 3) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
        uint16_t kid = (uint16_t)(req[3] | req[4] << 8);
        rc = p25_ks_set(ks, req[1], req[2], kid, req + 5 + 1 + P25_KS_SALT_BYTES, klen, req + 6);
        if (rc == P25_KS_OK) {
            p25_ks_kcv(&ks->slot[req[1] - 1].key, body);
            *body_len = 3;
            *changed = 1;
            return P25_KL_OK;
        }
        break;
    }
    case P25_KL_OP_CLEAR:
        if (len != 2) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
        rc = p25_ks_clear(ks, req[1]);
        break;
    case P25_KL_OP_ZEROIZE:
        if (len != 5) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
        if (memcmp(req + 1, "ZERO", 4)) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_CONFIRM);
        p25_ks_zeroize(ks);
        break;
    default: /* P25_KL_OP_TX */
        if (len != 2) return fail(body, cap, body_len, P25_KL_BAD_ARG, P25_KL_E_LENGTH);
        rc = p25_ks_set_tx(ks, req[1]);
        break;
    }
    if (rc != P25_KS_OK) return fail(body, cap, body_len, P25_KL_BAD_ARG, rc);
    *changed = 1;
    return P25_KL_OK;
}
