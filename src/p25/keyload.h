/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DM32_P25_KEYLOAD_H
#define DM32_P25_KEYLOAD_H

#include <stddef.h>
#include <stdint.h>
#include "keystore.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Key loading over the programming cable (debug link private command 0x23).
 * Request payload, first byte is the operation, integers little endian:
 *
 *   1 STATUS    (no more bytes)
 *   2 SET       slot, algorithm, key ID (2), key length, salt (4), key bytes, CRC-32
 *               of everything after the operation byte and before the CRC
 *   3 CLEAR     slot
 *   4 ZEROIZE   'Z' 'E' 'R' 'O'
 *   5 TX        slot (0 = transmit in the clear)
 *
 * Key material only ever travels host to radio. No operation returns it; the
 * radio answers with a key check value so the loader can confirm the load.
 * There is no password: whoever holds the cable can replace or erase keys but
 * not read them.
 */
enum { P25_KL_OP_STATUS = 1, P25_KL_OP_SET = 2, P25_KL_OP_CLEAR = 3, P25_KL_OP_ZEROIZE = 4, P25_KL_OP_TX = 5 };
enum { P25_KL_REQ_MAX = 1 + 1 + 1 + 2 + 1 + P25_KS_SALT_BYTES + P25_KEY_MAX_BYTES + 4 };

/* Result classes; the radio glue maps them to debug-link status codes. */
enum { P25_KL_OK = 0, P25_KL_BAD_ARG = 1, P25_KL_UNAVAILABLE = 2 };
/* First body byte of a non-OK reply: a P25_KS_ERR_* value (negated) or: */
enum { P25_KL_E_LENGTH = 100, P25_KL_E_CRC = 101, P25_KL_E_OP = 102, P25_KL_E_CONFIRM = 103, P25_KL_E_NO_FLASH = 104 };

/* State the radio glue reports in STATUS. */
enum { P25_KL_F_PERSISTED = 1, P25_KL_F_NONCE_READY = 2, P25_KL_F_FLASH_OK = 4, P25_KL_F_STORED_CORRUPT = 8 };

enum { P25_KL_STATUS_BODY = 8 + P25_KS_SLOTS * 6 };

/* Handles one request. body receives the reply after the status byte, up to
 * cap bytes; *body_len is its length. *changed is set when the store was
 * modified and needs saving. Returns a P25_KL_* class. */
int p25_keyload_handle(p25_keystore *ks, uint8_t flags, const uint8_t *req, size_t len,
                       uint8_t *body, size_t cap, size_t *body_len, int *changed);

#ifdef __cplusplus
}
#endif
#endif
