/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DM32_P25_KEYSTORE_H
#define DM32_P25_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Portable P25 key table. No I/O, no allocation, no RTOS: the radio glue owns
 * persistence and locking (integration/radiofoundry/p25_keys.c).
 *
 * Slots are numbered 1..P25_KS_SLOTS. A slot is empty when algorithm_id is 0.
 * tx_slot selects the key used to transmit (1..P25_KS_SLOTS); 0 transmits in
 * the clear. Received calls are tried against every non-empty slot by
 * (algorithm, key ID).
 *
 * boot_count only ever increases: it seeds the message-indicator generator
 * (nonce.h), so zeroizing the keys deliberately leaves it alone.
 *
 * Keys are stored in plaintext. There is no secure element in this radio.
 */
enum {
    P25_KS_SLOTS = 4,
    P25_KS_SALT_BYTES = 4,
    P25_KS_BLOB_BYTES = 256,
    P25_KS_VERSION = 1
};

enum {
    P25_KS_OK = 0,
    P25_KS_ERR_SLOT = -1,    /* slot out of range */
    P25_KS_ERR_ALG = -2,     /* unsupported algorithm or wrong key length */
    P25_KS_ERR_KEY = -3,     /* all-zero key */
    P25_KS_ERR_DUP = -4,     /* (algorithm, key ID) already in another slot */
    P25_KS_ERR_SALT = -5,    /* all-zero salt */
    P25_KS_ERR_EMPTY = -6    /* tx slot names an empty slot */
};

typedef struct {
    p25_key key;                         /* algorithm_id 0 = empty */
    uint8_t salt[P25_KS_SALT_BYTES];     /* host-generated per load, never 0 */
} p25_ks_slot;

typedef struct {
    p25_ks_slot slot[P25_KS_SLOTS];
    uint8_t tx_slot;
    uint32_t boot_count;
} p25_keystore;

void p25_ks_init(p25_keystore *ks);

/* Load a key. key_len must equal p25_key_length(algorithm_id) exactly. */
int p25_ks_set(p25_keystore *ks, unsigned slot, uint8_t algorithm_id, uint16_t key_id,
               const uint8_t *key, size_t key_len, const uint8_t salt[P25_KS_SALT_BYTES]);
/* Wipe one slot; if it was the tx slot, transmit goes back to clear. */
int p25_ks_clear(p25_keystore *ks, unsigned slot);
/* Wipe every key and return to clear transmit. boot_count is kept. */
void p25_ks_zeroize(p25_keystore *ks);
/* slot 0 = transmit clear. */
int p25_ks_set_tx(p25_keystore *ks, unsigned slot);

/* Non-empty keys, packed, for p25_voice_set_keys. Returns the count. */
unsigned p25_ks_rx_keys(const p25_keystore *ks, p25_key out[P25_KS_SLOTS]);
/* The transmit slot, or NULL for clear. */
const p25_ks_slot *p25_ks_tx(const p25_keystore *ks);

/* Key check value: first 3 bytes of the key encrypting a zero block (RC4
 * keystream for ADP). Lets a loader confirm what was stored without ever
 * reading the key back. */
void p25_ks_kcv(const p25_key *key, uint8_t out[3]);

/* Fixed 256-byte image with magic, version and CRC-32. */
void p25_ks_serialize(const p25_keystore *ks, uint8_t blob[P25_KS_BLOB_BYTES]);
/* 0 = loaded, 1 = blank flash (all 0xFF; ks left as is), -1 = corrupt (ks left
 * as is). A record that fails any check is rejected whole. */
int p25_ks_parse(p25_keystore *ks, const uint8_t blob[P25_KS_BLOB_BYTES]);

/* IEEE 802.3 CRC-32, zlib compatible. crc = 0 to start. */
uint32_t p25_crc32(uint32_t crc, const void *data, size_t len);

#ifdef __cplusplus
}
#endif
#endif
