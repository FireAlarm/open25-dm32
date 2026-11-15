/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef P25_KEYS_H
#define P25_KEYS_H
#include <stddef.h>
#include <stdint.h>
#include "voice.h"

/* Persistent P25 key store for the radio (keystore.h) and its cable loader
 * (keyload.h). Keys live in the last erase sector of the native codeplug area,
 * which nothing else writes in Classic. Debug-link private command 0x23. */

/* Boot: read the sector, count this boot and save the new count. Call once,
 * after storage_init and before any P25 session. */
void p25_keys_start(void);

/* Debug-link command 0x23 (docs in src/p25/keyload.h). */
size_t p25_keys_command(const uint8_t *req, uint16_t len, uint8_t *out, size_t cap);

/* Load the stored keys into a voice session; call right after p25_voice_init
 * and before every transmit. With for_tx the transmit key is armed (or set to
 * clear when no transmit slot is selected). Returns 0 when a transmit must NOT
 * start: encryption is selected but its key or message-indicator source is not
 * ready. Receive keys are copied to a private snapshot, so key changes apply
 * at the next session or PTT, never in the middle of a call. */
int p25_keys_apply(p25_voice *v, int for_tx);

#endif
