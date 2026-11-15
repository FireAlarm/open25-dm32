/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef P25_VOICE_H
#define P25_VOICE_H
#include "p25.h"
#include "crypto.h"
#include "dm32_imbe.h"

/* Conventional group voice, clear or encrypted (see crypto.h for the cipher
 * set and its validation status); half duplex. All calls and the PCM sink
 * run in ONE worker task, never in an ISR. No dynamic allocation. The sink
 * must consume/copy 160 samples before returning. See docs/conventional.md.
 * A transport supplies dibits in on-air order; this does not assert that a
 * particular chip can expose that stream, or implement RF modulation.
 */
typedef void (*p25_pcm_sink)(void *ctx, const int16_t pcm[160]);
enum { P25_VOICE_QUEUE = 3 };
typedef struct {
    uint8_t data[P25_LDU_BYTES];
    uint16_t bytes;
} p25_voice_packet;
typedef struct {
    dm32_imbe_context codec; /* RX and TX share it; every direction change resets it */
    p25_rx framer;
    p25_call call;
    p25_pcm_sink sink;
    void *sink_ctx;
    uint16_t group_filter; /* 0 = all group voice; implementation policy */
    uint16_t active_nac;
    uint16_t active_group;
    uint32_t active_source;
    uint16_t voice[9][8];
    p25_voice_packet queue[P25_VOICE_QUEUE];
    uint16_t packet_symbol;
    uint8_t head, tail, count, voice_count, next_duid;
    uint8_t transmitting, started, stopping, terminator_pending, fault;
    uint8_t crypto_clear, have_group;
    /* Encryption. keys is caller-owned and must outlive the context. */
    const p25_key *keys;
    uint8_t key_count;
    const p25_key *rx_key;          /* key matched to the current call, if any */
    uint8_t rx_have_mi, rx_algorithm, rx_mi[P25_MI_BYTES];
    uint16_t rx_key_id;
    uint8_t rx_ks[P25_KS_LDU_BYTES];
    p25_key tx_key;
    uint8_t tx_encrypt, tx_mi[P25_MI_BYTES], tx_ks[P25_KS_LDU_BYTES];
    uint32_t (*random32)(void);     /* entropy for the TX message indicator */
    uint32_t rx_decrypted, rx_no_key;
    uint32_t rx_frames, rx_voice, rx_muted, rx_erasures, tx_frames, tx_underruns;
    uint32_t (*micros)(void); /* optional task-level profiling, no clock assumption */
    uint32_t fec_max_us, imbe_max_us;
} p25_voice;

void p25_voice_init(p25_voice *v, uint16_t nac, uint16_t group,
                    p25_pcm_sink sink, void *ctx);
/* Clear RX admission/timing after tuning, a discontinuity, or carrier loss.
 * Caller owns the receive hang timer; no time unit is guessed here. */
void p25_voice_rx_reset(p25_voice *v);
void p25_voice_rx_dibit(p25_voice *v, uint8_t dibit);
/* Receive keys: an array of count entries, matched on (algorithm, key id).
 * NULL/0 mutes every encrypted call. Not allowed to change mid-call.
 * p25_voice_init clears all of this state, so call set_keys/set_tx_key after it. */
void p25_voice_set_keys(p25_voice *v, const p25_key *keys, unsigned count);
/* Transmit key, copied. NULL selects clear voice. Encrypted transmit needs
 * random32 (the hardware RNG) and fails closed: returns 0 and leaves the old
 * setting if the algorithm is unsupported, random32 is NULL, or a call is
 * active. A fresh random MI starts every call; MI repeats under one key would
 * reuse keystream. */
int p25_voice_set_tx_key(p25_voice *v, const p25_key *key, uint32_t (*random32)(void));
int p25_voice_tx_begin(p25_voice *v, const p25_call *call);
/* Exactly one 8 kHz / 20 ms microphone block; mutable for the codec.
 * Returns 0 on invalid state, codec failure or queue overflow. Abort/unkey.
 * Producer must be paced by microphone time, not called in an unbounded loop. */
int p25_voice_tx_pcm(p25_voice *v, int16_t pcm[160]);
/* Release: pad only the incomplete nine-frame LDU with encoded silence,
 * then a TDU. Empty, unstarted calls are canceled. Task context only. */
int p25_voice_tx_end(p25_voice *v);
/* Up to capacity dibits, including across CAI unit boundaries. Zero means
 * prefill waiting or completely drained; inspect tx_done(). No fabricated
 * idle/CACH/sync is inserted. An active underrun sets fault and ends TX.
 * Initial prefill holds HDU until the first complete LDU is queued. */
size_t p25_voice_tx_read(p25_voice *v, uint8_t *dibits, size_t capacity);
int p25_voice_tx_done(const p25_voice *v);
void p25_voice_tx_abort(p25_voice *v);
#endif
