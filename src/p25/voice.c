/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "voice.h"
#include "p25_runtime.h"

static void admission_reset(p25_voice *v)
{
    v->rx_key = NULL;
    v->rx_have_mi = 0;
    v->crypto_clear = v->have_group = 0;
    v->active_nac = P25_NAC_ANY;
    v->active_group = 0;
    v->active_source = 0;
    dm32_imbe_init(&v->codec);
}

void p25_voice_rx_reset(p25_voice *v)
{
    /* Stale receive records must not reset the shared active TX codec. */
    if (v->transmitting) return;
    p25_rx_init(&v->framer, v->framer.expected_nac, 2);
    admission_reset(v);
}

void p25_voice_init(p25_voice *v, uint16_t nac, uint16_t group,
                    p25_pcm_sink sink, void *ctx)
{
    memset(v, 0, sizeof *v);
    v->sink = sink;
    v->sink_ctx = ctx;
    v->group_filter = group;
    p25_rx_init(&v->framer, nac == 0xf7e ? P25_NAC_ANY : nac, 2);
    admission_reset(v);
}

void p25_voice_set_keys(p25_voice *v, const p25_key *keys, unsigned count)
{
    v->keys = keys;
    v->key_count = (uint8_t)(keys && count < 255 ? count : 0);
    v->rx_key = NULL;
    v->rx_have_mi = 0;
}

/* Take the encryption sync from an HDU or LDU2 and find its key. An LDU2 MI
 * applies to the superframe it arrives in, so late entry recovers from it. */
static void rx_sync(p25_voice *v, const p25_decoded *d)
{
    unsigned i;
    v->rx_key = NULL;
    v->rx_have_mi = 0;
    if (d->clear_voice) return;
    v->rx_algorithm = d->algorithm_id;
    v->rx_key_id = d->key_id;
    memcpy(v->rx_mi, d->message_indicator, P25_MI_BYTES);
    v->rx_have_mi = 1;
    for (i = 0; i < v->key_count; i++)
        if (v->keys[i].algorithm_id == d->algorithm_id && v->keys[i].key_id == d->key_id) {
            v->rx_key = &v->keys[i];
            break;
        }
}

void p25_voice_rx_dibit(p25_voice *v, uint8_t dibit)
{
    if (v->transmitting || !p25_rx_push_dibit(&v->framer, dibit)) return;
    p25_decoded d;
    uint32_t at=v->micros?v->micros():0;
    int decoded=p25_decode_frame(v->framer.frame, p25_frame_bytes(v->framer.nid.duid), &d);
    uint32_t elapsed=v->micros?v->micros()-at:0;
    if (elapsed>v->fec_max_us)v->fec_max_us=elapsed;
    if (decoded) {
        admission_reset(v);
        return;
    }
    v->rx_frames++;
    if (v->active_nac != d.nid.nac) {
        admission_reset(v);
        v->active_nac = d.nid.nac;
    }
    if (d.nid.duid == P25_DUID_TDU || d.nid.duid == P25_DUID_TDULC) {
        admission_reset(v);
        return;
    }
    if (!d.metadata_valid || (d.nid.duid == P25_DUID_HDU && d.manufacturer_id > 1)) {
        /* Do not reuse permission from a previous good header over damage. */
        v->crypto_clear = v->have_group = 0;
    } else if (d.nid.duid == P25_DUID_HDU) {
        admission_reset(v);
        v->active_nac = d.nid.nac;
        v->crypto_clear = d.clear_voice;
        v->active_group = d.talkgroup;
        v->have_group = d.talkgroup != 0;
        rx_sync(v, &d);
    } else if (d.nid.duid == P25_DUID_LDU1) {
        if ((v->have_group && v->active_group != d.talkgroup) ||
            (v->active_source && v->active_source != d.source_id))
            v->crypto_clear = 0;
        v->active_group = d.talkgroup;
        v->active_source = d.source_id;
        v->have_group = d.talkgroup && d.source_id && d.source_id <= 9999999u;
        if (!d.clear_voice) v->crypto_clear = 0;
        /* LC's unprotected bit alone cannot override an encrypted ALGID.
         * Late entry waits for a valid LDU2 encryption sync. */
    } else if (d.nid.duid == P25_DUID_LDU2) {
        v->crypto_clear = d.clear_voice;
        rx_sync(v, &d);
    }
    if (d.nid.duid != P25_DUID_LDU1 && d.nid.duid != P25_DUID_LDU2) return;
    unsigned ldu = d.nid.duid == P25_DUID_LDU2;
    /* Encrypted voice plays only with a matching key and a known MI; anything
     * else stays muted, as before. Late entry waits for an LDU2. */
    int decrypt = !v->crypto_clear && v->rx_have_mi && v->rx_key &&
        !p25_keystream_ldu(v->rx_key, v->rx_mi, ldu, v->rx_ks);
    if (!v->crypto_clear && v->rx_have_mi && !v->rx_key) v->rx_no_key++;
    int admitted = (v->crypto_clear || decrypt) && v->have_group &&
        (!v->group_filter || v->active_group == v->group_filter || v->active_group == 0xffff);
    for (unsigned i = 0; i < 9; i++) {
        int16_t pcm[160] = {0};
        if (!admitted) v->rx_muted++;
        /* Conservative implementation policy, not a TIA concealment rule.
         * Golay/Hamming can miscorrect beyond t; no audio-quality claim. */
        else {
            if (decrypt) {
                p25_crypt_imbe(d.imbe[i], v->rx_ks + P25_KS_VOICE_BYTES * i);
                v->rx_decrypted++;
            }
            at=v->micros?v->micros():0;
            int ok=d.voice_u0_corrected_bits[i] <= 3 && d.voice_corrected_bits[i] <= 10 &&
                   dm32_imbe_decode(&v->codec, d.imbe[i], pcm);
            elapsed=v->micros?v->micros()-at:0;
            if(elapsed>v->imbe_max_us)v->imbe_max_us=elapsed;
            if(!ok) {
                memset(pcm, 0, sizeof pcm);
                v->rx_erasures++;
                dm32_imbe_init(&v->codec);
            } else v->rx_voice++;
        }
        if (v->sink) v->sink(v->sink_ctx, pcm);
    }
    /* The next superframe's LDU1 uses the advanced MI; its LDU2 will confirm. */
    if (ldu && !v->crypto_clear && v->rx_have_mi) p25_mi_advance(v->rx_mi);
}

int p25_voice_set_tx_key(p25_voice *v, const p25_key *key, uint32_t (*random32)(void))
{
    if (v->transmitting) return 0;
    if (!key) { v->tx_encrypt = 0; return 1; }
    if (!p25_key_length(key->algorithm_id) || !random32) return 0;
    v->tx_key = *key;
    v->random32 = random32;
    v->tx_encrypt = 1;
    return 1;
}

static p25_voice_packet *next_packet(p25_voice *v)
{
    return v->count < P25_VOICE_QUEUE ? &v->queue[v->head] : NULL;
}

static void commit_packet(p25_voice *v, uint16_t bytes)
{
    v->queue[v->head].bytes = bytes;
    v->head = (uint8_t)((v->head + 1) % P25_VOICE_QUEUE);
    v->count++;
    v->tx_frames++;
}

void p25_voice_tx_abort(p25_voice *v)
{
    v->transmitting = v->started = v->stopping = v->terminator_pending = 0;
    v->count = v->head = v->tail = v->voice_count = 0;
    v->packet_symbol = 0;
    p25_voice_rx_reset(v);
}

static int fail(p25_voice *v)
{
    p25_voice_tx_abort(v);
    v->fault = 1;
    return 0;
}

int p25_voice_tx_begin(p25_voice *v, const p25_call *call)
{
    if (!call || v->transmitting || !call->talkgroup ||
        !call->source_id || call->source_id > 9999999u) return 0;
    p25_voice_tx_abort(v);
    v->fault = 0;
    p25_crypto_sync sync = {0}, *sp = NULL;
    if (v->tx_encrypt) {
        /* Fresh random 72-bit MI per call. An all-zero MI is the LFSR's fixed
         * point, so it is never used. */
        for (unsigned i = 0; i < P25_MI_BYTES; i += 4) {
            uint32_t r = v->random32();
            for (unsigned j = 0; j < 4 && i + j < P25_MI_BYTES; j++)
                v->tx_mi[i + j] = (uint8_t)(r >> (8 * j));
        }
        if (!(v->tx_mi[0] | v->tx_mi[1] | v->tx_mi[2] | v->tx_mi[3] |
              v->tx_mi[4] | v->tx_mi[5] | v->tx_mi[6] | v->tx_mi[7])) v->tx_mi[0] = 1;
        v->tx_mi[8] = 0;
        sync.algorithm_id = v->tx_key.algorithm_id;
        sync.key_id = v->tx_key.key_id;
        memcpy(sync.message_indicator, v->tx_mi, P25_MI_BYTES);
        sp = &sync;
    }
    if (p25_encode_hdu_ex(call, sp, v->queue[0].data)) return 0;
    v->call = *call;
    v->transmitting = 1;
    v->next_duid = P25_DUID_LDU1;
    commit_packet(v, P25_HDU_BYTES);
    return 1;
}

int p25_voice_tx_pcm(p25_voice *v, int16_t pcm[160])
{
    if (!v->transmitting || v->stopping || !pcm) return 0;
    if (!dm32_imbe_encode(&v->codec, pcm, v->voice[v->voice_count])) return fail(v);
    if (v->tx_encrypt) {
        /* The codec keeps the clear frame; only the transmitted copy is XORed. */
        if (!v->voice_count &&
            p25_keystream_ldu(&v->tx_key, v->tx_mi, v->next_duid == P25_DUID_LDU2, v->tx_ks))
            return fail(v);
        p25_crypt_imbe(v->voice[v->voice_count], v->tx_ks + P25_KS_VOICE_BYTES * v->voice_count);
    }
    if (++v->voice_count < 9) return 1;
    p25_voice_packet *p = next_packet(v);
    const uint8_t lsd[2] = {0, 0};
    p25_crypto_sync sync = {0};
    if (v->tx_encrypt) {
        sync.algorithm_id = v->tx_key.algorithm_id;
        sync.key_id = v->tx_key.key_id;
        memcpy(sync.message_indicator, v->tx_mi, P25_MI_BYTES);
    }
    if (!p || p25_encode_ldu_ex(&v->call, v->tx_encrypt ? &sync : NULL, v->next_duid, v->voice, lsd, p->data))
        return fail(v);
    commit_packet(v, P25_LDU_BYTES);
    if (v->tx_encrypt && v->next_duid == P25_DUID_LDU2) p25_mi_advance(v->tx_mi);
    v->voice_count = 0;
    v->next_duid ^= P25_DUID_LDU1 ^ P25_DUID_LDU2;
    v->started = 1;
    return 1;
}

static void append_terminator(p25_voice *v)
{
    p25_voice_packet *p = next_packet(v);
    if (v->terminator_pending && p) {
        if (p25_encode_tdu(&v->call, p->data)) { fail(v); return; }
        commit_packet(v, P25_TDU_BYTES);
        v->terminator_pending = 0;
    }
}

int p25_voice_tx_end(p25_voice *v)
{
    if (!v->transmitting || v->stopping) return 0;
    if (!v->started && !v->voice_count) { p25_voice_tx_abort(v); return 1; }
    while (v->voice_count) {
        int16_t silence[160] = {0};
        if (!p25_voice_tx_pcm(v, silence)) return 0;
    }
    v->stopping = v->terminator_pending = 1;
    append_terminator(v);
    return !v->fault;
}

size_t p25_voice_tx_read(p25_voice *v, uint8_t *out, size_t capacity)
{
    if (!v->transmitting || !v->started || !out || !capacity) return 0;
    size_t n = 0;
    while (n < capacity) {
        append_terminator(v);
        if (!v->count) {
            if (v->stopping) { p25_voice_tx_abort(v); break; }
            v->tx_underruns++;
            fail(v);
            break;
        }
        p25_voice_packet *p = &v->queue[v->tail];
        unsigned bit = v->packet_symbol * 2u;
        out[n++] = (uint8_t)((p->data[bit / 8] >> (6 - bit % 8)) & 3u);
        if (++v->packet_symbol == p->bytes * 4u) {
            v->packet_symbol = 0;
            v->tail = (uint8_t)((v->tail + 1) % P25_VOICE_QUEUE);
            v->count--;
        }
    }
    /* A read ending exactly at the TDU boundary is done immediately. */
    if (v->transmitting && v->stopping && !v->count && !v->terminator_pending)
        p25_voice_tx_abort(v);
    return n;
}

int p25_voice_tx_done(const p25_voice *v) { return !v->transmitting; }
