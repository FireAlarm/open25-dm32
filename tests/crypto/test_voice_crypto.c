/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Encrypted conventional voice, TX -> dibits -> RX, with a stand-in codec.
 * The stub maps PCM samples 0..7 straight onto the IMBE vector, so the test
 * checks that the cipher layer and framing return exactly what was sent.
 * It says nothing about audio quality or interoperability. Host only. */
#include "voice.h"
#include <stdio.h>
#include <string.h>

static int failures;
#define CHECK(cond, ...) do { if (!(cond)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- stand-in for the IMBE codec (the real one needs fetched sources) ---- */
static const uint16_t vmask[8] = {0xfff, 0xfff, 0xfff, 0xfff, 0x7ff, 0x7ff, 0x7ff, 0x7e};
void dm32_imbe_init(dm32_imbe_context *c) { (void)c; }
int dm32_imbe_encode(dm32_imbe_context *c, int16_t pcm[160], uint16_t u[8])
{
    unsigned j;
    (void)c;
    for (j = 0; j < 8; ++j) u[j] = (uint16_t)pcm[j] & vmask[j];
    return 1;
}
int dm32_imbe_decode(dm32_imbe_context *c, const uint16_t u[8], int16_t pcm[160])
{
    unsigned j;
    (void)c;
    memset(pcm, 0, 160 * sizeof *pcm);
    for (j = 0; j < 8; ++j) pcm[j] = (int16_t)(u[j] & vmask[j]);
    return 1;
}

/* ---- helpers ---- */
enum { FRAMES = 36, HDU_DIBITS = 396, LDU_DIBITS = 864, TDU_DIBITS = 72,
       STREAM_MAX = HDU_DIBITS + 4 * LDU_DIBITS + TDU_DIBITS };
static int16_t sunk[64][160];
static unsigned sunk_count;
static void sink(void *ctx, const int16_t pcm[160]) { (void)ctx; if (sunk_count < 64) memcpy(sunk[sunk_count++], pcm, sizeof sunk[0]); }

static uint32_t rng_state = 0x1badf00d;
static uint32_t test_random(void) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 17; rng_state ^= rng_state << 5; return rng_state; }

static void plain_pcm(unsigned f, int16_t pcm[160])
{
    unsigned j;
    memset(pcm, 0, 160 * sizeof *pcm);
    for (j = 0; j < 8; ++j) pcm[j] = (int16_t)((f * 37 + j * 101 + 7) & vmask[j]);
}

static p25_key make_key(uint8_t alg, uint16_t kid, uint8_t seed)
{
    p25_key k;
    unsigned i;
    memset(&k, 0, sizeof k);
    k.algorithm_id = alg; k.key_id = kid;
    for (i = 0; i < p25_key_length(alg); ++i) k.key[i] = (uint8_t)(seed + 7 * i);
    return k;
}

static const p25_call CALL = {0x293, 1234, 4321, 0, 0, 0};

/* Transmit FRAMES voice frames (4 LDUs) and collect the dibit stream. */
static size_t transmit(p25_voice *tx, uint8_t *dibits)
{
    size_t n = 0, got;
    unsigned f;
    int16_t pcm[160];
    CHECK(p25_voice_tx_begin(tx, &CALL), "tx_begin");
    for (f = 0; f < FRAMES; ++f) {
        plain_pcm(f, pcm);
        CHECK(p25_voice_tx_pcm(tx, pcm), "tx_pcm %u", f);
        if (f % 9 == 8) {
            if (f == 8) { got = p25_voice_tx_read(tx, dibits + n, HDU_DIBITS); n += got; CHECK(got == HDU_DIBITS, "hdu read %zu", got); }
            got = p25_voice_tx_read(tx, dibits + n, LDU_DIBITS); n += got;
            CHECK(got == LDU_DIBITS, "ldu read %zu", got);
        }
    }
    CHECK(p25_voice_tx_end(tx), "tx_end");
    got = p25_voice_tx_read(tx, dibits + n, TDU_DIBITS); n += got;
    CHECK(got == TDU_DIBITS && p25_voice_tx_done(tx), "tdu read %zu", got);
    return n;
}

static void receive(p25_voice *rx, const uint8_t *dibits, size_t n)
{
    size_t i;
    sunk_count = 0;
    for (i = 0; i < n; ++i) p25_voice_rx_dibit(rx, dibits[i]);
}

/* Sink frame f is compared with plaintext frame f + shift (late entry skips frames). */
static unsigned frames_matching_shift(unsigned first, unsigned count, unsigned shift)
{
    unsigned f, ok = 0;
    int16_t want[160];
    for (f = first; f < first + count && f < sunk_count; ++f) {
        plain_pcm(f + shift, want);
        if (!memcmp(want, sunk[f], sizeof want)) ++ok;
    }
    return ok;
}

static unsigned frames_matching(unsigned first, unsigned count)
{
    return frames_matching_shift(first, count, 0);
}

static unsigned silent_frames(unsigned first, unsigned count)
{
    unsigned f, ok = 0, j;
    for (f = first; f < first + count && f < sunk_count; ++f) {
        int zero = 1;
        for (j = 0; j < 160; ++j) if (sunk[f][j]) zero = 0;
        ok += (unsigned)zero;
    }
    return ok;
}

static void test_algorithm(uint8_t alg, const char *name)
{
    static uint8_t stream[STREAM_MAX];
    p25_voice tx, rx;
    p25_key key = make_key(alg, 0x0102, 0x30), wrong = make_key(alg, 0x0102, 0x31), other_kid = make_key(alg, 0x0103, 0x30);
    size_t n;

    memset(&tx, 0, sizeof tx); memset(&rx, 0, sizeof rx);
    p25_voice_init(&tx, 0x293, 0, sink, NULL);
    p25_voice_init(&rx, 0x293, 0, sink, NULL);
    CHECK(p25_voice_set_tx_key(&tx, &key, test_random), "%s set tx key", name);
    n = transmit(&tx, stream);
    CHECK(n == STREAM_MAX, "%s stream length %zu", name, n);

    /* Matching key: every frame returns bit-exact. */
    p25_voice_set_keys(&rx, &key, 1);
    receive(&rx, stream, n);
    CHECK(sunk_count == FRAMES, "%s sunk %u", name, sunk_count);
    CHECK(frames_matching(0, FRAMES) == FRAMES, "%s decrypted %u/%d frames", name, frames_matching(0, FRAMES), FRAMES);
    CHECK(rx.rx_decrypted == FRAMES && rx.rx_no_key == 0, "%s counters %u/%u", name, rx.rx_decrypted, rx.rx_no_key);

    /* No key loaded: muted, and nothing leaks. */
    p25_voice_rx_reset(&rx); p25_voice_set_keys(&rx, NULL, 0);
    receive(&rx, stream, n);
    CHECK(silent_frames(0, FRAMES) == FRAMES && frames_matching(0, FRAMES) == 0, "%s no-key mute", name);
    CHECK(rx.rx_no_key > 0, "%s no_key counter", name);

    /* Same key id, different key material: never reproduces the voice. */
    p25_voice_rx_reset(&rx); p25_voice_set_keys(&rx, &wrong, 1);
    receive(&rx, stream, n);
    CHECK(frames_matching(0, FRAMES) == 0, "%s wrong key produced %u clear frames", name, frames_matching(0, FRAMES));

    /* Right material under a different key id is a different key: muted. */
    p25_voice_rx_reset(&rx); p25_voice_set_keys(&rx, &other_kid, 1);
    receive(&rx, stream, n);
    CHECK(silent_frames(0, FRAMES) == FRAMES, "%s key id mismatch mute", name);

    /* Late entry at the first LDU2: its own sync and the following LDU1 are
     * muted or lost until an LDU1 supplies the group; everything after is exact. */
    p25_voice_rx_reset(&rx); p25_voice_set_keys(&rx, &key, 1);
    receive(&rx, stream + HDU_DIBITS + LDU_DIBITS, n - HDU_DIBITS - LDU_DIBITS);
    CHECK(sunk_count == FRAMES - 9, "%s late entry sunk %u", name, sunk_count);
    CHECK(silent_frames(0, 9) == 9, "%s late entry LDU2 muted until group known", name);
    CHECK(frames_matching_shift(9, 18, 9) == 18, "%s late entry matched %u/18", name, frames_matching_shift(9, 18, 9));
}

static void test_clear_unchanged(void)
{
    static uint8_t stream[STREAM_MAX];
    p25_voice tx, rx;
    uint8_t hdu_a[P25_HDU_BYTES], hdu_b[P25_HDU_BYTES];
    size_t n;

    memset(&tx, 0, sizeof tx); memset(&rx, 0, sizeof rx);
    p25_voice_init(&tx, 0x293, 0, sink, NULL);
    p25_voice_init(&rx, 0x293, 0, sink, NULL);
    CHECK(!p25_voice_set_tx_key(&tx, &(p25_key){0}, test_random), "zero key rejected");
    {
        p25_key k = make_key(P25_ALG_AES256, 1, 1);
        CHECK(!p25_voice_set_tx_key(&tx, &k, NULL), "encrypted tx without RNG fails closed");
        CHECK(p25_voice_set_tx_key(&tx, &k, test_random) && p25_voice_set_tx_key(&tx, NULL, NULL), "can return to clear");
    }
    n = transmit(&tx, stream);
    receive(&rx, stream, n);
    CHECK(frames_matching(0, FRAMES) == FRAMES, "clear call still plays");

    CHECK(!p25_encode_hdu(&CALL, hdu_a) && !p25_encode_hdu_ex(&CALL, NULL, hdu_b) && !memcmp(hdu_a, hdu_b, sizeof hdu_a),
          "clear HDU unchanged by _ex(NULL)");
}

static void test_framing(void)
{
    p25_call call = CALL;
    p25_crypto_sync sync = {P25_ALG_AES256, 0xbeef, {1, 2, 3, 4, 5, 6, 7, 8, 9}};
    uint8_t hdu[P25_HDU_BYTES], ldu[P25_LDU_BYTES];
    uint16_t imbe[9][8] = {{0}};
    const uint8_t lsd[2] = {0, 0};
    p25_decoded d;

    CHECK(!p25_encode_hdu_ex(&call, &sync, hdu) && !p25_decode_frame(hdu, sizeof hdu, &d), "hdu encode/decode");
    CHECK(d.metadata_valid && !d.clear_voice && d.algorithm_id == P25_ALG_AES256 && d.key_id == 0xbeef &&
          !memcmp(d.message_indicator, sync.message_indicator, 9) && d.talkgroup == 1234, "hdu fields");

    CHECK(!p25_encode_ldu_ex(&call, &sync, P25_DUID_LDU2, imbe, lsd, ldu) && !p25_decode_frame(ldu, sizeof ldu, &d), "ldu2 encode/decode");
    CHECK(d.metadata_valid && !d.clear_voice && d.algorithm_id == P25_ALG_AES256 && d.key_id == 0xbeef &&
          !memcmp(d.message_indicator, sync.message_indicator, 9), "ldu2 ess fields");

    CHECK(!p25_encode_ldu_ex(&call, &sync, P25_DUID_LDU1, imbe, lsd, ldu) && !p25_decode_frame(ldu, sizeof ldu, &d), "ldu1 encode/decode");
    CHECK(d.metadata_valid && !d.clear_voice && (d.service_options & 0x40) && d.talkgroup == 1234 && d.source_id == 4321, "ldu1 protected bit");

    CHECK(!p25_encode_ldu(&call, P25_DUID_LDU2, imbe, lsd, ldu) && !p25_decode_frame(ldu, sizeof ldu, &d) &&
          d.clear_voice && d.algorithm_id == 0x80, "clear ldu2 stays clear");

    sync.algorithm_id = 0x82;
    CHECK(p25_encode_hdu_ex(&call, &sync, hdu) == -1 && p25_encode_ldu_ex(&call, &sync, P25_DUID_LDU2, imbe, lsd, ldu) == -1,
          "unknown algorithm rejected");
}

static void test_fresh_mi(void)
{
    static uint8_t s1[STREAM_MAX], s2[STREAM_MAX];
    p25_voice tx;
    p25_key key = make_key(P25_ALG_AES256, 9, 5);
    p25_decoded a, b;
    memset(&tx, 0, sizeof tx);
    p25_voice_init(&tx, 0x293, 0, sink, NULL);
    p25_voice_set_tx_key(&tx, &key, test_random);
    transmit(&tx, s1); transmit(&tx, s2);
    /* The stream begins with the HDU; decode it from the dibit stream. */
    {
        uint8_t packed[P25_HDU_BYTES];
        unsigned i;
        memset(packed, 0, sizeof packed);
        for (i = 0; i < HDU_DIBITS; ++i) packed[i / 4] = (uint8_t)(packed[i / 4] | (s1[i] << (6 - 2 * (i % 4))));
        CHECK(!p25_decode_frame(packed, sizeof packed, &a), "hdu 1");
        memset(packed, 0, sizeof packed);
        for (i = 0; i < HDU_DIBITS; ++i) packed[i / 4] = (uint8_t)(packed[i / 4] | (s2[i] << (6 - 2 * (i % 4))));
        CHECK(!p25_decode_frame(packed, sizeof packed, &b), "hdu 2");
    }
    CHECK(memcmp(a.message_indicator, b.message_indicator, 9) != 0, "each call starts with a new MI");
}

int main(void)
{
    test_framing();
    test_algorithm(P25_ALG_AES256, "AES-256");
    test_algorithm(P25_ALG_DES_OFB, "DES-OFB");
    test_algorithm(P25_ALG_ADP, "ADP");
    test_clear_unchanged();
    test_fresh_mi();
    if (failures) { printf("%d failure(s)\n", failures); return 1; }
    printf("encrypted voice loopback tests passed\n");
    return 0;
}
