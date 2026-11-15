/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "nonce.h"

/* SplitMix64 finalizer. Every step (add, xorshift, odd multiply) is a bijection
 * on 64 bits, so the whole function is. */
static uint64_t mix64(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static uint64_t domain, counter, current;
static unsigned phase;

void p25_nonce_reset(void)
{
    counter = 0;
    phase = 0;
}

void p25_nonce_set_domain(const uint32_t uid[3], uint32_t boot_count,
                          const uint8_t salt[4], uint8_t algorithm_id, uint16_t key_id)
{
    uint32_t s = (uint32_t)salt[0] | (uint32_t)salt[1] << 8 | (uint32_t)salt[2] << 16 | (uint32_t)salt[3] << 24;
    uint64_t h = mix64((uint64_t)uid[0] | (uint64_t)uid[1] << 32);
    h = mix64(h ^ ((uint64_t)uid[2] | (uint64_t)boot_count << 32));
    h = mix64(h ^ ((uint64_t)s | (uint64_t)algorithm_id << 32 | (uint64_t)key_id << 40));
    domain = h;
}

uint32_t p25_nonce_random32(void)
{
    switch (phase) {
    case 0:
        current = mix64(domain + counter);
        phase = 1;
        return (uint32_t)current;
    case 1:
        phase = 2;
        return (uint32_t)(current >> 32);
    default:
        /* The voice code discards this third word (MI byte 8 is cleared). */
        phase = 0;
        counter++;
        return (uint32_t)(current >> 16);
    }
}
