/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DM32_P25_NONCE_H
#define DM32_P25_NONCE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Message-indicator source for encrypted transmit, for a radio with no
 * hardware random number generator.
 *
 * OFB mode is only safe if a (key, MI) pair is never used twice. The MI does
 * not have to be secret or random, only unique, so this is a counter run
 * through a bijective 64-bit mixer, not a pretend RNG:
 *
 *   MI(k) = mix64(domain + k)          k = per-boot call counter
 *   domain = hash(radio UID, boot_count, key salt, algorithm, key ID)
 *
 * For one domain the map k -> MI is a bijection, so no MI repeats within a
 * boot. Different radios, different boots and different key loads land in
 * different domains. The counter is NOT reset when the key changes, so
 * switching back to an earlier key in the same boot cannot replay its MIs.
 *
 * Uniqueness across domains is probabilistic (64 bits), not guaranteed. It
 * relies on boot_count never decreasing: restoring an old flash backup rewinds
 * it, which is why every key load carries a fresh host-generated salt. After
 * restoring a backup, reload the keys.
 *
 * p25_voice_tx_begin calls random32 three times per call start and uses the
 * first two results as MI bytes 0..7; the generator therefore advances its
 * counter every third call. tests/keys covers this against the real voice code.
 * Single caller (the TX worker); not reentrant.
 */
void p25_nonce_reset(void);   /* new boot: counter back to 0 */
void p25_nonce_set_domain(const uint32_t uid[3], uint32_t boot_count,
                          const uint8_t salt[4], uint8_t algorithm_id, uint16_t key_id);
uint32_t p25_nonce_random32(void);

#ifdef __cplusplus
}
#endif
#endif
