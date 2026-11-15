/* SPDX-License-Identifier: GPL-3.0-or-later */
/* User-authorized development derivative; not an MIT-only upstream submission. */
#include <string.h>
#include "p25_keys.h"
#include "keyload.h"
#include "nonce.h"
#include "config.h"
#include "board.h"
#include "storage/storage.h"
#include "debuglink/debuglink_proto.h"
#include "FreeRTOS.h"
#include "task.h"

static p25_keystore ks;                 /* guarded by a critical section */
static uint8_t pending[P25_KS_BLOB_BYTES];
static volatile uint8_t save_pending;   /* a save job is queued or running */
static volatile uint8_t persisted;      /* flash holds the current store */
static volatile uint8_t boot_saved;     /* flash holds this boot's incremented count */
static uint8_t flash_ok, stored_corrupt, uid_ok, count_exhausted;
static uint32_t uid[3];
static p25_key rx_keys[P25_KS_SLOTS];   /* p25_voice_set_keys keeps a pointer to this */

static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* The last erase unit of the native codeplug area: nothing in Classic writes
 * there. storage_native_erase (factory reset) leaves a non-blank area without
 * the native header alone, so a reset does NOT clear the keys; use zeroize. */
static uint32_t key_sector(void)
{
    const hal_flash_map_t *m = storage_map();
    if (!m || !m->native_addr || m->native_size < 2u * STORAGE_SECTOR ||
        (m->native_addr % STORAGE_SECTOR) || (m->native_size % STORAGE_SECTOR)) return 0;
    return m->native_addr + m->native_size - STORAGE_SECTOR;
}

static int nonce_ready(void)
{
    return uid_ok && boot_saved && !count_exhausted && ks.boot_count != 0;
}

static uint8_t flags_now(void)
{
    return (uint8_t)((persisted && !save_pending ? P25_KL_F_PERSISTED : 0) |
                     (nonce_ready() ? P25_KL_F_NONCE_READY : 0) |
                     (flash_ok ? P25_KL_F_FLASH_OK : 0) |
                     (stored_corrupt ? P25_KL_F_STORED_CORRUPT : 0));
}

/* Runs on the housekeeping task. */
static void save_job(void *ctx)
{
    uint32_t addr = key_sector();
    int ok = addr && storage_ready() && storage_write(addr, pending, sizeof pending);
    (void)ctx;
    taskENTER_CRITICAL();
    if (ok) { persisted = 1; boot_saved = 1; }
    save_pending = 0;
    taskEXIT_CRITICAL();
}

/* Snapshot the store and queue a write. storage_job_post is a bare
 * check-then-set, so the post is made with preemption off. */
static int queue_save(void)
{
    int ok;
    if (!flash_ok) return 0;
    taskENTER_CRITICAL();
    if (save_pending || storage_job_busy()) {
        ok = 0;
    } else {
        p25_ks_serialize(&ks, pending);
        persisted = 0;
        save_pending = 1;
        ok = storage_job_post(save_job, NULL);
        if (!ok) save_pending = 0;
    }
    taskEXIT_CRITICAL();
    return ok;
}

void p25_keys_start(void)
{
    hal_chip_t chip;
    uint8_t blob[P25_KS_BLOB_BYTES];
    uint32_t addr = key_sector();
    int rc;

    p25_ks_init(&ks);
    p25_nonce_reset();
    uid_ok = board.system && board.system->chip && board.system->chip(&chip) &&
             (chip.uid[0] | chip.uid[1] | chip.uid[2]);
    if (uid_ok) memcpy(uid, chip.uid, sizeof uid);

    if (!addr || !storage_ready() || !board.flash || !board.flash->read) return;
    storage_lock();
    rc = board.flash->read(addr, blob, sizeof blob) ? 0 : 1;
    storage_unlock();
    if (rc) return;                       /* unreadable: no keys, no writes */
    flash_ok = 1;
    rc = p25_ks_parse(&ks, blob);
    if (rc < 0) {
        /* Damaged record: keys are gone. The count is unknown, so restart it;
         * every key must be loaded again, and each load brings a fresh salt. */
        stored_corrupt = 1;
        p25_ks_init(&ks);
    }
    if (ks.boot_count == 0xFFFFFFFFu) count_exhausted = 1; else ks.boot_count++;
    wipe(blob, sizeof blob);
    (void)queue_save();                   /* failure leaves boot_saved clear: no encrypted TX */
}

int p25_keys_apply(p25_voice *v, int for_tx)
{
    p25_keystore snap;
    int ready, ok = 1;
    const p25_ks_slot *t;
    unsigned n;

    taskENTER_CRITICAL();
    snap = ks;
    ready = nonce_ready();
    taskEXIT_CRITICAL();

    n = p25_ks_rx_keys(&snap, rx_keys);
    p25_voice_set_keys(v, n ? rx_keys : NULL, n);

    t = p25_ks_tx(&snap);
    if (t && for_tx) {
        if (ready) {
            p25_nonce_set_domain(uid, snap.boot_count, t->salt, t->key.algorithm_id, t->key.key_id);
            ok = p25_voice_set_tx_key(v, &t->key, p25_nonce_random32) != 0;
        } else {
            ok = 0;
        }
        if (!ok) (void)p25_voice_set_tx_key(v, NULL, NULL);
    } else {
        (void)p25_voice_set_tx_key(v, NULL, NULL);
    }
    wipe(&snap, sizeof snap);
    return ok;
}

size_t p25_keys_command(const uint8_t *req, uint16_t len, uint8_t *out, size_t cap)
{
    uint8_t body[P25_KL_STATUS_BODY];
    size_t bl = 0;
    int changed = 0, cls;

    if (!cap) return 0;
    if (!req || !len) { out[0] = DL_ST_BAD_ARG; return 1; }
    if (req[0] == P25_KL_OP_STATUS) {
        if (!persisted && !save_pending) (void)queue_save();   /* retry a save that did not land */
    } else if (save_pending || storage_job_busy()) {
        out[0] = DL_ST_BUSY;                                    /* one flash job at a time: try again */
        return 1;
    }
    taskENTER_CRITICAL();
    cls = p25_keyload_handle(&ks, flags_now(), req, len, body, sizeof body, &bl, &changed);
    if (changed) persisted = 0;         /* flash is stale from this moment, whether or not the save queues */
    taskEXIT_CRITICAL();
    if (changed) (void)queue_save();                            /* STATUS shows if it did not land */
    out[0] = cls == P25_KL_OK ? DL_ST_OK : cls == P25_KL_UNAVAILABLE ? DL_ST_UNAVAILABLE : DL_ST_BAD_ARG;
    if (bl > cap - 1) bl = cap - 1;
    memcpy(out + 1, body, bl);
    wipe(body, sizeof body);
    return 1 + bl;
}
