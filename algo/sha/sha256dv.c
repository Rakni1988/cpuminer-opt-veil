#include <string.h>
#include <inttypes.h>

#include "miner.h"
#include "sha256-hash.h"
#include "sha256dv.h"


/*
 * Build the 80-byte Stage2 buffer exactly like veil_sha256d_miner.py:
 *
 *  version_le (4)
 *  midstate_be (32)
 *  merkle_le (32)
 *  ntime_le (4)
 *  nonce_low_le (4)
 *  nonce_high_le (4)
 *
 * Python equivalent:
 *   stage2 = version_le + midstate_be + merkle_le + ntime_le
 *            + nonce_low_le + nonce_high_le
 */
static inline void veil_sha256dv_build_stage2(
    uint8_t out[80],
    const struct work *work,
    uint32_t nonce_low,
    uint32_t nonce_high
)
{
    uint8_t *p = out;

    /* 1) VERSION:
     * use work->data[0] as version in host order
     * and encode it as little-endian (same as version.to_bytes(4, "little"))
     */
    uint32_t version_host = work->data[0];
    le32enc(p, version_host);
    p += 4;

    /* 2) MIDSTATE (big-endian) – copy as is */
    memcpy(p, work->veil_midstate_be, 32);
    p += 32;

    /* 3) MERKLE (little-endian) = reversed MERKLE_BE */
    for (int i = 0; i < 32; i++)
        p[i] = work->veil_merkle_be[31 - i];
    p += 32;

    /* 4) NTIME (little-endian) */
    le32enc(p, work->veil_ntime);
    p += 4;

    /* 5) nonce_low (little-endian) */
    le32enc(p, nonce_low);
    p += 4;

    /* 6) nonce_high (little-endian) */
    le32enc(p, nonce_high);
    p += 4;
}

/*
 * Silent equivalent of fulltest() – no logging.
 * `hash` and `target` are 8 × uint32 in LE, compared from the most significant word.
 */
static inline bool veil_hash_meets_target(const uint32_t *hash,
                                          const uint32_t *target)
{
    for (int i = 7; i >= 0; i--) {
        if (hash[i] > target[i])
            return false;
        if (hash[i] < target[i])
            return true;
    }
    return true;  /* exactly the same semantics as fulltest() */
}


/*
 * Main SHA256Dv loop – equivalent of the Python miner thread,
 * implemented in cpuminer-opt style.
 */
int scanhash_sha256dv(struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr)
{
    const int thr_id = mythr->id;

    /* If this work item is not Veil SHA256Dv, fall back immediately. */
    if (!work->veil_sha256dv)
        return 0;

    uint8_t  stage2[80] __attribute__((aligned(64)));
    uint8_t  hash_be[32];
    uint32_t hash_le[8];

    /*
     * Initial nonce_hi – same scheme as in the Python miner:
     *   base_hi = job.nonce_hi
     *   per-thread offset = thread_id
     */
    uint32_t nonce_hi = work->veil_nonce_hi + (uint32_t)thr_id;
    uint32_t nonce_lo = 0;

    const uint32_t *ptarget = work->target;
    *hashes_done = 0;

    while (!work_restart[thr_id].restart) {

        veil_sha256dv_build_stage2(stage2, work, nonce_lo, nonce_hi);

        sha256_full(hash_be, stage2, 80);
        sha256_full(hash_be, hash_be, 32);

        for (int i = 0; i < 8; i++)
            hash_le[i] = be32dec(hash_be + i * 4);

        if (veil_hash_meets_target(hash_le, ptarget)) {
            uint64_t nonce64 = ((uint64_t)nonce_hi << 32) | nonce_lo;

            /* Store final nonce pair for submit */
            work->veil_nonce_lo = nonce_lo;
            work->veil_nonce_hi = nonce_hi;

            if (!submit_solution(work, hash_be, mythr)) {
                /* Keep only a warning on submit failure – everything else stays silent */
                applog(LOG_WARNING,
                       "SHA256Dv[%d]: submit_solution failed for job=%s (nonce64=%016" PRIx64 ")",
                       thr_id,
                       work->job_id ? work->job_id : "(null)",
                       nonce64);
            }

            (*hashes_done)++;

            /*
             * Advance the high 32 bits by opt_n_threads so the next range
             * for this thread does not overlap with the current one.
             * This mirrors the Python miner behaviour and keeps the loop bounded.
             */
            uint32_t new_hi = work->veil_nonce_hi + (uint32_t)opt_n_threads;
            work->veil_nonce_hi = new_hi;

            return 0;
        }

        nonce_lo++;

        if (nonce_lo == 0)
            nonce_hi += (uint32_t)opt_n_threads;

        (*hashes_done)++;

        if (max_nonce && nonce_lo >= max_nonce)
            break;
    }

    return 0;
}


/*
 * Algorithm registration hook.
 * The gate still uses std_get_new_work, build_extraheader, etc.
 */
bool register_sha256dv_algo(algo_gate_t *gate)
{
    gate->scanhash = (void *)scanhash_sha256dv;
    return true;
}
