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
 * Main SHA256Dv loop (scalar): pre-hash the first 64 bytes of the 80-byte
 * stage2 buffer (one full SHA256 block), then iterate only over the last
 * 16 bytes (merkle tail + ntime + nonces). This reduces per-nonce work
 * without requiring AVX/SIMD paths.
 */
int scanhash_sha256dv(struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr)
{
    const int thr_id = mythr->id;

    if (!work->veil_sha256dv)
        return 0;

    uint8_t  stage2[80] __attribute__((aligned(64)));
    uint8_t  tail[16];      /* merkle_tail(4) + ntime(4) + nonce_lo(4) + nonce_hi(4) */
    uint8_t  hash1[32];
    uint8_t  hash2[32];
    uint32_t hash_le[8];

    /* Precomputed context after hashing the first 64 bytes (one SHA256 block). */
    sha256_context base_ctx;

    uint32_t nonce_hi = work->veil_nonce_hi + (uint32_t)thr_id;
    uint32_t nonce_lo = 0;
    const uint32_t *ptarget = work->target;

    *hashes_done = 0;

    /*
     * Build stage2 once to seed the base context. The first 64 bytes are constant
     * for a given job, so we hash them once and reuse the intermediate state.
     */
    veil_sha256dv_build_stage2(stage2, work, 0, nonce_hi);

    sha256_ctx_init(&base_ctx);
    sha256_update(&base_ctx, stage2, 64);

    /* Fixed part of the tail for this job: merkle tail (4) + ntime (4). */
    memcpy(tail, stage2 + 64, 8);

    while (!work_restart[thr_id].restart) {

        /* Update per-iteration nonces (little-endian). */
        le32enc(tail + 8,  nonce_lo);
        le32enc(tail + 12, nonce_hi);

        /* First SHA256 over 80 bytes using the pre-hashed first block. */
        sha256_context ctx = base_ctx;
        sha256_update(&ctx, tail, 16);
        sha256_final(&ctx, hash1);

        /* Second SHA256 (SHA256D). */
        sha256_full(hash2, hash1, 32);

        /* Convert digest words to LE for target comparison. */
        for (int i = 0; i < 8; i++)
            hash_le[i] = be32dec(hash2 + i * 4);

        if (veil_hash_meets_target(hash_le, ptarget)) {

            uint64_t nonce64 = ((uint64_t)nonce_hi << 32) | nonce_lo;

            /* Store final nonce pair for submit. */
            work->veil_nonce_lo = nonce_lo;
            work->veil_nonce_hi = nonce_hi;

            if (!submit_solution(work, hash2, mythr)) {
                applog(LOG_WARNING,
                       "SHA256Dv[%d]: submit_solution failed for job=%s (nonce64=%016" PRIx64 ")",
                       thr_id,
                       work->job_id ? work->job_id : "(null)",
                       nonce64);
            }

            (*hashes_done)++;

            /*
             * Move to the next non-overlapping high-nonce range for this thread.
             * Mirrors the Python miner / range-splitting scheme.
             */
            work->veil_nonce_hi = work->veil_nonce_hi + (uint32_t)opt_n_threads;

            return 0;
        }

        nonce_lo++;

        /* Carry to high part; step by opt_n_threads to keep thread ranges disjoint. */
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
