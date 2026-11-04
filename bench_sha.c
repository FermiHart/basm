/* bench_sha.c — measure SHA-256 throughput with and without SHA-NI.
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* Software-only path. */
#define SHA256NI_CTX_TYPE sw_sha_ctx
#define SHA256NI_PREFIX   sw_sha_
#undef SHA256NI_FORCE_SOFTWARE
#define SHA256NI_FORCE_SOFTWARE 1
#include "sha256_ni.h"

/* Hardware-dispatch path. */
#undef SHA256_NI_H
#undef SHA256NI_CTX_TYPE
#undef SHA256NI_PREFIX
#undef SHA256NI_FORCE_SOFTWARE
#define SHA256NI_FORCE_SOFTWARE 0 /* W01: distinct scalar and dispatch lanes. */
#define SHA256NI_CTX_TYPE hw_sha_ctx
#define SHA256NI_PREFIX   hw_sha_
#include "sha256_ni.h"

#define MiB (1024ULL * 1024ULL)
static volatile uint8_t digest_sink; /* Retain the computed digest under -O2. */

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static double bench_sw(const uint8_t *buf, size_t len, int rounds) {
    uint8_t out[32];
    double t0 = now();
    for (int r = 0; r < rounds; r++) {
        sw_sha_ctx c; sw_sha_init(&c);
        sw_sha_update(&c, buf, len);
        sw_sha_final(&c, out);
        digest_sink ^= out[r & 31];
    }
    return now() - t0;
}

static double bench_hw(const uint8_t *buf, size_t len, int rounds) {
    uint8_t out[32];
    double t0 = now();
    for (int r = 0; r < rounds; r++) {
        hw_sha_ctx c; hw_sha_init(&c);
        hw_sha_update(&c, buf, len);
        hw_sha_final(&c, out);
        digest_sink ^= out[r & 31];
    }
    return now() - t0;
}

int main(void) {
    size_t len = 64 * MiB;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) { printf("oom\n"); return 1; }
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(i & 0xff);

    /* Validate equal digests before allowing throughput numbers. */
    uint8_t sw[32], hw[32];
    sw_sha_ctx scalar; hw_sha_ctx dispatch;
    sw_sha_init(&scalar); sw_sha_update(&scalar,buf,len); sw_sha_final(&scalar,sw);
    hw_sha_init(&dispatch); hw_sha_update(&dispatch,buf,len); hw_sha_final(&dispatch,hw);
    if (memcmp(sw,hw,sizeof(sw))) { free(buf); printf("SHA digest mismatch\n"); return 1; }

    int rounds = 4;
    double t_sw = bench_sw(buf, len, rounds);
    double t_hw = bench_hw(buf, len, rounds);

    double mb_sw = (double)(len * rounds) / t_sw / MiB;
    double mb_hw = (double)(len * rounds) / t_hw / MiB;

    printf("SHA-256 software: %.3f s -> %.1f MiB/s\n", t_sw, mb_sw);
    printf("SHA-256 dispatch: %.3f s -> %.1f MiB/s\n", t_hw, mb_hw);
#ifdef SHA256NI_X86
    printf("SHA-NI selected: %s\n", hw_sha_has_sha_ni ? "yes" : "no (software fallback)");
#else
    printf("SHA-NI selected: no (software-only target)\n");
#endif
    if (t_sw > 0 && t_hw > 0)
        printf("speedup: %.2fx\n", t_sw / t_hw);

    free(buf);
    return 0;
}
