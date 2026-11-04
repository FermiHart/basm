/*═══════════════════════════════════════════════════════════════════════════════
 *
 *   sha256_ni.h  —  single-file, namespace-safe SHA-256 with runtime SHA-NI
 *                   dispatch.
 *
 *   Usage:
 *       #define SHA256NI_CTX_TYPE  my_sha_ctx
 *       #define SHA256NI_PREFIX    my_sha_
 *       #include "sha256_ni.h"
 *
 *   This header emits ONLY `static` symbols prefixed with `my_sha_` (or the
 *   default `sha256ni_`), so it can be included by multiple translation units
 *   without linkage conflicts.  It is designed to be dropped into sovereign-C
 *   projects (Bear/Basm/blibc) that do not yet have a shared crypto library.
 *
 *   Features:
 *     • FIPS 180-4 SHA-256 (software fallback).
 *     • Intel SHA Extensions (SHA-NI) acceleration on x86-64 with runtime
 *       CPUID detection; code path is guarded by `__attribute__((target(...)))`
 *       so the TU compiles even when the host compiler lacks `-msha`.
 *     • Constant-time-ish software path (no secret branches on data).
 *
 *   Author: F E R M I ∞ H A R T <contact@fermihart.com>
 *   SPDX-License-Identifier: Unlicense
 *
 *═══════════════════════════════════════════════════════════════════════════════*/

#ifndef SHA256_NI_H
#define SHA256_NI_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifndef SHA256NI_PREFIX
#define SHA256NI_PREFIX sha256ni_
#endif

#ifndef SHA256NI_CTX_TYPE
#define SHA256NI_CTX_TYPE sha256ni_ctx
#endif

#define SHA256NI_CAT2(a, b) a ## b
#define SHA256NI_CAT(a, b)  SHA256NI_CAT2(a, b)
#define SHA256NI_FN(name)   SHA256NI_CAT(SHA256NI_PREFIX, name)

/* The x86 SHA-NI block uses __m128i/immintrin.h, which the bear compiler
 * does not implement (ADR-0094 C7 — SSE is out of bear's declared scope).
 * Under __bear__ only the portable software path is compiled: identical
 * digests, no acceleration. */
/* W01: a diagnostic software lane must exclude the intrinsic implementation,
 * not merely make the runtime selector return zero. Reset the per-inclusion
 * feature marker because tests reuse this header with different namespaces. */
#ifndef SHA256NI_FORCE_SOFTWARE
#define SHA256NI_FORCE_SOFTWARE 0
#endif
#undef SHA256NI_X86
#if defined(__x86_64__) && !defined(__bear__) && !SHA256NI_FORCE_SOFTWARE
#define SHA256NI_X86 1
#endif

/*──────────────────────── Context & constants ───────────────────────────────*/
typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    int      nbuf;
} SHA256NI_CTX_TYPE;

static const uint32_t SHA256NI_FN(K)[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static const uint32_t SHA256NI_FN(IV)[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

static uint32_t SHA256NI_FN(ror)(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/*──────────────────────── Software block ─────────────────────────────────────*/
static void SHA256NI_FN(block)(SHA256NI_CTX_TYPE *c, const uint8_t *b) {
    uint32_t w[64], a, bb, cc, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)b[i * 4] << 24) |
               ((uint32_t)b[i * 4 + 1] << 16) |
               ((uint32_t)b[i * 4 + 2] << 8) |
               ((uint32_t)b[i * 4 + 3]);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = SHA256NI_FN(ror)(w[i - 15], 7) ^
                      SHA256NI_FN(ror)(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = SHA256NI_FN(ror)(w[i - 2], 17) ^
                      SHA256NI_FN(ror)(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; bb = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = SHA256NI_FN(ror)(e, 6) ^
                      SHA256NI_FN(ror)(e, 11) ^
                      SHA256NI_FN(ror)(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + SHA256NI_FN(K)[i] + w[i];
        uint32_t S0 = SHA256NI_FN(ror)(a, 2) ^
                      SHA256NI_FN(ror)(a, 13) ^
                      SHA256NI_FN(ror)(a, 22);
        uint32_t mj = (a & bb) ^ (a & cc) ^ (bb & cc);
        t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = bb; bb = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += bb; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

/*──────────────────────── x86 SHA-NI block ───────────────────────────────────*/
#ifdef SHA256NI_X86
#include <immintrin.h>
#include <cpuid.h>

__attribute__((target("sha,sse4.1")))
static void SHA256NI_FN(process_x86)(uint32_t state[8], const uint8_t data[], uint32_t length) {
    __m128i STATE0, STATE1, MSG, TMP, MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    TMP   = _mm_loadu_si128((const __m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);
    TMP    = _mm_shuffle_epi32(TMP, 0xB1);
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0);

    while (length >= 64) {
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        /* Rounds 0-3 */
        MSG  = _mm_loadu_si128((const __m128i *)(data + 0));
        MSG0 = _mm_shuffle_epi8(MSG, MASK);
        MSG  = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 4-7 */
        MSG1 = _mm_loadu_si128((const __m128i *)(data + 16));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        MSG  = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 8-11 */
        MSG2 = _mm_loadu_si128((const __m128i *)(data + 32));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        MSG  = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 12-15 */
        MSG3 = _mm_loadu_si128((const __m128i *)(data + 48));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        MSG  = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 16-19 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 20-23 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 24-27 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 28-31 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 32-35 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 36-39 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

        /* Rounds 40-43 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

        /* Rounds 44-47 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0   = _mm_add_epi32(MSG0, TMP);
        MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

        /* Rounds 48-51 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1   = _mm_add_epi32(MSG1, TMP);
        MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
        MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

        /* Rounds 52-55 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2   = _mm_add_epi32(MSG2, TMP);
        MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 56-59 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3   = _mm_add_epi32(MSG3, TMP);
        MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        /* Rounds 60-63 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        MSG    = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        data += 64;
        length -= 64;
    }

    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0);
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

static int SHA256NI_FN(has_sha_ni) = -1;

static int SHA256NI_FN(check_sha_ni)(void) {
#if SHA256NI_FORCE_SOFTWARE
    return 0;
#else
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
        return (ebx & (1u << 29)) != 0;
    return 0;
#endif
}
#endif /* SHA256NI_X86 */

/*──────────────────────── Public API ─────────────────────────────────────────*/
static void SHA256NI_FN(init)(SHA256NI_CTX_TYPE *c) {
    for (int i = 0; i < 8; i++) c->h[i] = SHA256NI_FN(IV)[i];
    c->len = 0;
    c->nbuf = 0;
}

static void SHA256NI_FN(update)(SHA256NI_CTX_TYPE *c, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    c->len += (uint64_t)n;

#ifdef SHA256NI_X86
    if (SHA256NI_FN(has_sha_ni) == -1)
        SHA256NI_FN(has_sha_ni) = SHA256NI_FN(check_sha_ni)();
    if (SHA256NI_FN(has_sha_ni) && c->nbuf == 0 && n >= 64) {
        size_t blocks = n / 64;
        SHA256NI_FN(process_x86)(c->h, p, (uint32_t)(blocks * 64));
        p += blocks * 64;
        n -= blocks * 64;
    }
#endif

    while (n) {
        int t = 64 - c->nbuf;
        if ((int)n < t) t = (int)n;
        memcpy(c->buf + c->nbuf, p, (size_t)t);
        c->nbuf += t;
        p += t;
        n -= (size_t)t;
        if (c->nbuf == 64) {
#ifdef SHA256NI_X86
            if (SHA256NI_FN(has_sha_ni))
                SHA256NI_FN(process_x86)(c->h, c->buf, 64);
            else
#endif
                SHA256NI_FN(block)(c, c->buf);
            c->nbuf = 0;
        }
    }
}

static void SHA256NI_FN(final)(SHA256NI_CTX_TYPE *c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    c->buf[c->nbuf++] = 0x80;
    if (c->nbuf > 56) {
        while (c->nbuf < 64) c->buf[c->nbuf++] = 0;
        SHA256NI_FN(block)(c, c->buf);
        c->nbuf = 0;
    }
    while (c->nbuf < 56) c->buf[c->nbuf++] = 0;
    for (int i = 7; i >= 0; i--)
        c->buf[c->nbuf++] = (uint8_t)(bits >> (i * 8));
    SHA256NI_FN(block)(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

#undef SHA256NI_FN
#undef SHA256NI_CAT
#undef SHA256NI_CAT2

#endif /* SHA256_NI_H */
