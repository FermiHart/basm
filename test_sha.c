/* test_sha.c — Known-answer + SHA-NI vs software equivalence tests.
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Software-only SHA-256 (forces the scalar path). */
#define SHA256NI_CTX_TYPE sw_sha_ctx
#define SHA256NI_PREFIX   sw_sha_
#undef SHA256NI_FORCE_SOFTWARE
#define SHA256NI_FORCE_SOFTWARE 1
#include "sha256_ni.h"

/* Hardware-dispatch SHA-256 (uses SHA-NI when CPUID says it is available).
 * Undefine the include guard so the namespace-safe header can be reused. */
#undef SHA256_NI_H
#undef SHA256NI_CTX_TYPE
#undef SHA256NI_PREFIX
#undef SHA256NI_FORCE_SOFTWARE
#define SHA256NI_FORCE_SOFTWARE 0 /* W01: exercise dispatch, not scalar twice. */
#define SHA256NI_CTX_TYPE hw_sha_ctx
#define SHA256NI_PREFIX   hw_sha_
#include "sha256_ni.h"

static int hex_eq(const uint8_t h[32], const char *hex) {
    char got[65];
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        got[i*2]   = H[h[i] >> 4];
        got[i*2+1] = H[h[i] & 15];
    }
    got[64] = 0;
    return strcmp(got, hex) == 0;
}

static int kat(const char *label, const uint8_t *msg, size_t len,
               const char *expect) {
    uint8_t sw[32], hw[32];
    sw_sha_ctx c1; sw_sha_init(&c1);
    sw_sha_update(&c1, msg, len);
    sw_sha_final(&c1, sw);

    hw_sha_ctx c2; hw_sha_init(&c2);
    hw_sha_update(&c2, msg, len);
    hw_sha_final(&c2, hw);

    if (!hex_eq(sw, expect) || !hex_eq(hw, expect)) {
        printf("FAIL %s\n", label);
        return 1;
    }
    if (memcmp(sw, hw, 32) != 0) {
        printf("FAIL %s: SW/HW mismatch\n", label);
        return 1;
    }
    printf("PASS %s\n", label);
    return 0;
}

int main(void) {
    int fail = 0;

    /* NIST SHA-256 KAT vectors. */
    fail |= kat("empty", (const uint8_t *)"", 0,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    fail |= kat("abc", (const uint8_t *)"abc", 3,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const uint8_t *msg2 = (const uint8_t *)
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    fail |= kat("56-byte", msg2, 56,
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /* Multi-block input to exercise the dispatcher loop. */
    uint8_t big[1024];
    for (int i = 0; i < 1024; i++) big[i] = (uint8_t)(i & 0xff);
    fail |= kat("1kib", big, sizeof(big),
                "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9");

#ifdef SHA256NI_X86
    if (hw_sha_has_sha_ni != hw_sha_check_sha_ni()) {
        printf("FAIL runtime SHA selector\n");
        fail = 1;
    }
    printf("SHA-NI exercised: %s\n", hw_sha_has_sha_ni ? "yes" : "no (software fallback)");
#else
    printf("SHA-NI exercised: no (software-only target)\n");
#endif

    return fail ? 1 : 0;
}
