/* test_sign.c — exercise sign_finalise_attestation + sign_verify_attestation.
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "sign.h"
#include <crypto/ed25519.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void write_body(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) { perror("fopen"); exit(1); }
    fprintf(f, "basm attestation v2\n");
    fprintf(f, "tool: basm\n");
    fprintf(f, "tool_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n");
    fprintf(f, "source_path: test.basm\n");
    fprintf(f, "source_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n");
    fprintf(f, "output_path: test.o\n");
    fprintf(f, "output_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n");
    fprintf(f, "output_format: elf64\n");
    fprintf(f, "merkle_node_id: 0000000000000000000000000000000000000000000000000000000000000000\n");
    fprintf(f, "signature: unsigned\n");
    fclose(f);
}

int main(void) {
    const char *path = "/tmp/test_sign.basmproof";
    uint8_t seed[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
    };

    write_body(path);

    if (sign_finalise_attestation(path, seed) != 0) {
        printf("FAIL sign_finalise_attestation\n");
        return 1;
    }

    uint8_t pub[32];
    if (sign_verify_attestation(path, pub) != 0) {
        printf("FAIL sign_verify_attestation\n");
        return 1;
    }

    /* Derive the expected public key from the seed to make sure the
     * attestation recorded the key that actually signed it. */
    extern void ed25519_keypair_from_seed(const uint8_t seed[32],
                                          uint8_t pk[ED25519_PUBKEY],
                                          uint8_t sk[ED25519_SECKEY]);
    uint8_t expect_pk[ED25519_PUBKEY];
    uint8_t sk[ED25519_SECKEY];
    ed25519_keypair_from_seed(seed, expect_pk, sk);

    if (memcmp(pub, expect_pk, 32) != 0) {
        printf("FAIL recovered public key mismatch\n");
        return 1;
    }

    printf("PASS sign round-trip\n");
    return 0;
}
