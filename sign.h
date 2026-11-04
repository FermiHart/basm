/*
 * Author: F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef BEARLD_SIGN_H
#define BEARLD_SIGN_H

#include <stdint.h>
#include <stddef.h>

#define SIGN_ATTESTATION_MAX_BYTES (16u * 1024u * 1024u)

/* Load a 32-byte signing seed from a key file (raw bytes or 64 hex chars).
 * Returns 0 on success. */
int sign_load_seed(const char *path, uint8_t seed[32]);
/* Public trust anchor, raw32 or hex64; never interpreted as a signing seed. */
int sign_load_public_key(const char *path, uint8_t pub[32]);

/* Sign a bounded, unambiguously framed snapshot. Caller owns *out on success.
 * This performs no pathname I/O. Legacy framing is preserved for v2/v3. */
int sign_attestation_buffer(const char *body, size_t len, const uint8_t seed[32],
                            char **out, size_t *out_len);
/* Validate trailer framing only: -1 malformed, 0 explicitly unsigned, 1 signed.
 * A result of 1 does NOT verify the signature or establish signer trust. */
int sign_attestation_signature_state(const char *body, size_t len);

/* Append an Ed25519-over-SHA256 signature to an existing attestation file.
 * Strips a trailing "signature:" placeholder before signing.  Returns 0
 * on success. */
int sign_finalise_attestation(const char *path, const uint8_t seed[32]);

/* Verify a signed attestation.  Returns 0 if signature valid.
 * If out_pub != NULL, copies the recorded public key into it. */
int sign_verify_attestation(const char *path, uint8_t out_pub[32]);
/* Verify precisely the bytes the caller parsed. expected_pub == NULL checks
 * cryptographic integrity only. A non-NULL external key pins signer identity. */
int sign_verify_attestation_buffer(const char *body, size_t len,
                                   const uint8_t expected_pub[32], uint8_t out_pub[32]);
int sign_verify_attestation_trusted(const char *path, const uint8_t expected_pub[32],
                                    uint8_t out_pub[32]);

/* ADR-0025 (S3 EMBED) — embedded-attestation core digest.
 *
 * Given an ELF file with a .note.soberania PROGBITS section whose payload
 * lives at [payload_off, payload_off + payload_len), compute the SHA-256 of
 * the ELF byte-stream with those payload bytes treated as zero (same length).
 * This breaks the self-hash paradox: the attestation can record a digest
 * that is reproducible by any third party who locates the same section and
 * substitutes zeros.
 *
 * out[32] receives the digest.  Returns 0 on success. */
int sign_core_sha256(const char *elf_path,
                     uint64_t payload_off, uint32_t payload_len,
                     uint8_t out[32]);

/* SHA-256 of a buffer (utility; exposed for keyforge/bearverify reuse). */
void sign_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif
