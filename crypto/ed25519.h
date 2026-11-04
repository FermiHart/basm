/* ed25519.h — Ed25519 (RFC 8032) + SHA-512, public API (portable)
 *
 * INV-275 (ADR-0100 Crypto Sovereign Tree): this is the ONE canonical
 * Ed25519 header for every Beyond domain — kernel ring0, surfaces/blibc,
 * surfaces/init/jash, toolchain and tools/testify. The hostiled auditor's
 * cc, the freestanding bear, the kernel cc and blibc all see the same
 * portable header: only `<stdint.h>` is required, present in every
 * consumer.
 *
 * `ED25519_MAX_MSG` is unified at 4096 — the worst case any domain
 * exercises (jash JEF bodies/PAE up to ~2560 bytes, per JINV-014).
 * Kernel callers sign digest-sized blobs (≤32 bytes), so 4096 is never
 * on the hot path; the `buf[64 + ED25519_MAX_MSG]` stack budget (~4 KiB)
 * fits cleanly in the 16 KiB kernel stack.
 *
 * B E Y O N D — sealed by S I G I L
 * Lineage: TweetNaCl v20140427 (public domain) → SigilOS
 * kernel/ring3/crypto/ed25519.c → Beyond (SIGIL-1).
 * TweetNaCl authors: Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen,
 * Tanja Lange, Peter Schwabe and Sjaak Smetsers.
 * Doutrina (Docs/SIGIL-MERGE.md §5): matemática de campo NUNCA é reescrita;
 * soberania em cripto = linhagem declarada + KAT no boot + drift-guard.
 *
 * Author of the Beyond/Basm interface, adaptations and maintenance:
 * F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-FileCopyrightText: 2026 F E R M I ∞ H A R T <contact@fermihart.com>
 * SPDX-License-Identifier: BSD-3-Clause AND LicenseRef-TweetNaCl-Public-Domain
 *
 * The copyright notice and BSD-3-Clause terms cover the Beyond/Basm
 * interface, adaptations and maintenance only. Original TweetNaCl code
 * remains public domain; its lineage is retained above and its declaration
 * is preserved in LICENSES/LicenseRef-TweetNaCl-Public-Domain.txt.
 */
#ifndef BEYOND_CRYPTO_ED25519_H
#define BEYOND_CRYPTO_ED25519_H

#ifndef BEYOND_TYPES_H /* INV-275: kernel types already own these names. */
#include <stdint.h>
#endif

#define ED25519_SEED    32
#define ED25519_PUBKEY  32
#define ED25519_SECKEY  64   /* seed || pubkey */
#define ED25519_SIG     64
#define ED25519_MAX_MSG 4096 /* INV-275: unified across domains; JINV-014 worst case */

/* SHA-512 (FIPS 180-4), the RFC 8032 inner hash. Exported for reuse. */
void sha512(const void *data, uint32_t len, uint8_t out[64]);

void ed25519_keypair_from_seed(const uint8_t seed[ED25519_SEED],
                               uint8_t pk[ED25519_PUBKEY],
                               uint8_t sk[ED25519_SECKEY]);

int  ed25519_sign(uint8_t sig[ED25519_SIG],
                  const uint8_t *msg, uint32_t len,
                  const uint8_t sk[ED25519_SECKEY]);

int  ed25519_verify(const uint8_t sig[ED25519_SIG],
                   const uint8_t *msg, uint32_t len,
                   const uint8_t pk[ED25519_PUBKEY]);

/* ─── Ed25519 group arithmetic (for Pedersen commitments / HAP) ─────── */

/* Extended point representation: (X, Y, Z, T) in projective coordinates. */
typedef int64_t ed25519_gf[16];
typedef ed25519_gf ed25519_extpoint[4];

/* Multiply the Ed25519 base point g by a 32-byte scalar.
 * Result stored as compressed point (32 bytes). */
void ed25519_scalarbase(const uint8_t scalar[32], uint8_t point_out[32]);

/* Multiply an arbitrary point (32-byte compressed) by a 32-byte scalar.
 * Result stored as compressed point (32 bytes). */
void ed25519_scalarmult(uint8_t point_out[32],
                        const uint8_t point_in[32],
                        const uint8_t scalar[32]);

/* Add two compressed Ed2559 points.
 * Result stored as compressed point (32 bytes).
 * Returns 0 on success, -1 if either point is invalid. */
int  ed25519_point_add(uint8_t result[32],
                       const uint8_t p1[32], const uint8_t p2[32]);

/* Known-Answer Test — RFC 8032 §7.1 Test 1 (pk derivation + deterministic
 * signature + verify) MAIS prova-o-negativo (assinatura corrompida DEVE
 * falhar). Retorna 0 = pass; negativo identifica o estágio que falhou.
 * Chamado no boot gate e na bateria GATE-2. */
int  ed25519_kat(void);

#endif /* BEYOND_CRYPTO_ED25519_H */
