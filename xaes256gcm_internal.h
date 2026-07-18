/*
 * Copyright (c) 2026 Dmitry Chestnykh <dmitry@codingrobots.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef XAES256GCM_INTERNAL_H
#define XAES256GCM_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#ifndef NODISCARD
#if defined(__GNUC__) || defined(__clang__)
#define NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
#define NODISCARD _Check_return_
#elif __STDC_VERSION__ >= 202311L
#define NODISCARD [[nodiscard]]
#else
#define NODISCARD
#endif
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_feature(bounds_safety)
#define COUNTED_BY(x) __counted_by(x)
#define SIZED_BY(x)   __sized_by(x)
#else
#define COUNTED_BY(x)
#define SIZED_BY(x)
#endif

/* Initialize AES block cipher (used for key derivation). */
NODISCARD
int xaes256gcm_internal_cipher_init(struct xaes256gcm_internal_cipher *c,
    const uint8_t key[32]);

/* Destroy AES block cipher. */
void xaes256gcm_internal_cipher_destroy(struct xaes256gcm_internal_cipher *c);

/* Encrypt blocks with AES-ECB. */
NODISCARD int
xaes256gcm_internal_encrypt_blocks(struct xaes256gcm_internal_cipher *c,
    const uint8_t *COUNTED_BY(len) in, uint8_t *COUNTED_BY(len) out,
    size_t len);

/* Seal with AES-256-GCM, writing ct || tag into ciphertext */
NODISCARD
int xaes256gcm_internal_gcm_seal(struct xaes256gcm_internal_cipher *c,
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *COUNTED_BY(plaintext_len) plaintext, size_t plaintext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len);

/* Open with AES-256-GCM ciphertext containing ct || tag. */
NODISCARD
int xaes256gcm_internal_gcm_open(struct xaes256gcm_internal_cipher *c,
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *COUNTED_BY(ciphertext_len) ciphertext, size_t ciphertext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(plaintext_max_len) plaintext, size_t plaintext_max_len);

/* Generate random bytes. */
NODISCARD
int xaes256gcm_internal_get_random(uint8_t *COUNTED_BY(len) p, size_t len);

/* Compare bytes in constant time. */
NODISCARD
int xaes256gcm_internal_verify(const uint8_t *COUNTED_BY(len) a,
    const uint8_t *COUNTED_BY(len) b, size_t len);

/* Clear memory. */
void xaes256gcm_internal_wipe(void *SIZED_BY(len) p, size_t len);

#endif /* XAES256GCM_INTERNAL_H */
