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

#ifndef XAES256GCM_H
#define XAES256GCM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Key length.
 */
#define XAES256GCM_KEY_SIZE 32

/**
 * Nonce length.
 */
#define XAES256GCM_NONCE_SIZE 24

/**
 * XAES-256-GCM overhead.
 *
 * The number of bytes the ciphertext is longer than the plaintext,
 * which is the 16-byte authentication tag.
 */
#define XAES256GCM_OVERHEAD 16

/**
 * KC-XAES-256-GCM (key committing variant) overhead.
 *
 * The number of bytes the ciphertext is longer than the plaintext,
 * which is the 16-byte authentication tag and the 32-byte key commitment tag.
 */
#define XAES256GCM_KC_OVERHEAD (XAES256GCM_OVERHEAD + 32)

/**
 * Maximum length of aad.
 *
 * AES-GCM aad limit is 2^64 - 1 bits, which is 2^61 - 1 whole bytes.
 * We're also limited by SIZE_MAX.
 */
#if SIZE_MAX >= UINT64_MAX
#define XAES256GCM_AAD_MAX ((size_t)(((uint64_t)1 << 61) - 1))
#else
#define XAES256GCM_AAD_MAX SIZE_MAX
#endif

/**
 * Maximum length of plaintext.
 *
 * AES-GCM plaintext limit is 2^32 - 2 blocks, which is 2^36 - 32 bytes.
 * We're also limited by SIZE_MAX - XAES256GCM_KC_OVERHEAD.
 */
#if SIZE_MAX >= UINT64_MAX
#define XAES256GCM_PLAINTEXT_MAX ((size_t)(((uint64_t)1 << 36) - 32))
#else
#define XAES256GCM_PLAINTEXT_MAX (SIZE_MAX - XAES256GCM_KC_OVERHEAD)
#endif

/* Include the configured backend. */
#include "xaes256gcm_platform.h"

/* Enforce checking of return values: */
#if defined(__GNUC__) || defined(__clang__)
#define XAES256GCM_NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
#define XAES256GCM_NODISCARD _Check_return_
#elif __STDC_VERSION__ >= 202311L
#define XAES256GCM_NODISCARD [[nodiscard]]
#else
#define XAES256GCM_NODISCARD
#endif

/* Make symbols visible when building shared lib: */
#if defined(_WIN32) || defined(__CYGWIN__)
/* we don't support Windows but just in case */
#define XAES256GCM_EXPORT __declspec(dllexport)
#else
#define XAES256GCM_EXPORT __attribute__((visibility("default")))
#endif

#define XAES256GCM_EXPORT_ND XAES256GCM_EXPORT XAES256GCM_NODISCARD

/* Playing with bounds safety enforcement in clang.
 * It works, but I think ABI is different, so we
 * don't turn it on for the library.
 */
#ifdef __has_feature
#if __has_feature(bounds_safety)
#define XAES256GCM_COUNTED_BY(x) __counted_by(x)
#else
#define XAES256GCM_COUNTED_BY(x) /* no-op */
#endif
#endif

/**
 * struct xaes256gcm_ctx
 *
 * The AEAD context, which contains the crypto backend
 * context and a cached intermediate key.
 *
 * Each seal and open operation is semantically independent,
 * but not guaranteed to be thread-safe.
 *
 * Must be initialized with xaes256gcm_ctx_init()
 * and destroyed with xaes256gcm_ctx_destroy().
 */
struct xaes256gcm_ctx {
	struct xaes256gcm_internal_cipher cipher;
	uint8_t k1[16];
};

/**
 * xaes256gcm_ctx_init(c, key)
 *
 * Initialize the AEAD context with the 32-byte secret key.
 *
 * Every context initialized with xaes256gcm_ctx_init() must be disposed of
 * with xaes256gcm_ctx_destroy().
 *
 * Returns 0 on success, nonzero on error.
 * An error indicates that the underlying crypto backend failed to initialize.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_ctx_init(struct xaes256gcm_ctx *c, const uint8_t key[32]);

/**
 * xaes256gcm_ctx_destroy(c)
 *
 * Dispose of the AEAD context.
 */
XAES256GCM_EXPORT
void xaes256gcm_ctx_destroy(struct xaes256gcm_ctx *c);

/**
 * xaes256gcm_ctx_seal(c, nonce, plaintext, plaintext_len,
 *                 aad, add_len, ciphertext, ciphertext_max_len)
 *
 * Encrypt and authenticate the plaintext, authenticate the optional additional
 * data and write the result to ciphertext. The ciphertext_max_len indicates
 * the space available for the result, which must be at least plaintext_len +
 * XAES256GCM_OVERHEAD.
 *
 * The nonce must be unique for this key. It doesn't need to be random
 * or unpredictable, however random nonces are allowed.
 * Reusing a nonce compromises privacy and authenticity.
 *
 * Returns 0 on success, nonzero on error.
 * An error indicates that the underlying crypto backend failed to encrypt, or
 * the input bounds are not satisfied. On error, the state of the resulting
 * ciphertext is undefined.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_ctx_seal(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(plaintext_len) plaintext,
    size_t plaintext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len,
    uint8_t *XAES256GCM_COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len);

/**
 * xeas256gcm_open(c, nonce, ciphertext, ciphertext_len,
 *                 aad, aad_len, plaintext, plaintext_max_len)
 *
 * Verify authentication tag in the ciphertext and decrypt ciphertext. The
 * plaintext_max_len indicates the space avilable for the result, which must be
 * at least ciphertext_len - XAES256GCM_OVERHEAD.
 *
 * The nonce and additional data must be the same as given to the seal function.
 *
 * Returns 0 on success, nonzero on error.
 * An error indicates that the underlying crypto backend failed to decrypt, the
 * input bounds are not satisfied, or ciphertext authentication failed. On
 * error, the resulting plaintext is undefined and may be overwritten with
 * zeros, but will not contain partially decrypted data if authentication
 * fails.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_ctx_open(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(ciphertext_len) ciphertext,
    size_t ciphertext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len, uint8_t *XAES256GCM_COUNTED_BY(plaintext_max_len) plaintext,
    size_t plaintext_max_len);

/**
 * xaes256gcm_ctx_seal_kc(c, nonce, plaintext, plaintext_len,
 *                    aad, add_len, ciphertext, ciphertext_max_len)
 *
 * Encrypt and authenticate the plaintext, authenticate the optional additional
 * data, calculate key commitment, and write the result to ciphertext. The
 * ciphertext_max_len indicates the space available for the result, which must
 * be at least plaintext_len + XAES256GCM_KC_OVERHEAD.
 *
 * The nonce must be unique for this key. It doesn't need to be random
 * or unpredictable, however random nonces are allowed.
 * Reusing a nonce compromises privacy and authenticity.
 *
 * Returns 0 on success, nonzero on error.
 * An error indicates that the underlying crypto backend failed to encrypt, or
 * the input bounds are not satisfied. On error, the state of the resulting
 * ciphertext is undefined.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_ctx_seal_kc(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(plaintext_len) plaintext,
    size_t plaintext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len,
    uint8_t *XAES256GCM_COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len);

/**
 * xeas256gcm_kc_open(c, nonce, ciphertext, ciphertext_len,
 *                    aad, aad_len, plaintext, plaintext_max_len)
 *
 * Verify key commitment and authentication tag in the ciphertext and decrypt
 * the ciphertext. The plaintext_max_len indicates the space avilable for the
 * result, which must be at least ciphertext_len - XAES256GCM_KC_OVERHEAD.
 *
 * The nonce and additional data must be the same as given to the seal function.
 *
 * Returns 0 on success, nonzero on error.
 * An error indicates that the underlying crypto backend failed to decrypt, the
 * input bounds are not satisfied, or key commitment or ciphertext
 * authentication failed. On error, the resulting plaintext is undefined and
 * may be overwritten with zeros, but will not contain partially decrypted data
 * if authentication fails.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_ctx_open_kc(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(ciphertext_len) ciphertext,
    size_t ciphertext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len, uint8_t *XAES256GCM_COUNTED_BY(plaintext_max_len) plaintext,
    size_t plaintext_max_len);

/**
 * xaes256_gcm_seal_simple(key, nonce, plaintext, plaintext_len,
 *                         aad, aad_len, ciphertext, ciphertext_max_len)
 *
 * Same as xaes256gcm_ctx_init() followed by xaes256gcm_ctx_seal(),
 * followed by xaes256gcm_ctx_destroy().
 *
 * Returns 0 on success, nonzero on error.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_seal(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(plaintext_len) plaintext,
    size_t plaintext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len,
    uint8_t *XAES256GCM_COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len);

/**
 * xaes256_gcm_open_simple(key, nonce, ciphertext, ciphertext_len,
 *                         aad, aad_len, plaintext, plaintext_max_len)
 *
 * Same as xaes256gcm_ctx_init() followed by xaes256gcm_ctx_open(),
 * followed by xaes256gcm_ctx_destroy().
 *
 * Returns 0 on success, nonzero on error.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_open(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(ciphertext_len) ciphertext,
    size_t ciphertext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len, uint8_t *XAES256GCM_COUNTED_BY(plaintext_max_len) plaintext,
    size_t plaintext_max_len);

/**
 * xaes256_gcm_kc_seal_simple(key, nonce, plaintext, plaintext_len,
 *                         aad, aad_len, ciphertext, ciphertext_len)
 *
 * Same as xaes256gcm_ctx_init() followed by xaes256gcm_ctx_seal_kc(),
 * followed by xaes256gcm_ctx_destroy().
 *
 * Returns 0 on success, nonzero on error.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_seal_kc(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(plaintext_len) plaintext,
    size_t plaintext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len,
    uint8_t *XAES256GCM_COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len);

/**
 * xaes256_gcm_kc_open_simple(key, nonce, ciphertext, ciphertext_len,
 *                         aad, aad_len, plaintext, plaintext_max_len)
 *
 * Same as xaes256gcm_ctx_init() followed by xaes256gcm_ctx_open_kc(),
 * followed by xaes256gcm_ctx_destroy().
 *
 * Returns 0 on success, nonzero on error.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_open_kc(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *XAES256GCM_COUNTED_BY(ciphertext_len) ciphertext,
    size_t ciphertext_len, const uint8_t *XAES256GCM_COUNTED_BY(aad_len) aad,
    size_t aad_len, uint8_t *XAES256GCM_COUNTED_BY(plaintext_max_len) plaintext,
    size_t plaintext_max_len);

/**
 * xaes256gcm_rand_nonce(nonce)
 *
 * Generate a random nonce.
 *
 * Returns 0 on success, nonzero on error.
 * An error indicates that the underlying crypto backend failed to generate
 * random bytes, and the contents of the nonce is undefined.
 */
XAES256GCM_EXPORT_ND
int xaes256gcm_rand_nonce(uint8_t nonce[24]);

#ifdef __cplusplus
}
#endif

#endif /* XAES256GCM_H */
