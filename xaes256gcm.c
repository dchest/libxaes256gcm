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

#include <string.h>

#include "xaes256gcm.h"
#include "xaes256gcm_internal.h"

#define wipe(p, n) xaes256gcm_internal_wipe(p, n)

static inline int
encrypt_blocks(struct xaes256gcm_ctx *c, const uint8_t *COUNTED_BY(len) in,
    uint8_t *COUNTED_BY(len) out, size_t len)
{
	return xaes256gcm_internal_encrypt_blocks(&c->cipher, in, out, len);
}

/**
 * compute_k1 calculates k1 for CMAC.
 */
static int
compute_k1(struct xaes256gcm_ctx *c)
{
	const uint8_t zero[16] = {0};
	uint8_t block[16];

	if (encrypt_blocks(c, zero, block, sizeof(block)) != 0)
		return -1;

	uint8_t msb = block[0] >> 7;
	for (int i = 0; i < 15; i++) {
		c->k1[i] = (uint8_t)((block[i] << 1) | (block[i + 1] >> 7));
	}
	c->k1[15] = (uint8_t)(block[15] << 1) ^ ((0u - msb) & 0x87);

	wipe(block, sizeof(block));
	return 0;
}

int
xaes256gcm_ctx_init(struct xaes256gcm_ctx *c, const uint8_t key[32])
{
	if (xaes256gcm_internal_cipher_init(&c->cipher, key) != 0)
		return -1;

	if (compute_k1(c) != 0) {
		xaes256gcm_internal_cipher_destroy(&c->cipher);
		return -1;
	}

	return 0;
}

void
xaes256gcm_ctx_destroy(struct xaes256gcm_ctx *c)
{
	wipe(c->k1, sizeof(c->k1));
	xaes256gcm_internal_cipher_destroy(&c->cipher);
}

static inline void
bxor(uint8_t *COUNTED_BY(len) dst, const uint8_t *COUNTED_BY(len) a,
    const uint8_t *COUNTED_BY(len) b, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = a[i] ^ b[i];
}

/**
 * derive_subkey derives an AES-GCM key from the context's key
 * and part of the nonce. It implements:
 *
 * subkey =
 *      CMAC(0x0001||'X'||0x00||nonce[:12]) ||
 *      CMAC(0x0002||'X'||0x00||nonce[:12])
 *
 * using the backend's AES-ECB for performance.
 *
 * The actual CMAC, if it was available in the backend, would derive
 * the second CMAC key (k2) and have other unnecessary logic, which
 * we don't need, because we only use full blocks.
 *
 * It can also be described as a KDF in counter mode from
 * NIST SP 800-108r1 using CMAC as PRF:
 *
 * subkey =
 *      KDF(i||Label='X'||0x00||Context=nonce[:12])
 *
 */
static int
derive_subkey(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    uint8_t subkey[32])
{
	// clang-format off
	uint8_t blocks[32] = {
		0, 1, 'X', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 2, 'X', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};
	// clang-format on

	memcpy(&blocks[4], nonce, 12);
	memcpy(&blocks[16 + 4], nonce, 12);

	bxor(blocks, blocks, c->k1, 16);
	bxor(&blocks[16], &blocks[16], c->k1, 16);

	if (encrypt_blocks(c, blocks, subkey, sizeof(blocks)) != 0)
		goto err;

	wipe(blocks, sizeof(blocks));
	return 0;

err:
	wipe(blocks, sizeof(blocks));
	return -1;
}

/**
 * derive_kc derives a 32-byte key commitment from the context's key
 * and nonce. It implements:
 *
 * kc =
 * 	CMAC("XCMT"||nonce||0x00010001) ||
 * 	CMAC("XCMT"||nonce||0x00010002)
 */
static int
derive_kc(struct xaes256gcm_ctx *c, const uint8_t nonce[24], uint8_t kc[32])
{
	/*
	 * The first common block with nonce[:12] at the end.
	 */
	uint8_t first[16] = {'X', 'C', 'M', 'T'};
	memcpy(&first[4], nonce, 12);

	/* Two final blocks computed independently.
	 * Each have nonce[12:] at the start.
	 */
	// clang-format off
	uint8_t	last[32] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2,
	};
	// clang-format on
	memcpy(last, &nonce[12], 12);
	memcpy(&last[16], &nonce[12], 12);

	/* Temporary space for the first processed block. */
	uint8_t x1[16];

	if (encrypt_blocks(c, first, x1, sizeof(first)) != 0)
		goto err;

	bxor(x1, x1, c->k1, 16);
	bxor(last, last, x1, 16);
	bxor(&last[16], &last[16], x1, 16);

	if (encrypt_blocks(c, last, kc, sizeof(last)) != 0)
		goto err;

	wipe(x1, sizeof(x1));
	wipe(last, sizeof(last));
	wipe(first, sizeof(first));
	return 0;

err:
	wipe(x1, sizeof(x1));
	wipe(last, sizeof(last));
	wipe(first, sizeof(first));
	wipe(kc, 32);
	return -1;
}

int
xaes256gcm_ctx_seal(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(plaintext_len) plaintext, size_t plaintext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len)
{
	uint8_t subkey[32];
	const uint8_t *subnonce = &nonce[12];

	if (plaintext_len > XAES256GCM_PLAINTEXT_MAX ||
	    aad_len > XAES256GCM_AAD_MAX)
		return -1;

	if (ciphertext_max_len < XAES256GCM_OVERHEAD ||
	    (ciphertext_max_len - XAES256GCM_OVERHEAD) < plaintext_len)
		return -1;

	if (derive_subkey(c, nonce, subkey) != 0)
		goto err;

	if (xaes256gcm_internal_gcm_seal(&c->cipher, subkey, subnonce,
		plaintext, plaintext_len, aad, aad_len, ciphertext,
		ciphertext_max_len) != 0)
		goto err;

	wipe(subkey, sizeof(subkey));
	return 0;

err:
	wipe(subkey, sizeof(subkey));
	return -1;
}

int
xaes256gcm_ctx_seal_kc(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(plaintext_len) plaintext, size_t plaintext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len)
{
	if (ciphertext_max_len < XAES256GCM_KC_OVERHEAD ||
	    (ciphertext_max_len - XAES256GCM_KC_OVERHEAD) < plaintext_len)
		return -1;

	if (xaes256gcm_ctx_seal(c, nonce, plaintext, plaintext_len, aad,
		aad_len, ciphertext, ciphertext_max_len) != 0)
		return -1;

	size_t kc_pos = plaintext_len + XAES256GCM_OVERHEAD;
	if (derive_kc(c, nonce, &ciphertext[kc_pos]) != 0) {
		wipe(ciphertext, kc_pos);
		return -1;
	}
	return 0;
}

int
xaes256gcm_ctx_open(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(ciphertext_len) ciphertext, size_t ciphertext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(plaintext_max_len) plaintext, size_t plaintext_max_len)
{
	uint8_t subkey[32];
	const uint8_t *subnonce = &nonce[12];

	if (ciphertext_len < XAES256GCM_OVERHEAD ||
	    plaintext_max_len < ciphertext_len - XAES256GCM_OVERHEAD)
		goto err0;

	if (ciphertext_len - XAES256GCM_OVERHEAD > XAES256GCM_PLAINTEXT_MAX ||
	    aad_len > XAES256GCM_AAD_MAX)
		goto err0;

	if (derive_subkey(c, nonce, subkey) != 0)
		goto err0;

	if (xaes256gcm_internal_gcm_open(&c->cipher, subkey, subnonce,
		ciphertext, ciphertext_len, aad, aad_len, plaintext,
		plaintext_max_len) != 0)
		goto err1;

	wipe(subkey, sizeof(subkey));
	return 0;

err1:
	wipe(subkey, sizeof(subkey));
err0:
	/* Prevent release of unverified plaintext
	 * if the backend implementation leaves it there
	 * and the caller doesn't check the result.
	 */
	memset(plaintext, 0, plaintext_max_len);
	return -1;
}

int
xaes256gcm_ctx_open_kc(struct xaes256gcm_ctx *c, const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(ciphertext_len) ciphertext, size_t ciphertext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(plaintext_max_len) plaintext, size_t plaintext_max_len)
{
	uint8_t kc[32];

	if (ciphertext_len < XAES256GCM_KC_OVERHEAD ||
	    plaintext_max_len < ciphertext_len - XAES256GCM_KC_OVERHEAD)
		return -1;

	if (ciphertext_len - XAES256GCM_KC_OVERHEAD >
		XAES256GCM_PLAINTEXT_MAX ||
	    aad_len > XAES256GCM_AAD_MAX)
		return -1;

	if (derive_kc(c, nonce, kc) != 0)
		return -1;

	if (xaes256gcm_internal_verify(kc,
		&ciphertext[ciphertext_len - sizeof(kc)], sizeof(kc)) != 0)
		goto err;

	if (xaes256gcm_ctx_open(c, nonce, ciphertext,
		ciphertext_len - sizeof(kc), aad, aad_len, plaintext,
		plaintext_max_len) != 0)
		goto err;

	wipe(kc, sizeof(kc));
	return 0;

err:
	wipe(kc, sizeof(kc));
	return -1;
}

int
xaes256gcm_seal(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(plaintext_len) plaintext, size_t plaintext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len)
{
	struct xaes256gcm_ctx c;

	if (xaes256gcm_ctx_init(&c, key) != 0)
		return -1;

	int ret = xaes256gcm_ctx_seal(&c, nonce, plaintext, plaintext_len, aad,
	    aad_len, ciphertext, ciphertext_max_len);

	xaes256gcm_ctx_destroy(&c);
	return ret;
}

int
xaes256gcm_open(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(ciphertext_len) ciphertext, size_t ciphertext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(plaintext_max_len) plaintext, size_t plaintext_max_len)
{
	struct xaes256gcm_ctx c;

	if (xaes256gcm_ctx_init(&c, key) != 0)
		return -1;

	int ret = xaes256gcm_ctx_open(&c, nonce, ciphertext, ciphertext_len,
	    aad, aad_len, plaintext, plaintext_max_len);

	xaes256gcm_ctx_destroy(&c);
	return ret;
}

int
xaes256gcm_seal_kc(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(plaintext_len) plaintext, size_t plaintext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len)
{
	struct xaes256gcm_ctx c;

	if (xaes256gcm_ctx_init(&c, key) != 0)
		return -1;

	int ret = xaes256gcm_ctx_seal_kc(&c, nonce, plaintext, plaintext_len,
	    aad, aad_len, ciphertext, ciphertext_max_len);

	xaes256gcm_ctx_destroy(&c);
	return ret;
}

int
xaes256gcm_open_kc(const uint8_t key[32], const uint8_t nonce[24],
    const uint8_t *COUNTED_BY(ciphertext_len) ciphertext, size_t ciphertext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(plaintext_max_len) plaintext, size_t plaintext_max_len)
{
	struct xaes256gcm_ctx c;

	if (xaes256gcm_ctx_init(&c, key) != 0)
		return -1;

	int ret = xaes256gcm_ctx_open_kc(&c, nonce, ciphertext, ciphertext_len,
	    aad, aad_len, plaintext, plaintext_max_len);

	xaes256gcm_ctx_destroy(&c);
	return ret;
}

int
xaes256gcm_rand_nonce(uint8_t nonce[24])
{
	return xaes256gcm_internal_get_random(nonce, XAES256GCM_NONCE_SIZE);
}
