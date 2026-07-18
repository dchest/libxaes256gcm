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

#include <limits.h>

#define OPENSSL_NO_DEPRECATED
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "xaes256gcm_openssl.h"
#include "xaes256gcm_internal.h"

int
xaes256gcm_internal_cipher_init(struct xaes256gcm_internal_cipher *c,
    const uint8_t key[32])
{
	if (!(c->ectx = EVP_CIPHER_CTX_new()))
		goto err0;
	if (!(c->gctx = EVP_CIPHER_CTX_new()))
		goto err1;
	if (!EVP_EncryptInit_ex(c->ectx, EVP_aes_256_ecb(), NULL, key, NULL))
		goto err2;
	EVP_CIPHER_CTX_set_padding(c->ectx, 0);
	return 0;

err2:
	EVP_CIPHER_CTX_free(c->gctx);
err1:
	EVP_CIPHER_CTX_free(c->ectx);
err0:
	return -1;
}

void
xaes256gcm_internal_cipher_destroy(struct xaes256gcm_internal_cipher *c)
{
	EVP_CIPHER_CTX_free(c->gctx);
	EVP_CIPHER_CTX_free(c->ectx);
	c->ectx = NULL;
	c->gctx = NULL;
}

int
xaes256gcm_internal_encrypt_blocks(struct xaes256gcm_internal_cipher *c,
    const uint8_t *COUNTED_BY(len) in, uint8_t *COUNTED_BY(len) out, size_t len)
{
	int outlen = 0;
	if (!EVP_EncryptUpdate(c->ectx, out, &outlen, in, len) ||
	    (size_t)outlen != len)
		return -1;
	return 0;
}

int
xaes256gcm_internal_gcm_seal(struct xaes256gcm_internal_cipher *c,
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *COUNTED_BY(plaintext_len) plaintext, size_t plaintext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(ciphertext_max_len) ciphertext,
    size_t ciphertext_max_len)
{
	if (ciphertext_max_len < 16 || ciphertext_max_len - 16 < plaintext_len)
		return -1;

	int outlen = 0, tmplen = 0, chunk;
	size_t ivlen = 12, remaining, offset;

	/* If you ever wanted to work at circus, but are stuck at
	 * your programming job, go work with OpenSSL developers on
	 * designing APIs.
	 */
	OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

	if (!EVP_EncryptInit_ex(c->gctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		goto err;

	params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
	    &ivlen);

	if (!EVP_CIPHER_CTX_set_params(c->gctx, params))
		goto err;

	if (!EVP_EncryptInit_ex(c->gctx, NULL, NULL, key, nonce))
		goto err;

	remaining = aad_len;
	offset = 0;
	while (remaining > 0) {
		chunk = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
		if (!EVP_EncryptUpdate(c->gctx, NULL, &tmplen, &aad[offset],
			chunk))
			goto err;
		remaining -= chunk;
		offset += chunk;
	}

	remaining = plaintext_len;
	offset = 0;
	outlen = 0;
	while (remaining > 0) {
		chunk = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
		tmplen = 0;
		if (!EVP_EncryptUpdate(c->gctx, &ciphertext[offset], &tmplen,
			&plaintext[offset], chunk))
			goto err;
		outlen += tmplen;
		remaining -= chunk;
		offset += chunk;
	}

	tmplen = 0;
	if (!EVP_EncryptFinal_ex(c->gctx, &ciphertext[outlen], &tmplen))
		goto err;
	outlen += tmplen;

	params[0] = OSSL_PARAM_construct_octet_string(
	    OSSL_CIPHER_PARAM_AEAD_TAG, &ciphertext[plaintext_len], 16);

	if (!EVP_CIPHER_CTX_get_params(c->gctx, params))
		goto err;

	EVP_CIPHER_CTX_reset(c->gctx);
	return 0;

err:
	EVP_CIPHER_CTX_reset(c->gctx);
	return -1;
}

int
xaes256gcm_internal_gcm_open(struct xaes256gcm_internal_cipher *c,
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *COUNTED_BY(ciphertext_len) ciphertext, size_t ciphertext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(plaintext_max_len) plaintext, size_t plaintext_max_len)
{
	if (ciphertext_len < 16 || plaintext_max_len < ciphertext_len - 16)
		return -1;

	size_t ct_len = ciphertext_len - 16;

	int outlen = 0, tmplen = 0, chunk;
	size_t ivlen = 12, remaining, offset;
	OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

	if (!EVP_DecryptInit_ex(c->gctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		goto err;

	params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
	    &ivlen);
	if (!EVP_CIPHER_CTX_set_params(c->gctx, params))
		goto err;

	if (!EVP_DecryptInit_ex(c->gctx, NULL, NULL, key, nonce))
		goto err;

	params[0] = OSSL_PARAM_construct_octet_string(
	    OSSL_CIPHER_PARAM_AEAD_TAG, (void *)(&ciphertext[ct_len]), 16);

	if (!EVP_CIPHER_CTX_set_params(c->gctx, params))
		goto err;

	remaining = aad_len;
	offset = 0;
	while (remaining > 0) {
		chunk = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
		if (!EVP_DecryptUpdate(c->gctx, NULL, &tmplen, &aad[offset],
			chunk))
			goto err;
		remaining -= chunk;
		offset += chunk;
	}

	remaining = ct_len;
	offset = 0;
	outlen = 0;
	while (remaining > 0) {
		chunk = (remaining > INT_MAX) ? INT_MAX : (int)remaining;
		tmplen = 0;
		if (!EVP_DecryptUpdate(c->gctx, &plaintext[offset], &tmplen,
			&ciphertext[offset], chunk))
			goto err;
		outlen += tmplen;
		remaining -= chunk;
		offset += chunk;
	}

	if (!EVP_DecryptFinal_ex(c->gctx, &plaintext[outlen], &tmplen))
		goto err;

	EVP_CIPHER_CTX_reset(c->gctx);
	return 0;

err:
	EVP_CIPHER_CTX_reset(c->gctx);
	return -1;
}

int
xaes256gcm_internal_get_random(uint8_t *COUNTED_BY(len) p, size_t len)
{
	if (RAND_bytes(p, len) != 1)
		return -1;
	return 0;
}

int
xaes256gcm_internal_verify(const uint8_t *COUNTED_BY(len) a,
    const uint8_t *COUNTED_BY(len) b, size_t len)
{
	if (CRYPTO_memcmp(a, b, len) != 0)
		return -1;
	return 0;
}

void
xaes256gcm_internal_wipe(void *SIZED_BY(len) p, size_t len)
{
	OPENSSL_cleanse(p, len);
}
