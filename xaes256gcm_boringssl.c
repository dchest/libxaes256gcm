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

#include <openssl/aead.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "xaes256gcm_boringssl.h"
#include "xaes256gcm_internal.h"

int
xaes256gcm_internal_cipher_init(struct xaes256gcm_internal_cipher *c,
    const uint8_t key[32])
{
	EVP_CIPHER_CTX_init(&c->ectx);
	if (!EVP_EncryptInit_ex(&c->ectx, EVP_aes_256_ecb(), NULL, key, NULL)) {
		EVP_CIPHER_CTX_cleanup(&c->ectx);
		return -1;
	}
	EVP_CIPHER_CTX_set_padding(&c->ectx, 0);
	return 0;
}

void
xaes256gcm_internal_cipher_destroy(struct xaes256gcm_internal_cipher *c)
{
	EVP_CIPHER_CTX_cleanup(&c->ectx);
}

int
xaes256gcm_internal_encrypt_blocks(struct xaes256gcm_internal_cipher *c,
    const uint8_t *COUNTED_BY(len) in, uint8_t *COUNTED_BY(len) out, size_t len)
{
	size_t outlen = 0;
	if (!EVP_EncryptUpdate_ex((EVP_CIPHER_CTX *)&c->ectx, out, &outlen, len,
		in, len) ||
	    outlen != len)
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
	const EVP_AEAD *aead = EVP_aead_aes_256_gcm();

	size_t outlen = 0;

	if (!EVP_AEAD_CTX_init(&c->gctx, aead, key, EVP_AEAD_key_length(aead),
		EVP_AEAD_DEFAULT_TAG_LENGTH, NULL))
		goto err;

	if (!EVP_AEAD_CTX_seal(&c->gctx, ciphertext, &outlen,
		ciphertext_max_len, nonce, EVP_AEAD_nonce_length(aead),
		plaintext, plaintext_len, aad, aad_len))
		goto err;

	EVP_AEAD_CTX_cleanup(&c->gctx);
	return 0;

err:
	EVP_AEAD_CTX_cleanup(&c->gctx);
	return -1;
}

int
xaes256gcm_internal_gcm_open(struct xaes256gcm_internal_cipher *c,
    const uint8_t *key, const uint8_t *nonce,
    const uint8_t *COUNTED_BY(ciphertext_len) ciphertext, size_t ciphertext_len,
    const uint8_t *COUNTED_BY(aad_len) aad, size_t aad_len,
    uint8_t *COUNTED_BY(plaintext_max_len) plaintext, size_t plaintext_max_len)
{
	if (ciphertext_len < 16)
		return -1;

	const EVP_AEAD *aead = EVP_aead_aes_256_gcm();

	size_t outlen = 0;

	if (!EVP_AEAD_CTX_init(&c->gctx, aead, key, EVP_AEAD_key_length(aead),
		EVP_AEAD_DEFAULT_TAG_LENGTH, NULL))
		goto err;

	if (!EVP_AEAD_CTX_open(&c->gctx, plaintext, &outlen, plaintext_max_len,
		nonce, EVP_AEAD_nonce_length(aead), ciphertext, ciphertext_len,
		aad, aad_len))
		goto err;

	EVP_AEAD_CTX_cleanup(&c->gctx);
	return 0;

err:
	EVP_AEAD_CTX_cleanup(&c->gctx);
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
