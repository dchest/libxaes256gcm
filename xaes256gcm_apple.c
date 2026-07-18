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

#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

#include <CommonCrypto/CommonRandom.h>

#include "xaes256gcm_apple.h"
#include "xaes256gcm_internal.h"

int
xaes256gcm_internal_cipher_init(struct xaes256gcm_internal_cipher *c,
    const uint8_t key[32])
{
	if (CCCryptorCreateWithMode(kCCEncrypt, kCCModeECB, kCCAlgorithmAES,
		ccNoPadding, NULL, key, kCCKeySizeAES256, NULL, 0, 0, 0,
		&c->cryptor) != kCCSuccess)
		return -1;
	return 0;
}

void
xaes256gcm_internal_cipher_destroy(struct xaes256gcm_internal_cipher *c)
{
	if (!c->cryptor)
		return;
	CCCryptorRelease(c->cryptor);
	c->cryptor = NULL;
}

int
xaes256gcm_internal_encrypt_blocks(struct xaes256gcm_internal_cipher *c,
    const uint8_t *COUNTED_BY(len) in, uint8_t *COUNTED_BY(len) out, size_t len)
{
	size_t moved = 0;
	CCCryptorStatus status = CCCryptorUpdate(c->cryptor, in, len, out, len,
	    &moved);
	if (status != kCCSuccess || moved != len)
		return -1;
	return 0;
}

int
xaes256gcm_internal_get_random(uint8_t *COUNTED_BY(len) p, size_t len)
{
	if (CCRandomGenerateBytes(p, len) != kCCSuccess)
		return -1;
	return 0;
}

int
xaes256gcm_internal_verify(const uint8_t *COUNTED_BY(len) a,
    const uint8_t *COUNTED_BY(len) b, size_t len)
{
	if (timingsafe_bcmp(a, b, len) != 0)
		return -1;
	return 0;
}

void
xaes256gcm_internal_wipe(void *SIZED_BY(len) p, size_t len)
{
	memset_s(p, len, 0, len);
}

/* xaes256gcm_internal_gcm_seal/open are in xaes256gcm_apple_shim.swift */
