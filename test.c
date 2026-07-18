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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xaes256gcm.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#if __has_feature(bounds_safety)
#define FORGE_BIDI(ptr, count) \
	__unsafe_forge_bidi_indexable(const uint8_t *, (ptr), (count))
#define NULL_TERMINATED __terminated_by(0)
#else
#define FORGE_BIDI(ptr, count) (const uint8_t *)(ptr)
#define NULL_TERMINATED	       /* no-op */
#endif

static void
print_hex(const char *label, const uint8_t *XAES256GCM_COUNTED_BY(len) buf,
    size_t len)
{
	printf("%s: ", label);
	for (size_t i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

static int
decode_hex_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return -1;
}

static int
decode_hex(const char *NULL_TERMINATED hex,
    uint8_t *XAES256GCM_COUNTED_BY(out_len) out, size_t out_len)
{
	if (!out || !hex)
		return -1;
	for (size_t i = 0; i < out_len; i++) {
		int hi = decode_hex_nibble(*hex++);
		if (hi < 0)
			return -1;
		int lo = decode_hex_nibble(*hex++);
		if (lo < 0)
			return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return (*hex == '\0') ? 0 : -1;
}

typedef struct {
	int kc;
	uint8_t key[32];
	uint8_t nonce[24];
	const char *plaintext;
	const char *aad;
	const char *ciphertext_hex;
} TestVector;

// clang-format off
static const TestVector vectors[] = {
    {
        .kc = 0,
        .key = {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        },
        .nonce = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X'},
        .plaintext = "XAES-256-GCM",
        .aad = "",
        .ciphertext_hex = "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271",
    },
    {
        .kc = 0,
        .key = {
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        },
        .nonce = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X'},
        .plaintext = "XAES-256-GCM",
        .aad = "c2sp.org/XAES-256-GCM",
        .ciphertext_hex = "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d",
    },
    {
        .kc = 1, // with key commitment
        .key = {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        },
        .nonce = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X'},
        .plaintext = "XAES-256-GCM",
        .aad = "",
        .ciphertext_hex = "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e227104076b6085"
                          "eebab138855fe57811c04112eff989d44120dfff662d5475a383c3",
    },
};
// clang-format on

static int
test_seal_open(void)
{
	int failed = 0;

	for (size_t i = 0; i < ARRAY_SIZE(vectors); i++) {
		const TestVector *v = &vectors[i];
		const char *suffix = v->kc ? "_kc" : "";
		printf("## Test ctx seal%s/open%s (%zu)\n", suffix, suffix, i);

		size_t pt_len = strlen(v->plaintext);
		size_t aad_len = strlen(v->aad);
		const uint8_t *plaintext = FORGE_BIDI(v->plaintext, pt_len);
		const uint8_t *aad = FORGE_BIDI(v->aad, aad_len);
		size_t ct_len = strlen(v->ciphertext_hex) / 2;
		uint8_t *expected_ct = (uint8_t *)malloc(ct_len);
		decode_hex(v->ciphertext_hex, expected_ct, ct_len);
		uint8_t *ciphertext = (uint8_t *)malloc(ct_len);
		uint8_t *decrypted = (uint8_t *)malloc(pt_len);

		const uint8_t *tag, *expected_tag, *kc, *expected_kc;
		const uint8_t bad_aad[] = "this AAD is fake";
		uint8_t bad_nonce[24];
		uint8_t wrong_key[32];

		struct xaes256gcm_ctx aead;
		if (xaes256gcm_ctx_init(&aead, v->key) != 0) {
			printf("FAIL: init failed");
			goto cleanup;
		}

		int r;

		if (v->kc)
			r = xaes256gcm_ctx_seal_kc(&aead, v->nonce, plaintext,
			    pt_len, aad, aad_len, ciphertext, ct_len);
		else
			r = xaes256gcm_ctx_seal(&aead, v->nonce, plaintext,
			    pt_len, aad, aad_len, ciphertext, ct_len);
		if (r != 0) {
			printf("FAIL: seal returned %d\n", r);
			failed++;
			goto cleanup;
		}

		if (pt_len > 0 &&
		    memcmp(ciphertext, expected_ct, pt_len) != 0) {
			printf("FAIL: ciphertext mismatch\n");
			print_hex("  expected", expected_ct, pt_len);
			print_hex("  got     ", ciphertext, pt_len);
			failed++;
		} else {
			printf("ok ciphertext\n");
		}

		tag = &ciphertext[pt_len];
		expected_tag = &expected_ct[pt_len];

		if (memcmp(tag, expected_tag, 16) != 0) {
			printf("FAIL: tag mismatch\n");
			print_hex("  expected", expected_tag, 16);
			print_hex("  got     ", tag, 16);
			failed++;
		} else {
			printf("ok tag\n");
		}

		if (v->kc) {
			kc = &ciphertext[pt_len + 16];
			expected_kc = &expected_ct[pt_len + 16];
			if (memcmp(kc, expected_kc, 32) != 0) {
				printf("FAIL: key commitment mismatch\n");
				print_hex("  expected", expected_kc, 32);
				print_hex("  got     ", kc, 32);
				failed++;
			} else {
				printf("ok key commitment\n");
			}
		}

		if (v->kc)
			r = xaes256gcm_ctx_open_kc(&aead, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		else
			r = xaes256gcm_ctx_open(&aead, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		if (r != 0) {
			printf("FAIL: open returned %d\n", r);
			failed++;
			goto cleanup;
		}

		if (pt_len > 0 && memcmp(decrypted, plaintext, pt_len) != 0) {
			printf("FAIL: decrypt plaintext mismatch\n");
			failed++;
		} else {
			printf("ok open\n");
		}

		// corrupt tag and verify open is rejected
		ciphertext[pt_len + 1] ^= 1;
		if (v->kc)
			r = xaes256gcm_ctx_open_kc(&aead, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		else
			r = xaes256gcm_ctx_open(&aead, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		if (r == 0) {
			printf("FAIL: bad tag not rejected\n");
			failed++;
		} else {
			printf("ok tag rejection\n");
		}
		// restore original ciphertext
		ciphertext[pt_len + 1] ^= 1;

		if (v->kc) {
			// corrupt key commitment and verify open is rejected
			ciphertext[ct_len - 1] ^= 1;
			if (v->kc)
				r = xaes256gcm_ctx_open_kc(&aead, v->nonce,
				    ciphertext, ct_len, aad, aad_len, decrypted,
				    pt_len);
			else
				r = xaes256gcm_ctx_open(&aead, v->nonce,
				    ciphertext, ct_len, aad, aad_len, decrypted,
				    pt_len);
			if (r == 0) {
				printf(
				    "FAIL: bad key commitment not rejected\n");
				failed++;
			} else {
				printf("ok key commitment rejection\n");
			}

			// restore original ciphertext
			ciphertext[ct_len - 1] ^= 1;
		}

		if (v->kc)
			r = xaes256gcm_ctx_open_kc(&aead, v->nonce, ciphertext,
			    ct_len, bad_aad, sizeof(bad_aad), decrypted,
			    pt_len);
		else
			r = xaes256gcm_ctx_open(&aead, v->nonce, ciphertext,
			    ct_len, bad_aad, sizeof(bad_aad), decrypted,
			    pt_len);
		if (r == 0) {
			printf("FAIL: bad aad not rejected\n");
			failed++;
		} else {
			printf("ok aad rejection\n");
		}

		memcpy(bad_nonce, v->nonce, sizeof(bad_nonce));

		// damage the first half
		bad_nonce[0] ^= 1;
		if (v->kc)
			r = xaes256gcm_ctx_open_kc(&aead, bad_nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		else
			r = xaes256gcm_ctx_open(&aead, bad_nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		if (r == 0) {
			printf("FAIL: bad first half of nonce not rejected\n");
			failed++;
		} else {
			printf("ok nonce rejection (first half)\n");
		}
		// restore and damage the last half
		bad_nonce[0] ^= 1;
		bad_nonce[23] ^= 1;
		if (v->kc)
			r = xaes256gcm_ctx_open_kc(&aead, bad_nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		else
			r = xaes256gcm_ctx_open(&aead, bad_nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		if (r == 0) {
			printf("FAIL: bad second half of nonce not rejected\n");
			failed++;
		} else {
			printf("ok nonce rejection (second half)\n");
		}

		xaes256gcm_ctx_destroy(&aead);

		memset(ciphertext, 0, ct_len);
		memset(decrypted, 0, pt_len);

		// test simple variant
		printf("## Test seal%s/open%s (%zu)\n", suffix,
		    suffix, i);

		if (v->kc)
			r = xaes256gcm_seal_kc(v->key, v->nonce, plaintext,
			    pt_len, aad, aad_len, ciphertext, ct_len);
		else
			r = xaes256gcm_seal(v->key, v->nonce, plaintext, pt_len,
			    aad, aad_len, ciphertext, ct_len);
		if (r != 0) {
			printf("FAIL: simple seal returned %d\n", r);
			failed++;
			goto cleanup;
		}
		if (memcmp(ciphertext, expected_ct, ct_len) != 0) {
			printf("FAIL: simple seal ciphertext mismatch\n");
			print_hex("  expected", expected_ct, ct_len);
			print_hex("  got     ", ciphertext, ct_len);
			failed++;
		} else {
			printf("ok simple seal\n");
		}

		if (v->kc)
			r = xaes256gcm_open_kc(v->key, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		else
			r = xaes256gcm_open(v->key, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		if (r != 0) {
			printf("FAIL: open_simple returned %d\n", r);
			failed++;
			goto cleanup;
		}
		if (memcmp(decrypted, plaintext, pt_len) != 0) {
			printf("FAIL: simple open plaintext mismatch\n");
			print_hex("  expected", plaintext, pt_len);
			print_hex("  got     ", decrypted, pt_len);
			failed++;
		} else {
			printf("ok simple open\n");
		}

		// test opening with a wrong key
		memcpy(wrong_key, v->key, sizeof(wrong_key));
		wrong_key[0] ^= 1;

		if (v->kc)
			r = xaes256gcm_open_kc(wrong_key, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		else
			r = xaes256gcm_open(wrong_key, v->nonce, ciphertext,
			    ct_len, aad, aad_len, decrypted, pt_len);
		if (r == 0) {
			printf("FAIL: opened with a wrong key %d\n", r);
			failed++;
		}

		// test empty aad.
		if (v->kc)
			r = xaes256gcm_seal_kc(v->key, v->nonce, plaintext,
			    pt_len, NULL, 0, ciphertext, ct_len);
		else
			r = xaes256gcm_seal(v->key, v->nonce, plaintext, pt_len,
			    NULL, 0, ciphertext, ct_len);

		if (r != 0) {
			printf("FAIL: failed to seal with null aad\n");
			failed++;
			continue;
		}
		if (v->kc)
			r = xaes256gcm_open_kc(v->key, v->nonce, ciphertext,
			    ct_len, NULL, 0, decrypted, pt_len);
		else
			r = xaes256gcm_open(v->key, v->nonce, ciphertext,
			    ct_len, NULL, 0, decrypted, pt_len);
		if (r != 0) {
			printf("FAIL: failed to open with null aad\n");
			failed++;
		} else {
			printf("ok null aad\n");
		}

		// test empty plaintext.
		if (v->kc)
			r = xaes256gcm_seal_kc(v->key, v->nonce, NULL, 0, NULL,
			    0, ciphertext, XAES256GCM_KC_OVERHEAD);
		else
			r = xaes256gcm_seal(v->key, v->nonce, NULL, 0, NULL, 0,
			    ciphertext, XAES256GCM_OVERHEAD);

		if (r != 0) {
			printf("FAIL: failed to seal null plaintext\n");
			failed++;
			continue;
		}
		if (v->kc)
			r = xaes256gcm_open_kc(v->key, v->nonce, ciphertext,
			    XAES256GCM_KC_OVERHEAD, NULL, 0, decrypted, 0);
		else
			r = xaes256gcm_open(v->key, v->nonce, ciphertext,
			    XAES256GCM_OVERHEAD, NULL, 0, decrypted, 0);
		if (r != 0) {
			printf("FAIL: failed to open null plaintext\n");
			failed++;
		} else {
			printf("ok empty plaintext\n");
		}

	cleanup:
		free(decrypted);
		free(ciphertext);
		free(expected_ct);
	}

	return failed;
}

static int
test_random_nonce()
{
	uint8_t nonce1[XAES256GCM_NONCE_SIZE] = {0};
	uint8_t nonce2[XAES256GCM_NONCE_SIZE] = {0};

	printf("## Test gen_random_nonce\n");

	if (xaes256gcm_rand_nonce(nonce1) != 0) {
		printf("FAIL: cannot generate random nonce");
		return 1;
	}
	if (memcmp(nonce1, nonce2, sizeof(nonce1)) == 0) {
		printf("FAIL: random nonce is all zeros");
		return 1;
	}
	if (memcmp(nonce1, &nonce1[12], 12) == 0) {
		printf(
		    "FAIL: random nonce's halves are equal, very improbable");
		return 1;
	}
	if (xaes256gcm_rand_nonce(nonce2) != 0) {
		printf("FAIL: cannot generate random nonce");
		return 1;
	}
	if (memcmp(nonce1, nonce2, sizeof(nonce1)) == 0) {
		printf("FAIL: two random nonces are equal");
		return 1;
	}
	int ndiff = 0;
	for (size_t i = 0; i < sizeof(nonce1); i++)
		if (nonce1[i] == nonce2[i])
			ndiff++;
	if (ndiff >= 16) {
		printf(
		    "FAIL: two random nonces have 16 common bytes, very improbable");
		return 1;
	}
	printf("ok random nonce\n");
	return 0;
}

int
main(void)
{
	int failed = 0;

	failed += test_seal_open();
	failed += test_random_nonce();

	if (failed == 0) {
		printf("\nAll tests passed.\n");
	} else {
		printf("\n%d test(s) failed.\n", failed);
	}

	return failed != 0;
}
