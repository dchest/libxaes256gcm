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

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xaes256gcm.h"

#define BIG_ITERATIONS	 1000
#define ITERATIONS	 10000
#define SMALL_ITERATIONS 50000

static struct timespec
bench_start(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t;
}

static void
bench_end(struct timespec start, const char *label, size_t size, int iters)
{
	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);
	double elapsed = (double)(end.tv_sec - start.tv_sec) +
	    (double)(end.tv_nsec - start.tv_nsec) / 1e9;
	double bps = ((double)iters * (double)size) / elapsed;
	const char *units[] = {"B/s", "KiB/s", "MiB/s"};
	int unit = 0;
	double b = bps;
	while (b >= 1024 && unit < 2) {
		b /= 1024;
		unit++;
	}
	if (strcmp(label, "silent") != 0)
		printf("  %-8s: %12.1f %s  (%d iters, %.3f s)\n", label, b,
		    units[unit], iters, elapsed);
}

static void
benchmark_seal(const char *label, size_t size, int iterations)
{
	uint8_t key[32] = {0}, nonce[24] = {0};
	uint8_t *pt = (uint8_t *)calloc(size, 1);
	uint8_t *ct = (uint8_t *)malloc(size + XAES256GCM_OVERHEAD);
	struct xaes256gcm_ctx a;
	struct timespec t;

	if (xaes256gcm_ctx_init(&a, key) != 0) {
		free(pt);
		free(ct);
		return;
	}
	t = bench_start();
	for (int i = 0; i < iterations; i++)
		if (xaes256gcm_ctx_seal(&a, nonce, pt, size, NULL, 0, ct,
			size + XAES256GCM_OVERHEAD) != 0) {
			abort();
		}
	bench_end(t, label, size, iterations);
	xaes256gcm_ctx_destroy(&a);
	free(pt);
	free(ct);
}

static void
benchmark_seal_simple(const char *label, size_t size, int iterations)
{
	uint8_t key[32] = {0}, nonce[24] = {0};
	uint8_t *pt = (uint8_t *)calloc(size, 1);
	uint8_t *ct = (uint8_t *)malloc(size + XAES256GCM_OVERHEAD);
	struct timespec t;

	t = bench_start();
	for (int i = 0; i < iterations; i++)
		if (xaes256gcm_seal(key, nonce, pt, size, NULL, 0, ct,
			size + XAES256GCM_OVERHEAD) != 0) {
			abort();
		}
	bench_end(t, label, size, iterations);
	free(pt);
	free(ct);
}

static void
benchmark_seal_kc(const char *label, size_t size, int iterations)
{
	uint8_t key[32] = {0}, nonce[24] = {0};
	uint8_t *pt = (uint8_t *)calloc(size, 1);
	uint8_t *ct = (uint8_t *)malloc(size + XAES256GCM_KC_OVERHEAD);
	struct xaes256gcm_ctx a;
	struct timespec t;

	if (xaes256gcm_ctx_init(&a, key) != 0) {
		free(pt);
		free(ct);
		return;
	}
	t = bench_start();
	for (int i = 0; i < iterations; i++)
		if (xaes256gcm_ctx_seal_kc(&a, nonce, pt, size, NULL, 0, ct,
			size + XAES256GCM_KC_OVERHEAD) != 0) {
			abort();
		}
	bench_end(t, label, size, iterations);
	xaes256gcm_ctx_destroy(&a);
	free(pt);
	free(ct);
}

static void
benchmark_seal_kc_simple(const char *label, size_t size, int iterations)
{
	uint8_t key[32] = {0}, nonce[24] = {0};
	uint8_t *pt = (uint8_t *)calloc(size, 1);
	uint8_t *ct = (uint8_t *)malloc(size + XAES256GCM_KC_OVERHEAD);
	struct timespec t;

	t = bench_start();
	for (int i = 0; i < iterations; i++)
		if (xaes256gcm_seal_kc(key, nonce, pt, size, NULL, 0, ct,
			size + XAES256GCM_KC_OVERHEAD) != 0) {
			abort();
		}
	bench_end(t, label, size, iterations);
	free(pt);
	free(ct);
}

int
main(void)
{
	benchmark_seal("silent", 8 * 1024, ITERATIONS); /* warmup */

	printf("XAES-256-GCM seal benchmark\n");
	printf("===========================\n\n");

	benchmark_seal("128 B", 128, SMALL_ITERATIONS);
	benchmark_seal("1 KiB", 1024, SMALL_ITERATIONS);
	benchmark_seal("8 KiB", 8 * 1024, ITERATIONS);
	benchmark_seal("16 KiB", 16 * 1024, ITERATIONS);
	benchmark_seal("1 MiB", 1024 * 1024, 1000);

	benchmark_seal_simple("silent", 8 * 1024, ITERATIONS); /* warmup */

	printf("\nXAES-256-GCM seal_simple benchmark\n");
	printf("=====================================\n\n");

	benchmark_seal_simple("128 B", 128, SMALL_ITERATIONS);
	benchmark_seal_simple("1 KiB", 1024, SMALL_ITERATIONS);
	benchmark_seal_simple("8 KiB", 8 * 1024, ITERATIONS);
	benchmark_seal_simple("16 KiB", 16 * 1024, ITERATIONS);
	benchmark_seal_simple("1 MiB", 1024 * 1024, BIG_ITERATIONS);

	benchmark_seal_kc("silent", 8 * 1024, ITERATIONS); /* warmup */

	printf("\nKC-XAES-256-GCM kc_seal benchmark\n");
	printf("===================================\n\n");

	benchmark_seal_kc("128 B", 128, SMALL_ITERATIONS);
	benchmark_seal_kc("1 KiB", 1024, SMALL_ITERATIONS);
	benchmark_seal_kc("8 KiB", 8 * 1024, ITERATIONS);
	benchmark_seal_kc("16 KiB", 16 * 1024, ITERATIONS);
	benchmark_seal_kc("1 MiB", 1024 * 1024, BIG_ITERATIONS);

	benchmark_seal_kc_simple("silent", 8 * 1024, ITERATIONS); /* warmup */

	printf("\nKC-XAES-256-GCM kc_seal_simple benchmark\n");
	printf("===========================================\n\n");

	benchmark_seal_kc_simple("128 B", 128, SMALL_ITERATIONS);
	benchmark_seal_kc_simple("1 KiB", 1024, SMALL_ITERATIONS);
	benchmark_seal_kc_simple("8 KiB", 8 * 1024, ITERATIONS);
	benchmark_seal_kc_simple("16 KiB", 16 * 1024, ITERATIONS);
	benchmark_seal_kc_simple("1 MiB", 1024 * 1024, BIG_ITERATIONS);

	return 0;
}
