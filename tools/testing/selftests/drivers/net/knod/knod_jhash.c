// SPDX-License-Identifier: GPL-2.0
/*
 * knod_jhash - the offloaded jhash against the one the host uses
 *
 * A map is filled by the host with jhash() and read by the GPU with a routine
 * that has to land on the same bucket.  Getting that wrong does not fail: the
 * lookup walks the wrong chain and misses, which reads as a cold map rather
 * than as a broken one.  So it is worth a test that does not need the GPU.
 *
 * blob_jhash() below is a transliteration of knod-blob/src/jhash.inc and
 * kernel_jhash() of include/linux/jhash.h.  Change either and this says so.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint8_t u8;

#define JHASH_INITVAL		0xdeadbeef
#define KNOD_MAX_KEY_WORDS	14
#define TRIALS			20000

static u32 rol32(u32 v, int n)
{
	return (v << n) | (v >> (32 - n));
}

#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

static u32 load32(const void *p)
{
	u32 v;

	memcpy(&v, p, sizeof(v));
	return v;
}

/* include/linux/jhash.h */
static u32 kernel_jhash(const void *key, u32 length, u32 initval)
{
	const u8 *k = key;
	u32 a, b, c;

	a = b = c = JHASH_INITVAL + length + initval;

	while (length > 12) {
		a += load32(k);
		b += load32(k + 4);
		c += load32(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}

	switch (length) {
	case 12: c += (u32)k[11] << 24; /* fallthrough */
	case 11: c += (u32)k[10] << 16; /* fallthrough */
	case 10: c += (u32)k[9] << 8;   /* fallthrough */
	case 9:  c += k[8];             /* fallthrough */
	case 8:  b += (u32)k[7] << 24;  /* fallthrough */
	case 7:  b += (u32)k[6] << 16;  /* fallthrough */
	case 6:  b += (u32)k[5] << 8;   /* fallthrough */
	case 5:  b += k[4];             /* fallthrough */
	case 4:  a += (u32)k[3] << 24;  /* fallthrough */
	case 3:  a += (u32)k[2] << 16;  /* fallthrough */
	case 2:  a += (u32)k[1] << 8;   /* fallthrough */
	case 1:  a += k[0];
		 __jhash_final(a, b, c);
		 break;
	case 0:
		 break;
	}
	return c;
}

/* knod-blob/src/jhash.inc, macro JHASH.  The routine is built per key length,
 * so the round count is settled while assembling rather than looped over, and
 * @key_size and @hashrnd reach it already summed in a scalar register.
 */
static u32 blob_jhash(const u32 *key, int nwords, u32 key_size, u32 hashrnd)
{
	int rounds = (nwords - 1) / 3;
	int left = nwords;
	int i = 0, r;
	u32 a, b, c;

	a = JHASH_INITVAL + key_size + hashrnd;
	b = a;
	c = a;

	for (r = 0; r < rounds; r++) {
		a += key[i + 0];
		b += key[i + 1];
		c += key[i + 2];
		__jhash_mix(a, b, c);
		i += 3;
		left -= 3;
	}

	if (left >= 3)
		c += key[i + 2];
	if (left >= 2)
		b += key[i + 1];
	if (left >= 1)
		a += key[i + 0];

	__jhash_final(a, b, c);
	return c;
}

static int check_length(int nwords)
{
	u32 key_size = nwords * 4;
	int bad = 0, trial, w;

	for (trial = 0; trial < TRIALS; trial++) {
		u32 key[KNOD_MAX_KEY_WORDS], seed = rand();

		for (w = 0; w < nwords; w++)
			key[w] = ((u32)rand() << 16) ^ (u32)rand();

		if (kernel_jhash(key, key_size, seed) !=
		    blob_jhash(key, nwords, key_size, seed))
			bad++;
	}

	printf("  %2d words (%2u bytes): %s\n", nwords, key_size,
	       bad ? "MISMATCH" : "ok");
	return bad;
}

int main(void)
{
	int nwords, bad = 0;

	srand(1);

	printf("offloaded jhash against the host's:\n");
	for (nwords = 1; nwords <= KNOD_MAX_KEY_WORDS; nwords++)
		bad += check_length(nwords);

	if (bad) {
		printf("FAIL: %d of %d hashes differ\n", bad,
		       TRIALS * KNOD_MAX_KEY_WORDS);
		return 1;
	}

	printf("PASS: %d hashes, every key length matches\n",
	       TRIALS * KNOD_MAX_KEY_WORDS);
	return 0;
}
