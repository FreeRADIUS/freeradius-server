/**
 * $Id$
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file md5.c
 * @brief md5 digest functions.
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>

/*
 *  FORCE MD5 TO USE OUR MD5 HEADER FILE!
 *  If we don't do this, it might pick up the systems broken MD5.
 */
#include <freeradius-devel/util/md5.h>

/** Calculate the MD5 hash of the contents of a buffer
 *
 * @param[out] out Where to write the MD5 digest. Must be a minimum of MD5_DIGEST_LENGTH.
 * @param[in] in Data to hash.
 * @param[in] inlen Length of the data.
 */
void fr_md5_calc(uint8_t *out, uint8_t const *in, size_t inlen)
{
	FR_MD5_CTX ctx;

	fr_md5_init(&ctx);
	fr_md5_update(&ctx, in, inlen);
	fr_md5_final(out, &ctx);
}

#ifndef HAVE_OPENSSL_EVP_H
/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.	This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to fr_md5_init, call fr_md5_update as
 * needed on buffers full of bytes, and then call fr_md5_final, which
 * will fill a supplied 16-byte array with the digest.
 */
#define PUT_64BIT_LE(cp, value) do {\
	(cp)[7] = (value)[1] >> 24;\
	(cp)[6] = (value)[1] >> 16;\
	(cp)[5] = (value)[1] >> 8;\
	(cp)[4] = (value)[1];\
	(cp)[3] = (value)[0] >> 24;\
	(cp)[2] = (value)[0] >> 16;\
	(cp)[1] = (value)[0] >> 8;\
	(cp)[0] = (value)[0];\
} while (0)

#define PUT_32BIT_LE(cp, value) do {\
	(cp)[3] = (value) >> 24;\
	(cp)[2] = (value) >> 16;\
	(cp)[1] = (value) >> 8;\
	(cp)[0] = (value);\
} while (0)

static const uint8_t PADDING[MD5_BLOCK_LENGTH] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/** Initialise a new MD5 context
 *
 * Set bit count to 0 and buffer to mysterious initialization constants.
 *
 * @param[out] ctx to initialise.
 */
void fr_md5_init(FR_MD5_CTX *ctx)
{
	ctx->count[0] = 0;
	ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/** Feed additional data into the MD5 hashing function
 *
 * @param[in,out] ctx to update.
 * @param[in] in Data to hash.
 * @param[in] inlen Length of the data.
 */
void fr_md5_update(FR_MD5_CTX *ctx, uint8_t const *in, size_t inlen)
{
	size_t have, need;

	/* Check how many bytes we already have and how many more we need. */
	have = (size_t)((ctx->count[0] >> 3) & (MD5_BLOCK_LENGTH - 1));
	need = MD5_BLOCK_LENGTH - have;

	/* Update bitcount */
/*	ctx->count += (uint64_t)inlen << 3;*/
	if ((ctx->count[0] += ((uint32_t)inlen << 3)) < (uint32_t)inlen) {
	/* Overflowed ctx->count[0] */
		ctx->count[1]++;
	}
	ctx->count[1] += ((uint32_t)inlen >> 29);

	if (inlen >= need) {
		if (have != 0) {
			memcpy(ctx->buffer + have, in, need);
			fr_md5_transform(ctx->state, ctx->buffer);
			in += need;
			inlen -= need;
			have = 0;
		}

		/* Process data in MD5_BLOCK_LENGTH-byte chunks. */
		while (inlen >= MD5_BLOCK_LENGTH) {
			fr_md5_transform(ctx->state, in);
			in += MD5_BLOCK_LENGTH;
			inlen -= MD5_BLOCK_LENGTH;
		}
	}

	/* Handle any remaining bytes of data. */
	if (inlen != 0) memcpy(ctx->buffer + have, in, inlen);
}

/** Finalise the MD5 context and write out the hash
 *
 * Final wrapup - pad to 64-byte boundary with the bit pattern 1 0*
 * (64-bit count of bits processed, MSB-first).
 *
 * @param[out] out Where to write the MD5 digest. Minimum length of MD5_DIGEST_LENGTH.
 * @param[in,out] ctx to finalise.
 */
void fr_md5_final(uint8_t out[MD5_DIGEST_LENGTH], FR_MD5_CTX *ctx)
{
	uint8_t count[8];
	size_t padlen;
	int i;

	/* Convert count to 8 bytes in little endian order. */
	PUT_64BIT_LE(count, ctx->count);

	/* Pad out to 56 mod 64. */
	padlen = MD5_BLOCK_LENGTH -
	    ((ctx->count[0] >> 3) & (MD5_BLOCK_LENGTH - 1));
	if (padlen < 1 + 8)
		padlen += MD5_BLOCK_LENGTH;
	fr_md5_update(ctx, PADDING, padlen - 8); /* padlen - 8 <= 64 */
	fr_md5_update(ctx, count, 8);

	if (out != NULL) {
		for (i = 0; i < 4; i++)
			PUT_32BIT_LE(out + i * 4, ctx->state[i]);
	}
	memset(ctx, 0, sizeof(*ctx));	/* in case it's sensitive */
}

/* The four core functions - F1 is optimized somewhat */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) (w += f(x, y, z) + data, w = w << s | w >> (32 - s),  w += x)

/** The core of the MD5 algorithm
 *
 * This alters an existing MD5 hash to reflect the addition of 16
 * longwords of new data.  fr_md5_update blocks the data and converts bytes
 * into longwords for this routine.
 *
 * @param[in] state 16 bytes of data to feed into the hashing function.
 * @param[in,out] block MD5 digest block to update.
 */
void fr_md5_transform(uint32_t state[4], uint8_t const block[MD5_BLOCK_LENGTH])
{
	uint32_t a, b, c, d, in[MD5_BLOCK_LENGTH / 4];

	for (a = 0; a < MD5_BLOCK_LENGTH / 4; a++) {
		in[a] = (uint32_t)(
		    (uint32_t)(block[a * 4 + 0]) |
		    (uint32_t)(block[a * 4 + 1]) <<  8 |
		    (uint32_t)(block[a * 4 + 2]) << 16 |
		    (uint32_t)(block[a * 4 + 3]) << 24);
	}

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD5STEP(F1, a, b, c, d, in[ 0] + 0xd76aa478,  7);
	MD5STEP(F1, d, a, b, c, in[ 1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[ 2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[ 3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[ 4] + 0xf57c0faf,  7);
	MD5STEP(F1, d, a, b, c, in[ 5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[ 6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[ 7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[ 8] + 0x698098d8,  7);
	MD5STEP(F1, d, a, b, c, in[ 9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122,  7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[ 1] + 0xf61e2562,  5);
	MD5STEP(F2, d, a, b, c, in[ 6] + 0xc040b340,  9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[ 0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[ 5] + 0xd62f105d,  5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453,  9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[ 4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[ 9] + 0x21e1cde6,  5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6,  9);
	MD5STEP(F2, c, d, a, b, in[ 3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[ 8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905,  5);
	MD5STEP(F2, d, a, b, c, in[ 2] + 0xfcefa3f8,  9);
	MD5STEP(F2, c, d, a, b, in[ 7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[ 5] + 0xfffa3942,  4);
	MD5STEP(F3, d, a, b, c, in[ 8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[ 1] + 0xa4beea44,  4);
	MD5STEP(F3, d, a, b, c, in[ 4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[ 7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6,  4);
	MD5STEP(F3, d, a, b, c, in[ 0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[ 3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[ 6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[ 9] + 0xd9d4d039,  4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2 ] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[ 0] + 0xf4292244,  6);
	MD5STEP(F4, d, a, b, c, in[7 ] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5 ] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3,  6);
	MD5STEP(F4, d, a, b, c, in[3 ] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1 ] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8 ] + 0x6fa87e4f,  6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6 ] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4 ] + 0xf7537e82,  6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2 ] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9 ] + 0xeb86d391, 21);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
#endif
