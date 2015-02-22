/**
 * $Id$
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file md4.c
 * @brief md4 digest functions.
 */

RCSID("$Id$")

/*
 *  FORCE MD4 TO USE OUR MD4 HEADER FILE!
 *  If we don't do this, it might pick up the systems broken MD4.
 */
#include <freeradius-devel/md4.h>

/** Calculate the MD4 hash of the contents of a buffer
 *
 * @param[out] out Where to write the MD4 digest. Must be a minimum of MD4_DIGEST_LENGTH.
 * @param[in] in Data to hash.
 * @param[in] inlen Length of the data.
 */
void fr_md4_calc(uint8_t out[MD4_DIGEST_LENGTH], uint8_t const *in, size_t inlen)
{
	FR_MD4_CTX ctx;

	fr_md4_init(&ctx);
	fr_md4_update(&ctx, in, inlen);
	fr_md4_final(out, &ctx);
}

#ifndef HAVE_OPENSSL_MD4_H
/*
 * This code implements the MD4 message-digest algorithm.
 * The algorithm is due to Ron Rivest.	This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 * Todd C. Miller modified the MD5 code to do MD4 based on RFC 1186.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD4Context structure, pass it to fr_md4_init, call fr_md4_update as
 * needed on buffers full of bytes, and then call fr_md4_final, which
 * will fill a supplied 16-byte array with the digest.
 */

#ifdef FR_LITTLE_ENDIAN
#  define htole32_4(buf)		/* Nothing */
#  define htole32_14(buf)		/* Nothing */
#  define htole32_16(buf)		/* Nothing */
#else
/* Sometimes defined by endian.h */
#  ifndef htole32
#    define htole32(x)\
	(((((uint32_t)x) & 0xff000000) >> 24) |\
	((((uint32_t)x) & 0x00ff0000) >> 8) |\
	((((uint32_t)x) & 0x0000ff00) << 8) |\
	((((uint32_t)x) & 0x000000ff) << 24))
#  endif
#  define htole32_4(buf) do {\
	(buf)[0] = htole32((buf)[0]);\
	(buf)[1] = htole32((buf)[1]);\
	(buf)[2] = htole32((buf)[2]);\
	(buf)[3] = htole32((buf)[3]);\
} while (0)

#  define htole32_14(buf) do {\
	(buf)[0] = htole32((buf)[0]);\
	(buf)[1] = htole32((buf)[1]);\
	(buf)[2] = htole32((buf)[2]);\
	(buf)[3] = htole32((buf)[3]);\
	(buf)[4] = htole32((buf)[4]);\
	(buf)[5] = htole32((buf)[5]);\
	(buf)[6] = htole32((buf)[6]);\
	(buf)[7] = htole32((buf)[7]);\
	(buf)[8] = htole32((buf)[8]);\
	(buf)[9] = htole32((buf)[9]);\
	(buf)[10] = htole32((buf)[10]);\
	(buf)[11] = htole32((buf)[11]);\
	(buf)[12] = htole32((buf)[12]);\
	(buf)[13] = htole32((buf)[13]);\
} while (0)

#  define htole32_16(buf) do {\
	(buf)[0] = htole32((buf)[0]);\
	(buf)[1] = htole32((buf)[1]);\
	(buf)[2] = htole32((buf)[2]);\
	(buf)[3] = htole32((buf)[3]);\
	(buf)[4] = htole32((buf)[4]);\
	(buf)[5] = htole32((buf)[5]);\
	(buf)[6] = htole32((buf)[6]);\
	(buf)[7] = htole32((buf)[7]);\
	(buf)[8] = htole32((buf)[8]);\
	(buf)[9] = htole32((buf)[9]);\
	(buf)[10] = htole32((buf)[10]);\
	(buf)[11] = htole32((buf)[11]);\
	(buf)[12] = htole32((buf)[12]);\
	(buf)[13] = htole32((buf)[13]);\
	(buf)[14] = htole32((buf)[14]);\
	(buf)[15] = htole32((buf)[15]);\
} while (0)
#endif

/** Initialise a new MD4 context
 *
 * Set bit count to 0 and buffer to mysterious initialization constants.
 *
 * @param[out] ctx to initialise.
 */
void fr_md4_init(FR_MD4_CTX *ctx)
{
	ctx->count[0] = 0;
	ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/** Feed additional data into the MD4 hashing function
 *
 * @param[in,out] ctx to update.
 * @param[in] in Data to hash.
 * @param[in] inlen Length of the data.
 */
void fr_md4_update(FR_MD4_CTX *ctx, uint8_t const *in, size_t inlen)
{
	uint32_t count;

	/* Bytes already stored in ctx->buffer */
	count = (uint32_t)((ctx->count[0] >> 3) & 0x3f);

	/* Update bitcount */
/*	ctx->count += (uint64_t)inlen << 3;*/
	if ((ctx->count[0] += ((uint32_t)inlen << 3)) < (uint32_t)inlen) {
		/* Overflowed ctx->count[0] */
		ctx->count[1]++;
	}
	ctx->count[1] += ((uint32_t)inlen >> 29);

	/* Handle any leading odd-sized chunks */
	if (count) {
		unsigned char *p = (unsigned char *)ctx->buffer + count;

		count = MD4_BLOCK_LENGTH - count;
		if (inlen < count) {
			memcpy(p, in, inlen);
			return;
		}
		memcpy(p, in, count);
		htole32_16((uint32_t *)ctx->buffer);
		fr_md4_transform(ctx->state, ctx->buffer);
		in += count;
		inlen -= count;
	}

	/* Process data in MD4_BLOCK_LENGTH-byte chunks */
	while (inlen >= MD4_BLOCK_LENGTH) {
		memcpy(ctx->buffer, in, MD4_BLOCK_LENGTH);
		htole32_16((uint32_t *)ctx->buffer);
		fr_md4_transform(ctx->state, ctx->buffer);
		in += MD4_BLOCK_LENGTH;
		inlen -= MD4_BLOCK_LENGTH;
	}

	/* Handle any remaining bytes of data. */
	memcpy(ctx->buffer, in, inlen);
}

/** Finalise the MD4 context and write out the hash
 *
 * Final wrapup - pad to 64-byte boundary with the bit pattern 1 0*
 * (64-bit count of bits processed, MSB-first).
 *
 * @param[out] out Where to write the MD4 digest. Minimum length of MD4_DIGEST_LENGTH.
 * @param[in,out] ctx to finalise.
 */
void fr_md4_final(uint8_t out[MD4_DIGEST_LENGTH], FR_MD4_CTX *ctx)
{
	uint32_t count;
	unsigned char *p;

	/* number of bytes mod 64 */
	count = (uint32_t)(ctx->count[0] >> 3) & 0x3f;

	/*
	 * Set the first char of padding to 0x80.
	 * This is safe since there is always at least one byte free.
	 */
	p = ctx->buffer + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		htole32_16((uint32_t *)ctx->buffer);
		fr_md4_transform(ctx->state, ctx->buffer);

		/* Now fill the next block with 56 bytes */
		memset(ctx->buffer, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
	}
	htole32_14((uint32_t *)ctx->buffer);

	/* Append bit count and transform */
	((uint32_t *)ctx->buffer)[14] = ctx->count[0];
	((uint32_t *)ctx->buffer)[15] = ctx->count[1];

	fr_md4_transform(ctx->state, ctx->buffer);
	htole32_4(ctx->state);
	memcpy(out, ctx->state, MD4_DIGEST_LENGTH);
	memset(ctx, 0, sizeof(*ctx));	/* in case it's sensitive */
}

/* The three core functions - F1 is optimized somewhat */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) ((x & y) | (x & z) | (y & z))
#define F3(x, y, z) (x ^ y ^ z)

/* This is the central step in the MD4 algorithm. */
#define MD4STEP(f, w, x, y, z, data, s) (w += f(x, y, z) + data, w = w << s | w >> (32 - s))

/** The core of the MD4 algorithm
 *
 * This alters an existing MD4 hash to reflect the addition of 16
 * longwords of new data.  fr_md4_update blocks the data and converts bytes
 * into longwords for this routine.
 *
 * @param[in] state 16 bytes of data to feed into the hashing function.
 * @param[in,out] block MD4 digest block to update.
 */
void fr_md4_transform(uint32_t state[4], uint8_t const block[MD4_BLOCK_LENGTH])
{
	uint32_t a, b, c, d;
	uint32_t const *in = (uint32_t const *)block;

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD4STEP(F1, a, b, c, d, in[ 0],  3);
	MD4STEP(F1, d, a, b, c, in[ 1],  7);
	MD4STEP(F1, c, d, a, b, in[ 2], 11);
	MD4STEP(F1, b, c, d, a, in[ 3], 19);
	MD4STEP(F1, a, b, c, d, in[ 4],  3);
	MD4STEP(F1, d, a, b, c, in[ 5],  7);
	MD4STEP(F1, c, d, a, b, in[ 6], 11);
	MD4STEP(F1, b, c, d, a, in[ 7], 19);
	MD4STEP(F1, a, b, c, d, in[ 8],  3);
	MD4STEP(F1, d, a, b, c, in[ 9],  7);
	MD4STEP(F1, c, d, a, b, in[10], 11);
	MD4STEP(F1, b, c, d, a, in[11], 19);
	MD4STEP(F1, a, b, c, d, in[12],  3);
	MD4STEP(F1, d, a, b, c, in[13],  7);
	MD4STEP(F1, c, d, a, b, in[14], 11);
	MD4STEP(F1, b, c, d, a, in[15], 19);

	MD4STEP(F2, a, b, c, d, in[ 0] + 0x5a827999,  3);
	MD4STEP(F2, d, a, b, c, in[ 4] + 0x5a827999,  5);
	MD4STEP(F2, c, d, a, b, in[ 8] + 0x5a827999,  9);
	MD4STEP(F2, b, c, d, a, in[12] + 0x5a827999, 13);
	MD4STEP(F2, a, b, c, d, in[ 1] + 0x5a827999,  3);
	MD4STEP(F2, d, a, b, c, in[ 5] + 0x5a827999,  5);
	MD4STEP(F2, c, d, a, b, in[ 9] + 0x5a827999,  9);
	MD4STEP(F2, b, c, d, a, in[13] + 0x5a827999, 13);
	MD4STEP(F2, a, b, c, d, in[ 2] + 0x5a827999,  3);
	MD4STEP(F2, d, a, b, c, in[ 6] + 0x5a827999,  5);
	MD4STEP(F2, c, d, a, b, in[10] + 0x5a827999,  9);
	MD4STEP(F2, b, c, d, a, in[14] + 0x5a827999, 13);
	MD4STEP(F2, a, b, c, d, in[ 3] + 0x5a827999,  3);
	MD4STEP(F2, d, a, b, c, in[ 7] + 0x5a827999,  5);
	MD4STEP(F2, c, d, a, b, in[11] + 0x5a827999,  9);
	MD4STEP(F2, b, c, d, a, in[15] + 0x5a827999, 13);

	MD4STEP(F3, a, b, c, d, in[ 0] + 0x6ed9eba1,  3);
	MD4STEP(F3, d, a, b, c, in[ 8] + 0x6ed9eba1,  9);
	MD4STEP(F3, c, d, a, b, in[ 4] + 0x6ed9eba1, 11);
	MD4STEP(F3, b, c, d, a, in[12] + 0x6ed9eba1, 15);
	MD4STEP(F3, a, b, c, d, in[ 2] + 0x6ed9eba1,  3);
	MD4STEP(F3, d, a, b, c, in[10] + 0x6ed9eba1,  9);
	MD4STEP(F3, c, d, a, b, in[ 6] + 0x6ed9eba1, 11);
	MD4STEP(F3, b, c, d, a, in[14] + 0x6ed9eba1, 15);
	MD4STEP(F3, a, b, c, d, in[ 1] + 0x6ed9eba1,  3);
	MD4STEP(F3, d, a, b, c, in[ 9] + 0x6ed9eba1,  9);
	MD4STEP(F3, c, d, a, b, in[ 5] + 0x6ed9eba1, 11);
	MD4STEP(F3, b, c, d, a, in[13] + 0x6ed9eba1, 15);
	MD4STEP(F3, a, b, c, d, in[ 3] + 0x6ed9eba1,  3);
	MD4STEP(F3, d, a, b, c, in[11] + 0x6ed9eba1,  9);
	MD4STEP(F3, c, d, a, b, in[ 7] + 0x6ed9eba1, 11);
	MD4STEP(F3, b, c, d, a, in[15] + 0x6ed9eba1, 15);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
#endif
