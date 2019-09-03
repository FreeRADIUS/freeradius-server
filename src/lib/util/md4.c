/** A local MD4 implementation
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file src/lib/util/md4.c
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/thread_local.h>

/*
 *  FORCE MD4 TO USE OUR MD4 HEADER FILE!
 *  If we don't do this, it might pick up the systems broken MD4.
 */
#include <freeradius-devel/util/md4.h>

fr_thread_local_setup(fr_md4_ctx_t *, md4_ctx)

/*
 *	If we have OpenSSL's EVP API available, then build wrapper functions.
 *
 *	We always need to build the local MD4 functions as OpenSSL could
 *	be operating in FIPS mode where MD4 digest functions are unavailable.
 */
#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/evp.h>
#  include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define EVP_MD_CTX_new EVP_MD_CTX_create
#  define EVP_MD_CTX_free EVP_MD_CTX_destroy
#  define EVP_MD_CTX_reset EVP_MD_CTX_cleanup
#endif

static int have_openssl_md4 = -1;

static void _md4_ctx_openssl_free_on_exit(void *arg)
{
	EVP_MD_CTX_free(arg);
}

/** @copydoc fr_md4_ctx_reset
 *
 */
static void fr_md4_openssl_ctx_reset(fr_md4_ctx_t *ctx)
{
	EVP_MD_CTX *md_ctx = ctx;

	EVP_MD_CTX_reset(md_ctx);
	EVP_DigestInit_ex(md_ctx, EVP_md4(), NULL);
}

/** @copydoc fr_md4_ctx_copy
 *
 */
static void fr_md4_openssl_ctx_copy(fr_md4_ctx_t *dst, fr_md4_ctx_t const *src)
{
	EVP_MD_CTX_copy_ex(dst, src);
}

/** @copydoc fr_md4_ctx_alloc
 *
 */
static fr_md4_ctx_t *fr_md4_openssl_ctx_alloc(bool thread_local)
{
	EVP_MD_CTX *md_ctx;

	/*
	 *	Use the thread local ctx to avoid heap allocations.
	 */
	if (thread_local) {
		if (unlikely(!md4_ctx)) {
			md_ctx = EVP_MD_CTX_new();
			if (unlikely(!md_ctx)) {
			oom:
				fr_strerror_printf("Out of memory");
				return NULL;
			}
			fr_thread_local_set_destructor(md4_ctx, _md4_ctx_openssl_free_on_exit, md_ctx);
			EVP_DigestInit_ex(md_ctx, EVP_md4(), NULL);
		} else {
			md_ctx = md4_ctx;
		}
	/*
	 *	If the MD4 ctx might be used across a yield point
	 *	shared should be set to false, and new contexts
	 *	should be allocated.
	 */
	} else {
		md_ctx = EVP_MD_CTX_new();
		if (unlikely(!md_ctx)) goto oom;
		EVP_DigestInit_ex(md_ctx, EVP_md4(), NULL);
	}

	return md_ctx;
}

/** @copydoc fr_md4_ctx_free
 *
 */
static void fr_md4_openssl_ctx_free(fr_md4_ctx_t **ctx)
{
	if (md4_ctx && (md4_ctx == *ctx)) {
		fr_md4_openssl_ctx_reset(*ctx);
		*ctx = NULL;
		return;
	}

	EVP_MD_CTX_free(*ctx);
	*ctx = NULL;
}

/** @copydoc fr_md4_update
 *
 */
static void fr_md4_openssl_update(fr_md4_ctx_t *ctx, uint8_t const *in, size_t inlen)
{
	EVP_DigestUpdate(ctx, in, inlen);
}

/** @copydoc fr_md4_final
 *
 */
static void fr_md4_openssl_final(uint8_t out[static MD4_DIGEST_LENGTH], fr_md4_ctx_t *ctx)
{
	unsigned int len;

	EVP_DigestFinal(ctx, out, &len);

	if (!fr_cond_assert(len == MD4_DIGEST_LENGTH)) return;
}
#endif

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
#ifndef WORDS_BIGENDIAN
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

#define MD4_BLOCK_LENGTH 64

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
static void fr_md4_local_transform(uint32_t state[static 4], uint8_t const block[static MD4_BLOCK_LENGTH])
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

typedef struct {
	uint32_t state[4];			//!< State.
	uint32_t count[2];			//!< Number of bits, mod 2^64.
	uint8_t buffer[MD4_BLOCK_LENGTH];	//!< Input buffer.
} fr_md4_ctx_local_t;

/** @copydoc fr_md4_ctx_reset
 *
 */
static void fr_md4_local_ctx_reset(fr_md4_ctx_t *ctx)
{
	fr_md4_ctx_local_t	*ctx_local = talloc_get_type_abort(ctx, fr_md4_ctx_local_t);

	ctx_local->count[0] = 0;
	ctx_local->count[1] = 0;
	ctx_local->state[0] = 0x67452301;
	ctx_local->state[1] = 0xefcdab89;
	ctx_local->state[2] = 0x98badcfe;
	ctx_local->state[3] = 0x10325476;
}

/** @copydoc fr_md4_ctx_copy
 *
 */
static void fr_md4_local_ctx_copy(fr_md4_ctx_t *dst, fr_md4_ctx_t const *src)
{
	fr_md4_ctx_local_t const *ctx_local_src = talloc_get_type_abort_const(src, fr_md4_ctx_local_t);
	fr_md4_ctx_local_t *ctx_local_dst = talloc_get_type_abort(dst, fr_md4_ctx_local_t);

	memcpy(ctx_local_dst, ctx_local_src, sizeof(*ctx_local_dst));
}

static void _md4_ctx_local_free_on_exit(void *arg)
{
	talloc_free(arg);
}

/** @copydoc fr_md4_ctx_alloc
 *
 */
static fr_md4_ctx_t *fr_md4_local_ctx_alloc(bool thread_local)
{
	fr_md4_ctx_local_t *ctx_local;

#ifdef HAVE_OPENSSL_EVP_H
	if (unlikely(have_openssl_md4 == -1)) {
		/*
		 *	If we're not in FIPS mode, then swap out the
		 *	md4 functions, and call the OpenSSL init
		 *	function.
		 */
		if (FIPS_mode() == 0) {
			have_openssl_md4 = 1;

			/*
			 *	Swap out the functions pointers
			 *	for the OpenSSL versions.
			 */
			fr_md4_ctx_reset = fr_md4_openssl_ctx_reset;
			fr_md4_ctx_copy = fr_md4_openssl_ctx_copy;
			fr_md4_ctx_alloc = fr_md4_openssl_ctx_alloc;
			fr_md4_ctx_free = fr_md4_openssl_ctx_free;
			fr_md4_update = fr_md4_openssl_update;
			fr_md4_final = fr_md4_openssl_final;

			return fr_md4_ctx_alloc(thread_local);
		}

		have_openssl_md4 = 0;
	}
#endif

	/*
	 *	Use the thread local ctx to avoid heap allocations.
	 */
	if (thread_local) {
		if (unlikely(!md4_ctx)) {
			ctx_local = talloc(NULL, fr_md4_ctx_local_t);
			if (unlikely(!ctx_local)) return NULL;
			fr_md4_local_ctx_reset(ctx_local);
			fr_thread_local_set_destructor(md4_ctx, _md4_ctx_local_free_on_exit, ctx_local);
		} else {
			ctx_local = md4_ctx;
		}
	/*
	 *	If the MD4 ctx might be used across a yield point
	 *	shared should be set to false, and new contexts
	 *	should be allocated.
	 */
	} else {
		ctx_local = talloc(NULL, fr_md4_ctx_local_t);
		if (unlikely(!ctx_local)) return NULL;
		fr_md4_local_ctx_reset(ctx_local);
	}

	return ctx_local;
}

/** @copydoc fr_md4_ctx_free
 *
 */
static void fr_md4_local_ctx_free(fr_md4_ctx_t **ctx)
{
	if (md4_ctx && (md4_ctx == *ctx)) {
		fr_md4_local_ctx_reset(*ctx);
		*ctx = NULL;
		return;	/* Don't free the thread_local ctx */
	}

	talloc_free(*ctx);
	*ctx = NULL;
}

/** @copydoc fr_md4_update
 *
 */
static void fr_md4_local_update(fr_md4_ctx_t *ctx, uint8_t const *in, size_t inlen)
{
	uint32_t		count;
	fr_md4_ctx_local_t	*ctx_local = talloc_get_type_abort(ctx, fr_md4_ctx_local_t);

	/* Bytes already stored in ctx_local->buffer */
	count = (uint32_t)((ctx_local->count[0] >> 3) & 0x3f);

	/* Update bitcount */
/*	ctx_local->count += (uint64_t)inlen << 3;*/
	if ((ctx_local->count[0] += ((uint32_t)inlen << 3)) < (uint32_t)inlen) {
		/* Overflowed ctx_local->count[0] */
		ctx_local->count[1]++;
	}
	ctx_local->count[1] += ((uint32_t)inlen >> 29);

	/* Handle any leading odd-sized chunks */
	if (count) {
		unsigned char *p = (unsigned char *)ctx_local->buffer + count;

		count = MD4_BLOCK_LENGTH - count;
		if (inlen < count) {
			memcpy(p, in, inlen);
			return;
		}
		memcpy(p, in, count);
		htole32_16((uint32_t *)ctx_local->buffer);
		fr_md4_local_transform(ctx_local->state, ctx_local->buffer);
		in += count;
		inlen -= count;
	}

	/* Process data in MD4_BLOCK_LENGTH-byte chunks */
	while (inlen >= MD4_BLOCK_LENGTH) {
		memcpy(ctx_local->buffer, in, MD4_BLOCK_LENGTH);
		htole32_16((uint32_t *)ctx_local->buffer);
		fr_md4_local_transform(ctx_local->state, ctx_local->buffer);
		in += MD4_BLOCK_LENGTH;
		inlen -= MD4_BLOCK_LENGTH;
	}

	/* Handle any remaining bytes of data. */
	memcpy(ctx_local->buffer, in, inlen);
}

/** @copydoc fr_md4_final
 *
 */
static void fr_md4_local_final(uint8_t out[static MD4_DIGEST_LENGTH], fr_md4_ctx_t *ctx)
{
	uint32_t		count;
	unsigned char		*p;
	fr_md4_ctx_local_t	*ctx_local = talloc_get_type_abort(ctx, fr_md4_ctx_local_t);

	/* number of bytes mod 64 */
	count = (uint32_t)(ctx_local->count[0] >> 3) & 0x3f;

	/*
	 * Set the first char of padding to 0x80.
	 * This is safe since there is always at least one byte free.
	 */
	p = ctx_local->buffer + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		htole32_16((uint32_t *)ctx_local->buffer);
		fr_md4_local_transform(ctx_local->state, ctx_local->buffer);

		/* Now fill the next block with 56 bytes */
		memset(ctx_local->buffer, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
	}
	htole32_14((uint32_t *)ctx_local->buffer);

	/* Append bit count and transform */
	((uint32_t *)ctx_local->buffer)[14] = ctx_local->count[0];
	((uint32_t *)ctx_local->buffer)[15] = ctx_local->count[1];

	fr_md4_local_transform(ctx_local->state, ctx_local->buffer);
	htole32_4(ctx_local->state);
	memcpy(out, ctx_local->state, MD4_DIGEST_LENGTH);
	memset(ctx_local, 0, sizeof(*ctx_local));	/* in case it's sensitive */
}

/*
 *	Digest function pointers
 */
fr_md4_ctx_reset_t fr_md4_ctx_reset = fr_md4_local_ctx_reset;
fr_md4_ctx_copy_t fr_md4_ctx_copy = fr_md4_local_ctx_copy;
fr_md4_ctx_alloc_t fr_md4_ctx_alloc = fr_md4_local_ctx_alloc;
fr_md4_ctx_free_t fr_md4_ctx_free = fr_md4_local_ctx_free;
fr_md4_update_t fr_md4_update = fr_md4_local_update;
fr_md4_final_t fr_md4_final = fr_md4_local_final;

/** Calculate the MD4 hash of the contents of a buffer
 *
 * @param[out] out Where to write the MD4 digest. Must be a minimum of MD4_DIGEST_LENGTH.
 * @param[in] in Data to hash.
 * @param[in] inlen Length of the data.
 */
void fr_md4_calc(uint8_t out[static MD4_DIGEST_LENGTH], uint8_t const *in, size_t inlen)
{
	fr_md4_ctx_t *ctx;

	ctx = fr_md4_ctx_alloc(true);
	fr_md4_update(ctx, in, inlen);
	fr_md4_final(out, ctx);
	fr_md4_ctx_free(&ctx);
}
