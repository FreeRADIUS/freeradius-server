/** A local MD5 implementation
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file src/lib/util/md5.c
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/thread_local.h>
#include <talloc.h>

/*
 *  FORCE MD5 TO USE OUR MD5 HEADER FILE!
 *  If we don't do this, it might pick up the systems broken MD5.
 */
#include <freeradius-devel/util/md5.h>

/** The thread local free list
 *
 * Any entries remaining in the list will be freed when the thread is joined
 */
fr_thread_local_setup(fr_md5_ctx_t *, md5_ctx); /* macro */

/*
 *	If we have OpenSSL's EVP API available, then build wrapper functions.
 *
 *	We always need to build the local MD5 functions as OpenSSL could
 *	be operating in FIPS mode where MD5 digest functions are unavailable.
 */
#ifdef HAVE_OPENSSL_EVP_H
#define ARRAY_SIZE (8)
typedef struct {
	bool		used;
	fr_md5_ctx_t	*md_ctx;
} fr_md5_free_list_t;
fr_thread_local_setup(fr_md5_free_list_t *, md5_array); /* macro */

#  include <openssl/evp.h>
#  include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define EVP_MD_CTX_new EVP_MD_CTX_create
#  define EVP_MD_CTX_free EVP_MD_CTX_destroy
#  define EVP_MD_CTX_reset EVP_MD_CTX_cleanup
#endif

static int have_openssl_md5 = -1;

static void _md5_ctx_openssl_free_on_exit(void *arg)
{
	int i;
	fr_md5_free_list_t *free_list = arg;

	for (i = 0; i < ARRAY_SIZE; i++) {
		if (free_list[i].used) continue;

		EVP_MD_CTX_free(free_list[i].md_ctx);
	}
	talloc_free(free_list);
}

/** @copydoc fr_md5_ctx_reset
 *
 */
static void fr_md5_openssl_ctx_reset(fr_md5_ctx_t *ctx)
{
	EVP_MD_CTX *md_ctx = ctx;

	EVP_MD_CTX_reset(md_ctx);
	EVP_DigestInit_ex(md_ctx, EVP_md5(), NULL);
}

/** @copydoc fr_md5_ctx_copy
 *
 */
static void fr_md5_openssl_ctx_copy(fr_md5_ctx_t *dst, fr_md5_ctx_t const *src)
{
	EVP_MD_CTX_copy_ex(dst, src);
}

/** @copydoc fr_md5_ctx_alloc
 *
 */
static fr_md5_ctx_t *fr_md5_openssl_ctx_alloc(bool thread_local)
{
	int i;
	EVP_MD_CTX *md_ctx;
	fr_md5_free_list_t *free_list;

	thread_local = true;

	/*
	 *	Use the thread local ctx to avoid heap allocations.
	 */
	if (!thread_local) {
	alloc:
		md_ctx = EVP_MD_CTX_new();
		if (unlikely(!md_ctx)) {
		oom:
			fr_strerror_printf("Out of memory");
			return NULL;
		}
		EVP_DigestInit_ex(md_ctx, EVP_md5(), NULL);
		return md_ctx;
	}

	if (unlikely(!md5_array)) {
		free_list = talloc_zero_array(NULL, fr_md5_free_list_t, ARRAY_SIZE);
		if (unlikely(!free_list)) goto oom;

		fr_thread_local_set_destructor(md5_array, _md5_ctx_openssl_free_on_exit, free_list);

		/*
		 *	Initialize all MD5 contexts
		 */
		for (i = 0; i < ARRAY_SIZE; i++) {
			free_list[i].md_ctx = EVP_MD_CTX_new();
			if (!free_list[i].md_ctx ) goto oom;
			EVP_DigestInit_ex(free_list[i].md_ctx, EVP_md5(), NULL);
		}
	} else {
		free_list = md5_array;
	}

	for (i = 0; i < ARRAY_SIZE; i++) {
		if (free_list[i].used) continue;

		free_list[i].used = true;
		return free_list[i].md_ctx;
	}

	/*
	 *	No more free contexts, just allocate a new one.
	 */
	goto alloc;
}

/** @copydoc fr_md5_ctx_free
 *
 */
static void fr_md5_openssl_ctx_free(fr_md5_ctx_t **ctx)
{
	int i;
	fr_md5_free_list_t *free_list = md5_array;

	if (free_list) for (i = 0; i < ARRAY_SIZE; i++) {
		if (free_list[i].md_ctx == *ctx) {
			free_list[i].used = false;
			fr_md5_openssl_ctx_reset(*ctx);
			*ctx = NULL;
			return;
		}
	}

	EVP_MD_CTX_free(*ctx);
	*ctx = NULL;
}

/** @copydoc fr_md5_update
 *
 */
static void fr_md5_openssl_update(fr_md5_ctx_t *ctx, uint8_t const *in, size_t inlen)
{
	EVP_DigestUpdate(ctx, in, inlen);
}

/** @copydoc fr_md5_final
 *
 */
static void fr_md5_openssl_final(uint8_t out[static MD5_DIGEST_LENGTH], fr_md5_ctx_t *ctx)
{
	unsigned int len;

	EVP_DigestFinal(ctx, out, &len);

	if (!fr_cond_assert(len == MD5_DIGEST_LENGTH)) return;
}
#endif

#  define MD5_BLOCK_LENGTH 64
typedef struct {
	uint32_t state[4];			//!< State.
	uint32_t count[2];			//!< Number of bits, mod 2^64.
	uint8_t buffer[MD5_BLOCK_LENGTH];	//!< Input buffer.
} fr_md5_ctx_local_t;


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
static void fr_md5_local_transform(uint32_t state[static 4], uint8_t const block[static MD5_BLOCK_LENGTH])
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

/** @copydoc fr_md5_ctx_reset
 *
 */
static void fr_md5_local_ctx_reset(fr_md5_ctx_t *ctx)
{
	fr_md5_ctx_local_t	*ctx_local = talloc_get_type_abort(ctx, fr_md5_ctx_local_t);

	ctx_local->count[0] = 0;
	ctx_local->count[1] = 0;
	ctx_local->state[0] = 0x67452301;
	ctx_local->state[1] = 0xefcdab89;
	ctx_local->state[2] = 0x98badcfe;
	ctx_local->state[3] = 0x10325476;
}

/** @copydoc fr_md5_ctx_copy
 *
 */
static void fr_md5_local_ctx_copy(fr_md5_ctx_t *dst, fr_md5_ctx_t const *src)
{
	fr_md5_ctx_local_t const *ctx_local_src = talloc_get_type_abort_const(src, fr_md5_ctx_local_t);
	fr_md5_ctx_local_t *ctx_local_dst = talloc_get_type_abort(dst, fr_md5_ctx_local_t);

	memcpy(ctx_local_dst, ctx_local_src, sizeof(*ctx_local_dst));
}

static void _md5_ctx_local_free_on_exit(void *arg)
{
	talloc_free(arg);
}

/** @copydoc fr_md5_ctx_alloc
 *
 */
static fr_md5_ctx_t *fr_md5_local_ctx_alloc(bool thread_local)
{
	fr_md5_ctx_local_t *ctx_local;

#ifdef HAVE_OPENSSL_EVP_H
	if (unlikely(have_openssl_md5 == -1)) {
		/*
		 *	If we're not in FIPS mode, then swap out the
		 *	md5 functions, and call the OpenSSL init
		 *	function.
		 */
		if (FIPS_mode() == 0) {
			have_openssl_md5 = 1;

			/*
			 *	Swap out the functions pointers
			 *	for the OpenSSL versions.
			 */
			fr_md5_ctx_reset = fr_md5_openssl_ctx_reset;
			fr_md5_ctx_copy = fr_md5_openssl_ctx_copy;
			fr_md5_ctx_alloc = fr_md5_openssl_ctx_alloc;
			fr_md5_ctx_free = fr_md5_openssl_ctx_free;
			fr_md5_update = fr_md5_openssl_update;
			fr_md5_final = fr_md5_openssl_final;

			return fr_md5_ctx_alloc(thread_local);
		}

		have_openssl_md5 = 0;
	}
#endif

	/*
	 *	Use the thread local ctx to avoid heap allocations.
	 */
	if (thread_local) {
		if (unlikely(!md5_ctx)) {
			ctx_local = talloc(NULL, fr_md5_ctx_local_t);
			if (unlikely(!ctx_local)) return NULL;
			fr_md5_local_ctx_reset(ctx_local);
			fr_thread_local_set_destructor(md5_ctx, _md5_ctx_local_free_on_exit, ctx_local);
		} else {
			ctx_local = md5_ctx;
		}
	/*
	 *	If the MD5 ctx might be used across a yield point
	 *	shared should be set to false, and new contexts
	 *	should be allocated.
	 */
	} else {
		ctx_local = talloc(NULL, fr_md5_ctx_local_t);
		if (unlikely(!ctx_local)) return NULL;
		fr_md5_local_ctx_reset(ctx_local);
	}

	return ctx_local;
}

/** @copydoc fr_md5_ctx_free
 *
 */
static void fr_md5_local_ctx_free(fr_md5_ctx_t **ctx)
{
	if (md5_ctx && (md5_ctx == *ctx)) {
		fr_md5_local_ctx_reset(*ctx);
		*ctx = NULL;
		return;	/* Don't free the thread_local ctx */
	}

	talloc_free(*ctx);
	*ctx = NULL;
}

/** @copydoc fr_md5_update
 *
 */
static void fr_md5_local_update(fr_md5_ctx_t *ctx, uint8_t const *in, size_t inlen)
{
	fr_md5_ctx_local_t	*ctx_local = talloc_get_type_abort(ctx, fr_md5_ctx_local_t);

	size_t have, need;

	/* Check how many bytes we already have and how many more we need. */
	have = (size_t)((ctx_local->count[0] >> 3) & (MD5_BLOCK_LENGTH - 1));
	need = MD5_BLOCK_LENGTH - have;

	/* Update bitcount */
/*	ctx_local->count += (uint64_t)inlen << 3;*/
	if ((ctx_local->count[0] += ((uint32_t)inlen << 3)) < (uint32_t)inlen) {
	/* Overflowed ctx_local->count[0] */
		ctx_local->count[1]++;
	}
	ctx_local->count[1] += ((uint32_t)inlen >> 29);

	if (inlen >= need) {
		if (have != 0) {
			memcpy(ctx_local->buffer + have, in, need);
			fr_md5_local_transform(ctx_local->state, ctx_local->buffer);
			in += need;
			inlen -= need;
			have = 0;
		}

		/* Process data in MD5_BLOCK_LENGTH-byte chunks. */
		while (inlen >= MD5_BLOCK_LENGTH) {
			fr_md5_local_transform(ctx_local->state, in);
			in += MD5_BLOCK_LENGTH;
			inlen -= MD5_BLOCK_LENGTH;
		}
	}

	/* Handle any remaining bytes of data. */
	if (inlen != 0) memcpy(ctx_local->buffer + have, in, inlen);
}

/** @copydoc fr_md5_final
 *
 */
static void fr_md5_local_final(uint8_t out[static MD5_DIGEST_LENGTH], fr_md5_ctx_t *ctx)
{
	fr_md5_ctx_local_t	*ctx_local = talloc_get_type_abort(ctx, fr_md5_ctx_local_t);
	uint8_t			count[8];
	size_t			padlen;
	int			i;

	/* Convert count to 8 bytes in little endian order. */
	PUT_64BIT_LE(count, ctx_local->count);

	/* Pad out to 56 mod 64. */
	padlen = MD5_BLOCK_LENGTH -
	    ((ctx_local->count[0] >> 3) & (MD5_BLOCK_LENGTH - 1));
	if (padlen < 1 + 8)
		padlen += MD5_BLOCK_LENGTH;
	fr_md5_update(ctx_local, PADDING, padlen - 8); /* padlen - 8 <= 64 */
	fr_md5_update(ctx_local, count, 8);

	if (out != NULL) {
		for (i = 0; i < 4; i++)
			PUT_32BIT_LE(out + i * 4, ctx_local->state[i]);
	}
	memset(ctx_local, 0, sizeof(*ctx_local));	/* in case it's sensitive */
}

/*
 *	Digest function pointers
 */
fr_md5_ctx_reset_t fr_md5_ctx_reset = fr_md5_local_ctx_reset;
fr_md5_ctx_copy_t fr_md5_ctx_copy = fr_md5_local_ctx_copy;
fr_md5_ctx_alloc_t fr_md5_ctx_alloc = fr_md5_local_ctx_alloc;
fr_md5_ctx_free_t fr_md5_ctx_free = fr_md5_local_ctx_free;
fr_md5_update_t fr_md5_update = fr_md5_local_update;
fr_md5_final_t fr_md5_final = fr_md5_local_final;

/** Calculate the MD5 hash of the contents of a buffer
 *
 * @param[out] out Where to write the MD5 digest. Must be a minimum of MD5_DIGEST_LENGTH.
 * @param[in] in Data to hash.
 * @param[in] inlen Length of the data.
 */
void fr_md5_calc(uint8_t out[static MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen)
{
	fr_md5_ctx_t *ctx;

	ctx = fr_md5_ctx_alloc(true);
	fr_md5_update(ctx, in, inlen);
	fr_md5_final(out, ctx);
	fr_md5_ctx_free(&ctx);
}
