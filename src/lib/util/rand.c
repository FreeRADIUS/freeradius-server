/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions to get randomness
 *
 * @file src/lib/util/rand.c
 *
 * @copyright 1999-2017 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/hash.h>

#include <fcntl.h>
#include <stdbool.h>

static _Thread_local fr_randctx fr_rand_pool;		//!< A pool of pre-generated random integers
static _Thread_local bool fr_rand_initialized = false;

void fr_rand_init(void)
{
	int fd;
	uint8_t *p = (uint8_t *) &fr_rand_pool.randrsl[0];
	uint8_t *end = p + sizeof(fr_rand_pool.randrsl);

	if (fr_rand_initialized) return;


	memset(&fr_rand_pool, 0, sizeof(fr_rand_pool));

	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ssize_t rcode;

		while (p < end) {
			rcode = read(fd, p, (size_t) (end - p));
			if ((rcode < 0) && (errno != EINTR)) break;
			if (rcode > 0) p += rcode;
		}
		close(fd);
	} else {
		/*
		 *	We use unix_time, because fr_time() is
		 *	nanoseconds since the server started.
		 *	Which is likely a very small number.
		 *	Whereas unix time is somewhat more
		 *	unknown.  If we're not seeding off of
		 *	/dev/urandom, then any randomness we
		 *	get here is terrible.
		 */
		int64_t when = fr_unix_time_unwrap(fr_time_to_unix_time(fr_time()));

		memcpy((void *) &fr_rand_pool.randrsl[0], &when, sizeof(when));
	}

	fr_isaac_init(&fr_rand_pool, 1);
	fr_rand_pool.randcnt = 0;
	fr_rand_initialized = true;
}

/** Mix data into the random number generator.
 *
 * May be called any number of times.
 */
void fr_rand_mixin(void const *data, size_t size)
{
	uint32_t hash;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		fr_rand_init();
	}

	/*
	 *	Hash the user data
	 */
	hash = fr_rand();
	if (!hash) hash = fr_rand();
	hash = fr_hash_update(data, size, hash);

	fr_rand_pool.randmem[fr_rand_pool.randcnt] ^= hash;
}


/** Return a 32-bit random number
 *
 * @hidecallergraph
 */
uint32_t fr_rand(void)
{
	uint32_t num;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		fr_rand_init();
	}

	num = fr_rand_pool.randrsl[fr_rand_pool.randcnt++];
	if (fr_rand_pool.randcnt >= 256) {
		fr_rand_pool.randcnt = 0;
		fr_isaac(&fr_rand_pool);
	}

	return num;
}

void fr_rand_buffer(void *start, size_t length)
{
	uint32_t x;
	uint8_t *buffer = start;
	size_t buflen = length;

	if (buflen > 4) {
		size_t i;

		for (i = 0; i < buflen; i += 4) {
			x = fr_rand();
			memcpy(buffer + i, &x, sizeof(x));
		}

		/*
		 *	Keep only the last bytes in the word.
		 */
		i = buflen & ~0x03;
		buffer += i;
		buflen &= 0x03;
	}

	if (!buflen) return;

	x = fr_rand();

	memcpy(buffer, &x, buflen);
}

/** Generate a random string
 *
 * @note Character selection is not perfectly distributed, should not be used
 *      for cryptographic purposes.
 *
 * @param[out] out	Where to write the string
 * @param[in] len	Length of the output buffer.
 * @param[in] class	to pick characters from (see function body).
 */
void fr_rand_str(uint8_t *out, size_t len, char class)
{
	uint8_t		*p = out, *end = p + len;
	unsigned int	word, mod;
	uint8_t		byte;

	/*
 	 *	Lookup tables for randstr char classes
 	 */
	static char	randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	static char	randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

 	/*
 	 *	Characters humans rarely confuse. Reduces char set considerably
 	 *	should only be used for things such as one time passwords.
 	 */
	static char	randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

/*
 *	yeah yeah not perfect distribution
 *	but close enough.
 */
#define fill(_expr) do { \
while (p < end) { \
	if ((mod = ((p - out) & (sizeof(word) - 1))) == 0) word = fr_rand(); \
	byte = ((uint8_t *)&word)[mod]; \
	*p++ = (_expr); \
} } while (0)

	switch (class) {
	/*
	 *  Lowercase letters
	 */
	case 'c':
		fill('a' + (byte % 26));
		return;

	/*
	 *  Uppercase letters
	 */
	case 'C':
		fill('A' + (byte % 26));
		return;

	/*
	 *  Numbers
	 */
	case 'n':
		fill('0' + (byte % 10));
		return;

	/*
	 *  Alpha numeric
	 */
	case 'a':
		fill(randstr_salt[byte % (sizeof(randstr_salt) - 3)]);
		return;

	/*
	 *  Punctuation
	 */
	case '!':
		fill(randstr_punc[byte % (sizeof(randstr_punc) - 1)]);
		return;

	/*
	 *  Alpha numeric + punctuation
	 */
	case '.':
		fill('!' + (byte % 95));
		break;

	/*
	 *  Alpha numeric + salt chars './'
	 */
	case 's':
		fill(randstr_salt[byte % (sizeof(randstr_salt) - 1)]);
		break;

	/*
	 *  Chars suitable for One Time Password tokens.
	 *  Alpha numeric with easily confused char pairs removed.
	 */
	case 'o':
		fill(randstr_otp[byte % (sizeof(randstr_otp) - 1)]);
		break;

	/*
	 *	Binary data
	 */
	case 'b':
	default:
		fill(byte);
		return;
	}
}


/*
 *	http://www.cse.yorku.ca/~oz/marsaglia-rng.html
 *
 *	We implement MWC here, which uses 2 32-bit numbers for a
 *	state, and has a period of 2^60.
 *
 *	We could extend this to a larger RNG with 4 32-bit state
 *	numbers {a, b, c, d} and use KISS, which has a period of about
 *	2^123.
 *
 *	a' = 36969 * (a & 65535) + (a >> 16)
 *	b' = 18000 * (b & 65535) + (b >> 16))
 *
 *	MWC	(a' << 16) + b'
 *	SHR3	(c ^= (c <<17); c ^= ( c>>13); c ^= (c << 5))
 *	CONG	d' = 69069 * d + 1234567
 *	KISS	((MWC^CONG)+SHR3)
 */
uint32_t fr_fast_rand(fr_fast_rand_t *ctx)
{
	ctx->a = (36969 * (ctx->a & 0xffff)) + (ctx->a >> 16);
	ctx->b = (18000 * (ctx->b & 0xffff)) + (ctx->b >> 16);

	return (ctx->a << 16) + ctx->b;
}
