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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static _Thread_local fr_randctx fr_rand_pool;		//!< A pool of pre-generated random integers
static _Thread_local bool fr_rand_initialized = false;

/** Seed the random number generator
 *
 * May be called any number of times.
 */
void fr_rand_seed(void const *data, size_t size)
{
	uint32_t hash;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		int fd;

		memset(&fr_rand_pool, 0, sizeof(fr_rand_pool));

		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			size_t total;
			ssize_t this;

			total = 0;
			while (total < sizeof(fr_rand_pool.randrsl)) {
				this = read(fd, fr_rand_pool.randrsl,
					    sizeof(fr_rand_pool.randrsl) - total);
				if ((this < 0) && (errno != EINTR)) break;
				if (this > 0) total += this;
			}
			close(fd);
		} else {
			fr_rand_pool.randrsl[0] = fd;
			fr_rand_pool.randrsl[1] = time(NULL);
			fr_rand_pool.randrsl[2] = errno;
		}

		fr_rand_init(&fr_rand_pool, 1);
		fr_rand_pool.randcnt = 0;
		fr_rand_initialized = 1;
	}

	if (!data) return;

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
 */
uint32_t fr_rand(void)
{
	uint32_t num;

	/*
	 *	Ensure that the pool is initialized.
	 */
	if (!fr_rand_initialized) {
		fr_rand_seed(NULL, 0);
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
#define fill(_expr) \
while (p < end) { \
	if ((mod = ((p - out) & (sizeof(word) - 1))) == 0) word = fr_rand(); \
	byte = ((uint8_t *)&word)[mod]; \
	*p++ = (_expr); \
}

	switch (class) {
	/*
	 *  Lowercase letters
	 */
	case 'c':
		fill('a' + (byte % 26))
		return;

	/*
	 *  Uppercase letters
	 */
	case 'C':
		fill('A' + (byte % 26))
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
		fill(byte)
		return;
	}
}
