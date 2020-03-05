#pragma once
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

/** Various miscellaneous utility functions
 *
 * @file src/lib/util/misc.h
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSIDH(misc_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/time.h>

#include <ctype.h>
#include <signal.h>
#include <stdbool.h>
#include <strings.h>
#include <talloc.h>

typedef		int8_t (*fr_cmp_t)(void const *a, void const *b);


/*
 *	Define TALLOC_DEBUG to check overflows with talloc.
 *	we can't use valgrind, because the memory used by
 *	talloc is valid memory... just not for us.
 */
#ifdef TALLOC_DEBUG
void		fr_talloc_verify_cb(const void *ptr, int depth,
				    int max_depth, int is_ref,
				    void *private_data);
#  define VERIFY_ALL_TALLOC talloc_report_depth_cb(NULL, 0, -1, fr_talloc_verify_cb, NULL)
#else
#  define VERIFY_ALL_TALLOC
#endif

/** Round up - Only works if _mul is a power of 2 but avoids division
 */
#define ROUND_UP_POW2(_num, _mul)	(((_num) + ((_mul) - 1)) & ~((_mul) - 1))

/** Round up - Works in all cases, but is slower
 */
#define ROUND_UP(_num, _mul)		(((((_num) + ((_mul) - 1))) / (_mul)) * (_mul))

/** Get the ceiling value of integer division
 *
 */
#define ROUND_UP_DIV(_x, _y)	(1 + (((_x) - 1) / (_y)))

/** Skip whitespace ('\\t', '\\n', '\\v', '\\f', '\\r', ' ')
 *
 * @param[in,out] _p	string to skip over.
 */
#define fr_skip_whitespace(_p) while(isspace((int)*(_p))) _p++

/** Skip whitespace, stopping at end ('\\t', '\\n', '\\v', '\\f', '\\r', ' ')
 *
 * @param[in,out] _p	string to skip over.
 * @param[in] _e	pointer to end of string.
 */
#define fr_bskip_whitespace(_p, _e) while((_p < _e) && isspace((int)*(_p))) _p++

/** Skip everything that's not whitespace ('\\t', '\\n', '\\v', '\\f', '\\r', ' ')
 *
 * @param[in,out] _p	string to skip over.
 */
#define fr_skip_not_whitespace(_p) while(*_p && !isspace((int)*(_p))) _p++

/** Zero out any whitespace with nul bytes
 *
 * @param[in,out] _p	string to process
 */
#define fr_zero_whitespace(_p) 	while (isspace((int) *_p)) *(_p++) = '\0'

/** Check whether the string is all whitespace
 *
 * @return
 *	- true if the entirety of the string is whitespace.
 *	- false if the string contains non whitespace.
 */
static inline bool is_whitespace(char const *value)
{
#ifdef __clang_analyzer__
	if (*value == '\0') return false;	/* clang analyzer doesn't seem to know what isspace does */
#endif
	do {
		if (!isspace(*value)) return false;
	} while (*++value);

	return true;
}

/** Check whether the string is made up of printable UTF8 chars
 *
 * @param value to check.
 * @param len of value.
 *
 * @return
 *	- true if the string is printable.
 *	- false if the string contains non printable chars
 */
 static inline bool is_printable(void const *value, size_t len)
 {
 	uint8_t	const *p = value;
 	size_t	clen;
 	size_t	i;

 	for (i = 0; i < len; i++) {
 		clen = fr_utf8_char(p, len - i);
 		if (clen == 0) return false;
 		i += (size_t)clen;
 		p += clen;
 	}
 	return true;
 }

/** Check whether the string is all numbers
 *
 * @return
 *	- true if the entirety of the string is number chars.
 *	- false if string contains non-numeric chars or is empty.
 */
static inline bool is_integer(char const *value)
{
#ifdef __clang_analyzer__
	if (*value == '\0') return false;	/* clang analyzer doesn't seem to know what isdigit does */
#endif
	do {
		if (!isdigit(*value)) return false;
	} while (*++value);

	return true;
}

/** Check whether the string is all zeros
 *
 * @return
 *	- true if the entirety of the string is all zeros.
 *	- false if string contains non-zero chars or is empty.
 */
static inline bool is_zero(char const *value)
{
	do {
		if (*value != '0') return false;
	} while (*++value);

	return true;
}

/** Encode a 64bit unsigned integer as a big endian number in the fewest bytes possible
 *
 * @param[out] out	Where to write big endian encoding of num.
 *			Should be at least 8 bytes.
 * @param[in] num	Number to encode.
 * @return
 *	- The number of bytes written to out.
 */
static inline size_t htonx(uint8_t *out, uint64_t num)
{
	size_t ret;

	/*
	 *	flsll isn't POSIX, but it's in at least
	 *	Linux, FreeBSD, OpenBSD and Solaris.
	 *
	 *	If we really care, implementing it
	 *	in missing.c is trivial.
	 *
	 *	This version however should compile down
	 *	to a single CPU instruction on supported
	 *	platforms.
	 */
	ret = ROUND_UP_DIV((size_t)flsll((long long)num), 8);
	switch (ret) {
	case 8:
		out[7] = (num & 0xFF00000000000000) >> 56;
	/* FALL-THROUGH */
	case 7:
		out[6] = (num & 0xFF000000000000) >> 48;
	/* FALL-THROUGH */
	case 6:
		out[5] = (num & 0xFF0000000000) >> 40;
	/* FALL-THROUGH */
	case 5:
		out[4] = (num & 0xFF00000000) >> 32;
	/* FALL-THROUGH */
	case 4:
		out[3] = (num & 0xFF000000) >> 24;
	/* FALL-THROUGH */
	case 3:
		out[2] = (num & 0xFF0000) >> 16;
	/* FALL-THROUGH */
	case 2:
		out[1] = (num & 0xFF00) >> 8;
	/* FALL-THROUGH */
	case 1:
		out[0] = (num & 0xFF);
		return ret;

	case 0:
		out[0] = 0;
		return 1;
	}

	return 0;
}

/** Convert a big endian number of variable size to a unsigned 64bit integer of native endianness
 *
 * @param[in] data	Buffer containing the number.
 * @param[in] data_len	Length of number.
 * @return unsigned 64bit integer.
 */
static inline uint64_t ntohx(uint8_t const *data, size_t data_len)
{
	uint64_t ret = 0;

	switch (data_len) {
	case 8:
		ret += ((uint64_t)data[7]) << 56;
	/* FALL-THROUGH */
	case 7:
		ret += ((uint64_t)data[6]) << 48;
	/* FALL-THROUGH */
	case 6:
		ret += ((uint64_t)data[5]) << 40;
	/* FALL-THROUGH */
	case 5:
		ret += ((uint64_t)data[4]) << 32;
	/* FALL-THROUGH */
	case 4:
		ret += ((uint64_t)data[3]) << 24;
	/* FALL-THROUGH */
	case 3:
		ret += ((uint64_t)data[2]) << 16;
	/* FALL-THROUGH */
	case 2:
		ret += ((uint64_t)data[1]) << 8;
	/* FALL-THROUGH */
	case 1:
		ret += data[8];
		return ret;
	}

	return 0;
}

int		fr_set_signal(int sig, sig_t func);
int		fr_unset_signal(int sig);
int		rad_lockfd(int fd, int lock_len);
int		rad_lockfd_nonblock(int fd, int lock_len);
int		rad_unlockfd(int fd, int lock_len);
char		*fr_abin2hex(TALLOC_CTX *ctx, uint8_t const *bin, size_t inlen);
size_t		fr_bin2hex(char * restrict hex, uint8_t const * restrict bin, size_t inlen);
size_t		fr_hex2bin(uint8_t *bin, size_t outlen, char const *hex, size_t inlen);
int		fr_strtoull(uint64_t *out, char **end, char const *value);
int		fr_strtoll(int64_t *out, char **end, char const *value);
char		*fr_trim(char const *str, size_t size);

int		fr_nonblock(int fd);
int		fr_blocking(int fd);

ssize_t		fr_writev(int fd, struct iovec vector[], int iovcnt, fr_time_delta_t timeout);
ssize_t		fr_utf8_to_ucs2(uint8_t *out, size_t outlen, char const *in, size_t inlen);
size_t		fr_snprint_uint128(char *out, size_t outlen, uint128_t const num);
int		fr_unix_time_from_str(fr_unix_time_t *date, char const *date_str);

bool		fr_multiply(uint64_t *result, uint64_t lhs, uint64_t rhs);
int		fr_size_from_str(size_t *out, char const *str);
int8_t		fr_pointer_cmp(void const *a, void const *b);
void		fr_quick_sort(void const *to_sort[], int min_idx, int max_idx, fr_cmp_t cmp);
int		fr_digest_cmp(uint8_t const *a, uint8_t const *b, size_t length) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
