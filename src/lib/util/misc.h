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
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/time.h>

#include <signal.h>

typedef		int8_t (*fr_cmp_t)(void const *a, void const *b);
typedef		void (*fr_free_t)(void *);

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

/** Zero out any whitespace with nul bytes
 *
 * @param[in,out] _p	string to process
 */
#define fr_zero_whitespace(_p) 	while (isspace((uint8_t) *_p)) *(_p++) = '\0'

/** Check whether the string is all whitespace
 *
 * @return
 *	- true if the entirety of the string is whitespace.
 *	- false if the string contains non whitespace.
 */
static inline bool is_whitespace(char const *value)
{
#ifdef STATIC_ANALYZER
	if (*value == '\0') return false;	/* clang analyzer doesn't seem to know what isspace does */
#endif
	do {
		if (!isspace((uint8_t) *value)) return false;
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
#ifdef STATIC_ANALYZER
	if (*value == '\0') return false;	/* clang analyzer doesn't seem to know what isdigit does */
#endif
	do {
		if (!isdigit((uint8_t) *value)) return false;
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

int		fr_set_signal(int sig, sig_t func);
int		fr_unset_signal(int sig);
int		rad_lockfd(int fd, int lock_len);
int		rad_lockfd_nonblock(int fd, int lock_len);
int		rad_unlockfd(int fd, int lock_len);
int		fr_strtoull(uint64_t *out, char **end, char const *value);
int		fr_strtoll(int64_t *out, char **end, char const *value);
char		*fr_trim(char const *str, size_t size);
char		*fr_tolower(char *str);

int		fr_nonblock(int fd);
int		fr_blocking(int fd);
int		fr_cloexec(int fd);

ssize_t		fr_utf8_to_ucs2(uint8_t *out, size_t outlen, char const *in, size_t inlen);
size_t		fr_snprint_uint128(char *out, size_t outlen, uint128_t const num);

int8_t		fr_pointer_cmp(void const *a, void const *b);
void		fr_quick_sort(void const *to_sort[], int min_idx, int max_idx, fr_cmp_t cmp);
int		fr_digest_cmp(uint8_t const *a, uint8_t const *b, size_t length) CC_HINT(nonnull);

char const	*fr_filename(char const *path);
char const	*fr_filename_common_trim(char const *path, char const *common);

#ifdef __cplusplus
}
#endif
