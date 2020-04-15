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

/** A generic string buffer structure for string printing and parsing
 *
 * @file src/lib/util/sbuff.c
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/print.h>

#include <stdlib.h>
#include <string.h>

static_assert(sizeof(long long) >= sizeof(int64_t), "long long must be as wide or wider than an int64_t");
static_assert(sizeof(unsigned long long) >= sizeof(uint64_t), "long long must be as wide or wider than an uint64_t");

/** Wind position to first instance of specified multibyte utf8 char
 *
 * Only use this function if the search char could be multibyte,
 * as there's a large performance penalty.
 *
 * @param[in,out] in		Sbuff to search in.
 * @param[in] chr		to search for.
 * @return
 *	- 0, no instances found.
 *	- >0 the offset at which the first occurrence of the multi-byte chr was found.
 */
size_t fr_sbuff_strchr_utf8(fr_sbuff_t *in, char *chr)
{
	char const *found;
	char const *p = in->p;

	found = fr_utf8_strchr(NULL, p, in->end - in->p, chr);
	if (!found) return 0;

	in->p = found;

	return found - p;
}

/** Wind position to first instance of specified char
 *
 * @param[in,out] in		Sbuff to search in.
 * @param[in] c			to search for.
 * @return
 *	- 0, no instances found.
 *	- >0 the offset at which the first occurrence of the char was found.
 */
size_t fr_sbuff_strchr(fr_sbuff_t *in, char c)
{
	char const *found;
	char const *p = in->p;

	found = memchr(in->p, c, in->end - in->p);
	if (!found) return 0;

	in->p = found;

	return found - p;
}

/** Wind position to the first instance of the specified needle
 *
 * @param[in,out] in		sbuff to search in.
 * @param[in] needle		to search for.
 * @param[in] len		Length of the needle.  -1 to use strlen.
 * @return
 *	- 0, no instances found.
 *	- >0 the offset at which the first occurrence of the needle was found.
 */
size_t fr_sbuff_strstr(fr_sbuff_t *in, char const *needle, ssize_t len)
{
	char const *found;
	char const *p = in->p;

	if (len < 0) len = strlen(needle);

	found = memmem(in->p, in->end - in->p, needle, len );
	if (!found) return 0;

	in->p = found;

	return found - p;
}

/** Copy n bytes from the sbuff to another buffer
 *
 * Will fail if output buffer is too small, or insufficient data is available in sbuff.
 *
 * @param[out] out	Where to copy to.
 * @param[in] outlen	Size of output buffer.
 * @param[in] in	Where to copy from.  Will copy len bytes from current position in buffer.
 * @param[in] len	How many bytes to copy.  If 0 the entire buffer will be copied.
 * @return
 *      - 0 if insufficient bytes are available in the sbuff.
 *	- <0 the number of additional bytes we'd need in the output buffer as a negative value.
 *	- >0 the number of bytes copied to out.
 */
ssize_t fr_sbuff_strncpy_exact(char *out, size_t outlen, fr_sbuff_t *in, size_t len)
{
	if (len == SIZE_MAX) len = in->end - in->p;
	if (unlikely(outlen == 0)) return -(len + 1);

	outlen--;	/* Account the \0 byte */

	if (len > outlen) return outlen - len;	/* Return how many bytes we'd need */
	if ((in->p + len) > in->end) return 0;	/* Copying off the end of sbuff */

	memcpy(out, in->p, len);
	out[len] = '\0';

	in->p += len;

	return len;
}

/** Copy as many bytes as possible from the sbuff to another buffer
 *
 * Copy size is limited by available data in sbuff and output buffer length.
 *
 * @param[out] out	Where to copy to.
 * @param[in] outlen	Size of output buffer.
 * @param[in] in	Where to copy from.  Will copy len bytes from current position in buffer.
 * @param[in] len	How many bytes to copy.  If 0 the entire buffer will be copied.
 */
size_t fr_sbuff_strncpy(char *out, size_t outlen, fr_sbuff_t *in, size_t len)
{
	if (unlikely(outlen == 0)) return 0;

	outlen--;	/* Account the \0 byte */

	if (len == SIZE_MAX) len = in->end - in->p;
	if (len > outlen) len = outlen;
	if ((in->p + len) > in->end) len = (in->end - in->p);

	memcpy(out, in->p, len);
	out[len] = '\0';

	in->p += len;

	return len;
}

/** Used to define a number parsing functions for singed integers
 *
 * @param[in] _type	Output type.
 * @param[in] _min	value.
 * @param[in] _max	value.
 */
#define PARSE_INT_DEF(_type, _min, _max) \
size_t fr_sbuff_parse_##_type(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in) \
{ \
	char		buff[sizeof(STRINGIFY(_min)) + 1]; \
	char		*end; \
	size_t		len; \
	long long	num; \
	len = fr_sbuff_strncpy(buff, sizeof(buff), FR_SBUFF_NO_ADVANCE(in), sizeof(STRINGIFY(_min))); \
	if ((len == 0) && err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
	num = strtoll(buff, &end, 10); \
	if (end == buff) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return 0; \
	} \
	if ((num > (_max)) || ((errno == EINVAL) && (num == LLONG_MAX)))  { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_INTEGER_OVERFLOW; \
		*out = (_type)(_max); \
	} else if (num < (_min) || ((errno == EINVAL) && (num == LLONG_MIN))) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_INTEGER_UNDERFLOW; \
		*out = (_type)(_min); \
	} else { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		*out = (_type)(num); \
	} \
	return end - buff; \
}

PARSE_INT_DEF(int8_t, INT8_MIN, INT8_MAX);
PARSE_INT_DEF(int16_t, INT16_MIN, INT16_MAX);
PARSE_INT_DEF(int32_t, INT32_MIN, INT32_MAX);
PARSE_INT_DEF(int64_t, INT64_MIN, INT64_MAX);

/** Used to define a number parsing functions for singed integers
 *
 * @param[in] _type	Output type.
 * @param[in] _max	value.
 */
#define PARSE_UINT_DEF(_type, _max) \
size_t fr_sbuff_parse_##_type(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in) \
{ \
	char			buff[sizeof(STRINGIFY(_max)) + 1]; \
	char			*end; \
	size_t			len; \
	unsigned long long	num; \
	len = fr_sbuff_strncpy(buff, sizeof(buff), FR_SBUFF_NO_ADVANCE(in), sizeof(STRINGIFY(_max))); \
	if ((len == 0) && err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
	num = strtoull(buff, &end, 10); \
	if (end == buff) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return 0; \
	} \
	if ((num > (_max)) || ((errno == EINVAL) && (num == ULLONG_MAX))) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_INTEGER_OVERFLOW; \
		*out = (_type)(_max); \
	} else { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		*out = (_type)(num); \
	} \
	return end - buff; \
}

PARSE_UINT_DEF(uint8_t, UINT8_MAX);
PARSE_UINT_DEF(uint16_t, UINT16_MAX);
PARSE_UINT_DEF(uint32_t, UINT32_MAX);
PARSE_UINT_DEF(uint64_t, UINT64_MAX);
