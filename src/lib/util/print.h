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

/** Functions to produce and parse the FreeRADIUS presentation format
 *
 * @file src/lib/util/print.h
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSIDH(print_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/talloc.h>

#include <stddef.h>
#include <stdint.h>

size_t		fr_utf8_char(uint8_t const *str, ssize_t inlen);
ssize_t		fr_utf8_str(uint8_t const *str, ssize_t inlen);
char const     	*fr_utf8_strchr(int *chr_len, char const *str, ssize_t inlen, char const *chr);
size_t		fr_snprint(char *out, size_t outlen, char const *in, ssize_t inlen, char quote);
size_t		fr_snprint_len(char const *in, ssize_t inlen, char quote);
char		*fr_asprint(TALLOC_CTX *ctx, char const *in, ssize_t inlen, char quote);
char		*fr_vasprintf(TALLOC_CTX *ctx, char const *fmt, va_list ap);
char		*fr_asprintf(TALLOC_CTX *ctx, char const *fmt, ...) CC_HINT(format (printf, 2, 3));
ssize_t 	fr_fprintf(FILE *stream, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

#define		is_truncated(_ret, _max) ((_ret) >= (size_t)(_max))
#define		truncate_len(_ret, _max) (((_ret) >= (size_t)(_max)) ? (((size_t)(_max)) - 1) : _ret)
