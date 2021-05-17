#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Encode and decode data in base64 format
 *
 * @file src/lib/util/base64.h
 *
 * @author Simon Josefsson
 * @copyright 2004, 2005, 2006 Free Software Foundation, Inc.
 */
RCSIDH(base64_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* This uses that the expression (n+(k-1))/k means the smallest
   integer >= n/k, i.e., the ceiling of n/k.  */
#define FR_BASE64_ENC_LENGTH(_inlen) ((((_inlen) + 2) / 3) * 4)
#define FR_BASE64_DEC_LENGTH(_inlen) ((3 * ((_inlen) / 4)) + 2)

extern char const fr_base64_str[];
extern uint8_t const fr_base64_alphabet_decode[UINT8_MAX];

#define		fr_is_base64(_c) fr_base64_nstd(_c, fr_base64_alphabet_decode)
bool		fr_is_base64_nstd(char c, uint8_t const alphabet[static UINT8_MAX]);

size_t		fr_base64_encode(char * restrict out, size_t outlen, uint8_t const * restrict in, size_t inlen);

#define		fr_base64_decode(_out, _outlen, _in, _inlen) fr_base64_decode_nstd(_out, _outlen, _in, _inlen, fr_base64_alphabet_decode)
ssize_t		fr_base64_decode_nstd(uint8_t * restrict out, size_t outlen, char const * restrict in, size_t inlen, uint8_t const alphabet[static UINT8_MAX]);



#ifdef __cplusplus
}
#endif
