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
#ifndef _FR_BASE64_H
#define _FR_BASE64_H
/**
 * $Id$
 *
 * @file include/base64.h
 * @brief Encode and decode data in base64 format.
 *
 * @author Simon Josefsson
 * @copyright 2004, 2005, 2006 Free Software Foundation, Inc.
 */
RCSIDH(base64_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* This uses that the expression (n+(k-1))/k means the smallest
   integer >= n/k, i.e., the ceiling of n/k.  */
#define FR_BASE64_ENC_LENGTH(_inlen) ((((_inlen) + 2) / 3) * 4)
#define FR_BASE64_DEC_LENGTH(_inlen) ((3 * ((_inlen) / 4)) + 2)

bool fr_is_base64(char c);

size_t fr_base64_encode(char *out, size_t outlen, uint8_t const *in, size_t inlen);

ssize_t fr_base64_decode(uint8_t *out, size_t outlen, char const *in, size_t inlen);

#ifdef __cplusplus
}
#endif
#endif /* _FR_BASE64_H */
