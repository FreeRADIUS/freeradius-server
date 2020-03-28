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

#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/pair.h>

#include <talloc.h>

/*
 *	Encoding byte 0
 */
#define FR_INTERNAL_MASK_TYPE		0xe0
#define FR_INTERNAL_MASK_LEN		0x1c
#define FR_INTERNAL_FLAG_EXTENDED	0x01
#define FR_INTERNAL_FLAG_TAINTED	0x02

/*
 *	Encoding byte 1
 */
#define FR_INTERNAL_FLAG_INTERNAL	0x80

/*
 * $Id$
 *
 * @file protocols/internal/internal.h
 * @brief Structures and prototypes for the internal encoder/decoder.
 *
 * @copyright 2020 The FreeRADIUS server project
 */

ssize_t fr_internal_encode_pair(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx);

ssize_t fr_internal_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				uint8_t const *data, size_t data_len, void *decoder_ctx);
