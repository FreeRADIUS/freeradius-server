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
#ifndef _FR_IO_PAIR_H
#define _FR_IO_PAIR_H

#include <freeradius-devel/value.h>

/**
 * $Id$
 *
 * @file io/pair.h
 * @brief Encoder/decoder library interface
 *
 * @copyright 2017 The FreeRADIUS project
 */

typedef ssize_t (*fr_pair_encode_t)(uint8_t *out, size_t outlen, vp_cursor_t *cursor, void *encoder_ctx);

typedef ssize_t (*fr_pair_decode_t)(TALLOC_CTX *ctx, vp_cursor_t *cursor,
				    uint8_t const *data, size_t data_len, void *decoder_ctx);

#endif /* _FR_IO_PAIR_H */

