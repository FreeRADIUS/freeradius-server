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

/**
 * $Id$
 *
 * @file io/pair.h
 * @brief Encoder/decoder library interface
 *
 * @copyright 2017-2020 The FreeRADIUS project
 */
#include <freeradius-devel/util/value.h>

/** @name Encoder errors
 * @{
 */

/** Encoder skipped encoding an attribute
 */
#define PAIR_ENCODE_SKIPPED	SSIZE_MIN + 1

/** Skipped encoding attribute
 */
#define PAIR_ENCODE_FATAL_ERROR	SSIZE_MIN

/** @} */

/** @name Decode errors
 * @{
 */

/** Fatal error - Out of memory
 */
#define PAIR_DECODE_OOM		FR_VALUE_BOX_NET_OOM

/** Fatal error - Failed decoding the packet
 */
#define PAIR_DECODE_FATAL_ERROR	FR_VALUE_BOX_NET_ERROR

/** @} */

/** Generic interface for encoding one or more VALUE_PAIRs
 *
 * An encoding function should consume at most, one top level VALUE_PAIR and encode
 * it in the appropriate wire format for the protocol, writing the encoded data to
 * out, and returning the encoded length.
 *
 * The exception to processing one VALUE_PAIR is if multiple VALUE_PAIRs can be aggregated
 * into a single TLV, in which case the encoder may consume as many VALUE_PAIRs as will
 * fit into that TLV.
 *
 * Outlen provides the length of the buffer to write the encoded data to.  The return
 * value must not be greater than outlen.
 *
 * The cursor is used to track how many pairs there are remaining.
 *
 * @param[out] out		Where to write encoded data.  The encoding function should
 *				not assume that this buffer has been initialised, and must
 *				zero out any portions used for padding.
 * @param[in] outlen		The length of the buffer provided.
 * @param[in] cursor		Cursor containing the list of attributes to process.
 * @param[in] encoder_ctx	Any encoder specific data such as secrets or configurables.
 * @return
 *	- PAIR_ENCODE_SKIPPED - The current pair is not valid for encoding and should be skipped.
 *	- PAIR_ENCODE_FATAL_ERROR - Encoding failed in a fatal way. Encoding the packet should be
 *	  aborted in its entirety.
 *	- <0 - The encoder ran out of space and returned the number of bytes as a negative
 *	  integer that would be required to encode the attribute.
 *	- >0 - The number of bytes written to out.
 */
typedef ssize_t (*fr_pair_encode_t)(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx);

/** A generic interface for decoding VALUE_PAIRs
 *
 * A decoding function should decode a single top level VALUE_PAIR from wire format.
 * If this top level VALUE_PAIR is a TLV, multiple child attributes may also be decoded.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] cursor		to insert new pairs into.
 * @param[in] dict		to use to lookup attributes.
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @param[in] decoder_ctx	Any decode specific data such as secrets or configurable.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
typedef ssize_t (*fr_pair_decode_t)(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				    uint8_t const *data, size_t data_len, void *decoder_ctx);
