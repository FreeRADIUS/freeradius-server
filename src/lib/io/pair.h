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
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/server/request.h>

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

/** Return the correct adjusted slen for errors
 *
 * @param[in] slen	returned from the function we called.
 * @param[in] start	of the buffer.
 * @param[in] p		offset passed to function which returned the slen.
 */
static inline ssize_t fr_pair_decode_slen(ssize_t slen, uint8_t const *start, uint8_t const *p)
{
	if (slen > 0) return slen;

	switch (slen) {
	case PAIR_DECODE_OOM:
	case PAIR_DECODE_FATAL_ERROR:
		return slen;

	default:
		return slen - (p - start);
	}
}

/** Determine if the return code for an encoding function is a fatal error
 *
 */
static inline bool fr_pair_encode_is_error(ssize_t slen)
{
	if (slen == PAIR_ENCODE_FATAL_ERROR) return true;
	return false;
}

/** Checks if we have sufficient buffer space, and returns how much space we'd need as a negative integer
 *
 */
#define FR_PAIR_ENCODE_HAVE_SPACE(_p, _end, _num) if (((_p) + (_num)) > (_end)) return (_end) - ((_p) + (_num));

/** @} */

/** Generic interface for encoding one or more fr_pair_ts
 *
 * An encoding function should consume at most, one top level fr_pair_t and encode
 * it in the appropriate wire format for the protocol, writing the encoded data to
 * out, and returning the encoded length.
 *
 * The exception to processing one fr_pair_t is if multiple fr_pair_ts can be aggregated
 * into a single TLV, in which case the encoder may consume as many fr_pair_ts as will
 * fit into that TLV.
 *
 * Outlen provides the length of the buffer to write the encoded data to.  The return
 * value must not be greater than outlen.
 *
 * The cursor is used to track how many pairs there are remaining.
 *
 * @param[out] out		Where to write the encoded data.
 * @param[in] cursor		Cursor containing the list of attributes to process.
 * @param[in] encode_ctx	Any encoder specific data such as secrets or configurables.
 * @return
 *	- PAIR_ENCODE_SKIPPED - The current pair is not valid for encoding and should be skipped.
 *	- PAIR_ENCODE_FATAL_ERROR - Encoding failed in a fatal way. Encoding the packet should be
 *	  aborted in its entirety.
 *	- <0 - The encoder ran out of space and returned the number of bytes as a negative
 *	  integer that would be required to encode the attribute.
 *	- >0 - The number of bytes written to out.
 */
typedef ssize_t (*fr_pair_encode_t)(fr_dbuff_t *out, fr_dcursor_t *cursor, void *encode_ctx);

/** A generic interface for decoding fr_pair_ts
 *
 * A decoding function should decode a single top level fr_pair_t from wire format.
 * If this top level fr_pair_t is a TLV, multiple child attributes may also be decoded.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] out		to insert new pairs into.
 * @param[in] dict		to use to lookup attributes.
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @param[in] decode_ctx	Any decode specific data such as secrets or configurable.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
typedef ssize_t (*fr_pair_decode_t)(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict,
				    uint8_t const *data, size_t data_len, void *decode_ctx);

int fr_pair_decode_value_box_list(TALLOC_CTX *ctx, fr_pair_list_t *out,
				  request_t *request, void *decode_ctx, fr_pair_decode_t decode,
				  fr_value_box_list_t *in);
