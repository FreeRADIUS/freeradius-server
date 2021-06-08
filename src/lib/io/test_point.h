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
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/pair.h>
#include "proto.h"
#include "pair.h"

/** Allocate an encoder/decoder ctx
 *
 * @param[out] out	Where the decoder context should be written.
 * @param[in] ctx	to allocate the test point context in.
 * @return proto or pair encoder or decoder ctx.
 */
typedef int (*fr_test_point_ctx_alloc_t)(void **out, TALLOC_CTX *ctx);

/** A generic interface for decoding packets to fr_pair_ts
 *
 * A decoding function should decode a single top level packet from wire format.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] list		where new VPs will be added
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @param[in] decode_ctx	Any decode specific data such as secrets or configurable.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
typedef ssize_t (*fr_tp_proto_decode_t)(TALLOC_CTX *ctx, fr_pair_list_t *list,
					uint8_t const *data, size_t data_len, void *decode_ctx);

/** A generic interface for encoding fr_pair_ts to packets
 *
 * An encoding function should encode multiple VPs to a wire format packet
 *
 * @param[in] ctx		to allocate any data in
 * @param[in] vps		vps to encode
 * @param[in] data		buffer where data can be written
 * @param[in] data_len		The length of the buffer, i.e. maximum packet length
 * @param[in] encode_ctx	Any enccode specific data such as secrets or configurable.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were encoded
 */
typedef ssize_t (*fr_tp_proto_encode_t)(TALLOC_CTX *ctx, fr_pair_list_t *vps,
					uint8_t *data, size_t data_len, void *encode_ctx);

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
typedef ssize_t (*fr_tp_pair_encode_t)(fr_dbuff_t *out, fr_dcursor_t *cursor, void *encode_ctx);

/** A generic interface for decoding fr_pair_ts
 *
 * A decoding function should decode a single top level fr_pair_t from wire format.
 * If this top level fr_pair_t is a TLV, multiple child attributes may also be decoded.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] cursor		to insert new pairs into.
 * @param[in] dict		to use to lookup attributes.
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @param[in] decode_ctx	Any decode specific data such as secrets or configurable.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
typedef ssize_t (*fr_tp_pair_decode_t)(TALLOC_CTX *ctx, fr_dcursor_t *cursor, fr_dict_t const *dict,
				       uint8_t const *data, size_t data_len, void *decode_ctx);

/** Entry point for protocol decoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_tp_proto_decode_t		func;		//!< Decoder for proto layer.
} fr_test_point_proto_decode_t;

/** Entry point for protocol encoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_tp_proto_encode_t		func;		//!< Encoder for proto layer.
	fr_dcursor_eval_t		eval;		//!< Evaluation function to filter
							///< attributes to encode.
} fr_test_point_proto_encode_t;

/** Entry point for pair decoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_tp_pair_decode_t		func;		//!< Decoder for pairs.
} fr_test_point_pair_decode_t;

/** Entry point for pair encoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_tp_pair_encode_t		func;		//!< Encoder for pairs.
	fr_dcursor_iter_t		next_encodable;	//!< Iterator to use to select attributes
							///< to encode.
	fr_dcursor_eval_t		eval;		//!< Evaluation function to filter
							///< attributes to encode.
} fr_test_point_pair_encode_t;
