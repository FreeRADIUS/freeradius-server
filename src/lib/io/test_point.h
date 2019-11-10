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
#include "proto.h"
#include "pair.h"

/** Allocate an encoder/decoder ctx
 *
 * @param[out] out	Where the decoder context should be written.
 * @param[in] ctx	to allocate the test point context in.
 * @return proto or pair encoder or decoder ctx.
 */
typedef int (*fr_test_point_ctx_alloc_t)(void **out, TALLOC_CTX *ctx);

/** A generic interface for decoding packets to VALUE_PAIRs
 *
 * A decoding function should decode a single top level packet from wire format.
 *
 * @param[in] ctx		to allocate new pairs in.
 * @param[in] vps		where new VPs will be added
 * @param[in] data		to decode.
 * @param[in] data_len		The length of the incoming data.
 * @param[in] decoder_ctx	Any decode specific data such as secrets or configurable.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were decoded.
 */
typedef ssize_t (*fr_tp_proto_decode_t)(TALLOC_CTX *ctx, VALUE_PAIR **vps,
					uint8_t const *data, size_t data_len, void *decoder_ctx);

/** A generic interface for encoding VALUE_PAIRs to packets
 *
 * An encoding function should encode multiple VPs to a wire format packet
 *
 * @param[in] ctx		to allocate any data in
 * @param[in] vps		vps to encode
 * @param[in] data		buffer where data can be written
 * @param[in] data_len		The length of the buffer, i.e. maximum packet length
 * @param[in] encoder_ctx	Any enccode specific data such as secrets or configurable.
 * @return
 *	- <= 0 on error.  May be the offset (as a negative value) where the error occurred.
 *	- > 0 on success.  How many bytes were encoded
 */
typedef ssize_t (*fr_tp_proto_encode_t)(TALLOC_CTX *ctx, VALUE_PAIR *vps,
					uint8_t *data, size_t data_len, void *encoder_ctx);

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
} fr_test_point_proto_encode_t;

/** Entry point for pair decoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_pair_decode_t		func;		//!< Decoder for pairs.
} fr_test_point_pair_decode_t;

/** Entry point for pair encoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_pair_encode_t		func;		//!< Encoder for pairs.
} fr_test_point_pair_encode_t;
