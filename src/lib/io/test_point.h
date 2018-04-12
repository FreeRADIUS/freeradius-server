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
 * @param[in] ctx	to allocate the test point context in.
 * @return proto or pair encoder or decoder ctx.
 */
typedef void *(*fr_test_point_ctx_alloc_t)(TALLOC_CTX *ctx);

/** Entry point for protocol decoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_proto_decode_t		func;		//!< Decoder for proto layer.
} fr_test_point_proto_decode_t;

/** Entry point for protocol encoders
 *
 */
typedef struct {
	fr_test_point_ctx_alloc_t	test_ctx;	//!< Allocate a test ctx for the encoder.
	fr_proto_encode_t		func;		//!< Encoder for proto layer.
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
