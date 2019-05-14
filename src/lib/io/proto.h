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
 * @file io/proto.h
 * @brief Encoder/decoder library interface
 *
 * @copyright 2017 The FreeRADIUS project
 */
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/util/value.h>

#define FR_PROTO_STACK_MAX	10

/** Option contexts
 *
 * Exported by the protocol library.
 * Indicates which option contexts the library implements.
 */
typedef enum {
	PROTO_OPT_GROUP_CUSTOM		= 0x01,		//!< Custom options exported by the library.
							///< See library header file for more information.
	PROTO_OPT_GROUP_L2		= 0x02,		//!< Generic layer 2 options.
	PROTO_OPT_GROUP_L3		= 0x04,		//!< Generic layer 3 options.
	PROTO_OPT_GROUP_L4		= 0x08,		//!< Generic layer 4 options.
	PROTO_OPT_GROUP_APPLICATION	= 0x10		//!< Generic application options.
} fr_proto_opt_group_t;

/** Layer 2 options such as Media addresses
 *
 */
typedef enum {
	PROTO_OPT_L2_PAYLOAD_LEN = 0,
	PROTO_OPT_L2_SRC_ADDRESS,			//!< Source address.
	PROTO_OPT_L2_DST_ADDRESS,			//!< Destination address.
	PROTO_OPT_L2_NEXT_PROTOCOL			//!< Next protocol (if available).
} fr_proto_opt_l2_t;

/** Layer 3 options, such as IP address
 *
 */
typedef enum {
	PROTO_OPT_L3_PAYLOAD_LEN = 0,			//!< The size of payload data.
	PROTO_OPT_L3_SRC_ADDRESS,			//!< Source address.
	PROTO_OPT_L3_DST_ADDRESS,			//!< Destination address.
	PROTO_OPT_L3_NEXT_PROTOCOL,			//!< Next protocol (if available).
} fr_proto_opt_l3_t;

/** Layer 4 options, such as port number
 *
 */
typedef enum {
	PROTO_OPT_L4_PAYLOAD_LEN = 0,			//!< The size of payload data.
	PROTO_OPT_L4_SRC_PORT,				//!< Source port.
	PROTO_OPT_L4_DST_PORT,				//!< Destination port.
} fr_proto_opt_l4_t;

/** Application options
 *
 */
typedef enum {
	PROTO_OPT_PAIRS = 0,				//!< Attribute Value Pairs belonging
							///< to the application.
} fr_proto_opt_app_t;

/** Decode a packet header
 *
 * This function is the opposite of #fr_proto_encode_t.
 *
 * The "decode" function is ONLY for decoding data.  It should be
 * aware of the protocol (e.g. RADIUS), but it MUST NOT know anything
 * about the underlying network transport (e.g. UDP), and it MUST NOT
 * know anything about how the data will be used.
 *
 * @param[out] proto_ctx	populated with information learned from the packet header.
 * @param[in] data		the raw packet data.
 * @param[in] data_len		the length of the raw data.
 * @return
 *	- >0 the number of bytes consumed.
 *	- <=0 the offset (as a negative integer), of where a parsing error occurred.
 */
typedef ssize_t (*fr_proto_decode_t)(void *proto_ctx, uint8_t const *data, size_t data_len);

/** Encode a packet header
 *
 * This function is the opposite of #fr_proto_decode_t.
 *
 * The "encode" function is ONLY for encoding data.  It should be
 * aware of the protocol (e.g. RADIUS), but it MUST NOT know anything
 * about the underlying network transport (e.g. UDP), and it MUST NOT
 * know anything about how the data will be used (e.g. reject delay
 * on Access-Reject)
 *
 * @param[in] proto_ctx		as created by #fr_proto_decode_t.
 * @param[out] buffer		the buffer where the raw packet will be written.
 * @param[in] buffer_len	the length of the buffer.
 * @return
 *	- <0 on error.  May indicate the number of bytes (as a negative) offset,
 *	  that would have been needed to encode the total packet data.
 *	- >=0 length of the encoded data in the buffer, will be <=buffer_len
 */
typedef ssize_t (*fr_proto_encode_t)(void *proto_ctx, uint8_t *buffer, size_t buffer_len);

/** Invert the src and address fields of a proto_ctx
 *
 * This is used to create a response to a decoded packet.
 *
 * @param[in] proto_ctx	to manipulate.
 */
typedef void (*fr_proto_invert_t)(void *proto_ctx);

/** Retrieve a protocol option
 *
 * @param[in] out		boxed value containing the option.
 * @param[in] proto_ctx		to retrieve data from.
 * @param[in] opt_group		Option group to use.
 * @param[in] opt		to retrieve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*fr_proto_get_option_t)(fr_value_box_t *out, void const *proto_ctx,
				     fr_proto_opt_group_t opt_group, int opt);

/** Set a protocol option
 *
 * @param[in] proto_ctx	to set option in.
 * @param[in] opt_group		Option group to use.
 * @param[in] opt		to set.
 * @param[in] in		value to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*fr_proto_set_option_t)(void *proto_ctx, fr_proto_opt_group_t opt_group, int opt, fr_value_box_t *in);


/** The public structure exported by protocol encoding/decoding libraries
 *
 */
typedef struct {
	DL_MODULE_COMMON;					//!< Common fields to all loadable modules.

	size_t				proto_ctx_size;		//!< Size required for the packet ctx structure.

	int				opt_group;		//!< Option groups implemented by proto lib.

	fr_proto_decode_t		decode;			//!< Function to decode a protocol/header.
	fr_proto_encode_t		encode;			//!< Function to encode a protocol/header.
	fr_proto_invert_t		invert;
	fr_proto_get_option_t		get_option;		//!< Get data from the proto_ctx.
	fr_proto_set_option_t		set_option;		//!< Set data in the proto_ctx.
} fr_proto_lib_t;

/** A protocol transcoder stack frame
 *
 */
typedef struct {
	fr_proto_lib_t const	*proto;				//!< Protocol library.
	void			*proto_ctx;			//!< Packet ctx produced by the decoder,
								///< or populated for consumption by the
								///< encoder.
} fr_proto_stack_frame_t;

/** Protocol transcoder stack
 *
 * Describes a series of encoders/decoders data must pass through
 */
typedef struct {
	fr_proto_stack_frame_t	frame[FR_PROTO_STACK_MAX + 1];
	int			depth;
} fr_proto_stack_t;
