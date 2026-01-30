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

/*
 * $Id$
 *
 * @file protocols/radius/radius.h
 * @brief Structures and prototypes for base RADIUS functionality.
 *
 * @copyright 1999-2017 The FreeRADIUS server project
 */
#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/io/test_point.h>

#define RADIUS_AUTH_VECTOR_OFFSET      		4
#define RADIUS_HEADER_LENGTH			20
#define RADIUS_MAX_STRING_LENGTH		253
#define RADIUS_MAX_TUNNEL_PASSWORD_LENGTH	249
#define RADIUS_AUTH_VECTOR_LENGTH		16
#define RADIUS_MESSAGE_AUTHENTICATOR_LENGTH	16
#define RADIUS_MAX_PASS_LENGTH			256
#define RADIUS_MAX_ATTRIBUTES			255
#define RADIUS_MAX_PACKET_SIZE			4096

#define RADIUS_VENDORPEC_USR			429
#define RADIUS_VENDORPEC_LUCENT			4846
#define RADIUS_VENDORPEC_STARENT		8164

/*
 *	protocols/radius/base.c
 */


#define FR_RADIUS_PACKET_CODE_VALID(_x) ((_x > 0) && (_x < FR_RADIUS_CODE_MAX))

#define AUTH_PASS_LEN (RADIUS_AUTH_VECTOR_LENGTH)

#define	FR_TUNNEL_FR_ENC_LENGTH(_x) (2 + 1 + _x + PAD(_x + 1, 16))

/** Control whether Message-Authenticator is required in Access-Requests
 *
 * @note Don't change the enum values.  They allow efficient bistmasking.
 */
typedef enum {
	FR_RADIUS_REQUIRE_MA_NO			= 0x00,		//!< Do not require Message-Authenticator
	FR_RADIUS_REQUIRE_MA_YES		= 0x01,		//!< Require Message-Authenticator
	FR_RADIUS_REQUIRE_MA_AUTO		= 0x02,		//!< Only require Message-Authenticator if we've previously
								///< received a packet from this client with Message-Authenticator.
								///< @note This isn't used by the radius protocol code, but may be used
								///< to drive logic in modules.

} fr_radius_require_ma_t;

/** Control whether Proxy-State is allowed in Access-Requests
 *
 * @note Don't change the enum values.  They allow efficient bistmasking.
 */
typedef enum {
	FR_RADIUS_LIMIT_PROXY_STATE_NO		= 0x00,		//!< Do not limit Proxy-State.  Allow proxy-state to be sent in
								///< all packets.
	FR_RADIUS_LIMIT_PROXY_STATE_YES		= 0x01,		//!< Limit Proxy-State.  Do not allow Proxy-State to be sent in
								///< packets which do not have a Message-Authenticator attribute.

	FR_RADIUS_LIMIT_PROXY_STATE_AUTO	= 0x02,		//!< Do not allow Proxy-State unless:
								///< - All packets received from a client have containted proxy state.
								///< - The client has sent a packet with a Message-Authenticator.
								///< @note This isn't used by the radius protocol code, but may be used
								///< to drive logic in modules.
} fr_radius_limit_proxy_state_t;

/** Failure reasons */
typedef enum {
	FR_RADIUS_FAIL_NONE = 0,
	FR_RADIUS_FAIL_MIN_LENGTH_PACKET,
	FR_RADIUS_FAIL_MAX_LENGTH_PACKET,
	FR_RADIUS_FAIL_MIN_LENGTH_FIELD,
	FR_RADIUS_FAIL_MIN_LENGTH_MISMATCH,
	FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE,
	FR_RADIUS_FAIL_UNEXPECTED_REQUEST_CODE,
	FR_RADIUS_FAIL_UNEXPECTED_RESPONSE_CODE,
	FR_RADIUS_FAIL_TOO_MANY_ATTRIBUTES,

	FR_RADIUS_FAIL_INVALID_ATTRIBUTE,

	FR_RADIUS_FAIL_HEADER_OVERFLOW,
	FR_RADIUS_FAIL_ATTRIBUTE_TOO_SHORT,
	FR_RADIUS_FAIL_ATTRIBUTE_OVERFLOW,
	FR_RADIUS_FAIL_ATTRIBUTE_DECODE,

	FR_RADIUS_FAIL_MA_INVALID_LENGTH,
	FR_RADIUS_FAIL_MA_MISSING,
	FR_RADIUS_FAIL_MA_INVALID,
	FR_RADIUS_FAIL_PROXY_STATE_MISSING,

	FR_RADIUS_FAIL_VERIFY,
	FR_RADIUS_FAIL_NO_MATCHING_REQUEST,
	FR_RADIUS_FAIL_IO_ERROR,
	FR_RADIUS_FAIL_MAX
} fr_radius_decode_fail_t;

extern char const *fr_radius_decode_fail_reason[FR_RADIUS_FAIL_MAX + 1];

typedef struct {
	fr_pair_t	*parent;
	fr_dcursor_t	cursor;
} fr_radius_tag_ctx_t;

typedef struct {
	char const		*secret;
	size_t			secret_length;

	bool			secure_transport;	//!< for TLS

	uint64_t		proxy_state;
} fr_radius_ctx_t;

typedef struct {
	fr_radius_ctx_t	const	*common;

	uint8_t const		*request_authenticator;

	fr_fast_rand_t		rand_ctx;		//!< for tunnel passwords
	int			salt_offset;		//!< for tunnel passwords


	uint8_t			tag;			//!< current tag for encoding

	uint8_t			request_code;

	uint8_t			code;
	uint8_t			id;

	bool			add_proxy_state;       	//!< do we add a Proxy-State?
	bool			seen_message_authenticator;
#ifdef NAS_VIOLATES_RFC
	bool			allow_vulnerable_clients; //!< for vendors who violate the RFCs.
#endif

} fr_radius_encode_ctx_t;

typedef struct {
	fr_radius_ctx_t const  	*common;

	uint8_t const		*request_authenticator;

	TALLOC_CTX		*tmp_ctx;		//!< for temporary things cleaned up during decoding
	uint8_t const  		*end;			//!< end of the packet

	fr_radius_decode_fail_t	reason;			//!< reason for decode failure

	uint8_t			request_code;		//!< original code for the request.

	bool 			tunnel_password_zeros;  //!< check for trailing zeros on decode
	bool			verify;			//!< can skip verify for dynamic clients
	bool			require_message_authenticator;
	bool			limit_proxy_state;	//!< Don't allow Proxy-State in requests

	fr_radius_tag_ctx_t    	**tags;			//!< for decoding tagged attributes
	fr_pair_list_t		*tag_root;		//!< Where to insert tag attributes.
	TALLOC_CTX		*tag_root_ctx;		//!< Where to allocate new tag attributes.
} fr_radius_decode_ctx_t;

typedef enum {
	RADIUS_FLAG_ENCRYPT_INVALID = -1,			//!< Invalid encryption flag.
	RADIUS_FLAG_ENCRYPT_NONE = 0,				//!< No encryption.
	RADIUS_FLAG_ENCRYPT_USER_PASSWORD = 1,			//!< Encrypt attribute RFC 2865 style.
	RADIUS_FLAG_ENCRYPT_TUNNEL_PASSWORD = 2,		//!< Encrypt attribute RFC 2868 style.
	RADIUS_FLAG_ENCRYPT_ASCEND_SECRET = 3,			//!< Encrypt attribute ascend style.
} fr_radius_attr_flags_encrypt_t;

typedef struct {
	unsigned int			long_extended : 1;	//!< Attribute is a long extended attribute
	unsigned int			extended : 1;		//!< Attribute is an extended attribute
	unsigned int			concat : 1;		//!< Attribute is concatenated
	unsigned int			has_tag : 1;		//!< Attribute has a tag
	unsigned int			abinary : 1;		//!< Attribute is in "abinary" format
	fr_radius_attr_flags_encrypt_t	encrypt;		//!< Attribute is encrypted
} fr_radius_attr_flags_t;

DIAG_OFF(unused-function)
/** Return RADIUS-specific flags for a given attribute
 */
static inline fr_radius_attr_flags_t const * fr_radius_attr_flags(fr_dict_attr_t const *da)
{
	return fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC);
}

#define fr_radius_flag_has_tag(_da)		fr_radius_attr_flags(_da)->has_tag
#define fr_radius_flag_concat(_da)		fr_radius_attr_flags(_da)->concat
#define fr_radius_flag_abinary(_da)		fr_radius_attr_flags(_da)->abinary
#define fr_radius_flag_encrypted(_da)		fr_radius_attr_flags(_da)->encrypt

static bool fr_radius_flag_extended(fr_dict_attr_t const *da)
{
	fr_radius_attr_flags_t const *flags = fr_radius_attr_flags(da);

	return flags->extended || flags->long_extended;
}

#define fr_radius_flag_long_extended(_da)	fr_radius_attr_flags(_da)->long_extended
DIAG_ON(unused-function)

extern fr_table_num_sorted_t const fr_radius_require_ma_table[];
extern size_t fr_radius_require_ma_table_len;

extern fr_table_num_sorted_t const fr_radius_limit_proxy_state_table[];
extern size_t fr_radius_limit_proxy_state_table_len;

extern fr_table_num_sorted_t const fr_radius_request_name_table[];
extern size_t fr_radius_request_name_table_len;

extern char const *fr_radius_packet_name[FR_RADIUS_CODE_MAX];

/*
 *	protocols/radius/base.c
 */
int		fr_radius_allow_reply(int code, bool allowed[static FR_RADIUS_CODE_MAX]);

int		fr_radius_sign(uint8_t *packet, uint8_t const *vector,
			       uint8_t const *secret, size_t secret_len) CC_HINT(nonnull (1,3));

int		fr_radius_verify(uint8_t *packet, uint8_t const *vector,
				 uint8_t const *secret, size_t secret_len,
				 bool require_message_authenticator, bool limit_proxy_state) CC_HINT(nonnull (1,3));

bool		fr_radius_ok(uint8_t const *packet, size_t *packet_len_p,
			     uint32_t max_attributes, bool require_message_authenticator, fr_radius_decode_fail_t *reason) CC_HINT(nonnull (1,2));

ssize_t		fr_radius_ascend_secret(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen,
					char const *secret, uint8_t const *vector);

ssize_t		fr_radius_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, uint16_t *src_port, unsigned int *code);

ssize_t		fr_radius_encode(fr_dbuff_t *dbuff, fr_pair_list_t *vps, fr_radius_encode_ctx_t *packet_ctx) CC_HINT(nonnull);

ssize_t		fr_radius_decode(TALLOC_CTX *ctx, fr_pair_list_t *out,
				 uint8_t *packet, size_t packet_len,
				 fr_radius_decode_ctx_t *decode_ctx) CC_HINT(nonnull);

ssize_t		fr_radius_decode_simple(TALLOC_CTX *ctx, fr_pair_list_t *out,
					uint8_t *packet, size_t packet_len,
					uint8_t const *vector, char const *secret) CC_HINT(nonnull(1,2,3,6));

int		fr_radius_global_init(void);

void		fr_radius_global_free(void);

/*
 *	protocols/radius/packet.c
 */
ssize_t		fr_packet_encode(fr_packet_t *packet, fr_pair_list_t *list,
					fr_packet_t const *original,
					char const *secret) CC_HINT(nonnull (1,2,4));

bool		fr_packet_ok(fr_packet_t *packet, uint32_t max_attributes, bool require_message_authenticator,
				    fr_radius_decode_fail_t *reason) CC_HINT(nonnull (1));

int		fr_packet_verify(fr_packet_t *packet, fr_packet_t *original,
					char const *secret) CC_HINT(nonnull (1,3));
int		fr_packet_sign(fr_packet_t *packet, fr_packet_t const *original,
				      char const *secret) CC_HINT(nonnull (1,3));

fr_packet_t	*fr_packet_recv(TALLOC_CTX *ctx, int fd, int flags, uint32_t max_attributes, bool require_message_authenticator);
int		fr_packet_send(fr_packet_t *packet, fr_pair_list_t *list,
				      fr_packet_t const *original, char const *secret) CC_HINT(nonnull (1,2,4));

#define fr_packet_log_hex(_log, _packet) _fr_packet_log_hex(_log, _packet, __FILE__, __LINE__)
void		_fr_packet_log_hex(fr_log_t const *log, fr_packet_t const *packet, char const *file, int line) CC_HINT(nonnull);

/*
 *	protocols/radius/abinary.c
 */
ssize_t		fr_radius_encode_abinary(fr_pair_t const *vp, fr_dbuff_t *dbuff);

ssize_t		fr_radius_decode_abinary(fr_pair_t *vp, uint8_t const *data, size_t data_len);

/*
 *	protocols/radius/encode.c
 */
ssize_t		fr_radius_encode_pair(fr_dbuff_t *dbuff, fr_dcursor_t *cursor, void *encode_ctx);

ssize_t		fr_radius_encode_foreign(fr_dbuff_t *dbuff, fr_pair_list_t const *list) CC_HINT(nonnull);

/*
 *	protocols/radius/decode.c
 */
int		fr_radius_decode_tlv_ok(uint8_t const *data, size_t length, size_t dv_type, size_t dv_length);

ssize_t		fr_radius_decode_pair_value(TALLOC_CTX *ctx, fr_pair_list_t *list,
					    fr_dict_attr_t const *parent,
					    uint8_t const *data, size_t const attr_len,
					    void *packet_ctx) CC_HINT(nonnull);

ssize_t		fr_radius_decode_tlv(TALLOC_CTX *ctx, fr_pair_list_t *list,
				     fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t data_len,
				     fr_radius_decode_ctx_t *packet_ctx) CC_HINT(nonnull);

ssize_t		fr_radius_decode_pair(TALLOC_CTX *ctx, fr_pair_list_t *list,
				      uint8_t const *data, size_t data_len, fr_radius_decode_ctx_t *packet_ctx) CC_HINT(nonnull);

ssize_t		fr_radius_decode_foreign(TALLOC_CTX *ctx, fr_pair_list_t *out,
					 uint8_t const *data, size_t data_len) CC_HINT(nonnull);

void		fr_radius_packet_header_log(fr_log_t const *log, fr_packet_t *packet, bool received);

void		fr_radius_packet_log(fr_log_t const *log, fr_packet_t *packet, fr_pair_list_t *list, bool received);
