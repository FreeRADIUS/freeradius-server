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
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/dbuff.h>

#define RADIUS_AUTH_VECTOR_OFFSET      		4
#define RADIUS_HEADER_LENGTH			20
#define RADIUS_MAX_STRING_LENGTH		253
#define RADIUS_MAX_TUNNEL_PASSWORD_LENGTH	249
#define RADIUS_AUTH_VECTOR_LENGTH		16
#define RADIUS_CHAP_CHALLENGE_LENGTH		16
#define RADIUS_MESSAGE_AUTHENTICATOR_LENGTH	16
#define RADIUS_MAX_PASS_LENGTH			128
#define RADIUS_MAX_ATTRIBUTES			255
#define RADIUS_MAX_PACKET_SIZE			4096

#define RADIUS_VENDORPEC_USR			429
#define RADIUS_VENDORPEC_LUCENT			4846
#define RADIUS_VENDORPEC_STARENT		8164

/*
 *	protocols/radius/base.c
 */

extern char const *fr_packet_codes[FR_RADIUS_MAX_PACKET_CODE];
#define is_radius_code(_x) ((_x > 0) && (_x < FR_RADIUS_MAX_PACKET_CODE))

#define AUTH_PASS_LEN (RADIUS_AUTH_VECTOR_LENGTH)

#define	FR_TUNNEL_FR_ENC_LENGTH(_x) (2 + 1 + _x + PAD(_x + 1, 16))
extern size_t const fr_radius_attr_sizes[FR_TYPE_MAX + 1][2];
extern fr_table_num_sorted_t const fr_request_types[];
extern size_t fr_request_types_len;
extern bool const fr_request_packets[FR_RADIUS_MAX_PACKET_CODE + 1];

typedef enum {
	DECODE_FAIL_NONE = 0,
	DECODE_FAIL_MIN_LENGTH_PACKET,
	DECODE_FAIL_MIN_LENGTH_FIELD,
	DECODE_FAIL_MIN_LENGTH_MISMATCH,
	DECODE_FAIL_HEADER_OVERFLOW,
	DECODE_FAIL_UNKNOWN_PACKET_CODE,
	DECODE_FAIL_INVALID_ATTRIBUTE,
	DECODE_FAIL_ATTRIBUTE_TOO_SHORT,
	DECODE_FAIL_ATTRIBUTE_OVERFLOW,
	DECODE_FAIL_MA_INVALID_LENGTH,
	DECODE_FAIL_ATTRIBUTE_UNDERFLOW,
	DECODE_FAIL_TOO_MANY_ATTRIBUTES,
	DECODE_FAIL_MA_MISSING,
	DECODE_FAIL_MA_INVALID,
	DECODE_FAIL_UNKNOWN,
	DECODE_FAIL_MAX
} decode_fail_t;

/** subtype values for RADIUS
 *
 *  Order of the flags is important for the flag_foo() checks.
 */
enum {
	FLAG_NONE = 0,					//!< No extra flags
	FLAG_EXTENDED_ATTR,	      			//!< the attribute is an extended attribute
	FLAG_LONG_EXTENDED_ATTR,	      		//!< the attribute is a long extended attribute
	FLAG_CONCAT,					//!< the attribute is concatenated
	FLAG_HAS_TAG,					//!< the attribute has a tag
	FLAG_ABINARY,					//!< the attribute is in "abinary" format
	FLAG_TAGGED_TUNNEL_PASSWORD,   			//!< the attribute has a tag and is encrypted

	FLAG_ENCRYPT_USER_PASSWORD,			//!< Encrypt attribute RFC 2865 style.
	FLAG_ENCRYPT_TUNNEL_PASSWORD,			//!< Encrypt attribute RFC 2868 style.
	FLAG_ENCRYPT_ASCEND_SECRET,			//!< Encrypt attribute ascend style.
};


#define flag_has_tag(_flags)	     (!(_flags)->extra && (((_flags)->subtype == FLAG_HAS_TAG) || ((_flags)->subtype == FLAG_TAGGED_TUNNEL_PASSWORD)))
#define flag_concat(_flags)	     (!(_flags)->extra && (_flags)->subtype == FLAG_CONCAT)
#define flag_abinary(_flags)	     (!(_flags)->extra && (_flags)->subtype == FLAG_ABINARY)
#define flag_encrypted(_flags)	     (!(_flags)->extra && (_flags)->subtype >= FLAG_TAGGED_TUNNEL_PASSWORD)
#define flag_extended(_flags)        (!(_flags)->extra && (((_flags)->subtype == FLAG_EXTENDED_ATTR) || (_flags)->subtype == FLAG_LONG_EXTENDED_ATTR))
#define flag_long_extended(_flags)   (!(_flags)->extra && (_flags)->subtype == FLAG_LONG_EXTENDED_ATTR)
#define flag_tunnel_password(_flags) (!(_flags)->extra && (((_flags)->subtype == FLAG_ENCRYPT_TUNNEL_PASSWORD) || ((_flags)->subtype == FLAG_TAGGED_TUNNEL_PASSWORD)))

/*
 *	protocols/radius/base.c
 */
size_t		fr_radius_attr_len(fr_pair_t const *vp);

int		fr_radius_sign(uint8_t *packet, uint8_t const *original,
			       uint8_t const *secret, size_t secret_len) CC_HINT(nonnull (1,3));
int		fr_radius_verify(uint8_t *packet, uint8_t const *original,
				 uint8_t const *secret, size_t secret_len) CC_HINT(nonnull (1,3));
bool		fr_radius_ok(uint8_t const *packet, size_t *packet_len_p,
			     uint32_t max_attributes, bool require_ma, decode_fail_t *reason) CC_HINT(nonnull (1,2));

ssize_t		fr_radius_ascend_secret(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen,
					char const *secret, uint8_t const vector[static RADIUS_AUTH_VECTOR_LENGTH]);

ssize_t		fr_radius_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, uint16_t *src_port, unsigned int *code);

ssize_t		fr_radius_encode(uint8_t *packet, size_t packet_len, uint8_t const *original,
				 char const *secret, size_t secret_len, int code, int id, fr_pair_t *vps);

ssize_t		fr_radius_encode_dbuff(fr_dbuff_t *dbuff, uint8_t const *original,
				 char const *secret, UNUSED size_t secret_len, int code, int id, fr_pair_t *vps);

ssize_t		fr_radius_decode(TALLOC_CTX *ctx, uint8_t const *packet, size_t packet_len, uint8_t const *original,
				 char const *secret, UNUSED size_t secret_len, fr_cursor_t *cursor) CC_HINT(nonnull(1,2,5,7));

int		fr_radius_init(void);

void		fr_radius_free(void);

/*
 *	protocols/radius/packet.c
 */
ssize_t		fr_radius_packet_encode(fr_radius_packet_t *packet, fr_radius_packet_t const *original,
					char const *secret) CC_HINT(nonnull (1,3));
int		fr_radius_packet_decode(fr_radius_packet_t *packet, fr_radius_packet_t *original,
					uint32_t max_attributes, bool tunnel_password_zeros,
					char const *secret) CC_HINT(nonnull (1,5));

bool		fr_radius_packet_ok(fr_radius_packet_t *packet, uint32_t max_attributes, bool require_ma,
				    decode_fail_t *reason) CC_HINT(nonnull (1));

int		fr_radius_packet_verify(fr_radius_packet_t *packet, fr_radius_packet_t *original,
					char const *secret) CC_HINT(nonnull (1,3));
int		fr_radius_packet_sign(fr_radius_packet_t *packet, fr_radius_packet_t const *original,
				      char const *secret) CC_HINT(nonnull (1,3));

fr_radius_packet_t	*fr_radius_packet_recv(TALLOC_CTX *ctx, int fd, int flags, uint32_t max_attributes, bool require_ma);
int		fr_radius_packet_send(fr_radius_packet_t *packet, fr_radius_packet_t const *original,
				      char const *secret) CC_HINT(nonnull (1,3));

#define fr_radius_packet_log_hex(_log, _packet) _fr_radius_packet_log_hex(_log, _packet, __FILE__, __LINE__);
void		_fr_radius_packet_log_hex(fr_log_t const *log, fr_radius_packet_t const *packet, char const *file, int line) CC_HINT(nonnull);

typedef struct {
	fr_pair_t	*parent;
	fr_cursor_t	cursor;
} fr_radius_tag_ctx_t;

typedef struct {
	TALLOC_CTX		*tmp_ctx;		//!< for temporary things cleaned up during decoding
	uint8_t 		vector[RADIUS_AUTH_VECTOR_LENGTH]; //!< vector for encryption / decryption of data
	char const		*secret;		//!< shared secret.  MUST be talloc'd
	fr_fast_rand_t		rand_ctx;		//!< for tunnel passwords
	int			salt_offset;		//!< for tunnel passwords
	bool 			tunnel_password_zeros;

	uint8_t			tag;			//!< current tag for encoding
	fr_radius_tag_ctx_t    	**tags;			//!< for decoding tagged attributes
} fr_radius_ctx_t;

/*
 *	protocols/radius/abinary.c
 */
ssize_t		fr_radius_encode_abinary(fr_pair_t const *vp, uint8_t *out, size_t outlen);

ssize_t		fr_radius_decode_abinary(fr_pair_t *vp, uint8_t const *data, size_t data_len);

/*
 *	protocols/radius/encode.c
 */
void		fr_radius_encode_chap_password(uint8_t out[static 1 + RADIUS_CHAP_CHALLENGE_LENGTH],
					       uint8_t id, uint8_t const vector[static RADIUS_AUTH_VECTOR_LENGTH],
					       char const *password, size_t password_len) CC_HINT(nonnull(1,3,4));

ssize_t		fr_radius_encode_pair(fr_dbuff_t *dbuff, fr_cursor_t *cursor, void *encoder_ctx);

/*
 *	protocols/radius/decode.c
 */
int		fr_radius_decode_tlv_ok(uint8_t const *data, size_t length, size_t dv_type, size_t dv_length);

ssize_t		fr_radius_decode_password(char *encpw, size_t len, char const *secret, uint8_t const *vector);


ssize_t		fr_radius_decode_tunnel_password(uint8_t *encpw, size_t *len, char const *secret,
						 uint8_t const *vector, bool tunnel_password_zeros);

ssize_t		fr_radius_decode_pair_value(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
					    fr_dict_attr_t const *parent,
					    uint8_t const *data, size_t const attr_len, size_t const packet_len,
					    void *decoder_ctx) CC_HINT(nonnull(1,2,3,4));

ssize_t		fr_radius_decode_tlv(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				     fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t data_len,
				     void *decoder_ctx);

ssize_t		fr_radius_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_t const *dict,
				      uint8_t const *data, size_t data_len, void *decoder_ctx);
