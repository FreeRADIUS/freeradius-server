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
#include <freeradius-devel/util/log.h>

#define AUTH_VECTOR_LEN		16
#define CHAP_VALUE_LENGTH       16
#define FR_MAX_STRING_LEN	254	/* RFC2138: string 0-253 octets */
#define RADIUS_MAX_ATTRIBUTES	255

#ifdef _LIBRADIUS
#  define RADIUS_HDR_LEN	20
#  define VENDORPEC_USR		429
#  define VENDORPEC_LUCENT	4846
#  define VENDORPEC_STARENT	8164
#  define DEBUG			if (fr_debug_lvl && fr_log_fp) fr_printf_log
#endif

/*
 *	protocols/radius/base.c
 */

#define	FR_MAX_PACKET_CODE (53)
extern char const *fr_packet_codes[FR_MAX_PACKET_CODE];
#define is_radius_code(_x) ((_x > 0) && (_x < FR_MAX_PACKET_CODE))

#define AUTH_PASS_LEN (AUTH_VECTOR_LEN)
#define MAX_PASS_LEN (128)
#define	FR_TUNNEL_FR_ENC_LENGTH(_x) (2 + 1 + _x + PAD(_x + 1, 16))
extern size_t const fr_radius_attr_sizes[FR_TYPE_MAX + 1][2];
extern FR_NAME_NUMBER const fr_request_types[];
extern bool const fr_request_packets[FR_CODE_MAX + 1];

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
	DECODE_FAIL_MAX
} decode_fail_t;

/*
 *	protocols/radius/base.c
 */
size_t		fr_radius_attr_len(VALUE_PAIR const *vp);

int		fr_radius_sign(uint8_t *packet, uint8_t const *original,
			       uint8_t const *secret, size_t secret_len) CC_HINT(nonnull (1,3));
int		fr_radius_verify(uint8_t *packet, uint8_t const *original,
				 uint8_t const *secret, size_t secret_len) CC_HINT(nonnull (1,3));
bool		fr_radius_ok(uint8_t const *packet, size_t *packet_len_p,
			     uint32_t max_attributes, bool require_ma, decode_fail_t *reason) CC_HINT(nonnull (1,2));

void		fr_radius_ascend_secret(uint8_t *digest, uint8_t const *vector,
					char const *secret, uint8_t const *value) CC_HINT(nonnull);

ssize_t		fr_radius_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, uint16_t *src_port, unsigned int *code);

ssize_t		fr_radius_encode(uint8_t *packet, size_t packet_len, uint8_t const *original,
				 char const *secret, UNUSED size_t secret_len, int code, int id, VALUE_PAIR *vps);

ssize_t		fr_radius_decode(TALLOC_CTX *ctx, uint8_t *packet, size_t packet_len, uint8_t const *original,
				 char const *secret, UNUSED size_t secret_len, VALUE_PAIR **vps) CC_HINT(nonnull);


void		fr_radius_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len);

int		fr_radius_init(void);

void		fr_radius_free(void);

/*
 *	protocols/radius/packet.c
 */
int		fr_radius_packet_encode(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
					char const *secret) CC_HINT(nonnull (1,3));
int		fr_radius_packet_decode(RADIUS_PACKET *packet, RADIUS_PACKET *original,
					uint32_t max_attributes, bool tunnel_password_zeros,
					char const *secret) CC_HINT(nonnull (1,5));

bool		fr_radius_packet_ok(RADIUS_PACKET *packet, uint32_t max_attributes, bool require_ma,
				    decode_fail_t *reason) CC_HINT(nonnull (1));

int		fr_radius_packet_verify(RADIUS_PACKET *packet, RADIUS_PACKET *original,
					char const *secret) CC_HINT(nonnull (1,3));
int		fr_radius_packet_sign(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
				      char const *secret) CC_HINT(nonnull (1,3));

RADIUS_PACKET	*fr_radius_packet_recv(TALLOC_CTX *ctx, int fd, int flags, uint32_t max_attributes, bool require_ma);
int		fr_radius_packet_send(RADIUS_PACKET *packet, RADIUS_PACKET const *original,
				      char const *secret) CC_HINT(nonnull (1,3));

void		fr_radius_packet_print_hex(RADIUS_PACKET const *packet) CC_HINT(nonnull);


typedef struct fr_radius_ctx {
	uint8_t const		*vector;		//!< vector for encryption / decryption of data
	char const		*secret;		//!< shared secret.  MUST be talloc'd
	bool 			tunnel_password_zeros;
	fr_dict_attr_t const	*root;
} fr_radius_ctx_t;

/*
 *	protocols/radius/encode.c
 */
int		fr_radius_encode_password(char *encpw, size_t *len, char const *secret, uint8_t const *vector);

int		fr_radius_encode_tunnel_password(char *encpw, size_t *len, char const *secret, uint8_t const *vector);

int		fr_radius_encode_chap_password(uint8_t *output, RADIUS_PACKET *packet, int id, VALUE_PAIR *password);

ssize_t		fr_radius_encode_pair(uint8_t *out, size_t outlen, fr_cursor_t *cursor, void *encoder_ctx);

/*
 *	protocols/radius/decode.c
 */
int		fr_radius_decode_tlv_ok(uint8_t const *data, size_t length, size_t dv_type, size_t dv_length);

ssize_t		fr_radius_decode_password(char *encpw, size_t len, char const *secret, uint8_t const *vector);


ssize_t		fr_radius_decode_tunnel_password(uint8_t *encpw, size_t *len, char const *secret,
						 uint8_t const *vector, bool tunnel_password_zeros);

ssize_t		fr_radius_decode_pair_value(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
					    uint8_t const *data, size_t const attr_len, size_t const packet_len,
					    void *decoder_ctx);

ssize_t		fr_radius_decode_tlv(TALLOC_CTX *ctx, fr_cursor_t *cursor, fr_dict_attr_t const *parent,
				     uint8_t const *data, size_t data_len,
				     void *decoder_ctx);

ssize_t		fr_radius_decode_pair(TALLOC_CTX *ctx, fr_cursor_t *cursor, uint8_t const *data, size_t data_len,
				      void *decoder_ctx);
