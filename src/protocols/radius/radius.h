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
#ifndef _FR_RADIUS_RADIUS_H
#define _FR_RADIUS_RADIUS_H
/*
 * $Id$
 *
 * @file radius/radius.h
 * @brief Structures and prototypes for base RADIUS functionality.
 *
 * @copyright 1999-2017 The FreeRADIUS server project
 */

/*
 *	protocols/radius/base.c
 */
#define AUTH_PASS_LEN (AUTH_VECTOR_LEN)
#define MAX_PASS_LEN (128)
#define	FR_TUNNEL_PW_ENC_LENGTH(_x) (2 + 1 + _x + PAD(_x + 1, 16))
extern FR_NAME_NUMBER const fr_request_types[];

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

int		fr_radius_sign(uint8_t *packet, uint8_t const *original,
			       uint8_t const *secret, size_t secret_len) CC_HINT(nonnull (1,3));
int		fr_radius_verify(uint8_t *packet, uint8_t const *original,
				 uint8_t const *secret, size_t secret_len) CC_HINT(nonnull (1,3));
bool		fr_radius_ok(uint8_t const *packet, size_t *packet_len_p, bool require_ma,
			     decode_fail_t *reason) CC_HINT(nonnull (1,2));

void		fr_radius_ascend_secret(uint8_t *digest, uint8_t const *vector,
					char const *secret, uint8_t const *value) CC_HINT(nonnull);

ssize_t		fr_radius_recv_header(int sockfd, fr_ipaddr_t *src_ipaddr, uint16_t *src_port, unsigned int *code);

#endif	/* _FR_RADIUS_RADIUS_H */
