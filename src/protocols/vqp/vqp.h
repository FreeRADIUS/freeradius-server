#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file src/protocols/vqp/vqp.h
 * @brief Structures and prototypes for Cisco's VLAN Query Protocol
 *
 * @copyright 2007  The FreeRADIUS server project
 * @copyright 2007  Alan DeKok <aland@deployingradius.com>
 */

RCSIDH(vqp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

extern fr_dict_t *dict_vqp;

extern fr_dict_attr_t const *attr_vqp_error_code;
extern fr_dict_attr_t const *attr_vqp_packet_type;
extern fr_dict_attr_t const *attr_vqp_sequence_number;

#define FR_MAX_VMPS_CODE (5)

RADIUS_PACKET		*vqp_recv(TALLOC_CTX *ctx, int sockfd);

bool			fr_vqp_ok(uint8_t const *packet, size_t *packet_len);

int			vqp_send(RADIUS_PACKET *packet);

int			vqp_decode(RADIUS_PACKET *packet);

int			vqp_encode(RADIUS_PACKET *packet, RADIUS_PACKET *original);

ssize_t			vqp_packet_size(uint8_t const *data, size_t data_len);

void			fr_vmps_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len);

ssize_t			fr_vmps_encode(uint8_t *buffer, size_t buflen, uint8_t const *original,
				       int code, uint32_t id, VALUE_PAIR *vps) CC_HINT(nonnull(1));

extern char const	*fr_vmps_codes[FR_MAX_VMPS_CODE];

int			fr_vqp_init(void);

void			fr_vqp_free(void);

#ifdef __cplusplus
}
#endif
