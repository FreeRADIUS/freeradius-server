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
 * @copyright 2007 The FreeRADIUS server project
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */

RCSIDH(vqp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define FR_VQP_MAX_CODE (5)
#define FR_VQP_HDR_LEN (8)
#define FR_VQP_VERSION (1)

bool			fr_vqp_ok(uint8_t const *packet, size_t *packet_len);

int			fr_vqp_decode(TALLOC_CTX *ctx, uint8_t const *data, size_t data_len, VALUE_PAIR **vps, unsigned int *code);

ssize_t			fr_vqp_packet_size(uint8_t const *data, size_t data_len);

void			fr_vqp_print_hex(FILE *fp, uint8_t const *packet, size_t packet_len);

ssize_t			fr_vqp_encode(uint8_t *buffer, size_t buflen, uint8_t const *original,
				       int code, uint32_t id, VALUE_PAIR *vps) CC_HINT(nonnull(1));

extern char const	*fr_vqp_codes[FR_VQP_MAX_CODE];

int			fr_vqp_init(void);

void			fr_vqp_free(void);

#ifdef __cplusplus
}
#endif
