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
 * @file eap_base.h
 * @brief Interface into the base EAP library
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(eap_base_h, "$Id$")

#include "eap_types.h"

/*
 * interfaces in eapcommon.c
 */
eap_type_t		eap_name2type(char const *name);
char const		*eap_type2name(eap_type_t method);
int			eap_wireformat(eap_packet_t *reply);

VALUE_PAIR		*eap_packet2vp(RADIUS_PACKET *packet, eap_packet_raw_t const *reply);
eap_packet_raw_t	*eap_vp2packet(TALLOC_CTX *ctx, VALUE_PAIR *vps);
void			eap_add_reply(REQUEST *request, fr_dict_attr_t const *da, uint8_t const *value, int len);

rlm_rcode_t		eap_virtual_server(REQUEST *request, REQUEST *fake,
					   eap_session_t *eap_session, char const *virtual_server);

int			eap_base_init(void);

void			eap_base_free(void);

