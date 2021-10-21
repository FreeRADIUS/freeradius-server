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
 * @file src/protocols/dhcpv6/attrs.h
 * @brief DHCP attributes
 *
 * @copyright 2018 The FreeRADIUS project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(dhcpv6_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern fr_dict_t const *dict_dhcpv6;

extern fr_dict_attr_t const *attr_packet_type;
extern fr_dict_attr_t const *attr_transaction_id;
extern fr_dict_attr_t const *attr_option_request;
extern fr_dict_attr_t const *attr_hop_count;
extern fr_dict_attr_t const *attr_relay_link_address;
extern fr_dict_attr_t const *attr_relay_peer_address;
extern fr_dict_attr_t const *attr_relay_message;

/*
 *	A private function that is used only in base.c and encode.c
 */
void *fr_dhcpv6_next_encodable(fr_dlist_head_t *list, void *to_eval, void *uctx);
