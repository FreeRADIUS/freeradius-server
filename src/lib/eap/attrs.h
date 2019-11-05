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
 * @file lib/eap/attrs.h
 * @brief EAP dictionary attributes
 *
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(lib_eap_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern fr_dict_t const *dict_freeradius;
extern fr_dict_t const *dict_radius;

extern fr_dict_attr_t const *attr_chbind_response_code;
extern fr_dict_attr_t const *attr_eap_session_id;
extern fr_dict_attr_t const *attr_eap_type;
extern fr_dict_attr_t const *attr_virtual_server;

extern fr_dict_attr_t const *attr_message_authenticator;
extern fr_dict_attr_t const *attr_eap_channel_binding_message;
extern fr_dict_attr_t const *attr_eap_message;
extern fr_dict_attr_t const *attr_eap_msk;
extern fr_dict_attr_t const *attr_eap_emsk;
extern fr_dict_attr_t const *attr_freeradius_proxied_to;
extern fr_dict_attr_t const *attr_ms_mppe_send_key;
extern fr_dict_attr_t const *attr_ms_mppe_recv_key;
extern fr_dict_attr_t const *attr_user_name;
extern fr_dict_attr_t const *attr_state;
