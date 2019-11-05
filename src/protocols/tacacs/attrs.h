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
 * @file src/protocols/tacacs/attrs.h
 * @brief TACACS attributes
 *
 * @copyright 2018 The FreeRADIUS project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(tacacs_attrs_h, "$Id$")

extern fr_dict_t const *dict_tacacs;

extern fr_dict_attr_t const *attr_tacacs_accounting_flags;
extern fr_dict_attr_t const *attr_tacacs_accounting_status;
extern fr_dict_attr_t const *attr_tacacs_action;
extern fr_dict_attr_t const *attr_tacacs_authentication_flags;
extern fr_dict_attr_t const *attr_tacacs_authentication_method;
extern fr_dict_attr_t const *attr_tacacs_authentication_service;
extern fr_dict_attr_t const *attr_tacacs_authentication_status;
extern fr_dict_attr_t const *attr_tacacs_authentication_type;
extern fr_dict_attr_t const *attr_tacacs_authorization_status;
extern fr_dict_attr_t const *attr_tacacs_client_port;
extern fr_dict_attr_t const *attr_tacacs_data;
extern fr_dict_attr_t const *attr_tacacs_packet_type;
extern fr_dict_attr_t const *attr_tacacs_privilege_level;
extern fr_dict_attr_t const *attr_tacacs_remote_address;
extern fr_dict_attr_t const *attr_tacacs_sequence_number;
extern fr_dict_attr_t const *attr_tacacs_server_message;
extern fr_dict_attr_t const *attr_tacacs_session_id;
extern fr_dict_attr_t const *attr_tacacs_user_message;
extern fr_dict_attr_t const *attr_tacacs_user_name;
extern fr_dict_attr_t const *attr_tacacs_version_minor;
