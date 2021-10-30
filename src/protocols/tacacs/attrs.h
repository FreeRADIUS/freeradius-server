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

extern HIDDEN fr_dict_t const *dict_tacacs;

extern HIDDEN fr_dict_attr_t const *attr_tacacs_accounting_flags;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_accounting_status;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_action;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_authentication_flags;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_authentication_continue_flags;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_authentication_method;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_authentication_service;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_authentication_status;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_authentication_type;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_authorization_status;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_argument_list;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_client_port;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_data;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_flags;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_length;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_packet;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_packet_body_type;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_packet_type;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_privilege_level;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_remote_address;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_sequence_number;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_server_message;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_session_id;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_user_message;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_user_name;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_version_major;
extern HIDDEN fr_dict_attr_t const *attr_tacacs_version_minor;
