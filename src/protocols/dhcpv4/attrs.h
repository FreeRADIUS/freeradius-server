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
 * @file src/protocols/dhcpv4/attrs.h
 * @brief DHCP attributes
 *
 * @copyright 2018 The FreeRADIUS project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(dhcpv4_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern fr_dict_t const *dict_dhcpv4;

extern fr_dict_attr_t const *attr_dhcp_boot_filename;
extern fr_dict_attr_t const *attr_dhcp_client_hardware_address;
extern fr_dict_attr_t const *attr_dhcp_client_ip_address;
extern fr_dict_attr_t const *attr_dhcp_flags;
extern fr_dict_attr_t const *attr_dhcp_gateway_ip_address;
extern fr_dict_attr_t const *attr_dhcp_hardware_address_length;
extern fr_dict_attr_t const *attr_dhcp_hardware_type;
extern fr_dict_attr_t const *attr_dhcp_hop_count;
extern fr_dict_attr_t const *attr_dhcp_number_of_seconds;
extern fr_dict_attr_t const *attr_dhcp_opcode;
extern fr_dict_attr_t const *attr_dhcp_server_host_name;
extern fr_dict_attr_t const *attr_dhcp_server_ip_address;
extern fr_dict_attr_t const *attr_dhcp_transaction_id;
extern fr_dict_attr_t const *attr_dhcp_your_ip_address;
extern fr_dict_attr_t const *attr_dhcp_dhcp_maximum_msg_size;
extern fr_dict_attr_t const *attr_dhcp_interface_mtu_size;
extern fr_dict_attr_t const *attr_dhcp_message_type;
extern fr_dict_attr_t const *attr_dhcp_parameter_request_list;
extern fr_dict_attr_t const *attr_dhcp_overload;
extern fr_dict_attr_t const *attr_dhcp_vendor_class_identifier;
