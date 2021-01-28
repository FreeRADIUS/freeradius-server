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
 * @file src/protocols/vmps/vmps.h
 * @brief Structures and prototypes for Cisco's VLAN Query Protocol
 *
 * @copyright 2018 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include "vmps.h"
#include "attrs.h"

static uint32_t instance_count = 0;

fr_dict_t const *dict_vmps;

extern fr_dict_autoload_t libfreeradius_vmps[];
fr_dict_autoload_t libfreeradius_vmps[] = {
	{ .out = &dict_vmps, .proto = "vmps" },
	{ NULL }
};

fr_dict_attr_t const *attr_error_code;
fr_dict_attr_t const *attr_packet_type;
fr_dict_attr_t const *attr_sequence_number;

extern fr_dict_attr_autoload_t libfreeradius_vmps_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_vmps_dict_attr[] = {
	{ .out = &attr_error_code, .name = "Error-Code", .type = FR_TYPE_UINT8, .dict = &dict_vmps },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_vmps },
	{ .out = &attr_sequence_number, .name = "Sequence-Number", .type = FR_TYPE_UINT32, .dict = &dict_vmps },
	{ NULL }
};


int fr_vmps_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_vmps) < 0) {
		fr_strerror_const_push("Failed loading the 'vmps' dictionary");
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_vmps_dict_attr) < 0) {
		fr_strerror_const("Failed loading the 'vmps' attributes");
		fr_dict_autofree(libfreeradius_vmps);
		return -1;
	}

	instance_count++;

	return 0;
}

void fr_vmps_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_vmps);
}
