/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/bfd/base.c
 * @brief Functions to send/receive BFD packets.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <fcntl.h>
#include <ctype.h>

#include "attrs.h"

#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/udp.h>

static uint32_t instance_count = 0;

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_bfd;

extern fr_dict_autoload_t libfreeradius_bfd_dict[];
fr_dict_autoload_t libfreeradius_bfd_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_bfd, .proto = "bfd" },
	{ NULL }
};

fr_dict_attr_t const *attr_packet_type;
fr_dict_attr_t const *attr_bfd_packet;

extern fr_dict_attr_autoload_t libfreeradius_bfd_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_bfd_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_bfd },
	{ .out = &attr_bfd_packet, .name = "Packet", .type = FR_TYPE_STRUCT, .dict = &dict_bfd },

	{ NULL }
};


int fr_bfd_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	if (fr_dict_autoload(libfreeradius_bfd_dict) < 0) return -1;
	if (fr_dict_attr_autoload(libfreeradius_bfd_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_bfd_dict);
		return -1;
	}

	instance_count++;

	return 0;
}

void fr_bfd_free(void)
{
	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_bfd_dict);
}

extern fr_dict_protocol_t libfreeradius_bfd_dict_protocol;
fr_dict_protocol_t libfreeradius_bfd_dict_protocol = {
	.name = "bfd",
	.default_type_size = 1,
	.default_type_length = 1,
};
