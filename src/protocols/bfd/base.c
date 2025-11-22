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
static bool	instantiated = false;

fr_dict_t const *dict_freeradius;
fr_dict_t const *dict_bfd;

extern fr_dict_autoload_t libfreeradius_bfd_dict[];
fr_dict_autoload_t libfreeradius_bfd_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_bfd, .proto = "bfd" },
	DICT_AUTOLOAD_TERMINATOR
};

fr_dict_attr_t const *attr_packet_type;
fr_dict_attr_t const *attr_bfd_packet;
fr_dict_attr_t const *attr_bfd_additional_data;

extern fr_dict_attr_autoload_t libfreeradius_bfd_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_bfd_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_bfd },
	{ .out = &attr_bfd_packet, .name = "Packet", .type = FR_TYPE_STRUCT, .dict = &dict_bfd },
	{ .out = &attr_bfd_additional_data, .name = "Additional-Data", .type = FR_TYPE_GROUP, .dict = &dict_bfd },

	DICT_AUTOLOAD_TERMINATOR
};

char const *fr_bfd_packet_names[FR_BFD_CODE_MAX] = {
	"Admin-Down",
	"Down",
	"Init",
	"Up",
};

fr_table_num_ordered_t const bfd_auth_type_table[] = {
	{ L("none"),		BFD_AUTH_RESERVED		},
	{ L("simple"),		BFD_AUTH_SIMPLE			},
	{ L("keyed-md5"),	BFD_AUTH_KEYED_MD5		},
	{ L("met-keyed-md5"),	BFD_AUTH_MET_KEYED_MD5		},
	{ L("keyed-sha1"),	BFD_AUTH_KEYED_SHA1		},
	{ L("met-keyed-sha1"),	BFD_AUTH_MET_KEYED_SHA1		},
};
size_t const bfd_auth_type_table_len = NUM_ELEMENTS(bfd_auth_type_table);

/*
 *	Perform basic packet checks as per the first part of RFC 5880 Section 6.8.6.
 */
bool fr_bfd_packet_ok(char const **err, uint8_t const *packet, size_t packet_len)
{
	bfd_packet_t const *bfd;
	char const *msg = NULL;

	if (packet_len < FR_BFD_HEADER_LENGTH) {
		msg = "Packet is too short to be BFD";
	fail:
		if (err) *err = msg;
		return false;
	}

	bfd = (bfd_packet_t const *) packet;

	/*
	 *	If the version number is not correct (1), the packet MUST be
	 *	discarded.
	 */
	if (bfd->version != 1) {
		msg = "Packet has wrong version - should be 1";
		goto fail;
	}

	/*
	 *	If the Length field is less than the minimum correct value (24 if
	 *	the A bit is clear, or 26 if the A bit is set), the packet MUST be
	 *	discarded.
	 */
	if (bfd->length < FR_BFD_HEADER_LENGTH) {
		msg = "Header length is too small";
		goto fail;
	}

	/*
	 *	If the Length field is greater than the payload of the
	 *	encapsulating protocol, the packet MUST be discarded.
	 *
	 *	Addendum: if the Length field is smaller than the
	 *	received data, that's bad, too.
	 */
	if (bfd->length > packet_len) {
		msg = "Header length is not the same as the amount of data we read";
		goto fail;
	}

	/*
	 *	If the Length field is less than the minimum correct value (24 if
	 *	the A bit is clear, or 26 if the A bit is set), the packet MUST be
	 *	discarded.
	 *
	 *	Addendum: if the Length field is not equal to 24 plus Auth-Len field,
	 *	then the packet is discarded.
	 */
	if (bfd->auth_present) {
		if (bfd->length < (FR_BFD_HEADER_LENGTH + 2)) { /* auth-type and auth-len */
			msg = "Header length is not enough for auth-type and auth-len";
			goto fail;
		}

		if (bfd->length != FR_BFD_HEADER_LENGTH + bfd->auth.basic.auth_len) {
			msg = "Header length mismatch with auth-len and amount of received data";
			goto fail;

		}

		switch (bfd->auth.basic.auth_type) {
		case BFD_AUTH_SIMPLE:
			if ((bfd->auth.basic.auth_len < (3 + 1)) || (bfd->auth.basic.auth_len > (3 + 16))) {
				msg = "Auth-Type Simple has invalid value for password length";
				goto fail;
			}
			break;

		case BFD_AUTH_KEYED_MD5:
		case BFD_AUTH_MET_KEYED_MD5:
			if (bfd->auth.basic.auth_len != 24) {
				msg = "Auth-Type MD5 has invalid value for digest length";
				goto fail;
			}
			break;

		case BFD_AUTH_KEYED_SHA1:
		case BFD_AUTH_MET_KEYED_SHA1:
			if (bfd->auth.basic.auth_len != 28) {
				msg = "Auth-Type SHA1 has invalid value for digest length";
				goto fail;
			}
			break;

		default:
			msg = "Invalid Auth-Type";
			goto fail;
		}
	}

	/*
	 *	If the Detect Mult field is zero, the packet MUST be discarded.
	 */
	if (bfd->detect_multi == 0) {
		msg = "Packet has invalid detect-multi == 0";
		goto fail;
	}

	/*
	 *	If the Multipoint (M) bit is nonzero, the packet MUST be
	 *	discarded.
	 */
	if (bfd->multipoint != 0) {
		msg = "Packet has invalid multipoint != 0";
		goto fail;
	}

	/*
	 *	If the My Discriminator field is zero, the packet MUST be
	 *	discarded.
	 */
	if (bfd->my_disc == 0) {
		msg = "Packet has invalid my-discriminator == 0";
		goto fail;
	}

	/*
	 *	If the Your Discriminator field is zero and the State field is not
	 *	Down or AdminDown, the packet MUST be discarded.
	 */
	if ((bfd->your_disc == 0) &&
	    !((bfd->state == BFD_STATE_DOWN) ||
	      (bfd->state == BFD_STATE_ADMIN_DOWN))) {
		msg = "Packet has your-discrimator==0, but state is not down or admin-down";
		goto fail;
	}

	if (err) *err = NULL;
	return true;
}



int fr_bfd_global_init(void)
{
	if (instance_count > 0) {
		instance_count++;
		return 0;
	}

	instance_count++;

	if (fr_dict_autoload(libfreeradius_bfd_dict) < 0) {
	fail:
		instance_count--;
		return -1;
	}

	if (fr_dict_attr_autoload(libfreeradius_bfd_dict_attr) < 0) {
		fr_dict_autofree(libfreeradius_bfd_dict);
		goto fail;
	}

	instantiated = true;	

	return 0;
}

void fr_bfd_global_free(void)
{
	if (!instantiated) return;

	if (--instance_count > 0) return;

	fr_dict_autofree(libfreeradius_bfd_dict);

	instantiated = false;
}

extern fr_dict_protocol_t libfreeradius_bfd_dict_protocol;
fr_dict_protocol_t libfreeradius_bfd_dict_protocol = {
	.name = "bfd",
	.default_type_size = 1,
	.default_type_length = 1,

	.init = fr_bfd_global_init,
	.free = fr_bfd_global_free,
};
