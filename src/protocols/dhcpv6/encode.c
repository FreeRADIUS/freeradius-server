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
 * @file protocols/dhcpv6/encode.c
 * @brief Functions to encode DHCP options.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 NetworkRADIUS SARL <info@networkradius.com>
 */
#include <stdint.h>
#include <stddef.h>
#include <talloc.h>
#include <freeradius-devel/pair.h>
#include <freeradius-devel/types.h>
#include <freeradius-devel/proto.h>
#include <freeradius-devel/io/test_point.h>

#include "dhcpv6.h"

static ssize_t encode_tlv_hdr(UNUSED uint8_t *out, UNUSED size_t outlen,
			      UNUSED fr_dict_attr_t const *tlv_stack[], UNUSED unsigned int depth, UNUSED fr_cursor_t *cursor)
{
	return 0;
}

static ssize_t encode_rfc_hdr(UNUSED uint8_t *out, UNUSED size_t outlen,
			      UNUSED fr_dict_attr_t const *tlv_stack[], UNUSED unsigned int depth, UNUSED fr_cursor_t *cursor)
{
	return 0;
}

/** Encode a DHCPv6 option and any sub-options.
 *
 * @param[out] out Where to write encoded DHCP attributes.
 * @param[in] outlen Length of out buffer.
 * @param[in] cursor with current VP set to the option to be encoded. Will be advanced to the next option to encode.
 * @param[in] encoder_ctx containing parameters for the encoder.
 * @return
 *	- > 0 length of data written.
 *	- < 0 error.
 *	- 0 not valid option for DHCP (skipping).
 */
ssize_t fr_dhcpv6_encode_option(uint8_t *out, size_t outlen, fr_cursor_t *cursor, UNUSED void *encoder_ctx)
{
	VALUE_PAIR		*vp;
	unsigned int		depth = 0;
	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];
	ssize_t			len;

	vp = fr_cursor_current(cursor);
	if (!vp) return -1;

	if (vp->da->flags.internal) {
		fr_strerror_printf("Attribute \"%s\" is not a DHCPv6 option", vp->da->name);
		fr_cursor_next(cursor);
		return 0;
	}

	fr_proto_tlv_stack_build(tlv_stack, vp->da);

	depth++;	/* Skip the root attribute */
	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	We only have two types of options in DHCPv6
	 */
	switch (tlv_stack[depth]->type) {
	case FR_TYPE_TLV:
		len = encode_tlv_hdr(out, outlen, tlv_stack, depth, cursor);
		break;

	default:
		len = encode_rfc_hdr(out, outlen, tlv_stack, depth, cursor);
		break;
	}

	if (len < 0) return len;

	FR_PROTO_TRACE("Complete option is %zu byte(s)", len);
	FR_PROTO_HEX_DUMP(NULL, out, len);

	return len;
}
