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

#include "dhcpv6.h"

size_t const fr_dhcpv6_attr_sizes[FR_TYPE_MAX + 1][2] = {
	[FR_TYPE_INVALID]		= {~0, 0},	//!< Ensure array starts at 0 (umm?)

	[FR_TYPE_STRING]		= {0, ~0},
	[FR_TYPE_OCTETS]		= {0, ~0},

	[FR_TYPE_IPV4_ADDR]		= {4, 4},
	[FR_TYPE_IPV4_PREFIX]		= {1, 5},	//!< Zero length prefix still requires one byte for prefix len.
	[FR_TYPE_IPV6_ADDR]		= {16, 16},
	[FR_TYPE_IPV6_PREFIX]		= {1, 17},	//!< Zero length prefix still requires one byte for prefix len.
	[FR_TYPE_IFID]			= {8, 8},
	[FR_TYPE_ETHERNET]		= {6, 6},

	[FR_TYPE_BOOL]			= {1, 1},
	[FR_TYPE_UINT8]			= {1, 1},
	[FR_TYPE_UINT16]		= {2, 2},
	[FR_TYPE_UINT32]		= {4, 4},
	[FR_TYPE_UINT64]		= {8, 8},

	[FR_TYPE_TLV]			= {2, ~0},
	[FR_TYPE_STRUCT]		= {1, ~0},

	[FR_TYPE_MAX]			= {~0, 0}	//!< Ensure array covers all types.
};

/** Return the on-the-wire length of an attribute value
 *
 * @param[in] vp to return the length of.
 * @return the length of the attribute.
 */
size_t fr_dhcpv6_option_len(VALUE_PAIR const *vp)
{
	switch (vp->vp_type) {
	case FR_TYPE_VARIABLE_SIZE:
		if (da->flags.length) return da->flags.length;	/* Variable type with fixed length */
		return vp->vp_length;

	default:
		return fr_dhcpv6_attr_sizes[vp->vp_type][0];

	case FR_TYPE_STRUCTURAL:
		if (!fr_cond_assert(0)) return 0;
	}
}
