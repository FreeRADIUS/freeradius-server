#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/ethernet/ethernet.h
 * @brief Structures and functions for parsing ethernet headers.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/util/inet.h>
#include <stdint.h>
#include <stddef.h>

/*
 *	The number of bytes in an ethernet (MAC) address.
 */
#define ETHER_ADDR_LEN 	6

/** Unpack the Priority Code Point from the TCI
 *
 */
#define VLAN_PCP_UNPACK(_vlan)		(((*(uint8_t const *)&(_vlan)->tag_control) & 0xe0) >> 5)

/** Unpack the Drop Eligible Indicator from the TCI
 *
 */
#define VLAN_DEI_UNPACK(_vlan)		(((*(uint8_t const *)&(_vlan)->tag_control) & 0x10) >> 4)

/** Unpack the VLAN ID from the TCI
 *
 */
#define VLAN_VID_UNPACK(_vlan)		((htons((_vlan)->tag_control) & 0x0fff))

/** Pack the PCP (Priority Code Point) DEI (Drop Eligable Indicator) and VID (VLAN ID)
 *
 * Packs the PCP, DEI and VID into the TCI (Tag control information). Output will be a 16bit integer
 * in network byte order.
 *
 * @param[in] _pcp	Priority Code Point, a 3 bit value
 *			indicating the relative priority of the packet.
 * @param[in] _dei	Drop eligible indicator.  Boolean indicating
 *			whether this packet should be dropped in case of congestion.
 * @param[in] _vid	12 bit VLAN identifier.
 */
#define VLAN_TCI_PACK(_pcp, _dei, _vid)	htons((((uint16_t)(_pcp) & 0xe0) << 13) | (((uint16_t)(_dei) & 0x01) << 12) | ((_vid) & 0x0fff))

/** A VLAN header
 *
 * Represents a single layer of 802.1Q or QinQ tagging.
 */
typedef struct CC_HINT(__packed__) {
	uint16_t	tag_type;		//!< Tag type.  One of (0x8100 - CVLAN, 0x9100,
						///< 0x9200, 0x9300 - SVLAN).
	uint16_t	tag_control;		//!< - 3 bits priority.
						///< - 1 bit DEI.
						///< - 12 bits VID.
} vlan_header_t;

/** Structure of a DEC/Intel/Xerox or 802.3 Ethernet header
 *
 */
typedef struct CC_HINT(__packed__) {
	uint8_t		dst_addr[ETHER_ADDR_LEN];
	uint8_t		src_addr[ETHER_ADDR_LEN];
	uint16_t	ether_type;
} ethernet_header_t;

/** Src/dst link layer information
 *
 */
typedef struct {
	fr_ethernet_t	src_addr;
	fr_ethernet_t	dst_addr;
	uint16_t	ether_type;		//!< Ether type.  Usually 0x0800 (IPv4) 0x086DD (IPv6).

	uint16_t	cvlan_tpid;		//!< CVLAN tag type.  If 0, no CVLAN/SVLAN present.
	uint8_t		cvlan_pcp;		//!< CVLAN priority code point 0-6.
	uint8_t		cvlan_dei;		//!< CVLAN drop eligible indicator.
	uint16_t	cvlan_vid;		//!< CVLAN vlan ID.

	uint16_t	svlan_tpid;		//!< SVLAN tag type.  If 0, no SVLAN present.
	uint8_t		svlan_pcp;		//!< SVLAN priority code point 0-6.
	uint8_t		svlan_dei;		//!< SVLAN drop eligible indicator.
	uint16_t	svlan_vid;		//!< SVLAN vlan ID.

	size_t		payload_len;		//!< Remaining bytes after the ethernet header has been parsed.
} fr_ethernet_proto_ctx_t;

/** Protocol options for ethernet
 *
 */
typedef enum {
	PROTO_OPT_ETHERNET_SVLAN_TPID = 0,	//!< Outer VLAN tag type.
	PROTO_OPT_ETHERNET_SVLAN_PCP,		//!< Outer VLAN priority code point.
	PROTO_OPT_ETHERNET_SVLAN_DEI,		//!< Outer VLAN drop eligible indicator.
	PROTO_OPT_ETHERNET_SVLAN_VID,		//!< Outer VLAN ID.
	PROTO_OPT_ETHERNET_CVLAN_TPID,		//!< Inner VLAN tag type.
	PROTO_OPT_ETHERNET_CVLAN_PCP,		//!< Inner VLAN priority code point.
	PROTO_OPT_ETHERNET_CVLAN_DEI,		//!< Inner VLAN drop eligible indicator.
	PROTO_OPT_ETHERNET_CVLAN_VID		//!< Inner VLAN ID.
} fr_ethernet_options_t;
