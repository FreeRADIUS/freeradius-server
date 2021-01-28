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
#ifdef HAVE_LIBPCAP
/** Prototypes and constants for PCAP functions
 *
 * @file src/lib/util/pcap.h
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(pcap_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include "pcap.h"

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/net.h>

#include <pcap.h>
#include <stdbool.h>
#include <sys/types.h>

#define SNAPLEN ETHER_HDR_LEN + IP_HDR_LEN + sizeof(udp_header_t) + MAX_RADIUS_LEN
#define PCAP_BUFFER_DEFAULT (10000)
/*
 *	It's unclear why this differs between platforms
 */
#ifndef __linux__
#  define PCAP_NONBLOCK_TIMEOUT (0)
#else
#  define PCAP_NONBLOCK_TIMEOUT (-1)
#endif

#ifndef BIOCIMMEDIATE
#  define BIOCIMMEDIATE (2147762800)
#endif

/*
 *	Older versions of libpcap don't define this
 */
#ifndef PCAP_NETMASK_UNKNOWN
#  define PCAP_NETMASK_UNKNOWN 0
#endif

typedef enum {
	PCAP_INVALID = 0,
	PCAP_INTERFACE_IN,
	PCAP_FILE_IN,
	PCAP_STDIO_IN,
	PCAP_INTERFACE_OUT,
	PCAP_FILE_OUT,
	PCAP_STDIO_OUT,
	PCAP_INTERFACE_IN_OUT
} fr_pcap_type_t;

/*
 *	Internal pcap structures
 */
typedef struct fr_pcap fr_pcap_t;
struct fr_pcap {
	char			errbuf[PCAP_ERRBUF_SIZE];	//!< Last error on this interface.
	fr_pcap_type_t		type;				//!< What type of handle this is.
	char			*name;				//!< Name of file or interface.
	uint8_t			ether_addr[ETHER_ADDR_LEN];	//!< The MAC address of the interface
	int			ifindex;			//!< ifindex of the name we're listening on.

	bool			promiscuous;			//!< Whether the interface is in promiscuous mode.
								//!< Only valid for live capture handles.
	int			buffer_pkts;			//!< How big to make the PCAP ring buffer.
								//!< Actual buffer size is SNAPLEN * buffer.
								//!< Only valid for live capture handles.

	pcap_t			*handle;			//!< libpcap handle.
	pcap_dumper_t		*dumper;			//!< libpcap dumper handle.

	int			link_layer;			//!< Link layer type.

	int			fd;				//!< Selectable file descriptor we feed to select.
	struct pcap_stat	pstats;				//!< The last set of pcap stats for this handle.

	fr_pcap_t		*next;				//!< Next handle in collection.
};

int		fr_pcap_if_link_layer(pcap_if_t *dev);
fr_pcap_t	*fr_pcap_init(TALLOC_CTX *ctx, char const *name, fr_pcap_type_t type);
int		fr_pcap_open(fr_pcap_t *handle);
int		fr_pcap_apply_filter(fr_pcap_t *handle, char const *expression);
char		*fr_pcap_device_names(TALLOC_CTX *ctx, fr_pcap_t *handle, char c);
int		fr_pcap_mac_addr(uint8_t *macaddr, char *ifname);
bool		fr_pcap_link_layer_supported(int link_layer);
ssize_t		fr_pcap_link_layer_offset(uint8_t const *data, size_t len, int link_layer);
#endif

#ifdef __cplusplus
}
#endif
