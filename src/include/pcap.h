#ifndef FR_PCAP_H
#define FR_PCAP_H
#ifdef HAVE_LIBPCAP
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
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
 * @file include/pcap.h
 * @brief Prototypes and constants for PCAP functions.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/net.h>

#include <sys/types.h>
#include <pcap.h>

#define SNAPLEN ETHER_HDR_LEN + IP_HDR_LEN + sizeof(struct udp_header) + MAX_RADIUS_LEN
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
	PCAP_STDIO_OUT
} fr_pcap_type_t;

extern const FR_NAME_NUMBER pcap_types[];

/*
 *	Internal pcap structures
 */
typedef struct fr_pcap fr_pcap_t;
struct fr_pcap {
	char			errbuf[PCAP_ERRBUF_SIZE];	//!< Last error on this interface.
	fr_pcap_type_t		type;				//!< What type of handle this is.
	char			*name;				//!< Name of file or interface.
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

int		fr_pcap_if_link_layer(char *errbuff, pcap_if_t *dev);
fr_pcap_t	*fr_pcap_init(TALLOC_CTX *ctx, char const *name, fr_pcap_type_t type);
int		fr_pcap_open(fr_pcap_t *handle);
int		fr_pcap_apply_filter(fr_pcap_t *handle, char const *expression);
char		*fr_pcap_device_names(TALLOC_CTX *ctx, fr_pcap_t *handle, char c);
#endif
#endif
