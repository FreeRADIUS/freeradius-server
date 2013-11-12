#ifndef FR_PCAP_H
#define FR_PCAP_H
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
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
 * @file pcap.h
 * @brief Prototypes and constants for PCAP functions.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/libradius.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>

/*
 *	Length of a DEC/Intel/Xerox or 802.3 Ethernet header.
 *	Note that some compilers may pad "struct ether_header" to
 *	a multiple of 4 *bytes, for example, so "sizeof (struct
 *	ether_header)" may not give the right answer.
 *
 *	6 Byte SRC, 6 Byte DST, 2 Byte Ether type, 4 Byte CVID, 4 Byte SVID
 */
#define ETHER_HDRLEN	22
#define IP_HDRLEN	60

/*
 *	RADIUS packet length.
 *	RFC 2865, Section 3., subsection 'length' says:
 *	" ... and maximum length is 4096."
 */
#define MAX_RADIUS_LEN 4096
#define MIN_RADIUS_LEN 20
#define SNAPLEN ETHER_HDRLEN + IP_HDRLEN + sizeof(struct udp_header) + MAX_RADIUS_LEN
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
#define BIOCIMMEDIATE (2147762800)
#endif

/*
 *	Older versions of libpcap don't define this
 */
#ifndef PCAP_NETMASK_UNKNOWN
#  define PCAP_NETMASK_UNKNOWN 0
#endif

/*
 *	The number of bytes in an ethernet (MAC) address.
 */
#define ETHER_ADDR_LEN		6

/*
 *	Structure of a DEC/Intel/Xerox or 802.3 Ethernet header.
 */
struct  ethernet_header {
	uint8_t		ether_dst[ETHER_ADDR_LEN];
	uint8_t		ether_src[ETHER_ADDR_LEN];
	uint16_t	ether_type;
};

/*
 *	Structure of an internet header, naked of options.
 */

#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)

#define	I_DF		0x4000		//!< Dont fragment flag.
#define IP_MF		0x2000		//!< More fragments flag.
#define IP_OFFMASK	0x1fff		//!< Mask for fragmenting bits.

struct ip_header {
	uint8_t		ip_vhl;		//!< Header length, version.

	uint8_t		ip_tos;		//!< Type of service.
	uint16_t	ip_len;		//!< Total length.
	uint16_t	ip_id;		//!< identification.
	uint16_t	ip_off;		//!< Fragment offset field.

	uint8_t		ip_ttl;		//!< Time To Live.
	uint8_t		ip_p;		//!< Protocol.
	uint16_t	ip_sum;		//!< Checksum.
	struct in_addr	ip_src, ip_dst;	//!< Src and Dst address
};

struct ip_header6 {
	uint32_t	ip_vtcfl;	//!< Version, traffic class, flow label.
	uint16_t	ip_len;		//!< Payload length

	uint8_t		ip_next;	//!< Next header (protocol)
	uint8_t		ip_hopl;	//!< IP Hop Limit

	struct in6_addr ip_src, ip_dst;	//!< Src and Dst address
};

/*
 *	UDP protocol header.
 *	Per RFC 768, September, 1981.
 */
struct udp_header {
	uint16_t       udp_sport;	//!< Source port.
	uint16_t       udp_dport;	//!< Destination port.
	uint16_t       udp_ulen;	//!< UDP length.
	uint16_t       udp_sum;		//!< UDP checksum.
};

typedef struct radius_packet_t {
	uint8_t       code;
	uint8_t       id;
	uint8_t       length[2];
	uint8_t       vector[AUTH_VECTOR_LEN];
	uint8_t       data[1];
} radius_packet_t;

#define AUTH_HDR_LEN 20

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

	int			link_type;			//!< Link layer type.

	int			fd;				//!< Selectable file descriptor we feed to select.
	struct pcap_stat	pstats;				//!< The last set of pcap stats for this handle.

	fr_pcap_t		*next;				//!< Next handle in collection.
};


fr_pcap_t *fr_pcap_init(TALLOC_CTX *ctx, char const *name, fr_pcap_type_t type);
int fr_pcap_open(fr_pcap_t *handle);
int fr_pcap_apply_filter(fr_pcap_t *handle, char const *expression);
char *fr_pcap_device_names(TALLOC_CTX *ctx, fr_pcap_t *handle, char c);
ssize_t fr_pcap_link_layer_offset(uint8_t const *data, size_t len, int link_type);

#endif

