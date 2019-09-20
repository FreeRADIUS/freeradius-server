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

/** Wrappers around libpcap functions
 *
 * @file src/lib/util/pcap.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#ifdef HAVE_LIBPCAP

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pcap.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef SIOCGIFHWADDR
#  include <ifaddrs.h>
#  include <net/if_dl.h>
#else
#  include <net/if.h>
#endif


/** Talloc destructor to free pcap resources associated with a handle.
 *
 * @param pcap to free.
 * @return 0
 */
static int _free_pcap(fr_pcap_t *pcap)
{
	switch (pcap->type) {
	case PCAP_INTERFACE_IN:
	case PCAP_INTERFACE_OUT:
	case PCAP_INTERFACE_IN_OUT:
	case PCAP_FILE_IN:
	case PCAP_STDIO_IN:
		if (pcap->handle) {
			pcap_close(pcap->handle);

			if (pcap->fd > 0) {
				close(pcap->fd);
			}
		}
		break;

	case PCAP_FILE_OUT:
	case PCAP_STDIO_OUT:
		if (pcap->dumper) {
			pcap_dump_flush(pcap->dumper);
			pcap_dump_close(pcap->dumper);
		}
		break;

	case PCAP_INVALID:
		break;
	}

	return 0;
}

/** Get data link from pcap_if_t
 *
 * libpcap requires an open pcap handle to get data_link type
 * unfortunately when we're trying to find useful interfaces
 * this is too late.
 *
 * @param dev to get link layer for.
 * @return
 *	- Datalink layer.
 *	- -1 on failure.
 */
int fr_pcap_if_link_layer(pcap_if_t *dev)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*pcap;
	int	data_link;

	pcap = pcap_open_live(dev->name, 0, 0, 0, errbuf);
	if (!pcap) {
		fr_strerror_printf("%s", errbuf);
		return -1;
	}

	data_link = pcap_datalink(pcap);
	pcap_close(pcap);

	return data_link;
}

/** Initialise a pcap handle abstraction
 *
 * @param ctx talloc TALLOC_CTX to allocate handle in.
 * @param name of interface or file to open.
 * @param type of handle to initialise.
 * @return new handle or NULL on error.
 */
fr_pcap_t *fr_pcap_init(TALLOC_CTX *ctx, char const *name, fr_pcap_type_t type)
{
	fr_pcap_t	*this;

	if (!fr_cond_assert(type >= PCAP_INTERFACE_IN && type <= PCAP_INTERFACE_IN_OUT)) {
		fr_strerror_printf("Invalid PCAP type: %d", type);
		return NULL;
	}

	this = talloc_zero(ctx, fr_pcap_t);
	if (!this) return NULL;

	talloc_set_destructor(this, _free_pcap);
	this->name = talloc_typed_strdup(this, name);
	this->type = type;
	this->link_layer = -1;

	return this;
}

/** Get MAC address for given interface
 *
 * @param[out] macaddr to write MAC address to.
 * @param[in] ifname to get MAC for.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int fr_pcap_mac_addr(uint8_t *macaddr, char *ifname)
{
#ifndef SIOCGIFHWADDR
	struct ifaddrs *ifap, *ifaptr;
	unsigned char *ptr;

	if (getifaddrs(&ifap) == 0) {
		for (ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
			if (!strcmp((ifaptr)->ifa_name, ifname) && (((ifaptr)->ifa_addr)->sa_family == AF_LINK)) {
				ptr = (uint8_t *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
				memcpy(macaddr, ptr, ETHER_ADDR_LEN);
				break;
			}
		}
		freeifaddrs(ifap);
		return (ifaptr != NULL ? 0 : -1);
	}
	return -1;
#else
	int fd, ret;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0) {
		return -1;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strlcpy(ifr.ifr_name, ifname , IFNAMSIZ-1);

	ret = ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	if (ret == 0) {
		memcpy(macaddr, (uint8_t *)ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
		return 0;
	}
	return -1;
#endif
}

/** Open a PCAP handle abstraction
 *
 * This opens interfaces for capture or injection, or files/streams for reading/writing.
 * @param pcap created with fr_pcap_init.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pcap_open(fr_pcap_t *pcap)
{
	switch (pcap->type) {
	case PCAP_INTERFACE_OUT:
	case PCAP_INTERFACE_IN:
	case PCAP_INTERFACE_IN_OUT:
	{
		/*
		 *	Also has the pleasant side effect of not allowing
		 *	handles to be opened on "any".
		 *
		 *	We do this first, as it's the most specific error.
		 */
		pcap->if_index = if_nametoindex(pcap->name);
		if (!pcap->if_index) {
			fr_strerror_printf("Unknown interface \"%s\"", pcap->name);
			return -1;
		}

#if defined(HAVE_PCAP_CREATE) && defined(HAVE_PCAP_ACTIVATE)
		pcap->handle = pcap_create(pcap->name, pcap->errbuf);
		if (!pcap->handle) {
			fr_strerror_printf("%s", pcap->errbuf);
			return -1;
		}
		if (pcap_set_snaplen(pcap->handle, SNAPLEN) != 0) {
		create_error:
			fr_strerror_printf("%s", pcap_geterr(pcap->handle));
			pcap_close(pcap->handle);
			pcap->handle = NULL;
			return -1;
		}
		if (pcap_set_timeout(pcap->handle, PCAP_NONBLOCK_TIMEOUT) != 0) {
			goto create_error;
		}
		if (pcap_set_promisc(pcap->handle, pcap->promiscuous) != 0) {
			goto create_error;
		}

		if (pcap_set_buffer_size(pcap->handle, SNAPLEN *
					 (pcap->buffer_pkts ? pcap->buffer_pkts : PCAP_BUFFER_DEFAULT)) != 0) {
			goto create_error;
		}
		if (pcap_activate(pcap->handle) != 0) {
			goto create_error;
		}
#else
		/*
		 *	Alternative functions for libpcap < 1.0
		 */
		pcap->handle = pcap_open_live(pcap->name, SNAPLEN, pcap->promiscuous, PCAP_NONBLOCK_TIMEOUT,
					      pcap->errbuf);
		if (!pcap->handle) {
			fr_strerror_printf("%s", pcap->errbuf);
			return -1;
		}
#endif

		/*
		 *	Do this later so we get real errors from libpcap,
		 *	when bad interfaces are passed in.
		 */
		if (fr_pcap_mac_addr((uint8_t *)&pcap->ether_addr, pcap->name) != 0) {
			fr_strerror_printf("Couldn't get MAC address for interface %s", pcap->name);
			pcap_close(pcap->handle);
			return -1;
		}

		/*
		 *	Despite accepting an errbuff, pcap_setnonblock doesn't seem to write
		 *	error message there in newer versions.
		 */
		if (pcap_setnonblock(pcap->handle, true, pcap->errbuf) != 0) {
			fr_strerror_printf("%s", *pcap->errbuf != '\0' ?
					   pcap->errbuf : pcap_geterr(pcap->handle));
			pcap_close(pcap->handle);
			pcap->handle = NULL;
			return -1;
		}

		pcap->fd = pcap_get_selectable_fd(pcap->handle);
		pcap->link_layer = pcap_datalink(pcap->handle);
#ifndef __linux__
		{
			int value = 1;
			if (ioctl(pcap->fd, BIOCIMMEDIATE, &value) < 0) {
				fr_strerror_printf("Failed setting BIOCIMMEDIATE: %s", fr_syserror(errno));
			}
		}
#endif
	}
		break;

	case PCAP_FILE_IN:
		pcap->handle = pcap_open_offline(pcap->name, pcap->errbuf);
		if (!pcap->handle) {
			fr_strerror_printf("%s", pcap->errbuf);

			return -1;
		}
		pcap->fd = pcap_get_selectable_fd(pcap->handle);
		pcap->link_layer = pcap_datalink(pcap->handle);
		break;

	case PCAP_FILE_OUT:
		if (pcap->link_layer < 0) {
			pcap->link_layer = DLT_EN10MB;
		}
		pcap->handle = pcap_open_dead(pcap->link_layer, SNAPLEN);
		if (!pcap->handle) {
			fr_strerror_printf("Unknown error occurred opening dead PCAP handle");

			return -1;
		}
		pcap->dumper = pcap_dump_open(pcap->handle, pcap->name);
		if (!pcap->dumper) {
			fr_strerror_printf("%s", pcap_geterr(pcap->handle));

			return -1;
		}
		break;

#ifdef HAVE_PCAP_FOPEN_OFFLINE
	case PCAP_STDIO_IN:
		pcap->handle = pcap_fopen_offline(stdin, pcap->errbuf);
		if (!pcap->handle) {
			fr_strerror_printf("%s", pcap->errbuf);

			return -1;
		}
		pcap->fd = pcap_get_selectable_fd(pcap->handle);
		pcap->link_layer = pcap_datalink(pcap->handle);
		break;
#else
	case PCAP_STDIO_IN:
		fr_strerror_printf("This version of libpcap does not support reading pcap data from streams");

		return -1;
#endif
#ifdef HAVE_PCAP_DUMP_FOPEN
	case PCAP_STDIO_OUT:
		pcap->handle = pcap_open_dead(DLT_EN10MB, SNAPLEN);
		pcap->dumper = pcap_dump_fopen(pcap->handle, stdout);
		if (!pcap->dumper) {
			fr_strerror_printf("%s", pcap_geterr(pcap->handle));

			return -1;
		}
		break;
#else
	case PCAP_STDIO_OUT:
		fr_strerror_printf("This version of libpcap does not support writing pcap data to streams");

		return -1;
#endif
	case PCAP_INVALID:
	default:
		(void)fr_cond_assert(0);
		fr_strerror_printf("Bad handle type (%i)", pcap->type);
		return -1;
	}

	return 0;
}

/** Apply capture filter to an interface
 *
 * @param pcap handle to apply filter to.
 * @param expression PCAP expression to use as a filter.
 * @return
 *	- 0 on success.
 *	- 1 can't apply to interface.
 *	- -1 on failure.
 */
int fr_pcap_apply_filter(fr_pcap_t *pcap, char const *expression)
{
	bpf_u_int32 mask = 0;		/* Our netmask */
	bpf_u_int32 net = 0;		/* Our IP */
	struct bpf_program fp;

	/*
	 *	nflog devices are in the set of devices selected by default.
	 *	Unfortunately there's a bug in all released version of libpcap (as of 2/1/2014)
	 *	which triggers an abort if pcap_setfilter is called on an nflog interface.
	 *
	 *	See here:
	 * 	https://github.com/the-tcpdump-group/libpcap/commit/676cf8a61ed240d0a86d471ef419f45ba35dba80
	 */
#ifdef DLT_NFLOG
	if (pcap->link_layer == DLT_NFLOG) {
		fr_strerror_printf("NFLOG link-layer type filtering not implemented");

		return 1;
	}
#endif

	if (pcap->type == PCAP_INTERFACE_IN || pcap->type == PCAP_INTERFACE_IN_OUT) {
		if (pcap_lookupnet(pcap->name, &net, &mask, pcap->errbuf) < 0) {
			fr_strerror_printf("Failed getting IP for interface \"%s\", using defaults: %s",
					   pcap->name, pcap->errbuf);
		}
	}

	if (pcap_compile(pcap->handle, &fp, expression, 0, net) < 0) {
		fr_strerror_printf("%s", pcap_geterr(pcap->handle));

		return -1;
	}

	if (pcap_setfilter(pcap->handle, &fp) < 0) {
		fr_strerror_printf("%s", pcap_geterr(pcap->handle));

		return -1;
	}

	pcap_freecode(&fp);	/* Free the filter, it's not longer needed after its been applied */

	return 0;
}

/** Retrieve list of interface names that will be used for capture.
 * Only used for debugging.
 *
 * @param ctx talloc context for allicating string.
 * @param pcap handle list.
 * @param c separator to use for list.
 * @return
 *	- string buffer.
 */
char *fr_pcap_device_names(TALLOC_CTX *ctx, fr_pcap_t *pcap, char c)
{
	fr_pcap_t *pcap_p;
	char *buff, *p, *end;
	size_t len = 0;

	if (!pcap) {
	null:
		return talloc_zero_array(ctx, char, 1);
	}

	for (pcap_p = pcap;
	     pcap_p;
	     pcap_p = pcap_p->next) {
	     	/*
	     	 *	talloc_array_length includes \0 which accounts for c
	     	 */
		len += talloc_array_length(pcap_p->name);
	}

	if (!len) goto null;

	buff = p = talloc_zero_array(ctx, char, len + 1);
	end = p + len;

	for (pcap_p = pcap;
	     pcap_p;
	     pcap_p = pcap_p->next) {
	     	size_t ret;

		ret = snprintf(p, end - p, "%s%c", pcap_p->name, c);
		rad_assert(!is_truncated(ret, end - p));		/* Static analysis */
		p += ret;
	}
	buff[len - 1] = '\0';

	return buff;
}


/** Check whether fr_pcap_link_layer_offset can process a link_layer
 *
 * @param link_layer to check.
 * @return
 *	- true if supported.
 *	- false if not supported.
 */
bool fr_pcap_link_layer_supported(int link_layer)
{
	switch (link_layer) {
	case DLT_EN10MB:
	case DLT_RAW:
	case DLT_NULL:
	case DLT_LOOP:
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
#endif
	case DLT_PFLOG:
		return true;

	default:
		return false;
	}
}

/** Returns the length of the link layer header
 *
 * Libpcap does not include a decoding function to skip the L2 header, but it does
 * at least inform us of the type.
 *
 * Unfortunately some headers are of variable length (like ethernet), so additional
 * decoding logic is required.
 *
 * @note No header data is returned, this is only meant to be used to determine how
 * data to consume before attempting to parse the IP header.
 *
 * @param data start of packet data.
 * @param len caplen.
 * @param link_layer value returned from pcap_linktype.
 * @return
 *	- Length of the header.
 *	- -1 on failure.
 */
ssize_t fr_pcap_link_layer_offset(uint8_t const *data, size_t len, int link_layer)
{
	uint8_t const *p = data;

	switch (link_layer) {
	case DLT_RAW:
		break;

	case DLT_NULL:
	case DLT_LOOP:
		p += 4;
		if (((size_t)(p - data)) > len) {
		ood:
			fr_strerror_printf("Out of data, needed %zu bytes, have %zu bytes",
					   (size_t)(p - data), len);
			return -1;
		}
		break;

	case DLT_EN10MB:
	{
		uint16_t ether_type;	/* Ethernet type */
		int i;

		p += 12;		/* SRC/DST Mac-Addresses */
		if (((size_t)(p - data)) > len) {
			goto ood;
		}

		for (i = 0; i < 3; i++) {
			ether_type = ntohs(*((uint16_t const *) p));
			switch (ether_type) {
			/*
			 *	There are a number of devices out there which
			 *	double tag with 0x8100 *sigh*
			 */
			case 0x8100:	/* CVLAN */
			case 0x9100:	/* SVLAN */
			case 0x9200:	/* SVLAN */
			case 0x9300:	/* SVLAN */
				p += 4;
				if (((size_t)(p - data)) > len) {
					goto ood;
				}
				break;

			default:
				p += 2;
				if (((size_t)(p - data)) > len) {
					goto ood;
				}
				goto done;
			}
		}
		fr_strerror_printf("Exceeded maximum level of VLAN tag nesting (2)");
		return -1;
	}

#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		p += 16;
		if (((size_t)(p - data)) > len) {
			goto ood;
		}
		break;
#endif

	case DLT_PFLOG:
		p += 28;
		if (((size_t)(p - data)) > len) {
			goto ood;
		}
		break;

	default:
		fr_strerror_printf("Unsupported link layer type %i", link_layer);
		return -1;
	}

done:
	return p - data;
}
#endif	/* HAVE_LIBPCAP */
