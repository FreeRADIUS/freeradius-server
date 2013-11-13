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
 * @file pcap.c
 * @brief Wrappers around libpcap functions
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#ifdef HAVE_LIBPCAP

#include <sys/ioctl.h>
#include <pcap/pcap.h>
#include <freeradius-devel/pcap.h>

const FR_NAME_NUMBER pcap_types[] = {
	{ "interface",	PCAP_INTERFACE_IN },
	{ "file",	PCAP_FILE_IN },
	{ "stdio",	PCAP_STDIO_IN },
	{ "interface",	PCAP_INTERFACE_OUT },
	{ "file",	PCAP_FILE_OUT },
	{ "stdio",	PCAP_STDIO_OUT },

	{ NULL, 0}
};

/** Talloc destructor to free pcap resources associated with a handle.
 *
 * @param pcap to free.
 * @return 0
 */
static int _free_pcap(fr_pcap_t *pcap) {
	switch (pcap->type) {
		case PCAP_INTERFACE_IN:
		case PCAP_INTERFACE_OUT:
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

/** Initialise a pcap handle abstraction
 *
 * @param ctx talloc TALLOC_CTX to allocate handle in.
 * @param name of interface or file to open.
 * @param type of handle to initialise.
 * @return new handle or NULL on error.
 */
fr_pcap_t *fr_pcap_init(TALLOC_CTX *ctx, char const *name, fr_pcap_type_t type)
{
	fr_pcap_t *this = talloc_zero(ctx, fr_pcap_t);
	if (!this) {
		return NULL;
	}

	talloc_set_destructor(this, _free_pcap);
	this->name = talloc_strdup(this, name);
	this->type = type;
	this->link_type = -1;

	return this;
}

/** Open a PCAP handle abstraction
 *
 * This opens interfaces for capture or injection, or files/streams for reading/writing.
 * @param pcap created with fr_pcap_init.
 * @return 0 on success, -1 on error.
 */
int fr_pcap_open(fr_pcap_t *pcap)
{
	switch (pcap->type) {
	case PCAP_INTERFACE_OUT:
	case PCAP_INTERFACE_IN:
		{
			pcap->handle = pcap_create(pcap->name, pcap->errbuf);
			if (!pcap->handle) {
				fr_strerror_printf("%s", pcap->errbuf);

				return -1;
			}
			if (pcap_set_snaplen(pcap->handle, SNAPLEN) != 0) {
				goto error;
			}
			if (pcap_set_timeout(pcap->handle, PCAP_NONBLOCK_TIMEOUT) != 0) {
				goto error;
			}
			if (pcap_set_promisc(pcap->handle, pcap->promiscuous) != 0) {
				goto error;
			}
			if (pcap_set_buffer_size(pcap->handle, SNAPLEN *
						 (pcap->buffer_pkts ? pcap->buffer_pkts : PCAP_BUFFER_DEFAULT)) != 0) {
				error:
				fr_strerror_printf("%s", pcap_geterr(pcap->handle));
				pcap_close(pcap->handle);
				pcap->handle = NULL;
				return -1;
			}
			if (pcap_activate(pcap->handle) != 0) {
				goto error;
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
			pcap->link_type = pcap_datalink(pcap->handle);
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
		pcap->link_type = pcap_datalink(pcap->handle);
		break;

	case PCAP_FILE_OUT:
		if (pcap->link_type < 0) {
			pcap->link_type = DLT_EN10MB;
		}
		pcap->handle = pcap_open_dead(pcap->link_type, SNAPLEN);
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
		fr_assert(0);
		fr_strerror_printf("Bad handle type (%i)", pcap->type);
		return -1;
	}

	return 0;
}

/** Apply capture filter to an interface
 *
 * @param pcap handle to apply filter to.
 * @param expression PCAP expression to use as a filter.
 * @return 0 on success, 1 wrong interface type, -1 on error.
 */
int fr_pcap_apply_filter(fr_pcap_t *pcap, char const *expression)
{
	bpf_u_int32 mask = 0;				/* Our netmask */
	bpf_u_int32 net = 0;				/* Our IP */
	struct bpf_program fp;

	if (pcap->type == PCAP_INTERFACE_IN) {
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

	return 0;
}

char *fr_pcap_device_names(TALLOC_CTX *ctx, fr_pcap_t *pcap, char c)
{
	fr_pcap_t *pcap_p;
	char *buff, *p;
	size_t len = 0, left = 0, wrote;

	if (!pcap) {
		goto null;
	}

	for (pcap_p = pcap;
	     pcap_p;
	     pcap_p = pcap_p->next) {
		len += talloc_array_length(pcap_p->name);	// Talloc array length includes the \0
	}

	if (!len) {
		null:
		return talloc_zero_array(ctx, char, 1);
	}

	left = len + 1;
	buff = p = talloc_zero_array(ctx, char, left);
	for (pcap_p = pcap;
	     pcap_p;
	     pcap_p = pcap_p->next) {
		wrote = snprintf(p, left, "%s%c", pcap_p->name, c);
		left -= wrote;
		p += wrote;
	}
	buff[len - 1] = '\0';

	return buff;
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
 * @param data start of PCAP data.
 * @param len caplen.
 * @param link_type value returned from pcap_linktype.
 * @return the length of the header, or -1 on error.
 */
ssize_t fr_pcap_link_layer_offset(uint8_t const *data, size_t len, int link_type)
{
	uint8_t const *p = data;

	switch (link_type) {
	case DLT_RAW:
		break;

	case DLT_NULL:
	case DLT_LOOP:
		p += 4;
		if (((size_t)(p - data)) > len) {
			goto ood;
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

	case DLT_LINUX_SLL:
		p += 16;
		if (((size_t)(p - data)) > len) {
			goto ood;
		}
		break;

	case DLT_PFLOG:
		p += 28;
		if (((size_t)(p - data)) > len) {
			goto ood;
		}
		break;

	default:
		fr_strerror_printf("Unsupported link layer type %i", link_type);
	}

	done:
	return p - data;

	ood:
	fr_strerror_printf("Out of data, needed %zu bytes, have %zu bytes", (size_t)(p - data), len);

	return -1;
}

#endif
