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
			if (pcap_set_buffer_size(pcap->handle, SNAPLEN * 10000) != 0) {
				error:
				fr_strerror_printf("%s", pcap_geterr(pcap->handle));
				pcap_close(pcap->handle);
				pcap->handle = NULL;
				return -1;
			}
			if (pcap_activate(pcap->handle) != 0) {
				goto error;
			}
			if (pcap_setnonblock(pcap->handle, true, pcap->errbuf) != 0) {
				fr_strerror_printf("%s", pcap->errbuf);
				pcap_close(pcap->handle);
				pcap->handle = NULL;
				return -1;
			}

			pcap->fd = pcap_get_selectable_fd(pcap->handle);
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
		break;
	case PCAP_FILE_OUT:
		pcap->handle = pcap_open_dead(DLT_EN10MB, SNAPLEN);
		pcap->dumper = pcap_dump_open(pcap->handle, pcap->name);
		if (!pcap->dumper) {
			fr_strerror_printf("%s", pcap->errbuf);

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
int fr_pcap_apply_filter(fr_pcap_t *pcap, char *expression)
{
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net = 0;				/* Our IP */
	struct bpf_program fp;

	/*
	 *	We can only apply filters to live interfaces
	 */
	if (pcap->type != PCAP_INTERFACE_IN) {
		return 1;
	}

	if (pcap_lookupnet(pcap->name, &net, &mask, pcap->errbuf) < 0) {
		DEBUG("Failed getting IP for interface \"%s\", using defaults: %s",
		      pcap->name, pcap->errbuf);
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

#endif
