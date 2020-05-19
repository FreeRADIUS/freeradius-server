/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * @file proto_arp_udp.c
 * @brief RADIUS handler for UDP.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/util/debug.h>

#include "proto_arp.h"

extern fr_app_io_t proto_arp_ethernet;

typedef struct {
	char const			*name;			//!< socket name
	fr_pcap_t			*pcap;			//!< PCAP handler
} proto_arp_ethernet_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration
	char const			*interface;		//!< Interface to bind to.
	char const			*filter;		//!< Additional PCAP filter
} proto_arp_ethernet_t;


/** How to parse an ARP listen section
 *
 */
static CONF_PARSER const arp_listen_config[] = {
	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING | FR_TYPE_NOT_EMPTY, proto_arp_ethernet_t,
			  interface), .dflt = "eth0" },

	{ FR_CONF_OFFSET("filter", FR_TYPE_STRING, proto_arp_ethernet_t, filter) },

	CONF_PARSER_TERMINATOR
};

static ssize_t mod_read(fr_listen_t *li, UNUSED void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_arp_ethernet_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_arp_ethernet_thread_t);
	int				ret;
	uint8_t const			*data;
	struct pcap_pkthdr		*header;
	uint8_t const			*p, *end;
	ssize_t				len;

	*leftover = 0;		/* always for message oriented protocols */

	ret = pcap_next_ex(thread->pcap->handle, &header, &data);
	if (ret == 0) return 0;
	if (ret < 0) {
		DEBUG("Failed getting next PCAP packet");
		return 0;
	}

	p = data;
	end = data + header->caplen;

	len = fr_pcap_link_layer_offset(data, header->caplen, thread->pcap->link_layer);
	if (len < 0) {
		DEBUG("Failed determining link layer header offset");
		return 0;
	}
	p += len;

	if ((end - p) < FR_ARP_PACKET_SIZE) {
		DEBUG("Packet is too small (%d) to be ARP", (int) (end - p));
		return 0;
	}

	/*
	 *	Shouldn't happen.
	 */
	if (buffer_len < FR_ARP_PACKET_SIZE) {
		return 0;
	}

	memcpy(buffer, p, FR_ARP_PACKET_SIZE);

	// @todo - talloc packet_ctx which is the ethernet header, so we know what kind of VLAN, etc. to encode?

	*recv_time_p = fr_time();
	return FR_ARP_PACKET_SIZE;
}


static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	proto_arp_ethernet_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_arp_ethernet_thread_t);

	int			ret;
	uint8_t			arp_packet[64] = { 0 };
	ethernet_header_t	*eth_hdr;
	fr_arp_packet_t		*arp;
	/* Pointer to the current position in the frame */
	uint8_t			*end = arp_packet;

	/*
	 *	Don't write anything.
	 */
	if (buffer_len == 1) return buffer_len;

	/* fill in Ethernet layer (L2) */
	eth_hdr = (ethernet_header_t *)arp_packet;
	eth_hdr->ether_type = htons(ETH_TYPE_ARP);
	end += ETHER_ADDR_LEN + ETHER_ADDR_LEN + sizeof(eth_hdr->ether_type);

	/*
	 *	Just copy what FreeRADIUS has encoded for us.
	 */
	arp = (fr_arp_packet_t *) end;
	memcpy(arp, buffer, buffer_len);

	/*
	 *	Set our MAC address as the ethernet source.
	 *
	 *	Set the destination MAC as the target address from
	 *	ARP.
	 */
	memcpy(eth_hdr->src_addr, thread->pcap->ether_addr, ETHER_ADDR_LEN);
	memcpy(eth_hdr->dst_addr, arp->tha, ETHER_ADDR_LEN);

	/*
	 *	If we fail injecting the reply, just ignore it.
	 *	Returning <0 means "close the socket", which is likely
	 *	not what we want.
	 */
	ret = pcap_inject(thread->pcap->handle, arp_packet, (end - arp_packet + buffer_len));
	if (ret < 0) {
		fr_strerror_printf("Error sending packet with pcap: %d, %s", ret, pcap_geterr(thread->pcap->handle));
		return 0;
	}

	/*
	 *	@todo - mirror src/protocols/dhcpv4/pcap.c for ARP send / receive.
	 *	We will need that functionality for rlm_arp, too.
	 */

	return FR_ARP_PACKET_SIZE;
}

/** Open a pcap file for ARP
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_arp_ethernet_t const      *inst = talloc_get_type_abort_const(li->app_io_instance, proto_arp_ethernet_t);
	proto_arp_ethernet_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_arp_ethernet_thread_t);

	CONF_SECTION			*server_cs;
	CONF_ITEM			*ci;
	char const			*filter;
	char				*our_filter = NULL;

	thread->pcap = fr_pcap_init(thread, inst->interface, PCAP_INTERFACE_IN);
	if (!thread->pcap) {
		PERROR("Failed initializing pcap handle.");
		return -1;
	}

	if (fr_pcap_open(thread->pcap) < 0) {
		PERROR("Failed opening interface %s", inst->interface);
		return -1;
	}

	/*
	 *	Ensure that we only get ARP, and an optional additional filter.
	 */
	if (!inst->filter) {
		filter = "arp";
	} else {
		MEM(filter = our_filter = talloc_asprintf(li, "arp and %s", inst->filter));
	}

	if (fr_pcap_apply_filter(thread->pcap, filter) < 0) {
		PERROR("Failed applying pcap filter '%s'", filter);
		talloc_free(our_filter);
		return -1;
	}
	talloc_free(our_filter);

	li->fd = thread->pcap->fd;

	ci = cf_parent(inst->cs); /* listen { ... } */
	fr_assert(ci != NULL);
	server_cs = cf_item_to_section(ci);

	thread->name = talloc_asprintf(thread, "arp on interface %s", inst->interface);
	return 0;
}

static char const *mod_name(fr_listen_t *li)
{
	proto_arp_ethernet_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_arp_ethernet_thread_t);

	return thread->name;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_arp_ethernet_t	*inst = talloc_get_type_abort(instance, proto_arp_ethernet_t);

	inst->cs = cs;

	return 0;
}


fr_app_io_t proto_arp_ethernet = {
	.magic			= RLM_MODULE_INIT,
	.name			= "arp_ethernet",
	.config			= arp_listen_config,
	.inst_size		= sizeof(proto_arp_ethernet_t),
	.thread_inst_size	= sizeof(proto_arp_ethernet_thread_t),
	.bootstrap		= mod_bootstrap,

	.default_message_size	= FR_ARP_PACKET_SIZE,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.get_name      		= mod_name,
};
