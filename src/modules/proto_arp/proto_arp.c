/*
 * arp.c	ARP processing.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright (C) 2013 Network RADIUS SARL <info@networkradius.com>
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/pcap.h>
#include <net/if_arp.h>

typedef struct arp_socket_t {
	listen_socket_t	lsock;
	uint64_t	counter;
	RADCLIENT	client;
} arp_socket_t;

/*
 *	ARP for ethernet && IPv4.
 */
typedef struct arp_over_ether {
	uint16_t	htype;			//!< Format of hardware address.
	uint16_t	ptype;			//!< Format of protocol address.
	uint8_t		hlen;			//!< Length of hardware address.
	uint8_t		plen;			//!< Length of protocol address.
	uint8_t		op;			//!< 1 - Request, 2 - Reply.
	uint8_t		sha[ETHER_ADDR_LEN];	//!< sender hardware address.
	uint8_t		spa[4];			//!< Sender protocol address.
	uint8_t		tha[ETHER_ADDR_LEN];	//!< Target hardware address.
	uint8_t		tpa[4];			//!< Target protocol address.
} arp_over_ether_t;

static int arp_process(REQUEST *request)
{
	RADIUS_PACKET *packet = request->packet;
	struct arphdr const *arp;
	uint8_t const *p;

	arp = (struct arphdr *) request->packet->data;

	p = (const uint8_t *) arp;
	if (p > (packet->data + packet->data_len)) return 0;

#if 0
	{
		size_t len, i;
		len = packet->data_len;
		len -= (p - packet->data);

		for (i = 0; i < len; i++) {
			if ((i & 0x0f) == 0) printf("%04zx: ", i);
			printf("%02x ", p[i]);
			if ((i & 0x0f) == 0x0f) printf("\r\n");
			fflush(stdout);
		}
		printf("\n");
		fflush(stdout);
	}
#endif

	/*
	 *
	 */
	process_post_auth(0, request);

	return 1;
}


/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int arp_socket_recv(rad_listen_t *listener)
{
	int ret;
	arp_socket_t *sock = listener->data;
	pcap_t *handle = sock->lsock.pcap->handle;

	const uint8_t *data;
	struct pcap_pkthdr *header;
	ssize_t link_len;

	arp_over_ether_t const *arp;
	RADIUS_PACKET *packet;

	ret = pcap_next_ex(handle, &header, &data);
	if (ret == 0) {
		DEBUG("No packet retrieved from pcap.");
		return 0; /* no packet */
	}

	if (ret < 0) {
		ERROR("Error requesting next packet, got (%i): %s", ret, pcap_geterr(handle));
		return 0;
	}

	link_len = fr_link_layer_offset(data, header->caplen, sock->lsock.pcap->link_layer);
	if (link_len < 0) {
		ERROR("Failed determining link layer header offset: %s", fr_strerror());
		return 0;
	}

	/*
	 *	Silently ignore it if it's too small to be ARP.
	 *
	 *	This can happen when pcap gets overloaded and starts truncating packets.
	 */
	if (header->caplen < (link_len + sizeof(*arp))) {
		ERROR("Packet too small, we require at least %zu bytes, got %i bytes",
		      link_len + sizeof(*arp), header->caplen);
		return 0;
	}

	data += link_len;
	arp = (arp_over_ether_t const *) data;

	if (ntohs(arp->htype) != ARPHRD_ETHER) return 0;

	if (ntohs(arp->ptype) != 0x0800) return 0;

	if (arp->hlen != ETHER_ADDR_LEN) return 0; /* FIXME: malformed error */

	if (arp->plen != 4) return 0; /* FIXME: malformed packet error */

	packet = talloc_zero(NULL, RADIUS_PACKET);
	if (!packet) return 0;

	packet->dst_port = 1;	/* so it's not a "fake" request */
	packet->data_len = header->caplen - link_len;
	packet->data = talloc_memdup(packet, arp, packet->data_len);
	talloc_set_type(packet->data, uint8_t);

	DEBUG("ARP received on interface %s", sock->lsock.interface);

	if (!request_receive(NULL, listener, packet, &sock->client, arp_process)) {
		rad_free(&packet);
		return 0;
	}

	return 1;
}

static int arp_socket_send(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	return 0;
}


static int arp_socket_encode(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	return 0;
}


typedef struct arp_decode_t {
	char const	*name;
	size_t		len;
} arp_decode_t;

static const arp_decode_t header_names[] = {
	{ "ARP-Hardware-Format",		2 },
	{ "ARP-Protocol-Format",		2 },
	{ "ARP-Hardware-Address-Length",	1 },
	{ "ARP-Protocol-Address-Length",	1 },
	{ "ARP-Operation",			2 },
	{ "ARP-Sender-Hardware-Address",	6 },
	{ "ARP-Sender-Protocol-Address",	4 },
	{ "ARP-Target-Hardware-Address",	6 },
	{ "ARP-Target-Protocol-Address",	4 },

	{ NULL, 0 }
};

static int arp_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	int i;
	arp_over_ether_t const *arp;
	uint8_t const *p;

	arp = (arp_over_ether_t const *) request->packet->data;
	/*
	 *	arp_socket_recv() takes care of validating it's really
	 *	our kind of ARP.
	 */
	for (i = 0, p = (uint8_t const *) arp;
	     header_names[i].name != NULL;
	     p += header_names[i].len, i++) {
		ssize_t len;
		DICT_ATTR const *da;
		VALUE_PAIR *vp;

		da = dict_attrbyname(header_names[i].name);
		if (!da) return 0;

		vp = NULL;
		len = data2vp(request->packet, request->packet, NULL, NULL, da, p,
			      header_names[i].len, header_names[i].len,
			      &vp);
		if (len <= 0) {
			RDEBUG("Failed decoding %s: %s",
			       header_names[i].name, fr_strerror());
			return 0;
		}

		debug_pair(vp);
		fr_pair_add(&request->packet->vps, vp);
	}

	return 0;
}


static void arp_socket_free(rad_listen_t *this)
{
	arp_socket_t *sock = this->data;

	talloc_free(sock);
	this->data = NULL;
}

/** Build PCAP filter string to pass to libpcap
 * Will be called by init_pcap.
 *
 * @param this listen section (not used)
 * @return PCAP filter string
 */
static const char * arp_pcap_filter_builder(UNUSED rad_listen_t *this)
{
	return "arp";
}

static int arp_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode;
	arp_socket_t *sock = this->data;
	RADCLIENT *client;
	CONF_PAIR	*cp = NULL;

	sock->lsock.pcap_filter_builder = arp_pcap_filter_builder;
	sock->lsock.pcap_type = PCAP_INTERFACE_IN;

	this->nodup = true;	/* don't check for duplicates */

	/* Add ipaddress to conf section as it is not required by ARP config */
	cp = cf_pair_alloc(cs, "ipv4addr", "0.0.0.0", T_OP_SET, T_BARE_WORD, T_BARE_WORD);
	cf_pair_add(cs, cp);

	rcode = common_socket_parse(cs, this);
	if (rcode != 0) return rcode;

	if (!sock->lsock.interface) {
		cf_log_err_cs(cs, "'interface' is required for arp");
		return -1;
	}

	if (check_config) return 0;

	/*
	 *	The server core is still RADIUS, and needs a client.
	 *	So we fake one here.
	 */
	client = &sock->client;
	memset(client, 0, sizeof(*client));
	client->ipaddr.af = AF_INET;
	client->ipaddr.ipaddr.ip4addr.s_addr = INADDR_NONE;
	client->ipaddr.prefix = 0;
	client->longname = client->shortname = sock->lsock.interface;
	client->secret = client->shortname;
	client->nas_type = talloc_typed_strdup(sock, "none");

	return 0;
}

static int arp_socket_print(const rad_listen_t *this, char *buffer, size_t bufsize)
{
	arp_socket_t *sock = this->data;

	snprintf(buffer, bufsize, "arp interface %s", sock->lsock.interface);

	return 1;
}

extern fr_protocol_t proto_arp;
fr_protocol_t proto_arp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "arp",
	.inst_size	= sizeof(arp_socket_t),
	.parse		= arp_socket_parse,
	.free		= arp_socket_free,
	.recv		= arp_socket_recv,
	.send		= arp_socket_send,
	.print		= arp_socket_print,
	.encode		= arp_socket_encode,
	.decode		= arp_socket_decode
};
