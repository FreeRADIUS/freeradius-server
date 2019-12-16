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
 * @copyright 2013 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/pcap.h>
#include <net/if_arp.h>

typedef struct {
	listen_socket_t	lsock;
	uint64_t	counter;
	RADCLIENT	client;
} arp_socket_t;

/*
 *	ARP for ethernet && IPv4.
 */
typedef struct {
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

static fr_dict_t const *dict_arp;

extern fr_dict_autoload_t proto_arp_dict[];
fr_dict_autoload_t proto_arp_dict[] = {
	{ .out = &dict_arp, .proto = "arp" },
	{ NULL }
};

static int request_receive(UNUSED TALLOC_CTX *ctx, UNUSED rad_listen_t *listener, UNUSED RADIUS_PACKET *packet,
		    UNUSED RADCLIENT *client, UNUSED RAD_REQUEST_FUNP fun)
{
	return 0;
}

static rlm_rcode_t arp_process(REQUEST *request)
{
	CONF_SECTION *unlang;

	request->server_cs = request->listener->server_cs;
	unlang = cf_section_find(request->server_cs, "arp", NULL);

	request->component = "arp";

	return unlang_interpret_section(request, unlang, RLM_MODULE_NOOP);
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

	link_len = fr_pcap_link_layer_offset(data, header->caplen, sock->lsock.pcap->link_layer);
	if (link_len < 0) {
		PERROR("Failed determining link layer header offset");
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
		fr_radius_packet_free(&packet);
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


typedef struct {
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
	int			i;
	uint8_t	const		*p = request->packet->data, *end = p + request->packet->data_len;
	fr_cursor_t		cursor;

	fr_cursor_init(&cursor, &request->packet->vps);

	for (i = 0; header_names[i].name != NULL; i++) {
		ssize_t			ret;
		size_t			len;
		fr_dict_attr_t const	*da;
		VALUE_PAIR		*vp = NULL;

		len = header_names[i].len;

		if (!fr_cond_assert((size_t)(end - p) < len)) return -1; /* Should have been detected in socket_recv */

		da = fr_dict_attr_by_name(dict_arp, header_names[i].name);
		if (!da) return 0;

		MEM(vp = fr_pair_afrom_da(request->packet, da));
		ret = fr_value_box_from_network(vp, &vp->data, da->type, da, p, len, true);
		if (ret <= 0) {
			fr_pair_to_unknown(vp);
			fr_pair_value_memcpy(vp, p, len, true);
		}

		DEBUG2("&%pP", vp);
		fr_cursor_insert(&cursor, vp);
	}

	return 0;
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
	arp_socket_t	*sock = this->data;
	RADCLIENT	*client;
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
		cf_log_err(cs, "'interface' is required for arp");
		return -1;
	}

	/*
	 *	The server core is still RADIUS, and needs a client.
	 *	So we fake one here.
	 */
	client = &sock->client;
	memset(client, 0, sizeof(*client));
	client->ipaddr.af = AF_INET;
	client->ipaddr.addr.v4.s_addr = INADDR_NONE;
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

/*
 *	If there's no "arp" section, we can't bootstrap anything.
 */
static int arp_socket_bootstrap(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	CONF_SECTION *cs;

	cs = cf_section_find(server_cs, "arp", NULL);
	if (!cs) {
		cf_log_err(server_cs, "No 'arp' sub-section found");
		return -1;
	}

	return 0;
}

/*
 *	Ensure that the "arp" section is compiled.
 */
static int arp_socket_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	CONF_SECTION *cs;

	cs = cf_section_find(server_cs, "arp", NULL);
	if (!cs) {
		cf_log_err(server_cs, "No 'arp' sub-section found");
		return -1;
	}

	cf_log_debug(cs, "Loading arp {...}");

	if (unlang_compile(cs, MOD_POST_AUTH, NULL, NULL) < 0) {
		cf_log_err(cs, "Failed compiling 'arp' section");
		return -1;
	}

	return 0;
}

extern rad_protocol_t proto_arp;
rad_protocol_t proto_arp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "arp",
	.inst_size	= sizeof(arp_socket_t),
	.transports	= 0,
	.tls		= false,

	.bootstrap	= arp_socket_bootstrap,
	.compile	= arp_socket_compile,
	.parse		= arp_socket_parse,
	.open		= common_socket_open,
	.recv		= arp_socket_recv,
	.send		= arp_socket_send,
	.print		= arp_socket_print,
	.debug		= common_packet_debug,
	.encode		= arp_socket_encode,
	.decode		= arp_socket_decode
};
