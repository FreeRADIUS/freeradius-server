/*
 * dhcp.c	DHCP processing.
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
 * Copyright 2008 The FreeRADIUS server project
 * Copyright 2008,2011 Alan DeKok <aland@deployingradius.com>
 */

#ifdef WITH_DHCP

/*
 * Standard sequence:
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	DISCOVER
 *	CLIENT_IP : 68 <- DHCP_SERVER_IP : 67		OFFER
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	REQUEST
 *	CLIENT_IP : 68 <- DHCP_SERVER_IP : 67		ACK
 *
 * Relay sequence:
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	DISCOVER
 *	RELAY_IP : 67 -> NEXT_SERVER_IP : 67		DISCOVER
 *				(NEXT_SERVER_IP can be a relay itself)
 *	FIRST_RELAY_IP : 67 <- DHCP_SERVER_IP : 67	OFFER
 *	CLIENT_IP : 68 <- FIRST_RELAY_IP : 67		OFFER
 *	INADDR_ANY : 68 -> INADDR_BROADCAST : 67	REQUEST
 *	RELAY_IP : 67 -> NEXT_SERVER_IP : 67		REQUEST
 *				(NEXT_SERVER_IP can be a relay itself)
 *	FIRST_RELAY_IP : 67 <- DHCP_SERVER_IP : 67	ACK
 *	CLIENT_IP : 68 <- FIRST_RELAY_IP : 67		ACK
 *
 * Note: NACK are broadcasted, rest is unicast, unless client asked
 * for a broadcast
 */

/*
 *	Same contents as listen_socket_t.
 */
typedef struct dhcp_socket_t {
	/*
	 *	For normal sockets.
	 */
	fr_ipaddr_t	ipaddr;
	int		port;
	const char		*interface;
	RADCLIENT_LIST	*clients;

	/*
	 *	DHCP-specific additions.
	 */
	int		suppress_responses;
	RADCLIENT	dhcp_client;
	const char	*src_interface;
        fr_ipaddr_t     src_ipaddr;
} dhcp_socket_t;

#ifdef WITH_UDPFROMTO
static int dhcprelay_process_client_request(REQUEST *request)
{
	uint8_t maxhops = 16;
	VALUE_PAIR *vp, *giaddrvp;
	dhcp_socket_t *sock;

	rad_assert(request->packet->data[0] == 1);

	/*
	 * Do the forward by ourselves, do not rely on dhcp_socket_send()
	 */
	request->reply->code = 0;

	/*
	 * It's invalid to have giaddr=0 AND a relay option
	 */
	giaddrvp = vp = pairfind(request->packet->vps, DHCP2ATTR(266)); /* DHCP-Gateway-IP-Address */
	if ((vp && (vp->vp_ipaddr == htonl(INADDR_ANY))) &&
	    pairfind(request->packet->vps, DHCP2ATTR(82))) { /* DHCP-Relay-Agent-Information */
		DEBUG("DHCP: Received packet with giaddr = 0 and containing relay option: Discarding packet\n");
		return 1;
	}

	/*
	 * RFC 1542 (BOOTP), page 15
	 *
	 * Drop requests if hop-count > 16 or admin specified another value
	 */
	if ((vp = pairfind(request->config_items, DHCP2ATTR(271)))) { /* DHCP-Relay-Max-Hop-Count */
	    maxhops = vp->vp_integer;
	}
	vp = pairfind(request->packet->vps, DHCP2ATTR(259)); /* DHCP-Hop-Count */
	rad_assert(vp != NULL);
	if (vp->vp_integer > maxhops) {
		DEBUG("DHCP: Number of hops is greater than %d: not relaying\n", maxhops);
		return 1;
	} else {
	    /* Increment hop count */
	    vp->vp_integer++;
	}

	sock = request->listener->data;

	/*
	 *	Forward the request to the next server using the
	 *	incoming request as a template.
	 */
	/* set SRC ipaddr/port to the listener ipaddr/port */
	request->packet->src_ipaddr.af = AF_INET;
	request->packet->src_ipaddr.ipaddr.ip4addr.s_addr = giaddrvp->vp_ipaddr;
	request->packet->src_port = sock->port;

	vp = pairfind(request->config_items, DHCP2ATTR(270)); /* DHCP-Relay-To-IP-Address */
	rad_assert(vp != NULL);

	/* set DEST ipaddr/port to the next server ipaddr/port */
	request->packet->dst_ipaddr.af = AF_INET;
	request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	request->packet->dst_port = request->packet->dst_port;

	if (fr_dhcp_encode(request->packet) < 0) {
		DEBUG("dhcprelay_process_client_request: ERROR in fr_dhcp_encode\n");
		return -1;
	}

	return fr_dhcp_send(request->packet);
}

static int dhcprelay_process_server_reply(REQUEST *request)
{
	VALUE_PAIR *vp, *giaddrvp;
	dhcp_socket_t *sock;

	rad_assert(request->packet->data[0] == 2);

	/*
	 * Do the forward by ourselves, do not rely on dhcp_socket_send()
	 */
	request->reply->code = 0;

	sock = request->listener->data;

	/*
	 * Check that packet is for us.
	 */
	giaddrvp = vp = pairfind(request->packet->vps, DHCP2ATTR(266)); /* DHCP-Gateway-IP-Address */
	rad_assert(vp != NULL);

	/* --with-udpfromto is needed just for the following test */
	if (!vp || vp->vp_ipaddr != request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr) {
		DEBUG("DHCP: Packet received from server was not for us (was for 0x%x). Discarding packet",
		    ntohl(request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr));
		return 1;
	}

	/* set SRC ipaddr/port to the listener ipaddr/port */
	request->packet->src_ipaddr.af = AF_INET;
	request->packet->src_ipaddr.ipaddr.ip4addr.s_addr = giaddrvp->vp_ipaddr;
	request->packet->src_port = sock->port;

	/* set DEST ipaddr/port to clientip/68 or broadcast in specific cases */
	request->packet->dst_ipaddr.af = AF_INET;
	request->packet->dst_port = request->packet->dst_port + 1; /* Port 68 */

	if ((request->packet->code == PW_DHCP_NAK) ||
	    ((vp = pairfind(request->packet->vps, DHCP2ATTR(262))) /* DHCP-Flags */ &&
		(vp->vp_integer & 0x8000) &&
		((vp = pairfind(request->packet->vps, DHCP2ATTR(263))) /* DHCP-Client-IP-Address */ &&
		    (vp->vp_ipaddr == htonl(INADDR_ANY))))) {
		/*
		 * RFC 2131, page 23
		 *
		 * Broadcast on
		 * - DHCPNAK
		 * or
		 * - Broadcast flag is set up and ciaddr == NULL
		 */
		request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_BROADCAST);
	} else {
		/*
		 * RFC 2131, page 23
		 *
		 * Unicast to
		 * - ciaddr if present
		 * otherwise to yiaddr
		 */
		if ((vp = pairfind(request->packet->vps, DHCP2ATTR(263))) /* DHCP-Client-IP-Address */ &&
		    (vp->vp_ipaddr != htonl(INADDR_ANY))) {
			request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		} else {
			vp = pairfind(request->packet->vps, DHCP2ATTR(264)); /* DHCP-Your-IP-Address */
			if (!vp) {
				DEBUG("DHCP: Failed to find IP Address for request.");
				return -1;
			}

			request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;

			/*
			 * When sending a DHCP_OFFER, make sure our ARP table
			 * contains an entry for the client IP address, or else
			 * packet may not be forwarded if it was the first time
			 * the client was requesting an IP address.
			 */
			if (request->packet->code == PW_DHCP_OFFER) {
				VALUE_PAIR *hwvp = pairfind(request->packet->vps, DHCP2ATTR(267)); /* DHCP-Client-Hardware-Address */
				if (hwvp == NULL) {
					DEBUG("DHCP: DHCP_OFFER packet received with "
					    "no Client Hardware Address. Discarding packet");
					return 1;
				}
				if (fr_dhcp_add_arp_entry(request->packet->sockfd, sock->src_interface, hwvp, vp) < 0) {
					DEBUG("%s", fr_strerror());
					return -1;
				}
			}
		}
	}

	if (fr_dhcp_encode(request->packet) < 0) {
		DEBUG("dhcprelay_process_server_reply: ERROR in fr_dhcp_encode\n");
		return -1;
	}

	return fr_dhcp_send(request->packet);
}
#else  /* WITH_UDPFROMTO */
static int dhcprelay_process_server_reply(UNUSED REQUEST *request)
{
	DEBUG("WARNING: DHCP Relaying requires the server to be configured with UDPFROMTO");
	return -1;
}

static int dhcprelay_process_client_request(UNUSED REQUEST *request)
{
	DEBUG("WARNING: DHCP Relaying requires the server to be configured with UDPFROMTO");
	return -1;
}

#endif	/* WITH_UDPFROMTO */

static const uint32_t attrnums[] = {
	57,	/* DHCP-DHCP-Maximum-Msg-Size */
	256,	/* DHCP-Opcode */
	257,	/* DHCP-Hardware-Type */
	258,	/* DHCP-Hardware-Address-Length */
	259,	/* DHCP-Hop-Count */
	260,	/* DHCP-Transaction-Id */
	262,	/* DHCP-Flags */
	263,	/* DHCP-Client-IP-Address */
	266,	/* DHCP-Gateway-IP-Address */
	267	/* DHCP-Client-Hardware-Address */
};

static int dhcp_process(REQUEST *request)
{
	int rcode;
	unsigned int i;
	VALUE_PAIR *vp;
	dhcp_socket_t *sock;

	vp = pairfind(request->packet->vps, DHCP2ATTR(53)); /* DHCP-Message-Type */
	if (vp) {
		DICT_VALUE *dv = dict_valbyattr(DHCP2ATTR(53), vp->vp_integer);
		DEBUG("Trying sub-section dhcp %s {...}",
		      dv->name ? dv->name : "<unknown>");
		rcode = module_post_auth(vp->vp_integer, request);
	} else {
		DEBUG("DHCP: Failed to find DHCP-Message-Type in packet!");
		rcode = RLM_MODULE_FAIL;
	}

	vp = pairfind(request->reply->vps, DHCP2ATTR(53)); /* DHCP-Message-Type */
	if (vp) {
		request->reply->code = vp->vp_integer;
		if ((request->reply->code != 0) &&
		    (request->reply->code < PW_DHCP_OFFSET)) {
			request->reply->code += PW_DHCP_OFFSET;
		}
	}
	else switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		if (request->packet->code == PW_DHCP_DISCOVER) {
			request->reply->code = PW_DHCP_OFFER;
			break;

		} else if (request->packet->code == PW_DHCP_REQUEST) {
			request->reply->code = PW_DHCP_ACK;
			break;
		}
		request->reply->code = PW_DHCP_NAK;
		break;

	default:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
		if (request->packet->code == PW_DHCP_DISCOVER) {
			request->reply->code = 0; /* ignore the packet */
		} else {
			request->reply->code = PW_DHCP_NAK;
		}
		break;

	case RLM_MODULE_HANDLED:
		request->reply->code = 0; /* ignore the packet */
		break;
	}

	/*
	 *	TODO: Handle 'output' of RLM_MODULE when acting as a
	 *	DHCP relay We may want to not forward packets in
	 *	certain circumstances.
	 */

	/*
	 * 	Handle requests when acting as a DHCP relay
	 */
	vp = pairfind(request->packet->vps, DHCP2ATTR(256)); /* DHCP-Opcode */
	if (!vp) {
		RDEBUG("FAILURE: Someone deleted the DHCP-Opcode!");
		return 1;
	}

	/* BOOTREPLY received on port 67 (i.e. from a server) */
	if (vp->vp_integer == 2) {
		return dhcprelay_process_server_reply(request);
	}

	/* Packet from client, and we have DHCP-Relay-To-IP-Address */
	if (pairfind(request->config_items, DHCP2ATTR(270))) { 
		return dhcprelay_process_client_request(request);
	}

	/* else it's a packet from a client, without relaying */
	rad_assert(vp->vp_integer == 1); /* BOOTREQUEST */

	sock = request->listener->data;

	/*
	 *	Handle requests when acting as a DHCP server
	 */

	/*
	 *	Releases don't get replies.
	 */
	if (request->packet->code == PW_DHCP_RELEASE) {
		request->reply->code = 0;
	}

	if (request->reply->code == 0) {
		return 1;
	}

	request->reply->sockfd = request->packet->sockfd;

	/*
	 *	Copy specific fields from packet to reply, if they
	 *	don't already exist
	 */
	for (i = 0; i < sizeof(attrnums) / sizeof(attrnums[0]); i++) {
		uint32_t attr = attrnums[i];

		if (pairfind(request->reply->vps, DHCP2ATTR(attr))) continue;
		if ((vp = pairfind(request->packet->vps, DHCP2ATTR(attr)))) {
			pairadd(&request->reply->vps, paircopyvp(vp));
		}
	}

	vp = pairfind(request->reply->vps, DHCP2ATTR(256)); /* DHCP-Opcode */
	rad_assert(vp != NULL);
	vp->vp_integer = 2; /* BOOTREPLY */

	/*
	 * Prepare the reply packet for sending through dhcp_socket_send()
	 */
	request->reply->dst_ipaddr.af = AF_INET;
	request->reply->src_ipaddr.af = AF_INET;
	request->reply->src_ipaddr.ipaddr.ip4addr.s_addr = sock->src_ipaddr.ipaddr.ip4addr.s_addr;

	request->reply->dst_port = request->packet->src_port;
	request->reply->src_port = request->packet->dst_port;

	vp = pairfind(request->reply->vps, DHCP2ATTR(266)); /* DHCP-Gateway-IP-Address */
	if (vp && (vp->vp_ipaddr != htonl(INADDR_ANY))) {
		/* Answer to client's nearest DHCP relay */
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	} else if ((request->reply->code == PW_DHCP_NAK) ||
	    ((vp = pairfind(request->reply->vps, DHCP2ATTR(262))) /* DHCP-Flags */ &&
		(vp->vp_integer & 0x8000) &&
		((vp = pairfind(request->reply->vps, DHCP2ATTR(263))) /* DHCP-Client-IP-Address */ &&
		    (vp->vp_ipaddr == htonl(INADDR_ANY))))) {
		/*
		 * RFC 2131, page 23
		 *
		 * Broadcast on
		 * - DHCPNAK
		 * or
		 * - Broadcast flag is set up and ciaddr == NULL
		 */
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_BROADCAST);
	} else {
		/*
		 * RFC 2131, page 23
		 *
		 * Unicast to
		 * - ciaddr if present
		 * otherwise to yiaddr
		 */
		if ((vp = pairfind(request->reply->vps, DHCP2ATTR(263))) /* DHCP-Client-IP-Address */ &&
		    (vp->vp_ipaddr != htonl(INADDR_ANY))) {
			request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		} else {
			vp = pairfind(request->reply->vps, DHCP2ATTR(264)); /* DHCP-Your-IP-Address */
			if (!vp) {
				DEBUG("DHCP: Failed to find IP Address for request.");
				return -1;
			}
			
			request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;

			/*
			 * When sending a DHCP_OFFER, make sure our ARP table
			 * contains an entry for the client IP address, or else
			 * packet may not be forwarded if it was the first time
			 * the client was requesting an IP address.
			 */
			if (request->reply->code == PW_DHCP_OFFER) {
				VALUE_PAIR *hwvp = pairfind(request->reply->vps, DHCP2ATTR(267)); /* DHCP-Client-Hardware-Address */

				if (!hwvp) return -1;

				if (fr_dhcp_add_arp_entry(request->reply->sockfd, sock->src_interface, hwvp, vp) < 0) {
					return -1;
				}
			}
		}
	}

	return 1;
}

static int dhcp_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode, broadcast = 1;
	int on = 1;
	dhcp_socket_t *sock;
	RADCLIENT *client;
	CONF_PAIR *cp;

	rcode = common_socket_parse(cs, this);
	if (rcode != 0) return rcode;

	if (check_config) return 0;

	sock = this->data;

	if (!sock->interface) {
		DEBUG("WARNING: No \"interface\" setting is defined.  Only unicast DHCP will work.");
	}

	/*
	 *	See whether or not we enable broadcast packets.
	 */
	cp = cf_pair_find(cs, "broadcast");
	if (cp) {
		const char *value = cf_pair_value(cp);
		if (value && (strcmp(value, "no") == 0)) {
			broadcast = 0;
		}
	}

	if (broadcast) {
		if (setsockopt(this->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
			radlog(L_ERR, "Can't set broadcast option: %s\n",
			       strerror(errno));
			return -1;
		}
	}

	if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		radlog(L_ERR, "Can't set re-use addres option: %s\n",
		       strerror(errno));
		return -1;
	}

	/*
	 *	Undocumented extension for testing without
	 *	destroying your network!
	 */
	sock->suppress_responses = FALSE;
	cp = cf_pair_find(cs, "suppress_responses");
	if (cp) {
		const char *value;

		cf_item_parse(cs, "suppress_responses", PW_TYPE_BOOLEAN,
			      &sock->suppress_responses, NULL);
	}
	
	cp = cf_pair_find(cs, "src_interface");
	if (cp) {
		cf_item_parse(cs, "src_interface", PW_TYPE_STRING_PTR,
			      &sock->src_interface, NULL);
	} else {
                sock->src_interface = sock->interface;
        }

	if (!sock->src_interface && sock->interface) {
		sock->src_interface = strdup(sock->interface);
	}

	cp = cf_pair_find(cs, "src_ipaddr");
	if (cp) {
		memset(&sock->src_ipaddr, 0, sizeof(sock->src_ipaddr));
		sock->src_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
		rcode = cf_item_parse(cs, "src_ipaddr", PW_TYPE_IPADDR,
				      &sock->src_ipaddr.ipaddr.ip4addr, NULL);
		if (rcode < 0) return -1;

		sock->src_ipaddr.af = AF_INET;
	} else {
		memcpy(&sock->src_ipaddr, &sock->ipaddr, sizeof(sock->src_ipaddr));
	}

	/*
	 *	Initialize the fake client.
	 */
	client = &sock->dhcp_client;
	memset(client, 0, sizeof(*client));
	client->ipaddr.af = AF_INET;
	client->ipaddr.ipaddr.ip4addr.s_addr = INADDR_NONE;
	client->prefix = 0;
	client->longname = client->shortname = "dhcp";
	client->secret = client->shortname;
	client->nastype = strdup("none");

	return 0;
}


/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int dhcp_socket_recv(rad_listen_t *listener,
			    RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	RADIUS_PACKET	*packet;
	dhcp_socket_t	*sock;

	packet = fr_dhcp_recv(listener->fd);
	if (!packet) {
		radlog(L_ERR, "%s", fr_strerror());
		return 0;
	}

	sock = listener->data;
	if (!received_request(listener, packet, prequest, &sock->dhcp_client)) {
		rad_free(&packet);
		return 0;
	}

	*pfun = dhcp_process;

	return 1;
}


/*
 *	Send an authentication response packet
 */
static int dhcp_socket_send(rad_listen_t *listener, REQUEST *request)
{
	dhcp_socket_t	*sock;

	rad_assert(request->listener == listener);
	rad_assert(listener->send == dhcp_socket_send);

	if (request->reply->code == 0) return 0; /* don't reply */

	if (fr_dhcp_encode(request->reply) < 0) {
		DEBUG("dhcp_socket_send: ERROR\n");
		return -1;
	}
	sock = listener->data;
	if (sock->suppress_responses) return 0;

	return fr_dhcp_send(request->reply);
}


static int dhcp_socket_encode(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	DEBUG2("NO ENCODE!");
	return 0;
}


static int dhcp_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	return fr_dhcp_decode(request->packet);
}
#endif /* WITH_DCHP */

