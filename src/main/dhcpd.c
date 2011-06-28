/*
 * dhcp.c	DHCP processing.  Done poorly for now.
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
 * Copyright 2008 Alan DeKok <aland@deployingradius.com>
 */

#ifdef WITH_DHCP

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
} dhcp_socket_t;

static int dhcp_process(REQUEST *request)
{
	int rcode;
	VALUE_PAIR *vp;

	vp = pairfind(request->packet->vps, 53, DHCP_MAGIC_VENDOR); /* DHCP-Message-Type */
	if (vp) {
		DICT_VALUE *dv = dict_valbyattr(53, DHCP_MAGIC_VENDOR, vp->vp_integer);
		DEBUG("Trying sub-section dhcp %s {...}",
		      dv->name ? dv->name : "<unknown>");
		rcode = module_post_auth(vp->vp_integer, request);
	} else {
		DEBUG("DHCP: Failed to find DHCP-Message-Type in packet!");
		rcode = RLM_MODULE_FAIL;
	}

	/*
	 *	For messages from a client, look for Relay attribute,
	 *	and forward it if necessary.
	 */
	if (request->packet->data[0] == 1) {
		vp = pairfind(request->config_items, 270, DHCP_MAGIC_VENDOR);
	}
	if (vp) {
		VALUE_PAIR *giaddr;
		
		/*
		 *	Find the original giaddr.
		 *	FIXME: Maybe look in the original packet?
		 *
		 *	It's invalid to have giaddr=0 AND a relay option
		 */
		giaddr = pairfind(request->packet->vps, 266, DHCP_MAGIC_VENDOR);
		if (giaddr && (giaddr->vp_ipaddr == htonl(INADDR_ANY))) {
			if (pairfind(request->packet->vps, 82, DHCP_MAGIC_VENDOR)) {
				RDEBUG("DHCP: Received packet with giaddr = 0 and containing relay option: Discarding packet");
				return 1;
			}
		}

		if (request->packet->data[3] > 10) {
			RDEBUG("DHCP: Number of hops is greater than 10: not relaying");
			return 1;
		}

		/*
		 *	Say there's no "original" packet.  Instead,
		 *	just forward the "response".
		 */
		rad_free(&request->reply);
		request->reply = request->packet;
		request->packet = NULL;

		request->reply->src_ipaddr = request->reply->dst_ipaddr;
		request->reply->src_port = request->reply->dst_port;
		request->reply->dst_ipaddr.af = AF_INET;
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		/*
		 *	Don't change the destination port.  It's the
		 *	server port.
		 */

		/*
		 *	Hop count goes up.
		 */
		vp = pairfind(request->reply->vps, DHCP2ATTR(259));
		if (vp) vp->vp_integer++;
		
		return 1;
	}

	/*
	 *	Responses from a server.  Handle them differently.
	 */
	if (request->packet->data[0] == 2) {
		/*
		 *	Delete any existing giaddr.  If we received a
		 *	message from the server, then we're NOT the
		 *	server.  So we must be the destination of the
		 *	giaddr field.
		 */
		pairdelete(&request->packet->vps, DHCP2ATTR(266));

		rad_free(&request->reply);
		request->reply = request->packet;
		request->packet = NULL;

		/*
		 *	Search for client IP address.
		 */
		vp = pairfind(request->packet->vps, DHCP2ATTR(264));
		if (!vp) {
			request->reply->code = 0;
			RDEBUG("DHCP: No YIAddr in the reply. Discarding packet");
			return 1;
		}

		/*
		 *	FROM us, TO the client's IP, OUR port + 1.
		 */
		request->reply->src_ipaddr = request->reply->dst_ipaddr;
		request->reply->src_port = request->reply->dst_port;
		request->reply->dst_ipaddr.af = AF_INET;
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		request->reply->dst_port++;

		/*
		 *	Hop count goes down.
		 */
		vp = pairfind(request->reply->vps, DHCP2ATTR(259));
		if (vp && (vp->vp_integer > 0)) vp->vp_integer--;

		/*
		 *	FIXME: Keep original somewhere?  If the
		 *	broadcast flags are set, use them here?
		 */
		
		return 1;
	}

	vp = pairfind(request->reply->vps, 53, DHCP_MAGIC_VENDOR); /* DHCP-Message-Type */
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
		break;
	}

	/*
	 *	Releases don't get replies.
	 */
	if (request->packet->code == PW_DHCP_RELEASE) {
		request->reply->code = 0;
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

		value = cf_pair_value(cp);

		if (value && (strcmp(value, "yes") == 0)) {
			sock->suppress_responses = TRUE;
		}
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
static int dhcp_socket_recv(rad_listen_t *listener)
{
	RADIUS_PACKET	*packet;
	dhcp_socket_t	*sock;

	packet = fr_dhcp_recv(listener->fd);
	if (!packet) {
		radlog(L_ERR, "%s", fr_strerror());
		return 0;
	}

	sock = listener->data;
	if (!request_receive(listener, packet, &sock->dhcp_client, dhcp_process)) {
		rad_free(&packet);
		return 0;
	}

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

	if (fr_dhcp_encode(request->reply, request->packet) < 0) {
		return -1;
	}

	sock = listener->data;
	if (sock->suppress_responses) return 0;

	return fr_dhcp_send(request->reply);
}


static int dhcp_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	DEBUG2("NO ENCODE!");
	return 0;
	return fr_dhcp_encode(request->reply, request->packet);
}


static int dhcp_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	return fr_dhcp_decode(request->packet);
}
#endif /* WITH_DCHP */

