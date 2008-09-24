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

static int dhcp_process(REQUEST *request)
{
	int rcode;
	VALUE_PAIR *vp;

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

	/*
	 *	Look for Relay attribute, and forward it if so...
	 */

	vp = pairfind(request->reply->vps, DHCP2ATTR(53)); /* DHCP-Message-Type */
	if (vp) {
		request->reply->code = vp->vp_integer;
	}
	else switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		if (request->packet->code == (PW_DHCP_DISCOVER)) {
			request->reply->code = PW_DHCP_OFFER;
			break;

		} else if (request->packet->code == PW_DHCP_REQUEST) {
			request->reply->code = PW_DHCP_ACK;
			break;
		}

		/* FALL-THROUGH */

	default:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
		request->reply->code = PW_DHCP_NAK;
		break;

	case RLM_MODULE_HANDLED:
		break;
	}

	return 1;
}

static int dhcp_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode;
	int on = 1;
	listen_socket_t *sock;

	rcode = common_socket_parse(cs, this);
	if (rcode != 0) return rcode;

	sock = this->data;

	/*
	 *	FIXME: Parse config file option for "do broadast = yes/no"
	 */
	if (setsockopt(this->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		radlog(L_ERR, "Can't set broadcast option: %s\n",
		       strerror(errno));
		return -1;
	}

	if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		radlog(L_ERR, "Can't set re-use addres option: %s\n",
		       strerror(errno));
		return -1;
	}

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
	RADCLIENT	*client;

	packet = fr_dhcp_recv(listener->fd);
	if (!packet) {
		radlog(L_ERR, "%s", fr_strerror());
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &packet->src_ipaddr,
					   packet->src_port)) == NULL) {
		rad_free(&packet);
		return 0;
	}

	if (!received_request(listener, packet, prequest, client)) {
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
	rad_assert(request->listener == listener);
	rad_assert(listener->send == dhcp_socket_send);

	if (request->reply->code == 0) return 0; /* don't reply */

	if (fr_dhcp_encode(request->reply, request->packet) < 0) {
		return -1;
	}

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

