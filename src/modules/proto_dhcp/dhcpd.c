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


#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/dhcp.h>
#include <freeradius-devel/rad_assert.h>

#ifndef __MINGW32__
#include <sys/ioctl.h>
#endif

/*
 *	Same contents as listen_socket_t.
 */
typedef struct dhcp_socket_t {
	listen_socket_t	lsock;

	/*
	 *	DHCP-specific additions.
	 */
	bool		suppress_responses;
	RADCLIENT	dhcp_client;
	char const	*src_interface;
	fr_ipaddr_t     src_ipaddr;
} dhcp_socket_t;

#ifdef WITH_UDPFROMTO
static int dhcprelay_process_client_request(REQUEST *request)
{
	int rcode;
	uint8_t maxhops = 16;
	VALUE_PAIR *vp, *giaddr;
	dhcp_socket_t *sock;
	RADIUS_PACKET *packet;

	rad_assert(request->packet->data[0] == 1);

	/*
	 *	Do the forward by ourselves, do not rely on dhcp_socket_send()
	 */
	request->reply->code = 0;

	/*
	 * It's invalid to have giaddr=0 AND a relay option
	 */
	giaddr = fr_pair_find_by_num(request->packet->vps, 266, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Gateway-IP-Address */
	if (giaddr && (giaddr->vp_ipaddr == htonl(INADDR_ANY)) &&
	    fr_pair_find_by_num(request->packet->vps, 82, DHCP_MAGIC_VENDOR, TAG_ANY)) { /* DHCP-Relay-Agent-Information */
		DEBUG("DHCP: Received packet with giaddr = 0 and containing relay option: Discarding packet\n");
		return 1;
	}

	/*
	 * RFC 1542 (BOOTP), page 15
	 *
	 * Drop requests if hop-count > 16 or admin specified another value
	 */
	if ((vp = fr_pair_find_by_num(request->config, 271, DHCP_MAGIC_VENDOR, TAG_ANY))) { /* DHCP-Relay-Max-Hop-Count */
	    maxhops = vp->vp_integer;
	}
	vp = fr_pair_find_by_num(request->packet->vps, 259, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Hop-Count */
	rad_assert(vp != NULL);
	if (vp->vp_byte > maxhops) {
		DEBUG("DHCP: Number of hops is greater than %d: not relaying\n", maxhops);
		return 1;
	} else {
		/* Increment hop count */
		vp->vp_byte++;
	}

	sock = request->listener->data;

	/*
	 *	Don't muck with the original request packet.  That's
	 *	bad form.  Plus, dhcp_encode() does nothing if
	 *	packet->data is already set.
	 */
	packet = rad_alloc(request, false);

	/*
	 *	Forward the request to the next server using the
	 *	incoming request as a template.
	 */
	packet->code = request->packet->code;
	packet->sockfd = request->packet->sockfd;

	/*
	 *	Forward the request to the next server using the
	 *	incoming request as a template.
	 */
	/* set SRC ipaddr/port to the listener ipaddr/port */
	packet->src_ipaddr.af = AF_INET;
	packet->src_ipaddr.ipaddr.ip4addr.s_addr = sock->lsock.my_ipaddr.ipaddr.ip4addr.s_addr;
	packet->src_port = sock->lsock.my_port;

	vp = fr_pair_find_by_num(request->config, 270, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Relay-To-IP-Address */
	rad_assert(vp != NULL);

	/* set DEST ipaddr/port to the next server ipaddr/port */
	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	packet->dst_port = sock->lsock.my_port;

	packet->vps = request->packet->vps; /* hackity hack */

	if (fr_dhcp_encode(packet) < 0) {
		packet->vps = NULL;
		talloc_free(packet);
		DEBUG("dhcprelay_process_client_request: ERROR in fr_dhcp_encode\n");
		return -1;
	}

	rcode = fr_dhcp_send(packet);
	packet->vps = NULL;
	talloc_free(packet);

	return rcode;
}


/*
 *	We've seen a reply from a server.
 *	i.e. we're a relay.
 */
static int dhcprelay_process_server_reply(REQUEST *request)
{
	int rcode;
	VALUE_PAIR *vp, *giaddr;
	dhcp_socket_t *sock;
	RADIUS_PACKET *packet;

	rad_assert(request->packet->data[0] == 2);

	/*
	 * Do the forward by ourselves, do not rely on dhcp_socket_send()
	 */
	request->reply->code = 0;

	sock = request->listener->data;

	/*
	 * Check that packet is for us.
	 */
	giaddr = fr_pair_find_by_num(request->packet->vps, 266, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Gateway-IP-Address */

	/* --with-udpfromto is needed just for the following test */
	if (!giaddr || giaddr->vp_ipaddr != request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr) {
		DEBUG("DHCP: Packet received from server was not for us (was for 0x%x). Discarding packet",
		    ntohl(request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr));
		return 1;
	}

	/*
	 *	Don't muck with the original request packet.  That's
	 *	bad form.  Plus, dhcp_encode() does nothing if
	 *	packet->data is already set.
	 */
	packet = rad_alloc(request, false);
	rcode = -1;

	/*
	 *	Forward the request to the next server using the
	 *	incoming request as a template.
	 */
	packet->code = request->packet->code;
	packet->sockfd = request->packet->sockfd;

	/* set SRC ipaddr/port to the listener ipaddr/port */
	packet->src_ipaddr.af = AF_INET;
	packet->src_port = sock->lsock.my_port;

	/* set DEST ipaddr/port to clientip/68 or broadcast in specific cases */
	packet->dst_ipaddr.af = AF_INET;

	/*
	 *	We're a relay, figure out where to send the packet.
	 */
	packet->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_BROADCAST);
	packet->dst_port = request->packet->dst_port;		/* server port */

	/*
	  *	Unicast the response to another relay if requested.
	  */
	vp = fr_pair_find_by_num(request->config, 270, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Relay-To-IP-Address */
	if (vp) {
		RDEBUG("DHCP: response will be relayed to previous gateway");
		packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		giaddr->vp_ipaddr = vp->vp_ipaddr;

	} else if ((packet->code == PW_DHCP_NAK) ||
	    !sock->src_interface ||
	    ((vp = fr_pair_find_by_num(request->packet->vps, 262, DHCP_MAGIC_VENDOR, TAG_ANY)) /* DHCP-Flags */ &&
	     (vp->vp_integer & 0x8000) &&
	     ((vp = fr_pair_find_by_num(request->packet->vps, 263, DHCP_MAGIC_VENDOR, TAG_ANY)) /* DHCP-Client-IP-Address */ &&
	      (vp->vp_ipaddr == htonl(INADDR_ANY))))) {
		/*
		 * RFC 2131, page 23
		 *
		 * Broadcast on
		 * - DHCPNAK
		 * or
		 * - Broadcast flag is set up and ciaddr == NULL
		 */
		RDEBUG("DHCP: response will be broadcast");
		packet->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_BROADCAST);

	} else if ((vp = fr_pair_find_by_num(request->packet->vps, 263, DHCP_MAGIC_VENDOR, TAG_ANY)) /* DHCP-Client-IP-Address */ &&
		   (vp->vp_ipaddr != htonl(INADDR_ANY))) {
		/*
		 * RFC 2131, page 23
		 *
		 * Unicast to
		 * - ciaddr if present
		 * otherwise to yiaddr
		 */
		packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	} else {
		vp = fr_pair_find_by_num(request->packet->vps, 264, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Your-IP-Address */
		if (!vp) {
			DEBUG("DHCP: Failed to find IP Address for request");
			goto error;
		}

		RDEBUG("DHCP: response will be unicast to your-ip-address");
		packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;

		/*
		 * When sending a DHCP_OFFER, make sure our ARP table
		 * contains an entry for the client IP address, or else
		 * packet may not be forwarded if it was the first time
		 * the client was requesting an IP address.
		 */
		if (packet->code == PW_DHCP_OFFER) {
			VALUE_PAIR *hwvp = fr_pair_find_by_num(request->packet->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Client-Hardware-Address */
			if (hwvp == NULL) {
				DEBUG("DHCP: DHCP_OFFER packet received with "
				      "no Client Hardware Address. Discarding packet");
				goto error;
			}
			if (fr_dhcp_add_arp_entry(packet->sockfd, sock->src_interface, hwvp, vp) < 0) {
				DEBUG("Failed adding ARP entry: %s", fr_strerror());
				goto error;
			}
		}
	}

	packet->vps = request->packet->vps; /* hackity hack */
	
	if (fr_dhcp_encode(packet) < 0) {
		DEBUG("dhcprelay_process_server_reply: ERROR in fr_dhcp_encode\n");
		goto error;
	}

	rcode = fr_dhcp_send(packet);

error:
	packet->vps = NULL;
	talloc_free(packet);
	return rcode;
}
#else  /* WITH_UDPFROMTO */
static int dhcprelay_process_server_reply(UNUSED REQUEST *request)
{
	WARN("DHCP Relaying requires the server to be configured with UDPFROMTO");
	return -1;
}

static int dhcprelay_process_client_request(UNUSED REQUEST *request)
{
	WARN("DHCP Relaying requires the server to be configured with UDPFROMTO");
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

	/*
	 *	If there's a giaddr, save it as the Relay-IP-Address
	 *	in the response.  That way the later code knows where
	 *	to send the reply.
	 */
	vp = fr_pair_find_by_num(request->packet->vps, 266, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Gateway-IP-Address */
	if (vp && (vp->vp_ipaddr != htonl(INADDR_ANY))) {
		VALUE_PAIR *relay;

		/* DHCP-Relay-IP-Address */
		relay = radius_pair_create(request->reply, &request->reply->vps,
					  272, DHCP_MAGIC_VENDOR);
		if (relay) relay->vp_ipaddr = vp->vp_ipaddr;
	}

	vp = fr_pair_find_by_num(request->packet->vps, 53, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Message-Type */
	if (vp) {
		DICT_VALUE *dv = dict_valbyattr(53, DHCP_MAGIC_VENDOR, vp->vp_byte);
		DEBUG("Trying sub-section dhcp %s {...}",
		      dv ? dv->name : "<unknown>");
		rcode = process_post_auth(vp->vp_byte, request);
	} else {
		DEBUG("DHCP: Failed to find DHCP-Message-Type in packet!");
		rcode = RLM_MODULE_FAIL;
	}

	vp = fr_pair_find_by_num(request->reply->vps, 53, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Message-Type */
	if (vp) {
		request->reply->code = vp->vp_byte;
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
	vp = fr_pair_find_by_num(request->packet->vps, 256, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Opcode */
	if (!vp) {
		RDEBUG("FAILURE: Someone deleted the DHCP-Opcode!");
		return 1;
	}

	/* BOOTREPLY received on port 67 (i.e. from a server) */
	if (vp->vp_byte == 2) {
		if (request->reply->code == 0) {
			return 1;
		}
		return dhcprelay_process_server_reply(request);
	}

	/*
	 *	If it's not BOOTREQUEST, we ignore it.
	 */
	if (vp->vp_byte != 1) {
		REDEBUG("Ignoring invalid packet code %u", vp->vp_byte);
		return 1;
	}

	/* Packet from client, and we have DHCP-Relay-To-IP-Address */
	if (fr_pair_find_by_num(request->config, 270, DHCP_MAGIC_VENDOR, TAG_ANY)) {
		return dhcprelay_process_client_request(request);
	}

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

		if (fr_pair_find_by_num(request->reply->vps, attr, DHCP_MAGIC_VENDOR, TAG_ANY)) continue;

		vp = fr_pair_find_by_num(request->packet->vps, attr, DHCP_MAGIC_VENDOR, TAG_ANY);
		if (vp) {
			fr_pair_add(&request->reply->vps, fr_pair_copy(request->reply, vp));
		}
	}

	vp = fr_pair_find_by_num(request->reply->vps, 256, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Opcode */
	rad_assert(vp != NULL);
	vp->vp_byte = 2; /* BOOTREPLY */

	/*
	 *	Allow NAKs to be delayed for a short period of time.
	 */
	if (request->reply->code == PW_DHCP_NAK) {
		vp = fr_pair_find_by_num(request->reply->vps, PW_FREERADIUS_RESPONSE_DELAY, 0, TAG_ANY);
		if (vp) {
			if (vp->vp_integer <= 10) {
				request->response_delay.tv_sec = vp->vp_integer;
				request->response_delay.tv_usec = 0;
			} else {
				request->response_delay.tv_sec = 10;
				request->response_delay.tv_usec = 0;
			}
		} else {
#define USEC 1000000
			vp = fr_pair_find_by_num(request->reply->vps, PW_FREERADIUS_RESPONSE_DELAY_USEC, 0, TAG_ANY);
			if (vp) {
				if (vp->vp_integer <= 10 * USEC) {
					request->response_delay.tv_sec = vp->vp_integer / USEC;
					request->response_delay.tv_usec = vp->vp_integer % USEC;
				} else {
					request->response_delay.tv_sec = 10;
					request->response_delay.tv_usec = 0;
				}
			}
		}
	}

	/*
	 *	Prepare the reply packet for sending through dhcp_socket_send()
	 */
	request->reply->dst_ipaddr.af = AF_INET;
	request->reply->src_ipaddr.af = AF_INET;
	request->reply->src_ipaddr.prefix = 32;

	/*
	 *	Packet-Src-IP-Address has highest precedence
	 */
	vp = fr_pair_find_by_num(request->reply->vps, PW_PACKET_SRC_IP_ADDRESS, 0, TAG_ANY);
	if (vp) {
		request->reply->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	/*
	 *	The request was unicast (via a relay)
	 */
	} else if (request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr != htonl(INADDR_BROADCAST) &&
		   request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr != htonl(INADDR_ANY)) {
		request->reply->src_ipaddr.ipaddr.ip4addr.s_addr = request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr;
	/*
	 *	The listener was bound to an IP address, or we determined
	 *	the address automatically, as it was the only address bound
	 *	to the interface, and we bound to the interface.
	 */
	} else if (sock->src_ipaddr.ipaddr.ip4addr.s_addr != htonl(INADDR_ANY)) {
		request->reply->src_ipaddr.ipaddr.ip4addr.s_addr = sock->src_ipaddr.ipaddr.ip4addr.s_addr;
	/*
	 *	There's a Server-Identification attribute
	 */
	} else if ((vp = fr_pair_find_by_num(request->reply->vps, 54, DHCP_MAGIC_VENDOR, TAG_ANY))) {
		request->reply->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	} else {
		REDEBUG("Unable to determine correct src_ipaddr for response");
		return -1;
	}
	request->reply->dst_port = request->packet->src_port;
	request->reply->src_port = request->packet->dst_port;

	/*
	 *	Answer to client's nearest DHCP relay.
	 *
	 *	Which may be different than the giaddr given in the
	 *	packet to the client.  i.e. the relay may have a
	 *	public IP, but the gateway a private one.
	 */
	vp = fr_pair_find_by_num(request->reply->vps, 272, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Relay-IP-Address */
	if (vp && (vp->vp_ipaddr != ntohl(INADDR_ANY))) {
		RDEBUG("DHCP: Reply will be unicast to giaddr from original packet");
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		request->reply->dst_port = request->packet->dst_port;

		vp = fr_pair_find_by_num(request->reply->vps, PW_PACKET_DST_PORT, 0, TAG_ANY);
		if (vp) request->reply->dst_port = vp->vp_integer;

		return 1;
	}

	/*
	 *	Answer to client's nearest DHCP gateway.  In this
	 *	case, the client can reach the gateway, as can the
	 *	server.
	 *
	 *	We also use *our* source port as the destination port.
	 *	Gateways are servers, and listen on the server port,
	 *	not the client port.
	 */
	vp = fr_pair_find_by_num(request->reply->vps, 266, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Gateway-IP-Address */
	if (vp && (vp->vp_ipaddr != htonl(INADDR_ANY))) {
		RDEBUG("DHCP: Reply will be unicast to giaddr");
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		request->reply->dst_port = request->packet->dst_port;
		return 1;
	}

	/*
	 *	If it's a NAK, or the broadcast flag was set, ond
	 *	there's no client-ip-address, send a broadcast.
	 */
	if ((request->reply->code == PW_DHCP_NAK) ||
	    ((vp = fr_pair_find_by_num(request->reply->vps, 262, DHCP_MAGIC_VENDOR, TAG_ANY)) && /* DHCP-Flags */
	     (vp->vp_integer & 0x8000) &&
	     ((vp = fr_pair_find_by_num(request->reply->vps, 263, DHCP_MAGIC_VENDOR, TAG_ANY)) && /* DHCP-Client-IP-Address */
	      (vp->vp_ipaddr == htonl(INADDR_ANY))))) {
		/*
		 * RFC 2131, page 23
		 *
		 * Broadcast on
		 * - DHCPNAK
		 * or
		 * - Broadcast flag is set up and ciaddr == NULL
		 */
		RDEBUG("DHCP: Reply will be broadcast");
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_BROADCAST);
		return 1;
	}

	/*
	 *	RFC 2131, page 23
	 *
	 *	Unicast to ciaddr if present, otherwise to yiaddr.
	 */
	if ((vp = fr_pair_find_by_num(request->reply->vps, 263, DHCP_MAGIC_VENDOR, TAG_ANY)) && /* DHCP-Client-IP-Address */
	    (vp->vp_ipaddr != htonl(INADDR_ANY))) {
		RDEBUG("DHCP: Reply will be sent unicast to client-ip-address");
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
		return 1;
	}

	vp = fr_pair_find_by_num(request->reply->vps, 264, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Your-IP-Address */
	if (!vp) {
		RDEBUG("DHCP: Failed to find DHCP-Client-IP-Address or DHCP-Your-IP-Address for request; "
		       "not responding");
		/*
		 *	There is nowhere to send the response to, so don't bother.
		 */
		request->reply->code = 0;
		return -1;
	}

#ifdef SIOCSARP
	/*
	 *	The system is configured to listen for broadcast
	 *	packets, which means we'll need to send unicast
	 *	replies, to IPs which haven't yet been assigned.
	 *	Therefore, we need to update the ARP table.
	 *
	 *	However, they haven't specified a interface.  So we
	 *	can't update the ARP table.  And we must send a
	 *	broadcast response.
	 */
	if (sock->lsock.broadcast && !sock->src_interface) {
		WARN("You MUST set \"interface\" if you have \"broadcast = yes\"");
		RDEBUG("DHCP: Reply will be broadcast as no interface was defined");
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_BROADCAST);
		return 1;
	}

	RDEBUG("DHCP: Reply will be unicast to your-ip-address");
	request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;

	/*
	 *	When sending a DHCP_OFFER, make sure our ARP table
	 *	contains an entry for the client IP address.
	 *	Otherwise the packet may not be sent to the client, as
	 *	the OS has no ARP entry for it.
	 *
	 *	This is a cute hack to avoid us having to create a raw
	 *	socket to send DHCP packets.
	 */
	if (request->reply->code == PW_DHCP_OFFER) {
		VALUE_PAIR *hwvp = fr_pair_find_by_num(request->reply->vps, 267, DHCP_MAGIC_VENDOR, TAG_ANY); /* DHCP-Client-Hardware-Address */

		if (!hwvp) return -1;

		if (fr_dhcp_add_arp_entry(request->reply->sockfd, sock->src_interface, hwvp, vp) < 0) {
			RDEBUG("Failed adding ARP entry: %s", fr_strerror());
			return -1;
		}
	}
#else
	if (request->packet->src_ipaddr.ipaddr.ip4addr.s_addr != ntohl(INADDR_NONE)) {
		RDEBUG("DHCP: Request will be unicast to the unicast source IP address");
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = request->packet->src_ipaddr.ipaddr.ip4addr.s_addr;
	} else {
		RDEBUG("DHCP: Reply will be broadcast as this system does not support ARP updates");
		request->reply->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_BROADCAST);
	}
#endif

	return 1;
}

static int dhcp_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode, broadcast = 1;
	int on = 1;
	dhcp_socket_t *sock;
	RADCLIENT *client;
	CONF_PAIR *cp;

	/*
	 *	Set if before parsing, so the user can forcibly turn
	 *	it off later.
	 */
	this->nodup = true;

	rcode = common_socket_parse(cs, this);
	if (rcode != 0) return rcode;

	if (check_config) return 0;

	sock = this->data;

	if (!sock->lsock.interface) {
		WARN("No \"interface\" setting is defined.  Only unicast DHCP will work");
	}

	/*
	 *	See whether or not we enable broadcast packets.
	 */
	cp = cf_pair_find(cs, "broadcast");
	if (cp) {
		char const *value = cf_pair_value(cp);
		if (value && (strcmp(value, "no") == 0)) {
			broadcast = 0;
		}
	}

	if (broadcast) {
		if (setsockopt(this->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
			ERROR("Can't set broadcast option: %s\n",
			       fr_syserror(errno));
			return -1;
		}
	}

	if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		ERROR("Can't set re-use address option: %s\n",
		       fr_syserror(errno));
		return -1;
	}

	/*
	 *	Undocumented extension for testing without
	 *	destroying your network!
	 */
	sock->suppress_responses = false;
	cp = cf_pair_find(cs, "suppress_responses");
	if (cp) {
		rcode = cf_item_parse(cs, "suppress_responses", FR_ITEM_POINTER(PW_TYPE_BOOLEAN, &sock->suppress_responses), NULL);
		if (rcode < 0) return -1;
	}

	cp = cf_pair_find(cs, "src_interface");
	if (cp) {
		rcode = cf_item_parse(cs, "src_interface", FR_ITEM_POINTER(PW_TYPE_STRING, &sock->src_interface), NULL);
		if (rcode < 0) return -1;
	} else {
		sock->src_interface = sock->lsock.interface;
	}

	if (!sock->src_interface && sock->lsock.interface) {
		sock->src_interface = talloc_typed_strdup(sock, sock->lsock.interface);
	}

	cp = cf_pair_find(cs, "src_ipaddr");
	if (cp) {
		memset(&sock->src_ipaddr, 0, sizeof(sock->src_ipaddr));
		sock->src_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
		rcode = cf_item_parse(cs, "src_ipaddr", FR_ITEM_POINTER(PW_TYPE_IPV4_ADDR, &sock->src_ipaddr), NULL);
		if (rcode < 0) return -1;

		sock->src_ipaddr.af = AF_INET;
	} else {
		memcpy(&sock->src_ipaddr, &sock->lsock.my_ipaddr, sizeof(sock->src_ipaddr));
	}

	/*
	 *	Initialize the fake client.
	 */
	client = &sock->dhcp_client;
	memset(client, 0, sizeof(*client));
	client->ipaddr.af = AF_INET;
	client->ipaddr.ipaddr.ip4addr.s_addr = ntohl(INADDR_NONE);
	client->ipaddr.prefix = 0;
	client->longname = client->shortname = "dhcp";
	client->secret = client->shortname;
	client->nas_type = talloc_typed_strdup(sock, "none");

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
		ERROR("%s", fr_strerror());
		return 0;
	}

	sock = listener->data;
	if (!request_receive(NULL, listener, packet, &sock->dhcp_client, dhcp_process)) {
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

extern fr_protocol_t proto_dhcp;
fr_protocol_t proto_dhcp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcp",
	.inst_size	= sizeof(dhcp_socket_t),
	.parse		= dhcp_socket_parse,
	.recv		= dhcp_socket_recv,
	.send		= dhcp_socket_send,
	.print		= common_socket_print,
	.encode		= dhcp_socket_encode,
	.decode		= dhcp_socket_decode
};
