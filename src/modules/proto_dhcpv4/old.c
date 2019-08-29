/*
 * proto_dhcp.c	DHCP processing.
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
 * @copyright 2008 The FreeRADIUS server project
 * @copyright 2008,2016 Alan DeKok (aland@deployingradius.com)
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


#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/server/rad_assert.h>

#ifndef __MINGW32__
#  include <sys/ioctl.h>
#endif

/*
 *	Same contents as listen_socket_t.
 */
typedef struct {
	listen_socket_t	lsock;

	/*
	 *	DHCP-specific additions.
	 */
	bool		suppress_responses;
	RADCLIENT	dhcp_client;
	char const	*src_interface;
	fr_ipaddr_t	src_ipaddr;
} dhcp_socket_t;

static void dhcp_packet_debug(REQUEST *request, RADIUS_PACKET *packet, bool received);

#ifdef WITH_UDPFROMTO
static int dhcprelay_process_client_request(REQUEST *request)
{
	int		rcode;
	uint8_t		maxhops = 16;
	VALUE_PAIR	*vp, *giaddr;
	dhcp_socket_t	*sock;
	RADIUS_PACKET	*packet;

	rad_assert(request->packet->data[0] == 1);

	/*
	 *	Do the forward by ourselves, do not rely on dhcp_socket_send()
	 */
	request->reply->code = 0;

	/*
	 * It's invalid to have giaddr=0 AND a relay option
	 */
	giaddr = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 266, TAG_ANY); /* DHCP-Gateway-IP-Address */
	if (giaddr && (giaddr->vp_ipv4addr == htonl(INADDR_ANY)) &&
			fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 82, TAG_ANY)) { /* DHCP-Relay-Agent-Information */
		RDEBUG2("Received packet with giaddr = 0 and containing relay option: Discarding packet");
		return 1;
	}

	/*
	 * RFC 1542 (BOOTP), page 15
	 *
	 * Drop requests if hop-count > 16 or admin specified another value
	 */
	if ((vp = fr_pair_find_by_num(request->control, DHCP_MAGIC_VENDOR, 271, TAG_ANY))) { /* DHCP-Relay-Max-Hop-Count */
	    maxhops = vp->vp_uint32;
	}
	vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 259, TAG_ANY); /* DHCP-Hop-Count */
	rad_assert(vp != NULL);
	if (vp->vp_uint8 > maxhops) {
		RDEBUG2("Number of hops is greater than %d: not relaying", maxhops);
		return 1;
	} else {
	    /* Increment hop count */
	    vp->vp_uint8++;
	}

	sock = request->listener->data;

	/*
	 *	Don't muck with the original request packet.  That's
	 *	bad form.  Plus, dhcp_encode() does nothing if
	 *	packet->data is already set.
	 */
	packet = fr_radius_alloc(request, false);
	rcode = -1;

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
	packet->src_ipaddr.addr.v4.s_addr = sock->lsock.my_ipaddr.addr.v4.s_addr;
	packet->src_port = sock->lsock.my_port;

	vp = fr_pair_find_by_num(request->control, DHCP_MAGIC_VENDOR, 270, TAG_ANY); /* DHCP-Relay-To-IP-Address */
	rad_assert(vp != NULL);

	/* set DEST ipaddr/port to the next server ipaddr/port */
	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
	packet->dst_port = sock->lsock.my_port;

	packet->vps = request->packet->vps; /* hackity hack */

	/*
	 *	Relaying is not proxying, we just forward it on and forget
	 *	about it, not sending a response to the DHCP client.
	 */
	dhcp_packet_debug(request, packet, false);

	if (fr_dhcpv4_packet_encode(packet) < 0) {
		RPERROR("Failed encoding DHCP packet");
		goto error;
	}

	rcode = fr_dhcpv4_udp_packet_send(packet);

error:
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
	giaddr = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 266, TAG_ANY); /* DHCP-Gateway-IP-Address */

	/* --with-udpfromto is needed just for the following test */
	if (!giaddr || giaddr->vp_ipv4addr != request->packet->dst_ipaddr.addr.v4.s_addr) {
		RDEBUG2("Packet received from server was not for us (was for 0x%x). Discarding packet",
			ntohl(request->packet->dst_ipaddr.addr.v4.s_addr));
		return 1;
	}

	/*
	 *	Don't muck with the original request packet.  That's
	 *	bad form.  Plus, dhcp_encode() does nothing if
	 *	packet->data is already set.
	 */
	packet = fr_radius_alloc(request, false);
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
	 *	We're a relay, and send the reply to giaddr.
	 */
	packet->dst_ipaddr.addr.v4.s_addr = htonl(INADDR_BROADCAST);
	packet->dst_port = request->packet->dst_port;		/* server port */

	vp = fr_pair_find_by_num(request->control, DHCP_MAGIC_VENDOR, 270, TAG_ANY); /* DHCP-Relay-To-IP-Address */
	if (vp) {
		RDEBUG("DHCP: response will be relayed to previous gateway");
		packet->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
		giaddr->vp_ipv4addr = vp->vp_ipv4addr;

	} else if ((packet->code == FR_DHCP_NAK) ||
	    !sock->src_interface ||
	    ((vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 262, TAG_ANY)) /* DHCP-Flags */ &&
	     (vp->vp_uint32 & 0x8000) &&
	     ((vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 263, TAG_ANY)) /* DHCP-Client-IP-Address */ &&
	      (vp->vp_ipv4addr == htonl(INADDR_ANY))))) {
		/*
		 * RFC 2131, page 23
		 *
		 * Broadcast on
		 * - DHCPNAK
		 * or
		 * - Broadcast flag is set up and ciaddr == NULL
		 */
		RDEBUG2("Response will be broadcast");
		packet->dst_ipaddr.addr.v4.s_addr = htonl(INADDR_BROADCAST);

	} else if ((vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 263, TAG_ANY)) /* DHCP-Client-IP-Address */ &&
		   (vp->vp_ipv4addr != htonl(INADDR_ANY))) {

		/*
		 * RFC 2131, page 23
		 *
		 * Unicast to
		 * - ciaddr if present
		 * otherwise to yiaddr
		 */
		packet->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
	} else {
		vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 264, TAG_ANY); /* DHCP-Your-IP-Address */
		if (!vp) {
			RPEDEBUG("Failed to find IP Address for request");
			goto error;
		}

		RDEBUG2("Response will be unicast to &DHCP-Your-IP-Address");
		packet->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;

		/*
		 * When sending a DHCP_OFFER, make sure our ARP table
		 * contains an entry for the client IP address, or else
		 * packet may not be forwarded if it was the first time
		 * the client was requesting an IP address.
		 */
		if (request->packet->code == FR_DHCP_OFFER) {
			VALUE_PAIR *hwvp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 267,
							       TAG_ANY); /* DHCP-Client-Hardware-Address */
			if (hwvp == NULL) {
				RDEBUG2("DHCP_OFFER packet received with no Client Hardware Address. "
					"Discarding packet");
				goto error;
			}
			if (fr_dhcpv4_udp_add_arp_entry(request->packet->sockfd, sock->src_interface,
							&vp->vp_ip, hwvp->vp_ether) < 0) {
				REDEBUG("Failed adding ARP entry");
				goto error;
			}
		}
	}

	packet->vps = request->packet->vps; /* hackity hack */

	/*
	 *	Our response doesn't go through process.c
	 */
	dhcp_packet_debug(request, packet, false);

	if (fr_dhcpv4_packet_encode(packet) < 0) {
		RPERROR("Failed encoding DHCP packet");
		goto error;
	}

	rcode = fr_dhcpv4_udp_packet_send(request->packet);

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

static rlm_rcode_t dhcp_process(REQUEST *request)
{
	rlm_rcode_t	rcode;
	unsigned int	i;
	VALUE_PAIR	*vp;
	dhcp_socket_t	*sock;

	/*
	 *	If there's a giaddr, save it as the Relay-IP-Address
	 *	in the response.  That way the later code knows where
	 *	to send the reply.
	 */
	vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 266, TAG_ANY); /* DHCP-Gateway-IP-Address */
	if (vp && (vp->vp_ipv4addr != htonl(INADDR_ANY))) {
		VALUE_PAIR *relay;

		/* DHCP-Relay-IP-Address */
		MEM(relay = fr_pair_afrom_num(request->reply, DHCP_MAGIC_VENDOR, 222));
		relay->vp_ipv4addr = vp->vp_ipv4addr;
		fr_pair_add(&request->reply->vps, relay);
	}

	vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 53, TAG_ANY); /* DHCP-Message-Type */
	if (vp) {
		fr_dict_enum_t *dv = fr_dict_enum_by_value(vp->da, &vp->data);

		if (dv) {
			CONF_SECTION *server, *unlang;

			RDEBUG("Trying sub-section dhcp %s {...}", dv->alias);

			server = cf_item_to_section(cf_parent(request->listener->cs));

			unlang = cf_section_find(server, "dhcp", dv->alias);
			rcode = unlang_interpret(request, unlang, RLM_MODULE_NOOP);
		} else {
			REDEBUG("Unknown DHCP-Message-Type %d", vp->vp_uint8);
			rcode = RLM_MODULE_FAIL;
		}
	} else {
		REDEBUG("Failed to find DHCP-Message-Type in packet!");
		rcode = RLM_MODULE_FAIL;
	}

	vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 53, TAG_ANY); /* DHCP-Message-Type */
	if (vp) {
		request->reply->code = vp->vp_uint8;
	}
	else switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		if (request->packet->code == FR_DHCP_DISCOVER) {
			request->reply->code = FR_DHCP_OFFER;
			break;

		} else if (request->packet->code == FR_DHCP_REQUEST) {
			request->reply->code = FR_DHCP_ACK;
			break;
		}
		request->reply->code = FR_DHCP_NAK;
		break;

	default:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
		if (request->packet->code == FR_DHCP_DISCOVER) {
			request->reply->code = 0; /* ignore the packet */
		} else {
			request->reply->code = FR_DHCP_NAK;
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
	vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 256, TAG_ANY); /* DHCP-Opcode */
	if (!vp) {
		RPEDEBUG("Someone deleted the DHCP-Opcode!");
		return RLM_MODULE_FAIL;
	}

	/* BOOTREPLY received on port 67 (i.e. from a server) */
	if (vp->vp_uint8 == 2) {
		return dhcprelay_process_server_reply(request);
	}

	/* Packet from client, and we have DHCP-Relay-To-IP-Address */
	if (fr_pair_find_by_num(request->control, DHCP_MAGIC_VENDOR, 270, TAG_ANY)) {
		return dhcprelay_process_client_request(request);
	}

	/* else it's a packet from a client, without relaying */
	rad_assert(vp->vp_uint8 == 1); /* BOOTREQUEST */

	sock = request->listener->data;

	/*
	 *	Handle requests when acting as a DHCP server
	 */

	/*
	 *	Releases don't get replies.
	 */
	if (request->packet->code == FR_DHCP_RELEASE) {
		request->reply->code = 0;
	}

	if (request->reply->code == 0) {
		return RLM_MODULE_OK;
	}

	request->reply->sockfd = request->packet->sockfd;

	/*
	 *	Copy specific fields from packet to reply, if they
	 *	don't already exist
	 */
	for (i = 0; i < NUM_ELEMENTS(attrnums); i++) {
		uint32_t attr = attrnums[i];

		if (fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, attr, TAG_ANY)) continue;

		vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, attr, TAG_ANY);
		if (vp) {
			fr_pair_add(&request->reply->vps, fr_pair_copy(request->reply, vp));
		}
	}

	vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 256, TAG_ANY); /* DHCP-Opcode */
	rad_assert(vp != NULL);
	vp->vp_uint8 = 2; /* BOOTREPLY */

	/*
	 *	Allow NAKs to be delayed for a short period of time.
	 */
	if (request->reply->code == FR_DHCP_NAK) {
		vp = fr_pair_find_by_num(request->reply->vps, 0, FR_FREERADIUS_RESPONSE_DELAY, TAG_ANY);
		if (vp) {
			if (vp->vp_uint32 <= 10) {
				request->response_delay.tv_sec = vp->vp_uint32;
				request->response_delay.tv_usec = 0;
			} else {
				request->response_delay.tv_sec = 10;
				request->response_delay.tv_usec = 0;
			}
		} else {

			vp = fr_pair_find_by_num(request->reply->vps, 0, FR_FREERADIUS_RESPONSE_DELAY_USEC, TAG_ANY);
			if (vp) {
				if (vp->vp_uint32 <= 10 * USEC) {
					request->response_delay.tv_sec = vp->vp_uint32 / USEC;
					request->response_delay.tv_usec = vp->vp_uint32 % USEC;
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
	vp = fr_pair_find_by_num(request->reply->vps, 0, FR_PACKET_SRC_IP_ADDRESS, TAG_ANY);
	if (vp) {
		request->reply->if_index = 0;	/* Must be 0, we don't know the outbound if_index */
		request->reply->src_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
	/*
	 *	The request was unicast (via a relay)
	 */
	} else if (request->packet->dst_ipaddr.addr.v4.s_addr != htonl(INADDR_BROADCAST) &&
		   request->packet->dst_ipaddr.addr.v4.s_addr != htonl(INADDR_ANY)) {
		request->reply->src_ipaddr.addr.v4.s_addr = request->packet->dst_ipaddr.addr.v4.s_addr;
		request->reply->if_index = request->packet->if_index;
	/*
	 *	The listener was bound to an IP address, or we determined
	 *	the address automatically, as it was the only address bound
	 *	to the interface, and we bound to the interface.
	 */
	} else if (sock->src_ipaddr.addr.v4.s_addr != htonl(INADDR_ANY)) {
		request->reply->src_ipaddr.addr.v4.s_addr = sock->src_ipaddr.addr.v4.s_addr;
#ifdef WITH_IFINDEX_IPADDR_RESOLUTION
	/*
	 *	We built with udpfromto and have the if_index of the receiving
	 *	interface, which we can now resolve to an IP address.
	 */
	} else if (request->packet->if_index > 0) {
		fr_ipaddr_t primary;

		if (fr_ipaddr_from_ifindex(&primary, request->packet->sockfd, request->packet->dst_ipaddr.af,
					   request->packet->if_index) < 0) {
			RPEDEBUG("Failed determining src_ipaddr from if_index");
			return RLM_MODULE_FAIL;
		}
		request->reply->src_ipaddr.addr.v4.s_addr = primary.addr.v4.s_addr;
#endif
	/*
	 *	There's a Server-Identification attribute
	 */
	} else if ((vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 54, TAG_ANY))) {
		request->reply->src_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
	} else {
		REDEBUG("Unable to determine correct src_ipaddr for response");
		return RLM_MODULE_FAIL;
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
	vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 272, TAG_ANY); /* DHCP-Relay-IP-Address */
	if (vp && (vp->vp_ipv4addr != ntohl(INADDR_ANY))) {
		RDEBUG2("Reply will be unicast to giaddr from original packet");
		request->reply->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
		request->reply->dst_port = request->packet->dst_port;

		vp = fr_pair_find_by_num(request->reply->vps, 0, FR_PACKET_DST_PORT, TAG_ANY);
		if (vp) request->reply->dst_port = vp->vp_uint16;

		return RLM_MODULE_OK;
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
	vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 266, TAG_ANY); /* DHCP-Gateway-IP-Address */
	if (vp && (vp->vp_ipv4addr != htonl(INADDR_ANY))) {
		RDEBUG2("Reply will be unicast to giaddr");
		request->reply->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
		request->reply->dst_port = request->packet->dst_port;
		return RLM_MODULE_OK;
	}

	/*
	 *	If it's a NAK, or the broadcast flag was set, ond
	 *	there's no client-ip-address, send a broadcast.
	 */
	if ((request->reply->code == FR_DHCP_NAK) ||
	    ((vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 262, TAG_ANY)) && /* DHCP-Flags */
	     (vp->vp_uint32 & 0x8000) &&
	     ((vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 263, TAG_ANY)) && /* DHCP-Client-IP-Address */
	      (vp->vp_ipv4addr == htonl(INADDR_ANY))))) {
		/*
		 * RFC 2131, page 23
		 *
		 * Broadcast on
		 * - DHCPNAK
		 * or
		 * - Broadcast flag is set up and ciaddr == NULL
		 */
		RDEBUG2("Reply will be broadcast");
		request->reply->dst_ipaddr.addr.v4.s_addr = htonl(INADDR_BROADCAST);
		return RLM_MODULE_OK;
	}

	/*
	 *	RFC 2131, page 23
	 *
	 *	Unicast to ciaddr if present, otherwise to yiaddr.
	 */
	if ((vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 263, TAG_ANY)) && /* DHCP-Client-IP-Address */
	    (vp->vp_ipv4addr != htonl(INADDR_ANY))) {
		RDEBUG2("Reply will be sent unicast to &DHCP-Client-IP-Address");
		request->reply->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
		return RLM_MODULE_OK;
	}

	vp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 264, TAG_ANY); /* DHCP-Your-IP-Address */
	if (!vp) {
		REDEBUG("Can't assign address to client: Neither &reply:DHCP-Client-IP-Address nor "
			"&reply:DHCP-Your-IP-Address set");
		/*
		 *	There is nowhere to send the response to, so don't bother.
		 */
		request->reply->code = 0;
		return RLM_MODULE_FAIL;
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
		RDEBUG2("Reply will be broadcast as no interface was defined");
		request->reply->dst_ipaddr.addr.v4.s_addr = htonl(INADDR_BROADCAST);
		return RLM_MODULE_OK;
	}

	RDEBUG2("Reply will be unicast to &DHCP-Your-IP-Address");
	request->reply->dst_ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;

	/*
	 *	When sending a DHCP_OFFER, make sure our ARP table
	 *	contains an entry for the client IP address.
	 *	Otherwise the packet may not be sent to the client, as
	 *	the OS has no ARP entry for it.
	 *
	 *	This is a cute hack to avoid us having to create a raw
	 *	socket to send DHCP packets.
	 */
	if (request->reply->code == FR_DHCP_OFFER) {
		VALUE_PAIR *hwvp = fr_pair_find_by_num(request->reply->vps, DHCP_MAGIC_VENDOR, 267, TAG_ANY); /* DHCP-Client-Hardware-Address */

		if (!hwvp) return RLM_MODULE_FAIL;

		if (fr_dhcpv4_udp_add_arp_entry(request->reply->sockfd, sock->src_interface,
						&vp->vp_ip, hwvp->vp_ether) < 0) {
			RPEDEBUG("Failed adding arp entry");
			return RLM_MODULE_FAIL;
		}
	}
#else
	if (request->packet->src_ipaddr.addr.v4.s_addr != ntohl(INADDR_NONE)) {
		RDEBUG2("Reply will be unicast to the unicast source IP address");
		request->reply->dst_ipaddr.addr.v4.s_addr = request->packet->src_ipaddr.addr.v4.s_addr;
	} else {
		RDEBUG2("Reply will be broadcast as this system does not support ARP updates");
		request->reply->dst_ipaddr.addr.v4.s_addr = htonl(INADDR_BROADCAST);
	}
#endif

	return RLM_MODULE_OK;
}

/*
 *	We allow using PCAP, but only if there's no SO_BINDTODEVICE
 */
#ifndef SO_BINDTODEVICE
#ifdef HAVE_LIBPCAP
#define PCAP_RAW_SOCKETS (1)
#endif
#endif

#ifdef PCAP_RAW_SOCKETS
/** Build PCAP filter string to pass to libpcap based on listen section
 * Will be called by init_pcap.
 *
 * @param this listen section
 * @return PCAP filter string
 */
static const char *dhcp_pcap_filter_build(rad_listen_t *this)
{
	dhcp_socket_t	*sock = this->data;
	char		*filter;

	/*
	 *	Set the port filter
	 */
	filter = talloc_strdup(this, "(udp and dst port ");
	if (sock->lsock.my_port) {
		filter = talloc_asprintf_append_buffer(filter, "%u)", sock->lsock.my_port);
	} else {
		filter = talloc_strdup_append_buffer(filter, "bootps)");
	}

	if (!fr_ipaddr_is_inaddr_any(&sock->lsock.my_ipaddr)) {
		char buffer[INET_ADDRSTRLEN];
		fr_inet_ntoh(&sock->lsock.my_ipaddr, buffer, sizeof(buffer));

		if (sock->lsock.broadcast) {
			filter = talloc_asprintf_append_buffer(filter, " and (dst host %s or dst host 255.255.255.255)",
							       buffer);
		} else {
			filter = talloc_asprintf_append_buffer(filter, " and dst host %s", buffer);
		}
	}

	return filter;
}
#endif

static int dhcp_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode;
	dhcp_socket_t *sock = this->data;
	RADCLIENT *client;
	CONF_PAIR *cp;

#ifdef PCAP_RAW_SOCKETS
	sock->lsock.pcap_filter_builder = dhcp_pcap_filter_build;
	sock->lsock.pcap_type = PCAP_INTERFACE_IN_OUT;
#endif

	/*
	 *	Set if before parsing, so the user can forcibly turn
	 *	it off later.
	 */
	this->nodup = true;

	rcode = common_socket_parse(cs, this);
	if (rcode != 0) return rcode;

	if (!sock->lsock.interface) WARN("No \"interface\" setting is defined.  Only unicast DHCP will work");

	/*
	 *	Undocumented extension for testing without
	 *	destroying your network!
	 */
	sock->suppress_responses = false;
	cp = cf_pair_find(cs, "suppress_responses");
	if (cp) {
		rcode = cf_pair_parse(sock, cs, "suppress_responses",
				      FR_ITEM_POINTER(FR_TYPE_BOOL, &sock->suppress_responses), NULL, T_INVALID);
		if (rcode < 0) return -1;
	}

	cp = cf_pair_find(cs, "src_interface");
	if (cp) {
		rcode = cf_pair_parse(sock, cs, "src_interface",
				      FR_ITEM_POINTER(FR_TYPE_STRING, &sock->src_interface), NULL, T_INVALID);
		if (rcode < 0) return -1;
	} else {
		sock->src_interface = sock->lsock.interface;
	}

	if (!sock->src_interface && sock->lsock.interface) {
		sock->src_interface = talloc_typed_strdup(sock, sock->lsock.interface);
	}

	/*
	 *	Set the source IP address explicitly.
	 */
	cp = cf_pair_find(cs, "src_ipaddr");
	if (cp) {
		memset(&sock->src_ipaddr, 0, sizeof(sock->src_ipaddr));
		sock->src_ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);
		rcode = cf_pair_parse(sock, cs, "src_ipaddr",
				      FR_ITEM_POINTER(FR_TYPE_IPV4_ADDR, &sock->src_ipaddr), NULL, T_INVALID);
		if (rcode < 0) return -1;

		sock->src_ipaddr.af = AF_INET;
	/*
	 *	Or by looking up the IP address associated with the
	 *	src_interface or interface (if we're binding to INADDR_ANY).
	 */
	} else {
		char buffer[INET_ADDRSTRLEN];

		if (fr_ipaddr_is_inaddr_any(&sock->lsock.my_ipaddr) && sock->src_interface) {
			if (fr_ipaddr_from_ifname(&sock->src_ipaddr, AF_INET, sock->src_interface) < 0) {
				WARN("Failed resolving interface %s to IP address: %s", sock->src_interface,
				     fr_strerror());
				WARN("Will continue, but source address must be set within the DHCP virtual server");
				goto src_addr_is_bound_addr;
			}
			inet_ntop(sock->src_ipaddr.af, &sock->src_ipaddr.addr.v4.s_addr, buffer, sizeof(buffer));
			rad_assert(sock->src_ipaddr.af == AF_INET);
		} else {
		src_addr_is_bound_addr:
			sock->src_ipaddr = sock->lsock.my_ipaddr;
		}

		/*
		 *	If src is not INADDR_ANY add a configuration item
		 */
		if (!fr_ipaddr_is_inaddr_any(&sock->src_ipaddr)) {
			/*
			 *	Magic defaults FTW.
			 *
			 *	This lets %{config:} work as expected, if we want to set
			 *	DHCP-DHCP-Server-Identifier.
			 */
			inet_ntop(sock->src_ipaddr.af, &sock->src_ipaddr.addr.v4.s_addr, buffer, sizeof(buffer));
			DEBUG2("\tsrc_ipaddr = \"%s\"", buffer);
			cp = cf_pair_alloc(cs, "src_ipaddr", buffer, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
			if (!cp) return -1;
			cf_pair_add(cs, cp);
		}
	}

	/*
	 *	Initialize the fake client.
	 */
	client = &sock->dhcp_client;
	memset(client, 0, sizeof(*client));
	client->ipaddr.af = AF_INET;
	client->ipaddr.addr.v4.s_addr = ntohl(INADDR_NONE);
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
	dhcp_socket_t	*sock = listener->data;
	RADCLIENT	*client = &sock->dhcp_client;

	if (!fr_cond_assert(client != NULL)) return 1;

	FR_STATS_INC(auth, total_requests);
	FR_STATS_TYPE_INC(client->auth.total_requests);

#ifdef PCAP_RAW_SOCKETS
	if (sock->lsock.pcap) {
		packet = fr_dhcpv4_pcap_recv(sock->lsock.pcap);
	} else
#endif
	{
		packet = fr_dhcpv4_udp_packet_recv(listener->fd);
	}

	if (!packet) {
		FR_STATS_INC(auth, total_malformed_requests);
		PERROR("Failed receiving packet");
		return 0;
	}

	if (!request_receive(NULL, listener, packet, &sock->dhcp_client, dhcp_process)) {
		FR_STATS_INC(auth, total_packets_dropped);
		fr_radius_packet_free(&packet);
		return 0;
	}

	return 1;
}


/*
 *	Send an authentication response packet
 */
static int dhcp_socket_send(rad_listen_t *listener, REQUEST *request)
{
	dhcp_socket_t	*sock = listener->data;

	rad_assert(request->listener == listener);
	rad_assert(listener->send == dhcp_socket_send);

	if (request->reply->code == 0) return 0; /* don't reply */

	if (fr_dhcpv4_packet_encode(request->reply) < 0) {
		RPERROR("Failed encoding DHCP packet");
		return -1;
	}

	if (sock->suppress_responses) return 0;

#ifdef PCAP_RAW_SOCKETS
	if (sock->lsock.pcap) {
		/* set ethernet destination address to DHCP-Client-Hardware-Address in request. */
		uint8_t dhmac[ETHER_HDR_LEN] = { 0 };
		VALUE_PAIR *vp;

		vp = fr_pair_find_by_num(request->packet->vps, DHCP_MAGIC_VENDOR, 267, TAG_ANY);
		if (vp) {
			memcpy(dhmac, vp->vp_ether, sizeof(vp->vp_ether));
		} else {
			REDEBUG("&DHCP-Client-Hardware-Address not found in request");
			return -1;
		}

		return fr_dhcpv4_pcap_send(sock->lsock.pcap, dhmac, request->reply);
	} else
#endif
	{
		return fr_dhcpv4_udp_packet_send(request->reply);
	}
}

/*
 *	Debug the packet if requested.
 */
static void dhcp_packet_debug(REQUEST *request, RADIUS_PACKET *packet, bool received)
{
	char src_ipaddr[INET6_ADDRSTRLEN];
	char dst_ipaddr[INET6_ADDRSTRLEN];
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
	char if_name[IFNAMSIZ];
#endif

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	/*
	 *	Client-specific debugging re-prints the input
	 *	packet into the client log.
	 *
	 *	This really belongs in a utility library
	 */
	if ((packet->code > 0) && (packet->code < FR_DHCP_MAX)) {
		RDEBUG("%s %s Id %08x from %s%s%s:%i to %s%s%s:%i "
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
		       "%s%s%s"
#endif
		       "length %zu",
		       received ? "Received" : "Sent",
		       dhcp_message_types[packet->code],
		       packet->id,
		       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.addr,
				 src_ipaddr, sizeof(src_ipaddr)),
		       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->src_port,
		       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->dst_ipaddr.af,
				 &packet->dst_ipaddr.addr,
				 dst_ipaddr, sizeof(dst_ipaddr)),
		       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->dst_port,
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
		       packet->if_index ? "via " : "",
		       packet->if_index ? fr_ifname_from_ifindex(if_name, packet->if_index) : "",
		       packet->if_index ? " " : "",
#endif
		       packet->data_len);
	} else {
		RDEBUG("%s code %u Id %08x from %s%s%s:%i to %s%s%s:%i "
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
		       "%s%s%s"
#endif
		       "length %zu",
		       received ? "Received" : "Sent",
		       packet->code,
		       packet->id,
		       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.addr,
				 src_ipaddr, sizeof(src_ipaddr)),
		       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->src_port,
		       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
		       inet_ntop(packet->dst_ipaddr.af,
				 &packet->dst_ipaddr.addr,
				 dst_ipaddr, sizeof(dst_ipaddr)),
		       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->dst_port,
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
		       packet->if_index ? "via " : "",
		       packet->if_index ? fr_ifname_from_ifindex(if_name, packet->if_index) : "",
		       packet->if_index ? " " : "",
#endif
		       packet->data_len);
	}

	if (received) {
		log_request_pair_list(L_DBG_LVL_2, request, packet->vps, NULL);
	} else {
		log_request_proto_pair_list(L_DBG_LVL_2, request, packet->vps, NULL);
	}
}

static int dhcp_socket_encode(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	DEBUG2("NO ENCODE!");
	return 0;
}


static int dhcp_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	return fr_dhcpv4_packet_decode(request->packet);
}


/*
 *	Ensure that the "dhcp FOO" sections are compiled.
 */
static int dhcp_listen_compile(CONF_SECTION *server_cs, CONF_SECTION *listen_cs)
{
	CONF_SECTION *subcs = NULL;
	fr_dict_attr_t const *da;
	fr_dict_enum_t const *dv;

	da = fr_dict_attr_by_name(NULL, "DHCP-Message-Type");
	if (!da) {
		cf_log_err(listen_cs, "No DHCP-Message-Type attribute found");
		return -1;
	}

	while ((subcs = cf_section_find_next(server_cs, subcs, "dhcp", NULL))) {
		char const *name2 = cf_section_name2(subcs);


		if (name2) {
			cf_log_debug(subcs, "Loading dhcp %s {...}", name2);
		} else {
			cf_log_debug(subcs, "Loading dhcp {...}");
		}

		dv = fr_dict_enum_by_alias(da, name2, -1);
		if (!dv) {
			cf_log_err(subcs, "Server contains 'dhcp %s {...}, but there is no such value for "
				   "DHCP-Message-Type", name2);
			return -1;
		}

		if (unlang_compile(subcs, MOD_POST_AUTH) < 0) {
			cf_log_err(subcs, "Failed compiling 'dhcp %s' section", name2);
			return -1;
		}
	}

	return 0;
}

static int dhcp_load(void)
{
	if (fr_dhcpv4_global_init() < 0) {
		PERROR("Failed initialising DHCP");
		return -1;
	}

	return ret;
}

static void dhcp_unload(void)
{
	fr_dhcpv4_global_free();
}


extern rad_protocol_t proto_dhcp;
rad_protocol_t proto_dhcp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcp",
	.inst_size	= sizeof(dhcp_socket_t),
	.transports	= TRANSPORT_UDP,
	.tls		= false,

	.onload		= dhcp_load,
	.unload		= dhcp_unload,
	.compile	= dhcp_listen_compile,
	.parse		= dhcp_socket_parse,
	.open		= common_socket_open,
	.recv		= dhcp_socket_recv,
	.send		= dhcp_socket_send,
	.print		= common_socket_print,
	.debug		= dhcp_packet_debug,
	.encode		= dhcp_socket_encode,
	.decode		= dhcp_socket_decode,
};
