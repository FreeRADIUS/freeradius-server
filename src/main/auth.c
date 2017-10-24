/*
 * auth.c	User authentication.
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>


/*
 *	Post-authentication step processes the response before it is
 *	sent to the NAS. It can receive both Access-Accept and Access-Reject
 *	replies.
 */
rlm_rcode_t rad_postauth(REQUEST *request)
{
	rlm_rcode_t rcode;
	int	postauth_type = 0;
	VALUE_PAIR *vp;

	/*
	 *	Do post-authentication calls. ignoring the return code.
	 */
	vp = fr_pair_find_by_num(request->control, 0, FR_POST_AUTH_TYPE, TAG_ANY);
	if (vp) {
		postauth_type = vp->vp_uint32;
		RDEBUG2("Using Post-Auth-Type %s",
			fr_dict_enum_alias_by_value(NULL, vp->da, fr_box_uint32(postauth_type)));
	}
	rcode = process_post_auth(postauth_type, request);
	switch (rcode) {
	/*
	 *	The module failed, or said to reject the user: Do so.
	 */
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_USERLOCK:
	default:
		request->reply->code = FR_CODE_ACCESS_REJECT;
		fr_state_discard(global_state, request, request->packet);
		rcode = RLM_MODULE_REJECT;
		break;
	/*
	 *	The module handled the request, cancel the reply.
	 */
	case RLM_MODULE_HANDLED:
		/* FIXME */
		break;
	/*
	 *	The module had a number of OK return codes.
	 */
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		rcode = RLM_MODULE_OK;

		if (request->reply->code == FR_CODE_ACCESS_CHALLENGE) {
			fr_request_to_state(global_state, request, request->packet, request->reply);

		} else {
			fr_state_discard(global_state, request, request->packet);
		}
		break;
	}
	return rcode;
}


#include <freeradius-devel/io/listen.h>

static rlm_rcode_t virtual_server_async(REQUEST *request, bool parent)
{
	fr_io_final_t final;

	if (parent) {
		request->async = talloc_memdup(request, request->parent->async,
					       sizeof(fr_async_t));
	}

	RDEBUG("server %s {", cf_section_name2(request->server_cs));
	final = request->async->process(request, FR_IO_ACTION_RUN);
	RDEBUG("} # server %s", cf_section_name2(request->server_cs));

	rad_cond_assert(final == FR_IO_REPLY);

	if (!request->reply->code ||
	    (request->reply->code == FR_CODE_ACCESS_REJECT)) {
		return RLM_MODULE_REJECT;
	}

	if (request->reply->code == FR_CODE_ACCESS_CHALLENGE) {
		return RLM_MODULE_HANDLED;
	}

	return RLM_MODULE_OK;
}


/*
 *	Run a virtual server auth and postauth
 *
 */
rlm_rcode_t rad_virtual_server(REQUEST *request)
{
	VALUE_PAIR *vp;
	int rcode;

	RDEBUG("Virtual server %s received request", cf_section_name2(request->server_cs));
	rdebug_pair_list(L_DBG_LVL_1, request, request->packet->vps, NULL);

	if (!request->username) {
		request->username = fr_pair_find_by_num(request->packet->vps, 0, FR_USER_NAME, TAG_ANY);
	}

	/*
	 *	Complain about possible issues related to tunnels.
	 */
	if (request->parent && request->parent->username && request->username) {
		/*
		 *	Look at the full User-Name with realm.
		 */
		if (request->parent->username->da->attr == FR_STRIPPED_USER_NAME) {
			vp = fr_pair_find_by_num(request->parent->packet->vps, 0, FR_USER_NAME, TAG_ANY);
			if (!vp) goto skip;
		} else {
			vp = request->parent->username;
		}

		/*
		 *	If the names aren't identical, we do some detailed checks.
		 */
		if (strcmp(vp->vp_strvalue, request->username->vp_strvalue) != 0) {
			char const *outer, *inner;

			outer = strchr(vp->vp_strvalue, '@');

			/*
			 *	If there's no realm, or there's a user identifier before
			 *	the realm name, check the user identifier.
			 *
			 *	It SHOULD be "anonymous", or "anonymous@realm"
			 */
			if (outer) {
				if ((outer != vp->vp_strvalue) &&
				    ((vp->vp_length < 10) || (memcmp(vp->vp_strvalue, "anonymous@", 10) != 0))) {
					RWDEBUG("Outer User-Name is not anonymized.  User privacy is compromised.");
				} /* else it is anonymized */

				/*
				 *	Check when there's no realm, and without the trailing '@'
				 */
			} else if ((vp->vp_length < 9) || (memcmp(vp->vp_strvalue, "anonymous", 9) != 0)) {
					RWDEBUG("Outer User-Name is not anonymized.  User privacy is compromised.");

			} /* else the user identifier is anonymized */

			/*
			 *	Look for an inner realm, which may or may not exist.
			 */
			inner = strchr(request->username->vp_strvalue, '@');
			if (outer && inner) {
				outer++;
				inner++;

				/*
				 *	The realms are different, do
				 *	more detailed checks.
				 */
				if (strcmp(outer, inner) != 0) {
					size_t outer_len, inner_len;

					outer_len = vp->vp_length;
					outer_len -= (outer - vp->vp_strvalue);

					inner_len = request->username->vp_length;
					inner_len -= (inner - request->username->vp_strvalue);

					/*
					 *	Inner: secure.example.org
					 *	Outer: example.org
					 */
					if (inner_len > outer_len) {
						char const *suffix;

						suffix = inner + (inner_len - outer_len) - 1;

						if ((*suffix != '.') ||
						    (strcmp(suffix + 1, outer) != 0)) {
							RWDEBUG("Possible spoofing: Inner realm '%s' is not a "
								"subdomain of the outer realm '%s'", inner, outer);
						}

					} else {
						RWDEBUG("Possible spoofing: Inner realm and "
							"outer realms are different");
					}
				}
			}

		} else {
			RWDEBUG("Outer and inner identities are the same.  User privacy is compromised.");
		}
	}

skip:
	rad_assert(request->async != NULL);

	return virtual_server_async(request, false);
}

void common_packet_debug(REQUEST *request, RADIUS_PACKET *packet, bool received);

/*
 *	Debug the packet if requested.
 */
void common_packet_debug(REQUEST *request, RADIUS_PACKET *packet, bool received)
{
	char src_ipaddr[FR_IPADDR_STRLEN];
	char dst_ipaddr[FR_IPADDR_STRLEN];
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
	if (is_radius_code(packet->code)) {
		radlog_request(L_DBG, L_DBG_LVL_1, request, "%s %s Id %i from %s%s%s:%i to %s%s%s:%i "
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
			       "%s%s%s"
#endif
			       "length %zu",
			       received ? "Received" : "Sent",
			       fr_packet_codes[packet->code],
			       packet->id,
			       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
			       fr_inet_ntop(src_ipaddr, sizeof(src_ipaddr), &packet->src_ipaddr),
			       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
			       packet->src_port,
			       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
			       fr_inet_ntop(dst_ipaddr, sizeof(dst_ipaddr), &packet->dst_ipaddr),
			       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
			       packet->dst_port,
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
			       packet->if_index ? "via " : "",
			       packet->if_index ? fr_ifname_from_ifindex(if_name, packet->if_index) : "",
			       packet->if_index ? " " : "",
#endif
			       packet->data_len);
	} else {
		radlog_request(L_DBG, L_DBG_LVL_1, request, "%s code %u Id %i from %s%s%s:%i to %s%s%s:%i "
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
			       "%s%s%s"
#endif
			       "length %zu",
			       received ? "Received" : "Sent",
			       packet->code,
			       packet->id,
			       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
			       fr_inet_ntop(src_ipaddr, sizeof(src_ipaddr), &packet->src_ipaddr),
			       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
			       packet->src_port,
			       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
			       fr_inet_ntop(dst_ipaddr, sizeof(dst_ipaddr), &packet->dst_ipaddr),
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
		rdebug_pair_list(L_DBG_LVL_1, request, packet->vps, NULL);
	} else {
		rdebug_proto_pair_list(L_DBG_LVL_1, request, packet->vps, NULL);
	}
}
