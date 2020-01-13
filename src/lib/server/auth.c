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
 *
 * @file src/lib/server/auth.c
 * @brief The old authentication state machine.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Jeff Carneal (jeff@apex.net)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/util/print.h>

#include <freeradius-devel/radius/defs.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

/*
 *	Run a virtual server auth and postauth
 *
 */
rlm_rcode_t rad_virtual_server(REQUEST *request)
{
	VALUE_PAIR *vp, *username, *parent_username = NULL;
	rlm_rcode_t final;

	RDEBUG("Virtual server %s received request", cf_section_name2(request->server_cs));
	log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, NULL);

	username = fr_pair_find_by_num(request->packet->vps, 0, FR_STRIPPED_USER_NAME, TAG_ANY);
	if (!username) username = fr_pair_find_by_num(request->packet->vps, 0, FR_USER_NAME, TAG_ANY);

	if (request->parent) {
		parent_username = fr_pair_find_by_num(request->parent->packet->vps, 0, FR_STRIPPED_USER_NAME, TAG_ANY);
		if (!parent_username) parent_username = fr_pair_find_by_num(request->parent->packet->vps, 0, FR_USER_NAME, TAG_ANY);
	}

	/*
	 *	Complain about possible issues related to tunnels.
	 */
	if (username && parent_username) {
		/*
		 *	Look at the full User-Name with realm.
		 */
		if (parent_username->da->attr == FR_STRIPPED_USER_NAME) {
			vp = fr_pair_find_by_num(request->parent->packet->vps, 0, FR_USER_NAME, TAG_ANY);
			if (!vp) goto runit;
		} else {
			vp = parent_username;
		}

		/*
		 *	If the names aren't identical, we do some detailed checks.
		 */
		if (strcmp(vp->vp_strvalue, username->vp_strvalue) != 0) {
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
			inner = strchr(username->vp_strvalue, '@');
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

					inner_len = username->vp_length;
					inner_len -= (inner - username->vp_strvalue);

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

runit:
#if 1
	RDEBUG("rad_virtual_server() needs to be fixed to work with the new method");
	final = RLM_MODULE_REJECT;
	return final;
#else
	if (!request->async) {
#ifdef __clang_analyzer__
		if (!request->parent) return RLM_MODULE_FAIL;
#endif
		rad_assert(request->parent != NULL);

		request->async = talloc_memdup(request, request->parent->async, sizeof(fr_async_t));
		talloc_set_name_const(request->async, talloc_get_name(request->parent->async));
	}

	/*
	 *	@todo - copy root stack frame from the parent.  It
	 *	contains the method to call which processes the
	 *	packet.  Now that request->async->process is gone, we
	 *	have to fix this code.
	 *
	 *	However, if we're running another virtual server, we
	 *	should really be using the unlang "call"
	 *	functionality.  That code already looks at the virtual
	 *	server in order to tell the child how to run.
	 */

	RDEBUG("server %s {", cf_section_name2(request->server_cs));
	final = unlang_interpret(request);
	RDEBUG("} # server %s", cf_section_name2(request->server_cs));

	fr_cond_assert(final == RLM_MODULE_OK);

	if (!request->reply->code ||
	    (request->reply->code == FR_CODE_ACCESS_REJECT)) {
		return RLM_MODULE_REJECT;
	}

	if (request->reply->code == FR_CODE_ACCESS_CHALLENGE) {
		return RLM_MODULE_HANDLED;
	}

	return RLM_MODULE_OK;
#endif
}

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


	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s code %u Id %i from %s%s%s:%i to %s%s%s:%i "
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

	if (received) {
		log_request_pair_list(L_DBG_LVL_1, request, packet->vps, NULL);
	} else {
		log_request_proto_pair_list(L_DBG_LVL_1, request, packet->vps, NULL);
	}
}
