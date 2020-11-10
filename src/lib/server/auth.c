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
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/io/listen.h>

#include <freeradius-devel/util/print.h>

#include <freeradius-devel/radius/defs.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

/*
 *	Run a virtual server auth and postauth
 *
 */
rlm_rcode_t rad_virtual_server(request_t *request)
{
	fr_pair_t *vp, *username, *parent_username = NULL;
	rlm_rcode_t final;

	RDEBUG("Virtual server %s received request", cf_section_name2(request->server_cs));
	log_request_pair_list(L_DBG_LVL_1, request, request->request_pairs, NULL);

	username = fr_pair_find_by_num(&request->request_pairs, 0, FR_STRIPPED_USER_NAME);
	if (!username) username = fr_pair_find_by_num(&request->request_pairs, 0, FR_USER_NAME);

	if (request->parent) {
		parent_username = fr_pair_find_by_num(&request->parent->request_pairs, 0, FR_STRIPPED_USER_NAME);
		if (!parent_username) parent_username = fr_pair_find_by_num(&request->parent->request_pairs, 0, FR_USER_NAME);
	}

	/*
	 *	Complain about possible issues related to tunnels.
	 */
	if (username && parent_username) {
		/*
		 *	Look at the full User-Name with realm.
		 */
		if (parent_username->da->attr == FR_STRIPPED_USER_NAME) {
			vp = fr_pair_find_by_num(&request->parent->request_pairs, 0, FR_USER_NAME);
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
	if (!request->async) {
#ifdef __clang_analyzer__
		if (!request->parent) return RLM_MODULE_FAIL;
#endif
		fr_assert(request->parent != NULL);

		request->async = talloc_memdup(request, request->parent->async, sizeof(fr_async_t));
		talloc_set_name_const(request->async, talloc_get_name(request->parent->async));
	}

	RDEBUG("server %s {", cf_section_name2(request->server_cs));
	final = request->async->process(&(module_ctx_t){ .instance = request->async->process_inst }, request);
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
}

/*
 *	Debug the packet if requested.
 */
void common_packet_debug(request_t *request, fr_radius_packet_t *packet, bool received)
{
#ifdef WITH_IFINDEX_NAME_RESOLUTION
	char if_name[IFNAMSIZ];
#endif

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;


	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s code %u Id %i from %s%pV%s:%i to %s%pV%s:%i "
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		       "%s%s%s"
#endif
		       "length %zu",
		       received ? "Received" : "Sent",
		       packet->code,
		       packet->id,
		       packet->socket.inet.src_ipaddr.af == AF_INET6 ? "[" : "",
		       fr_box_ipaddr(packet->socket.inet.src_ipaddr),
		       packet->socket.inet.src_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->socket.inet.src_port,
		       packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "[" : "",
		       fr_box_ipaddr(packet->socket.inet.dst_ipaddr),
		       packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->socket.inet.dst_port,
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		       packet->socket.inet.ifindex ? "via " : "",
		       packet->socket.inet.ifindex ? fr_ifname_from_ifindex(if_name, packet->socket.inet.ifindex) : "",
		       packet->socket.inet.ifindex ? " " : "",
#endif
		       packet->data_len);

	if (received) {
		log_request_pair_list(L_DBG_LVL_1, request, request->request_pairs, NULL);
	} else {
		log_request_proto_pair_list(L_DBG_LVL_1, request, request->request_pairs, NULL);
	}
}
