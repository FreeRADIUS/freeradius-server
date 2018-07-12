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
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * @copyright 2000  Jeff Carneal <jeff@apex.net>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>

/*
 *	Check password.
 *
 *	Returns:	0  OK
 *			-1 Password fail
 *			-2 Rejected (Auth-Type = Reject, send Port-Message back)
 *			1  End check & return, don't reply
 *
 *	NOTE: NOT the same as the RLM_ values !
 */
static int CC_HINT(nonnull) rad_check_password(REQUEST *request)
{
	fr_cursor_t		cursor;
	VALUE_PAIR		*auth_type_pair;
	int			auth_type = -1;
	int			result;
	int			auth_type_count = 0;
	fr_dict_attr_t const	*da;

	da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), FR_AUTH_TYPE);
	if (!da) {
		RERROR("Missing definition for Auth-Type");
		return -1;
	}

	/*
	 *	Look for matching check items. We skip the whole lot
	 *	if the authentication type is FR_AUTH_TYPE_ACCEPT or
	 *	FR_AUTH_TYPE_REJECT.
	 */
	for (auth_type_pair = fr_cursor_iter_by_da_init(&cursor, &request->control, da);
	     auth_type_pair;
	     auth_type_pair = fr_cursor_next(&cursor)) {
		auth_type = auth_type_pair->vp_uint32;
		auth_type_count++;

		RDEBUG2("Using '%pP' for authenticate {...}", auth_type_pair);
		if (auth_type == FR_AUTH_TYPE_REJECT) {
			RDEBUG2("Auth-Type = Reject, rejecting user");

			return -2;
		}
	}

	/*
	 *	Warn if more than one Auth-Type was found, because only the last
	 *	one found will actually be used.
	 */
	if ((auth_type_count > 1) && (rad_debug_lvl) && request->username) {
		RERROR("Warning:  Found %d auth-types on request for user '%s'",
		       auth_type_count, request->username->vp_strvalue);
	}

	/*
	 *	This means we have a proxy reply or an accept and it wasn't
	 *	rejected in the above loop. So that means it is accepted and we
	 *	do no further authentication.
	 */
	if ((auth_type == FR_AUTH_TYPE_ACCEPT)
#ifdef WITH_PROXY
	    || (request->proxy)
#endif
	    ) {
		RDEBUG2("Auth-Type = Accept, accepting the user");
		return 0;
	}

	/*
	 *	Check that Auth-Type has been set, and reject if not.
	 *
	 *	Do quick checks to see if Cleartext-Password or Crypt-Password have
	 *	been set, and complain if so.
	 */
	if (auth_type < 0) {
		if (fr_pair_find_by_num(request->control, 0, FR_CRYPT_PASSWORD, TAG_ANY) != NULL) {
			RWDEBUG2("Please update your configuration, and remove 'Auth-Type = Crypt'");
			RWDEBUG2("Use the PAP module instead");
		}
		else if (fr_pair_find_by_num(request->control, 0, FR_CLEARTEXT_PASSWORD, TAG_ANY) != NULL) {
			RWDEBUG2("Please update your configuration, and remove 'Auth-Type = Local'");
			RWDEBUG2("Use the PAP or CHAP modules instead");
		}

		/*
		 *	The admin hasn't told us how to
		 *	authenticate the user, so we reject them!
		 *
		 *	This is fail-safe.
		 */

		REDEBUG2("No Auth-Type found: rejecting the user via Post-Auth-Type = Reject");
		return -2;
	}

	/*
	 *	See if there is a module that handles
	 *	this Auth-Type, and turn the RLM_ return
	 *	status into the values as defined at
	 *	the top of this function.
	 */
	result = process_authenticate(auth_type, request);
	switch (result) {
	/*
	 *	An authentication module FAIL
	 *	return code, or any return code that
	 *	is not expected from authentication,
	 *	is the same as an explicit REJECT!
	 */
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_UPDATED:
	case RLM_MODULE_USERLOCK:
	default:
		result = -1;
		break;

	case RLM_MODULE_OK:
		result = 0;
		break;

	case RLM_MODULE_HANDLED:
		result = 1;
		break;
	}

	return result;
}

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
			fr_dict_enum_alias_by_value(vp->da, fr_box_uint32(postauth_type)));
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
		break;
	}
	return rcode;
}

/*
 *	Process and reply to an authentication request
 *
 *	The return value of this function isn't actually used right now, so
 *	it's not entirely clear if it is returning the right things. --Pac.
 */
rlm_rcode_t rad_authenticate(REQUEST *request)
{
	VALUE_PAIR	*tmp = NULL;
	int		result;
	rlm_rcode_t    	rcode;
	char		autz_retry = 0;
	int		autz_type = 0;

#ifdef WITH_PROXY
	/*
	 *	Old proxy code removed, see v3.0.x for details
	 */
#endif
	/*
	 *	Look for, and cache, passwords.
	 */
	if (!request->password) {
		request->password = fr_pair_find_by_num(request->packet->vps, 0, FR_USER_PASSWORD, TAG_ANY);
	}
	if (!request->password) {
		request->password = fr_pair_find_by_num(request->packet->vps, 0, FR_CHAP_PASSWORD, TAG_ANY);
	}

	/*
	 *	Get the user's authorization information from the database
	 */
autz_redo:
	rcode = process_authorize(autz_type, request);
	switch (rcode) {
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;
	case RLM_MODULE_HANDLED:
		return rcode;
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_USERLOCK:
	default:
		request->reply->code = FR_CODE_ACCESS_REJECT;
		return rcode;
	}
	if (!autz_retry) {
		tmp = fr_pair_find_by_num(request->control, 0, FR_AUTZ_TYPE, TAG_ANY);
		if (tmp) {
			autz_type = tmp->vp_uint32;
			RDEBUG2("Using Autz-Type %s",
				fr_dict_enum_alias_by_value(tmp->da, fr_box_uint32(autz_type)));
			autz_retry = 1;
			goto autz_redo;
		}
	}

	/*
	 *	Validate the user
	 */
	do {
		result = rad_check_password(request);
		if (result > 0) {
			return RLM_MODULE_HANDLED;
		}

	} while(0);

	/*
	 *	Failed to validate the user.
	 *
	 *	We PRESUME that the code which failed will clean up
	 *	request->reply->vps, to be ONLY the reply items it
	 *	wants to send back.
	 */
	if (result < 0) {
		RDEBUG2("Failed to authenticate the user");
		request->reply->code = FR_CODE_ACCESS_REJECT;

		if (request->password) {
			VP_VERIFY(request->password);
			/* double check: maybe the secret is wrong? */
			if ((rad_debug_lvl > 1) && (request->password->da->attr == FR_USER_PASSWORD)) {
				uint8_t const *p;

				p = (uint8_t const *) request->password->vp_strvalue;
				while (*p) {
					int size;

					size = fr_utf8_char(p, -1);
					if (!size) {
						RWDEBUG("Unprintable characters in the password.  Double-check the "
							"shared secret on the server and the NAS!");
						break;
					}
					p += size;
				}
			}
		}
	}

	/*
	 *	Result should be >= 0 here - if not, it means the user
	 *	is rejected, so we just process post-auth and return.
	 */
	if (result < 0) {
		return RLM_MODULE_REJECT;
	}

	/*
	 *	Set the reply to Access-Accept, if it hasn't already
	 *	been set to something.  (i.e. Access-Challenge)
	 */
	if (request->reply->code == 0) request->reply->code = FR_CODE_ACCESS_ACCEPT;

	return rcode;
}

#include <freeradius-devel/io/listen.h>

static rlm_rcode_t virtual_server_async(REQUEST *request, bool parent)
{
	fr_io_final_t final;

	if (parent) {
		request->async = talloc_memdup(request, request->parent->async, sizeof(fr_async_t));
		talloc_set_name_const(request->async, talloc_get_name(request->parent->async));
	}

	RDEBUG("server %s {", cf_section_name2(request->server_cs));
	final = request->async->process(request->async->process_inst, request, FR_IO_ACTION_RUN);
	RDEBUG("} # server %s", cf_section_name2(request->server_cs));

	fr_cond_assert(final == FR_IO_REPLY);

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
	int rcode;
	VALUE_PAIR *vp;

	RDEBUG("Virtual server %s received request", cf_section_name2(request->server_cs));
	log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, NULL);

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
	if (request->async) return virtual_server_async(request, false);

	if (request->parent && request->parent->async) return virtual_server_async(request, true);

	RDEBUG("server %s {", cf_section_name2(request->server_cs));

	RINDENT();

	/*
	 *	We currently only handle AUTH packets here.
	 *	This could be expanded to handle other packets as well if required.
	 */
	rad_assert(request->packet->code == FR_CODE_ACCESS_REQUEST);

	rcode = rad_authenticate(request);

	if (request->reply->code == FR_CODE_ACCESS_REJECT) {
		fr_pair_delete_by_child_num(&request->control, fr_dict_root(fr_dict_internal), FR_POST_AUTH_TYPE, TAG_ANY);

		MEM(vp = fr_pair_afrom_child_num(request, fr_dict_root(fr_dict_internal), FR_POST_AUTH_TYPE));
		fr_pair_value_from_str(vp, "Reject", -1, '\0', false);
		fr_pair_add(&request->control, vp);

		rad_postauth(request);
	}

	if (request->reply->code == FR_CODE_ACCESS_ACCEPT) {
		(void) rad_postauth(request);
	}

	REXDENT();
	RDEBUG("} # server %s", cf_section_name2(request->server_cs));

	RDEBUG("Virtual server sending reply");
	log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, NULL);

	return rcode;
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


	log_request(L_DBG, L_DBG_LVL_1, request, "%s code %u Id %i from %s%s%s:%i to %s%s%s:%i "
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
