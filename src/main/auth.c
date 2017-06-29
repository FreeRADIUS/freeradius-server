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
 *	Return a short string showing the terminal server, port
 *	and calling station ID.
 */
char *auth_name(char *buf, size_t buflen, REQUEST *request, bool do_cli)
{
	VALUE_PAIR	*cli;
	VALUE_PAIR	*pair;
	uint32_t	port = 0;	/* RFC 2865 NAS-Port is 4 bytes */
	char const	*tls = "";

	if ((cli = fr_pair_find_by_num(request->packet->vps, 0, FR_CALLING_STATION_ID, TAG_ANY)) == NULL) {
		do_cli = false;
	}

	if ((pair = fr_pair_find_by_num(request->packet->vps, 0, FR_NAS_PORT, TAG_ANY)) != NULL) {
		port = pair->vp_uint32;
	}

	if (request->packet->dst_port == 0) {
		if (fr_pair_find_by_num(request->packet->vps, 0, FR_FREERADIUS_PROXIED_TO, TAG_ANY)) {
			tls = " via TLS tunnel";
		} else {
			tls = " via proxy to virtual server";
		}
	}

	snprintf(buf, buflen, "from client %.128s port %u%s%.128s%s",
			request->client->shortname, port,
		 (do_cli ? " cli " : ""), (do_cli ? cli->vp_strvalue : ""),
		 tls);

	return buf;
}



/*
 * Make sure user/pass are clean
 * and then log them
 */
static int rad_authlog(char const *msg, REQUEST *request, int goodpass)
{
	int logit;
	char const *extra_msg = NULL;
	char clean_password[1024];
	char clean_username[1024];
	char buf[1024];
	char extra[1024];
	char *p;
	VALUE_PAIR *username = NULL;

	if (!request->root->log_auth) {
		return 0;
	}

	/*
	 * Get the correct username based on the configured value
	 */
	if (!log_stripped_names) {
		username = fr_pair_find_by_num(request->packet->vps, 0, FR_USER_NAME, TAG_ANY);
	} else {
		username = request->username;
	}

	/*
	 *	Clean up the username
	 */
	if (username == NULL) {
		strcpy(clean_username, "<no User-Name attribute>");
	} else {
		fr_snprint(clean_username, sizeof(clean_username), username->vp_strvalue, username->vp_length, '\0');
	}

	/*
	 *	Clean up the password
	 */
	if (request->root->log_auth_badpass || request->root->log_auth_goodpass) {
		if (!request->password) {
			VALUE_PAIR *auth_type;

			auth_type = fr_pair_find_by_num(request->control, 0, FR_AUTH_TYPE, TAG_ANY);
			if (auth_type) {
				snprintf(clean_password, sizeof(clean_password),
					 "<via Auth-Type = %s>",
					 fr_dict_enum_alias_by_value(NULL, auth_type->da, &auth_type->data));
			} else {
				strcpy(clean_password, "<no User-Password attribute>");
			}
		} else if (fr_pair_find_by_num(request->packet->vps, 0, FR_CHAP_PASSWORD, TAG_ANY)) {
			strcpy(clean_password, "<CHAP-Password>");
		} else {
			fr_snprint(clean_password, sizeof(clean_password),
				  request->password->vp_strvalue, request->password->vp_length, '\0');
		}
	}

	if (goodpass) {
		logit = request->root->log_auth_goodpass;
		extra_msg = request->root->auth_goodpass_msg;
	} else {
		logit = request->root->log_auth_badpass;
		extra_msg = request->root->auth_badpass_msg;
	}

	if (extra_msg) {
		extra[0] = ' ';
		p = extra + 1;
		if (xlat_eval(p, sizeof(extra) - 1, request, extra_msg, NULL, NULL) < 0) {
			return -1;
		}
	} else {
		*extra = '\0';
	}

	RAUTH("%s: [%s%s%s] (%s)%s",
		       msg,
		       clean_username,
		       logit ? "/" : "",
		       logit ? clean_password : "",
		       auth_name(buf, sizeof(buf), request, 1),
		       extra);

	return 0;
}

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
	vp_cursor_t cursor;
	VALUE_PAIR *auth_type_pair;
	int auth_type = -1;
	int result;
	int auth_type_count = 0;

	/*
	 *	Look for matching check items. We skip the whole lot
	 *	if the authentication type is FR_AUTH_TYPE_ACCEPT or
	 *	FR_AUTH_TYPE_REJECT.
	 */
	fr_pair_cursor_init(&cursor, &request->control);
	while ((auth_type_pair = fr_pair_cursor_next_by_num(&cursor, 0, FR_AUTH_TYPE, TAG_ANY))) {
		auth_type = auth_type_pair->vp_uint32;
		auth_type_count++;

		RDEBUG2("Using 'Auth-Type = %s' for authenticate {...}",
			fr_dict_enum_alias_by_value(NULL, auth_type_pair->da, fr_box_uint32(auth_type)));
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

/*
 *	Process and reply to an authentication request
 *
 *	The return value of this function isn't actually used right now, so
 *	it's not entirely clear if it is returning the right things. --Pac.
 */
rlm_rcode_t rad_authenticate(REQUEST *request)
{
	VALUE_PAIR	*module_msg;
	VALUE_PAIR	*tmp = NULL;
	int		result;
	rlm_rcode_t    	rcode;
	char		autz_retry = 0;
	int		autz_type = 0;

#ifdef WITH_PROXY
	/*
	 *	If this request got proxied to another server, we need
	 *	to check whether it authenticated the request or not.
	 *
	 *	request->proxy gets set only AFTER authorization, so
	 *	it's safe to check it here.  If it exists, it means
	 *	we're doing a second pass through rad_authenticate().
	 */
	if (request->proxy) {
		int code = 0;

		if (request->proxy->reply) code = request->proxy->reply->code;

		switch (code) {
		/*
		 *	Reply of ACCEPT means accept, thus set Auth-Type
		 *	accordingly.
		 */
		case FR_CODE_ACCESS_ACCEPT:
			tmp = radius_pair_create(request,
						&request->control,
						FR_AUTH_TYPE, 0);
			if (tmp) tmp->vp_uint32 = FR_AUTH_TYPE_ACCEPT;
			rcode = RLM_MODULE_OK;
			goto authenticate;

		/*
		 *	Challenges are punted back to the NAS without any
		 *	further processing.
		 */
		case FR_CODE_ACCESS_CHALLENGE:
			request->reply->code = FR_CODE_ACCESS_CHALLENGE;
			fr_request_to_state(global_state, request, request->packet, request->reply);
			return RLM_MODULE_OK;

		/*
		 *	ALL other replies mean reject. (this is fail-safe)
		 *
		 *	Do NOT do any authorization or authentication. They
		 *	are being rejected, so we minimize the amount of work
		 *	done by the server, by rejecting them here.
		 */
		case FR_CODE_ACCESS_REJECT:
			rad_authlog("Login incorrect (Home Server says so)",
				    request, 0);
			request->reply->code = FR_CODE_ACCESS_REJECT;
			fr_state_discard(global_state, request, request->packet);
			return RLM_MODULE_REJECT;

		default:
			rad_authlog("Login incorrect (Home Server failed to respond)",
				    request, 0);
			fr_state_discard(global_state, request, request->packet);
			return RLM_MODULE_REJECT;
		}
	}
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
	 *	Grab the VPS and data associated with the State attribute.
	 */
	fr_state_to_request(global_state, request, request->packet);

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
		if ((module_msg = fr_pair_find_by_num(request->packet->vps, 0, FR_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL) {
			char msg[FR_MAX_STRING_LEN + 16];
			snprintf(msg, sizeof(msg), "Invalid user (%s)",
				 module_msg->vp_strvalue);
			rad_authlog(msg,request,0);
		} else {
			rad_authlog("Invalid user", request, 0);
		}
		request->reply->code = FR_CODE_ACCESS_REJECT;
		return rcode;
	}
	if (!autz_retry) {
		tmp = fr_pair_find_by_num(request->control, 0, FR_AUTZ_TYPE, TAG_ANY);
		if (tmp) {
			autz_type = tmp->vp_uint32;
			RDEBUG2("Using Autz-Type %s",
				fr_dict_enum_alias_by_value(NULL, tmp->da, fr_box_uint32(autz_type)));
			autz_retry = 1;
			goto autz_redo;
		}
	}

	/*
	 *	If we haven't already proxied the packet, then check
	 *	to see if we should.  Maybe one of the authorize
	 *	modules has decided that a proxy should be used. If
	 *	so, get out of here and send the packet.
	 */
	if (
#ifdef WITH_PROXY
	    (request->proxy == NULL) &&
#endif
	    ((tmp = fr_pair_find_by_num(request->control, 0, FR_PROXY_TO_REALM, TAG_ANY)) != NULL)) {
		REALM *realm;

		realm = NULL;

		/*
		 *	Don't authenticate, as the request is going to
		 *	be proxied.
		 */
		if (realm && realm->auth_pool) {
			return RLM_MODULE_OK;
		}

		/*
		 *	Catch users who set Proxy-To-Realm to a LOCAL
		 *	realm (sigh).  But don't complain if it is
		 *	*the* LOCAL realm.
		 */
		if (realm &&(strcmp(realm->name, "LOCAL") != 0)) {
			RWDEBUG2("You set Proxy-To-Realm = %s, but it is a LOCAL realm!  Cancelling proxy request.", realm->name);
		}

		if (!realm) {
			RWDEBUG2("You set Proxy-To-Realm = %s, but the realm does not exist!  Cancelling invalid proxy request.", tmp->vp_strvalue);
		}
	}

#ifdef WITH_PROXY
authenticate:
#endif

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

		if ((module_msg = fr_pair_find_by_num(request->packet->vps, 0, FR_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL){
			char msg[FR_MAX_STRING_LEN+19];

			snprintf(msg, sizeof(msg), "Login incorrect (%s)",
				 module_msg->vp_strvalue);
			rad_authlog(msg, request, 0);
		} else {
			rad_authlog("Login incorrect", request, 0);
		}

		if (request->password) {
			VERIFY_VP(request->password);
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

	if ((module_msg = fr_pair_find_by_num(request->packet->vps, 0, FR_MODULE_SUCCESS_MESSAGE, TAG_ANY)) != NULL){
		char msg[FR_MAX_STRING_LEN+12];

		snprintf(msg, sizeof(msg), "Login OK (%s)",
			 module_msg->vp_strvalue);
		rad_authlog(msg, request, 1);
	} else {
		rad_authlog("Login OK", request, 1);
	}

	return rcode;
}

#include <freeradius-devel/io/listen.h>

static rlm_rcode_t virtual_server_async(REQUEST *request)
{
	fr_io_final_t final;

	request->async = talloc_memdup(request, request->parent->async,
				       sizeof(fr_async_t));

	RDEBUG("server %s (async) {", cf_section_name2(request->server_cs));
	final = request->async->process(request, FR_IO_ACTION_RUN);
	RDEBUG("} # server %s (async) ", cf_section_name2(request->server_cs));

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
	if (request->parent && request->parent->async) return virtual_server_async(request);

	RDEBUG("server %s {", cf_section_name2(request->server_cs));

	RINDENT();

	/*
	 *	We currently only handle AUTH packets here.
	 *	This could be expanded to handle other packets as well if required.
	 */
	rad_assert(request->packet->code == FR_CODE_ACCESS_REQUEST);

	rcode = rad_authenticate(request);

	if (request->reply->code == FR_CODE_ACCESS_REJECT) {
		fr_pair_delete_by_num(&request->control, 0, FR_POST_AUTH_TYPE, TAG_ANY);
		vp = pair_make_config("Post-Auth-Type", "Reject", T_OP_SET);
		if (vp) (void) rad_postauth(request);
	}

	if (request->reply->code == FR_CODE_ACCESS_ACCEPT) {
		(void) rad_postauth(request);
	}

	REXDENT();
	RDEBUG("} # server %s", cf_section_name2(request->server_cs));

	RDEBUG("Virtual server sending reply");
	rdebug_pair_list(L_DBG_LVL_1, request, request->reply->vps, NULL);

	return rcode;
}
