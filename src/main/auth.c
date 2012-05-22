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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

/*
 *	Return a short string showing the terminal server, port
 *	and calling station ID.
 */
char *auth_name(char *buf, size_t buflen, REQUEST *request, int do_cli)
{
	VALUE_PAIR	*cli;
	VALUE_PAIR	*pair;
	int		port = 0;
	const char	*tls = "";

	if ((cli = pairfind(request->packet->vps, PW_CALLING_STATION_ID)) == NULL)
		do_cli = 0;
	if ((pair = pairfind(request->packet->vps, PW_NAS_PORT)) != NULL)
		port = pair->vp_integer;

	if (request->packet->dst_port == 0) {
		if (pairfind(request->packet->vps, PW_FREERADIUS_PROXIED_TO)) {
			tls = " via TLS tunnel";
		} else {
			tls = " via proxy to virtual server";
		}
	}

	snprintf(buf, buflen, "from client %.128s port %u%s%.128s%s",
			request->client->shortname, port,
		 (do_cli ? " cli " : ""), (do_cli ? (char *)cli->vp_strvalue : ""),
		 tls);

	return buf;
}



/*
 * Make sure user/pass are clean
 * and then log them
 */
static int rad_authlog(const char *msg, REQUEST *request, int goodpass)
{
	int logit;
	const char *extra_msg = NULL;
	char clean_password[1024];
	char clean_username[1024];
	char buf[1024];
	char extra[1024];
	VALUE_PAIR *username = NULL;

	if (!request->root->log_auth) {
		return 0;
	}

	/*
	 * Get the correct username based on the configured value
	 */
	if (log_stripped_names == 0) {
		username = pairfind(request->packet->vps, PW_USER_NAME);
	} else {
		username = request->username;
	}

	/*
	 *	Clean up the username
	 */
	if (username == NULL) {
		strcpy(clean_username, "<no User-Name attribute>");
	} else {
		fr_print_string((char *)username->vp_strvalue,
				username->length,
				clean_username, sizeof(clean_username));
	}

	/*
	 *	Clean up the password
	 */
	if (request->root->log_auth_badpass || request->root->log_auth_goodpass) {
		if (!request->password) {
			VALUE_PAIR *auth_type;

			auth_type = pairfind(request->config_items,
					     PW_AUTH_TYPE);
			if (auth_type) {
				snprintf(clean_password, sizeof(clean_password),
					 "<via Auth-Type = %s>",
					 dict_valnamebyattr(PW_AUTH_TYPE,
							    auth_type->vp_integer));
			} else {
				strcpy(clean_password, "<no User-Password attribute>");
			}
		} else if (pairfind(request->packet->vps, PW_CHAP_PASSWORD)) {
			strcpy(clean_password, "<CHAP-Password>");
		} else {
			fr_print_string((char *)request->password->vp_strvalue,
					 request->password->length,
					 clean_password, sizeof(clean_password));
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
		radius_xlat(extra + 1, sizeof(extra) - 1, extra_msg, request,
			    NULL);
	} else {
		*extra = '\0';
	}

	radlog_request(L_AUTH, 0, request, "%s: [%s%s%s] (%s)%s",
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
static int rad_check_password(REQUEST *request)
{
	VALUE_PAIR *auth_type_pair;
	VALUE_PAIR *cur_config_item;
	VALUE_PAIR *password_pair;
	VALUE_PAIR *auth_item;
	uint8_t my_chap[MAX_STRING_LEN];
	int auth_type = -1;
	int result;
	int auth_type_count = 0;
	result = 0;

	/*
	 *	Look for matching check items. We skip the whole lot
	 *	if the authentication type is PW_AUTHTYPE_ACCEPT or
	 *	PW_AUTHTYPE_REJECT.
	 */
	cur_config_item = request->config_items;
	while(((auth_type_pair = pairfind(cur_config_item, PW_AUTH_TYPE))) != NULL) {

		auth_type = auth_type_pair->vp_integer;
		auth_type_count++;

		RDEBUG2("Found Auth-Type = %s",
			dict_valnamebyattr(PW_AUTH_TYPE,
					   auth_type_pair->vp_integer));
		cur_config_item = auth_type_pair->next;

		if (auth_type == PW_AUTHTYPE_REJECT) {
			RDEBUG2("Auth-Type = Reject, rejecting user");
			return -2;
		}
	}

	if (( auth_type_count > 1) && (debug_flag)) {
		radlog_request(L_ERR, 0, request, "Warning:  Found %d auth-types on request for user '%s'",
			auth_type_count, request->username->vp_strvalue);
	}

	/*
	 *	This means we have a proxy reply or an accept
	 *  and it wasn't rejected in the above loop.  So
	 *  that means it is accepted and we do no further
	 *  authentication
	 */
	if ((auth_type == PW_AUTHTYPE_ACCEPT)
#ifdef WITH_PROXY
	    || (request->proxy)
#endif
	    ) {
		RDEBUG2("Auth-Type = Accept, accepting the user");
		return 0;
	}

	password_pair =  pairfind(request->config_items, PW_USER_PASSWORD);
	if (password_pair &&
	    pairfind(request->config_items, PW_CLEARTEXT_PASSWORD)) {
		pairdelete(&request->config_items, PW_USER_PASSWORD);
		password_pair = NULL;
	}

	if (password_pair) {
		DICT_ATTR *da;

		RDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		RDEBUG("!!!    Replacing User-Password in config items with Cleartext-Password.     !!!");
		RDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		RDEBUG("!!! Please update your configuration so that the \"known good\"               !!!");
		RDEBUG("!!! clear text password is in Cleartext-Password, and not in User-Password. !!!");
		RDEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		password_pair->attribute = PW_CLEARTEXT_PASSWORD;
		da = dict_attrbyvalue(PW_CLEARTEXT_PASSWORD);
		if (!da) {
			radlog_request(L_ERR, 0, request, "FATAL: You broke the dictionaries.  Please use the default dictionaries!");
			_exit(1);
		}

		password_pair->name = da->name;
	}

	/*
	 *	Find the "known good" password.
	 *
	 *	FIXME: We should get rid of these hacks, and replace
	 *	them with a module.
	 */
	if ((password_pair = pairfind(request->config_items, PW_CRYPT_PASSWORD)) != NULL) {
		/*
		 *	Re-write Auth-Type, but ONLY if it isn't already
		 *	set.
		 */
		if (auth_type == -1) auth_type = PW_AUTHTYPE_CRYPT;
	} else {
		password_pair = pairfind(request->config_items, PW_CLEARTEXT_PASSWORD);
	}

	if (auth_type < 0) {
		if (password_pair) {
			auth_type = PW_AUTHTYPE_LOCAL;
		} else {
			/*
		 	*	The admin hasn't told us how to
		 	*	authenticate the user, so we reject them!
		 	*
		 	*	This is fail-safe.
		 	*/
			RDEBUG2("ERROR: No authenticate method (Auth-Type) found for the request: Rejecting the user");
			return -2;
		}
	}

	switch(auth_type) {
		case PW_AUTHTYPE_CRYPT:
			RDEBUG2("WARNING: Please update your configuration, and remove 'Auth-Type = Crypt'");
			RDEBUG2("WARNING: Use the PAP module instead.");

			/*
			 *	Find the password sent by the user. It
			 *	SHOULD be there, if it's not
			 *	authentication fails.
			 */
			auth_item = request->password;
			if (auth_item == NULL) {
				RDEBUG2("No User-Password or CHAP-Password attribute in the request");
				return -1;
			}

			if (password_pair == NULL) {
				RDEBUG2("No Crypt-Password configured for the user");
				rad_authlog("Login incorrect "
					"(No Crypt-Password configured for the user)", request, 0);
				return -1;
			}

			switch (fr_crypt_check((char *)auth_item->vp_strvalue,
									 (char *)password_pair->vp_strvalue)) {
			case -1:
			  rad_authlog("Login incorrect "
						  "(system failed to supply an encrypted password for comparison)", request, 0);
			  /* FALL-THROUGH */
			case 1:
			  return -1;
			}
			break;
		case PW_AUTHTYPE_LOCAL:
			RDEBUG2("WARNING: Please update your configuration, and remove 'Auth-Type = Local'");
			RDEBUG2("WARNING: Use the PAP or CHAP modules instead.");

			/*
			 *	Find the password sent by the user. It
			 *	SHOULD be there, if it's not
			 *	authentication fails.
			 */
			auth_item = request->password;
			if (!auth_item)
				auth_item = pairfind(request->packet->vps,
						     PW_CHAP_PASSWORD);
			if (!auth_item) {
				RDEBUG2("No User-Password or CHAP-Password attribute in the request.");
				RDEBUG2("Cannot perform authentication.");
				return -1;
			}

			/*
			 *	Plain text password.
			 */
			if (password_pair == NULL) {
				RDEBUG2("No \"known good\" password was configured for the user.");
				RDEBUG2("As a result, we cannot authenticate the user.");
				rad_authlog("Login incorrect "
					"(No password configured for the user)", request, 0);
				return -1;
			}

			/*
			 *	Local password is just plain text.
	 		 */
			if (auth_item->attribute == PW_USER_PASSWORD) {
				if (strcmp((char *)password_pair->vp_strvalue,
					   (char *)auth_item->vp_strvalue) != 0) {
					RDEBUG2("User-Password in the request does NOT match \"known good\" password.");
					return -1;
				}
				RDEBUG2("User-Password in the request is correct.");
				break;

			} else if (auth_item->attribute != PW_CHAP_PASSWORD) {
				RDEBUG2("The user did not supply a User-Password or a CHAP-Password attribute");
				rad_authlog("Login incorrect "
					"(no User-Password or CHAP-Password attribute)", request, 0);
				return -1;
			}

			rad_chap_encode(request->packet, my_chap,
					auth_item->vp_octets[0], password_pair);

			/*
			 *	Compare them
			 */
			if (memcmp(my_chap + 1, auth_item->vp_strvalue + 1,
				   CHAP_VALUE_LENGTH) != 0) {
				RDEBUG2("CHAP-Password is incorrect.");
				return -1;
			}
			RDEBUG2("CHAP-Password is correct.");
			break;
		default:
			/*
			 *	See if there is a module that handles
			 *	this type, and turn the RLM_ return
			 *	status into the values as defined at
			 *	the top of this function.
			 */
			result = module_authenticate(auth_type, request);
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
			break;
	}

	return result;
}

/*
 *	Post-authentication step processes the response before it is
 *	sent to the NAS. It can receive both Access-Accept and Access-Reject
 *	replies.
 */
int rad_postauth(REQUEST *request)
{
	int	result;
	int	postauth_type = 0;
	VALUE_PAIR *vp;

	/*
	 *	Do post-authentication calls. ignoring the return code.
	 */
	vp = pairfind(request->config_items, PW_POST_AUTH_TYPE);
	if (vp) {
		RDEBUG2("Using Post-Auth-Type %s",
			dict_valnamebyattr(PW_POST_AUTH_TYPE, vp->vp_integer));
		postauth_type = vp->vp_integer;
	}
	result = module_post_auth(postauth_type, request);
	switch (result) {
		/*
		 *	The module failed, or said to reject the user: Do so.
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			request->reply->code = PW_AUTHENTICATION_REJECT;
			result = RLM_MODULE_REJECT;
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
			result = RLM_MODULE_OK;
			break;
	}
	return result;
}

/*
 *	Process and reply to an authentication request
 *
 *	The return value of this function isn't actually used right now, so
 *	it's not entirely clear if it is returning the right things. --Pac.
 */
int rad_authenticate(REQUEST *request)
{
	VALUE_PAIR	*namepair;
#ifdef WITH_SESSION_MGMT
	VALUE_PAIR	*check_item;
#endif
	VALUE_PAIR	*auth_item = NULL;
	VALUE_PAIR	*module_msg;
	VALUE_PAIR	*tmp = NULL;
	int		result;
	const char	*password;
	char		autz_retry = 0;
	int		autz_type = 0;

	password = "";

#ifdef WITH_PROXY
	/*
	 *	If this request got proxied to another server, we need
	 *	to check whether it authenticated the request or not.
	 */
	if (request->proxy_reply) {
		switch (request->proxy_reply->code) {
		/*
		 *	Reply of ACCEPT means accept, thus set Auth-Type
		 *	accordingly.
		 */
		case PW_AUTHENTICATION_ACK:
			tmp = radius_paircreate(request,
						&request->config_items,
						PW_AUTH_TYPE, PW_TYPE_INTEGER);
			if (tmp) tmp->vp_integer = PW_AUTHTYPE_ACCEPT;
#ifdef WITH_POST_PROXY_AUTHORIZE
			if (mainconfig.post_proxy_authorize) break;
#endif
			goto authenticate;

		/*
		 *	Challenges are punted back to the NAS without any
		 *	further processing.
		 */
		case PW_ACCESS_CHALLENGE:
			request->reply->code = PW_ACCESS_CHALLENGE;
			return RLM_MODULE_OK;
		/*
		 *	ALL other replies mean reject. (this is fail-safe)
		 *
		 *	Do NOT do any authorization or authentication. They
		 *	are being rejected, so we minimize the amount of work
		 *	done by the server, by rejecting them here.
		 */
		case PW_AUTHENTICATION_REJECT:
			rad_authlog("Login incorrect (Home Server says so)",
				    request, 0);
			request->reply->code = PW_AUTHENTICATION_REJECT;
			return RLM_MODULE_REJECT;

		default:
			rad_authlog("Login incorrect (Home Server failed to respond)",
				    request, 0);
			return RLM_MODULE_REJECT;
		}
	}
#endif

	/*
	 *	Get the username from the request.
	 *
	 *	Note that namepair MAY be NULL, in which case there
	 *	is no User-Name attribute in the request.
	 */
	namepair = request->username;

	/*
	 *	Look for, and cache, passwords.
	 */
	if (!request->password) {
		request->password = pairfind(request->packet->vps,
					     PW_USER_PASSWORD);
	}

	/*
	 *	Discover which password we want to use.
	 */
	auth_item = request->password;
	if (auth_item) {
		password = (const char *)auth_item->vp_strvalue;

	} else {
		/*
		 *	Maybe there's a CHAP-Password?
		 */
		if ((auth_item = pairfind(request->packet->vps,
					  PW_CHAP_PASSWORD)) != NULL) {
			password = "<CHAP-PASSWORD>";

		} else {
			/*
			 *	No password we recognize.
			 */
			password = "<NO-PASSWORD>";
		}
	}
	request->password = auth_item;

	/*
	 *	Get the user's authorization information from the database
	 */
autz_redo:
	result = module_authorize(autz_type, request);
	switch (result) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			break;
		case RLM_MODULE_HANDLED:
			return result;
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			if ((module_msg = pairfind(request->packet->vps,
					PW_MODULE_FAILURE_MESSAGE)) != NULL) {
				char msg[MAX_STRING_LEN + 16];
				snprintf(msg, sizeof(msg), "Invalid user (%s)",
					 module_msg->vp_strvalue);
				rad_authlog(msg,request,0);
			} else {
				rad_authlog("Invalid user", request, 0);
			}
			request->reply->code = PW_AUTHENTICATION_REJECT;
			return result;
	}
	if (!autz_retry) {
		tmp = pairfind(request->config_items, PW_AUTZ_TYPE);
		if (tmp) {
			autz_type = tmp->vp_integer;
			RDEBUG2("Using Autz-Type %s",
				dict_valnamebyattr(PW_AUTZ_TYPE, autz_type));
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
	    ((tmp = pairfind(request->config_items, PW_PROXY_TO_REALM)) != NULL)) {
		REALM *realm;

		realm = realm_find2(tmp->vp_strvalue);

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
			RDEBUG2("WARNING: You set Proxy-To-Realm = %s, but it is a LOCAL realm!  Cancelling proxy request.", realm->name);
		}

		if (!realm) {
			RDEBUG2("WARNING: You set Proxy-To-Realm = %s, but the realm does not exist!  Cancelling invalid proxy request.", tmp->vp_strvalue);
		}
	}

#ifdef WITH_PROXY
 authenticate:
#endif

	/*
	 *	Perhaps there is a Stripped-User-Name now.
	 */
	namepair = request->username;

	/*
	 *	Validate the user
	 */
	do {
		result = rad_check_password(request);
		if (result > 0) {
			/* don't reply! */
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
		RDEBUG2("Failed to authenticate the user.");
		request->reply->code = PW_AUTHENTICATION_REJECT;

		if ((module_msg = pairfind(request->packet->vps,PW_MODULE_FAILURE_MESSAGE)) != NULL){
			char msg[MAX_STRING_LEN+19];

			snprintf(msg, sizeof(msg), "Login incorrect (%s)",
				 module_msg->vp_strvalue);
			rad_authlog(msg, request, 0);
		} else {
			rad_authlog("Login incorrect", request, 0);
		}

		/* double check: maybe the secret is wrong? */
		if ((debug_flag > 1) && (auth_item != NULL) &&
				(auth_item->attribute == PW_USER_PASSWORD)) {
			uint8_t *p;

			p = (uint8_t *) auth_item->vp_strvalue;
			while (*p) {
				int size;

				size = fr_utf8_char(p);
				if (!size) {
					log_debug("  WARNING: Unprintable characters in the password.  Double-check the shared secret on the server and the NAS!");
					break;
				}
				p += size;
			}
		}
	}

#ifdef WITH_SESSION_MGMT
	if (result >= 0 &&
	    (check_item = pairfind(request->config_items, PW_SIMULTANEOUS_USE)) != NULL) {
		int r, session_type = 0;
		char		logstr[1024];
		char		umsg[MAX_STRING_LEN + 1];
		const char	*user_msg = NULL;

		tmp = pairfind(request->config_items, PW_SESSION_TYPE);
		if (tmp) {
			session_type = tmp->vp_integer;
			RDEBUG2("Using Session-Type %s",
				dict_valnamebyattr(PW_SESSION_TYPE, session_type));
		}

		/*
		 *	User authenticated O.K. Now we have to check
		 *	for the Simultaneous-Use parameter.
		 */
		if (namepair &&
		    (r = module_checksimul(session_type, request, check_item->vp_integer)) != 0) {
			char mpp_ok = 0;

			if (r == 2){
				/* Multilink attempt. Check if port-limit > simultaneous-use */
				VALUE_PAIR *port_limit;

				if ((port_limit = pairfind(request->reply->vps, PW_PORT_LIMIT)) != NULL &&
					port_limit->vp_integer > check_item->vp_integer){
					RDEBUG2("MPP is OK");
					mpp_ok = 1;
				}
			}
			if (!mpp_ok){
				if (check_item->vp_integer > 1) {
		  		snprintf(umsg, sizeof(umsg),
							"\r\nYou are already logged in %d times  - access denied\r\n\n",
							(int)check_item->vp_integer);
					user_msg = umsg;
				} else {
					user_msg = "\r\nYou are already logged in - access denied\r\n\n";
				}

				request->reply->code = PW_AUTHENTICATION_REJECT;

				/*
				 *	They're trying to log in too many times.
				 *	Remove ALL reply attributes.
				 */
				pairfree(&request->reply->vps);
				radius_pairmake(request, &request->reply->vps,
						"Reply-Message",
						user_msg, T_OP_SET);

				snprintf(logstr, sizeof(logstr), "Multiple logins (max %d) %s",
					check_item->vp_integer,
					r == 2 ? "[MPP attempt]" : "");
				rad_authlog(logstr, request, 1);

				result = -1;
			}
		}
	}
#endif

	/*
	 *	Result should be >= 0 here - if not, it means the user
	 *	is rejected, so we just process post-auth and return.
	 */
	if (result < 0) {
		return RLM_MODULE_REJECT;
	}

	/*
	 *	Add the port number to the Framed-IP-Address if
	 *	vp->addport is set.
	 */
	if (((tmp = pairfind(request->reply->vps,
			     PW_FRAMED_IP_ADDRESS)) != NULL) &&
	    (tmp->flags.addport != 0)) {
		VALUE_PAIR *vpPortId;

		/*
		 *  Find the NAS port ID.
		 */
		if ((vpPortId = pairfind(request->packet->vps,
					 PW_NAS_PORT)) != NULL) {
		  unsigned long tvalue = ntohl(tmp->vp_integer);
		  tmp->vp_integer = htonl(tvalue + vpPortId->vp_integer);
		  tmp->flags.addport = 0;
		  ip_ntoa(tmp->vp_strvalue, tmp->vp_integer);
		} else {
			RDEBUG2("WARNING: No NAS-Port attribute in request.  CANNOT return a Framed-IP-Address + NAS-Port.\n");
			pairdelete(&request->reply->vps, PW_FRAMED_IP_ADDRESS);
		}
	}

	/*
	 *	Set the reply to Access-Accept, if it hasn't already
	 *	been set to something.  (i.e. Access-Challenge)
	 */
	if (request->reply->code == 0)
	  request->reply->code = PW_AUTHENTICATION_ACK;

	if ((module_msg = pairfind(request->packet->vps,PW_MODULE_SUCCESS_MESSAGE)) != NULL){
		char msg[MAX_STRING_LEN+12];

		snprintf(msg, sizeof(msg), "Login OK (%s)",
			 module_msg->vp_strvalue);
		rad_authlog(msg, request, 1);
	} else {
		rad_authlog("Login OK", request, 1);
	}

	/*
	 *	Run the modules in the 'post-auth' section.
	 */
	result = rad_postauth(request);

	return result;
}
