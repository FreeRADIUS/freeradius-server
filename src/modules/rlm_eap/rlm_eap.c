/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_eap.c
 * @brief Implements the EAP framework.
 *
 * @copyright 2000-2003,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_eap (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "rlm_eap.h"

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("default_eap_type", PW_TYPE_STRING, rlm_eap_t, default_method_name), .dflt = "md5" },
	{ FR_CONF_DEPRECATED("timer_expire", PW_TYPE_INTEGER, rlm_eap_t, timer_limit), .dflt = "60" },
	{ FR_CONF_OFFSET("ignore_unknown_eap_types", PW_TYPE_BOOLEAN, rlm_eap_t, ignore_unknown_types), .dflt = "no" },
	{ FR_CONF_OFFSET("cisco_accounting_username_bug", PW_TYPE_BOOLEAN, rlm_eap_t,
			 mod_accounting_username_bug), .dflt = "no" },
	{ FR_CONF_DEPRECATED("max_sessions", PW_TYPE_INTEGER, rlm_eap_t, max_sessions), .dflt = "2048" },
	CONF_PARSER_TERMINATOR
};

static rlm_rcode_t mod_post_proxy(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_authenticate(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request) CC_HINT(nonnull);

static int mod_bootstrap(CONF_SECTION *cs, void *instance)
{
	int		i, ret;
	eap_type_t	method;
	int		num_methods;
	CONF_SECTION 	*scs;
	rlm_eap_t	*inst = instance;

	/*
	 *	Create our own random pool.
	 */
	for (i = 0; i < 256; i++) inst->rand_pool.randrsl[i] = fr_rand();
	fr_randinit(&inst->rand_pool, 1);
	inst->rand_pool.randcnt = 0;

	inst->name = cf_section_name2(cs);
	if (!inst->name) inst->name = "EAP";

	/* Load all the configured EAP-Types */
	num_methods = 0;
	for (scs = cf_subsection_find_next(cs, NULL, NULL);
	     scs != NULL;
	     scs = cf_subsection_find_next(cs, scs, NULL)) {

		char const *name;

		name = cf_section_name1(scs);
		if (!name) continue;

		if (!strcmp(name, TLS_CONFIG_SECTION)) continue;

		method = eap_name2type(name);
		if (method == PW_EAP_INVALID) {
			cf_log_err_cs(cs, "Unknown EAP type %s", name);
			return -1;
		}

		if ((method < PW_EAP_MD5) || (method >= PW_EAP_MAX_TYPES)) {
			cf_log_err_cs(cs, "Invalid EAP method %s (unsupported)", name);
			return -1;
		}

#if !defined(HAVE_OPENSSL_SSL_H) || !defined(HAVE_LIBSSL)
		/*
		 *	This allows the default configuration to be
		 *	shipped with EAP-TLS, etc. enabled.  If the
		 *	system doesn't have OpenSSL, they will be
		 *	ignored.
		 *
		 *	If the system does have OpenSSL, then this
		 *	code will not be used.  The administrator will
		 *	then have to delete the tls,
		 *	etc. configurations from eap.conf in order to
		 *	have EAP without the TLS types.
		 */
		switch (method) {
		case PW_EAP_TLS:
		case PW_EAP_TTLS:
		case PW_EAP_PEAP:
		case PW_EAP_FAST:
		case PW_EAP_PWD:
			WARN("Ignoring EAP method %s because we don't have OpenSSL support", name);
			continue;

		default:
			break;
		}
#endif

		/*
		 *	Load the type.
		 */
		ret = eap_module_instantiate(inst, &inst->methods[method], method, scs);

		(void)talloc_get_type_abort(inst->methods[method], eap_module_t);

		if (ret < 0) {
			(void)talloc_steal(inst, inst->methods[method]);
			return -1;
		}

		(void)talloc_steal(inst, inst->methods[method]);
		num_methods++;        /* successfully loaded one more methods */
	}

	if (num_methods == 0) {
		cf_log_err_cs(cs, "No EAP method configured, module cannot do anything");
		return -1;
	}

	/*
	 *	Ensure that the default EAP type is loaded.
	 */
	method = eap_name2type(inst->default_method_name);
	if (method == PW_EAP_INVALID) {
		cf_log_err_by_name(cs, "default_eap_type", "Unknown EAP type %s",
				   inst->default_method_name);
		return -1;
	}

	if (!inst->methods[method]) {
		cf_log_err_cs(cs, "No such sub-type for default EAP method %s",
			      inst->default_method_name);
		return -1;
	}
	inst->default_method = method; /* save the numerical method */

	return 0;
}

static rlm_rcode_t mod_authenticate(void *instance, REQUEST *request)
{
	rlm_eap_t		*inst;
	eap_session_t		*eap_session;
	eap_packet_raw_t	*eap_packet;
	eap_rcode_t		status;
	rlm_rcode_t		rcode;

	inst = (rlm_eap_t *)instance;

	if (!fr_pair_find_by_num(request->packet->vps, 0, PW_EAP_MESSAGE, TAG_ANY)) {
		REDEBUG("You set 'Auth-Type = EAP' for a request that does not contain an EAP-Message attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Reconstruct the EAP packet from EAP-Message fragments
	 *	in the request.
	 */
	eap_packet = eap_vp2packet(request, request->packet->vps);
	if (!eap_packet) {
		RERROR("Malformed EAP Message: %s", fr_strerror());
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Allocate a new eap_session, or if this request
	 *	is part of an ongoing authentication session,
	 *	retrieve the existing eap_session from the request
	 *	data.
	 */
	eap_session = eap_session_continue(&eap_packet, inst, request);
	if (!eap_session) {
		REDEBUG("Failed allocating or retrieving EAP session");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Call an EAP submodule to process the request,
	 *	or with simple types like Identity and NAK,
	 *	process it ourselves.
	 */
	status = eap_method_select(inst, eap_session);

	/*
	 *	The submodule failed.  Die.
	 */
	if (status == EAP_INVALID) {
		eap_fail(eap_session);
		eap_session_destroy(&eap_session);
		rcode = RLM_MODULE_INVALID;
		goto finish;
	}

#ifdef WITH_PROXY
	/*
	 *	If we're doing horrible tunnelling work, remember it.
	 */
	if ((request->options & RAD_REQUEST_OPTION_PROXY_EAP) != 0) {
		int ret;

		RDEBUG2("Proxy EAP as non-EAP.  Not composing EAP");

		/*
		 *	Mark the request up as having been see by the EAP
		 *	module before proxying.
		 */
		ret = request_data_add(request, inst, REQUEST_DATA_EAP_SESSION_PROXIED, NULL,
				       false, false, false);
		rad_cond_assert(ret == 0);
		rcode = RLM_MODULE_HANDLED;
		goto finish;
	}

	/*
	 *	Maybe the request was marked to be proxied.  If so,
	 *	proxy it.
	 */
	if (request->proxy != NULL) {
		VALUE_PAIR 	*vp = NULL;
		int		ret;

		rad_assert(!request->proxy->reply);

		/*
		 *	Mark the request up as having been see by the EAP
		 *	module before proxying.
		 */
		ret = request_data_add(request, inst, REQUEST_DATA_EAP_SESSION_PROXIED, NULL,
				       false, false, false);
		rad_cond_assert(ret == 0);

		/*
		 *	Some simple sanity checks.  These should really
		 *	be handled by the radius library...
		 */
		vp = fr_pair_find_by_num(request->proxy->packet->vps, 0, PW_EAP_MESSAGE, TAG_ANY);
		if (vp) {
			vp = fr_pair_find_by_num(request->proxy->packet->vps, 0, PW_MESSAGE_AUTHENTICATOR, TAG_ANY);
			if (!vp) {
				fr_pair_make(request->proxy->packet, &request->proxy->packet->vps,
					     "Message-Authenticator", NULL, T_OP_EQ);
			}
		}

		/*
		 *	Delete the "proxied to" attribute, as it's
		 *	set to 127.0.0.1 for tunneled requests, and
		 *	we don't want to tell the world that...
		 */
		fr_pair_delete_by_num(&request->proxy->packet->vps, VENDORPEC_FREERADIUS, PW_FREERADIUS_PROXIED_TO, TAG_ANY);

		RDEBUG2("Tunneled session will be proxied.  Not doing EAP");
		rcode = RLM_MODULE_HANDLED;
		goto finish;
	}
#endif

	/*
	 *	We are done, wrap the EAP-request in RADIUS to send
	 *	with all other required radius attributes
	 */
	rcode = eap_compose(eap_session);

	/*
	 *	Add to the list only if it is EAP-Request, OR if
	 *	it's LEAP, and a response.
	 */
	if (((eap_session->this_round->request->code == PW_EAP_REQUEST) &&
	    (eap_session->this_round->request->type.num >= PW_EAP_MD5)) ||

		/*
		 *	LEAP is a little different.  At Stage 4,
		 *	it sends an EAP-Success message, but we still
		 *	need to keep the State attribute & session
		 *	data structure around for the AP Challenge.
		 *
		 *	At stage 6, LEAP sends an EAP-Response, which
		 *	isn't put into the list.
		 */
	    ((eap_session->this_round->response->code == PW_EAP_RESPONSE) &&
	     (eap_session->this_round->response->type.num == PW_EAP_LEAP) &&
	     (eap_session->this_round->request->code == PW_EAP_SUCCESS) &&
	     (eap_session->this_round->request->type.num == 0))) {
		talloc_free(eap_session->prev_round);
		eap_session->prev_round = eap_session->this_round;
		eap_session->this_round = NULL;
	} else {
		RDEBUG2("Cleaning up EAP session");
		eap_session_destroy(&eap_session);
	}

	/*
	 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
	 *	says that we MUST include a User-Name attribute in the
	 *	Access-Accept.
	 */
	if ((request->reply->code == PW_CODE_ACCESS_ACCEPT) && request->username) {
		VALUE_PAIR *vp;

		/*
		 *	Doesn't exist, add it in.
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 0, PW_USER_NAME, TAG_ANY);
		if (!vp) {
			vp = fr_pair_copy(request->reply, request->username);
			fr_pair_add(&request->reply->vps, vp);
		}

		/*
		 *	Cisco AP1230 has a bug and needs a zero
		 *	terminated string in Access-Accept.
		 */
		if (inst->mod_accounting_username_bug) {
			char *new;

			new = talloc_zero_array(vp, char, vp->vp_length + 1 + 1);	/* \0 + \0 */
			memcpy(new, vp->vp_strvalue, vp->vp_length);
			fr_pair_value_strsteal(vp, new);        /* Also frees existing buffer */
		}
	}

finish:
	/*
	 *	Freeze the eap_session so we can continue
	 *	the authentication session later.
	 */
	eap_session_freeze(&eap_session);

	return rcode;
}

/*
 * EAP authorization DEPENDS on other rlm authorizations,
 * to check for user existence & get their configured values.
 * It Handles EAP-START Messages, User-Name initilization.
 */
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	rlm_eap_t	*inst;
	int		status;
	VALUE_PAIR	*vp;

	inst = (rlm_eap_t *)instance;

#ifdef WITH_PROXY
	/*
	 *	We don't do authorization again, once we've seen the
	 *	proxy reply (or the proxied packet)
	 */
	if (request->proxy != NULL)
		return RLM_MODULE_NOOP;
#endif

	/*
	 *	For EAP_START, send Access-Challenge with EAP Identity
	 *	request.  even when we have to proxy this request
	 *
	 *	RFC 2869, Section 2.3.1 notes that the "domain" of the
	 *	user, (i.e. where to proxy him) comes from the EAP-Identity,
	 *	so we CANNOT proxy the user, until we know his identity.
	 *
	 *	We therefore send an EAP Identity request.
	 */
	status = eap_start(inst, request);
	switch (status) {
	case EAP_NOOP:
		return RLM_MODULE_NOOP;

	case EAP_FAIL:
		return RLM_MODULE_FAIL;

	case EAP_FOUND:
		return RLM_MODULE_HANDLED;

	case EAP_OK:
	case EAP_NOTFOUND:
	default:
		break;
	}

	/*
	 *	RFC 2869, Section 2.3.1.  If a NAS sends an EAP-Identity,
	 *	it MUST copy the identity into the User-Name attribute.
	 *
	 *	But we don't worry about that too much.  We depend on
	 *	each EAP sub-module to look for eap_session->request->username,
	 *	and to get excited if it doesn't appear.
	 */
	vp = fr_pair_find_by_num(request->control, 0, PW_AUTH_TYPE, TAG_ANY);
	if ((!vp) || (vp->vp_integer != PW_AUTH_TYPE_REJECT)) {
		vp = pair_make_config("Auth-Type", inst->name, T_OP_EQ);
		if (!vp) {
			RDEBUG2("Failed to create Auth-Type %s: %s\n",
				inst->name, fr_strerror());
			return RLM_MODULE_FAIL;
		}
	} else {
		RWDEBUG2("Auth-Type already set.  Not setting to EAP");
	}

	if (status == EAP_OK) return RLM_MODULE_OK;

	return RLM_MODULE_UPDATED;
}

#ifdef WITH_PROXY
/*
 *	If we're proxying EAP, then there may be magic we need
 *	to do.
 */
static rlm_rcode_t mod_post_proxy(void *instance, REQUEST *request)
{
	size_t		i;
	size_t		len;
	ssize_t		ret;
	char		*p;
	VALUE_PAIR	*vp;
	eap_session_t	*eap_session;
	vp_cursor_t	cursor;
	rlm_eap_t	*inst = instance;

	/*
	 *	If there was a eap_session associated with this request,
	 *	then it's a tunneled request which was proxied...
	 */
	if (request_data_get(request, inst, REQUEST_DATA_EAP_SESSION_PROXIED)) {
		rlm_rcode_t		rcode;
		eap_tunnel_data_t	*data;

		eap_session = eap_session_thaw(request);
		rad_assert(eap_session);

		/*
		 *	Grab the tunnel callbacks from the request.
		 */
		data = (eap_tunnel_data_t *) request_data_get(request,
							      request->proxy,
							      REQUEST_DATA_EAP_TUNNEL_CALLBACK);
		if (!data) {
			RERROR("Failed to retrieve callback for tunneled session!");
			eap_session_destroy(&eap_session);
			return RLM_MODULE_FAIL;
		}

		/*
		 *	Do the callback...
		 */
		RDEBUG2("Doing post-proxy callback");
		rcode = data->callback(eap_session, data->tls_session);

		talloc_free(data);
		if (rcode == 0) {
			RDEBUG2("Failed in post-proxy callback");
			eap_fail(eap_session);
			eap_session_destroy(&eap_session);
			return RLM_MODULE_REJECT;
		}

		/*
		 *	We are done, wrap the EAP-request in RADIUS to send
		 *	with all other required radius attributes
		 */
		eap_compose(eap_session);

		/*
		 *	Add to the list only if it is EAP-Request, OR if
		 *	it's LEAP, and a response.
		 */
		if ((eap_session->this_round->request->code == PW_EAP_REQUEST) &&
		    (eap_session->this_round->request->type.num >= PW_EAP_MD5)) {
			talloc_free(eap_session->prev_round);
			eap_session->prev_round = eap_session->this_round;
			eap_session->this_round = NULL;
		} else {	/* couldn't have been LEAP, there's no tunnel */
			RDEBUG2("Freeing eap_session");
			eap_session_destroy(&eap_session);
		}

		/*
		 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
		 *	says that we MUST include a User-Name attribute in the
		 *	Access-Accept.
		 */
		if ((request->reply->code == PW_CODE_ACCESS_ACCEPT) && request->username) {
			/*
			 *	Doesn't exist, add it in.
			 */
			vp = fr_pair_find_by_num(request->reply->vps, 0, PW_USER_NAME, TAG_ANY);
			if (!vp) {
				pair_make_reply("User-Name", request->username->vp_strvalue, T_OP_EQ);
			}
		}

		eap_session_freeze(&eap_session);

		return RLM_MODULE_OK;
	} else {
		RDEBUG2("No pre-existing eap_session found");
	}

	/*
	 *	This is allowed.
	 */
	if (!request->proxy->reply) return RLM_MODULE_NOOP;

	/*
	 *	Hmm... there's got to be a better way to
	 *	discover codes for vendor attributes.
	 *
	 *	This is vendor Cisco (9), Cisco-AVPair
	 *	attribute (1)
	 */
	for (vp = fr_cursor_init(&cursor, &request->proxy->reply->vps);
	     vp;
	     vp = fr_cursor_next_by_num(&cursor, 9, 1, TAG_ANY)) {
		/*
		 *	If it's "leap:session-key", then stop.
		 *
		 *	The format is VERY specific!
		 */
		if (strncasecmp(vp->vp_strvalue, "leap:session-key=", 17) == 0) break;
	}

	/*
	 *	Got to the end without finding "leap:session-key="
	 */
	if (!vp) return RLM_MODULE_NOOP;

	/*
	 *	The format is very specific.
	 *
	 *	- 17 bytes are "leap:session-key="
	 *	- 32 are the hex encoded session key.
	 *	- 2 bytes are the salt.
	 */
	if (vp->vp_length != (17 + 34)) {
		RDEBUG2("&Cisco-AVPair with leap:session-key has incorrect length. Got %zu, expected %d",
		       vp->vp_length, 17 + 34);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Decrypt the session key, using the proxy data.
	 *
	 *	Note that the session key is *binary*, and therefore
	 *	may contain embedded zeros.  So we have to use memdup.
	 *	However, Cisco-AVPair is a "string", so the rest of the
	 *	code assumes that it's terminated by a trailing '\0'.
	 *
	 *	So... be sure to (a) use memdup, and (b) include the last
	 *	zero byte.
	 */
	i = 34;
	p = talloc_memdup(vp, vp->vp_strvalue, vp->vp_length + 1);
	talloc_set_type(p, uint8_t);
	ret = fr_radius_decode_tunnel_password((uint8_t *)p + 17, &i, request->proxy->home_server->secret,
					       request->proxy->packet->vector);
	if (ret < 0) {
		REDEBUG("Decoding leap:session-key failed");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}
	len = i;
	if (len != 16) {
		REDEBUG("Decoded key length is incorrect, must be 16 bytes");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Encrypt the session key again, using the request data.
	 */
	ret = fr_radius_encode_tunnel_password(p + 17, &len, request->client->secret, request->packet->vector);
	if (ret < 0) {
		REDEBUG("Encoding leap:session-key failed");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}

	fr_pair_value_strsteal(vp, p);

	return RLM_MODULE_UPDATED;
}
#endif

static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request)
{
	rlm_eap_t		*inst = instance;
	VALUE_PAIR		*vp;
	eap_session_t		*eap_session;
	eap_packet_raw_t	*eap_packet;

	/*
	 *	Only build a failure message if something previously rejected the request
	 */
	vp = fr_pair_find_by_num(request->control, 0, PW_POST_AUTH_TYPE, TAG_ANY);

	if (!vp || (vp->vp_integer != PW_POST_AUTH_TYPE_REJECT)) return RLM_MODULE_NOOP;

	if (!fr_pair_find_by_num(request->packet->vps, 0, PW_EAP_MESSAGE, TAG_ANY)) {
		RDEBUG3("Request didn't contain an EAP-Message, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	if (fr_pair_find_by_num(request->reply->vps, 0, PW_EAP_MESSAGE, TAG_ANY)) {
		RDEBUG3("Reply already contained an EAP-Message, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Reconstruct the EAP packet from EAP-Message fragments
	 *	in the request.
	 */
	eap_packet = eap_vp2packet(request, request->packet->vps);
	if (!eap_packet) {
		RERROR("Malformed EAP Message: %s", fr_strerror());
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Retrieve pre-existing eap_session from request
	 *	data.  This will have been added to the request
	 *	data by the state API.
	 */
	eap_session = eap_session_continue(&eap_packet, inst, request);
	if (!eap_session) {
		RDEBUG2("Failed to get eap_session, probably already removed, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	REDEBUG("Request was previously rejected, inserting EAP-Failure");
	eap_fail(eap_session);				/* Compose an EAP failure */
	eap_session_destroy(&eap_session);		/* Free the EAP session, and dissociate it from the request */

	/*
	 *	Make sure there's a message authenticator attribute in the response
	 *	RADIUS protocol code will calculate the correct value later...
	 */
	vp = fr_pair_find_by_num(request->reply->vps, 0, PW_MESSAGE_AUTHENTICATOR, TAG_ANY);
	if (!vp) {
		vp = fr_pair_afrom_num(request->reply, 0, PW_MESSAGE_AUTHENTICATOR);
		fr_pair_value_memsteal(vp, talloc_zero_array(vp, uint8_t, AUTH_VECTOR_LEN));
		fr_pair_add(&(request->reply->vps), vp);
	}

	return RLM_MODULE_UPDATED;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern module_t rlm_eap;
module_t rlm_eap = {
	.magic		= RLM_MODULE_INIT,
	.name		= "eap",
	.inst_size	= sizeof(rlm_eap_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_PROXY
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
