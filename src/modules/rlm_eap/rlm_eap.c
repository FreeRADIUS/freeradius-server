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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "rlm_eap.h"

#include <sys/stat.h>

static const CONF_PARSER module_config[] = {
	{ "default_eap_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_eap_t, default_method_name), "md5" },
	{ "timer_expire", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_eap_t, timer_limit), "60" },
	{ "max_eap_type", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_eap_t, max_eap_type), "52" },
	{ "ignore_unknown_eap_types", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_t, ignore_unknown_types), "no" },
	{ "cisco_accounting_username_bug", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_t, mod_accounting_username_bug), "no" },
	{ "allow_empty_identities", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_eap_t, allow_empty_identities), NULL },
	{ "max_sessions", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_eap_t, max_sessions), "2048" },
	{ "dedup_key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_eap_t, dedup_key), "" },
	CONF_PARSER_TERMINATOR
};

/*
 * delete all the allocated space by eap module
 */
static int mod_detach(void *instance)
{
	rlm_eap_t *inst;

	inst = (rlm_eap_t *)instance;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&(inst->session_mutex));
#endif

	rbtree_free(inst->session_tree);
	inst->session_tree = NULL;
	eaplist_free(inst);

	return 0;
}


/*
 *	Compare two handlers.
 */
static int eap_handler_cmp(void const *a, void const *b)
{
	int rcode;
	eap_handler_t const *one = a;
	eap_handler_t const *two = b;

	if (one->eap_id < two->eap_id) return -1;
	if (one->eap_id > two->eap_id) return +1;

	rcode = memcmp(one->state, two->state, sizeof(one->state));
	if (rcode != 0) return rcode;

	/*
	 *	As of 2.1.8, we don't key off of source IP.  This
	 *	a NAS to send packets load-balanced (or fail-over)
	 *	across multiple intermediate proxies, and still have
	 *	EAP work.
	 */
	if (fr_ipaddr_cmp(&one->src_ipaddr, &two->src_ipaddr) != 0) {
		char src1[64], src2[64];

		fr_ntop(src1, sizeof(src1), &one->src_ipaddr);
		fr_ntop(src2, sizeof(src2), &two->src_ipaddr);
		
		RATE_LIMIT(WARN("EAP packets for one session are arriving from two different upstream"
				"servers (%s and %s).  Has there been a proxy fail-over?",
				src1, src2));
	}

	return 0;
}

/*
 *	Compare two handlers by dedup key
 */
static int CC_HINT(nonnull) dedup_cmp(void const *a, void const *b)
{
	eap_handler_t const *one = a;
	eap_handler_t const *two = b;

	if (!one->dedup && two->dedup) return -1;
	if (one->dedup && !two->dedup) return +1;

	if (!one->dedup && !two->dedup) return 0;

	return strcmp(one->dedup, two->dedup);
}

/*
 * read the config section and load all the eap authentication types present.
 */
static int mod_instantiate(CONF_SECTION *cs, void *instance)
{
	int		i, ret;
	eap_type_t	method;
	int		num_methods;
	CONF_SECTION 	*scs;
	rlm_eap_t	*inst = instance;

	/*
	 *	Create our own random pool.
	 */
	for (i = 0; i < 256; i++) {
		inst->rand_pool.randrsl[i] = fr_rand();
	}
	fr_randinit(&inst->rand_pool, 1);
	inst->rand_pool.randcnt = 0;

	inst->xlat_name = cf_section_name2(cs);
	if (!inst->xlat_name) inst->xlat_name = "EAP";

	if (!dict_valbyname(PW_AUTH_TYPE, 0, inst->xlat_name)) {
		cf_log_err_cs(cs, "Failed to find 'Auth-Type %s' section.  Cannot authenticate users.",
			      inst->xlat_name);
		return -1;
	}

	/* Load all the configured EAP-Types */
	num_methods = 0;
	for(scs = cf_subsection_find_next(cs, NULL, NULL);
	    scs != NULL;
	    scs = cf_subsection_find_next(cs, scs, NULL)) {
		char const *name;

		name = cf_section_name1(scs);
		if (!name)  continue;

		if (!strcmp(name, TLS_CONFIG_SECTION))  continue;

		/*
		 *	Don't break configurations for lazy people who still have LEAP enabled.
		 */
		if (!strcmp(name, "leap")) {
			WARN("rlm_eap (%s): Ignoring EAP method 'leap', because it is no longer supported",
			     inst->xlat_name);
			continue;
		}

		/*
		 *	Easier sometimes than commenting out blocks,
		 *	or deleting blocks.
		 */
		if (!strcmp(name, "disable")) continue;

		method = eap_name2type(name);
		if (method == PW_EAP_INVALID) {
			cf_log_err_cs(cs, "No dictionary definition for EAP method %s", name);
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
		case PW_EAP_FAST:
		case PW_EAP_TLS:
		case PW_EAP_TTLS:
		case PW_EAP_PEAP:
		case PW_EAP_PWD:
		case PW_EAP_TEAP:
			WARN("rlm_eap (%s): Ignoring EAP method %s because we don't have OpenSSL support",
			     inst->xlat_name, name);
			continue;

		default:
			break;
		}
#endif

		/*
		 *	Load the type.
		 */
		ret = eap_module_instantiate(inst, &inst->methods[method], method, scs);

		(void) talloc_get_type_abort(inst->methods[method], eap_module_t);

		if (ret < 0) {
			(void) talloc_steal(inst, inst->methods[method]);
			return -1;
		}

		(void) talloc_steal(inst, inst->methods[method]);
		num_methods++;	/* successfully loaded one more methods */
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
		cf_log_err_cs(cs, "No dictionary definition for default EAP method '%s'",
		       inst->default_method_name);
		return -1;
	}

	if (!inst->methods[method]) {
		cf_log_err_cs(cs, "No such sub-type for default EAP method %s",
		       inst->default_method_name);
		return -1;
	}
	inst->default_method = method; /* save the numerical method */

	/*
	 *	List of sessions are set to NULL by the memset
	 *	of 'inst', above.
	 */

	/*
	 *	Lookup sessions in the tree.  We don't free them in
	 *	the tree, as that's taken care of elsewhere...
	 */
	inst->session_tree = rbtree_create(NULL, eap_handler_cmp, NULL, 0);
	if (!inst->session_tree) {
		ERROR("rlm_eap (%s): Cannot initialize tree", inst->xlat_name);
		return -1;
	}
	fr_link_talloc_ctx_free(inst, inst->session_tree);

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&(inst->session_mutex), NULL) < 0) {
		ERROR("rlm_eap (%s): Failed initializing mutex: %s", inst->xlat_name, fr_syserror(errno));
		return -1;
	}
#endif

	if (!inst->dedup_key || !*inst->dedup_key) {
		return 0;
	}

	inst->dedup_tree = rbtree_create(NULL, dedup_cmp, NULL,  0);
	if (!inst->dedup_tree) {
		ERROR("rlm_eap (%s): Cannot initialize dedup tree", inst->xlat_name);
		return -1;
	}

	return 0;
}


/*
 *	For backwards compatibility.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_eap_t		*inst;
	eap_handler_t		*handler;
	eap_packet_raw_t	*eap_packet;
	eap_rcode_t		status;
	rlm_rcode_t		rcode;

	inst = (rlm_eap_t *) instance;

	if (!fr_pair_find_by_num(request->packet->vps, PW_EAP_MESSAGE, 0, TAG_ANY)) {
		REDEBUG("You set 'Auth-Type = %s' for a request that does "
			"not contain an EAP-Message attribute!", inst->xlat_name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Get the eap packet  to start with
	 */
	eap_packet = eap_vp2packet(request, request->packet->vps);
	if (!eap_packet) {
		RERROR("Malformed EAP Message: %s", fr_strerror());
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Create the eap handler.  The eap_packet will end up being
	 *	"swallowed" into the handler, so we can't access it after
	 *	this call.
	 */
	handler = eap_handler(inst, &eap_packet, request);
	if (!handler) {
		RDEBUG2("Failed in handler");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Select the appropriate method or default to the
	 *	configured one
	 */
	status = eap_method_select(inst, handler);

	/*
	 *	If it failed, die.
	 */
	if (status == EAP_INVALID) {
		eap_fail(handler);
		talloc_free(handler);
		RDEBUG2("Failed in EAP select");
		return RLM_MODULE_INVALID;
	}

#ifdef WITH_PROXY
	/*
	 *	If we're doing horrible tunneling work, remember it.
	 */
	if ((request->options & RAD_REQUEST_OPTION_PROXY_EAP) != 0) {
		RDEBUG2("No EAP proxy set.  Not composing EAP");
		/*
		 *	Add the handle to the proxied list, so that we
		 *	can retrieve it in the post-proxy stage, and
		 *	send a response.
		 */
		handler->inst_holder = inst;
		status = request_data_add(request, inst, REQUEST_DATA_EAP_HANDLER, handler, true);

		rad_assert(status == 0);
		return RLM_MODULE_HANDLED;
	}
#endif

#ifdef WITH_PROXY
	/*
	 *	Maybe the request was marked to be proxied.  If so,
	 *	proxy it.
	 */
	if (request->proxy != NULL) {
		VALUE_PAIR *vp = NULL;

		rad_assert(!request->proxy_reply);

		/*
		 *	Add the handle to the proxied list, so that we
		 *	can retrieve it in the post-proxy stage, and
		 *	send a response.
		 */
		handler->inst_holder = inst;

		status = request_data_add(request, inst, REQUEST_DATA_EAP_HANDLER, handler, true);

		rad_assert(status == 0);

		/*
		 *	Some simple sanity checks.  These should really
		 *	be handled by the radius library...
		 */
		vp = fr_pair_find_by_num(request->proxy->vps, PW_EAP_MESSAGE, 0, TAG_ANY);
		if (vp) {
			vp = fr_pair_find_by_num(request->proxy->vps, PW_MESSAGE_AUTHENTICATOR, 0, TAG_ANY);
			if (!vp) {
				fr_pair_make(request->proxy,
					 &request->proxy->vps,
					 "Message-Authenticator",
					 NULL, T_OP_EQ);
			}
		}

		/*
		 *	Delete the "proxied to" attribute, as it's
		 *	set to 127.0.0.1 for tunneled requests, and
		 *	we don't want to tell the world that...
		 */
		fr_pair_delete_by_num(&request->proxy->vps, PW_FREERADIUS_PROXIED_TO, VENDORPEC_FREERADIUS, TAG_ANY);

		RWDEBUG2("Tunneled session will be proxied.  Not doing EAP");
		return RLM_MODULE_HANDLED;
	}
#endif

	/*
	 *	We are done, wrap the EAP-request in RADIUS to send
	 *	with all other required radius attributes
	 */
	rcode = eap_compose(handler);

	/*
	 *	Add to the list only if it is EAP-Request.
	 */
	if ((handler->eap_ds->request->code == PW_EAP_REQUEST) &&
	    (handler->eap_ds->request->type.num >= PW_EAP_MD5)) {
		/*
		 *	Return FAIL if we can't remember the handler.
		 *	This is actually disallowed by the
		 *	specification, as unexpected FAILs could have
		 *	been forged.  However, we want to signal to
		 *	everyone else involved that we are
		 *	intentionally failing the session, as opposed
		 *	to accidentally failing it.
		 */
		if (!eaplist_add(inst, handler)) {
			RDEBUG("Failed adding handler to the list");
			eap_fail(handler);
			talloc_free(handler);
			return RLM_MODULE_FAIL;
		}

	} else {
		/*
		 *	Enable the cached entry on success.
		 */
		if (handler->eap_ds->request->code == PW_EAP_SUCCESS) {
			VALUE_PAIR *vp;

			vp = fr_pair_find_by_num(request->state, PW_TLS_CACHE_FILENAME, 0, TAG_ANY);
			if (vp) (void) chmod(vp->vp_strvalue, S_IRUSR | S_IWUSR);
		}

		/*
		 *	Disable the cached entry on failure.
		 */
		if (handler->eap_ds->request->code == PW_EAP_FAILURE) {
			VALUE_PAIR *vp;

			vp = fr_pair_find_by_num(request->state, PW_TLS_CACHE_FILENAME, 0, TAG_ANY);
			if (vp) (void) unlink(vp->vp_strvalue);
		}

		RDEBUG2("Freeing handler");
		/* handler is not required any more, free it now */
		talloc_free(handler);
	}

	/*
	 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
	 *	says that we MUST include a User-Name attribute in the
	 *	Access-Accept.
	 */
	if ((request->reply->code == PW_CODE_ACCESS_ACCEPT) &&
	    request->username) {
		VALUE_PAIR *vp;

		/*
		 *	Doesn't exist, add it in.
		 */
		vp = fr_pair_find_by_num(request->reply->vps, PW_USER_NAME, 0, TAG_ANY);
		if (!vp) {
			vp = request->username;
			if (vp->da->attr != PW_USER_NAME) {
				vp = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
			}
			if (vp) {
				vp = fr_pair_copy(request->reply, vp);
				fr_pair_add(&request->reply->vps, vp);
			}
		}

		/*
		 *	Cisco AP1230 has a bug and needs a zero
		 *	terminated string in Access-Accept.  This
		 *	means it requires 2 trailing zeros.  One to
		 *	send in the RADIUS packet, and the other to
		 *	convince the rest of the server that
		 *	vp->vp_strvalue is still a NUL-terminated C
		 *	string.
		 */
		if (vp && inst->mod_accounting_username_bug) {
			char const *old = vp->vp_strvalue;
			char *new;

			vp->vp_length++; /* account for an additional zero */

			new = talloc_array(vp, char, vp->vp_length + 1);

			memcpy(new, old, vp->vp_length);
			new[vp->length] = '\0';
			vp->vp_strvalue = new;

			rad_const_free(old);
			VERIFY_VP(vp);
		}
	}

	return rcode;
}

/*
 * EAP authorization DEPENDS on other rlm authorizations,
 * to check for user existence & get their configured values.
 * It Handles EAP-START Messages, User-Name initilization.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
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
	 *	each EAP sub-module to look for handler->request->username,
	 *	and to get excited if it doesn't appear.
	 */
	vp = fr_pair_find_by_num(request->config, PW_AUTH_TYPE, 0, TAG_ANY);
	if ((!vp) || (vp->vp_integer != PW_AUTH_TYPE_REJECT)) {
		vp = pair_make_config("Auth-Type", inst->xlat_name, T_OP_EQ);
		if (!vp) {
			RDEBUG2("Failed to create Auth-Type %s: %s\n",
				inst->xlat_name, fr_strerror());
			return RLM_MODULE_FAIL;
		}
	} else {
		RWDEBUG2("Auth-Type already set.  Not setting to EAP");
	}

	if (status == EAP_OK) return RLM_MODULE_OK;

	return RLM_MODULE_UPDATED;
}


#ifdef WITH_PROXY
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(UNUSED void *instance, REQUEST *request)
{
	VALUE_PAIR	*vp;
	vp_cursor_t	cursor;
	size_t		length, eap_length = 0;

	vp = fr_pair_find_by_num(request->packet->vps, PW_EAP_MESSAGE, 0, TAG_ANY);
	if (!vp) return RLM_MODULE_NOOP;

	if (vp->vp_length < 4) {
		RDEBUG("EAP packet is too small");

	add_error_cause:
		/*
		 *	Invalid EAP packet (ignored)
		 */
		pair_make_reply("Error-Cause", "202", T_OP_EQ);
		return RLM_MODULE_REJECT;
	}

	/*
	 *	The length field has to match the length of all EAP-Messages.
	 */
	length = (vp->vp_octets[2] << 8) | vp->vp_octets[3];

	/*
	 *	Get length of all EAP-Message attributes
	 */
	fr_cursor_init(&cursor, &request->packet->vps);
	while ((vp = fr_cursor_next_by_num(&cursor, PW_EAP_MESSAGE, 0, TAG_ANY))) {
		eap_length += vp->vp_length;
	}

	if (length != eap_length) {
		RDEBUG("EAP length (%zu) does not match attribute length (%zu)", eap_length, length);
		goto add_error_cause;
	}

	return RLM_MODULE_NOOP;
}

/*
 *	If we're proxying EAP, then there may be magic we need
 *	to do.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *inst, REQUEST *request)
{
	size_t		i;
	size_t		len;
	ssize_t		ret;
	char		*p;
	VALUE_PAIR	*vp;
	eap_handler_t	*handler;
	vp_cursor_t	cursor;

	/*
	 *	If there was a handler associated with this request,
	 *	then it's a tunneled request which was proxied...
	 */
	handler = request_data_get(request, inst, REQUEST_DATA_EAP_HANDLER);
	if (handler != NULL) {
		rlm_rcode_t rcode;
		eap_tunnel_data_t *data;

		/*
		 *	Grab the tunnel callbacks from the request.
		 */
		data = (eap_tunnel_data_t *) request_data_get(request,
							      request->proxy,
							      REQUEST_DATA_EAP_TUNNEL_CALLBACK);
		if (!data) {
			RERROR("Failed to retrieve callback for tunneled session!");
			talloc_free(handler);
			return RLM_MODULE_FAIL;
		}

		/*
		 *	Do the callback...
		 */
		RDEBUG2("Doing post-proxy callback");
		rcode = data->callback(handler, data->tls_session);
		talloc_free(data);
		if (rcode == 0) {
			RDEBUG2("Failed in post-proxy callback");
			eap_fail(handler);
			talloc_free(handler);
			return RLM_MODULE_REJECT;
		}

		/*
		 *	We are done, wrap the EAP-request in RADIUS to send
		 *	with all other required radius attributes
		 */
		eap_compose(handler);

		/*
		 *	Add to the list only if it is EAP-Request.
		 */
		if ((handler->eap_ds->request->code == PW_EAP_REQUEST) &&
		    (handler->eap_ds->request->type.num >= PW_EAP_MD5)) {
			if (!eaplist_add(inst, handler)) {
				eap_fail(handler);
				talloc_free(handler);
				return RLM_MODULE_FAIL;
			}

		} else {
			RDEBUG2("Freeing handler");
			/* handler is not required any more, free it now */
			talloc_free(handler);
		}

		/*
		 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
		 *	says that we MUST include a User-Name attribute in the
		 *	Access-Accept.
		 */
		if ((request->reply->code == PW_CODE_ACCESS_ACCEPT) &&
		    request->username) {
			/*
			 *	Doesn't exist, add it in.
			 */
			vp = fr_pair_find_by_num(request->reply->vps, PW_USER_NAME, 0, TAG_ANY);
			if (!vp) {
				pair_make_reply("User-Name",
					       request->username->vp_strvalue,
					       T_OP_EQ);
			}
		}

		return RLM_MODULE_OK;
	} else {
		RDEBUG2("No pre-existing handler found");
	}

	/*
	 *	This is allowed.
	 */
	if (!request->proxy_reply) return RLM_MODULE_NOOP;

	/*
	 *	There may be more than one Cisco-AVPair.
	 *	Ensure we find the one with the LEAP attribute.
	 */
	fr_cursor_init(&cursor, &request->proxy_reply->vps);
	for (;;) {
		/*
		 *	Hmm... there's got to be a better way to
		 *	discover codes for vendor attributes.
		 *
		 *	This is vendor Cisco (9), Cisco-AVPair
		 *	attribute (1)
		 */
		vp = fr_cursor_next_by_num(&cursor, 1, 9, TAG_ANY);
		if (!vp) {
			return RLM_MODULE_NOOP;
		}

		/*
		 *	If it's "leap:session-key", then stop.
		 *
		 *	The format is VERY specific!
		 */
		if (strncasecmp(vp->vp_strvalue, "leap:session-key=", 17) == 0) {
			break;
		}
	}

	/*
	 *	The format is very specific.
	 */
	if (vp->vp_length != (17 + 34)) {
		RDEBUG2("Cisco-AVPair with leap:session-key has incorrect length %zu: Expected %d",
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
	ret = rad_tunnel_pwdecode((uint8_t *)p + 17, &i, request->home_server->secret, request->proxy->vector);
	if (ret < 0) {
		REDEBUG("Decoding leap:session-key failed");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}
	len = i;

	if (i != 16) {
		REDEBUG("Decoded key length is incorrect, must be 16 bytes");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Encrypt the session key again, using the request data.
	 */
	ret = rad_tunnel_pwencode(p + 17, &len, request->client->secret, request->packet->vector);
	if (ret < 0) {
		REDEBUG("Decoding leap:session-key failed");
		talloc_free(p);
		return RLM_MODULE_FAIL;
	}

	fr_pair_value_strsteal(vp, p);

	return RLM_MODULE_UPDATED;
}
#endif

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_eap_t	*inst = instance;
	VALUE_PAIR	*vp;
	eap_handler_t	*handler;
	eap_packet_raw_t	*eap_packet;

	/*
	 * Only build a failure message if something previously rejected the request
	 */
	vp = fr_pair_find_by_num(request->config, PW_POST_AUTH_TYPE, 0, TAG_ANY);

	if (!vp || (vp->vp_integer != PW_POST_AUTH_TYPE_REJECT)) return RLM_MODULE_NOOP;

	if (!fr_pair_find_by_num(request->packet->vps, PW_EAP_MESSAGE, 0, TAG_ANY)) {
		RDEBUG3("Request didn't contain an EAP-Message, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	if (fr_pair_find_by_num(request->reply->vps, PW_EAP_MESSAGE, 0, TAG_ANY)) {
		RDEBUG3("Reply already contained an EAP-Message, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	eap_packet = eap_vp2packet(request, request->packet->vps);
	if (!eap_packet) {
		RERROR("Malformed EAP Message: %s", fr_strerror());
		return RLM_MODULE_FAIL;
	}

	handler = eap_handler(inst, &eap_packet, request);
	if (!handler) {
		RDEBUG2("Failed to get handler, probably already removed, not inserting EAP-Failure");
		return RLM_MODULE_NOOP;
	}

	RDEBUG2("Request was previously rejected, inserting EAP-Failure");
	eap_fail(handler);
	talloc_free(handler);

	/*
	 * Make sure there's a message authenticator attribute in the response
	 * RADIUS protocol code will calculate the correct value later...
	 */
	vp = fr_pair_find_by_num(request->reply->vps, PW_MESSAGE_AUTHENTICATOR, 0, TAG_ANY);
	if (!vp) {
		pair_make_reply("Message-Authenticator", "0x00", T_OP_EQ);
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
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
