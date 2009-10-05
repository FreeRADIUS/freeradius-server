/*
 * rlm_eap.c  contains handles that are called from modules.
 *
 * Version:     $Id$
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
 * Copyright 2000-2003,2006  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "rlm_eap.h"

static const CONF_PARSER module_config[] = {
	{ "default_eap_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_t, default_eap_type_name), NULL, "md5" },
	{ "timer_expire", PW_TYPE_INTEGER,
	  offsetof(rlm_eap_t, timer_limit), NULL, "60"},
	{ "ignore_unknown_eap_types", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_t, ignore_unknown_eap_types), NULL, "no" },
	{ "cisco_accounting_username_bug", PW_TYPE_BOOLEAN,
	  offsetof(rlm_eap_t, cisco_accounting_username_bug), NULL, "no" },
	{ "max_sessions", PW_TYPE_INTEGER,
	  offsetof(rlm_eap_t, max_sessions), NULL, "2048"},

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

/*
 * delete all the allocated space by eap module
 */
static int eap_detach(void *instance)
{
	rlm_eap_t *inst;
	int i;

	inst = (rlm_eap_t *)instance;

	rbtree_free(inst->session_tree);
	inst->session_tree = NULL;
	eaplist_free(inst);

	for (i = 0; i < PW_EAP_MAX_TYPES; i++) {
		if (inst->types[i]) eaptype_free(inst->types[i]);
		inst->types[i] = NULL;
	}

	pthread_mutex_destroy(&(inst->session_mutex));

	free(inst);

	return 0;
}


/*
 *	Compare two handlers.
 */
static int eap_handler_cmp(const void *a, const void *b)
{
	int rcode;
	const EAP_HANDLER *one = a;
	const EAP_HANDLER *two = b;

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
		DEBUG("WARNING: EAP packets are arriving from two different upstream servers.  Has there been a proxy fail-over?");
	}

	return 0;
}


/*
 * read the config section and load all the eap authentication types present.
 */
static int eap_instantiate(CONF_SECTION *cs, void **instance)
{
	int		i, eap_type;
	int		num_types;
	CONF_SECTION 	*scs;
	rlm_eap_t	*inst;

	inst = (rlm_eap_t *) malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));
	if (cf_section_parse(cs, inst, module_config) < 0) {
		eap_detach(inst);
		return -1;
	}

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

	/* Load all the configured EAP-Types */
	num_types = 0;
	for(scs=cf_subsection_find_next(cs, NULL, NULL);
		scs != NULL;
		scs=cf_subsection_find_next(cs, scs, NULL)) {

		const char	*auth_type;

		auth_type = cf_section_name1(scs);

		if (!auth_type)  continue;

		eap_type = eaptype_name2type(auth_type);
		if (eap_type < 0) {
			radlog(L_ERR, "rlm_eap: Unknown EAP type %s",
			       auth_type);
			eap_detach(inst);
			return -1;
		}

#ifndef HAVE_OPENSSL_SSL_H
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
		if ((eap_type == PW_EAP_TLS) ||
		    (eap_type == PW_EAP_TTLS) ||
		    (eap_type == PW_EAP_PEAP)) {
			DEBUG2("Ignoring EAP-Type/%s because we do not have OpenSSL support.", auth_type);
			continue;
		}
#endif

		/*
		 *	If we're asked to load TTLS or PEAP, ensure
		 *	that we've first loaded TLS.
		 */
		if (((eap_type == PW_EAP_TTLS) ||
		     (eap_type == PW_EAP_PEAP)) &&
		    (inst->types[PW_EAP_TLS] == NULL)) {
			radlog(L_ERR, "rlm_eap: Unable to load EAP-Type/%s, as EAP-Type/TLS is required first.",
			       auth_type);
			return -1;
		}

		/*
		 *	Load the type.
		 */
		if (eaptype_load(&inst->types[eap_type], eap_type, scs) < 0) {
			eap_detach(inst);
			return -1;
		}

		num_types++;	/* successfully loaded one more types */
	}

	if (num_types == 0) {
		radlog(L_ERR|L_CONS, "rlm_eap: No EAP type configured, module cannot do anything.");
		eap_detach(inst);
		return -1;
	}

	/*
	 *	Ensure that the default EAP type is loaded.
	 */
	eap_type = eaptype_name2type(inst->default_eap_type_name);
	if (eap_type < 0) {
		radlog(L_ERR|L_CONS, "rlm_eap: Unknown default EAP type %s",
		       inst->default_eap_type_name);
		eap_detach(inst);
		return -1;
	}

	if (inst->types[eap_type] == NULL) {
		radlog(L_ERR|L_CONS, "rlm_eap: No such sub-type for default EAP type %s",
		       inst->default_eap_type_name);
		eap_detach(inst);
		return -1;
	}
	inst->default_eap_type = eap_type; /* save the numerical type */

	/*
	 *	List of sessions are set to NULL by the memset
	 *	of 'inst', above.
	 */

	/*
	 *	Lookup sessions in the tree.  We don't free them in
	 *	the tree, as that's taken care of elsewhere...
	 */
	inst->session_tree = rbtree_create(eap_handler_cmp, NULL, 0);
	if (!inst->session_tree) {
		radlog(L_ERR|L_CONS, "rlm_eap: Cannot initialize tree");
		eap_detach(inst);
		return -1;
	}

	pthread_mutex_init(&(inst->session_mutex), NULL);

	*instance = inst;
	return 0;
}


/*
 *	For backwards compatibility.
 */
static int eap_authenticate(void *instance, REQUEST *request)
{
	rlm_eap_t	*inst;
	EAP_HANDLER	*handler;
	eap_packet_t	*eap_packet;
	int		rcode;

	inst = (rlm_eap_t *) instance;

	/*
	 *	Get the eap packet  to start with
	 */
	eap_packet = eap_vp2packet(request->packet->vps);
	if (eap_packet == NULL) {
		radlog_request(L_ERR, 0, request, "Malformed EAP Message");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Create the eap handler.  The eap_packet will end up being
	 *	"swallowed" into the handler, so we can't access it after
	 *	this call.
	 */
	handler = eap_handler(inst, &eap_packet, request);
	if (handler == NULL) {
		RDEBUG2("Failed in handler");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Select the appropriate eap_type or default to the
	 *	configured one
	 */
	rcode = eaptype_select(inst, handler);

	/*
	 *	If it failed, die.
	 */
	if (rcode == EAP_INVALID) {
		eap_fail(handler);
		eap_handler_free(handler);
		RDEBUG2("Failed in EAP select");
		return RLM_MODULE_INVALID;
	}

#ifdef WITH_PROXY
	/*
	 *	If we're doing horrible tunneling work, remember it.
	 */
	if ((request->options & RAD_REQUEST_OPTION_PROXY_EAP) != 0) {
		RDEBUG2("  Not-EAP proxy set.  Not composing EAP");
		/*
		 *	Add the handle to the proxied list, so that we
		 *	can retrieve it in the post-proxy stage, and
		 *	send a response.
		 */
		rcode = request_data_add(request,
					 inst, REQUEST_DATA_EAP_HANDLER,
					 handler,
					 (void *) eap_handler_free);
		rad_assert(rcode == 0);

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

		rad_assert(request->proxy_reply == NULL);

		/*
		 *	Add the handle to the proxied list, so that we
		 *	can retrieve it in the post-proxy stage, and
		 *	send a response.
		 */
		rcode = request_data_add(request,
					 inst, REQUEST_DATA_EAP_HANDLER,
					 handler,
					 (void *) eap_handler_free);
		rad_assert(rcode == 0);

		/*
		 *	Some simple sanity checks.  These should really
		 *	be handled by the radius library...
		 */
		vp = pairfind(request->proxy->vps, PW_EAP_MESSAGE, 0);
		if (vp) {
			vp = pairfind(request->proxy->vps, PW_MESSAGE_AUTHENTICATOR, 0);
			if (!vp) {
				vp = pairmake("Message-Authenticator",
					      "0x00", T_OP_EQ);
				rad_assert(vp != NULL);
				pairadd(&(request->proxy->vps), vp);
			}
		}

		/*
		 *	Delete the "proxied to" attribute, as it's
		 *	set to 127.0.0.1 for tunneled requests, and
		 *	we don't want to tell the world that...
		 */
		pairdelete(&request->proxy->vps, PW_FREERADIUS_PROXIED_TO, VENDORPEC_FREERADIUS);

		RDEBUG2("  Tunneled session will be proxied.  Not doing EAP.");
		return RLM_MODULE_HANDLED;
	}
#endif

	/*
	 *	We are done, wrap the EAP-request in RADIUS to send
	 *	with all other required radius attributes
	 */
	rcode = eap_compose(handler);

	/*
	 *	Add to the list only if it is EAP-Request, OR if
	 *	it's LEAP, and a response.
	 */
	if (((handler->eap_ds->request->code == PW_EAP_REQUEST) &&
	    (handler->eap_ds->request->type.type >= PW_EAP_MD5)) ||

		/*
		 *	LEAP is a little different.  At Stage 4,
		 *	it sends an EAP-Success message, but we still
		 *	need to keep the State attribute & session
		 *	data structure around for the AP Challenge.
		 *
		 *	At stage 6, LEAP sends an EAP-Response, which
		 *	isn't put into the list.
		 */
	    ((handler->eap_ds->response->code == PW_EAP_RESPONSE) &&
	     (handler->eap_ds->response->type.type == PW_EAP_LEAP) &&
	     (handler->eap_ds->request->code == PW_EAP_SUCCESS) &&
	     (handler->eap_ds->request->type.type == 0))) {

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
			eap_fail(handler);
			eap_handler_free(handler);
			return RLM_MODULE_FAIL;
		}

	} else {
		RDEBUG2("Freeing handler");
		/* handler is not required any more, free it now */
		eap_handler_free(handler);
	}

	/*
	 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
	 *	says that we MUST include a User-Name attribute in the
	 *	Access-Accept.
	 */
	if ((request->reply->code == PW_AUTHENTICATION_ACK) &&
	    request->username) {
		VALUE_PAIR *vp;

		/*
		 *	Doesn't exist, add it in.
		 */
		vp = pairfind(request->reply->vps, PW_USER_NAME, 0);
		if (!vp) {
			vp = pairmake("User-Name", "",
				      T_OP_EQ);
			strlcpy(vp->vp_strvalue, request->username->vp_strvalue,
				sizeof(vp->vp_strvalue));
			vp->length = request->username->length;
			rad_assert(vp != NULL);
			pairadd(&(request->reply->vps), vp);
		}

		/*
		 *	Cisco AP1230 has a bug and needs a zero
		 *	terminated string in Access-Accept.
		 */
		if ((inst->cisco_accounting_username_bug) &&
		    (vp->length < (int) sizeof(vp->vp_strvalue))) {
			vp->vp_strvalue[vp->length] = '\0';
			vp->length++;
		}
	}

	return rcode;
}

/*
 * EAP authorization DEPENDS on other rlm authorizations,
 * to check for user existance & get their configured values.
 * It Handles EAP-START Messages, User-Name initilization.
 */
static int eap_authorize(void *instance, REQUEST *request)
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
	switch(status) {
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

	vp = pairfind(request->config_items, PW_AUTH_TYPE, 0);
	if ((!vp) ||
	    (vp->vp_integer != PW_AUTHTYPE_REJECT)) {
		vp = pairmake("Auth-Type", inst->xlat_name, T_OP_EQ);
		if (!vp) {
			RDEBUG2("Failed to create Auth-Type %s: %s\n",
				inst->xlat_name, fr_strerror());
			return RLM_MODULE_FAIL;
		}
		pairadd(&request->config_items, vp);
	}

	if (status == EAP_OK) return RLM_MODULE_OK;

	return RLM_MODULE_UPDATED;
}


#ifdef WITH_PROXY
/*
 *	If we're proxying EAP, then there may be magic we need
 *	to do.
 */
static int eap_post_proxy(void *inst, REQUEST *request)
{
	size_t		i;
	size_t		len;
	VALUE_PAIR	*vp;
	EAP_HANDLER	*handler;

	/*
	 *	Just in case the admin lists EAP in post-proxy-type Fail.
	 */
	if (!request->proxy_reply) return RLM_MODULE_NOOP;

	/*
	 *	If there was a handler associated with this request,
	 *	then it's a tunneled request which was proxied...
	 */
	handler = request_data_get(request, inst, REQUEST_DATA_EAP_HANDLER);
	if (handler != NULL) {
		int		rcode;
		eap_tunnel_data_t *data;

		/*
		 *	Grab the tunnel callbacks from the request.
		 */
		data = (eap_tunnel_data_t *) request_data_get(request,
							      request->proxy,
							      REQUEST_DATA_EAP_TUNNEL_CALLBACK);
		if (!data) {
			radlog_request(L_ERR, 0, request, "Failed to retrieve callback for tunneled session!");
			eap_handler_free(handler);
			return RLM_MODULE_FAIL;
		}

		/*
		 *	Do the callback...
		 */
		RDEBUG2("Doing post-proxy callback");
		rcode = data->callback(handler, data->tls_session);
		free(data);
		if (rcode == 0) {
			RDEBUG2("Failed in post-proxy callback");
			eap_fail(handler);
			eap_handler_free(handler);
			return RLM_MODULE_REJECT;
		}

		/*
		 *	We are done, wrap the EAP-request in RADIUS to send
		 *	with all other required radius attributes
		 */
		eap_compose(handler);

		/*
		 *	Add to the list only if it is EAP-Request, OR if
		 *	it's LEAP, and a response.
		 */
		if ((handler->eap_ds->request->code == PW_EAP_REQUEST) &&
		    (handler->eap_ds->request->type.type >= PW_EAP_MD5)) {
			if (!eaplist_add(inst, handler)) {
				eap_fail(handler);
				eap_handler_free(handler);
				return RLM_MODULE_FAIL;
			}
			
		} else {	/* couldn't have been LEAP, there's no tunnel */
			RDEBUG2("Freeing handler");
			/* handler is not required any more, free it now */
			eap_handler_free(handler);
		}

		/*
		 *	If it's an Access-Accept, RFC 2869, Section 2.3.1
		 *	says that we MUST include a User-Name attribute in the
		 *	Access-Accept.
		 */
		if ((request->reply->code == PW_AUTHENTICATION_ACK) &&
		    request->username) {
			/*
			 *	Doesn't exist, add it in.
			 */
			vp = pairfind(request->reply->vps, PW_USER_NAME, 0);
			if (!vp) {
				vp = pairmake("User-Name", request->username->vp_strvalue,
					      T_OP_EQ);
				rad_assert(vp != NULL);
				pairadd(&(request->reply->vps), vp);
			}
		}

		return RLM_MODULE_OK;
	} else {
		RDEBUG2("No pre-existing handler found");
	}

	/*
	 *	There may be more than one Cisco-AVPair.
	 *	Ensure we find the one with the LEAP attribute.
	 */
	vp = request->proxy_reply->vps;
	for (;;) {
		/*
		 *	Hmm... there's got to be a better way to
		 *	discover codes for vendor attributes.
		 *
		 *	This is vendor Cisco (9), Cisco-AVPair
		 *	attribute (1)
		 */
		vp = pairfind(vp, 1, 9);
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

		/*
		 *	Not this AV-pair.  Go to the next one.
		 */
		vp = vp->next;
	}

	/*
	 *	The format is very specific.
	 */
	if (vp->length != 17 + 34) {
		RDEBUG2("Cisco-AVPair with leap:session-key has incorrect length %d: Expected %d",
		       vp->length, 17 + 34);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Decrypt the session key, using the proxy data.
	 */
	i = 34;			/* starts off with 34 octets */
	len = rad_tunnel_pwdecode(vp->vp_octets + 17, &i,
				  request->home_server->secret,
				  request->proxy->vector);

	/*
	 *	FIXME: Assert that i == 16.
	 */

	/*
	 *	Encrypt the session key again, using the request data.
	 */
	rad_tunnel_pwencode(vp->vp_strvalue + 17, &len,
			    request->client->secret,
			    request->packet->vector);

	return RLM_MODULE_UPDATED;
}
#endif

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
module_t rlm_eap = {
	RLM_MODULE_INIT,
	"eap",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	eap_instantiate,		/* instantiation */
	eap_detach,			/* detach */
	{
		eap_authenticate,	/* authentication */
		eap_authorize,		/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
#ifdef WITH_PROXY
		eap_post_proxy,		/* post-proxy */
#else
		NULL,
#endif
		NULL			/* post-auth */
	},
};
