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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000,2001  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

#include "autoconf.h"
#include "rlm_eap.h"
#include "modules.h"

static const char rcsid[] = "$Id$";
static CONF_PARSER module_config[] = {
	{ "default_eap_type", PW_TYPE_STRING_PTR,
	  offsetof(rlm_eap_t, default_eap_type), NULL, "md5" },
	{ "timer_expire", PW_TYPE_INTEGER,
	  offsetof(rlm_eap_t, timer_limit), NULL, "60"},
	
 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

static int eap_init(void)
{
	return 0;
}


/*
 * delete all the allocated space by eap module
 */
static int eap_detach(void *instance)
{
	rlm_eap_t *inst;
	int i;

	inst = (rlm_eap_t *)instance;

	eaplist_free(inst);

	for (i = 0; i < PW_EAP_MAX_TYPES; i++) {
		if (inst->types[i]) eaptype_free(inst->types[i]);
		inst->types[i] = NULL;
	}

#if HAVE_PTHREAD_H
	pthread_mutex_destroy(&(inst->mutex));
#endif

	if (inst->default_eap_type) free(inst->default_eap_type);
	free(inst);

	return 0;
}


/*
 * read the config section and load all the eap authentication types present.
 */
static int eap_instantiate(CONF_SECTION *cs, void **instance)
{
	int		id;
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

	/* Load all the configured EAP-Types */
	num_types = 0;
	for(scs=cf_subsection_find_next(cs, NULL, NULL);
		scs != NULL;
		scs=cf_subsection_find_next(cs, scs, NULL)) {

		char	*auth_type;

		auth_type = cf_section_name1(scs);

		if (!auth_type)  continue;

		id = eaptype_name2id(auth_type);
		if (id < 0) {
			radlog(L_ERR|L_CONS, "rlm_eap: Unknown EAP type %s",
			       auth_type);
			eap_detach(inst);
			return -1;
		}

		if (eaptype_load(&inst->types[id], id, scs) < 0) {
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
	id = eaptype_name2id(inst->default_eap_type);
	if (id < 0) {
		radlog(L_ERR|L_CONS, "rlm_eap: Unknown default EAP type %s",
		       inst->default_eap_type);
		eap_detach(inst);
		return -1;
	}

	if (inst->types[id] == NULL) {
		radlog(L_ERR|L_CONS, "rlm_eap: No such sub-type for default EAP type %s",
		       inst->default_eap_type);
		eap_detach(inst);
		return -1;
	}
	inst->default_eap_id = id;

	/*
	 *	List of sessions are set to NULL by the memset
	 *	of 'inst', above.
	 */

	/* Generate a state key, specific to eap */
	generate_key();

#if HAVE_PTHREAD_H
	pthread_mutex_init(&(inst->mutex), NULL);
#endif
	
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
#if HAVE_PTHREAD_H
	int		locked = FALSE;
#endif

	inst = (rlm_eap_t *) instance;

	/* get the eap packet  to start with */
	eap_packet = eap_attribute(request->packet->vps);
	if (eap_packet == NULL) {
		radlog(L_ERR, "rlm_eap: Malformed EAP Message");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	The EAP internals aren't currently thread-safe,
	 *	so we need a lock against other threads, before we
	 *	process them.
	 */
#if HAVE_PTHREAD_H
	pthread_mutex_lock(&(inst->mutex));
	locked = TRUE;		/* for recursive calls to the module */
#endif

	/*
	 *	Create the eap handler 
	 */
	handler = eap_handler(inst, &eap_packet, request);
	if (handler == NULL) {
#if HAVE_PTHREAD_H
		if (locked) pthread_mutex_unlock(&(inst->mutex));
#endif
		DEBUG2("  rlm_eap: Failed in handler");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	No User-Name, No authentication
	 */
	if (handler->username == NULL) {
		radlog(L_ERR, "rlm_eap: Unknown User, authentication failed");
		eap_fail(request, handler->eap_ds);
		eap_handler_free(&handler);

#if HAVE_PTHREAD_H
		if (locked) pthread_mutex_unlock(&(inst->mutex));
#endif
		DEBUG2("  rlm_eap: No user name");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	Select the appropriate eap_type or default to the
	 *	configured one
	 */
	if (eaptype_select(inst, handler) == EAP_INVALID) {

		eap_fail(request, handler->eap_ds);
		eap_handler_free(&handler);

#if HAVE_PTHREAD_H
		if (locked) pthread_mutex_unlock(&(inst->mutex));
#endif
		DEBUG2("  rlm_eap: Failed in EAP select");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We are done, wrap the EAP-request in RADIUS to send
	 *	with all other required radius attributes
	 */
	rcode = eap_compose(request, handler->eap_ds);

	/*
	 *	Add to the list only if it is EAP-Request, OR if
	 *	it's LEAP, and a response.
	 */
	if ((handler->eap_ds->request->code == PW_EAP_REQUEST) &&
	    (handler->eap_ds->request->type.type >= PW_EAP_MD5)) {
		eaplist_add(inst, handler);

		/*
		 *	LEAP is a little different.  At Stage 4,
		 *	it sends an EAP-Success message, but we still
		 *	need to keep the State attribute & session
		 *	data structure around for the AP Challenge.
		 *
		 *	At stage 6, LEAP sends an EAP-Response, which
		 *	isn't put into the list.
		 */
	} else if ((handler->eap_ds->response->code == PW_EAP_RESPONSE) &&
		   (handler->eap_ds->response->type.type == PW_EAP_LEAP) &&
		   (handler->eap_ds->request->code == PW_EAP_SUCCESS) &&
		   (handler->eap_ds->request->type.type == 0)) {

		eaplist_add(inst, handler);

	} else {
		DEBUG2("  rlm_eap: Freeing handler");
		/* handler is no more required, free it now */
		eap_handler_free(&handler);
	}

	/*
	 *	The next bit doesn't use EAP internals, so we can
	 *	unlock the mutex, and let other EAP request use
	 *	this module.
	 */
#if HAVE_PTHREAD_H
	if (locked) pthread_mutex_unlock(&(inst->mutex));
#endif

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
		vp = pairfind(request->reply->vps, PW_USER_NAME);
		if (!vp) {
			vp = pairmake("User-Name", request->username->strvalue,
				      T_OP_EQ);
			rad_assert(vp != NULL);
			pairadd(&(request->reply->vps), vp);
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

	/*
	 *	We don't do authorization again, once we've seen the
	 *	proxy reply (or the proxied packet)
	 */
	if (request->proxy != NULL)
                return RLM_MODULE_NOOP;

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
	status = eap_start(request);
	switch(status) {
	case EAP_NOOP:
                return RLM_MODULE_NOOP;
	case EAP_FAIL:
		return RLM_MODULE_FAIL;
	case EAP_FOUND:
		return RLM_MODULE_HANDLED;
	case EAP_NOTFOUND:
	default:
		break;
	}
	
	/*
	 * We should have User-Name to proceed further
	 */
	if (request->username == NULL) {
		radlog(L_ERR, "rlm_eap: User-Name is required for EAP authentication");
		return RLM_MODULE_FAIL;
	}

	vp = pairfind(request->config_items, PW_AUTH_TYPE);
	if ((!vp) ||
	    (vp->lvalue != PW_AUTHTYPE_REJECT)) {
		vp = pairmake("Auth-Type", "EAP", T_OP_EQ);
		if (!vp) {
			return RLM_MODULE_FAIL;
		}
		pairadd(&request->config_items, vp);
	}

	return RLM_MODULE_UPDATED;
}

/*
 *	If we're proxying EAP, then there may be magic we need
 *	to do.
 */
static int eap_post_proxy(void *instance, REQUEST *request)
{
	int i, len;
	VALUE_PAIR *vp = request->proxy_reply->vps;

	/*
	 *	There may be more than one Cisco-AVPair.
	 *	Ensure we find the one with the LEAP attribute.
	 */
	for (;;) {
		/*
		 *	Hmm... there's got to be a better way to
		 *	discover codes for vendor attributes.
		 *
		 *	This is vendor Cisco (9), Cisco-AVPair
		 *	attribute (1)
		 */
		vp = pairfind(vp, (9 << 16)  | 1);
		if (!vp) {
			return RLM_MODULE_NOOP;
		}
		
		/*
		 *	If it's "leap:session-key", then stop.
		 *
		 *	The format is VERY specific!
		 */
		if (strncasecmp(vp->strvalue, "leap:session-key=", 17) == 0) {
			break;
		}
	}

	/*
	 *	The format is very specific.
	 */
	if (vp->length != 17 + 34) {
		DEBUG2("  rlm_eap: Cisco-AVPair with leap:session-key has incorrect length %d: Expected %d",
		       vp->length, 17 + 34);
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Decrypt the session key, using the proxy data.
	 */
	i = 34;			/* starts off with 34 octets */
	len = rad_tunnel_pwdecode(vp->strvalue + 17, &i,
				  request->proxysecret,
				  request->proxy->vector);

	/*
	 *	FIXME: Assert that i == 16.
	 */

	/*
	 *	Encrypt the session key again, using the request data.
	 */
	rad_tunnel_pwencode(vp->strvalue + 17, &len,
			    request->secret,
			    request->packet->vector);

	return RLM_MODULE_UPDATED;
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
module_t rlm_eap = {
	"eap",
	RLM_TYPE_THREAD_SAFE,		/* type */
	eap_init,			/* initialization */
	eap_instantiate,		/* instantiation */
	{
		eap_authenticate,	/* authentication */
		eap_authorize,		/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		eap_post_proxy,		/* post-proxy */
		NULL			/* post-auth */
	},
	eap_detach,			/* detach */
	NULL,				/* destroy */
};
