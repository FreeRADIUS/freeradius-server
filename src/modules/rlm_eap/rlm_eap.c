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

static CONF_PARSER module_config[] = {
	{ "default_eap_type", PW_TYPE_STRING_PTR, offsetof(EAP_CONF, default_eap_type), NULL, "md5" },
	{ "timer_expire", PW_TYPE_INTEGER, offsetof(EAP_CONF, timer_limit), NULL, "60"},

 	{ NULL, -1, 0, NULL, NULL }           /* end the list */
};

static int eap_init(void)
{
	return 0;
}


/*
 * read the config section and load all the eap authentication types present.
 */
static int eap_instantiate(CONF_SECTION *cs, void **instance)
{
	char		*auth_type;
	CONF_SECTION 	*scs;
	EAP_TYPES	*types;
	EAP_CONF	*conf;
	rlm_eap_t	**eap_stuff;
	
	eap_stuff = (rlm_eap_t **)instance;
	types	 = NULL;
	conf	 = NULL;
	auth_type = NULL;

	conf = (EAP_CONF *)malloc(sizeof(EAP_CONF));
	if (conf == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return -1;
	}
	if (cf_section_parse(cs, conf, module_config) < 0) {
		free(conf);
		return -1;
	}

	/* Load all the configured EAP-Types */
	for(scs=cf_subsection_find_next(cs, NULL, NULL);
		scs != NULL;
		scs=cf_subsection_find_next(cs, scs, NULL)) {

		auth_type = cf_section_name1(scs);

		if (!auth_type)  continue;

		if (eaptype_load(&types, auth_type, scs) < 0) {
			free(conf);
			return -1;
		}
	}

	if (!types) {
		free(conf->default_eap_type);
		conf->default_eap_type = NULL;
		free(conf);
		conf = NULL;
		return -1;
	}

	*eap_stuff = (rlm_eap_t *)malloc(sizeof(rlm_eap_t));
	if (*eap_stuff) {
		(*eap_stuff)->typelist = types;
		(*eap_stuff)->echolist = NULL;
		(*eap_stuff)->conf = conf;
	}  else {
		radlog(L_ERR, "rlm_eap: out of memory");
		eaptype_freelist(&types);
		free(conf->default_eap_type);
		conf->default_eap_type = NULL;
		free(conf);
		conf = NULL;
		return -1;
	}

	/* Generate a state key, specific to eap */
	generate_key();
	return 0;
}

/*
 * delete all the allocated space by eap module
 */
static int eap_detach(void *instance)
{
	rlm_eap_t *t;
	t = (rlm_eap_t *)instance;

	eaplist_free(&(t->echolist));
	eaptype_freelist(&(t->typelist));

	free(t->conf->default_eap_type);
	free(t->conf);

	free(t);
	t = NULL;

	return 0;
}

/*
 * Assumption: Any one of the Authorization module should
 * 	get the configured password for any valid user.
 *  	If not, Authentication fails to validate.
 *
 * All EAP types will be handled in their respective sub modules.
 *
 * To Handle EAP-response, we keep track of the EAP-request we send.
 * When Success or Failure or when timed out, we delete them.
 */
static int eap_authenticate(void *instance, REQUEST *request)
{
	EAP_HANDLER	*handler;
	rlm_eap_t	*eap_stuff;
	eap_packet_t	*eap_packet;
	int		status;

	eap_stuff = (rlm_eap_t *)instance;

	/* 
	 * Always, clean the list first as it is not timer based
	 * FIXME: Appropriate cleaning mechanism.
	 */
	eaplist_clean(&(eap_stuff->echolist), (time_t)eap_stuff->conf->timer_limit);

	/*
	 * Incase if EAP is not configured in autz block
	 * or eap_authorize is not invoked
	 */
	status = eap_start(request);
	switch(status) {
	case EAP_NOOP:
		return RLM_MODULE_NOOP;
	case EAP_FAIL:
		return RLM_MODULE_FAIL;
	case EAP_FOUND:
		return RLM_MODULE_OK;
	case EAP_NOTFOUND:
	default:
		break;
	}

	/* get the eap packet  to start with */
	eap_packet = eap_attribute(request->packet->vps);
	if (eap_packet == NULL) {
		radlog(L_ERR, "rlm_eap: Malformed EAP Message");
		return RLM_MODULE_FAIL;
	}

	/*
	 * create the eap handler 
	 */
	handler = eap_handler(&(eap_stuff->echolist), &eap_packet, request);
	if (handler == NULL) {
		return RLM_MODULE_INVALID;
	}

	/*
	 * No User-Name, No authentication
	 */
	if (handler->username == NULL) {
		radlog(L_ERR, "rlm_eap: Unknown User, authentication failed");
		eap_fail(request, handler->eap_ds->request);
		eap_handler_free(&handler);
		return RLM_MODULE_REJECT;
	}

	/*
	 * Select the appropriate eap_type or default to the configured one
	 */
	if (eaptype_select(eap_stuff->typelist, handler,
		eap_stuff->conf->default_eap_type) == EAP_INVALID) {

		eap_fail(request, handler->eap_ds->request);
		eap_handler_free(&handler);
		return RLM_MODULE_INVALID;
	}

	/*
	 * We are done, wrap the EAP-request in RADIUS to send
	 * with all other required radius attributes
	 */
	eap_compose(request, handler->eap_ds->request);

	/*
	 * Add to the list only if it is EAP-Request,
	 * OR if it's LEAP, and a response.
	 */
	if ((handler->eap_ds->request->code == PW_EAP_REQUEST) &&
	    (handler->eap_ds->request->type.type >= PW_EAP_MD5)) {
		handler->id = eap_generateid(request, (u_char)handler->eap_ds->request->id);
		if (handler->id == NULL) {
			radlog(L_ERR, "rlm_eap: problem in generating ID, Present EAP is not valid");
			eap_handler_free(&handler);
		} else {
			eaplist_add(&(eap_stuff->echolist), handler);
		}

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
		VALUE_PAIR *state;

		DEBUG2("  rlm_eap: Saving LEAP state");
		handler->id = eap_regenerateid(request, (u_char)handler->eap_ds->request->id);
		if (handler->id == NULL) {
			radlog(L_ERR, "rlm_eap: problem in generating ID, Present EAP is not valid");
			eap_handler_free(&handler);
		} else {
			eaplist_add(&(eap_stuff->echolist), handler);
		}

		/*
		 *  And copy the State attribute from the request
		 */
		state = paircopy2(request->packet->vps, PW_STATE);

		/*
		 *  FIXME: Assert there's only 1 state?
		 */
		pairadd(&request->reply->vps, state);

	} else {
		DEBUG2("  rlm_eap: Freeing handler");
		/* handler is no more required, free it now */
		eap_handler_free(&handler);
	}
	return RLM_MODULE_OK;
}

/*
 * EAP authorization DEPENDS on other rlm authorizations,
 * to check for user existance & get their configured values.
 * It Handles EAP-START Messages, User-Name initilization.
 */
static int eap_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR	*atype, *vp;
	rlm_eap_t	*eap_stuff;
	eap_packet_t    *eap_packet;
	int		status;
	unsigned char   *id;
	
	eap_stuff = (rlm_eap_t *)instance;

	/* Authorization not valid for proxies */
	if (request->proxy != NULL)
                return RLM_MODULE_NOOP;

	/*
	 * For EAP_START, send Access-Challenge with EAP Identity request.
	 * even when we have to proxy this request
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

		/* get the eap packet */
		eap_packet = eap_attribute(request->packet->vps);
		if (eap_packet == NULL) {
			radlog(L_ERR, "rlm_eap: Malformed EAP Message");
			return RLM_MODULE_FAIL;
		}

		id = eap_regenerateid(request, eap_packet->id);
		if (id == NULL) {
			radlog(L_ERR, "rlm_eap: User-Name cannot be obtained");
			free(eap_packet);
			return RLM_MODULE_FAIL;
		}

		request->username = eap_useridentity(eap_stuff->echolist, eap_packet, id);
		if (request->username == NULL) {
			radlog(L_ERR, "rlm_eap: Unknown User, authorization failed");
			free(eap_packet);
			free(id);
			return RLM_MODULE_FAIL;
		}
		free(eap_packet);
		free(id);
	}

	/*
	 * Enforce EAP authentication

	 * Auth-type(s) already set?  overide it with EAP
	 * If EAP-Message is present in RADIUS, then EAP authentication is MUST.

	 * TODO: When Multiple authentications are supported in RADIUS, 
	 *     then prioritize EAP by prepending it before all Auth-Types
	 */

	atype = pairfind(request->config_items, PW_AUTHTYPE);
	if ((atype == NULL) || 
		((atype->lvalue != PW_AUTHTYPE_EAP) &&
		(atype->lvalue != PW_AUTHTYPE_ACCEPT) &&
		(atype->lvalue != PW_AUTHTYPE_REJECT))) {

		vp = pairmake("Auth-Type", "EAP", T_OP_EQ);
		if (vp == NULL) {
			return RLM_MODULE_FAIL;
		}
		/* to overide */
		pairdelete(&request->config_items, PW_AUTHTYPE);
		pairadd(&request->config_items, vp);

		/* To prioritize
		vp->next = request->config_items;
		request->config_items = vp;
		*/
	}

	return RLM_MODULE_UPDATED;
}

/*
 *	If we're proxying EAP, then there may be magic we need
 *	to do.
 */
static int eap_post_proxy(void *instance, REQUEST *request)
{
	int i, len, offset;
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
	RLM_TYPE_THREAD_UNSAFE,		/* type */
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
