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

#include <stdio.h>
#include <stdlib.h>

#include "eap.h"


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
	char		*eap_name;
	CONF_SECTION 	*scs;
	EAP_TYPES	*types;
	EAP_CONF	*conf;
	rlm_eap_t	**eap_stuff;
	
	eap_stuff = (rlm_eap_t **)instance;
	types	 = NULL;
	conf	 = NULL;
        eap_name = NULL;

	conf = malloc(sizeof(EAP_CONF));
        if (cf_section_parse(cs, conf, module_config) < 0) {
                free(conf);
                return -1;
        }

        for(scs=cf_subsection_find_next(cs, NULL, NULL);
                        scs != NULL;
                        scs=cf_subsection_find_next(cs, scs, NULL)) {
                eap_name = cf_section_name1(scs);

                if (!eap_name)  continue;
		load_type(&types, eap_name, scs);
        }

	if (!types) return -1;

	*eap_stuff = malloc(sizeof(rlm_eap_t));
	if (*eap_stuff) {
		(*eap_stuff)->typelist = types;
		(*eap_stuff)->unique_id = (getpid() & 0xff);
		(*eap_stuff)->echolist = NULL;
		(*eap_stuff)->conf = conf;
		(*eap_stuff)->eap_data = NULL;
	}  else {
		radlog(L_ERR, "rlm_eap: out of memory");
		free_type_list(&types);
		return -1;
	}

	return 0;
}

/*
 * delete all the allocated space by eap module
 */
static int eap_detach(void *instance)
{
	rlm_eap_t *t;

	t = (rlm_eap_t *)instance;

	free_type_list(&(t->typelist));

	list_free(&(t->echolist));

	free(t->conf->default_eap_type);
	free(t->conf);

	free(t);

	return 0;
}

/*
 *	Assumption: Any one of the Authorization module should
 *		get the configured password for any valid user.
 * 		If not, Authentication fails to validate.
 *
 *	Authenticate the user with the given password.
 *	Extract the EAP data into EAP packet if Authtype is EAP.
 *	EAP packet contains the list of EAP attributes.
 *	Check for eap Authentication type.
 *	All EAP authentication types will be handled in the sub modules.
 *
 *	Based on EAP type, corresponding EAP-type module must be called.
 *	currently only MD5 EAP-type is supported, so all are defaulted.
 *	Later on this should call relevant EAP-type
 *
 *	To Handle nak, we need to keep track of id, to find out
 * 	the type we sent earlier.
 *	When Success or Failure is sent we can delete the id.
 */
static int eap_authenticate(void *instance, REQUEST *request)
{
	EAP_DS		*eap_ds;
	eap_packet_t	*eap_msg;
	rlm_eap_t	*eap_stuff;
	int		status;

	eap_stuff = (rlm_eap_t *)instance;

	/* 
	 * Always, clean the list first as it is not timer based
	 * FIXME: Appropriate cleaning mechanism.
	 *	Probably, each sub module should handle this list.
	 */
	list_clean(&(eap_stuff->echolist), (time_t)eap_stuff->conf->timer_limit);

	if (eap_stuff->eap_data == NULL) {
		/*
		 * Incase if EAP is not configured in autz block
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

		/*
		 * Authenticate only proper EAP_Messages
		 */
		eap_msg = get_eapmsg_attr(request->packet->vps);

		/*
		 * No User-Name, No authentication
		 */
		if (request->username == NULL) {
			radlog(L_ERR, "rlm_eap: Unknown User, authentication failed");
			return RLM_MODULE_REJECT;
			/* FIXME: This should be only in authorization
			request->username = get_username(eap_msg);
			if (request->username == NULL) {
				radlog(L_ERR, "rlm_eap: Unknown User, authentication failed");
				return RLM_MODULE_REJECT;
			}
			*/
		}
	} else {
		eap_msg = eap_stuff->eap_data;
	}

	eap_ds = extract(eap_msg);

	if (eap_msg) {
		free(eap_msg);
		eap_msg= NULL;
		eap_stuff->eap_data = NULL;
	}
	if (eap_ds == NULL) {
		return RLM_MODULE_INVALID;
	}

	eap_ds->username = paircopy(request->username);

	/*
	 * Password is never sent over the wire.
	 * So never rely on the password attribute in the request.
	 * Always get the configured password, for each user.
	 */
	eap_ds->password = paircopy2(request->config_items, PW_PASSWORD);
	if (eap_ds->password == NULL) {
		DEBUG("rlm_eap: Could not find User-Password configuration item, cannot do EAP authentication\n");
		eap_ds->request->code = PW_EAP_FAILURE;
		compose(request, eap_ds->request);

		eap_ds_free(&eap_ds);

		return RLM_MODULE_INVALID;
	}

	/*
	 * Select the appropriate eap_type or default to the configured one
	 */
	if (select_eap_type(&(eap_stuff->echolist), eap_stuff->typelist,
		eap_ds, eap_stuff->conf->default_eap_type) == EAP_INVALID) {

		eap_ds_free(&eap_ds);

		return RLM_MODULE_INVALID;
	}
	compose(request, eap_ds->request);

	/*
	 * Add to the list only if it is EAP-Request
	 */
	if ((eap_ds->request->code == PW_EAP_REQUEST) &&
		(eap_ds->request->type != PW_EAP_IDENTITY)) {
		list_add(&(eap_stuff->echolist), eap_ds);
	} else {
		eap_ds_free(&eap_ds);
	}

	return RLM_MODULE_OK;
}

/*
 * EAP authorization works in conjunction with other rlm authorizations but not alone.
 * It Handles EAP-START Messages and tries to fill username if present in EAP, but
 * as such it doesnot know if the user exists or how to get the configured values for each user. 

 * Ideal way is to have EAP as one of the first authorize module in radiusd.conf
 * probably after preprocess
 */
static int eap_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR	*vp;
	VALUE_PAIR	*atype;
	int		status;
	eap_packet_t	*eap_msg;
	
	/*
	 * Authorization not valid for proxies
	 */
	if (request->proxy != NULL)
                return RLM_MODULE_NOOP;

	/*
	 * For EAP_START, send Access-Challenge with EAP Identity request.
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
	
	eap_msg = get_eapmsg_attr(request->packet->vps);
	if (eap_msg == NULL) {
		radlog(L_ERR, "rlm_eap: Malformed EAP Message");
		return RLM_MODULE_FAIL;
	}
	((rlm_eap_t *)instance)->eap_data = eap_msg;

	/*
	 * If we came here, we should have the username to proceed further
	 */
	if (request->username == NULL) {
		request->username = get_username(((rlm_eap_t *)instance)->eap_data);
		if (request->username == NULL) {
			radlog(L_ERR, "rlm_eap: Unknown User, authorization failed");
			return RLM_MODULE_FAIL;
		}
	} else {
		/*
		 * For Identity responses, compare EAP username with the request username
		 */
		vp = get_username(((rlm_eap_t *)instance)->eap_data);
		if ((vp != NULL) && 
			(memcmp(request->username->strvalue, vp->strvalue, vp->length) != 0)) {

			radlog(L_ERR, "rlm_eap: Mismatched User, authorization failed");
			return RLM_MODULE_FAIL;
		}
	}

	/*
	 * ??? Is this user, a valid existing user in our db ???
	 * Other authorize modules will handle this,
	 * as username is now not empty from this point
	 */

	/*
	 * Enforce EAP authentication if it is not proxy reply.
	 * and set the return type to try the next module to get the user details

	 * ???: If Auth-type is already set then what ???
	 * I guess, overide it instead of prepending it before all Auth-Types
	 * If multiple Auth-types are set then it is invalid, remove them & set EAP

		pairdelete(&request->config_items, PW_AUTHTYPE);
		vp = pairmake("Auth-Type", "EAP", T_OP_EQ);
		pairadd(&request->config_items, vp);
	 */
	atype = pairfind(request->config_items, PW_AUTHTYPE);
	if ((atype == NULL) || ((atype->lvalue != PW_AUTHTYPE_EAP) &&
		(atype->lvalue != PW_AUTHTYPE_ACCEPT))) {
		vp = pairmake("Auth-Type", "EAP", T_OP_EQ);
		if (vp == NULL) {
			return RLM_MODULE_FAIL;
		}
		vp->next = request->config_items;
		request->config_items = vp;
	}

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
		NULL			/* checksimul */
	},
	eap_detach,			/* detach */
	NULL,				/* destroy */
};
