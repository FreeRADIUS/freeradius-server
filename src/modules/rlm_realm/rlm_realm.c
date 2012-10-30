/*
 * rlm_realm.c
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
 * FIXME add copyrights
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#define  REALM_FORMAT_PREFIX   0
#define  REALM_FORMAT_SUFFIX   1

typedef struct realm_config_t {
        int        format;
        char       *formatstring;
        char       *delim;
	int        ignore_default;
	int        ignore_null;
} realm_config_t;

static CONF_PARSER module_config[] = {
  { "format", PW_TYPE_STRING_PTR,
    offsetof(realm_config_t,formatstring), NULL, "suffix" },
  { "delimiter", PW_TYPE_STRING_PTR,
    offsetof(realm_config_t,delim), NULL, "@" },
  { "ignore_default", PW_TYPE_BOOLEAN,
    offsetof(realm_config_t,ignore_default), NULL, "no" },
  { "ignore_null", PW_TYPE_BOOLEAN,
    offsetof(realm_config_t,ignore_null), NULL, "no" },
  { NULL, -1, 0, NULL, NULL }    /* end the list */
};

/*
 *	Internal function to cut down on duplicated code.
 *
 *	Returns -1 on failure, 0 on no failure.  returnrealm
 *	is NULL on don't proxy, realm otherwise.
 */
static int check_for_realm(void *instance, REQUEST *request, REALM **returnrealm)
{
	char namebuf[MAX_STRING_LEN];
	char *username;
	const char *realmname = NULL;
	char *ptr;
	VALUE_PAIR *vp;
	REALM *realm;

        struct realm_config_t *inst = instance;

	/* initiate returnrealm */
	*returnrealm = NULL;

	/*
	 *	If the request has a proxy entry, then it's a proxy
	 *	reply, and we're walking through the module list again.
	 *
	 *	In that case, don't bother trying to proxy the request
	 *	again.
	 *
	 *	Also, if there's no User-Name attribute, we can't
	 *	proxy it, either.
	 */
	if ((request->username == NULL)
#ifdef WITH_PROXY
	    || (request->proxy != NULL)
#endif
	    ) {
	    
		RDEBUG2("Proxy reply, or no User-Name.  Ignoring.");
		return RLM_MODULE_OK;
	}

	/*
	 *      Check for 'Realm' attribute.  If it exists, then we've proxied
	 *      it already ( via another rlm_realm instance ) and should return.
	 */

	if (pairfind(request->packet->vps, PW_REALM, 0) != NULL ) {
	        RDEBUG2("Request already proxied.  Ignoring.");
		return RLM_MODULE_OK;
	}

	/*
	 *	We will be modifing this later, so we want our own copy
	 *	of it.
	 */
	strlcpy(namebuf, (char *)request->username->vp_strvalue, sizeof(namebuf));
	username = namebuf;

	switch(inst->format)
	{

	case REALM_FORMAT_SUFFIX:

	  /* DEBUG2("  rlm_realm: Checking for suffix after \"%c\"", inst->delim[0]); */
		ptr = strrchr(username, inst->delim[0]);
		if (ptr) {
			*ptr = '\0';
			realmname = ptr + 1;
		}
		break;

	case REALM_FORMAT_PREFIX:

		/* DEBUG2("  rlm_realm: Checking for prefix before \"%c\"", inst->delim[0]); */

		ptr = strchr(username, inst->delim[0]);
		if (ptr) {
			*ptr = '\0';
		     ptr++;
		     realmname = username;
		     username = ptr;
		}
		break;

	default:
		realmname = NULL;
		break;
	}

	/*
	 *	Print out excruciatingly descriptive debugging messages
	 *	for the people who find it too difficult to think about
	 *	what's going on.
	 */
	if (realmname) {
		RDEBUG2("Looking up realm \"%s\" for User-Name = \"%s\"",
		       realmname, request->username->vp_strvalue);
	} else {
		if( inst->ignore_null ) {
			RDEBUG2("No '%c' in User-Name = \"%s\", skipping NULL due to config.",
			inst->delim[0], request->username->vp_strvalue);
			return RLM_MODULE_NOOP;
		}
		RDEBUG2("No '%c' in User-Name = \"%s\", looking up realm NULL",
		       inst->delim[0], request->username->vp_strvalue);
	}

	/*
	 *	Allow DEFAULT realms unless told not to.
	 */
	realm = realm_find(realmname);
	if (!realm) {
		RDEBUG2("No such realm \"%s\"",
		       (realmname == NULL) ? "NULL" : realmname);
		return RLM_MODULE_NOOP;
	}
	if( inst->ignore_default &&
	    (strcmp(realm->name, "DEFAULT")) == 0) {
		RDEBUG2("Found DEFAULT, but skipping due to config.");
		return RLM_MODULE_NOOP;
	}

	RDEBUG2("Found realm \"%s\"", realm->name);

	/*
	 *	If we've been told to strip the realm off, then do so.
	 */
	if (realm->striprealm) {
		/*
		 *	Create the Stripped-User-Name attribute, if it
		 *	doesn't exist.
		 *
		 */
		if (request->username->attribute != PW_STRIPPED_USER_NAME) {
			vp = radius_paircreate(request, &request->packet->vps,
					       PW_STRIPPED_USER_NAME, 0,
					       PW_TYPE_STRING);
			RDEBUG2("Adding Stripped-User-Name = \"%s\"", username);
		} else {
			vp = request->username;
			RDEBUG2("Setting Stripped-User-Name = \"%s\"", username);
		}

		strcpy(vp->vp_strvalue, username);
		vp->length = strlen((char *)vp->vp_strvalue);
		request->username = vp;
	}

	/*
	 *	Add the realm name to the request.
	 *	If the realm is a regex, the use the realm as entered
	 *	by the user.  Otherwise, use the configured realm name,
	 *	as realm name comparison is case insensitive.  We want
	 *	to use the configured name, rather than what the user
	 *	entered.
	 */
	if (realm->name[0] != '~') realmname = realm->name;
	pairadd(&request->packet->vps, pairmake("Realm", realmname,
						T_OP_EQ));
	RDEBUG2("Adding Realm = \"%s\"", realmname);

	/*
	 *	Figure out what to do with the request.
	 */
	switch (request->packet->code) {
	default:
		RDEBUG2("Unknown packet code %d\n",
		       request->packet->code);
		return RLM_MODULE_OK;		/* don't do anything */

		/*
		 *	Perhaps accounting proxying was turned off.
		 */
	case PW_ACCOUNTING_REQUEST:
		if (!realm->acct_pool) {
			RDEBUG2("Accounting realm is LOCAL.");
			return RLM_MODULE_OK;
		}
		break;

		/*
		 *	Perhaps authentication proxying was turned off.
		 */
	case PW_AUTHENTICATION_REQUEST:
		if (!realm->auth_pool) {
			RDEBUG2("Authentication realm is LOCAL.");
			return RLM_MODULE_OK;
		}
		break;
	}

#ifdef WITH_PROXY
	RDEBUG2("Proxying request from user %s to realm %s",
	       username, realm->name);

	/*
	 *	Skip additional checks if it's not an accounting
	 *	request.
	 */
	if (request->packet->code != PW_ACCOUNTING_REQUEST) {
		*returnrealm = realm;
		return RLM_MODULE_UPDATED;
	}

	/*
	 *	FIXME: Each server should have a unique server key,
	 *	and put it in the accounting packet.  Every server
	 *	should know about the keys, and NOT proxy requests to
	 *	a server with key X if the packet already contains key
	 *	X.
	 */

	/*
	 *      If this request has arrived from another freeradius server
	 *      that has already proxied the request, we don't need to do
	 *      it again.
	 */
	vp = pairfind(request->packet->vps, PW_FREERADIUS_PROXIED_TO, 0);
	if (vp && (request->packet->src_ipaddr.af == AF_INET)) {
		int i;
		fr_ipaddr_t my_ipaddr;

		my_ipaddr.af = AF_INET;
		my_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;

		/*
		 *	Loop over the home accounting servers for this
		 *	realm.  If one of them has the same IP as the
		 *	FreeRADIUS-Proxied-To attribute, then the
		 *	packet has already been sent there.  Don't
		 *	send it there again.
		 */
		for (i = 0; i < realm->acct_pool->num_home_servers; i++) {
			if (fr_ipaddr_cmp(&realm->acct_pool->servers[i]->ipaddr,
					    &my_ipaddr) == 0) {
				RDEBUG2("Suppressing proxy due to FreeRADIUS-Proxied-To");
				return RLM_MODULE_OK;
			}
		}

		/*
		 *	See detail_recv() in src/main/listen.c for the
		 *	additional checks.
		 */
#ifdef WITH_DETAIL
	} else if ((request->listener->type == RAD_LISTEN_DETAIL) &&
		   !fr_inaddr_any(&request->packet->src_ipaddr)) {
		int i;

		/*
		 *	Loop over the home accounting servers for this
		 *	realm.  If one of them has the same IP as the
		 *	FreeRADIUS-Proxied-To attribute, then the
		 *	packet has already been sent there.  Don't
		 *	send it there again.
		 */
		for (i = 0; i < realm->acct_pool->num_home_servers; i++) {
			if ((fr_ipaddr_cmp(&realm->acct_pool->servers[i]->ipaddr,
					     &request->packet->src_ipaddr) == 0) &&
			    (realm->acct_pool->servers[i]->port == request->packet->src_port)) {
				RDEBUG2("Suppressing proxy because packet was already sent to a server in that realm");
				return RLM_MODULE_OK;
			}
		}
#endif	/* WITH_DETAIL */
	}
#endif	/* WITH_PROXY */

	/*
	 *	We got this far, which means we have a realm, set returnrealm
	 */
	*returnrealm = realm;

	return RLM_MODULE_UPDATED;
}

/*
 *	Add a "Proxy-To-Realm" attribute to the request.
 */
static void add_proxy_to_realm(VALUE_PAIR **vps, REALM *realm)
{
	VALUE_PAIR *vp;

	/*
	 *	Tell the server to proxy this request to another
	 *	realm.
	 */
	vp = pairmake("Proxy-To-Realm", realm->name, T_OP_EQ);
	if (!vp) {
		radlog(L_ERR|L_CONS, "no memory");
		exit(1);
	}

	/*
	 *  Add it, even if it's already present.
	 */
	pairadd(vps, vp);
}

/*
 *  Perform the realm module instantiation.  Configuration info is
 *  stored in *instance for later use.
 */

static int realm_instantiate(CONF_SECTION *conf, void **instance)
{
        struct realm_config_t *inst;

        /* setup a storage area for instance data */
        inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if(cf_section_parse(conf, inst, module_config) < 0) {
	       free(inst);
               return -1;
	}

	if(strcasecmp(inst->formatstring, "suffix") == 0) {
	     inst->format = REALM_FORMAT_SUFFIX;
	} else if(strcasecmp(inst->formatstring, "prefix") == 0) {
	     inst->format = REALM_FORMAT_PREFIX;
        } else {
	     radlog(L_ERR, "Bad value \"%s\" for realm format value", inst->formatstring);
	     free(inst);
	     return -1;
	}
	if(strlen(inst->delim) != 1) {
	     radlog(L_ERR, "Bad value \"%s\" for realm delimiter value", inst->delim);
	     free(inst);
	     return -1;
	}

	*instance = inst;
	return 0;

}





/*
 *  Examine a request for a username with an realm, and if it
 *  corresponds to something in the realms file, set that realm as
 *  Proxy-To.
 *
 *  This should very nearly duplicate the old proxy_send() code
 */
static int realm_authorize(void *instance, REQUEST *request)
{
	int rcode;
	REALM *realm;

	/*
	 *	Check if we've got to proxy the request.
	 *	If not, return without adding a Proxy-To-Realm
	 *	attribute.
	 */
	rcode = check_for_realm(instance, request, &realm);
	if (rcode != RLM_MODULE_UPDATED) return rcode;
	if (!realm) return RLM_MODULE_NOOP;

	/*
	 *	Maybe add a Proxy-To-Realm attribute to the request.
	 */
	RDEBUG2("Preparing to proxy authentication request to realm \"%s\"\n",
	       realm->name);
	add_proxy_to_realm(&request->config_items, realm);

	return RLM_MODULE_UPDATED; /* try the next module */
}

/*
 * This does the exact same thing as the realm_authorize, it's just called
 * differently.
 */
static int realm_preacct(void *instance, REQUEST *request)
{
	int rcode;
	const char *name = (char *)request->username->vp_strvalue;
	REALM *realm;

	if (!name)
	  return RLM_MODULE_OK;


	/*
	 *	Check if we've got to proxy the request.
	 *	If not, return without adding a Proxy-To-Realm
	 *	attribute.
	 */
	rcode = check_for_realm(instance, request, &realm);
	if (rcode != RLM_MODULE_UPDATED) return rcode;
	if (!realm) return RLM_MODULE_NOOP;

	/*
	 *	Maybe add a Proxy-To-Realm attribute to the request.
	 */
	RDEBUG2("Preparing to proxy accounting request to realm \"%s\"\n",
	       realm->name);
	add_proxy_to_realm(&request->config_items, realm);

	return RLM_MODULE_UPDATED; /* try the next module */
}

#ifdef WITH_COA
/*
 *	CoA realms via Operator-Name.  Because the realm isn't in a
 *	User-Name, concepts like "prefix" and "suffix' don't matter.
 */
static int realm_coa(UNUSED void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	REALM *realm;

	if (pairfind(request->packet->vps, PW_REALM, 0) != NULL) {
	        RDEBUG2("Request already proxied.  Ignoring.");
		return RLM_MODULE_OK;
	}

	vp = pairfind(request->packet->vps, PW_OPERATOR_NAME, 0);

	/*
	 *	Catch the case of broken dictionaries.
	 */
	if (vp->type != PW_TYPE_STRING) return RLM_MODULE_NOOP;

	/*
	 *	The string is too short.
	 */
	if (vp->length == 1) return RLM_MODULE_NOOP;

	/*
	 *	'1' means "the rest of the string is a realm"
	 */
	if (vp->vp_strvalue[0] != '1') return RLM_MODULE_NOOP;

	realm = realm_find(vp->vp_strvalue + 1);
	if (!realm) return RLM_MODULE_NOTFOUND;

	if (!realm->coa_pool) {
		RDEBUG2("CoA realm is LOCAL.");
		return RLM_MODULE_OK;
	}

	/*
	 *	Maybe add a Proxy-To-Realm attribute to the request.
	 */
	RDEBUG2("Preparing to proxy authentication request to realm \"%s\"\n",
	       realm->name);
	add_proxy_to_realm(&request->config_items, realm);

	return RLM_MODULE_UPDATED; /* try the next module */
}
#endif

static int realm_detach(void *instance)
{
	free(instance);
	return 0;
}

/* globally exported name */
module_t rlm_realm = {
	RLM_MODULE_INIT,
	"realm",
	RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,   	/* type */
	realm_instantiate,	       	/* instantiation */
	realm_detach,			/* detach */
	{
		NULL,			/* authentication */
		realm_authorize,	/* authorization */
		realm_preacct,	/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
#ifdef WITH_COA
		, realm_coa,		/* recv-coa */
		NULL			/* send-coa */
#endif
	},
};
