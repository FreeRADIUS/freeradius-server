/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
 * @file rlm_expiration.c
 * @brief Lockout user accounts based on control attributes.
 *
 * @copyright 2001,2006  The FreeRADIUS server project
 * @copyright 2004  Kostas Kalevras <kkalev@noc.ntua.gr>
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_expiration_t {
	char *msg;		/* The Reply-Message passed back to the user if the account is expired */
} rlm_expiration_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
  { "reply-message", PW_TYPE_STRING_PTR, offsetof(rlm_expiration_t,msg),
    NULL, "Password Has Expired\r\n"},
  { NULL, -1, 0, NULL, NULL }
};

/*
 *      Check if account has expired, and if user may login now.
 */
static rlm_rcode_t expiration_authorize(void *instance, REQUEST *request)
{
	rlm_expiration_t *data = (rlm_expiration_t *)instance;
	VALUE_PAIR *vp, *check_item = NULL;
	char msg[MAX_STRING_LEN];

	if ((check_item = pairfind(request->config_items, PW_EXPIRATION, 0, TAG_ANY)) != NULL){
		/*
		*      Has this user's password expired?
		*
		*      If so, remove ALL reply attributes,
		*      and add our own Reply-Message, saying
		*      why they're being rejected.
		*/
		RDEBUG("Checking Expiration time: '%s'",check_item->vp_strvalue);
		if (((time_t) check_item->vp_date) <= request->timestamp) {
			char logstr[MAX_STRING_LEN];
			VALUE_PAIR *module_fmsg_vp;

			RDEBUG("Account has expired");

			if (data->msg && data->msg[0]){
				if (!radius_xlat(msg, sizeof(msg), data->msg, request, NULL, NULL)) {
					radlog(L_ERR, "rlm_expiration: xlat failed.");
					return RLM_MODULE_FAIL;
				}

				vp = pairmake("Reply-Message", msg, T_OP_ADD);
				pairfree(&request->reply->vps);
				request->reply->vps = vp;
			}
                        snprintf(logstr, sizeof(logstr), "Account has expired [Expiration %s]",check_item->vp_strvalue);
                        module_fmsg_vp = pairmake("Module-Failure-Message", logstr, T_OP_EQ);
                        pairadd(&request->packet->vps, module_fmsg_vp);

			return RLM_MODULE_USERLOCK;
		}
		/*
		 *	Else the account hasn't expired, but it may do so
		 *	in the future.  Set Session-Timeout.
		 */
		vp = pairfind(request->reply->vps, PW_SESSION_TIMEOUT, 0, TAG_ANY);
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       PW_SESSION_TIMEOUT, 0);
			vp->vp_date = (uint32_t) (((time_t) check_item->vp_date) - request->timestamp);

		} else if (vp->vp_date > ((uint32_t) (((time_t) check_item->vp_date) - request->timestamp))) {
			vp->vp_date = (uint32_t) (((time_t) check_item->vp_date) - request->timestamp);
		}
	}
	else
		return RLM_MODULE_NOOP;

	return RLM_MODULE_OK;
}

/*
 *      Compare the expiration date.
 */
static int expirecmp(void *instance, REQUEST *req,
		VALUE_PAIR *request, VALUE_PAIR *check,
		VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	time_t now = 0;
	instance = instance;
	request = request;      /* shut the compiler up */
	check_pairs = check_pairs;
	reply_pairs = reply_pairs;

	now = (req) ? req->timestamp : time(NULL);

	if (now <= ((time_t) check->vp_date))
		return 0;
	return +1;
}


static int expiration_detach(UNUSED void *instance)
{
	paircompare_unregister(PW_EXPIRATION, expirecmp);
	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int expiration_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_expiration_t *data;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = data = talloc_zero(conf, rlm_expiration_t);
	if (!data) return -1;

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		radlog(L_ERR, "rlm_expiration: Configuration parsing failed.");
		return -1;
	}

	/*
	 * Register the expiration comparison operation.
	 */
	paircompare_register(PW_EXPIRATION, 0, expirecmp, data);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_expiration = {
	RLM_MODULE_INIT,
	"expiration",
	RLM_TYPE_THREAD_SAFE,		/* type */
	expiration_instantiate,		/* instantiation */
	expiration_detach,		/* detach */
	{
		NULL,			/* authentication */
		expiration_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
