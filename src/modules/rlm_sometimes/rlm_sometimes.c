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
 * @file rlm_sometimes.c
 * @brief Switches between retuning different return codes.
 *
 * @copyright 2012 The FreeRADIUS server project
 */
#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	The instance data for rlm_sometimes is the list of fake values we are
 *	going to return.
 */
typedef struct rlm_sometimes_t {
	char			*rcode_str;
	int			rcode;
	int			start;
	int			end;
	char			*key;
	const DICT_ATTR		*da;
} rlm_sometimes_t;

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
  { "rcode",      PW_TYPE_STRING_PTR, offsetof(rlm_sometimes_t,rcode_str),
    NULL, "fail" },

  { "key", PW_TYPE_STRING_PTR,    offsetof(rlm_sometimes_t,key),
    NULL, "User-Name" },

  { "start", PW_TYPE_INTEGER,    offsetof(rlm_sometimes_t,start),
    NULL, "0" },

  { "end", PW_TYPE_INTEGER,    offsetof(rlm_sometimes_t,end),
    NULL, "127" },

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

static int str2rcode(const char *s)
{
	if(!strcasecmp(s, "reject"))
		return RLM_MODULE_REJECT;
	else if(!strcasecmp(s, "fail"))
		return RLM_MODULE_FAIL;
	else if(!strcasecmp(s, "ok"))
		return RLM_MODULE_OK;
	else if(!strcasecmp(s, "handled"))
		return RLM_MODULE_HANDLED;
	else if(!strcasecmp(s, "invalid"))
		return RLM_MODULE_INVALID;
	else if(!strcasecmp(s, "userlock"))
		return RLM_MODULE_USERLOCK;
	else if(!strcasecmp(s, "notfound"))
		return RLM_MODULE_NOTFOUND;
	else if(!strcasecmp(s, "noop"))
		return RLM_MODULE_NOOP;
	else if(!strcasecmp(s, "updated"))
		return RLM_MODULE_UPDATED;
	else {
		radlog(L_ERR,
			"rlm_sometimes: Unknown module rcode '%s'.\n", s);
		return -1;
	}
}

static int sometimes_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_sometimes_t *inst;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = inst = talloc_zero(conf, rlm_sometimes_t);
	if (!inst) return -1;

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		return -1;
	}

	/*
	 *	Convert the rcode string to an int, and get rid of it
	 */
	inst->rcode = str2rcode(inst->rcode_str);
	if (inst->rcode == -1) {
		return -1;
	}

	inst->da = dict_attrbyname(inst->key);
	if (!inst->da) {
		radlog(L_ERR, "rlm_sometimes; Unknown attributes %s", inst->key);
		return -1;
	}

	*instance = inst;

	return 0;
}

/*
 *	A lie!  It always returns!
 */
static rlm_rcode_t sometimes_return(void *instance, RADIUS_PACKET *packet,
				    RADIUS_PACKET *reply)
{
	uint32_t hash;
	int value;
	rlm_sometimes_t *inst = instance;
	VALUE_PAIR *vp;

	/*
	 *	Set it to NOOP and the module will always do nothing
	 */
	if (inst->rcode == RLM_MODULE_NOOP) return inst->rcode;

	/*
	 *	Hash based on the given key.  Usually User-Name.
	 */
	vp = pairfind(packet->vps, inst->da->attr, inst->da->vendor, TAG_ANY);
	if (!vp) return RLM_MODULE_NOOP;

	hash = fr_hash(&vp->data, vp->length);
	hash &= 0xff;		/* ensure it's 0..255 */
	value = hash;

	/*
	 *	Ranges are INCLUSIVE.
	 *	[start,end] returns "rcode"
	 *	Everything else returns "noop"
	 */
	if (value < inst->start) return RLM_MODULE_NOOP;
	if (value > inst->end) return RLM_MODULE_NOOP;

	/*
	 *	If we're returning "handled", then set the packet
	 *	code in the reply, so that the server responds.
	 */
	if ((inst->rcode == RLM_MODULE_HANDLED) && reply) {
		switch (packet->code) {
		case PW_AUTHENTICATION_REQUEST:
			reply->code = PW_AUTHENTICATION_ACK;
			break;

		case PW_ACCOUNTING_REQUEST:
			reply->code = PW_ACCOUNTING_RESPONSE;
			break;

		case PW_COA_REQUEST:
			reply->code = PW_COA_ACK;
			break;

		case PW_DISCONNECT_REQUEST:
			reply->code = PW_DISCONNECT_ACK;
			break;

		default:
			break;
		}
	}

	return inst->rcode;
}

static rlm_rcode_t sometimes_packet(void *instance, REQUEST *request)
{
	return sometimes_return(instance, request->packet, request->reply);
}

static rlm_rcode_t sometimes_reply(void *instance, REQUEST *request)
{
	return sometimes_return(instance, request->reply, NULL);
}

static rlm_rcode_t sometimes_pre_proxy(void *instance, REQUEST *request)
{
	if (!request->proxy) return RLM_MODULE_NOOP;

	return sometimes_return(instance, request->proxy, request->proxy_reply);
}

static rlm_rcode_t sometimes_post_proxy(void *instance, REQUEST *request)
{
	if (!request->proxy_reply) return RLM_MODULE_NOOP;

	return sometimes_return(instance, request->proxy_reply, NULL);
}

module_t rlm_sometimes = {
	RLM_MODULE_INIT,
	"sometimes",
	RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,   	/* type */
	sometimes_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		sometimes_packet,	/* authentication */
		sometimes_packet,	/* authorization */
		sometimes_packet,	/* preaccounting */
		sometimes_packet,	/* accounting */
		NULL,
		sometimes_pre_proxy,	/* pre-proxy */
		sometimes_post_proxy,	/* post-proxy */
		sometimes_reply		/* post-auth */
#ifdef WITH_COA
		,
		sometimes_packet,	/* recv-coa */
		sometimes_reply		/* send-coa */
#endif
	},
};
