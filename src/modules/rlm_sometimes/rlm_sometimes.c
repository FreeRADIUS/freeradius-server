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
 * @file rlm_sometimes.c
 * @brief Switches between retuning different return codes.
 *
 * @copyright 2012 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	The instance data for rlm_sometimes is the list of fake values we are
 *	going to return.
 */
typedef struct rlm_sometimes_t {
	char const	*rcode_str;
	rlm_rcode_t	rcode;
	uint32_t	start;
	uint32_t	end;
	char const	*key;
	DICT_ATTR const	*da;
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
	{ "rcode", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sometimes_t, rcode_str), "fail" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_ATTRIBUTE, rlm_sometimes_t, key), "User-Name" },
	{ "start", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sometimes_t, start), "0" },
	{ "end", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sometimes_t, end), "127" },
	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_sometimes_t *inst = instance;

	/*
	 *	Convert the rcode string to an int, and get rid of it
	 */
	inst->rcode = fr_str2int(mod_rcode_table, inst->rcode_str, RLM_MODULE_UNKNOWN);
	if (inst->rcode == RLM_MODULE_UNKNOWN) {
		cf_log_err_cs(conf, "Unknown module return code '%s'", inst->rcode_str);
		return -1;
	}

	inst->da = dict_attrbyname(inst->key);
	rad_assert(inst->da);

	return 0;
}

/*
 *	A lie!  It always returns!
 */
static rlm_rcode_t sometimes_return(void *instance, RADIUS_PACKET *packet, RADIUS_PACKET *reply)
{
	uint32_t hash;
	uint32_t value;
	rlm_sometimes_t *inst = instance;
	VALUE_PAIR *vp;

	/*
	 *	Set it to NOOP and the module will always do nothing
	 */
	if (inst->rcode == RLM_MODULE_NOOP) return inst->rcode;

	/*
	 *	Hash based on the given key.  Usually User-Name.
	 */
	vp = fr_pair_find_by_da(packet->vps, inst->da, TAG_ANY);
	if (!vp) return RLM_MODULE_NOOP;

	hash = fr_hash(&vp->data, vp->vp_length);
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
		case PW_CODE_ACCESS_REQUEST:
			reply->code = PW_CODE_ACCESS_ACCEPT;
			break;

		case PW_CODE_ACCOUNTING_REQUEST:
			reply->code = PW_CODE_ACCOUNTING_RESPONSE;
			break;

		case PW_CODE_COA_REQUEST:
			reply->code = PW_CODE_COA_ACK;
			break;

		case PW_CODE_DISCONNECT_REQUEST:
			reply->code = PW_CODE_DISCONNECT_ACK;
			break;

		default:
			break;
		}
	}

	return inst->rcode;
}

static rlm_rcode_t CC_HINT(nonnull) mod_sometimes_packet(void *instance, REQUEST *request)
{
	return sometimes_return(instance, request->packet, request->reply);
}

static rlm_rcode_t CC_HINT(nonnull) mod_sometimes_reply(void *instance, REQUEST *request)
{
	return sometimes_return(instance, request->reply, NULL);
}

#ifdef WITH_PROXY
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void *instance, REQUEST *request)
{
	if (!request->proxy) return RLM_MODULE_NOOP;

	return sometimes_return(instance, request->proxy, request->proxy_reply);
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, REQUEST *request)
{
	if (!request->proxy_reply) return RLM_MODULE_NOOP;

	return sometimes_return(instance, request->proxy_reply, NULL);
}
#endif

extern module_t rlm_sometimes;
module_t rlm_sometimes = {
	.magic		= RLM_MODULE_INIT,
	.name		= "sometimes",
	.type		= RLM_TYPE_HUP_SAFE,   	/* needed for radmin */
	.inst_size	= sizeof(rlm_sometimes_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_sometimes_packet,
		[MOD_AUTHORIZE]		= mod_sometimes_packet,
		[MOD_PREACCT]		= mod_sometimes_packet,
		[MOD_ACCOUNTING]	= mod_sometimes_packet,
#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_sometimes_reply,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_sometimes_packet,
		[MOD_SEND_COA]		= mod_sometimes_reply,
#endif
	},
};
