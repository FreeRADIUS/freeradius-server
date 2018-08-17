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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/rad_assert.h>

/*
 *	The instance data for rlm_sometimes is the list of fake values we are
 *	going to return.
 */
typedef struct rlm_sometimes_t {
	char const	*rcode_str;
	rlm_rcode_t	rcode;
	uint32_t	start;
	uint32_t	end;
	vp_tmpl_t	*key;
} rlm_sometimes_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("rcode", FR_TYPE_STRING, rlm_sometimes_t, rcode_str), .dflt = "fail" },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_sometimes_t, key), .dflt = "&User-Name", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("start", FR_TYPE_UINT32, rlm_sometimes_t, start), .dflt = "0" },
	{ FR_CONF_OFFSET("end", FR_TYPE_UINT32, rlm_sometimes_t, end), .dflt = "127" },
	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_sometimes_t *inst = instance;

	/*
	 *	Convert the rcode string to an int, and get rid of it
	 */
	inst->rcode = fr_str2int(mod_rcode_table, inst->rcode_str, RLM_MODULE_UNKNOWN);
	if (inst->rcode == RLM_MODULE_UNKNOWN) {
		cf_log_err(conf, "Unknown module return code '%s'", inst->rcode_str);
		return -1;
	}

	return 0;
}

/*
 *	A lie!  It always returns!
 */
static rlm_rcode_t sometimes_return(void const *instance, REQUEST *request, RADIUS_PACKET *packet, RADIUS_PACKET *reply)
{
	uint32_t		hash;
	uint32_t		value;
	rlm_sometimes_t const	*inst = instance;
	VALUE_PAIR		*vp;

	/*
	 *	Set it to NOOP and the module will always do nothing
	 */
	if (inst->rcode == RLM_MODULE_NOOP) return inst->rcode;

	/*
	 *	Hash based on the given key.  Usually User-Name.
	 */
	tmpl_find_vp(&vp, request, inst->key);
	if (!vp) return RLM_MODULE_NOOP;

	switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		hash = fr_hash(vp->data.datum.ptr, vp->vp_length);
		break;

	case FR_TYPE_ABINARY:
		hash = fr_hash(vp->vp_filter, vp->vp_length);
		break;

	case FR_TYPE_STRUCTURAL:
		return RLM_MODULE_FAIL;

	default:
		hash = fr_hash(&vp->data.datum, fr_value_box_field_sizes[vp->vp_type]);
		break;
	}
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
		case FR_CODE_ACCESS_REQUEST:
			reply->code = FR_CODE_ACCESS_ACCEPT;
			break;

		case FR_CODE_ACCOUNTING_REQUEST:
			reply->code = FR_CODE_ACCOUNTING_RESPONSE;
			break;

		case FR_CODE_COA_REQUEST:
			reply->code = FR_CODE_COA_ACK;
			break;

		case FR_CODE_DISCONNECT_REQUEST:
			reply->code = FR_CODE_DISCONNECT_ACK;
			break;

		default:
			break;
		}
	}

	return inst->rcode;
}

static rlm_rcode_t CC_HINT(nonnull) mod_sometimes_packet(void *instance, UNUSED void *thread, REQUEST *request)
{
	return sometimes_return(instance, request, request->packet, request->reply);
}

static rlm_rcode_t CC_HINT(nonnull) mod_sometimes_reply(void *instance, UNUSED void *thread, REQUEST *request)
{
	return sometimes_return(instance, request, request->reply, NULL);
}

#ifdef WITH_PROXY
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void *instance, UNUSED void *thread, REQUEST *request)
{
	if (!request->proxy) return RLM_MODULE_NOOP;

	return sometimes_return(instance, request, request->proxy->packet, request->proxy->reply);
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, UNUSED void *thread, REQUEST *request)
{
	if (!request->proxy || !request->proxy->reply) return RLM_MODULE_NOOP;

	return sometimes_return(instance, request, request->proxy->reply, NULL);
}
#endif

extern rad_module_t rlm_sometimes;
rad_module_t rlm_sometimes = {
	.magic		= RLM_MODULE_INIT,
	.name		= "sometimes",
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
