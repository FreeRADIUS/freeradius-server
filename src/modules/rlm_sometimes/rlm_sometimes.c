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
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/util/debug.h>

/*
 *	The instance data for rlm_sometimes is the list of fake values we are
 *	going to return.
 */
typedef struct {
	char const	*rcode_str;
	rlm_rcode_t	rcode;
	float		percentage;
	tmpl_t	*key;
} rlm_sometimes_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("rcode", FR_TYPE_STRING, rlm_sometimes_t, rcode_str), .dflt = "fail" },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_sometimes_t, key), .dflt = "&User-Name", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("percentage", FR_TYPE_FLOAT32, rlm_sometimes_t, percentage), .dflt = "0" },
	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_sometimes_t *inst = instance;

	/*
	 *	Convert the rcode string to an int, and get rid of it
	 */
	inst->rcode = fr_table_value_by_str(rcode_table, inst->rcode_str, RLM_MODULE_UNKNOWN);
	if (inst->rcode == RLM_MODULE_UNKNOWN) {
		cf_log_err(conf, "Unknown module return code '%s'", inst->rcode_str);
		return -1;
	}

	if ((inst->percentage < 0) || (inst->percentage > 100)) {
		cf_log_err(conf, "Invalid value for 'percentage'.  It must be 0..100 inclusive");
		return -1;
	}

	return 0;
}

/*
 *	A lie!  It always returns!
 */
static unlang_action_t sometimes_return(rlm_rcode_t *p_result, void const *instance, request_t *request,
					fr_radius_packet_t *packet, fr_radius_packet_t *reply)
{
	uint32_t		hash;
	rlm_sometimes_t const	*inst = talloc_get_type_abort_const(instance, rlm_sometimes_t);
	fr_pair_t		*vp;
	float			value;

	/*
	 *	Set it to NOOP and the module will always do nothing
	 */
	if (inst->rcode == RLM_MODULE_NOOP) RETURN_MODULE_RCODE(inst->rcode);

	/*
	 *	Hash based on the given key.  Usually User-Name.
	 */
	tmpl_find_vp(&vp, request, inst->key);
	if (!vp) RETURN_MODULE_NOOP;

	switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		hash = fr_hash(vp->data.datum.ptr, vp->vp_length);
		break;

	case FR_TYPE_STRUCTURAL:
		RETURN_MODULE_FAIL;

	default:
		hash = fr_hash(&vp->data.datum, fr_value_box_field_sizes[vp->vp_type]);
		break;
	}

	hash &= 0xffff;		/* all we need are 2^16 bits of precision */
	value = hash;
	value /= (1 << 16);
	value *= 100;

	if (value > inst->percentage) RETURN_MODULE_NOOP;

	/*
	 *	If we're returning "handled", then set the packet
	 *	code in the reply, so that the server responds.
	 *
	 *	@todo - MULTI_PROTOCOL - make this protocol agnostic
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

	RETURN_MODULE_RCODE(inst->rcode);
}

static unlang_action_t CC_HINT(nonnull) mod_sometimes_packet(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	return sometimes_return(p_result, mctx->instance, request, request->packet, request->reply);
}

static unlang_action_t CC_HINT(nonnull) mod_sometimes_reply(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	return sometimes_return(p_result, mctx->instance, request, request->reply, NULL);
}

extern module_t rlm_sometimes;
module_t rlm_sometimes = {
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
		[MOD_POST_AUTH]		= mod_sometimes_reply,
	},
};
