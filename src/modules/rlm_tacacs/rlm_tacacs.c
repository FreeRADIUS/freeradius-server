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
 * @file rlm_tacacs.c
 * @brief A TACACS client library.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include "lib/unlang/action.h"
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>

#include "rlm_tacacs.h"

static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

/*
 *	Retransmission intervals for the packets we support.
 */
static conf_parser_t retry_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", fr_retry_config_t, irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", fr_retry_config_t, mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("max_rtx_count", fr_retry_config_t, mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", fr_retry_config_t, mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

/*
 *	A mapping of configuration file names to internal variables.
 */
static conf_parser_t const module_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("transport", FR_TYPE_VOID, 0, rlm_tacacs_t, io_submodule),
	  .func = module_rlm_submodule_parse },

	{ FR_CONF_OFFSET_FLAGS("type", CONF_FLAG_NOT_EMPTY | CONF_FLAG_MULTI | CONF_FLAG_REQUIRED, rlm_tacacs_t, types),
	  .func = type_parse },

	{ FR_CONF_OFFSET("max_attributes", rlm_tacacs_t, max_attributes), .dflt = STRINGIFY(FR_MAX_ATTRIBUTES) },

	{ FR_CONF_OFFSET("response_window", rlm_tacacs_t, response_window), .dflt = STRINGIFY(20) },

	{ FR_CONF_OFFSET("zombie_period", rlm_tacacs_t, zombie_period), .dflt = STRINGIFY(40) },

	{ FR_CONF_OFFSET("revive_interval", rlm_tacacs_t, revive_interval) },

	{ FR_CONF_OFFSET_SUBSECTION("pool", 0, rlm_tacacs_t, trunk_conf, trunk_config ) },

	{ FR_CONF_OFFSET_SUBSECTION("retry", 0, rlm_tacacs_t, retry, retry_config ) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t rlm_tacacs_dict[];
fr_dict_autoload_t rlm_tacacs_dict[] = {
	{ .out = &dict_tacacs, .proto = "tacacs" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t rlm_tacacs_dict_attr[];
fr_dict_attr_autoload_t rlm_tacacs_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ NULL }
};

/** Set which types of packets we can parse
 *
 * @param[in] ctx	to allocate data in (instance of rlm_tacacs).
 * @param[out] out	Where to write the parsed data.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
		      CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	fr_dict_enum_value_t const	*type_enum;
	uint32_t		code;

#ifndef NDEBUG
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));
#endif

	/*
	 *	Must be the TACACS+ module
	 */
	fr_assert(cs && (strcmp(cf_section_name1(cs), "tacacs") == 0));

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_name(attr_packet_type, type_str, -1);
	if (!type_enum) {
		cf_log_err(ci, "Unknown TACACS+ packet type '%s'", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;

	memcpy(out, &code, sizeof(code));

	return 0;
}

static void mod_tacacs_signal(module_ctx_t const *mctx, request_t *request, fr_signal_t action)
{
	rlm_tacacs_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_tacacs_t);
	rlm_tacacs_io_t	const	*io = (rlm_tacacs_io_t const *)inst->io_submodule->exported;		/* Public symbol exported by the module */

	/*
	 *	We received a duplicate packet, ignore the dup, and rely on the
	 *	IO submodule / trunk to do it's own retransmissions.
	 */
	if (action == FR_SIGNAL_DUP) return;

	if (!io->signal) return;

	io->signal(MODULE_CTX(inst->io_submodule,
			      module_thread(inst->io_submodule)->data, mctx->env_data,
			      mctx->rctx), request, action);
}

/** Send packets outbound.
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_tacacs_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_tacacs_t);
	unlang_action_t		ua;

	void			*rctx = NULL;

	if (!FR_TACACS_PACKET_CODE_VALID(request->packet->code)) {
		REDEBUG("Invalid packet code %d", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	if (!inst->allowed[request->packet->code]) {
		REDEBUG("Packet code %s is disallowed by the configuration",
		       fr_tacacs_packet_names[request->packet->code]);
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	Push the request and it's data to the IO submodule.
	 *
	 *	This may return YIELD, for "please yield", or it may
	 *	return another code which indicates what happened to
	 *	the request...
	 */
	ua = inst->io->enqueue(p_result, &rctx, inst->io_submodule->data,
			       module_thread(inst->io_submodule)->data, request);
	if (ua != UNLANG_ACTION_YIELD) {
		fr_assert(rctx == NULL);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return unlang_module_yield(request, inst->io->resume, mod_tacacs_signal, 0, rctx);
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	size_t i, num_types;
	rlm_tacacs_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_tacacs_t);

	inst->io = (rlm_tacacs_io_t const *)inst->io_submodule->exported;	/* Public symbol exported by the module */
	inst->name = mctx->mi->name;

	/*
	 *	These limits are specific to TACACS, and cannot be over-ridden, due to 8-bit ID fields!
	 */
	FR_INTEGER_BOUND_CHECK("trunk.per_connection_max", inst->trunk_conf.max_req_per_conn, >=, 2);
	FR_INTEGER_BOUND_CHECK("trunk.per_connection_max", inst->trunk_conf.max_req_per_conn, <=, 255);
	FR_INTEGER_BOUND_CHECK("trunk.per_connection_target", inst->trunk_conf.target_req_per_conn, <=, inst->trunk_conf.max_req_per_conn / 2);

	FR_TIME_DELTA_BOUND_CHECK("response_window", inst->zombie_period, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("response_window", inst->zombie_period, <=, fr_time_delta_from_sec(120));

	FR_TIME_DELTA_BOUND_CHECK("zombie_period", inst->zombie_period, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("zombie_period", inst->zombie_period, <=, fr_time_delta_from_sec(120));

	FR_TIME_DELTA_BOUND_CHECK("revive_interval", inst->revive_interval, >=, fr_time_delta_from_sec(10));
	FR_TIME_DELTA_BOUND_CHECK("revive_interval", inst->revive_interval, <=, fr_time_delta_from_sec(3600));

	num_types = talloc_array_length(inst->types);
	fr_assert(num_types > 0);

	/*
	 *	Allow for O(1) lookup later...
	 */
	for (i = 0; i < num_types; i++) {
		uint32_t code;

		code = inst->types[i];
		fr_assert(FR_TACACS_PACKET_CODE_VALID(code));

		inst->allowed[code] = true;
	}


	return 0;
}

static int mod_load(void)
{
	if (fr_tacacs_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	fr_tacacs_global_free();
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_tacacs;
module_rlm_t rlm_tacacs = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "tacacs",
		.inst_size	= sizeof(rlm_tacacs_t),
		.config		= module_config,
		.dict		= &dict_tacacs,

		.onload		= mod_load,
		.unload		= mod_unload,

		.instantiate	= mod_instantiate,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_process },
			MODULE_BINDING_TERMINATOR
		}
	}
};
