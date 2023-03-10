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
 * @file rlm_radius.c
 * @brief A RADIUS client library.
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Network RADIUS SAS
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>

#include "rlm_radius.h"

static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int status_check_type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int status_check_update_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static CONF_PARSER const status_check_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID, rlm_radius_t, status_check),
	  .func = status_check_type_parse },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const status_check_update_config[] = {
	{ FR_CONF_OFFSET("update", FR_TYPE_SUBSECTION | FR_TYPE_REQUIRED, rlm_radius_t, status_check_map),
	  .ident2 = CF_IDENT_ANY,
	  .func = status_check_update_parse },
	{ FR_CONF_OFFSET("num_answers_to_alive", FR_TYPE_UINT32, rlm_radius_t, num_answers_to_alive), .dflt = STRINGIFY(3) },

	CONF_PARSER_TERMINATOR
};

/*
 *	Retransmission intervals for the packets we support.
 */
static CONF_PARSER auth_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("max_rtx_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER acct_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrt), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrc), .dflt = STRINGIFY(1) },
	{ FR_CONF_OFFSET("max_rtx_duration", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER status_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].mrt), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER coa_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("max_rtx_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER disconnect_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("max_rtx_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", FR_TYPE_TIME_DELTA, rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};


/*
 *	A mapping of configuration file names to internal variables.
 */
static CONF_PARSER const module_config[] = {
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, rlm_radius_t, io_submodule),
	  .func = module_rlm_submodule_parse },

	{ FR_CONF_OFFSET("type", FR_TYPE_UINT32 | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY | FR_TYPE_REQUIRED, rlm_radius_t, types),
	  .func = type_parse },

	{ FR_CONF_OFFSET("replicate", FR_TYPE_BOOL, rlm_radius_t, replicate) },

	{ FR_CONF_OFFSET("synchronous", FR_TYPE_BOOL, rlm_radius_t, synchronous) },

	{ FR_CONF_OFFSET("originate", FR_TYPE_BOOL, rlm_radius_t, originate) },

	{ FR_CONF_POINTER("status_check", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) status_check_config },

	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, rlm_radius_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) },

	{ FR_CONF_OFFSET("response_window", FR_TYPE_TIME_DELTA, rlm_radius_t, response_window), .dflt = STRINGIFY(20) },

	{ FR_CONF_OFFSET("zombie_period", FR_TYPE_TIME_DELTA, rlm_radius_t, zombie_period), .dflt = STRINGIFY(40) },

	{ FR_CONF_OFFSET("revive_interval", FR_TYPE_TIME_DELTA, rlm_radius_t, revive_interval) },

	{ FR_CONF_OFFSET("pool", FR_TYPE_SUBSECTION, rlm_radius_t, trunk_conf), .subcs = (void const *) fr_trunk_config, },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const type_interval_config[FR_RADIUS_CODE_MAX] = {
	[FR_RADIUS_CODE_ACCESS_REQUEST] = { FR_CONF_POINTER("Access-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) auth_config },

	[FR_RADIUS_CODE_ACCOUNTING_REQUEST] = { FR_CONF_POINTER("Accounting-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) acct_config },
	[FR_RADIUS_CODE_STATUS_SERVER] = { FR_CONF_POINTER("Status-Server", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) status_config },
	[FR_RADIUS_CODE_COA_REQUEST] = { FR_CONF_POINTER("CoA-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) coa_config },
	[FR_RADIUS_CODE_DISCONNECT_REQUEST] = { FR_CONF_POINTER("Disconnect-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) disconnect_config },
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_radius_dict[];
fr_dict_autoload_t rlm_radius_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_proxy_state;

extern fr_dict_attr_autoload_t rlm_radius_dict_attr[];
fr_dict_attr_autoload_t rlm_radius_dict_attr[] = {
	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_proxy_state, .name = "Proxy-State", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ NULL }
};

/** Set which types of packets we can parse
 *
 * @param[in] ctx	to allocate data in (instance of rlm_radius).
 * @param[out] out	Where to write the parsed data.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
		      CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));
	fr_dict_enum_value_t const	*type_enum;
	uint32_t		code;

	/*
	 *	Must be the RADIUS module
	 */
	fr_assert(cs && (strcmp(cf_section_name1(cs), "radius") == 0));

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_name(attr_packet_type, type_str, -1);
	if (!type_enum) {
	invalid_code:
		cf_log_err(ci, "Unknown or invalid RADIUS packet type '%s'", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;

	/*
	 *	Status-Server packets cannot be proxied.
	 */
	if (code == FR_RADIUS_CODE_STATUS_SERVER) {
		cf_log_err(ci, "Invalid setting of 'type = Status-Server'.  Status-Server packets cannot be proxied.");
		return -1;
	}

	if (!code ||
	    (code >= FR_RADIUS_CODE_MAX) ||
	    (!type_interval_config[code].name)) goto invalid_code;

	/*
	 *	If we're doing async proxying, push the timers for the
	 *	various packet types.
	 */
	cf_section_rule_push(cs, &type_interval_config[code]);

	memcpy(out, &code, sizeof(code));

	return 0;
}

/** Allow for Status-Server ping checks
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write our parsed data.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int status_check_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));
	fr_dict_enum_value_t const	*type_enum;
	uint32_t		code;

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_name(attr_packet_type, type_str, -1);
	if (!type_enum) {
	invalid_code:
		cf_log_err(ci, "Unknown or invalid RADIUS packet type '%s'", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;

	/*
	 *	Cheat, and re-use the "type" array for allowed packet
	 *	types.
	 */
	if (!code ||
	    (code >= FR_RADIUS_CODE_MAX) ||
	    (!type_interval_config[code].name)) goto invalid_code;

	/*
	 *	Add irt / mrt / mrd / mrc parsing, in the parent
	 *	configuration section.
	 */
	cf_section_rule_push(cf_item_to_section(cf_parent(cs)), &type_interval_config[code]);

	memcpy(out, &code, sizeof(code));

	/*
	 *	Nothing more to do here, so we stop.
	 */
	if (code == FR_RADIUS_CODE_STATUS_SERVER) return 0;

	cf_section_rule_push(cs, status_check_update_config);

	return 0;
}

/** Allow the admin to set packet contents for Status-Server ping checks
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write our parsed data
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION specifying the things to update
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int status_check_update_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	int			rcode;
	CONF_SECTION		*cs;
	char const		*name2;
	map_list_t		*head = (map_list_t *)out;

	fr_assert(cf_item_is_section(ci));
	map_list_init(head);

	cs = cf_item_to_section(ci);
	name2 = cf_section_name2(cs);
	if (!name2 || (strcmp(name2, "request") != 0)) {
		cf_log_err(cs, "You must specify 'request' as the destination list");
		return -1;
	}

	/*
	 *	Compile the "update" section.
	 */
	{
		tmpl_rules_t	parse_rules = {
			.attr = {
				.allow_foreign = true	/* Because we don't know where we'll be called */
			}
		};

		rcode = map_afrom_cs(ctx, head, cs, &parse_rules, &parse_rules, unlang_fixup_update, NULL, 128);
		if (rcode < 0) return -1; /* message already printed */
		if (map_list_empty(head)) {
			cf_log_err(cs, "'update' sections cannot be empty");
			return -1;
		}
	}

	/*
	 *	Rely on "bootstrap" to do sanity checks between 'type
	 *	= Access-Request', and 'update' containing passwords.
	 */
	return 0;
}


static void mod_radius_signal(module_ctx_t const *mctx, request_t *request, fr_state_signal_t action)
{
	rlm_radius_t const	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_radius_t);
	rlm_radius_io_t	const	*io = (rlm_radius_io_t const *)inst->io_submodule->module;		/* Public symbol exported by the module */

	/*
	 *	We received a duplicate packet, but we're not doing
	 *	synchronous proxying.  Ignore the dup, and rely on the
	 *	IO submodule to time it's own retransmissions.
	 */
	if ((action == FR_SIGNAL_DUP) && !inst->synchronous) return;

	if (!io->signal) return;

	io->signal(MODULE_CTX(inst->io_submodule->dl_inst,
			      module_thread(inst->io_submodule)->data, mctx->env_data,
			      mctx->rctx), request, action);
}

/** Do any RADIUS-layer fixups for proxying.
 *
 */
static void radius_fixups(rlm_radius_t const *inst, request_t *request)
{
	fr_pair_t *vp;

	/*
	 *	Check for proxy loops.
	 */
	if (RDEBUG_ENABLED) {
		fr_dcursor_t cursor;

		for (vp = fr_pair_dcursor_by_da_init(&cursor, &request->request_pairs, attr_proxy_state);
		     vp;
		     vp = fr_dcursor_next(&cursor)) {
			if (vp->vp_length != 4) continue;

			if (memcmp(&inst->proxy_state, vp->vp_octets, 4) == 0) {
				RWARN("Possible proxy loop - please check server configuration.");
				break;
			}
		}
	}

	if (request->packet->code != FR_RADIUS_CODE_ACCESS_REQUEST) return;

	if (fr_pair_find_by_da(&request->request_pairs, NULL, attr_chap_password) &&
	    !fr_pair_find_by_da(&request->request_pairs, NULL, attr_chap_challenge)) {
	    	MEM(pair_append_request(&vp, attr_chap_challenge) >= 0);
		fr_pair_value_memdup(vp, request->packet->vector, sizeof(request->packet->vector), true);
	}
}


/** Send packets outbound.
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_radius_t const	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_radius_t);
	rlm_rcode_t		rcode;
	unlang_action_t		ua;
	fr_client_t		*client;

	void			*rctx = NULL;

	if (!request->packet->code) {
		REDEBUG("You MUST specify a packet code");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Reserve Status-Server for ourselves, for link-specific
	 *	signaling.
	 */
	if (request->packet->code == FR_RADIUS_CODE_STATUS_SERVER) {
		REDEBUG("Cannot proxy Status-Server packets");
		RETURN_MODULE_FAIL;
	}

	if ((request->packet->code >= FR_RADIUS_CODE_MAX) ||
	    !fr_time_delta_ispos(inst->retry[request->packet->code].irt)) { /* can't be zero */
		REDEBUG("Invalid packet code %d", request->packet->code);
		RETURN_MODULE_FAIL;
	}

	if (!inst->allowed[request->packet->code]) {
		REDEBUG("Packet code %s is disallowed by the configuration",
		       fr_radius_packet_names[request->packet->code]);
		RETURN_MODULE_FAIL;
	}

	client = client_from_request(request);
	if (client && client->dynamic && !client->active) {
		REDEBUG("Cannot proxy packets which define dynamic clients");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Do any necessary RADIUS level fixups
	 *	- check Proxy-State
	 *	- do CHAP-Challenge fixups
	 */
	radius_fixups(inst, request);

	/*
	 *	Push the request and it's data to the IO submodule.
	 *
	 *	This may return YIELD, for "please yield", or it may
	 *	return another code which indicates what happened to
	 *	the request...
	 */
	ua = inst->io->enqueue(&rcode, &rctx, inst->io_submodule->dl_inst->data,
			       module_thread(inst->io_submodule)->data, request);
	if (ua != UNLANG_ACTION_YIELD) {
		fr_assert(rctx == NULL);
		RETURN_MODULE_RCODE(rcode);
	}

	return unlang_module_yield(request, inst->io->resume, mod_radius_signal, rctx);
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	size_t i, num_types;
	rlm_radius_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_radius_t);
	CONF_SECTION *conf = mctx->inst->conf;

	inst->io = (rlm_radius_io_t const *)inst->io_submodule->module;	/* Public symbol exported by the module */
	inst->name = mctx->inst->name;

	/*
	 *	These limits are specific to RADIUS, and cannot be over-ridden
	 */
	FR_INTEGER_BOUND_CHECK("trunk.per_connection_max", inst->trunk_conf.max_req_per_conn, >=, 2);
	FR_INTEGER_BOUND_CHECK("trunk.per_connection_max", inst->trunk_conf.max_req_per_conn, <=, 255);
	FR_INTEGER_BOUND_CHECK("trunk.per_connection_target", inst->trunk_conf.target_req_per_conn, <=, inst->trunk_conf.max_req_per_conn / 2);

	FR_TIME_DELTA_BOUND_CHECK("response_window", inst->zombie_period, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("response_window", inst->zombie_period, <=, fr_time_delta_from_sec(120));

	FR_TIME_DELTA_BOUND_CHECK("zombie_period", inst->zombie_period, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("zombie_period", inst->zombie_period, <=, fr_time_delta_from_sec(120));

	if (!inst->status_check) {
		FR_TIME_DELTA_BOUND_CHECK("revive_interval", inst->revive_interval, >=, fr_time_delta_from_sec(10));
		FR_TIME_DELTA_BOUND_CHECK("revive_interval", inst->revive_interval, <=, fr_time_delta_from_sec(3600));
	}

	num_types = talloc_array_length(inst->types);
	fr_assert(num_types > 0);

	/*
	 *	Allow for O(1) lookup later...
	 */
	for (i = 0; i < num_types; i++) {
		uint32_t code;

		code = inst->types[i];
		fr_assert(code > 0);
		fr_assert(code < FR_RADIUS_CODE_MAX);

		inst->allowed[code] = true;
	}

	fr_assert(inst->status_check < FR_RADIUS_CODE_MAX);

	/*
	 *	If we're replicating, we don't care if the other end
	 *	is alive.
	 */
	if (inst->replicate && inst->status_check) {
		cf_log_warn(conf, "Ignoring 'status_check = %s' due to 'replicate = true'",
			    fr_radius_packet_names[inst->status_check]);
		inst->status_check = 0;
	}


	/*
	 *	If we have status checks, then do some sanity checks.
	 *	Status-Server is always allowed.  Otherwise, the
	 *	status checks have to match one of the allowed
	 *	packets.
	 */
	if (inst->status_check) {
		if (inst->status_check == FR_RADIUS_CODE_STATUS_SERVER) {
			inst->allowed[inst->status_check] = true;

		} else if (!inst->allowed[inst->status_check]) {
			cf_log_err(conf, "Using 'status_check = %s' requires also 'type = %s'",
				   fr_radius_packet_names[inst->status_check], fr_radius_packet_names[inst->status_check]);
			return -1;
		}

		/*
		 *	@todo - check the contents of the "update"
		 *	section, to be sure that (e.g.) Access-Request
		 *	contains User-Name, etc.
		 */
	}

	/*
	 *	Don't sanity check the async timers if we're doing
	 *	synchronous proxying.
	 */
	if (inst->synchronous) goto setup_io_submodule;

	/*
	 *	Set limits on retransmission timers
	 */
	if (inst->allowed[FR_RADIUS_CODE_ACCESS_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Access-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("Access-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Access-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	Note that RFC 5080 allows for Accounting-Request to
	 *	have mrt=mrc=mrd = 0, which means "retransmit
	 *	forever".  We allow that, with the restriction that
	 *	the server core will automatically free the request at
	 *	max_request_time.
	 */
	if (inst->allowed[FR_RADIUS_CODE_ACCOUNTING_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].irt, >=, fr_time_delta_from_sec(1));
#if 0
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Accounting-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrc, >=, 0);
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrd, >=, fr_time_delta_from_sec(0));
#endif

		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Accounting-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	Status-Server
	 */
	if (inst->allowed[FR_RADIUS_CODE_STATUS_SERVER]) {
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.initial_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Status-Server.max_rtx_count", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_duration", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("Status-Server.initial_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Status-Server.max_rtx_count", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_duration", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	CoA
	 */
	if (inst->allowed[FR_RADIUS_CODE_COA_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("CoA-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrt, <=, fr_time_delta_from_sec(60));
		FR_INTEGER_BOUND_CHECK("CoA-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	Disconnect
	 */
	if (inst->allowed[FR_RADIUS_CODE_DISCONNECT_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

setup_io_submodule:
	/*
	 *	Get random Proxy-State identifier for this module.
	 */
	inst->proxy_state = fr_rand();

	return 0;
}

static int mod_load(void)
{
	if (fr_radius_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	fr_radius_free();
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
extern module_rlm_t rlm_radius;
module_rlm_t rlm_radius = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "radius",
		.type		= MODULE_TYPE_THREAD_SAFE | MODULE_TYPE_RESUMABLE,
		.inst_size	= sizeof(rlm_radius_t),
		.config		= module_config,

		.onload		= mod_load,
		.unload		= mod_unload,

		.bootstrap	= mod_bootstrap,
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = CF_IDENT_ANY,	.name2 = CF_IDENT_ANY,	.method = mod_process },
		MODULE_NAME_TERMINATOR
	},
};
