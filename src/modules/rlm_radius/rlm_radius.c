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
 * @copyright 2016  The FreeRADIUS server project
 * @copyright 2016  Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/server/rad_assert.h>

#include "rlm_radius.h"

static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int status_check_type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int status_check_update_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static CONF_PARSER const status_checks_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID, rlm_radius_t, status_check),
	  .func = status_check_type_parse },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const status_check_update_config[] = {
	{ FR_CONF_OFFSET("update", FR_TYPE_SUBSECTION | FR_TYPE_REQUIRED, rlm_radius_t, status_check_map),
	  .ident2 = CF_IDENT_ANY,
	  .func = status_check_update_parse },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const connection_config[] = {
	{ FR_CONF_OFFSET("connect_timeout", FR_TYPE_TIMEVAL, rlm_radius_t, connection_timeout),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("reconnect_delay", FR_TYPE_TIMEVAL, rlm_radius_t, reconnection_delay),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIMEVAL, rlm_radius_t, idle_timeout),
	  .dflt = STRINGIFY(300) },

	{ FR_CONF_OFFSET("zombie_period", FR_TYPE_TIMEVAL, rlm_radius_t, zombie_period),
	  .dflt = STRINGIFY(40) },

	CONF_PARSER_TERMINATOR
};

/*
 *	Retransmission intervals for the packets we support.
 */
static CONF_PARSER auth_config[] = {
	{ FR_CONF_OFFSET("initial_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCESS_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("maximum_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCESS_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("maximum_retransmission_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCESS_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("maximum_retransmission_duration", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCESS_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER acct_config[] = {
	{ FR_CONF_OFFSET("initial_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCOUNTING_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("maximum_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCOUNTING_REQUEST].mrt), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("maximum_retransmission_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCOUNTING_REQUEST].mrc), .dflt = STRINGIFY(1) },
	{ FR_CONF_OFFSET("maximum_retransmission_duration", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_ACCOUNTING_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER status_config[] = {
	{ FR_CONF_OFFSET("initial_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_STATUS_SERVER].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("maximum_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_STATUS_SERVER].mrt), .dflt = STRINGIFY(10) },
	{ FR_CONF_OFFSET("maximum_retransmission_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_STATUS_SERVER].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("maximum_retransmission_duration", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_STATUS_SERVER].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER coa_config[] = {
	{ FR_CONF_OFFSET("initial_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_COA_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("maximum_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_COA_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("maximum_retransmission_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_COA_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("maximum_retransmission_duration", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_COA_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER disconnect_config[] = {
	{ FR_CONF_OFFSET("initial_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_DISCONNECT_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("maximum_retransmission_time", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_DISCONNECT_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("maximum_retransmission_count", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_DISCONNECT_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("maximum_retransmission_duration", FR_TYPE_UINT32, rlm_radius_t, retry[FR_CODE_DISCONNECT_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};


/*
 *	A mapping of configuration file names to internal variables.
 */
static CONF_PARSER const module_config[] = {
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, rlm_radius_t, io_submodule),
	  .func = transport_parse },

	{ FR_CONF_OFFSET("type", FR_TYPE_UINT32 | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY | FR_TYPE_REQUIRED, rlm_radius_t, types),
	  .func = type_parse },

	{ FR_CONF_OFFSET("replicate", FR_TYPE_BOOL, rlm_radius_t, replicate) },

	{ FR_CONF_OFFSET("synchronous", FR_TYPE_BOOL, rlm_radius_t, synchronous) },

	{ FR_CONF_OFFSET("no_connection_fail", FR_TYPE_BOOL, rlm_radius_t, no_connection_fail) },

	{ FR_CONF_POINTER("status_checks", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) status_checks_config },

	{ FR_CONF_OFFSET("max_connections", FR_TYPE_UINT32, rlm_radius_t, max_connections), .dflt = STRINGIFY(32) },

	{ FR_CONF_OFFSET("max_attributes", FR_TYPE_UINT32, rlm_radius_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) },

	{ FR_CONF_POINTER("connection", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) connection_config },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const type_interval_config[FR_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_REQUEST] = { FR_CONF_POINTER("Access-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) auth_config },

	[FR_CODE_ACCOUNTING_REQUEST] = { FR_CONF_POINTER("Accounting-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) acct_config },
	[FR_CODE_STATUS_SERVER] = { FR_CONF_POINTER("Status-Server", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) status_config },
	[FR_CODE_COA_REQUEST] = { FR_CONF_POINTER("CoA-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) coa_config },
	[FR_CODE_DISCONNECT_REQUEST] = { FR_CONF_POINTER("Disconnect-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) disconnect_config },
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_radius_dict[];
fr_dict_autoload_t rlm_radius_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_proxy_state;
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t rlm_radius_dict_attr[];
fr_dict_attr_autoload_t rlm_radius_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
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
	fr_dict_enum_t const	*type_enum;
	uint32_t		code;

	/*
	 *	Must be the RADIUS module
	 */
	rad_assert(cs && (strcmp(cf_section_name1(cs), "radius") == 0));

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_alias(attr_packet_type, type_str, -1);
	if (!type_enum) {
	invalid_code:
		cf_log_err(ci, "Unknown or invalid RADIUS packet type '%s'", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;

	/*
	 *	Status-Server packets cannot be proxied.
	 */
	if (code == FR_CODE_STATUS_SERVER) {
		cf_log_err(ci, "Invalid setting of 'type = Status-Server'.  Status-Server packets cannot be proxied.");
		return -1;
	}

	if (!code ||
	    (code >= FR_MAX_PACKET_CODE) ||
	    (!type_interval_config[code].name)) goto invalid_code;

	/*
	 *	If we're doing async proxying, push the timers for the
	 *	various packet types.
	 */
	cf_section_rule_push(cs, &type_interval_config[code]);

	memcpy(out, &code, sizeof(code));

	return 0;
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	dl_instance_t	*parent_inst;
	CONF_SECTION	*cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(cs, cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(cs, dl_instance_t, "rlm_radius"));
	rad_assert(parent_inst);

	return dl_instance(ctx, out, transport_cs, parent_inst, name, DL_TYPE_SUBMODULE);
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
	fr_dict_enum_t const	*type_enum;
	uint32_t		code;

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_alias(attr_packet_type, type_str, -1);
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
	    (code >= FR_MAX_PACKET_CODE) ||
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
	if (code == FR_CODE_STATUS_SERVER) return 0;

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
static int status_check_update_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	int			rcode;
	CONF_SECTION		*cs;
	char const		*name2;
	vp_map_t		*head = NULL;

	rad_assert(cf_item_is_section(ci));

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
		vp_tmpl_rules_t	parse_rules = {
			.allow_foreign = true	/* Because we don't know where we'll be called */
		};

		rcode = map_afrom_cs(&head, cs, &parse_rules, &parse_rules, unlang_fixup_update, NULL, 128);
		if (rcode < 0) return -1; /* message already printed */
		if (!head) {
			cf_log_err(cs, "'update' sections cannot be empty");
			return -1;
		}
	}

	/*
	 *	Rely on "bootstrap" to do sanity checks between 'type
	 *	= Access-Request', and 'update' containing passwords.
	 */
	memcpy(out, &head, sizeof(head));

	return 0;
}



/** Free an rlm_radius_link_t
 *
 *  Unlink it from the running list, and remove it from the
 *  transport.
 */
static int mod_link_free(rlm_radius_link_t *link)
{
	fr_dlist_remove(&link->t->running, link);

	/*
	 *	Free the child's request io context.  That will call
	 *	the IO submodules destructor, which will remove it
	 *	from the tracking table, etc.
	 *
	 *	Note that the IO submodule has to set the destructor
	 *	itself...
	 */
	talloc_free(link->request_io_ctx);

	return 0;
}

static void mod_radius_signal(REQUEST *request, void *instance, void *thread, void *ctx,
			      fr_state_signal_t action)
{
	rlm_radius_t const *inst = talloc_get_type_abort_const(instance, rlm_radius_t);
	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
	rlm_radius_link_t *link = talloc_get_type_abort(ctx, rlm_radius_link_t);

	/*
	 *	We've been told we're done.  Clean up.
	 *
	 *	Note that the caller doesn't necessarily need to send
	 *	us the signal, as he can just talloc_free(request).
	 *	But it is more polite to send a signal, and it allows
	 *	the IO modules to do additional debugging if
	 *	necessary.
	 */
	if (action == FR_SIGNAL_CANCEL) {
		talloc_free(link);
		return;
	}

	/*
	 *	We received a duplicate packet, but we're not doing
	 *	synchronous proxying.  Ignore the dup, and rely on the
	 *	IO submodule to time it's own retransmissions.
	 */
	if ((action == FR_SIGNAL_DUP) && !inst->synchronous) return;

	if (!inst->io->signal) return;

	inst->io->signal(request, inst->io_instance, t->thread_io_ctx, link, action);
}


/** Continue after unlang_resumable()
 *
 */
static rlm_rcode_t mod_radius_resume(UNUSED REQUEST *request, UNUSED void *instance, UNUSED void *thread, void *ctx)
{
	rlm_radius_link_t *link = talloc_get_type_abort(ctx, rlm_radius_link_t);
	rlm_rcode_t rcode;

	rcode = link->rcode;
	rad_assert(rcode != RLM_MODULE_YIELD);
	talloc_free(link);

	return rcode;
}

/** Do any RADIUS-layer fixups for proxying.
 *
 */
static void radius_fixups(rlm_radius_t *inst, REQUEST *request)
{
	VALUE_PAIR *vp;

	/*
	 *	Check for proxy loops.
	 */
	if (RDEBUG_ENABLED) {
		fr_cursor_t cursor;

		for (vp = fr_cursor_iter_by_da_init(&cursor, &request->packet->vps, attr_proxy_state);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			if (vp->vp_length != 4) continue;

			if (memcmp(&inst->proxy_state, vp->vp_octets, 4) == 0) {
				RWARN("Possible proxy loop - please check server configuration.");
				break;
			}
		}
	}

	if (request->packet->code != FR_CODE_ACCESS_REQUEST) return;

	/*
	 *	If there is no PW_CHAP_CHALLENGE attribute but
	 *	there is a PW_CHAP_PASSWORD we need to add it
	 *	since we can't use the request->packet request
	 *	authenticator anymore, as the
	 *	request->proxy->packet authenticator is
	 *	different.
	 */
	if (fr_pair_find_by_da(request->packet->vps, attr_chap_password, TAG_ANY) &&
	    !fr_pair_find_by_da(request->packet->vps, attr_chap_challenge, TAG_ANY)) {
	    	MEM(pair_add_request(&vp, attr_chap_challenge) >= 0);
		fr_pair_value_memcpy(vp, request->packet->vector, sizeof(request->packet->vector));
	}
}


/** Send packets outbound.
 *
 */
static rlm_rcode_t CC_HINT(nonnull) mod_process(void *instance, void *thread, REQUEST *request)
{
	rlm_rcode_t rcode;
	rlm_radius_t *inst = instance;
	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
	rlm_radius_link_t *link;

	if (!request->packet->code) {
		RDEBUG("You MUST specify a packet code");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Reserve Status-Server for ourselves, for link-specific
	 *	signaling.
	 */
	if (request->packet->code == FR_CODE_STATUS_SERVER) {
		REDEBUG("Cannot proxy Status-Server packets");
		return RLM_MODULE_FAIL;
	}

	if ((request->packet->code >= FR_MAX_PACKET_CODE) ||
	    !inst->retry[request->packet->code].irt) { /* can't be zero */
		REDEBUG("Invalid packet code %d", request->packet->code);
		return RLM_MODULE_FAIL;
	}

	if (!inst->allowed[request->packet->code]) {
		REDEBUG("Packet code %s is disallowed by the configuration",
		       fr_packet_codes[request->packet->code]);
		return RLM_MODULE_FAIL;
	}

	if (request->client->dynamic && !request->client->active) {
		REDEBUG("Cannot proxy packets which define dynamic clients");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Allocate and fill in the data structure which links
	 *	the request to the IO submodule.
	 */
	link = talloc_zero(request, rlm_radius_link_t);
	if (!link) return RLM_MODULE_FAIL;

	/*
	 *	The submodule needs to track it's own data associated
	 *	with the request.  Allocate that here.  Note that the
	 *	IO submodule has to set the destructor if it so wishes.
	 */
	link->request_io_ctx = talloc_zero_array(link, uint8_t, inst->io->request_inst_size);
	if (!link->request_io_ctx) {
		talloc_free(link);
		return RLM_MODULE_FAIL;
	}
	if (inst->io->request_inst_type) talloc_set_name_const(link->request_io_ctx, inst->io->request_inst_type);

	link->t = t;
	link->request = request;

	link->rcode = RLM_MODULE_FAIL;

	/*
	 *	Do any necessary RADIUS level fixups
	 *	- check Proxy-State
	 *	- do CHAP-Challenge fixups
	 */
	radius_fixups(inst, request);

	fr_dlist_insert_tail(&t->running, link);
	talloc_set_destructor(link, mod_link_free);

	/*
	 *	Push the request and it's link to the IO submodule.
	 *
	 *	This may return YIELD, for "please yield", or it may
	 *	return another code which indicates what happened to
	 *	the request...b
	 */
	rcode = inst->io->push(inst->io_instance, request, link, t->thread_io_ctx);
	if (rcode != RLM_MODULE_YIELD) {
		talloc_free(link);
		return rcode;
	}

	return unlang_module_yield(request, mod_radius_resume, mod_radius_signal, link);
}


/** Bootstrap the module
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf    our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	size_t i, num_types;
	uint32_t num_connections;
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	FR_TIMEVAL_BOUND_CHECK("connection.connect_timeout", &inst->connection_timeout, >=, 1, 0);
	FR_TIMEVAL_BOUND_CHECK("connection.connect_timeout", &inst->connection_timeout, <=, 30, 0);

	FR_TIMEVAL_BOUND_CHECK("connection.reconnect_delay", &inst->reconnection_delay, >=, 5, 0);
	FR_TIMEVAL_BOUND_CHECK("connection.reconnect_delay", &inst->reconnection_delay, <=, 300, 0);

	if ((inst->idle_timeout.tv_sec != 0) && (inst->idle_timeout.tv_usec != 0)) {
		FR_TIMEVAL_BOUND_CHECK("connection.idle_timeout", &inst->idle_timeout, >=, 5, 0);
	}
	FR_TIMEVAL_BOUND_CHECK("connection.idle_timeout", &inst->idle_timeout, <=, 600, 0);

	FR_TIMEVAL_BOUND_CHECK("connection.zombie_period", &inst->zombie_period, >=, 1, 0);
	FR_TIMEVAL_BOUND_CHECK("connection.zombie_period", &inst->zombie_period, <=, 120, 0);

	num_types = talloc_array_length(inst->types);
	rad_assert(num_types > 0);

	/*
	 *	Allow for O(1) lookup later...
	 */
	for (i = 0; i < num_types; i++) {
		uint32_t code;

		code = inst->types[i];
		rad_assert(code > 0);
		rad_assert(code < FR_MAX_PACKET_CODE);

		inst->allowed[code] = 1;
	}

	rad_assert(inst->status_check < FR_MAX_PACKET_CODE);

	/*
	 *	If we have status_check = packet, then 'packet' MUST either be
	 *	Status-Server, or it MUST be one of the allowed packet types for this connection.
	 */
	if (inst->status_check && inst->status_check != FR_CODE_STATUS_SERVER) {
		if (!inst->allowed[inst->status_check]) {
			cf_log_err(conf, "Using 'status_check = %s' requires also 'type = %s'",
				   fr_packet_codes[inst->status_check], fr_packet_codes[inst->status_check]);
			return -1;
		}

		/*
		 *	@todo - check the contents of the "update"
		 *	section, to be sure that (e.g.) Access-Request
		 *	contains User-Name, etc.
		 */
	}

	/*
	 *	If we're replicating, we don't care if the other end
	 *	is alive.
	 */
	if (inst->replicate && inst->status_check) {
		cf_log_warn(conf, "Ignoring 'status_check = %s' due to 'replicate = true'",
			    fr_packet_codes[inst->status_check]);
		inst->status_check = 0;
	}

	/*
	 *	Don't sanity check the async timers if we're doing
	 *	synchronous proxying.
	 */
	if (inst->synchronous) goto setup_io_submodule;

	/*
	 *	Set limits on retransmission timers
	 */
	if (inst->allowed[FR_CODE_ACCESS_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("Access-Request.initial_retransmission_time", inst->retry[FR_CODE_ACCESS_REQUEST].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("Access-Request.maximum_retransmission_time", inst->retry[FR_CODE_ACCESS_REQUEST].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("Access-Request.maximum_retransmission_count", inst->retry[FR_CODE_ACCESS_REQUEST].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("Access-Request.maximum_retransmission_duration", inst->retry[FR_CODE_ACCESS_REQUEST].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("Access-Request.initial_retransmission_time", inst->retry[FR_CODE_ACCESS_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Access-Request.maximum_retransmission_time", inst->retry[FR_CODE_ACCESS_REQUEST].mrt, <=, 30);
		FR_INTEGER_BOUND_CHECK("Access-Request.maximum_retransmission_count", inst->retry[FR_CODE_ACCESS_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Access-Request.maximum_retransmission_duration", inst->retry[FR_CODE_ACCESS_REQUEST].mrd, <=, 30);
	}

	/*
	 *	Note that RFC 5080 allows for Accounting-Request to
	 *	have mrt=mrc=mrd = 0, which means "retransmit
	 *	forever".  We allow that, with the restriction that
	 *	the server core will automatically free the request at
	 *	max_request_time.
	 */
	if (inst->allowed[FR_CODE_ACCOUNTING_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("Accounting-Request.initial_retransmission_time", inst->retry[FR_CODE_ACCOUNTING_REQUEST].irt, >=, 1);
#if 0
		FR_INTEGER_BOUND_CHECK("Accounting-Request.maximum_retransmission_time", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.maximum_retransmission_count", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrc, >=, 0);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.maximum_retransmission_duration", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrd, >=, 0);
#endif

		FR_INTEGER_BOUND_CHECK("Accounting-Request.initial_retransmission_time", inst->retry[FR_CODE_ACCOUNTING_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.maximum_retransmission_time", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrt, <=, 30);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.maximum_retransmission_count", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.maximum_retransmission_duration", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrd, <=, 30);
	}

	/*
	 *	Status-Server
	 */
	if (inst->allowed[FR_CODE_STATUS_SERVER]) {
		FR_INTEGER_BOUND_CHECK("Status-Server.initial_retransmission_time", inst->retry[FR_CODE_STATUS_SERVER].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("Status-Server.maximum_retransmission_time", inst->retry[FR_CODE_STATUS_SERVER].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("Status-Server.maximum_retransmission_count", inst->retry[FR_CODE_STATUS_SERVER].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("Status-Server.maximum_retransmission_duration", inst->retry[FR_CODE_STATUS_SERVER].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("Status-Server.initial_retransmission_time", inst->retry[FR_CODE_STATUS_SERVER].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Status-Server.maximum_retransmission_time", inst->retry[FR_CODE_STATUS_SERVER].mrt, <=, 30);
		FR_INTEGER_BOUND_CHECK("Status-Server.maximum_retransmission_count", inst->retry[FR_CODE_STATUS_SERVER].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Status-Server.maximum_retransmission_duration", inst->retry[FR_CODE_STATUS_SERVER].mrd, <=, 30);
	}

	/*
	 *	CoA
	 */
	if (inst->allowed[FR_CODE_COA_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("CoA-Request.initial_retransmission_time", inst->retry[FR_CODE_COA_REQUEST].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("CoA-Request.maximum_retransmission_time", inst->retry[FR_CODE_COA_REQUEST].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("CoA-Request.maximum_retransmission_count", inst->retry[FR_CODE_COA_REQUEST].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("CoA-Request.maximum_retransmission_duration", inst->retry[FR_CODE_COA_REQUEST].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("CoA-Request.initial_retransmission_time", inst->retry[FR_CODE_COA_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("CoA-Request.maximum_retransmission_time", inst->retry[FR_CODE_COA_REQUEST].mrt, <=, 60);
		FR_INTEGER_BOUND_CHECK("CoA-Request.maximum_retransmission_count", inst->retry[FR_CODE_COA_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("CoA-Request.maximum_retransmission_duration", inst->retry[FR_CODE_COA_REQUEST].mrd, <=, 30);
	}

	/*
	 *	Disconnect
	 */
	if (inst->allowed[FR_CODE_DISCONNECT_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.initial_retransmission_time", inst->retry[FR_CODE_DISCONNECT_REQUEST].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.maximum_retransmission_time", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.maximum_retransmission_count", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.maximum_retransmission_duration", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("Disconnect-Request.initial_retransmission_time", inst->retry[FR_CODE_DISCONNECT_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.maximum_retransmission_time", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrt, <=, 30);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.maximum_retransmission_count", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.maximum_retransmission_duration", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrd, <=, 30);
	}

setup_io_submodule:
	inst->io = (fr_radius_client_io_t const *) inst->io_submodule->module->common;
	inst->io_instance = inst->io_submodule->data;
	inst->io_conf = inst->io_submodule->conf;

	rad_assert(inst->io->thread_inst_size > 0);
	rad_assert(inst->io->bootstrap != NULL);
	rad_assert(inst->io->instantiate != NULL);

	/*
	 *	Get random Proxy-State identifier for this module.
	 */
	inst->proxy_state = fr_rand();

	FR_INTEGER_BOUND_CHECK("max_connections", inst->max_connections, >=, 2);
	FR_INTEGER_BOUND_CHECK("max_connections", inst->max_connections, <=, 1024);

	num_connections = 0;
	store(inst->num_connections, num_connections);

	/*
	 *	Bootstrap the submodule.
	 */
	if (inst->io->bootstrap(inst->io_instance, inst->io_conf) < 0) {
		cf_log_err(inst->io_conf, "Bootstrap failed for \"%s\"",
			   inst->io->name);
		return -1;
	}

	return 0;
}


/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf	our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);

	if (inst->io->instantiate(inst, inst->io_instance, inst->io_conf) < 0) {
		cf_log_err(inst->io_conf, "Instantiate failed for \"%s\"",
			   inst->io->name);
		return -1;
	}

	return 0;
}

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);
	rlm_radius_thread_t *t = thread;

	(void) talloc_set_type(t, rlm_radius_thread_t);

	t->inst = instance;
	t->el = el;

	fr_dlist_init(&t->running, rlm_radius_link_t, entry);

	/*
	 *	Allocate thread-specific data.  The connections should
	 *	live here.
	 */
	t->thread_io_ctx = talloc_zero_array(t, uint8_t, inst->io->thread_inst_size);
	if (!t->thread_io_ctx) {
		return -1;
	}

	/*
	 *	Instantiate the per-thread data.  This should open up
	 *	sockets, set timers, etc.
	 */
	if (inst->io->thread_instantiate(inst->io_conf, inst->io_instance, el, t->thread_io_ctx) < 0) {
		return -1;
	}

	return 0;
}


/** Destroy thread data for the submodule.
 *
 */
static int mod_thread_detach(fr_event_list_t *el, void *thread)
{
	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
	rlm_radius_t const *inst = t->inst;

	/*
	 *	Tell the submodule to shut down all of its
	 *	connections.
	 */
	if (inst->io->thread_detach &&
	    (inst->io->thread_detach(el, t->thread_io_ctx) < 0)) {
		return -1;
	}

	/*
	 *	The scheduler MUST be destroyed before this modules
	 *	thread memory is freed.  That ordering ensures that
	 *	all of the requests for a worker thread are forcibly
	 *	marked DONE, and (in an ideal world) resumed / cleaned
	 *	up before this memory is freed.
	 */
	if (fr_dlist_head(&t->running) != NULL) {
		ERROR("Module still has running requests!");
		return -1;
	}

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
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern rad_module_t rlm_radius;
rad_module_t rlm_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.type		= RLM_TYPE_THREAD_SAFE | RLM_TYPE_RESUMABLE,
	.inst_size	= sizeof(rlm_radius_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.load		= mod_load,
	.unload		= mod_unload,

	.thread_inst_size = sizeof(rlm_radius_thread_t),
	.thread_instantiate = mod_thread_instantiate,
	.thread_detach	= mod_thread_detach,
	.methods = {
		[MOD_PREACCT]		= mod_process,
		[MOD_ACCOUNTING]	= mod_process,
		[MOD_AUTHORIZE]		= mod_process,
		[MOD_AUTHENTICATE]     	= mod_process,
	},
};
