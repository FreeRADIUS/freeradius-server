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
#include <freeradius-devel/rad_assert.h>

#include "rlm_radius.h"

static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);
static int type_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

static CONF_PARSER const timer_config[] = {
	{ FR_CONF_OFFSET("connect_timeout", FR_TYPE_TIMEVAL, rlm_radius_t, connection_timeout),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("reconnect_delay", FR_TYPE_TIMEVAL, rlm_radius_t, reconnection_delay),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIMEVAL, rlm_radius_t, idle_timeout),
	  .dflt = STRINGIFY(300) },

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

	{ FR_CONF_OFFSET("replicate", FR_TYPE_BOOL, rlm_radius_t, replicate) },

	{ FR_CONF_OFFSET("type", FR_TYPE_UINT32 | FR_TYPE_MULTI | FR_TYPE_NOT_EMPTY | FR_TYPE_REQUIRED, rlm_radius_t, types),
	  .func = type_parse },

	{ FR_CONF_POINTER("connection", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) timer_config },

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const type_interval_config[FR_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_REQUEST] = { FR_CONF_POINTER("Access-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) auth_config },

	[FR_CODE_ACCOUNTING_REQUEST] = { FR_CONF_POINTER("Accounting-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) acct_config },
	[FR_CODE_STATUS_SERVER] = { FR_CONF_POINTER("Status-Server", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) status_config },
	[FR_CODE_COA_REQUEST] = { FR_CONF_POINTER("CoA-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) coa_config },
	[FR_CODE_DISCONNECT_REQUEST] = { FR_CONF_POINTER("Disconnect-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) disconnect_config },

};


/** Set which types of packets we can parse
 *
 * @param[in] ctx	to allocate data in (instance of rlm_radius).
 * @param[out] out	Where to write the parsed data
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));
	fr_dict_attr_t const	*da;
	fr_dict_enum_t const	*type_enum;
	uint32_t		code;

	/*
	 *	Must be the RADIUS module
	 */
	rad_assert(cs && (strcmp(cf_section_name1(cs), "radius") == 0));

	da = fr_dict_attr_by_name(NULL, "Packet-Type");
	if (!da) {
		ERROR("Missing definiton for Packet-Type");
		return -1;
	}

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_alias(NULL, da, type_str);
	if (!type_enum) {
	invalid_code:
		cf_log_err(ci, "Unknown or invalid RADIUS packet type '%s'", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;

	if (!code ||
	    (code >= FR_MAX_PACKET_CODE) ||
	    (!type_interval_config[code].name)) goto invalid_code;

	cf_section_rule_push(cs, &type_interval_config[code]);

	memcpy(out, &code, sizeof(code));				     

	return 0;
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a dl_instance_t containing the module handle and instance.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
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

/** Free an rlm_radius_link_t
 *
 *  Unlink it from the running list, and remove it from the
 *  transport.
 */
static int mod_link_free(rlm_radius_link_t *link)
{
	fr_dlist_remove(&link->entry);

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
static void radius_fixups(REQUEST *request)
{
	VALUE_PAIR *vp;

	if (request->packet->code != FR_CODE_ACCESS_REQUEST) return;

	/*
	 *	If there is no PW_CHAP_CHALLENGE attribute but
	 *	there is a PW_CHAP_PASSWORD we need to add it
	 *	since we can't use the request->packet request
	 *	authenticator anymore, as the
	 *	request->proxy->packet authenticator is
	 *	different.
	 */
	if (fr_pair_find_by_num(request->packet->vps, 0, FR_CHAP_PASSWORD, TAG_ANY) &&
	    !fr_pair_find_by_num(request->packet->vps, 0, FR_CHAP_CHALLENGE, TAG_ANY)) {
		vp = fr_pair_afrom_num(request->packet, 0, FR_CHAP_CHALLENGE);

		fr_pair_value_memcpy(vp, request->packet->vector, sizeof(request->packet->vector));
		fr_pair_add(&request->packet->vps, vp);
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
		RDEBUG("Cannot proxy Status-Server packets");
		return RLM_MODULE_FAIL;
	}

	if ((request->packet->code >= FR_MAX_PACKET_CODE) ||
	    !inst->retry[request->packet->code].irt) { /* can't be zero */
		RDEBUG("Invalid packet code %d", request->packet->code);
		return RLM_MODULE_FAIL;
	}

	if (!inst->allowed[request->packet->code]) {
		RDEBUG("Packet code %s is disallowed by the configuration",
		       fr_packet_codes[request->packet->code]);
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

	link->request = request;
	fr_dlist_insert_tail(&t->running, &link->entry);

	link->rcode = RLM_MODULE_FAIL;

	/*
	 *	Do any necessary RADIUS level fixups
	 *	- add Proxy-State
	 *	- do CHAP-Challenge fixups
	 */
	radius_fixups(request);

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

	talloc_set_destructor(link, mod_link_free);

	// @todo - add signal / cancellation handler
	return unlang_module_yield(request, mod_radius_resume, NULL, link);
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
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	FR_TIMEVAL_BOUND_CHECK("timers.connect_timeout", &inst->connection_timeout, >=, 1, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.connect_timeout", &inst->connection_timeout, <=, 30, 0);

	FR_TIMEVAL_BOUND_CHECK("timers.reconnect_delay", &inst->reconnection_delay, >=, 5, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.reconnect_delay", &inst->reconnection_delay, <=, 300, 0);

	if ((inst->idle_timeout.tv_sec != 0) && (inst->idle_timeout.tv_usec != 0)) {
		FR_TIMEVAL_BOUND_CHECK("timers.idle_timeout", &inst->idle_timeout, >=, 5, 0);
	}
	FR_TIMEVAL_BOUND_CHECK("timers.idle_timeout", &inst->idle_timeout, <=, 600, 0);

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

	/*
	 *	Set limits on retransmission timers
	 */
	if (inst->allowed[FR_CODE_ACCESS_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("Access-Request.irt", inst->retry[FR_CODE_ACCESS_REQUEST].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("Access-Request.mrt", inst->retry[FR_CODE_ACCESS_REQUEST].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("Access-Request.mrc", inst->retry[FR_CODE_ACCESS_REQUEST].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("Access-Request.mrd", inst->retry[FR_CODE_ACCESS_REQUEST].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("Access-Request.irt", inst->retry[FR_CODE_ACCESS_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Access-Request.mrt", inst->retry[FR_CODE_ACCESS_REQUEST].mrt, <=, 10);
		FR_INTEGER_BOUND_CHECK("Access-Request.mrc", inst->retry[FR_CODE_ACCESS_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Access-Request.mrd", inst->retry[FR_CODE_ACCESS_REQUEST].mrd, <=, 30);
	}
		
	/*
	 *	Note that RFC 5080 allows for Accounting-Request to
	 *	have mrt=mrc=mrd = 0, which means "retransmit
	 *	forever".  We allow that, with the restriction that
	 *	the server core will automatically free the request at
	 *	max_request_time.
	 */
	if (inst->allowed[FR_CODE_ACCOUNTING_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("Accounting-Request.irt", inst->retry[FR_CODE_ACCOUNTING_REQUEST].irt, >=, 1);
#if 0
		FR_INTEGER_BOUND_CHECK("Accounting-Request.mrt", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrt, >=, 0);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.mrc", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrc, >=, 0);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.mrd", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrd, >=, 0);
#endif

		FR_INTEGER_BOUND_CHECK("Accounting-Request.irt", inst->retry[FR_CODE_ACCOUNTING_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.mrt", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrt, <=, 10);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.mrc", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Accounting-Request.mrd", inst->retry[FR_CODE_ACCOUNTING_REQUEST].mrd, <=, 30);
	}

	/*
	 *	Status-Server
	 */
	if (inst->allowed[FR_CODE_STATUS_SERVER]) {
		FR_INTEGER_BOUND_CHECK("Status-Server.irt", inst->retry[FR_CODE_STATUS_SERVER].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("Status-Server.mrt", inst->retry[FR_CODE_STATUS_SERVER].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("Status-Server.mrc", inst->retry[FR_CODE_STATUS_SERVER].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("Status-Server.mrd", inst->retry[FR_CODE_STATUS_SERVER].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("Status-Server.irt", inst->retry[FR_CODE_STATUS_SERVER].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Status-Server.mrt", inst->retry[FR_CODE_STATUS_SERVER].mrt, <=, 10);
		FR_INTEGER_BOUND_CHECK("Status-Server.mrc", inst->retry[FR_CODE_STATUS_SERVER].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Status-Server.mrd", inst->retry[FR_CODE_STATUS_SERVER].mrd, <=, 30);
	}

	/*
	 *	CoA
	 */
	if (inst->allowed[FR_CODE_COA_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("CoA-Request.irt", inst->retry[FR_CODE_COA_REQUEST].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("CoA-Request.mrt", inst->retry[FR_CODE_COA_REQUEST].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("CoA-Request.mrc", inst->retry[FR_CODE_COA_REQUEST].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("CoA-Request.mrd", inst->retry[FR_CODE_COA_REQUEST].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("CoA-Request.irt", inst->retry[FR_CODE_COA_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("CoA-Request.mrt", inst->retry[FR_CODE_COA_REQUEST].mrt, <=, 10);
		FR_INTEGER_BOUND_CHECK("CoA-Request.mrc", inst->retry[FR_CODE_COA_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("CoA-Request.mrd", inst->retry[FR_CODE_COA_REQUEST].mrd, <=, 30);
	}

	/*
	 *	Disconnect
	 */
	if (inst->allowed[FR_CODE_DISCONNECT_REQUEST]) {
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.irt", inst->retry[FR_CODE_DISCONNECT_REQUEST].irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.mrt", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrt, >=, 5);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.mrc", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrc, >=, 1);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.mrd", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrd, >=, 5);

		FR_INTEGER_BOUND_CHECK("Disconnect-Request.irt", inst->retry[FR_CODE_DISCONNECT_REQUEST].irt, <=, 3);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.mrt", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrt, <=, 10);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.mrc", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrc, <=, 10);
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.mrd", inst->retry[FR_CODE_DISCONNECT_REQUEST].mrd, <=, 30);
	}

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

	FR_DLIST_INIT(t->running);

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
static int mod_thread_detach(void *thread)
{
	rlm_radius_thread_t *t = talloc_get_type_abort(thread, rlm_radius_thread_t);
	rlm_radius_t const *inst = t->inst;
	fr_dlist_t *entry;

	/*
	 *	Tell the submodule to shut down all of its
	 *	connections.
	 */
	if (inst->io->thread_detach &&
	    (inst->io->thread_detach(t->thread_io_ctx) < 0)) {
		return -1;
	}

	/*
	 *	The scheduler MUST be destroyed before this modules
	 *	thread memory is freed.  That ordering ensures that
	 *	all of the requests for a worker thread are forcibly
	 *	marked DONE, and (in an ideal world) resumed / cleaned
	 *	up before this memory is freed.
	 */
	entry = FR_DLIST_FIRST(t->running);
	if (entry != NULL) {
		ERROR("Module still has running requests!");
		return -1;
	}

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
extern rad_module_t rlm_radius;
rad_module_t rlm_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius",
	.type		= RLM_TYPE_THREAD_SAFE | RLM_TYPE_RESUMABLE,
	.inst_size	= sizeof(rlm_radius_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,

	.thread_inst_size = sizeof(rlm_radius_thread_t),
	.thread_instantiate = mod_thread_instantiate,
	.thread_detach	= mod_thread_detach,
	.methods = {
		[MOD_PREACCT]		= mod_process,
		[MOD_AUTHENTICATE]     	= mod_process,
	},
};
