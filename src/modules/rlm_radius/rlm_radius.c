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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_radius.h"

static int transport_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);

/*
 *	Define a structure for our module configuration.
 */
typedef struct radius_instance {
	char const		*name;		//!< Module instance name.

	struct timeval		connection_timeout;
	struct timeval		reconnect_delay;
	struct timeval		idle_timeout;

	dl_instance_t		*io_submodule;	//!< As provided by the transport_parse
	fr_radius_client_io_t	*client_io;	//!< Easy access to the client_io handle
	void			*client_io_instance; //!< Easy access to the client_io instance
	CONF_SECTION		*client_io_conf;  //!< Easy access to the client_io's config section
} rlm_radius_t;

static CONF_PARSER const timer_config[] = {
	{ FR_CONF_OFFSET("connection", FR_TYPE_TIMEVAL, rlm_radius_t, connection_timeout),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("reconnect", FR_TYPE_TIMEVAL, rlm_radius_t, reconnect_delay),
	  .dflt = STRINGIFY(5) },

	{ FR_CONF_OFFSET("idle", FR_TYPE_TIMEVAL, rlm_radius_t, idle_timeout),
	  .dflt = STRINGIFY(300) },

	CONF_PARSER_TERMINATOR
};



/*
 *	A mapping of configuration file names to internal variables.
 */
static CONF_PARSER const module_config[] = {
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, rlm_radius_t, io_submodule),
	  .func = transport_parse },

	{ FR_CONF_POINTER("timers", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) timer_config },

	CONF_PARSER_TERMINATOR
};

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

/** Send packets outbound.
 *
 */
static rlm_rcode_t CC_HINT(nonnull) mod_process(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request)
{
//	rlm_radius_t *inst = instance;

	return RLM_MODULE_FAIL;
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
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	FR_TIMEVAL_BOUND_CHECK("timers.connection", &inst->connection_timeout, >=, 1, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.connection", &inst->connection_timeout, <=, 30, 0);

	FR_TIMEVAL_BOUND_CHECK("timers.reconnect", &inst->reconnect_delay, >=, 5, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.reconned", &inst->reconnect_delay, <=, 300, 0);

	FR_TIMEVAL_BOUND_CHECK("timers.idle", &inst->connection_timeout, >=, 30, 0);
	FR_TIMEVAL_BOUND_CHECK("timers.idle", &inst->connection_timeout, <=, 600, 0);

	if (!inst->client_io->bootstrap) return 0;

	if (inst->client_io->bootstrap(inst->client_io_instance, inst->client_io_conf) < 0) {
		cf_log_err(inst->client_io_conf, "Bootstrap failed for \"%s\"",
			   inst->client_io->name);
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

	if (!inst->client_io->instantiate) return 0;

	if (inst->client_io->instantiate(inst->client_io_instance, inst->client_io_conf) < 0) {
		cf_log_err(inst->client_io_conf, "Instantiate failed for \"%s\"",
			   inst->client_io->name);
		return -1;
	}

	return 0;
}

static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_radius_t *inst = talloc_get_type_abort(instance, rlm_radius_t);

	if (inst->client_io->thread_instantiate(inst->client_io_conf, inst->client_io_instance, el, thread) < 0) {
		cf_log_err(inst->client_io_conf, "Thread instantiate failed for \"%s\"",
			   inst->client_io->name);
		return -1;
       }

	// start up one connection
	//
	// add to per-thread data

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
	.thread_instantiate = mod_thread_instantiate,
	.methods = {
		[MOD_PREACCT]		= mod_process,
		[MOD_AUTHENTICATE]     	= mod_process,
	},
};
