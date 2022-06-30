#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/module.h
 * @brief Interface to the FreeRADIUS module system.
 *
 * @copyright 2022 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 The FreeRADIUS server project
 */
RCSIDH(modules_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/module_ctx.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/compile.h>
#include <freeradius-devel/util/event.h>

typedef struct module_s				module_t;
typedef struct module_method_name_s		module_method_name_t;
typedef struct module_instance_s		module_instance_t;
typedef struct module_thread_instance_s		module_thread_instance_t;
typedef struct module_list_t			module_list_t;

#define MODULE_TYPE_THREAD_SAFE		(0 << 0) 	//!< Module is threadsafe.
#define MODULE_TYPE_THREAD_UNSAFE	(1 << 0) 	//!< Module is not threadsafe.
							//!< Server will protect calls
							//!< with mutex.
#define MODULE_TYPE_RESUMABLE     	(1 << 2) 	//!< does yield / resume

#define MODULE_TYPE_RETRY     		(1 << 3) 	//!< can handle retries

/** Module section callback
 *
 * Is called when the module is listed in a particular section of a virtual
 * server, and the request has reached the module call.
 *
 * @param[in] mctx		Holds global instance data, thread instance
 *				data and call specific instance data.
 * @param[in] request		to process.
 * @return the appropriate rcode.
 */
typedef unlang_action_t (*module_method_t)(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request);

/** Module instantiation callback
 *
 * Is called once per module instance. Is not called when new threads are
 * spawned. See module_thread_instantiate_t for that.
 *
 * @param[in] mctx		Holds global instance data.
 * @return
 *	- 0 on success.
 *	- -1 if instantiation failed.
 */
typedef int (*module_instantiate_t)(module_inst_ctx_t const *mctx);

/** Module thread creation callback
 *
 * Called whenever a new thread is created.
 *
 * @param[in] mctx		Holds global instance data, thread instance
 *				data, and the thread-specific event list.
 * @return
 *	- 0 on success.
 *	- -1 if instantiation failed.
 */
typedef int (*module_thread_instantiate_t)(module_thread_inst_ctx_t const *mctx);

/** Module thread destruction callback
 *
 * Destroy a module/thread instance.
 *
 * @param[in] mctx		Holds global instance data, thread instance
 *				data, and the thread-specific event list.
 * @return
 *	- 0 on success.
 *	- -1 if instantiation failed.
 */
typedef int (*module_thread_detach_t)(module_thread_inst_ctx_t const *mctx);

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/components.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/server/pool.h>
#include <freeradius-devel/server/rcode.h>

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/features.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Named methods exported by a module
 *
 */
struct module_method_name_s {
	char const		*name1;			//!< i.e. "recv", "send", "process"
	char const		*name2;			//!< The packet type i.e Access-Request, Access-Reject.

	module_method_t		method;			//!< Module method to call
};

#define MODULE_NAME_TERMINATOR { NULL }

/** Struct exported by a rlm_* module
 *
 * Determines the capabilities of the module, and maps internal functions
 * within the module to different sections.
 */
struct module_s {
	DL_MODULE_COMMON;		//!< Common fields for all loadable modules.

	module_instantiate_t		bootstrap;
	module_instantiate_t		instantiate;
	int				type;	/* flags */
	module_thread_instantiate_t	thread_instantiate;
	module_thread_detach_t		thread_detach;
	char const			*thread_inst_type;
	size_t				thread_inst_size;
};

/** What state the module instance is currently in
 *
 */
typedef enum {
	MODULE_INSTANCE_INIT = 0,
	MODULE_INSTANCE_BOOTSTRAPPED,
	MODULE_INSTANCE_INSTANTIATED
} module_instance_state_t;

/** Per instance data
 *
 * Per-instance data structure, to correlate the modules with the
 * instance names (may NOT be the module names!), and the per-instance
 * data structures.
 */
struct module_instance_s {
	fr_heap_index_t			inst_idx;	//!< Entry in the bootstrap/instantiation heap.
							//!< should be an identical value to the thread-specific
							///< data for this module.

	fr_rb_node_t			name_node;	//!< Entry in the name tree.
	fr_rb_node_t			data_node;	//!< Entry in the data tree.

	module_list_t			*ml;		//!< Module list this instance belongs to.

	uint32_t			number;		//!< Unique module number.

	char const			*name;		//!< Instance name e.g. user_database.

	dl_module_inst_t		*dl_inst;	//!< Structure containing the module's instance data,
							//!< configuration, and dl handle.  This can be used
							///< to access the parsed configuration data for the
							///< module.

	module_t const			*module;	//!< Public module structure.  Cached for convenience.
							///< This exports module methods, i.e. the functions
							///< which allow the module to perform actions.

	pthread_mutex_t			mutex;		//!< Used prevent multiple threads entering a thread
							///< unsafe module simultaneously.

	module_instance_state_t		state;		//!< What's been done with this module so far.

	/** @name Return code overrides
	 * @{
 	 */
	bool				force;		//!< Force the module to return a specific code.
							//!< Usually set via an administrative interface.

	rlm_rcode_t			code;		//!< Code module will return when 'force' has
							//!< has been set to true.

	unlang_actions_t       		actions;	//!< default actions and retries.

	/** @} */
};

/** Per thread per instance data
 *
 * Stores module and thread specific data.
 */
struct module_thread_instance_s {
	fr_heap_index_t			inst_idx;	//!< Entry in the thread-specific bootstrap heap.
							///< Should be an identical value to the global
							///< instance data for the same module.

	void				*data;		//!< Thread specific instance data.

	fr_event_list_t			*el;		//!< Event list associated with this thread.

	module_instance_t const		*mi;		//!< As opposed to the thread local inst.

	uint64_t			total_calls;	//! total number of times we've been called
	uint64_t			active_callers; //! number of active callers.  i.e. number of current yields
};

/** A list of modules
 *
 * This allows modules to be instantiated and freed in phases,
 * i.e. proto modules before rlm modules.
 */
struct module_list_t {
	uint32_t			last_number;	//!< Last identifier assigned to a module instance.
	char const			*name;		//!< Friendly list identifier.
	fr_rb_tree_t			*name_tree;	//!< Modules indexed by name.
	fr_rb_tree_t			*data_tree;	//!< Modules indexed by data.
};

/** Map string values to module state method
 *
 */
typedef struct {
	char const			*name;		//!< String identifier for state.
	module_method_t			func;		//!< State function.
} module_state_func_table_t;

/** @name Callbacks for the CONF_PARSER
 *
 * @{
 */
int		module_submodule_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
				       CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
/** @} */

/** @name Module and module thread lookup
 *
 * @{
 */
module_instance_t	*module_parent(module_instance_t const *child);

module_instance_t	*module_root(module_instance_t const *child);

module_instance_t	*module_by_name(module_list_t const *ml, module_instance_t const *parent, char const *asked_name)
			CC_HINT(nonnull(1,3));

module_instance_t	*module_by_data(module_list_t const *ml, void const *data);

module_thread_instance_t *module_thread(module_instance_t *mi);

module_thread_instance_t *module_thread_by_data(module_list_t const *ml, void const *data);
/** @} */

/** @name Module and module thread initialisation and instantiation
 *
 * @{
 */
void		module_free(module_instance_t *mi);

void		modules_thread_detach(module_list_t const *ml);

int		modules_thread_instantiate(TALLOC_CTX *ctx, module_list_t const *ml, fr_event_list_t *el) CC_HINT(nonnull);

int		module_instantiate(module_instance_t *mi) CC_HINT(nonnull);

int		modules_instantiate(module_list_t const *ml) CC_HINT(nonnull);

int		module_bootstrap(module_instance_t *mi) CC_HINT(nonnull);

int		modules_bootstrap(module_list_t const *ml) CC_HINT(nonnull);

int		module_conf_parse(module_instance_t *mi, CONF_SECTION *mod_cs) CC_HINT(nonnull);

module_instance_t *module_alloc(module_list_t *ml,
			        module_instance_t const *parent,
			        dl_module_type_t type, char const *mod_name, char const *inst_name)
			        CC_HINT(nonnull(1));

module_list_t	*module_list_alloc(TALLOC_CTX *ctx, char const *name);

void		modules_init(char const *lib_dir);
/** @} */

#ifdef __cplusplus
}
#endif
