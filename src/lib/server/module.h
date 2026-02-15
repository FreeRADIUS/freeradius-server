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

typedef struct module_s				module_t;
typedef struct module_state_func_table_s	module_state_func_table_t;
typedef struct module_method_group_s		module_method_group_t;
typedef struct module_method_binding_s		module_method_binding_t;
typedef struct module_instance_s		module_instance_t;
typedef struct module_thread_instance_s		module_thread_instance_t;
typedef struct module_list_type_s		module_list_type_t;
typedef struct module_list_s			module_list_t;

#include <freeradius-devel/server/module_ctx.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/unlang/interpret.h>

DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	MODULE_TYPE_THREAD_UNSAFE	= (1 << 0), 	//!< Module is not threadsafe.
							//!< Server will protect calls with mutex.
	MODULE_TYPE_RETRY		= (1 << 2), 	//!< can handle retries

	MODULE_TYPE_DYNAMIC_UNSAFE	= (1 << 3)	//!< Instances of this module cannot be
							///< created at runtime.
} module_flags_t;
DIAG_ON(attributes)

/** Module section callback
 *
 * Is called when the module is listed in a particular section of a virtual
 * server, and the request has reached the module call.
 *
 * @param[out] p_result		Result code of the module method.
 * @param[in] mctx		Holds global instance data, thread instance
 *				data and call specific instance data.
 * @param[in] request		to process.
 * @return the appropriate rcode.
 */
typedef unlang_action_t (*module_method_t)(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request);

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

/** Module detach callback
 *
 * Is called just before the server exits, and after re-instantiation on HUP,
 * to free the old module instance.
 *
 * Detach should close all handles associated with the module instance, and
 * free any memory allocated during instantiate.
 *
 * @param[in] inst to free.
 * @return
 *	- 0 on success.
 *	- -1 if detach failed.
 */
typedef int (*module_detach_t)(module_detach_ctx_t const *inst);

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

#include <freeradius-devel/features.h>
#include <freeradius-devel/io/schedule.h>

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/server/pool.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/section.h>

#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/unlang/mod_action.h>

#include <freeradius-devel/util/event.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The maximum size of a module instance
 */
#define MODULE_INSTANCE_LEN_MAX 256

/** Terminate a module binding list
 */
#define MODULE_BINDING_TERMINATOR { .section = NULL }

/** A group of methods exported by a module or added as an overlay
 *
 * Module method groups are organised into a linked list, with each group
 * containing a list of named methods.  This allows common collections of
 * methods to be added to a module.
 *
 * One common use case is adding the `instantiate`, `exists`, and `detach`
 * methods which are added to dynamic modules, and allow dynamic module
 * instances to be created and destroyed at runtime.
 */
struct module_method_group_s {
	module_method_binding_t			*bindings;		//!< named methods

	bool					validated;		//!< Set to true by #module_method_group_validate.
	module_method_group_t			*next;			//!< Next group in the list.
};

/** Named methods exported by a module
 *
 */
struct module_method_binding_s {
	section_name_t const			*section;		//!< Identifier for a section.

	module_method_t				method;			//!< Module method to call
	call_env_method_t const			*method_env;		//!< Method specific call_env.

	size_t					rctx_size;		//!< If set, this overrides the module_t rctx_size.
									///< Instructs the module instruction to pre-allocate
									///< an rctx (available in mctx->rctx) before the module
									///< method is called.
	char const				*rctx_type;		//!< If rctx_size is used from the mmb, this sets the
									///< type of the rctx.

	fr_dlist_head_t				same_name1;		//!< List of bindings with the same name1.  Only initialised
									///< for the the first name1 binding.
									///< DO NOT INITIALISE IN THE MODULE.
	fr_dlist_t				entry;			//!< Linked list of bindings with the same name1.
									///< Allows us to more quickly iterate over all
									///< name2 entries after finding a matching name1.
									///< This is also temporarily used to verify the ordering
									///< of name bindings.
									///< DO NOT INITIALISE IN THE MODULE.
};

/** Struct exported by a rlm_* module
 *
 * Determines the capabilities of the module, and maps internal functions
 * within the module to different sections.
 */
struct module_s {
	DL_MODULE_COMMON;					//!< Common fields for all loadable modules.

	conf_parser_t const		*config;		//!< How to convert a CONF_SECTION to a module instance.
	fr_dict_t const			**dict;			//!< _required_ dictionary for this module.

	size_t				boot_size;		//!< Size of the module's bootstrap data.
	char const			*boot_type;		//!< talloc type to assign to bootstrap data.

	size_t				inst_size;		//!< Size of the module's instance data.
	char const			*inst_type;		//!< talloc type to assign to instance data.

	module_instantiate_t		bootstrap;		//!< Callback to allow the module to register any global
								///< resources like xlat functions and attributes.
								///< Instance data is read only during the bootstrap phase
								///< and MUST NOT be modified.
								///< Any attributes added during this phase that the module
								///< need to be re-resolved during the instantiation phase
								///< so that dynamic modules (which don't run bootstrap)
								///< work correctly.
								///< @note Not modifying the instance data is not just a
								///< suggestion, if you try, you'll generate a SIGBUS
								///< or SIGSEGV and it won't be obvious why.

	module_instantiate_t		instantiate;		//!< Callback to allow the module to register any
								///< per-instance resources like sockets and file handles.
								///< After instantiate completes the module instance data
								///< is mprotected to prevent modification.

	module_detach_t			detach;			//!< Clean up module resources from the instantiation pahses.

	module_detach_t			unstrap;		//!< Clean up module resources from both the bootstrap phase.

	module_flags_t			flags;			//!< Flags that control how a module starts up and how
								///< a module is called.

	module_thread_instantiate_t	thread_instantiate;	//!< Callback to populate a new module thread instance data.
								///< Called once per thread.
	module_thread_detach_t		thread_detach;		//!< Callback to free thread-specific resources associated
								///!< with a module.

	size_t				thread_inst_size;	//!< Size of the module's thread-specific instance data.
	char const			*thread_inst_type;	//!< talloc type to assign to thread instance data.

	size_t				rctx_size;		//!< Size of the module's thread-specific data.
	char const			*rctx_type;		//!< talloc type to assign to thread instance data.
};

#define TALLOCED_TYPE(_field, _ctype) \
	._field##_size = sizeof(_ctype), ._field##_type = #_ctype

#define MODULE_BOOT(_ctype) TALLOCED_TYPE(boot, _ctype)
#define MODULE_INST(_ctype) TALLOCED_TYPE(inst, _ctype)
#define MODULE_THREAD_INST(_ctype) TALLOCED_TYPE(thread_inst, _ctype)
#define MODULE_RCTX(_ctype) TALLOCED_TYPE(rctx, _ctype)

/** What state the module instance is currently in
 *
 */
DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) {
	MODULE_INSTANCE_BOOTSTRAPPED		= (1 << 1),	//!< Module instance has been bootstrapped, but not
								///< yet instantiated.
	MODULE_INSTANCE_INSTANTIATED		= (1 << 2),	//!< Module instance has been bootstrapped and
								///< instantiated.
	MODULE_INSTANCE_NO_THREAD_INSTANTIATE	= (1 << 3)	//!< Not set internally, but can be used to prevent
								///< thread instantiation for certain modules.
} module_instance_state_t;
DIAG_ON(attributes)

typedef struct {
	TALLOC_CTX 			*ctx;		//!< ctx data is allocated in.
	void				*start;		//!< Start address which may be passed to mprotect.
	size_t 				len;		//!< How much data we need mprotect to protect.
} module_data_pool_t;

/** Module instance data
 *
 * Per-module-instance data structure to correlate the modules with the
 * instance names (may NOT be the module names!), and the per-instance
 * data structures.
 */
struct module_instance_s {
       /** @name Fields that are most frequently accessed at runtime
	*
	* Putting them first gives us the greatest chance of the pointers being prefetched.
	* @{
	*/
	void				*data;		//!< Module's instance data.  This is most
							///< frequently accessed, so comes first.

	void				*boot;		//!< Data allocated during the boostrap phase

	module_t			*exported;	//!< Public module structure.  Cached for convenience.
							///< This exports module methods, i.e. the functions
							///< which allow the module to perform actions.
							///< This is an identical address to module->common,
							///< but with a different type, containing additional
							///< instance callbacks to make it easier to use.

	pthread_mutex_t			mutex;		//!< Used prevent multiple threads entering a thread
							///< unsafe module simultaneously.

	dl_module_t			*module;	//!< Dynamic loader handle.  Contains the module's
							///< dlhandle, and the functions it exports.
							///< The dl_module is reference counted so that it
							///< can be freed automatically when the last instance
							///< is freed.  This will also (usually) unload the
							///< .so or .dylib.
	/** @} */

	/** @name Return code overrides
	 * @{
 	 */
	bool				force;		//!< Force the module to return a specific code.
							//!< Usually set via an administrative interface.

	rlm_rcode_t			code;		//!< Code module will return when 'force' has
							//!< has been set to true.

	unlang_mod_actions_t       	actions;	//!< default actions and retries.
	/** @} */

       /** @name Allow module instance data to be resolved by name or data, and to get back to the module list
	* @{
	*/
	module_list_t			*ml;		//!< Module list this instance belongs to.
	fr_rb_node_t			name_node;	//!< Entry in the name tree.
	fr_rb_node_t			data_node;	//!< Entry in the data tree.
	uint32_t			number;		//!< Unique module number.  Used to assign a stable
							///< number to each module instance.
	/** @} */

       /** @name These structures allow mprotect to protect/unprotest bootstrap and instance data
	* @{
	*/
	module_data_pool_t		inst_pool;	//!< Data to allow mprotect state toggling
							///< for instance data.
	module_data_pool_t		boot_pool;	//!< Data to allow mprotect state toggling
							///< for bootstrap data.
	/** @} */

       /** @name Module instance state
	* @{
	*/
	module_instance_state_t		state;		//!< What's been done with this module so far.
	CONF_SECTION			*conf;		//!< Module's instance configuration.
	/** @} */

       /** @name Misc fields
	* @{
	*/
	char const			*name;		//!< Instance name e.g. user_database.

	module_instance_t const		*parent;	//!< Parent module's instance (if any).

	void				*uctx;		//!< Extra data passed to module_instance_alloc.
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

	module_instance_t		*mi;		//!< As opposed to the thread local inst.

	uint64_t			total_calls;	//! total number of times we've been called
	uint64_t			active_callers; //! number of active callers.  i.e. number of current yields
};

/** Callback to retrieve thread-local data for a module
 *
 * This is public for performance reasons, and should be called through
 * #module_thread.
 *
 * @param[in] mi	to add data to (use mi->ml for the module list).
 * @return
 *	- NULL if no data exists.
 *	- Pointer to the data on success.
 */
typedef module_thread_instance_t *(*module_list_thread_data_get_t)(module_instance_t const *mi);

/** A list of modules
 *
 * This used to be a global structure, but was move to a struct.
 *
 * Module lists allow collections of modules to be created.  The module lists themselves can be configured
 * to be thread-local or global, with optional runtime write protection.
 *
 * Thread-local module lists are used for dynamic modules, i.e. those created at runtime, where as the
 * global module lists are used for backend modules, listeners, and process state machines.
 */
struct module_list_s
{
	char const			*name;			//!< Friendly list identifier.
	module_instance_state_t		mask;			//!< Prevent phases from being executed.

	uint32_t			last_number;		//!< Last identifier assigned to a module instance.
	fr_rb_tree_t			*name_tree;		//!< Modules indexed by name.
	fr_rb_tree_t			*data_tree;		//!< Modules indexed by data.
	fr_heap_t			*inst_heap;		//!< Heap of module instances.

	bool				write_protect;		//!< If true, pages containing module boot or
								///< instance data will be write protected after
								///< bootstrapping and instantiation is complete,
								///< to prevent accidental modification.

	/** @name Callbacks to manage thread-specific data
	 *
	 * In "child" lists, which are only operating in a single thread, we don't need
	 * to use true thread-local data, because the module list itself is thread-local.
	 *
	 * In that case these callbacks hang memory off of the list itself.
	 *
	 * In the main module list, which is shared between threads, these callbacks
	 * do use true thread-local data, to manage the module_thread_instance_t
	 * on a per thread-basis.
	 *
	 * @{
 	 */
	module_list_type_t const	*type;			//!< Type of module list.
	module_list_thread_data_get_t	thread_data_get; 	//!< Callback to get thread-specific data.
								///< Copy of type->thread_data_get.
	/** @} */
};

/** Map string values to module state method
 *
 */
struct module_state_func_table_s {
	char const			*name;			//!< String identifier for state.
	module_method_t			func;			//!< State function.
};

/** @name Callbacks for the conf_parser_t
 *
 * @{
 */
int			module_submodule_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
					       CONF_ITEM *ci, UNUSED conf_parser_t const *rule) CC_HINT(warn_unused_result);
/** @} */

/** @name Debugging functions
 *
 * @{
 */
void module_instance_debug(module_instance_t const *mi) CC_HINT(nonnull);

void module_list_debug(module_list_t const *ml) CC_HINT(nonnull);
 /** @} */

/** @name Toggle protection on module instance data
 *
 * This is used for module lists which implement additional instantiation phases
 * (like li->open).  It should NOT be used by modules to hack around instance
 * data being read-only after instantiation completes.
 *
 * @{
 */
int			module_instance_data_protect(module_instance_t *mi);

int			module_instance_data_unprotect(module_instance_t *mi);
 /** @} */

/** @name Module and module thread lookup
 *
 * @{
 */
fr_slen_t		module_instance_name_from_conf(char const **name, CONF_SECTION *conf);

int 			module_instance_conf_parse(module_instance_t *mi, CONF_SECTION *conf);

char const 		*module_instance_root_prefix_str(module_instance_t const *mi) CC_HINT(nonnull) CC_HINT(warn_unused_result);

module_instance_t	*module_instance_root(module_instance_t const *child); CC_HINT(warn_unused_result)

module_instance_t	*module_instance_by_name(module_list_t const *ml, module_instance_t const *parent, char const *asked_name)
			CC_HINT(nonnull(1,3)) CC_HINT(warn_unused_result);

module_instance_t	*module_instance_by_data(module_list_t const *ml, void const *data) CC_HINT(warn_unused_result);

/** Retrieve module/thread specific instance for a module
 *
 * @param[in] mi	to find thread specific data for.
 * @return
 *	- Thread specific instance data on success.
 *	- NULL if module has no thread instance data.
 */
static inline CC_HINT(warn_unused_result) CC_HINT(always_inline)
module_thread_instance_t *module_thread(module_instance_t const *mi)
{
	return mi->ml->thread_data_get(mi);
}

module_thread_instance_t *module_thread_by_data(module_list_t const *ml, void const *data) CC_HINT(warn_unused_result);
/** @} */

/** @name Module and module thread initialisation and instantiation
 *
 * @{
 */
void 			modules_thread_detach(module_list_t *ml);

int 			module_thread_instantiate(TALLOC_CTX *ctx, module_instance_t *mi, fr_event_list_t *el)
			CC_HINT(nonnull) CC_HINT(warn_unused_result);

int			modules_thread_instantiate(TALLOC_CTX *ctx, module_list_t const *ml, fr_event_list_t *el)
			CC_HINT(nonnull) CC_HINT(warn_unused_result);

int			module_instantiate(module_instance_t *mi) CC_HINT(nonnull) CC_HINT(warn_unused_result);

int			modules_instantiate(module_list_t const *ml) CC_HINT(nonnull) CC_HINT(warn_unused_result);

int			module_bootstrap(module_instance_t *mi) CC_HINT(nonnull) CC_HINT(warn_unused_result);

int			modules_bootstrap(module_list_t const *ml) CC_HINT(nonnull) CC_HINT(warn_unused_result);

extern bool const module_instance_allowed_chars[UINT8_MAX + 1];

fr_slen_t		module_instance_name_valid(char const *inst_name) CC_HINT(nonnull);

module_instance_t	*module_instance_copy(module_list_t *dst, module_instance_t const *src, char const *inst_name)
			CC_HINT(nonnull(1,2)) CC_HINT(warn_unused_result);

module_instance_t	*module_instance_alloc(module_list_t *ml,
					       module_instance_t const *parent,
					       dl_module_type_t type, char const *mod_name, char const *inst_name,
					       module_instance_state_t init_state)
					       CC_HINT(nonnull(1)) CC_HINT(warn_unused_result);

void			module_instance_uctx_set(module_instance_t *mi, void *uctx);

/** @name Module list variants
 *
 * These are passed to the module_list_alloc function to allocate lists of different types
 *
 * Global module lists are used for backend modules, listeners, and process state machines.
 *
 * Thread-local lists are usually runtime instantiated variants of modules, or modules that represent client connections.
 *
 * One major difference (from the module's perspective) is that bootstrap is not called for thread-local modules.
 *
 * @{
 */
extern module_list_type_t const module_list_type_global;	//!< Initialise a global module, with thread-specific data.
extern module_list_type_t const module_list_type_thread_local;	//!< Initialise a thread-local module, which is only used in a single thread.
/** @} */

/** @name Control which phases are skipped (if any)
 * @{
 */
bool			module_instance_skip_bootstrap(module_instance_t *mi);

bool			module_instance_skip_instantiate(module_instance_t *mi);

bool			module_instance_skip_thread_instantiate(module_instance_t *mi);

void			module_list_mask_set(module_list_t *ml, module_instance_state_t mask);
/** @} */

module_list_t 		*module_list_alloc(TALLOC_CTX *ctx, module_list_type_t const *type,
					   char const *name, bool write_protect)
					   CC_HINT(nonnull(2,3)) CC_HINT(warn_unused_result);

void			modules_init(char const *lib_dir);
/** @} */

#ifdef __cplusplus
}
#endif
