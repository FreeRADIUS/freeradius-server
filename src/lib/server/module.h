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
 * @brief Interface to the RADIUS module system.
 *
 * @copyright 2013 The FreeRADIUS server project
 */
RCSIDH(modules_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rad_module_s module_t;
typedef struct rad_module_method_names_s module_method_names_t;
typedef struct module_instance_s module_instance_t;
typedef struct module_thread_instance_s  module_thread_instance_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/cf_parse.h>
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

extern fr_table_num_sorted_t const mod_rcode_table[];
extern size_t mod_rcode_table_len;

/** Mappings between section names, and control attributes
 *
 * Defined in module.c.
 */
extern const char *section_type_value[MOD_COUNT];

#define RLM_TYPE_THREAD_SAFE	(0 << 0) 	//!< Module is threadsafe.
#define RLM_TYPE_THREAD_UNSAFE	(1 << 0) 	//!< Module is not threadsafe.
						//!< Server will protect calls
						//!< with mutex.
#define RLM_TYPE_RESUMABLE     	(1 << 2) 	//!< does yield / resume

/** Module section callback
 *
 * Is called when the module is listed in a particular section of a virtual
 * server, and the request has reached the module call.
 *
 * @param[in] instance		data, specific to an instantiated module.
 *				Pre-allocated, and populated during the
 *				bootstrap and instantiate calls.
 * @param[in] thread		data specific to this module instance.
 * @param[in] request		to process.
 * @return the appropriate rcode.
 */
typedef rlm_rcode_t (*module_method_t)(void *instance, void *thread, REQUEST *request);

/** Module instantiation callback
 *
 * Is called once per module instance. Is not called when new threads are
 * spawned. See module_thread_instantiate_t for that.
 *
 * @param[in] mod_cs		Module instance's configuration section.
 * @param[in] instance		data, specific to an instantiated module.
 *				Pre-allocated, and populated during the
 *				bootstrap and instantiate calls.
 * @return
 *	- 0 on success.
 *	- -1 if instantiation failed.
 */
typedef int (*module_instantiate_t)(void *instance, CONF_SECTION *mod_cs);

/** Module thread creation callback
 *
 * Called whenever a new thread is created.
 *
 * @param[in] mod_cs		Module instance's configuration section.
 * @param[in] instance		data, specific to an instantiated module.
 *				Pre-allocated, and populated during the
 *				bootstrap and instantiate calls.
 * @param[in] el		The event list serviced by this thread.
 * @param[in] thread		data specific to this module instance.
 * @return
 *	- 0 on success.
 *	- -1 if instantiation failed.
 */
typedef int (*module_thread_instantiate_t)(CONF_SECTION const *mod_cs, void *instance, fr_event_list_t *el, void *thread);

/** Module thread destruction callback
 *
 * Destroy a module/thread instance.
 *
 * @param[in] thread		data specific to this module instance.
 * @return
 *	- 0 on success.
 *	- -1 if instantiation failed.
 */
typedef int (*module_thread_detach_t)(fr_event_list_t *el, void *thread);

#define FR_MODULE_COMMON \
	struct { \
		module_instantiate_t		bootstrap;		\
		module_instantiate_t		instantiate;		\
		int				type;	/* flags */	\
	}

/** Common fields for the interface struct modules export
 *
 */
#define FR_MODULE_THREADED_COMMON \
	struct { \
		module_thread_instantiate_t	thread_instantiate;	\
		module_thread_detach_t		thread_detach;		\
		char const			*thread_inst_type;	\
		size_t				thread_inst_size;	\
	}

/** Common fields for submodules
 *
 * This should either be the first field in the structure exported from
 * the submodule or the submodule should export an identical set of fields
 * in the same order, preferably using the macros above.
 */
struct rad_submodule_s {
	DL_MODULE_COMMON;					//!< Common fields for all loadable modules.
	FR_MODULE_COMMON;					//!< Common fields for all instantiated modules.
	FR_MODULE_THREADED_COMMON;				//!< Common fields for threaded modules.
};

/** Named methods exported by a module
 *
 */
struct rad_module_method_names_s {
	char const	*name1;
	char const	*name2;
	module_method_t	method;
};

#define MODULE_NAME_TERMINATOR { .name1 = NULL }


/** Struct exported by a rlm_* module
 *
 * Determines the capabilities of the module, and maps internal functions
 * within the module to different sections.
 */
struct rad_module_s {
	DL_MODULE_COMMON;					//!< Common fields for all loadable modules.
	FR_MODULE_COMMON;					//!< Common fields for all instantiated modules.
	FR_MODULE_THREADED_COMMON;				//!< Common fields for threaded modules.

	module_method_t			methods[MOD_COUNT];	//!< Pointers to the various section callbacks.
	module_method_names_t const	*method_names;		//!< named methods
	fr_dict_t const			**dict;			//!< pointer to local fr_dict_t*
};

/** Per instance data
 *
 * Per-instance data structure, to correlate the modules with the
 * instance names (may NOT be the module names!), and the per-instance
 * data structures.
 */
struct module_instance_s {
	char const			*name;		//!< Instance name e.g. user_database.

	dl_module_inst_t		*dl_inst;	//!< Structure containing the module's instance data,
							//!< configuration, and dl handle.

	module_t const			*module;	//!< Public module structure.  Cached for convenience.

	pthread_mutex_t			*mutex;		//!< To prevent multiple threads entering a thread unsafe
							///< module.

	size_t				number;		//!< unique module number
	bool				instantiated;	//!< Whether the module has been instantiated yet.

	bool				force;		//!< Force the module to return a specific code.
							//!< Usually set via an administrative interface.

	rlm_rcode_t			code;		//!< Code module will return when 'force' has
							//!< has been set to true.
	bool				in_name_tree;	//!< Whether this is in the name lookup tree.
	bool				in_data_tree;	//!< Whether this is in the data lookup tree.
};

/** Per thread per instance data
 *
 * Stores module and thread specific data.
 */
struct module_thread_instance_s {
	void				*data;		//!< Thread specific instance data.

	fr_event_list_t			*el;		//!< Event list associated with this thread.

	module_t const			*module;	//!< Public module structure.  Cached for convenience,
							///< and to prevent use-after-free if the global data
							///< is freed before the thread instance data.

	void				*mod_inst;	//!< Avoids thread_inst->inst->dl_inst->data.
							///< This is in the hot path, so it makes sense.

	uint64_t			total_calls;	//! total number of times we've been called
	uint64_t			active_callers; //! number of active callers.  i.e. number of current yields
};

/** Map string values to module state method
 *
 */
typedef struct {
	char const			*name;		//!< String identifier for state.
	module_method_t			func;		//!< State function.
} module_state_func_table_t;

/** @name Convenience wrappers around other internal APIs to make them easier to instantiate with modules
 *
 * @{
 */
fr_pool_t	*module_connection_pool_init(CONF_SECTION *module,
					     void *opaque,
					     fr_pool_connection_create_t c,
					     fr_pool_connection_alive_t a,
					     char const *log_prefix,
					     char const *trigger_prefix,
					     VALUE_PAIR *trigger_args);
exfile_t	*module_exfile_init(TALLOC_CTX *ctx,
			     	    CONF_SECTION *module,
				    uint32_t max_entries,
				    uint32_t max_idle,
				    bool locking,
				    char const *trigger_prefix,
				    VALUE_PAIR *trigger_args);
/** @{ */

/** @name Helper functions
 *
 * @{
 */
module_method_t	module_state_str_to_method(module_state_func_table_t const *table,
					   char const *name, module_method_t def);

char const	*module_state_method_to_str(module_state_func_table_t const *table,
					    module_method_t method, char const *def);

bool		module_section_type_set(REQUEST *request, fr_dict_attr_t const *type_da, fr_dict_enum_t const *enumv);

int		module_instance_read_only(TALLOC_CTX *ctx, char const *name);

/** @{ */

/** @name Module and module thread lookup
 *
 * @{
 */
module_instance_t	*module_by_name(module_instance_t const *parent, char const *asked_name);

module_instance_t	*module_by_name_and_method(module_method_t *method, rlm_components_t *component,
						   char const **name1, char const **name2,
						   char const *asked_name);

module_instance_t	*module_by_data(void const *data);

module_thread_instance_t *module_thread(module_instance_t *mi);

module_thread_instance_t *module_thread_by_data(void const *data);
/** @} */

/** @name Module and module thread initialisation and instantiation
 *
 * @{
 */
void		module_free(module_instance_t *mi);

int		modules_init(void);

void		modules_free(void);

int		modules_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el) CC_HINT(nonnull);

int		modules_instantiate(void) CC_HINT(nonnull);

module_instance_t *module_bootstrap(module_instance_t const *parent, CONF_SECTION *cs) CC_HINT(nonnull(2));

int		modules_bootstrap(CONF_SECTION *root) CC_HINT(nonnull);
/** @} */

#ifdef __cplusplus
}
#endif
