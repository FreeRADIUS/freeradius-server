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
 * @file lib/server/modules.h
 * @brief Interface to the RADIUS module system.
 *
 * @copyright 2013 The FreeRADIUS server project
 */
RCSIDH(modules_h, "$Id$")

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/dl.h>
#include <freeradius-devel/features.h>
#include <freeradius-devel/server/pool.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/components.h>
#include <freeradius-devel/unlang/base.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const FR_NAME_NUMBER mod_rcode_table[];

/** Map a section name, to a section typename, to an attribute number
 *
 * Used by module.c to define the mappings between names, types and control
 * attributes.
 */
typedef struct section_type_value_t {
	char const      *section;		//!< Section name e.g. "Authorize".
	char const      *typename;		//!< Type name e.g. "Auth-Type".
	int		attr;			//!< Attribute number.
} section_type_value_t;

/** Mappings between section names, typenames and control attributes
 *
 * Defined in module.c.
 */
extern const section_type_value_t section_type_value[];

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
typedef int (*module_thread_t)(CONF_SECTION const *mod_cs, void *instance, fr_event_list_t *el, void *thread);

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


/** A callback when the the timeout occurs
 *
 * Used when a module needs wait for an event.
 * Typically the callback is set, and then the module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable(), i.e. if an event
 *	on a registered FD occurs before the timeout event fires.
 *
 * @param[in] request		the request.
 * @param[in] instance		the module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] rctx		a local context for the callback.
 * @param[in] fired		the time the timeout event actually fired.
 */
typedef	void (*fr_unlang_module_timeout_t)(REQUEST *request, void *instance, void *thread, void *rctx,
					   struct timeval *fired);

/** A callback when the FD is ready for reading
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable(), so
 *
 * @param[in] request		the current request.
 * @param[in] instance		the module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] rctx		a local context for the callback.
 * @param[in] fd		the file descriptor.
 */
typedef void (*fr_unlang_module_fd_event_t)(REQUEST *request, void *instance, void *thread, void *rctx, int fd);

/** A callback for when the request is resumed.
 *
 * The resumed request cannot call the normal "authorize", etc. method.  It needs a separate callback.
 *
 * @param[in] request		the current request.
 * @param[in] instance		The module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] rctx		a local context for the callback.
 * @return a normal rlm_rcode_t.
 */
typedef rlm_rcode_t (*fr_unlang_module_resume_t)(REQUEST *request, void *instance, void *thread, void *rctx);

/** A callback when the request gets a fr_state_signal_t.
 *
 * A module may call unlang_yeild(), but still need to do something on FR_SIGNAL_DUP.  If so, it's
 * set here.
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * @param[in] request		The current request.
 * @param[in] instance		The module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] rctx		Resume ctx for the callback.
 * @param[in] action		which is signalling the request.
 */
typedef void (*fr_unlang_module_signal_t)(REQUEST *request, void *instance, void *thread,
					  void *rctx, fr_state_signal_t action);

/** Struct exported by a rlm_* module
 *
 * Determines the capabilities of the module, and maps internal functions
 * within the module to different sections.
 */
typedef struct rad_module_t {
	RAD_MODULE_COMMON;

	int			type;			//!< Type flags that control calling conventions for modules.

	module_instantiate_t	bootstrap;		//!< Callback to register dynamic attrs, xlats, etc.
	module_instantiate_t	instantiate;		//!< Callback to configure a new module instance.

	module_thread_t		thread_instantiate;	//!< Callback to configure a module's instance for
							//!< a new worker thread.
	module_thread_detach_t	thread_detach;		//!< Destroy thread specific data.
	size_t			thread_inst_size;	//!< Size of data to allocate to the thread instance.

	module_method_t		methods[MOD_COUNT];	//!< Pointers to the various section callbacks.
} rad_module_t;

/** Per instance data
 *
 * Per-instance data structure, to correlate the modules with the
 * instance names (may NOT be the module names!), and the per-instance
 * data structures.
 */
typedef struct {
	char const			*name;		//!< Instance name e.g. user_database.

	dl_instance_t			*dl_inst;	//!< Structure containing the module's instance data,
							//!< configuration, and dl handle.

	rad_module_t const		*module;	//!< Public module structure.  Cached for convenience.

	pthread_mutex_t			*mutex;

	bool				instantiated;	//!< Whether the module has been instantiated yet.

	bool				force;		//!< Force the module to return a specific code.
							//!< Usually set via an administrative interface.

	rlm_rcode_t			code;		//!< Code module will return when 'force' has
							//!< has been set to true.
} module_instance_t;

/** Per thread per instance data
 *
 * Stores module and thread specific data.
 */
typedef struct {
	void				*data;		//!< Thread specific instance data.

	fr_event_list_t			*el;		//!< Event list associated with this thread.

	rad_module_t const		*module;	//!< Public module structure.  Cached for convenience,
							///< and to prevent use-after-free if the global data
							///< is freed before the thread instance data.

	void				*mod_inst;	//!< Avoids thread_inst->inst->dl_inst->data.
							///< This is in the hot path, so it makes sense.

	uint64_t			total_calls;	//! total number of times we've been called
	uint64_t			active_callers; //! number of active callers.  i.e. number of current yields
} module_thread_instance_t;

/*
 *	Share connection pool instances between modules
 */
fr_pool_t	*module_connection_pool_init(CONF_SECTION *module,
						     void *opaque,
						     fr_pool_connection_create_t c,
						     fr_pool_connection_alive_t a,
						     char const *log_prefix,
						     char const *trigger_prefix,
						     VALUE_PAIR *trigger_args);
exfile_t *module_exfile_init(TALLOC_CTX *ctx,
			     CONF_SECTION *module,
			     uint32_t max_entries,
			     uint32_t max_idle,
			     bool locking,
			     char const *trigger_prefix,
			     VALUE_PAIR *trigger_args);
/*
 *	Create free and destroy module instances
 */
module_thread_instance_t *module_thread_instance_find(module_instance_t *mi);
void		*module_thread_instance_by_data(void *mod_data);
int		modules_thread_instantiate(TALLOC_CTX *ctx, CONF_SECTION *root, fr_event_list_t *el) CC_HINT(nonnull);
int		modules_instantiate(CONF_SECTION *root) CC_HINT(nonnull);
int		modules_bootstrap(CONF_SECTION *root) CC_HINT(nonnull);
int		modules_free(void);
bool		module_section_type_set(REQUEST *request, fr_dict_attr_t const *type_da, fr_dict_enum_t const *enumv);
int		module_instance_read_only(TALLOC_CTX *ctx, char const *name);

/*
 *	Call various module sections
 */
rlm_rcode_t	process_authorize(int type, REQUEST *request);
rlm_rcode_t	process_authenticate(int type, REQUEST *request);
rlm_rcode_t	process_post_proxy(int type, REQUEST *request);
rlm_rcode_t	process_post_auth(int type, REQUEST *request);

#ifdef WITH_COA
#  define MODULE_NULL_COA_FUNCS ,NULL,NULL
#else
#  define MODULE_NULL_COA_FUNCS
#endif

extern const CONF_PARSER virtual_servers_config[];
extern const CONF_PARSER virtual_servers_on_read_config[];

typedef int (*fr_virtual_server_compile_t)(CONF_SECTION *server);

int		virtual_server_section_attribute_define(CONF_SECTION *server_cs, char const *subcs_name,
							fr_dict_attr_t const *da);
int		virtual_servers_open(fr_schedule_t *sc);
int		virtual_servers_instantiate(void);
int		virtual_servers_bootstrap(CONF_SECTION *config);
CONF_SECTION	*virtual_server_find(char const *name);
int		virtual_server_namespace_register(char const *namespace, fr_virtual_server_compile_t func);

void		fr_request_async_bootstrap(REQUEST *request, fr_event_list_t *el); /* for unit_test_module */

/*
 *	unlang_module.c
 */
int		unlang_event_module_timeout_add(REQUEST *request, fr_unlang_module_timeout_t callback,
						void const *ctx, struct timeval *timeout);

int 		unlang_event_fd_add(REQUEST *request,
				    fr_unlang_module_fd_event_t read,
				    fr_unlang_module_fd_event_t write,
				    fr_unlang_module_fd_event_t error,
				    void const *ctx, int fd);

int		unlang_event_timeout_delete(REQUEST *request, void const *ctx);

int		unlang_event_fd_delete(REQUEST *request, void const *ctx, int fd);

rlm_rcode_t	unlang_module_push_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
					REQUEST *request, xlat_exp_t const *xlat,
					fr_unlang_module_resume_t callback,
					fr_unlang_module_signal_t signal_callback, void *uctx);

rlm_rcode_t	unlang_module_yield(REQUEST *request, fr_unlang_module_resume_t callback,
				    fr_unlang_module_signal_t signal_callback, void *ctx);

void		unlang_module_init(void);
#ifdef __cplusplus
}
#endif
