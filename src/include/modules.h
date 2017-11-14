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
#ifndef _FR_MODULES_H
#define _FR_MODULES_H
/**
 * $Id$
 *
 * @file include/modules.h
 * @brief Interface to the RADIUS module system.
 *
 * @copyright 2013 The FreeRADIUS server project
 */
RCSIDH(modules_h, "$Id$")

#include <freeradius-devel/cf_parse.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/features.h>
#include <freeradius-devel/pool.h>
#include <freeradius-devel/exfile.h>
#include <freeradius-devel/io/schedule.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The different section components of the server
 *
 * Used as indexes in the methods array in the rad_module_t struct.
 */
typedef enum rlm_components {
	MOD_AUTHENTICATE = 0,			//!< 0 methods index for authenticate section.
	MOD_AUTHORIZE,				//!< 1 methods index for authorize section.
	MOD_PREACCT,				//!< 2 methods index for preacct section.
	MOD_ACCOUNTING,				//!< 3 methods index for accounting section.
	MOD_PRE_PROXY,				//!< 5 methods index for preproxy section.
	MOD_POST_PROXY,				//!< 6 methods index for postproxy section.
	MOD_POST_AUTH,				//!< 7 methods index for postauth section.
#ifdef WITH_COA
	MOD_RECV_COA,				//!< 8 methods index for recvcoa section.
	MOD_SEND_COA,				//!< 9 methods index for sendcoa section.
#endif
	MOD_COUNT				//!< 10 how many components there are.
} rlm_components_t;

extern const FR_NAME_NUMBER mod_rcode_table[];

/** Map a section name, to a section typename, to an attribute number
 *
 * Used by modules.c to define the mappings between names, types and control
 * attributes.
 */
typedef struct section_type_value_t {
	char const      *section;		//!< Section name e.g. "Authorize".
	char const      *typename;		//!< Type name e.g. "Auth-Type".
	int		attr;			//!< Attribute number.
} section_type_value_t;

/** Mappings between section names, typenames and control attributes
 *
 * Defined in modules.c.
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
typedef int (*module_thread_detach_t)(void *thread);

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
void		*module_thread_instance_find(void *inst);
int		modules_thread_instantiate(CONF_SECTION *root, fr_event_list_t *el) CC_HINT(nonnull);
int		modules_instantiate(CONF_SECTION *root) CC_HINT(nonnull);
int		modules_bootstrap(CONF_SECTION *root) CC_HINT(nonnull);
int		modules_free(void);
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

int		virtual_server_section_attribute_define(CONF_SECTION *server_cs, char const *subcs_name,
							fr_dict_attr_t const *da);
int		virtual_servers_open(fr_schedule_t *sc);
int		virtual_servers_instantiate(void);
int		virtual_servers_bootstrap(CONF_SECTION *config);
CONF_SECTION	*virtual_server_find(char const *name);
void		fr_request_async_bootstrap(REQUEST *request, fr_event_list_t *el); /* for unit_test_module */

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
 * @param[in] ctx		a local context for the callback.
 * @param[in] fired		the time the timeout event actually fired.
 */
typedef	void (*fr_unlang_timeout_callback_t)(REQUEST *request, void *instance, void *thread, void *ctx,
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
 * @param[in] ctx		a local context for the callback.
 * @param[in] fd		the file descriptor.
 */
typedef void (*fr_unlang_fd_callback_t)(REQUEST *request, void *instance, void *thread, void *ctx, int fd);

/** A callback for when the request is resumed.
 *
 * The resumed request cannot call the normal "authorize", etc. method.  It needs a separate callback.
 *
 * @param[in] request		the current request.
 * @param[in] instance		The module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] ctx		a local context for the callback.
 * @return a normal rlm_rcode_t.
 */
typedef rlm_rcode_t (*fr_unlang_resume_callback_t)(REQUEST *request, void *instance, void *thread, void *ctx);

/** A callback when the request gets a fr_state_action_t.
 *
 * A module may call unlang_yeild(), but still need to do something on FR_ACTION_DUP.  If so, it's
 * set here.
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * @param[in] request		The current request.
 * @param[in] instance		The module instance.
 * @param[in] thread		data specific to this module instance.
 * @param[in] ctx		for the callback.
 * @param[in] action		which is signalling the request.
 */
typedef void (*fr_unlang_action_t)(REQUEST *request, void *instance, void *thread, void *ctx,
				   fr_state_action_t action);

/*
 *	In unlang_interpret.c, but here for public consumption.
 */
void		unlang_push_section(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t default_action);

rlm_rcode_t	unlang_push_module_xlat(TALLOC_CTX *ctx, fr_value_box_t **out,
					REQUEST *request, xlat_exp_t const *xlat,
					fr_unlang_resume_callback_t callback,
					fr_unlang_action_t signal_callback, void *uctx);

rlm_rcode_t	unlang_interpret_continue(REQUEST *request);

rlm_rcode_t	unlang_interpret(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t default_action);

rlm_rcode_t	unlang_interpret_synchronous(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action);

int		unlang_compile(CONF_SECTION *cs, rlm_components_t component);
int		unlang_compile_subsection(CONF_SECTION *server_cs, char const *name1, char const *name2, rlm_components_t component);

int		unlang_event_timeout_add(REQUEST *request, fr_unlang_timeout_callback_t callback,
					 void const *ctx, struct timeval *timeout);

int 		unlang_event_fd_add(REQUEST *request,
				    fr_unlang_fd_callback_t read,
				    fr_unlang_fd_callback_t write,
				    fr_unlang_fd_callback_t error,
				    void const *ctx, int fd);

int		unlang_event_timeout_delete(REQUEST *request, void const *ctx);

int		unlang_event_fd_delete(REQUEST *request, void const *ctx, int fd);

void		unlang_resumable(REQUEST *request);

void		unlang_signal(REQUEST *request, fr_state_action_t action);

int		unlang_stack_depth(REQUEST *request);

rlm_rcode_t	unlang_module_yield(REQUEST *request, fr_unlang_resume_callback_t callback, fr_unlang_action_t signal_callback,
			     void *ctx);

int		unlang_initialize(void);

#ifdef __cplusplus
}
#endif
#endif /* _FR_MODULES_H */
