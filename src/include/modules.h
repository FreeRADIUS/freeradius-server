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

#include <freeradius-devel/conffile.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/features.h>
#include <freeradius-devel/connection.h>
#include <freeradius-devel/exfile.h>

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
	MOD_SESSION,				//!< 4 methods index for checksimul section.
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
#define RLM_TYPE_HUP_SAFE	(1 << 2) 	//!< Will be restarted on HUP.
						//!< Server will instantiated
						//!< new instance, and then
						//!< destroy old instance.

/** Module section callback
 *
 * Is called when the module is listed in a particular section of a virtual
 * server, and the request has reached the module call.
 *
 * @param[in] instance created in instantiated, holds module config.
 * @param[in,out] request being processed.
 * @return the appropriate rcode.
 */
typedef rlm_rcode_t (*module_method_t)(void *instance, REQUEST *request);

/** Module instantiation callback
 *
 * Is called once per module instance. Is not called when new threads are
 * spawned. Modules that require separate thread contexts should use the
 * connection pool API.
 *
 * @param[in] mod_cs Module instance's configuration section.
 * @param[out] instance Module instance's configuration structure, should be
 *	alloced by by callback and freed by detach.
 * @return
 *	- 0 on success.
 *	- -1 if instantiation failed.
 */
typedef int (*module_instantiate_t)(CONF_SECTION *mod_cs, void *instance);

/** Struct export by a rlm_* module
 *
 * Determines the capabilities of the module, and maps internal functions
 * within the module to different sections.
 */
typedef struct rad_module_t {
	RAD_MODULE_COMMON;

	int			type;			//!< Type flags that control calling conventions for modules.

	module_instantiate_t	bootstrap;		//!< Callback to register dynamic attrs, xlats, etc.
	module_instantiate_t	instantiate;		//!< Callback to configure a new module instance.

	module_method_t		methods[MOD_COUNT];	//!< Pointers to the various section callbacks.
} rad_module_t;

/*
 *	Share connection pool instances between modules
 */
fr_connection_pool_t	*module_connection_pool_init(CONF_SECTION *module,
						     void *opaque,
						     fr_connection_create_t c,
						     fr_connection_alive_t a,
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
int		modules_bootstrap(CONF_SECTION *root) CC_HINT(nonnull);
int		modules_init(CONF_SECTION *root) CC_HINT(nonnull);
int		modules_free(void);
int		modules_hup(CONF_SECTION *modules);

/*
 *	Call various module sections
 */
rlm_rcode_t	process_authorize(int type, REQUEST *request);
rlm_rcode_t	process_authenticate(int type, REQUEST *request);
rlm_rcode_t	process_preacct(REQUEST *request);
rlm_rcode_t	process_accounting(int type, REQUEST *request);
int		process_checksimul(int type, REQUEST *request, int maxsimul);
rlm_rcode_t	process_pre_proxy(int type, REQUEST *request);
rlm_rcode_t	process_post_proxy(int type, REQUEST *request);
rlm_rcode_t	process_post_auth(int type, REQUEST *request);

#ifdef WITH_COA
rlm_rcode_t 	process_recv_coa(int type, REQUEST *request);
rlm_rcode_t	process_send_coa(int type, REQUEST *request);
#  define MODULE_NULL_COA_FUNCS ,NULL,NULL
#else
#  define MODULE_NULL_COA_FUNCS
#endif

int virtual_servers_bootstrap(CONF_SECTION *config);
int virtual_servers_init(CONF_SECTION *config);

/*
 *	In interpreter.h, but here for public consumption.
 */
void unlang_push_section(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action);
rlm_rcode_t unlang_interpret_continue(REQUEST *request);
rlm_rcode_t unlang_interpret(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action);

int unlang_compile(CONF_SECTION *cs, rlm_components_t component);


typedef	void (*fr_unlang_timeout_callback_t)(REQUEST *, void *, void *, struct timeval *);
typedef void (*fr_unlang_fd_callback_t)(REQUEST *, void *, void *, int);

int unlang_event_timeout_add(REQUEST *request, fr_unlang_timeout_callback_t callback,
			     void *inst, void *ctx, struct timeval *when);
int unlang_event_fd_add(REQUEST *request, fr_unlang_fd_callback_t callback,
			void *inst, void *ctx, int fd);
int unlang_event_timeout_delete(REQUEST *request, void *ctx);
int unlang_event_fd_delete(REQUEST *request, void *ctx, int fd);

typedef rlm_rcode_t (*fr_unlang_resume_t)(REQUEST *, void *, void *);
void unlang_resumable(REQUEST *request);
rlm_rcode_t unlang_yield(REQUEST *request, fr_unlang_resume_t callback, void *inst, void *ctx);


#ifdef __cplusplus
}
#endif
#endif /* _FR_MODULES_H */
