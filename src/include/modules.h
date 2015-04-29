/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 *
 * @file modules.h
 * @brief Interface to the RADIUS module system.
 *
 * @copyright 2013 The FreeRADIUS server project
 */

#ifndef RADIUS_MODULES_H
#define RADIUS_MODULES_H

RCSIDH(modules_h, "$Id$")

#include <freeradius-devel/conffile.h>
#include <freeradius-devel/features.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The different section components of the server
 *
 * Used as indexes in the methods array in the module_t struct.
 */
typedef enum rlm_components {
	MOD_AUTHENTICATE = 0,	//!< 0 methods index for authenticate section.
	MOD_AUTHORIZE,		//!< 1 methods index for authorize section.
	MOD_PREACCT,		//!< 2 methods index for preacct section.
	MOD_ACCOUNTING,		//!< 3 methods index for accounting section.
	MOD_SESSION,		//!< 4 methods index for checksimul section.
	MOD_PRE_PROXY,		//!< 5 methods index for preproxy section.
	MOD_POST_PROXY,		//!< 6 methods index for postproxy section.
	MOD_POST_AUTH,		//!< 7 methods index for postauth section.
#ifdef WITH_COA
	MOD_RECV_COA,		//!< 8 methods index for recvcoa section.
	MOD_SEND_COA,		//!< 9 methods index for sendcoa section.
#endif
	MOD_COUNT		//!< 10 how many components there are.
} rlm_components_t;

extern const FR_NAME_NUMBER mod_rcode_table[];

/** Map a section name, to a section typename, to an attribute number
 *
 * Used by modules.c to define the mappings between names, types and control
 * attributes.
 */
typedef struct section_type_value_t {
	char const      *section;	//!< Section name e.g. "Authorize".
	char const      *typename;	//!< Type name e.g. "Auth-Type".
	int	     attr;		//!< Attribute number.
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


/* Stop people using different module/library/server versions together */
#define RLM_MODULE_INIT RADIUSD_MAGIC_NUMBER

/** Module section callback
 *
 * Is called when the module is listed in a particular section of a virtual
 * server, and the request has reached the module call.
 *
 * @param[in] instance created in instantiated, holds module config.
 * @param[in,out] request being processed.
 * @return the appropriate rcode.
 */
typedef rlm_rcode_t (*packetmethod)(void *instance, REQUEST *request);

/** Module instantiation callback
 *
 * Is called once per module instance. Is not called when new threads are
 * spawned. Modules that require separate thread contexts should use the
 * connection pool API.
 *
 * @param[in] mod_cs Module instance's configuration section.
 * @param[out] instance Module instance's configuration structure, should be
 *		alloced by by callback and freed by detach.
 * @return -1 if instantiation failed, else 0.
 */
typedef int (*instantiate_t)(CONF_SECTION *mod_cs, void *instance);

/** Module detach callback
 *
 * Is called just before the server exits, and after re-instantiation on HUP,
 * to free the old module instance.
 *
 * Detach should close all handles associated with the module instance, and
 * free any memory allocated during instantiate.
 *
 * @param[in] instance to free.
 * @return -1 if detach failed, else 0.
 */
typedef int (*detach_t)(void *instance);

/** Metadata exported by the module
 *
 * This determines the capabilities of the module, and maps internal functions
 * within the module to different sections.
 */
typedef struct module_t {
	uint64_t 		magic;			//!< Used to validate module struct.
	char const		*name;			//!< The name of the module (without rlm_ prefix).
	int			type;			//!< One or more of the RLM_TYPE_* constants.
	size_t			inst_size;		//!< Size of the instance data
	CONF_PARSER const	*config;		//!< Configuration information
	instantiate_t		bootstrap;		//!< register dynamic attrs, etc.
	instantiate_t		instantiate;		//!< Function to use for instantiation.
	detach_t		detach;			//!< Function to use to free module instance.
	packetmethod		methods[MOD_COUNT];	//!< Pointers to the various section functions.
} module_t;

int modules_init(CONF_SECTION *);
int modules_free(void);
int modules_hup(CONF_SECTION *modules);
rlm_rcode_t process_authorize(int type, REQUEST *request);
rlm_rcode_t process_authenticate(int type, REQUEST *request);
rlm_rcode_t module_preacct(REQUEST *request);
rlm_rcode_t process_accounting(int type, REQUEST *request);
int process_checksimul(int type, REQUEST *request, int maxsimul);
rlm_rcode_t process_pre_proxy(int type, REQUEST *request);
rlm_rcode_t process_post_proxy(int type, REQUEST *request);
rlm_rcode_t process_post_auth(int type, REQUEST *request);
#ifdef WITH_COA
rlm_rcode_t process_recv_coa(int type, REQUEST *request);
rlm_rcode_t process_send_coa(int type, REQUEST *request);
#define MODULE_NULL_COA_FUNCS ,NULL,NULL
#else
#define MODULE_NULL_COA_FUNCS
#endif

rlm_rcode_t indexed_modcall(rlm_components_t comp, int idx, REQUEST *request);

/*
 *	For now, these are strongly tied together.
 */
int virtual_servers_load(CONF_SECTION *config);
void virtual_servers_free(time_t when);

#ifdef __cplusplus
}
#endif

#endif /* RADIUS_MODULES_H */
