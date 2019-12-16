#pragma once
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
 * @file src/lib/server/virtual_servers.h
 * @brief Declarations for functions that parse and manipulate virtual server sections.
 *
 * @copyright 2019 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/util/dict.h>

extern const CONF_PARSER virtual_servers_config[];
extern const CONF_PARSER virtual_servers_on_read_config[];

/** @name Parsing, bootstrap and instantiation
 *
 * @{
 */
int		virtual_server_section_attribute_define(CONF_SECTION *server_cs, char const *subcs_name,
							fr_dict_attr_t const *da);

int		virtual_servers_instantiate(void);

int		virtual_servers_bootstrap(CONF_SECTION *config);

int		virtual_servers_init(CONF_SECTION *config) CC_HINT(nonnull);

int		virtual_servers_free(void);

/** @} */

/** @name Runtime management
 *
 * @{
 */
int		virtual_servers_open(fr_schedule_t *sc);
/** @} */

/** @name Lookup and namespace management
 *
 * @{
 */
typedef int (*fr_virtual_server_compile_t)(CONF_SECTION *server);

CONF_SECTION	*virtual_server_find(char const *name);

CONF_SECTION	*virtual_server_by_child(CONF_SECTION *section);

int		virtual_server_cf_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

int		virtual_namespace_register(char const *namespace,
					   char const *proto_dict, char const *proto_dir,
					   fr_virtual_server_compile_t func);

fr_dict_t	*virtual_server_namespace(char const *virtual_server);

int		virtual_server_has_namespace(CONF_SECTION **out,
					     char const *virtual_server, fr_dict_t const *namespace,
					     CONF_ITEM *ci);
/** @} */

rlm_rcode_t	process_authenticate(int type, REQUEST *request);

rlm_rcode_t	virtual_server_process_auth(REQUEST *request, CONF_SECTION *virtual_server,
					    rlm_rcode_t default_rcode,
					    fr_unlang_module_resume_t resume,
					    fr_unlang_module_signal_t signal, void *rctx);

void		fr_request_async_bootstrap(REQUEST *request, fr_event_list_t *el); /* for unit_test_module */

fr_listen_t *  	listen_find_any(fr_listen_t *li) CC_HINT(nonnull);
bool		listen_record(fr_listen_t *li) CC_HINT(nonnull);

int fr_app_process_bootstrap(CONF_SECTION *server, dl_module_inst_t **type_submodule, CONF_SECTION *conf);
int fr_app_process_instantiate(CONF_SECTION *server, dl_module_inst_t **type_submodule, dl_module_inst_t **type_submodule_by_code, int code_max, CONF_SECTION *conf);


/** Module methods which are allowed in virtual servers.
 *
 */
typedef struct {
	char const		*name;		//!< module method name1 which is allowed in this section
	char const		*name2;		//!< module method name2 which is allowed in this section
} virtual_server_method_t;

/** Processing sections which are allowed in this virtual server.
 *
 */
typedef struct {
	char const		*name;		//!< Name of the processing section, such as "recv" or "send"
	char const		*name2;		//!< Second name, such as "Access-Request"
	rlm_components_t	component;	//!< Sets the default list of actions for this section
	size_t			offset;		//!< where the CONF_SECTION pointer is written
	size_t			instruction;	//!< where the instruction pointer is written
	virtual_server_method_t *methods;	//!< list of module methods which are allowed in this section
} virtual_server_compile_t;

#define COMPILE_TERMINATOR { .name = NULL, .name2 = NULL }

int virtual_server_compile_sections(CONF_SECTION *server, virtual_server_compile_t const *list, vp_tmpl_rules_t const *rules, void *uctx) CC_HINT(nonnull(1,2,3));

int		virtual_server_section_component(rlm_components_t *component, char const *name1, char const *name2);
virtual_server_method_t *virtual_server_section_methods(char const *name1, char const *name2) CC_HINT(nonnull(1));

#ifdef __cplusplus
}
#endif
