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
void		virtual_server_dict_set(CONF_SECTION *server_cs, fr_dict_t const *dict, bool do_free) CC_HINT(nonnull);

fr_dict_t const *virtual_server_dict(CONF_SECTION *server_cs) CC_HINT(nonnull);

int		virtual_server_section_attribute_define(CONF_SECTION *server_cs, char const *subcs_name,
							fr_dict_attr_t const *da) CC_HINT(nonnull);

int		virtual_servers_instantiate(void);

int		virtual_servers_bootstrap(CONF_SECTION *config) CC_HINT(nonnull);

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
CONF_SECTION	*virtual_server_find(char const *name) CC_HINT(nonnull);

CONF_SECTION	*virtual_server_by_child(CONF_SECTION *section) CC_HINT(nonnull);

int		virtual_server_cf_parse(TALLOC_CTX *ctx, void *out, void *parent,
					CONF_ITEM *ci, CONF_PARSER const *rule) CC_HINT(nonnull(2,4));

fr_dict_t const	*virtual_server_namespace(char const *virtual_server) CC_HINT(nonnull);

fr_dict_t const *virtual_server_namespace_by_ci(CONF_ITEM *ci) CC_HINT(nonnull);

int		virtual_server_has_namespace(CONF_SECTION **out,
					     char const *virtual_server, fr_dict_t const *namespace,
					     CONF_ITEM *ci) CC_HINT(nonnull(2,3));
/** @} */
unlang_action_t process_authenticate(rlm_rcode_t *p_result, int auth_type,
				     request_t *request, CONF_SECTION *server_cs) CC_HINT(nonnull);

rlm_rcode_t	virtual_server_process_auth(request_t *request, CONF_SECTION *virtual_server,
					    rlm_rcode_t default_rcode,
					    unlang_module_resume_t resume,
					    unlang_module_signal_t signal, void *rctx) CC_HINT(nonnull);

fr_listen_t *  	listen_find_any(fr_listen_t *li) CC_HINT(nonnull);
bool		listen_record(fr_listen_t *li) CC_HINT(nonnull);


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
	bool			dont_cache;	//!< If true, the CONF_SECTION pointer won't be written
						///< and the offset will be ignored.
	size_t			instruction;	//!< where the instruction pointer is written
	virtual_server_method_t const *methods;	//!< list of module methods which are allowed in this section
} virtual_server_compile_t;

#define COMPILE_TERMINATOR { .name = NULL, .name2 = NULL }

int		virtual_server_section_register(virtual_server_compile_t const *entry) CC_HINT(nonnull);

int		virtual_server_compile_sections(CONF_SECTION *server, virtual_server_compile_t const *list,
						tmpl_rules_t const *rules, void *instance) CC_HINT(nonnull(1,2,3));

virtual_server_method_t const *virtual_server_section_methods(char const *name1, char const *name2) CC_HINT(nonnull(1));

unlang_action_t	virtual_server_push(request_t *request, CONF_SECTION *server_cs, bool top_frame) CC_HINT(nonnull);

int		virtual_server_dynamic_clients_allow(CONF_SECTION *server_cs) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
