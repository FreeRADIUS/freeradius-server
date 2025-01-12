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

typedef struct virtual_server_s virtual_server_t;

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/unlang/mod_action.h>
#include <freeradius-devel/util/dict.h>

extern const conf_parser_t virtual_servers_config[];
extern const conf_parser_t virtual_servers_on_read_config[];

/** @name Debug functions
 * @{
 */
void 		virtual_server_listen_debug(void);

void		virtual_server_process_debug(void);
/** @} */

/** @name Resolution functions
 * @{
 */
module_instance_t *virtual_server_listener_by_data(void const *data);
/** @} */

/** @name Callbacks for dealing with transports
 *
 * @{
 */
int virtual_server_listen_transport_parse(TALLOC_CTX *ctx, void *out, void *parent,
					 CONF_ITEM *ci, conf_parser_t const *rule);
/** @} */

/** @name Namespace management
 *
 * @{
 */
fr_dict_t const	*virtual_server_dict_by_name(char const *virtual_server) CC_HINT(nonnull);

fr_dict_t const *virtual_server_dict_by_cs(CONF_SECTION const *server_cs) CC_HINT(nonnull);

fr_dict_t const *virtual_server_dict_by_child_ci(CONF_ITEM const *ci) CC_HINT(nonnull);

int		virtual_server_has_namespace(CONF_SECTION **out,
					     char const *virtual_server, fr_dict_t const *namespace,
					     CONF_ITEM *ci) CC_HINT(nonnull(2,3));
/** @} */

/** @name Lookup and namespace management
 *
 * @{
 */
CONF_SECTION		*virtual_server_cs(virtual_server_t const *vs) CC_HINT(nonnull);

virtual_server_t const	*virtual_server_find(char const *name) CC_HINT(nonnull);

virtual_server_t const	*virtual_server_by_child(CONF_ITEM const *ci) CC_HINT(nonnull);

int			virtual_server_cf_parse(TALLOC_CTX *ctx, void *out, void *parent,
						CONF_ITEM *ci, conf_parser_t const *rule) CC_HINT(nonnull(2,4));
/** @} */

fr_listen_t *  		listen_find_any(fr_listen_t *li) CC_HINT(nonnull);
bool			listen_record(fr_listen_t *li) CC_HINT(nonnull);

/** Processing sections which are allowed in this virtual server.
 *
 */
typedef struct {
	section_name_t const			*section;	//!< Identifier for the section.
	size_t					offset;		//!< where the CONF_SECTION pointer is written
	bool					dont_cache;	//!< If true, the CONF_SECTION pointer won't be written
								///< and the offset will be ignored.
	size_t					instruction;	//!< where the instruction pointer is written
	unlang_mod_actions_t const		*actions;	//!< Default actions for this section.
	section_name_t const			**methods;	//!< list of auxilliary module methods which are allowed in
								///< if the main name doesn't match.
} virtual_server_compile_t;

#define COMPILE_TERMINATOR { .section = NULL }

int		virtual_server_section_register(virtual_server_t *vs, virtual_server_compile_t const *entry) CC_HINT(nonnull);

section_name_t const **virtual_server_section_methods(virtual_server_t const *vs, section_name_t const *section) CC_HINT(nonnull);

int		virtual_server_compile_sections(virtual_server_t const *vs, tmpl_rules_t const *rules) CC_HINT(nonnull);

unlang_action_t	virtual_server_push(request_t *request, CONF_SECTION *server_cs, bool top_frame) CC_HINT(nonnull);

/** @name Parsing, bootstrap and instantiation
 *
 * @{
 */
int		virtual_server_section_attribute_define(CONF_SECTION *server_cs, char const *subcs_name,
							fr_dict_attr_t const *da) CC_HINT(nonnull);

int		virtual_servers_open(fr_schedule_t *sc);

void		virtual_servers_thread_detach(void);

int		virtual_servers_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el) CC_HINT(nonnull);

int		virtual_servers_instantiate(void) CC_HINT(nonnull);

int		virtual_servers_bootstrap(CONF_SECTION *config) CC_HINT(nonnull);

int		virtual_servers_free(void);

int		virtual_servers_init(void) CC_HINT(nonnull);
/** @} */

#ifdef __cplusplus
}
#endif
