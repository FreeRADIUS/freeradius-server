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
 * @copyright 2019  The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/cf_parse.h>
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

int		virtual_server_namespace_register(char const *namespace, fr_virtual_server_compile_t func);

fr_dict_t	*virtual_server_namespace(char const *virtual_server);

bool		virtual_server_has_namespace(CONF_SECTION **out,
					     char const *virtual_server, fr_dict_t const *namespace,
					     CONF_ITEM *ci);
/** @} */

rlm_rcode_t	process_authenticate(int type, REQUEST *request);


void		fr_request_async_bootstrap(REQUEST *request, fr_event_list_t *el); /* for unit_test_module */

#ifdef __cplusplus
}
#endif
