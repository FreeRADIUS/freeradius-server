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
 * @file src/lib/server/module_rlm.h
 * @brief Defines functions for rlm module (re-)initialisation.
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(module_rlm_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/module.h>

extern char const *section_type_value[MOD_COUNT];

/** @name Convenience wrappers around other internal APIs to make them easier to instantiate with modules
 *
 * @{
 */
fr_pool_t	*module_rlm_connection_pool_init(CONF_SECTION *module,
						 void *opaque,
						 fr_pool_connection_create_t c,
						 fr_pool_connection_alive_t a,
						 char const *log_prefix,
						 char const *trigger_prefix,
						 fr_pair_list_t *trigger_args);
exfile_t	*module_rlm_exfile_init(TALLOC_CTX *ctx,
					CONF_SECTION *module,
					uint32_t max_entries,
					fr_time_delta_t max_idle,
					bool locking,
					char const *trigger_prefix,
					fr_pair_list_t *trigger_args);
/** @} */

/** @name Helper functions
 *
 * @{
 */
module_method_t	module_rlm_state_str_to_method(module_state_func_table_t const *table,
					       char const *name, module_method_t def);

char const	*module_rlm_state_method_to_str(module_state_func_table_t const *table,
						module_method_t method, char const *def);

bool		module_rlm_section_type_set(request_t *request, fr_dict_attr_t const *type_da, fr_dict_enum_value_t const *enumv);
/** @} */

/** @name Module and module thread lookup
 *
 * @{
 */
module_instance_t	*module_rlm_by_name_and_method(module_method_t *method, rlm_components_t *component,
						   char const **name1, char const **name2,
						   char const *asked_name);

CONF_SECTION		*module_rlm_by_name_virtual(char const *asked_name);

/** @} */

/** @name Module and module thread initialisation and instantiation
 *
 * @{
 */
int		modules_rlm_bootstrap(CONF_SECTION *root) CC_HINT(nonnull);
/** @} */

void	modules_rlm_free(void);

int	modules_rlm_init(void);

#ifdef __cplusplus
}
#endif
