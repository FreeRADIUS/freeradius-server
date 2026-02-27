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
 * @copyright 2022,2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(module_rlm_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct module_rlm_s module_rlm_t;
typedef struct module_rlm_instance_s module_rlm_instance_t;

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/virtual_servers.h>

struct module_rlm_s {
	module_t			common;			//!< Common fields presented by all modules.
	module_method_group_t		method_group;		//!< named methods
};

struct module_rlm_instance_s {
	fr_dlist_head_t			xlats;			//!< xlats registered to this module instance.
								///< This is used by the redundant/loadbalance
								///< xlats to register versions of the xlats
								///< exported by the module instances.
};

/** An xlat function registered to a module
 */
typedef struct {
	xlat_t const			*xlat;			//!< The xlat function.
	module_instance_t		*mi;			//!< The module instance that registered the xlat.
	fr_dlist_t			entry;			//!< Entry in a linked list of registered xlats.
} module_rlm_xlat_t;

/** The output of module_rlm_by_name_and_method
 *
 * Everything needed to call a module method.
 */
typedef struct {
	module_instance_t	 	*mi;			//!< The process modules also push module calls
								///< onto the stack for execution.  So we need
								///< to use the common type here.
	module_rlm_t const		*rlm;			//!< Cached module_rlm_t.
	section_name_t			asked;			//!< The actual <name1>.<name2> used for the module call.
								///< This was either the override the user specified,
								///< or the name of the section.
	module_method_binding_t		mmb;			//!< Method we're calling.
	tmpl_t				*key;			//!< Dynamic key, only set for dynamic modules.
} module_method_call_t;

static inline module_rlm_t *module_rlm_from_module(module_t *module)
{
	return (module_rlm_t *)module;
}

/** @name Debug functions
 * @{
 */
void			module_rlm_list_debug(void);
/** @} */

/** @name Convenience wrappers around other internal APIs to make them easier to instantiate with modules
 *
 * @{
 */
xlat_t			*module_rlm_xlat_register(TALLOC_CTX *ctx, module_inst_ctx_t const *mctx,
						  char const *name, xlat_func_t func, fr_type_t return_type)
						  CC_HINT(nonnull(2,4));

fr_pool_t		*module_rlm_connection_pool_init(CONF_SECTION *module,
							 void *opaque,
							 fr_pool_connection_create_t c,
							 fr_pool_connection_alive_t a,
							 char const *log_prefix,
							 char const *trigger_prefix,
							 fr_pair_list_t *trigger_args);

exfile_t		*module_rlm_exfile_init(TALLOC_CTX *ctx,
						CONF_SECTION *module,
						uint32_t max_entries,
						fr_time_delta_t max_idle,
						bool locking,
						bool triggers,
						char const *trigger_prefix,
						fr_pair_list_t *trigger_args);
/** @} */

/** @name Helper functions
 *
 * @{
 */
bool			module_rlm_section_type_set(request_t *request, fr_dict_attr_t const *type_da,
						    fr_dict_enum_value_t const *enumv);
/** @} */

/** @name Module and module thread lookup
 *
 * @{
 */
fr_slen_t 		module_rlm_by_name_and_method(TALLOC_CTX *ctx, module_method_call_t *mmc_out,
						      virtual_server_t const *vs, section_name_t const *section, fr_sbuff_t *name,
						      tmpl_rules_t const *t_rules) CC_HINT(nonnull(5));

module_instance_t	*module_rlm_dynamic_by_name(module_instance_t const *parent, char const *name);

module_instance_t	*module_rlm_static_by_name(module_instance_t const *parent, char const *name);

CONF_SECTION		*module_rlm_virtual_by_name(char const *name);
/** @} */

/** @name Support functions
 *
 * @{
 */
int			module_rlm_submodule_parse(TALLOC_CTX *ctx, void *out, void *parent,
						   CONF_ITEM *ci, conf_parser_t const *rule);
/** @} */

/** @name Module and module thread initialisation and instantiation
 *
 * @{
 */
void			modules_rlm_thread_detach(void);

int			modules_rlm_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el) CC_HINT(nonnull(2));

int			modules_rlm_coord_attach(fr_event_list_t *el) CC_HINT(nonnull);

int			modules_rlm_instantiate(void);

int			modules_rlm_bootstrap(CONF_SECTION *root) CC_HINT(nonnull);
/** @} */

/** @name Global initialisation and free functions
 *
 * @{
 */
int			modules_rlm_free(void);

int			modules_rlm_init(void);
/** @} */

#ifdef __cplusplus
}
#endif
