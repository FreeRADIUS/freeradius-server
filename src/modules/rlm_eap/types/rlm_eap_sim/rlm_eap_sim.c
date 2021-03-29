/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_eap_sim.c
 * @brief Implements EAP-SIM
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Network RADIUS SARL (sales@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap_aka_sim/attrs.h>
#include <freeradius-devel/eap_aka_sim/base.h>
#include <freeradius-devel/eap_aka_sim/module.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/util/debug.h>

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_VOID | FR_TYPE_REQUIRED, eap_aka_sim_module_conf_t, virtual_server), .func = virtual_server_cf_parse },
	CONF_PARSER_TERMINATOR
};

extern rlm_eap_submodule_t rlm_eap_sim;

static unlang_action_t mod_session_init(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t			*eap_session = eap_session_get(request->parent);
	eap_aka_sim_mod_session_t	*mod_session;

	MEM(mod_session = talloc_zero(eap_session, eap_aka_sim_mod_session_t));
	mod_session->id = (uint8_t)(fr_rand() & 0xff);
	mod_session->ctx.hmac_md = mod_session->ctx.checkcode_md = EVP_sha1();
	eap_session->opaque = mod_session;
	eap_session->process = eap_aka_sim_process;

	return eap_session->process(p_result, mctx, request);
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	eap_aka_sim_module_conf_t	*inst = talloc_get_type_abort(instance, eap_aka_sim_module_conf_t);

	inst->type = rlm_eap_sim.provides[0];

	return 0;
}
static int mod_load(void)
{
	if (fr_aka_sim_init() < 0) return -1;

	fr_aka_sim_xlat_register();

	return 0;
}

static void mod_unload(void)
{
	fr_aka_sim_xlat_unregister();

	fr_aka_sim_free();
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
rlm_eap_submodule_t rlm_eap_sim = {
	.name		= "eap_sim",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_METHOD_SIM },

	.inst_size	= sizeof(eap_aka_sim_module_conf_t),
	.inst_type	= "eap_aka_sim_module_conf_t",
	.config		= submodule_config,

	.onload		= mod_load,
	.unload		= mod_unload,

	.instantiate	= mod_instantiate,

	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= eap_aka_sim_process,
	.namespace	= &dict_eap_aka_sim
};
