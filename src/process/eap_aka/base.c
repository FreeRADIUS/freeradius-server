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
 * @file src/process/eap_aka/base.c
 * @brief EAP-AKA process module
 *
 * The state machine for EAP-SIM, EAP-AKA and EAP-AKA' is common to all methods
 * and is in src/lib/eap_aka_sim/state_machine.c
 *
 * The process modules for the different EAP methods just define the sections
 * for that EAP method, and parse different config items.
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

#include <freeradius-devel/eap_aka_sim/base.h>
#include <freeradius-devel/eap_aka_sim/attrs.h>
#include <freeradius-devel/eap_aka_sim/state_machine.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/process.h>

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET("request_identity", eap_aka_sim_process_conf_t, request_identity ),
	  .func = cf_table_parse_int,
	  .uctx = &(cf_table_parse_ctx_t){ .table = fr_aka_sim_id_request_table, .len = &fr_aka_sim_id_request_table_len }},
	{ FR_CONF_OFFSET("strip_permanent_identity_hint", eap_aka_sim_process_conf_t,
			 strip_permanent_identity_hint ), .dflt = "yes" },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ephemeral_id_length", FR_TYPE_SIZE, 0, eap_aka_sim_process_conf_t, ephemeral_id_length ), .dflt = "14" },	/* 14 for compatibility */
	{ FR_CONF_OFFSET("protected_success", eap_aka_sim_process_conf_t, protected_success ), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

static virtual_server_compile_t const compile_list[] = {
	/*
	 *	Identity negotiation
	 *	The initial identity here is the EAP-Identity.
	 *      We can then choose to request additional
	 *      identities.
	 */
	{
		.section = SECTION_NAME("recv", "Identity-Response"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_common_identity_response)
	},
	{
		.section = SECTION_NAME("send", "Identity-Request"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_common_identity_request)
	},

	/*
	 *	Optional override sections if the user *really*
	 *	wants to apply special policies for subsequent
	 *	request/response rounds.
	 */
	{
		.section = SECTION_NAME("send", "AKA-Identity-Request"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_aka_identity_request)
	},
	{
		.section = SECTION_NAME("recv", "AKA-Identity-Response"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_aka_identity_response)
	},

	/*
	 *	Full-Authentication
	 */
	{
		.section = SECTION_NAME("send", "Challenge-Request"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_aka_challenge_request)
	},
	{
		.section = SECTION_NAME("recv", "Challenge-Response"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_aka_challenge_response)
	},

	/*
	 *	Fast-Re-Authentication
	 */
	{
		.section = SECTION_NAME("send", "Reauthentication-Request"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_common_reauthentication_request)
	},
	{
		.section = SECTION_NAME("recv", "Reauthentication-Response"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_common_reauthentication_response)
	},

	/*
	 *	Failures originating from the supplicant
	 */
	{
		.section = SECTION_NAME("recv", "Client-Error"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_common_client_error)
	},
	{
		.section = SECTION_NAME("recv", "Authentication-Reject"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_aka_authentication_reject)
	},
	{
		.section = SECTION_NAME("recv", "Synchronization-Failure"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_aka_synchronization_failure)
	},

	/*
	 *	Failure originating from the server
	 */
	{
		.section = SECTION_NAME("send", "Failure-Notification"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_common_failure_notification)
	},
	{
		.section = SECTION_NAME("recv", "Failure-Notification-ACK"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_common_failure_notification_ack)
	},

	/*
	 *	Protected success indication
	 */
	{
		.section = SECTION_NAME("send", "Success-Notification"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_common_success_notification)
	},
	{
		.section = SECTION_NAME("recv", "Success-Notification-ACK"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_common_success_notification_ack)
	},

	/*
	 *	Final EAP-Success and EAP-Failure messages
	 */
	{
		.section = SECTION_NAME("send", "EAP-Success"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_eap_success)
	},
	{
		.section = SECTION_NAME("send", "EAP-Failure"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_eap_failure)
	},

	/*
	 *	Fast-Reauth vectors
	 */
	{
		.section = SECTION_NAME("store", "session"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.store_session)
	},
	{
		.section = SECTION_NAME("load", "session"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.load_session)
	},
	{
		.section = SECTION_NAME("clear", "session"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.clear_session)
	},

	/*
	 *	Pseudonym processing
	 */
	{
		.section = SECTION_NAME("store", "pseudonym"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.store_pseudonym)
	},
	{
		.section = SECTION_NAME("load", "pseudonym"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.load_pseudonym)
	},
	{
		.section = SECTION_NAME("clear", "pseudonym"),
		.actions = &mod_actions_authorize,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.clear_pseudonym)
	},

	COMPILE_TERMINATOR
};

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	eap_aka_sim_process_conf_t	*inst = talloc_get_type_abort(mctx->mi->data, eap_aka_sim_process_conf_t);

	inst->type = FR_EAP_METHOD_AKA;

	/*
	 *	This isn't allowed, so just munge
	 *	it to no id request.
	 */
	if (inst->request_identity == AKA_SIM_INIT_ID_REQ) inst->request_identity = AKA_SIM_NO_ID_REQ;

	return 0;
}

static int mod_load(void)
{
	if (unlikely(fr_aka_sim_init() < 0)) return -1;

	fr_aka_sim_xlat_func_register();

	return 0;
}

static void mod_unload(void)
{
	fr_aka_sim_xlat_func_unregister();

	fr_aka_sim_free();
}

extern fr_process_module_t process_eap_aka;
fr_process_module_t process_eap_aka = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "eap_aka",
		.onload		= mod_load,
		.unload		= mod_unload,
		.config		= submodule_config,
		.instantiate	= mod_instantiate,
		.inst_size	= sizeof(eap_aka_sim_process_conf_t),
		.inst_type	= "eap_aka_sim_process_conf_t"
	},
	.process	= eap_aka_sim_state_machine_process,
	.compile_list	= compile_list,
	.dict		= &dict_eap_aka_sim,
};
