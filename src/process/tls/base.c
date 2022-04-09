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
 * @file src/process/tls/base.c
 * @brief TLS processing.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/protocol/tls/freeradius.h>

static fr_dict_t const *dict_tls;

extern fr_dict_autoload_t process_tls_dict[];
fr_dict_autoload_t process_tls_dict[] = {
	{ .out = &dict_tls, .proto = "tls" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t process_tls_dict_attr[];
fr_dict_attr_autoload_t process_tls_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tls},
	{ NULL }
};

typedef struct {
	CONF_SECTION	*load_session;
	CONF_SECTION	*store_session;
	CONF_SECTION	*clear_session;
	CONF_SECTION	*verify_certificate;
} process_tls_sections_t;

typedef struct {
	process_tls_sections_t	sections;
} process_tls_t;

#define FR_TLS_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) <= FR_PACKET_TYPE_VALUE_NOTFOUND))

#define PROCESS_INST			process_tls_t
#define PROCESS_PACKET_TYPE		uint32_t
#define PROCESS_PACKET_CODE_VALID	FR_TLS_PACKET_CODE_VALID

#include <freeradius-devel/server/process.h>

static fr_process_state_t const process_state[] = {
	[FR_PACKET_TYPE_VALUE_LOAD_SESSION] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_SUCCESS,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_SUCCESS,

			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_REJECT] =  	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_NOTFOUND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_no_send,
		.section_offset = PROCESS_CONF_OFFSET(load_session),
	},
	[FR_PACKET_TYPE_VALUE_STORE_SESSION] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_SUCCESS,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_SUCCESS,

			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_REJECT] =  	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_NOTFOUND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_no_send,
		.section_offset = PROCESS_CONF_OFFSET(store_session),
	},
	[FR_PACKET_TYPE_VALUE_CLEAR_SESSION] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_SUCCESS,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_SUCCESS,

			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_REJECT] =  	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_NOTFOUND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_no_send,
		.section_offset = PROCESS_CONF_OFFSET(clear_session),
	},
	[FR_PACKET_TYPE_VALUE_VERIFY_CERTIFICATE] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_SUCCESS,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_SUCCESS,
			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_SUCCESS,

			[RLM_MODULE_REJECT] =  	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_FAILURE,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_NOTFOUND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_no_send,
		.section_offset = PROCESS_CONF_OFFSET(verify_certificate),
	},
};

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->inst->data, process_tls_t);

	request->component = "tls";
	request->module = NULL;
	fr_assert(request->dict == dict_tls);

	UPDATE_STATE(packet);

	log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->request_pairs, NULL);

	return state->recv(p_result, mctx, request);
}

static const virtual_server_compile_t compile_list[] = {
	{
		.name = "store",
		.name2 = "session",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(store_session)
	},
	{
		.name = "load",
		.name2 = "session",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(load_session)
	},
	{
		.name = "clear",
		.name2 = "session",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(clear_session)
	},
	{
		.name = "verify",
		.name2 = "certificate",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(verify_certificate)
	},
	COMPILE_TERMINATOR
};


extern fr_process_module_t process_tls;
fr_process_module_t process_tls = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "tls",
		.inst_size	= sizeof(process_tls_t)
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_tls,
};
