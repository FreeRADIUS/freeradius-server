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
 * @brief ARP processing.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>

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
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*request;
	CONF_SECTION	*reply;
	CONF_SECTION	*recv_reply;
	CONF_SECTION	*reverse_request;
	CONF_SECTION	*reverse_reply;
	CONF_SECTION	*do_not_respond;
} process_tls_sections_t;

typedef struct {
	bool		test;

	process_tls_sections_t	sections;
} process_tls_t;

#define PROCESS_PACKET_TYPE		fr_tls_packet_code_t
#define PROCESS_CODE_MAX		FR_ARP_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_ARP_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_ARP_PACKET_CODE_VALID
#define PROCESS_INST			process_tls_t
#include <freeradius-devel/server/process.h>

static fr_process_state_t const process_state[] = {
	[ FR_ARP_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_NOOP] = 	FR_ARP_REPLY,
			[RLM_MODULE_OK] = 	FR_ARP_REPLY,
			[RLM_MODULE_UPDATED] =	FR_ARP_REPLY,

			[RLM_MODULE_REJECT] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_ARP_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(request),
	},
	[ FR_ARP_REPLY ] = {
		.packet_type = {
			[RLM_MODULE_NOOP] = 	FR_ARP_REPLY,
			[RLM_MODULE_OK] = 	FR_ARP_REPLY,
			[RLM_MODULE_UPDATED] =	FR_ARP_REPLY,

			[RLM_MODULE_REJECT] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_ARP_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(reply),
	},

	[ FR_ARP_REVERSE_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_NOOP] = 	FR_ARP_REVERSE_REPLY,
			[RLM_MODULE_OK] = 	FR_ARP_REVERSE_REPLY,
			[RLM_MODULE_UPDATED] =	FR_ARP_REVERSE_REPLY,

			[RLM_MODULE_REJECT] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_ARP_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(reverse_request),
	},
	[ FR_ARP_REVERSE_REPLY ] = {
		.packet_type = {
			[RLM_MODULE_NOOP] = 	FR_ARP_REVERSE_REPLY,
			[RLM_MODULE_OK] = 	FR_ARP_REVERSE_REPLY,
			[RLM_MODULE_UPDATED] =	FR_ARP_REVERSE_REPLY,

			[RLM_MODULE_REJECT] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_ARP_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(reverse_reply),
	},

	// @todo - recv reply, to look at other replies.

	[ FR_ARP_DO_NOT_RESPOND ] = {
		.packet_type = {
			[RLM_MODULE_NOOP] = 	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_OK] = 	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_ARP_DO_NOT_RESPOND,

			[RLM_MODULE_REJECT] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_ARP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_ARP_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
};

/*
 *	Debug the packet if requested.
 */
static void tls_packet_debug(request_t *request, fr_radius_packet_t const *packet, fr_pair_list_t const *list, bool received)
{
	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s %s",
		    received ? "Received" : "Sending",
		    fr_tls_packet_codes[packet->code]);

	if (received || request->parent) {
		log_request_pair_list(L_DBG_LVL_1, request, NULL, list, NULL);
	} else {
		log_request_proto_pair_list(L_DBG_LVL_1, request, NULL, list, NULL);
	}
}

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->instance, process_tls_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "tls";
	request->module = NULL;
	fr_assert(request->dict == dict_tls);

	UPDATE_STATE(packet);

	tls_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}


static const virtual_server_compile_t compile_list[] = {
	{
		.name = "store",
		.name2 = "session",
		.component = MOD_AUTHORIZE,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.store_session)
	},
	{
		.name = "load",
		.name2 = "session",
		.component = MOD_AUTHORIZE,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.load_session)
	},
	{
		.name = "clear",
		.name2 = "session",
		.component = MOD_AUTHORIZE,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.clear_session)
	},
	{
		.name = "recv",
		.name2 = "certificate",
		.component = MOD_AUTHORIZE,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.recv_certificate)
	},
	{
		.name = "send",
		.name2 = "success",
		.component = MOD_POST_AUTH,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_success)
	},
	{
		.name = "send",
		.name2 = "failure",
		.component = MOD_POST_AUTH,
		.offset = offsetof(eap_aka_sim_process_conf_t, actions.send_failure)
	}
	COMPILE_TERMINATOR
};


extern fr_process_module_t process_tls;
fr_process_module_t process_tls = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_tls",
	.inst_size	= sizeof(process_tls_t),
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_tls,
};
