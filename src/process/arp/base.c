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
 * @file src/process/arp/base.c
 * @brief ARP processing.
 *
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/arp/arp.h>
#include <freeradius-devel/unlang/interpret.h>

static fr_dict_t const *dict_arp;

extern fr_dict_autoload_t process_arp_dict[];
fr_dict_autoload_t process_arp_dict[] = {
	{ .out = &dict_arp, .proto = "arp" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t process_arp_dict_attr[];
fr_dict_attr_autoload_t process_arp_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_arp},
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
} process_arp_sections_t;

typedef struct {
	bool		test;

	process_arp_sections_t	sections;
} process_arp_t;

#define PROCESS_PACKET_TYPE		fr_arp_packet_code_t
#define PROCESS_CODE_MAX		FR_ARP_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_ARP_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_ARP_PACKET_CODE_VALID
#define PROCESS_INST			process_arp_t
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
			[RLM_MODULE_TIMEOUT] =  FR_ARP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
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
			[RLM_MODULE_TIMEOUT] =  FR_ARP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
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
			[RLM_MODULE_TIMEOUT] =  FR_ARP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
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
			[RLM_MODULE_TIMEOUT] =  FR_ARP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
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
			[RLM_MODULE_TIMEOUT] =  FR_ARP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_HANDLED,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
};

/*
 *	Debug the packet if requested.
 */
static void arp_packet_debug(request_t *request, fr_packet_t const *packet, fr_pair_list_t const *list, bool received)
{
	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s %s",
		    received ? "Received" : "Sending",
		    fr_arp_packet_codes[packet->code]);

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

	(void)talloc_get_type_abort_const(mctx->mi->data, process_arp_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "arp";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_arp);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_MODULE_FAIL;
	}

	arp_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}


static const virtual_server_compile_t compile_list[] = {
	{
		.section = SECTION_NAME("recv", "Request"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(request),
	},
	{
		.section = SECTION_NAME("send", "Reply"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(reply),
	},
	{			/* we can listen for others ARP replies, too */
		.section = SECTION_NAME("recv", "Reply"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(recv_reply),
	},
	{
		.section = SECTION_NAME("recv", "Reverse-Request"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(reverse_request),
	},
	{
		.section = SECTION_NAME("send", "Reverse-Reply"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(reverse_reply),
	},
	{
		.section = SECTION_NAME("send", "Do-Not-Respond"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
	COMPILE_TERMINATOR
};


extern fr_process_module_t process_arp;
fr_process_module_t process_arp = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "arp",
		MODULE_INST(process_arp_t),
		MODULE_RCTX(process_rctx_t)
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_arp,
	.packet_type	= &attr_packet_type
};
