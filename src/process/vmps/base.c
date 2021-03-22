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
 * @file src/process/vmps/base.c
 * @brief VMPS processing.
 *
 * @copyright 2018 The Freeradius server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/vmps/vmps.h>

#include <freeradius-devel/protocol/vmps/vmps.h>

static fr_dict_t const *dict_vmps;

extern fr_dict_autoload_t process_vmps_dict[];
fr_dict_autoload_t process_vmps_dict[] = {
	{ .out = &dict_vmps, .proto = "vmps" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t process_vmps_dict_attr[];
fr_dict_attr_autoload_t process_vmps_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_vmps },
	{ NULL }
};

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*join_request;
	CONF_SECTION	*join_response;
	CONF_SECTION	*reconfirm_request;
	CONF_SECTION	*reconfirm_response;
	CONF_SECTION	*do_not_respond;
} process_vmps_sections_t;

typedef struct {
	process_vmps_sections_t sections;
} process_vmps_t;

#define PROCESS_PACKET_TYPE		fr_vmps_packet_code_t
#define PROCESS_CODE_MAX		FR_VMPS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_VMPS_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_VMPS_PACKET_CODE_VALID
#define PROCESS_INST			process_vmps_t
#include <freeradius-devel/server/process.h>

static fr_process_state_t const process_state[] = {
	[FR_PACKET_TYPE_VALUE_JOIN_REQUEST] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_JOIN_RESPONSE,
			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_JOIN_RESPONSE,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_JOIN_RESPONSE,

			[RLM_MODULE_REJECT] =  	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(join_request),
	},
	[FR_PACKET_TYPE_VALUE_JOIN_RESPONSE] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_JOIN_RESPONSE,
			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_JOIN_RESPONSE,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_JOIN_RESPONSE,

			[RLM_MODULE_REJECT] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(join_response),
	},

	[FR_PACKET_TYPE_VALUE_RECONFIRM_REQUEST] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE,
			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE,

			[RLM_MODULE_REJECT] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(reconfirm_request),
	},
	[FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE,
			[RLM_MODULE_NOOP] =	FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE,
			[RLM_MODULE_UPDATED] =	FR_PACKET_TYPE_VALUE_RECONFIRM_RESPONSE,

			[RLM_MODULE_REJECT] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(reconfirm_response),
	},

	[ FR_VMPS_DO_NOT_RESPOND ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_VMPS_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_VMPS_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED]	= FR_VMPS_DO_NOT_RESPOND,
			[RLM_MODULE_HANDLED]	= FR_VMPS_DO_NOT_RESPOND,

			[RLM_MODULE_NOTFOUND]	= FR_VMPS_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_VMPS_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_VMPS_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_VMPS_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_VMPS_DO_NOT_RESPOND
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
static void vmps_packet_debug(request_t *request, fr_radius_packet_t const *packet, fr_pair_list_t const *list, bool received)
{
#ifdef WITH_IFINDEX_NAME_RESOLUTION
	char if_name[IFNAMSIZ];
#endif

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s %s XID %08x from %s%pV%s:%i to %s%pV%s:%i "
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		    "%s%s%s"
#endif
		    "",
		    received ? "Received" : "Sending",
		    fr_vmps_codes[packet->code],
		    packet->id,
		    packet->socket.inet.src_ipaddr.af == AF_INET6 ? "[" : "",
		    fr_box_ipaddr(packet->socket.inet.src_ipaddr),
		    packet->socket.inet.src_ipaddr.af == AF_INET6 ? "]" : "",
		    packet->socket.inet.src_port,
		    packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "[" : "",
		    fr_box_ipaddr(packet->socket.inet.dst_ipaddr),
		    packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "]" : "",
		    packet->socket.inet.dst_port
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		    , packet->socket.inet.ifindex ? "via " : "",
		    packet->socket.inet.ifindex ? fr_ifname_from_ifindex(if_name, packet->socket.inet.ifindex) : "",
		    packet->socket.inet.ifindex ? " " : ""
#endif
		    );

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

	(void)talloc_get_type_abort_const(mctx->instance, process_vmps_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "vmps";
	fr_assert(request->dict == dict_vmps);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_MODULE_FAIL;
	}

	vmps_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

static const virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Join-Request",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(join_request),
	},
	{
		.name = "send",
		.name2 = "Join-Response",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(join_response),
	},
	{
		.name = "recv",
		.name2 = "Reconfirm-Request",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(reconfirm_request),
	},
	{
		.name = "send",
		.name2 = "Reconfirm-Response",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(reconfirm_response),
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_vmps;
fr_process_module_t process_vmps = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_vmps",
	.inst_size	= sizeof(process_vmps_t),

	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_vmps,
};
