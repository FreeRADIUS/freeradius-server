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
 * @file src/process/dhcpv4/base.c
 * @brief Base DORA, etc. DHCPV4 processing.
 *
 * @copyright 2018 The Freeradius server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#define LOG_PREFIX "process_dhcpv4"

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/module_method.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t process_dhcpv4_dict[];
fr_dict_autoload_t process_dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_message_type;
static fr_dict_attr_t const *attr_yiaddr;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_dhcp_option_82;

extern fr_dict_attr_autoload_t process_dhcpv4_dict_attr[];
fr_dict_attr_autoload_t process_dhcpv4_dict_attr[] = {
	{ .out = &attr_message_type, .name = "Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4},
	{ .out = &attr_yiaddr, .name = "Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4},
	{ .out = &attr_dhcp_option_82, .name = "Relay-Agent-Information", .type = FR_TYPE_TLV, .dict = &dict_dhcpv4 },
	DICT_AUTOLOAD_TERMINATOR
};

/*
 *	Debug the packet if requested.
 */
static void dhcpv4_packet_debug(request_t *request, fr_packet_t *packet, fr_pair_list_t *list, bool received)
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
		       dhcp_message_types[packet->code],
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

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*discover;
	CONF_SECTION	*offer;
	CONF_SECTION	*request;
	CONF_SECTION	*decline;
	CONF_SECTION	*ack;
	CONF_SECTION	*nak;
	CONF_SECTION	*release;
	CONF_SECTION	*inform;
	CONF_SECTION	*force_renew;
	CONF_SECTION	*lease_query;
	CONF_SECTION	*lease_unassigned;
	CONF_SECTION	*lease_unknown;
	CONF_SECTION	*lease_active;
	CONF_SECTION	*do_not_respond;

	CONF_SECTION	*new_client;
	CONF_SECTION	*add_client;
	CONF_SECTION	*deny_client;
} process_dhcpv4_sections_t;

typedef struct {
	process_dhcpv4_sections_t sections;
} process_dhcpv4_t;

#define FR_DHCP_PROCESS_CODE_VALID(_x) (FR_DHCP_PACKET_CODE_VALID(_x) || (_x == FR_DHCP_DO_NOT_RESPOND))

#define PROCESS_PACKET_TYPE		fr_dhcpv4_packet_code_t
#define PROCESS_CODE_MAX		FR_DHCP_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_DHCP_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_DHCP_PROCESS_CODE_VALID
#define PROCESS_INST			process_dhcpv4_t
#define PROCESS_CODE_DYNAMIC_CLIENT	FR_DHCP_ACK
#include <freeradius-devel/server/process.h>

RESUME(check_offer_ack_options)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_yiaddr);
	if (!vp) {
		REDEBUG("%s packet does not have YIADDR.  The client will not receive an IP address.",
			dhcp_message_types[request->reply->code]);
	}

	/*
	 *	RFC3046 says:
	 *	DHCP servers claiming to support the Relay Agent Information option
	 *	SHALL echo the entire contents of the Relay Agent Information option
	 *	in all replies.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_dhcp_option_82);
	if (vp) {
		fr_pair_t 	*reply_vp;
		int		ret;
		MEM((ret = pair_update_reply(&reply_vp, attr_dhcp_option_82)) >= 0);
		if ((ret == 0) && (fr_pair_list_num_elements(&vp->vp_group) > 0)) {
			MEM(fr_pair_list_copy(reply_vp, &reply_vp->vp_group, &vp->vp_group));
		}
	}

	return CALL_RESUME(send_generic);
}

static fr_process_state_t const process_state[] = {
	[FR_DHCP_DISCOVER] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_OFFER,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_OFFER,

			[RLM_MODULE_REJECT] =  	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(discover),
	},
	[FR_DHCP_OFFER] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_OFFER,
			[RLM_MODULE_NOOP] =	FR_DHCP_OFFER,
			[RLM_MODULE_UPDATED] =	FR_DHCP_OFFER,

			[RLM_MODULE_REJECT] =  	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_check_offer_ack_options,
		.section_offset = PROCESS_CONF_OFFSET(offer),
	},

	[FR_DHCP_REQUEST] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_ACK,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_ACK,

			[RLM_MODULE_REJECT] =  	FR_DHCP_NAK,
			[RLM_MODULE_FAIL] =	FR_DHCP_NAK,
			[RLM_MODULE_INVALID] =	FR_DHCP_NAK,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_NAK,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_NAK,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(request),
	},

	[FR_DHCP_DECLINE] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_DO_NOT_RESPOND,

			[RLM_MODULE_REJECT] =  	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(decline),
	},

	[FR_DHCP_ACK] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_ACK,
			[RLM_MODULE_NOOP] =	FR_DHCP_ACK,
			[RLM_MODULE_UPDATED] =	FR_DHCP_ACK,

			[RLM_MODULE_REJECT] =  	FR_DHCP_NAK,
			[RLM_MODULE_FAIL] =	FR_DHCP_NAK,
			[RLM_MODULE_INVALID] =	FR_DHCP_NAK,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_NAK,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_NAK,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_check_offer_ack_options,
		.section_offset = PROCESS_CONF_OFFSET(ack),
	},
	[FR_DHCP_NAK] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_NAK,
			[RLM_MODULE_NOOP] =	FR_DHCP_NAK,
			[RLM_MODULE_UPDATED] =	FR_DHCP_NAK,

			[RLM_MODULE_REJECT] =  	FR_DHCP_NAK,
			[RLM_MODULE_FAIL] =	FR_DHCP_NAK,
			[RLM_MODULE_INVALID] =	FR_DHCP_NAK,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_NAK,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_NAK,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(nak),
	},

	[FR_DHCP_INFORM] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_ACK,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_ACK,

			[RLM_MODULE_REJECT] =  	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(inform),
	},

	[FR_DHCP_RELEASE] = {	/* releases are not responded to */
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_DO_NOT_RESPOND,

			[RLM_MODULE_REJECT] =  	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(release),
	},

	[FR_DHCP_LEASE_QUERY] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_LEASE_ACTIVE,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_LEASE_ACTIVE,

			[RLM_MODULE_REJECT] =	FR_DHCP_LEASE_UNKNOWN,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_LEASE_UNASSIGNED,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(lease_query),
	},

	[FR_DHCP_LEASE_UNASSIGNED] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_LEASE_UNASSIGNED,
			[RLM_MODULE_NOOP] =	FR_DHCP_LEASE_UNASSIGNED,
			[RLM_MODULE_UPDATED] =	FR_DHCP_LEASE_UNASSIGNED,

			[RLM_MODULE_REJECT] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_LEASE_UNASSIGNED,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(lease_unassigned),
	},

	[FR_DHCP_LEASE_UNKNOWN] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_LEASE_UNKNOWN,
			[RLM_MODULE_NOOP] =	FR_DHCP_LEASE_UNKNOWN,
			[RLM_MODULE_UPDATED] =	FR_DHCP_LEASE_UNKNOWN,

			[RLM_MODULE_REJECT] =	FR_DHCP_LEASE_UNKNOWN,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_NOTFOUND,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(lease_unknown),
	},

	[FR_DHCP_LEASE_ACTIVE] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_LEASE_ACTIVE,
			[RLM_MODULE_NOOP] =	FR_DHCP_LEASE_ACTIVE,
			[RLM_MODULE_UPDATED] =	FR_DHCP_LEASE_ACTIVE,

			[RLM_MODULE_REJECT] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(lease_active),
	},

	[FR_DHCP_DO_NOT_RESPOND] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_DO_NOT_RESPOND,

			[RLM_MODULE_REJECT] =  	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =  FR_DHCP_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_DISALLOW,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
};

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_dhcpv4_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "dhcpv4";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_dhcpv4);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	dhcpv4_packet_debug(request, request->packet, &request->request_pairs, true);

	if (unlikely(request_is_dynamic_client(request))) {
		return new_client(p_result, mctx, request);
	}

	return state->recv(p_result, mctx, request);
}

static const virtual_server_compile_t compile_list[] = {
	{
		.section = SECTION_NAME("recv", "Discover"),
		.actions = &mod_actions_postauth,

		.methods = (const section_name_t *[]) {
			&module_method_ippool_allocate,
			NULL
		},
		.offset = PROCESS_CONF_OFFSET(discover),
	},
	{
		.section = SECTION_NAME("send", "Offer"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(offer),
	},
	{
		.section = SECTION_NAME("recv", "Request"),
		.actions = &mod_actions_postauth,

		.methods = (const section_name_t *[]) {
			&module_method_ippool_extend,
			NULL
		},
		.offset = PROCESS_CONF_OFFSET(request),
	},

	{
		.section = SECTION_NAME("send", "Ack"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(ack),
	},
	{
		.section = SECTION_NAME("send", "NAK"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(nak),
	},
	{
		.section = SECTION_NAME("recv", "Decline"),
		.actions = &mod_actions_postauth,

		.methods = (const section_name_t *[]) {
			&module_method_ippool_mark,
			NULL
		},
		.offset = PROCESS_CONF_OFFSET(decline),
	},

	{
		.section = SECTION_NAME("recv", "Release"),
		.actions = &mod_actions_postauth,

		.methods = (const section_name_t *[]) {
			&module_method_ippool_release,
			NULL
		},
		.offset = PROCESS_CONF_OFFSET(release),
	},
	{
		.section = SECTION_NAME("recv", "Inform"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(inform),
	},

	{
		.section = SECTION_NAME("recv", "Lease-Query"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(lease_query),
	},
	{
		.section = SECTION_NAME("send", "Lease-Unassigned"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(lease_unassigned),
	},
	{
		.section = SECTION_NAME("send", "Lease-Unknown"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(lease_unknown),
	},
	{
		.section = SECTION_NAME("send", "Lease-Active"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(lease_active),
	},

	{
		.section = SECTION_NAME("send", "Do-Not-Respond"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},

	DYNAMIC_CLIENT_SECTIONS,

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_dhcpv4;
fr_process_module_t process_dhcpv4 = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "dhcpv4",
		MODULE_INST(process_dhcpv4_t),
		MODULE_RCTX(process_rctx_t)
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_dhcpv4,
	.packet_type	= &attr_packet_type
};
