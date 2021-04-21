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
#define LOG_PREFIX "process_dhcpv4 - "

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/protocol/dhcpv4/rfc2131.h>

static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t process_dhcpv4_dict[];
fr_dict_autoload_t process_dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_message_type;
static fr_dict_attr_t const *attr_yiaddr;
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t process_dhcpv4_dict_attr[];
fr_dict_attr_autoload_t process_dhcpv4_dict_attr[] = {
	{ .out = &attr_message_type, .name = "Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4},
	{ .out = &attr_yiaddr, .name = "Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4},
	{ NULL }
};

/*
 *	Debug the packet if requested.
 */
static void dhcpv4_packet_debug(request_t *request, fr_radius_packet_t *packet, fr_pair_list_t *list, bool received)
{
	size_t i;
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

	/*
	 *	Print the fields in the header, too.
	 */
	RINDENT();
	for (i = 0; i < dhcp_header_attrs_len; i++) {
		fr_pair_t *vp;

		if (!*dhcp_header_attrs[i]) continue;

		vp = fr_pair_find_by_da(list, *dhcp_header_attrs[i], 0);
		if (!vp) continue;
		RDEBUGX(L_DBG_LVL_1, "%pP", vp);
	}
	REXDENT();

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
#if 0
	CONF_SECTION	*lease_query;
	CONF_SECTION	*lease_unassigned;
	CONF_SECTION	*lease_unknown;
	CONF_SECTION	*lease_active;
#endif
	CONF_SECTION	*do_not_respond;
} process_dhcpv4_sections_t;

typedef struct {
	process_dhcpv4_sections_t sections;
} process_dhcpv4_t;

#define PROCESS_PACKET_TYPE		fr_dhcpv4_packet_code_t
#define PROCESS_CODE_MAX		FR_DHCP_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_DHCP_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_DHCP_PACKET_CODE_VALID
#define PROCESS_INST			process_dhcpv4_t
#include <freeradius-devel/server/process.h>

RESUME(check_yiaddr)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->reply_pairs, attr_yiaddr, 0);
	if (!vp) {
		REDEBUG("%s packet does not have YIADDR.  The client will not receive an IP address.",
			dhcp_message_types[request->reply->code]);
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
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(discover),
	},
	[FR_DHCP_OFFER] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_OFFER,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_OFFER,

			[RLM_MODULE_REJECT] =  	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_check_yiaddr,
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
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(request),
	},
	[FR_DHCP_ACK] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_ACK,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_ACK,

			[RLM_MODULE_REJECT] =  	FR_DHCP_NAK,
			[RLM_MODULE_FAIL] =	FR_DHCP_NAK,
			[RLM_MODULE_INVALID] =	FR_DHCP_NAK,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_NAK,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_NAK,
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_check_yiaddr,
		.section_offset = PROCESS_CONF_OFFSET(ack),
	},
	[FR_DHCP_NAK] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_DHCP_NAK,
			[RLM_MODULE_NOOP] =	FR_DHCP_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DHCP_NAK,

			[RLM_MODULE_REJECT] =  	FR_DHCP_NAK,
			[RLM_MODULE_FAIL] =	FR_DHCP_NAK,
			[RLM_MODULE_INVALID] =	FR_DHCP_NAK,
			[RLM_MODULE_DISALLOW] =	FR_DHCP_NAK,
			[RLM_MODULE_NOTFOUND] =	FR_DHCP_NAK,
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(ack),
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
		},
		.rcode = RLM_MODULE_NOOP,
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
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = PROCESS_CONF_OFFSET(request),
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
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_DHCP_DO_NOT_RESPOND,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
};

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->instance, process_dhcpv4_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "dhcpv4";
	request->module = NULL;
	fr_assert(request->dict == dict_dhcpv4);

	UPDATE_STATE(packet);

	dhcpv4_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

static const virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Discover",
		.component = MOD_POST_AUTH,

		.methods = (const virtual_server_method_t[]) {
			{
				.name = "ippool",
				.name2 = "allocate",
			},
			COMPILE_TERMINATOR
		},
		.offset = PROCESS_CONF_OFFSET(discover),
	},
	{
		.name = "send",
		.name2 = "Offer",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(offer),
	},
	{
		.name = "recv",
		.name2 = "Request",
		.component = MOD_POST_AUTH,

		.methods = (const virtual_server_method_t[]) {
			{
				.name = "ippool",
				.name2 = "extend",
			},
			COMPILE_TERMINATOR
		},
		.offset = PROCESS_CONF_OFFSET(request),
	},

	{
		.name = "send",
		.name2 = "Ack",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(ack),
	},
	{
		.name = "send",
		.name2 = "NAK",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(nak),
	},
	{
		.name = "recv",
		.name2 = "Decline",
		.component = MOD_POST_AUTH,

		.methods = (const virtual_server_method_t[]) {
			{
				.name = "ippool",
				.name2 = "mark",
			},
			COMPILE_TERMINATOR
		},
		.offset = PROCESS_CONF_OFFSET(decline),
	},

	{
		.name = "recv",
		.name2 = "Release",
		.component = MOD_POST_AUTH,

		.methods = (const virtual_server_method_t[]) {
			{
				.name = "ippool",
				.name2 = "release",
			},
			COMPILE_TERMINATOR
		},
		.offset = PROCESS_CONF_OFFSET(release),
	},
	{
		.name = "recv",
		.name2 = "Inform",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(inform),
	},

#if 0
	/*
	 *	These are for TCP transport.
	 */
	{
		.name = "recv",
		.name2 = "Lease-Query",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(lease_query),
	},
	{
		.name = "send",
		.name2 = "Lease-Unassigned",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(lease_unassigned),
	},
	{
		.name = "send",
		.name2 = "Lease-Unknown",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(lease_unknown),
	},
	{
		.name = "send",
		.name2 = "Lease-Active",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(lease_active),
	},
#endif

	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_dhcpv4;
fr_process_module_t process_dhcpv4 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_dhcpv4",
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_dhcpv4,
};
