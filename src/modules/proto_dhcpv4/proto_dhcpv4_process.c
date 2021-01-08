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
 * @file proto_dhcpv4/proto_dhcpv4_process.c
 * @brief Base DORA, etc. DHCPV4 processing.
 *
 * @copyright 2018 The Freeradius server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#define LOG_PREFIX "proto_dhcpv4 - "

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/protocol/dhcpv4/rfc2131.h>

static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t proto_dhcpv4_process_dict[];
fr_dict_autoload_t proto_dhcpv4_process_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_message_type;
static fr_dict_attr_t const *attr_yiaddr;

extern fr_dict_attr_autoload_t proto_dhcpv4_process_dict_attr[];
fr_dict_attr_autoload_t proto_dhcpv4_process_dict_attr[] = {
	{ .out = &attr_message_type, .name = "Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4},
	{ .out = &attr_yiaddr, .name = "Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ NULL }
};

/*
 *	Debug the packet if requested.
 */
static void dhcpv4_packet_debug(request_t *request, fr_radius_packet_t *packet, fr_pair_list_t *list, bool received)
{
	int i;
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
	for (i = 0; dhcp_header_attrs[i] != NULL; i++) {
		fr_pair_t *vp;

		if (!*dhcp_header_attrs[i]) continue;

		vp = fr_pair_find_by_da(list, *dhcp_header_attrs[i]);
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

static unlang_action_t mod_process(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	fr_pair_t *vp;

	static int reply_ok[] = {
		[0]			= FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND,
		[FR_DHCP_DISCOVER]	= FR_DHCP_OFFER,
		[FR_DHCP_OFFER]		= FR_DHCP_OFFER,
		[FR_DHCP_REQUEST]	= FR_DHCP_ACK,
		[FR_DHCP_DECLINE]	= 0,
		[FR_DHCP_ACK]		= FR_DHCP_ACK,
		[FR_DHCP_NAK]		= FR_DHCP_NAK,
		[FR_DHCP_RELEASE]	= 0,
		[FR_DHCP_INFORM]	= FR_DHCP_ACK,
		[FR_DHCP_LEASE_QUERY]	= FR_DHCP_LEASE_ACTIVE, /* not really correct, but whatever */
	};

	static int reply_fail[] = {
		[0]			= FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND,
		[FR_DHCP_DISCOVER]	= 0,
		[FR_DHCP_OFFER]		= FR_DHCP_NAK,
		[FR_DHCP_REQUEST]	= FR_DHCP_NAK,
		[FR_DHCP_DECLINE]	= 0,
		[FR_DHCP_ACK]		= FR_DHCP_NAK,
		[FR_DHCP_NAK]		= FR_DHCP_NAK,
		[FR_DHCP_RELEASE]	= 0,
		[FR_DHCP_INFORM]	= FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND,
		[FR_DHCP_LEASE_QUERY]	= FR_DHCP_LEASE_UNKNOWN,
	};

#define REPLY_OK(_code, _default)	((_code < NUM_ELEMENTS(reply_ok)) ? reply_ok[_code] : _default)
#define REPLY_FAIL(_code, _default)	((_code < NUM_ELEMENTS(reply_fail)) ? reply_fail[_code] : _default)

	REQUEST_VERIFY(request);
	fr_assert(request->packet->code > 0);
	fr_assert(request->packet->code < NUM_ELEMENTS(reply_ok));

	switch (request->request_state) {
	case REQUEST_INIT:
		dhcpv4_packet_debug(request, request->packet, &request->request_pairs, true);

		request->component = "dhcpv4";

		dv = fr_dict_enum_by_value(attr_message_type, fr_box_uint8(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request.DHCP-Message-Type");
			RETURN_MODULE_FAIL;
		}

		unlang = cf_section_find(request->server_cs, "recv", dv->name);
		if (!unlang) {
			RWDEBUG("Failed to find 'recv %s' section", dv->name);
			request->reply->code = FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND;
			goto send_reply;
		}

		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		if (unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) {
			RETURN_MODULE_FAIL;
		}

		request->request_state = REQUEST_RECV;
		FALL_THROUGH;

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) {
			*p_result = RLM_MODULE_HANDLED;
			return UNLANG_ACTION_STOP_PROCESSING;
		}

		if (rcode == RLM_MODULE_YIELD) RETURN_MODULE_YIELD;

		/*
		 *	Allow the admin to explicitly set the reply
		 *	type.
		 */
		vp = fr_pair_find_by_da(&request->reply_pairs, attr_message_type);
		if (vp) {
			request->reply->code = vp->vp_uint8;
		} else switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = REPLY_OK(request->packet->code, FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND);
			break;

		default:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_FAIL:
			request->reply->code = REPLY_FAIL(request->packet->code, FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND);
			break;

		case RLM_MODULE_HANDLED:
			if (!request->reply->code) request->reply->code = FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND;
			break;
		}

		/*
		 *	Release / Decline doesn't send a reply, and doesn't run "send Do-Not-Respond"
		 */
		if (!request->reply->code) {
			RETURN_MODULE_HANDLED;
		}

		/*
		 *	Offer and ACK MUST have YIADDR.
		 */
		if ((request->reply->code == FR_DHCP_OFFER) || (request->reply->code == FR_DHCP_ACK)) {
			vp = fr_pair_find_by_da(&request->reply_pairs, attr_yiaddr);
			if (!vp) {
				REDEBUG("%s packet does not have YIADDR.  The client will not receive an IP address.",
					dhcp_message_types[request->reply->code]);
			}
		}

		dv = fr_dict_enum_by_value(attr_message_type, fr_box_uint8(request->reply->code));
		unlang = NULL;
		if (dv) unlang = cf_section_find(request->server_cs, "send", dv->name);

		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		if (unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) {
			RETURN_MODULE_FAIL;
		}

		request->request_state = REQUEST_SEND;
		FALL_THROUGH;

	case REQUEST_SEND:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) {
			*p_result = RLM_MODULE_HANDLED;
			return UNLANG_ACTION_STOP_PROCESSING;
		}

		if (rcode == RLM_MODULE_YIELD) RETURN_MODULE_YIELD;

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
		case RLM_MODULE_HANDLED:
			/* reply is already set */
			break;

		default:
			/*
			 *	If we over-ride an ACK with a NAK, run
			 *	the NAK section.
			 */
			if (request->reply->code != FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND) {
				dv = fr_dict_enum_by_value(attr_message_type, fr_box_uint8(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Do-Not-Respond'", dv->name);

				request->reply->code = FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND;

				dv = fr_dict_enum_by_value(attr_message_type, fr_box_uint8(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->name);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->name);
			}
			break;
		}

	send_reply:
		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_MESSAGE_TYPE_VALUE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client");
			RETURN_MODULE_HANDLED;
		}

		if (RDEBUG_ENABLED) dhcpv4_packet_debug(request, request->reply, &request->reply_pairs, false);
		break;

	default:
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
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
	},
	{
		.name = "send",
		.name2 = "Offer",
		.component = MOD_POST_AUTH,
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
	},

	{
		.name = "send",
		.name2 = "Ack",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "NAK",
		.component = MOD_POST_AUTH,
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
	},
	{
		.name = "recv",
		.name2 = "Inform",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
	},

	{
		.name = "recv",
		.name2 = "Lease-Query",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Lease-Unassigned",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Lease-Unknown",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Lease-Active",
		.component = MOD_POST_AUTH,
	},

	COMPILE_TERMINATOR
};


extern fr_app_worker_t proto_dhcpv4_process;
fr_app_worker_t proto_dhcpv4_process = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcpv4_process",
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
