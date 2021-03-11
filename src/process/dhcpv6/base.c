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
 * @file src/process/dhcpv6/base.c
 * @brief Base DHCPV6 processing.
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
#define LOG_PREFIX "process_dhcpv6 - "

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/dhcpv6/dhcpv6.h>

/*
 *	No one outside of proto_dhcpv6 needs this definition.
 */
#define FR_DHCPV6_DO_NOT_RESPOND (256)

static fr_dict_t const *dict_dhcpv6;

extern fr_dict_autoload_t process_dhcpv6_dict[];
fr_dict_autoload_t process_dhcpv6_dict[] = {
	{ .out = &dict_dhcpv6, .proto = "dhcpv6" },
	{ NULL }
};

static fr_dict_attr_t const *attr_client_id;
static fr_dict_attr_t const *attr_hop_count;
static fr_dict_attr_t const *attr_interface_id;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_relay_link_address;
static fr_dict_attr_t const *attr_relay_peer_address;
static fr_dict_attr_t const *attr_transaction_id;

extern fr_dict_attr_autoload_t process_dhcpv6_dict_attr[];
fr_dict_attr_autoload_t process_dhcpv6_dict_attr[] = {
	{ .out = &attr_client_id, .name = "Client-ID", .type = FR_TYPE_STRUCT, .dict = &dict_dhcpv6 },
	{ .out = &attr_hop_count, .name = "Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv6 },
	{ .out = &attr_interface_id, .name = "Interface-ID", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv6 },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6 },
	{ .out = &attr_relay_link_address, .name = "Relay-Link-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_dhcpv6 },
	{ .out = &attr_relay_peer_address, .name = "Relay-Peer-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_dhcpv6 },
	{ .out = &attr_transaction_id, .name = "Transaction-Id", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv6 },
	{ NULL }
};

/*
 *	Debug the packet if requested.
 */
static void dhcpv6_packet_debug(request_t *request, fr_radius_packet_t const *packet, fr_pair_list_t const *list, bool received)
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
		    fr_dhcpv6_packet_types[packet->code],
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

/** Generate a reply using the attributes we received in the request
 *
 * This should be called before the user has the opportunity to mangle
 * the request so that we get the original values.
 */
static inline CC_HINT(always_inline) void dhcpv6_reply_initialise(request_t *request)
{
	fr_pair_t	*vp;

	switch (request->packet->code) {
	case FR_DHCPV6_RELAY_FORWARD:
		for (vp = fr_pair_list_head(&request->request_pairs);
		     vp;
		     vp = fr_pair_list_next(&request->request_pairs, vp)) {
		     	if (vp->da == attr_hop_count) {
		     		fr_pair_add(&request->reply_pairs, fr_pair_copy(request->reply_ctx, vp));
		     		continue;
		     	}
		     	if (vp->da == attr_relay_link_address) {
		     		fr_pair_add(&request->reply_pairs, fr_pair_copy(request->reply_ctx, vp));
		     		continue;
		     	}
		     	if (vp->da == attr_relay_peer_address) {
		     		fr_pair_add(&request->reply_pairs, fr_pair_copy(request->reply_ctx, vp));
		     		continue;
		     	}
		     	if (vp->da == attr_interface_id) {
		     		fr_pair_add(&request->reply_pairs, fr_pair_copy(request->reply_ctx, vp));
		     		continue;
		     	}
		}
		break;

	default:
		fr_pair_list_copy_by_da(request->reply_ctx, &request->reply_pairs, &request->request_pairs, attr_transaction_id, 1);
		fr_pair_list_copy_by_ancestor(request->reply_ctx, &request->reply_pairs, &request->request_pairs, attr_client_id, 0);
		break;
	}
}

static unlang_action_t mod_process(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	rlm_rcode_t		rcode;
	CONF_SECTION		*unlang;
	fr_dict_enum_t const	*dv;
	fr_pair_t		*vp;

	static int reply_ok[] = {
		[0]				= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_SOLICIT]		= FR_DHCPV6_ADVERTISE,
		[FR_DHCPV6_REQUEST]		= FR_DHCPV6_REPLY,
		[FR_DHCPV6_CONFIRM]		= FR_DHCPV6_REPLY,
		[FR_DHCPV6_RENEW]		= FR_DHCPV6_REPLY,
		[FR_DHCPV6_REBIND]		= FR_DHCPV6_REPLY,
		[FR_DHCPV6_RELEASE]		= FR_DHCPV6_REPLY,
		[FR_DHCPV6_DECLINE]		= FR_DHCPV6_REPLY,
		[FR_DHCPV6_INFORMATION_REQUEST]	= FR_DHCPV6_REPLY,
		[FR_DHCPV6_RELAY_FORWARD]	= FR_DHCPV6_RELAY_REPLY
	};

	static int reply_fail[] = {
		[0]				= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_SOLICIT]		= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_REQUEST]		= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_CONFIRM]		= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_RENEW]		= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_REBIND]		= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_RELEASE]		= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_DECLINE]		= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_INFORMATION_REQUEST]	= FR_DHCPV6_DO_NOT_RESPOND,
		[FR_DHCPV6_RELAY_FORWARD]	= FR_DHCPV6_DO_NOT_RESPOND
	};

#define REPLY_OK(_code, _default)	((_code < NUM_ELEMENTS(reply_ok)) ? reply_ok[_code] : _default)
#define REPLY_FAIL(_code, _default)	((_code < NUM_ELEMENTS(reply_fail)) ? reply_fail[_code] : _default)

	REQUEST_VERIFY(request);
	fr_assert(request->packet->code > 0);
	fr_assert(request->packet->code < NUM_ELEMENTS(reply_ok));

	switch (request->request_state) {
	case REQUEST_INIT:
	{
		dhcpv6_packet_debug(request, request->packet, &request->request_pairs, true);

		dhcpv6_reply_initialise(request);

		request->component = "dhcpv6";

		unlang = cf_section_find(request->server_cs, "recv", fr_dhcpv6_packet_types[request->packet->code]);
		if (!unlang) {
			RWDEBUG("Failed to find 'recv %s' section", fr_dhcpv6_packet_types[request->packet->code]);
			request->reply->code = FR_DHCPV6_DO_NOT_RESPOND;
			goto send_reply;
		}

		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		if (unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) {
			RETURN_MODULE_FAIL;
		}

		request->request_state = REQUEST_RECV;
	}
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
		vp = fr_pair_find_by_da(&request->reply_pairs, attr_packet_type);
		if (vp) {
			request->reply->code = vp->vp_uint32;
		} else switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = REPLY_OK(request->packet->code, FR_DHCPV6_DO_NOT_RESPOND);
			break;

		default:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_FAIL:
			request->reply->code = REPLY_FAIL(request->packet->code, FR_DHCPV6_DO_NOT_RESPOND);
			break;

		case RLM_MODULE_HANDLED:
			if (!request->reply->code) request->reply->code = FR_DHCPV6_DO_NOT_RESPOND;
			break;
		}

		/*
		 *	Release / Decline doesn't send a reply, and doesn't run "send Do-Not-Respond"
		 */
		if (!request->reply->code) {
			RETURN_MODULE_HANDLED;
		}

		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
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
			if (request->reply->code != FR_DHCPV6_DO_NOT_RESPOND) {
				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Do-Not-Respond'", dv->name);

				request->reply->code = FR_DHCPV6_DO_NOT_RESPOND;

				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->name);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->name);
			}
			break;
		}

	send_reply:
		{
			fr_pair_t *reply_packet_type;

			/*
			 *	Add reply->packet-type in case we're
			 *	being called via the `call {}` keyword.
			 */
			MEM(fr_pair_update_by_da(request->reply_ctx, &reply_packet_type,
						 &request->reply_pairs, attr_packet_type) >= 0);
			reply_packet_type->vp_uint32 = request->reply->code;

			/*
			 *	Check for "do not respond".
			 */
			if (request->reply->code == FR_DHCPV6_DO_NOT_RESPOND) {
				RDEBUG("Not sending reply to client");
				RETURN_MODULE_HANDLED;
			}

			if (RDEBUG_ENABLED) dhcpv6_packet_debug(request, request->reply, &request->reply_pairs, false);
		}
		break;

	default:
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
}


static const virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Solicit",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Advertise",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Request",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Confirm",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Renew",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Rebind",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Release",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Decline",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Information-Request",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Reply",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Relay-Forward",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Relay-Reply",
		.component = MOD_POST_AUTH,
	},

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_dhcpv6;
fr_process_module_t process_dhcpv6 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_dhcpv6",
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_dhcpv6,
};
