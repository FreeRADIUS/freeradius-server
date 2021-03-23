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
 * This code was originally written under contract for Network RADIUS
 * but has been substantially modified from its original form outside
 * of the project that required its creation.
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
#define LOG_PREFIX "process_dhcpv6 - "

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/dhcpv6/dhcpv6.h>
#include <freeradius-devel/protocol/dhcpv6/freeradius.internal.h>

static fr_dict_t const *dict_dhcpv6;

extern fr_dict_autoload_t process_dhcpv6_dict[];
fr_dict_autoload_t process_dhcpv6_dict[] = {
	{ .out = &dict_dhcpv6, .proto = "dhcpv6" },
	{ NULL }
};

static fr_dict_attr_t const *attr_client_id;
static fr_dict_attr_t const *attr_server_id;
static fr_dict_attr_t const *attr_hop_count;
static fr_dict_attr_t const *attr_interface_id;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_relay_link_address;
static fr_dict_attr_t const *attr_relay_peer_address;
static fr_dict_attr_t const *attr_transaction_id;
static fr_dict_attr_t const *attr_status_code_value;

extern fr_dict_attr_autoload_t process_dhcpv6_dict_attr[];
fr_dict_attr_autoload_t process_dhcpv6_dict_attr[] = {
	{ .out = &attr_client_id, .name = "Client-ID", .type = FR_TYPE_STRUCT, .dict = &dict_dhcpv6 },
	{ .out = &attr_hop_count, .name = "Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv6 },
	{ .out = &attr_interface_id, .name = "Interface-ID", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv6 },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv6 },
	{ .out = &attr_relay_link_address, .name = "Relay-Link-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_dhcpv6 },
	{ .out = &attr_relay_peer_address, .name = "Relay-Peer-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_dhcpv6 },
	{ .out = &attr_server_id, .name = "Server-ID", .type = FR_TYPE_STRUCT, .dict = &dict_dhcpv6 },
	{ .out = &attr_status_code_value, .name = "Status-Code.Value", .type = FR_TYPE_UINT16, .dict = &dict_dhcpv6 },
	{ .out = &attr_transaction_id, .name = "Transaction-Id", .type = FR_TYPE_OCTETS, .dict = &dict_dhcpv6 },
	{ NULL }
};

static fr_value_box_t const	*enum_status_code_success;
static fr_value_box_t const	*enum_status_code_unspec_fail;
static fr_value_box_t const	*enum_status_code_not_on_link;
static fr_value_box_t const	*enum_status_code_no_binding;

extern fr_dict_enum_autoload_t process_dhcpv6_dict_enum[];
fr_dict_enum_autoload_t process_dhcpv6_dict_enum[] = {
	{ .out = &enum_status_code_success, .name = "success", .attr = &attr_status_code_value },
	{ .out = &enum_status_code_unspec_fail, .name = "UnspecFail", .attr = &attr_status_code_value },
	{ .out = &enum_status_code_not_on_link, .name = "NotOnLink", .attr = &attr_status_code_value },
	{ .out = &enum_status_code_no_binding, .name = "NoBinding", .attr = &attr_status_code_value },
	{ NULL }
};

/*
 *	DHCPV6 state machine configuration
 */
typedef struct {
	uint64_t	nothing;			// so that "solicit" isn't at offset 0

	CONF_SECTION	*recv_solicit;
	CONF_SECTION	*recv_request;
	CONF_SECTION	*recv_confirm;
	CONF_SECTION	*recv_renew;
	CONF_SECTION	*recv_rebind;
	CONF_SECTION	*recv_release;
	CONF_SECTION	*recv_decline;
	CONF_SECTION	*recv_reconfigure;

	CONF_SECTION	*recv_information_request;
	CONF_SECTION	*recv_relay_forward;

	CONF_SECTION	*send_advertise;
	CONF_SECTION	*send_reply;
	CONF_SECTION	*send_relay_reply;

	CONF_SECTION	*do_not_respond;
} process_dhcpv6_sections_t;

typedef struct {
	CONF_SECTION			*server_cs;	//!< Our virtual server.
	process_dhcpv6_sections_t	sections;	//!< Pointers to various config sections
							///< we need to execute.
} process_dhcpv6_t;

/** Records fields from the original request so we have a known good copy
 */
typedef struct {
	fr_pair_t	*transaction_id;
	fr_pair_t	*client_id;
	fr_pair_t	*server_id;
} process_dhcpv6_client_fields_t;

/** Records fields from the original relay-request so we have a known good copy
 */
typedef struct {
	fr_pair_t	*hop_count;
	fr_pair_t	*link_address;
	fr_pair_t	*peer_address;
} process_dhcpv6_relay_fields_t;

#define PROCESS_PACKET_TYPE		fr_dhcpv6_packet_code_t
#define PROCESS_CODE_MAX		FR_DHCPV6_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_DHCPV6_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_DHCPV6_PACKET_CODE_VALID
#define PROCESS_INST			process_dhcpv6_t

/*
 *	DHCPv6 is nonstandard in that we reply
 *	to the majority of requests, but include a
 *	status code to indicate failures.
 */
#define PROCESS_STATE_EXTRA_FIELDS	fr_value_box_t const **status_codes[RLM_MODULE_NUMCODES];
#include <freeradius-devel/server/process.h>

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

/** Keep a copy of header fields to prevent them being tampered with
 *
 */
static inline CC_HINT(always_inline)
process_dhcpv6_client_fields_t *dhcpv6_client_fields_store(request_t *request, bool expect_server_id)
{
	fr_pair_t			*transaction_id, *client_id, *server_id;
	process_dhcpv6_client_fields_t	*rctx;

	transaction_id = fr_pair_find_by_da(&request->request_pairs, attr_transaction_id);
	if (!transaction_id) {
		REDEBUG("Missing Transaction-ID");
		return NULL;
	}

	if (transaction_id->vp_length != DHCPV6_TRANSACTION_ID_LEN) {
		REDEBUG("Invalid Transaction-ID, expected len %u, got len %zu",
			DHCPV6_TRANSACTION_ID_LEN, transaction_id->vp_length);
		return NULL;
	}

	client_id = fr_pair_find_by_ancestor(&request->request_pairs, attr_client_id);
	if (!client_id) {
		REDEBUG("Missing Client-ID");
		return NULL;
	}

	server_id = fr_pair_find_by_da(&request->request_pairs, attr_server_id);
	if (!server_id && expect_server_id) {
		REDEBUG("Missing Server-ID");
		return NULL;
	} else if (server_id && !expect_server_id) {
		REDEBUG("Server-ID should not be present");
		return NULL;
	}

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), process_dhcpv6_client_fields_t));
	rctx->transaction_id = fr_pair_copy(rctx, transaction_id);
	rctx->client_id = fr_pair_copy(rctx, client_id);
	if (expect_server_id) rctx->server_id = fr_pair_copy(rctx, server_id);

	return rctx;
}

/** Validate a solicit/rebind/confirm message
 *
 * Servers MUST discard any solicit/rebind/confirm  messages that
 * do not include a Client Identifier option or that do include a
 * Server Identifier option.
 */
RECV(for_any_server)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	process_dhcpv6_t const		*inst = mctx->instance;
	process_dhcpv6_client_fields_t	*rctx = NULL;

	PROCESS_TRACE;

	rctx = dhcpv6_client_fields_store(request, false);
	if (!rctx) RETURN_MODULE_INVALID;

	UPDATE_STATE_CS(packet);

	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->resume,
					      NULL, rctx);
}

/** Validate a request/renew/decline/release
 *
 * Servers MUST discard any received Request message that meet any of
 * the following conditions:
 *
 * -  the message does not include a Server Identifier option.
 *
 * -  the contents of the Server Identifier option do not match the
 *    server's DUID.
 *
 * -  the message does not include a Client Identifier option.
 *
 * Servers MUST discard any received Confirm messages that do not
 * include a Client Identifier option or that do include a Server
 * Identifier option.
 */
RECV(for_this_server)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	process_dhcpv6_t const		*inst = mctx->instance;
	process_dhcpv6_client_fields_t	*rctx;

	PROCESS_TRACE;

	rctx = dhcpv6_client_fields_store(request, true);
	if (!rctx) RETURN_MODULE_INVALID;

	UPDATE_STATE_CS(packet);

	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->resume,
					      NULL, rctx);
}

/** Copy a reply pair back into the response
 *
 */
static inline CC_HINT(always_inline)
int restore_field(request_t *request, fr_pair_t **to_restore)
{
	fr_pair_t			*vp;

	VP_VERIFY(*to_restore);

	vp = fr_pair_find_by_da(&request->reply_pairs, (*to_restore)->da);
	if (vp) {
		if (fr_pair_cmp(vp, *to_restore) != 0) {
			RWDEBUG("&reply.%pP does not match &request.%pP", vp, *to_restore);
			return 0;
		}
	} else if (fr_pair_steal_append(request->reply_ctx, &request->reply_pairs, *to_restore) < 0) {
		RPERROR("Failed adding %s", (*to_restore)->da->name);
		return -1;
	}
	*to_restore = NULL;

	return 0;
}

/** Add a status code if one doesn't already exist
 *
 */
static inline CC_HINT(always_inline)
void status_code_add(request_t *request, fr_value_box_t const **code)
{
	fr_pair_t		*vp;

	if (!code) return;

	/*
	 *	Don't override user
	 */
	if (pair_update_reply(&vp, attr_status_code_value) == 1) return;
	fr_value_box_copy(vp, &vp->data, *code);
}

/** Restore our copy of the header fields into the reply list
 *
 */
RESUME(send_to_client)
{
	process_dhcpv6_client_fields_t	*fields = talloc_get_type_abort(rctx, process_dhcpv6_client_fields_t);
	fr_process_state_t const	*state;


	UPDATE_STATE(reply);

	/*
	 *	Don't bother adding VPs if we're not going
	 *	be responding to the client.
	 */
	if (state->packet_type[*p_result] == FR_DHCPV6_DO_NOT_RESPOND) return CALL_RESUME(send_generic);

	/*
	 *	Add a status code if we have one
	 */
	status_code_add(request, state->status_codes[*p_result]);

	/*
	 *	If we have a status code entry then we'll
	 *	be returning something to the client and
	 *	need to fill in all these fields
	 */
	if (unlikely(restore_field(request, &fields->transaction_id) < 0)) {
	fail:
		*p_result = RLM_MODULE_FAIL;
		return CALL_RESUME(send_generic);
	}
	if (unlikely(restore_field(request, &fields->client_id) < 0)) goto fail;
	if (fields->server_id && unlikely(restore_field(request, &fields->server_id) < 0)) goto fail;

	return CALL_RESUME(send_generic);
}

/** Record the original hop-count, link-address, peer-address etc...
 *
 */
static inline CC_HINT(always_inline)
process_dhcpv6_relay_fields_t *dhcpv6_relay_fields_store(request_t *request)
{
	fr_pair_t		 	*hop_count, *link_address, *peer_address;
	process_dhcpv6_relay_fields_t	*rctx;

	hop_count = fr_pair_find_by_da(&request->request_pairs, attr_hop_count);
	if (!hop_count) {
		REDEBUG("Missing Hop-Count");
		return NULL;
	}

	link_address = fr_pair_find_by_ancestor(&request->request_pairs, attr_relay_link_address);
	if (!link_address) {
		REDEBUG("Missing Link-Address");
		return NULL;
	}

	if (link_address->vp_length != DHCPV6_LINK_ADDRESS_LEN) {
		REDEBUG("Invalid Link-Address, expected len %u, got len %zu",
			DHCPV6_LINK_ADDRESS_LEN, link_address->vp_length);
		return NULL;
	}

	peer_address = fr_pair_find_by_ancestor(&request->request_pairs, attr_relay_peer_address);
	if (!peer_address) {
		REDEBUG("Missing Peer-Address");
		return NULL;
	}

	if (peer_address->vp_length != DHCPV6_PEER_ADDRESS_LEN) {
		REDEBUG("Invalid Peer-Address, expected len %u, got len %zu",
			DHCPV6_PEER_ADDRESS_LEN, peer_address->vp_length);
		return NULL;
	}

	/*
	 *	Remember the relay fields
	 */
	MEM(rctx = talloc(unlang_interpret_frame_talloc_ctx(request), process_dhcpv6_relay_fields_t));
	MEM(rctx->hop_count = fr_pair_copy(rctx, hop_count));
	MEM(rctx->link_address = fr_pair_copy(rctx, link_address));
	MEM(rctx->peer_address = fr_pair_copy(rctx, peer_address));

	return rctx;
}

/** Ensure we have the necessary pairs from the relay
 *
 */
RECV(from_relay)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	process_dhcpv6_t const		*inst = mctx->instance;
	process_dhcpv6_relay_fields_t	*rctx = NULL;

	rctx = dhcpv6_relay_fields_store(request);
	if (!rctx) *p_result = RLM_MODULE_INVALID;

	UPDATE_STATE_CS(packet);

	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->resume,
					      NULL, rctx);
}

/** Restore our copy of the header fields into the reply list
 *
 */
RESUME(send_to_relay)
{
	process_dhcpv6_relay_fields_t	*fields = talloc_get_type_abort(rctx, process_dhcpv6_relay_fields_t);
	fr_process_state_t const	*state;

	UPDATE_STATE(reply);

	/*
	 *	Add a status code if we have one
	 */
	status_code_add(request, state->status_codes[*p_result]);

	/*
	 *	Restore relay fields
	 */
	if (unlikely(restore_field(request, &fields->hop_count) < 0)) {
	fail:
		*p_result = RLM_MODULE_FAIL;
		return CALL_RESUME(send_generic);
	}
	if (unlikely(restore_field(request, &fields->link_address) < 0)) goto fail;
	if (unlikely(restore_field(request, &fields->peer_address) < 0)) goto fail;

	return CALL_RESUME(send_generic);
}

/** Main dispatch function
 *
 */
static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->instance, process_dhcpv6_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "dhcpv6";
	fr_assert(request->dict == dict_dhcpv6);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_MODULE_FAIL;
	}

	dhcpv6_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	process_dhcpv6_t	*inst = instance;

	inst->server_cs = cf_section_find_in_parent(cs, "server", CF_IDENT_ANY);

	return 0;
}

static fr_process_state_t const process_state[] = {
	/*
	 *	A client sends a Solicit message to locate
	 *	servers.
	 */
	[ FR_DHCPV6_SOLICIT ] = {
		.recv = recv_for_any_server,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_DHCPV6_ADVERTISE,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_ADVERTISE,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_DO_NOT_RESPOND
		},
		.status_codes = {
			/* RLM_MODULE_NOOP	- No response */
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			/* RLM_MODULE_FAIL	- No response */
			/* RLM_MODULE_INVALID	- No response */
			/* RLM_MODULE_REJECT	- No response */
			/* RLM_MODULE_DISALLOW	- No response */
			/* RLM_MODULE_NOTFOUND	- No response */
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_solicit),
	},

	/*
	 *	A client sends a Request message to request
	 *	configuration parameters, including IP
	 *	addresses, from a specific server.
	 */
	[ FR_DHCPV6_REQUEST ] = {
		.recv = recv_for_this_server,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_OK]		= FR_DHCPV6_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_REPLY,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_INVALID]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_request),
	},

	/*
	 *	A client sends a Confirm message to any
	 *	available server to determine whether the
	 *	addresses it was assigned are still appropriate
	 *	to the link to which the client is connected.
	 */
	[ FR_DHCPV6_CONFIRM ] = {
		.recv = recv_for_any_server,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_DHCPV6_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_REPLY,
			/* RLM_MODULE_HANDLED - Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_DO_NOT_RESPOND
		},

		/*
		 *	When the server receives a Confirm message, the server determines
		 *	whether the addresses in the Confirm message are appropriate for the
		 *	link to which the client is attached.  If all of the addresses in the
		 *	Confirm message pass this test, the server returns a status of
		 *	Success.  If any of the addresses do not pass this test, the server
		 *	returns a status of NotOnLink.  If the server is unable to perform
		 *	this test (for example, the server does not have information about
		 *	prefixes on the link to which the client is connected), or there were
		 *	no addresses in any of the IAs sent by the client, the server MUST
		 *	NOT send a reply to the client.
		 */
		.status_codes = {
			/* RLM_MODULE_NOOP	- No response */
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			/* RLM_MODULE_FAIL	- No response */
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_not_on_link,
			/* RLM_MODULE_DISALLOW	- No response */
			/* RLM_MODULE_NOTFOUND	- No response */
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_confirm),
	},

	/*
	 *	A client sends a Renew message to the server
	 *	that originally provided the client's addresses
	 *	and configuration parameters to extend the
	 *	lifetimes on the addresses assigned to the
	 *	client and to update other configuration
	 *	parameters.
	 */
	[ FR_DHCPV6_RENEW ] = {
		.recv = recv_for_this_server,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_OK]		= FR_DHCPV6_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_REPLY,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_REPLY
		},

   		/*
   		 *	If the server cannot find a client entry for the IA the server
		 *	returns the IA containing no addresses with a Status Code option set
  		 *	to NoBinding in the Reply message.
  		 */
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_no_binding,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_no_binding
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_renew),
	},

	/*
	 *	A client sends a Rebind message to any
	 *	available server to extend the lifetimes on the
	 *	addresses assigned to the client and to update
	 *	other configuration parameters; this message is
	 *	sent after a client receives no response to a
	 *	Renew message.
	 */
	[ FR_DHCPV6_REBIND ] = {
		.recv = recv_for_any_server,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_OK]		= FR_DHCPV6_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_REPLY,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_rebind),
	},
	/*
	 *	A client sends an Information-request
	 *	message to a server to request configuration
	 *	parameters without the assignment of any IP
	 *	addresses to the client.
	 */
	[ FR_DHCPV6_INFORMATION_REQUEST ] = {
		.recv = recv_for_this_server,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_OK]		= FR_DHCPV6_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_REPLY,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_information_request),
	},
	/*
	 *	A client sends a Release message to the server
	 *	that assigned addresses to the client to
	 *	indicate that the client will no longer use one
	 *	or more of the assigned addresses.
	 */
	[ FR_DHCPV6_RELEASE ] = {
		.recv = recv_for_this_server,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_OK]		= FR_DHCPV6_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_REPLY,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,

		.section_offset = offsetof(process_dhcpv6_sections_t, recv_release),
	},
	/*
	 *
	 *	A client sends a Decline message to a server to
	 *	indicate that the client has determined that
	 *	one or more addresses assigned by the server
	 *	are already in use on the link to which the
	 *	client is connected.
	 */
	[ FR_DHCPV6_DECLINE ] = {
		.recv = recv_for_this_server,	/* Need to check for attributes */
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_OK]		= FR_DHCPV6_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_REPLY,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_decline),
	},
	/*
	 *	A relay agent sends a Relay-forward message
	 *	to relay messages to servers, either directly
	 *	or through another relay agent.  The received
	 *	message, either a client message or a
	 *	Relay-forward message from another relay
	 *	agent, is encapsulated in an option in the
	 *	Relay-forward message.
	 */
	[ FR_DHCPV6_RELAY_FORWARD ] = {
		.recv = recv_from_relay,
		.resume = resume_recv_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_OK]		= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_RELAY_REPLY,
			/* RLM_MODULE_HANDLED	- Requires the user to set packet-type */

			[RLM_MODULE_FAIL]	= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_RELAY_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, recv_relay_forward),
	},
	/*
	 *	A server sends an Advertise message to indicate
	 *	that it is available for DHCP service, in
	 *	response to a Solicit message received from a
	 *	client.
	 */
	[ FR_DHCPV6_ADVERTISE ] = {
		.send = send_generic,
		.resume = resume_send_to_client,
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_DO_NOT_RESPOND
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_success,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			/* RLM_MODULE_FAIL	- No response */
			/* RLM_MODULE_INVALID	- No response */
			/* RLM_MODULE_REJECT	- No response */
			/* RLM_MODULE_DISALLOW	- No response */
			/* RLM_MODULE_NOTFOUND	- No response */
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, send_advertise),
	},
	/*
	 *	A server sends a Reply message containing
	 *	assigned addresses and configuration parameters
	 *	in response to a Solicit, Request, Renew,
	 *	Rebind message received from a client.  A
	 *	server sends a Reply message containing
	 *	configuration parameters in response to an
	 *	Information-request message.  A server sends a
	 *	Reply message in response to a Confirm message
	 *	confirming or denying that the addresses
	 *	assigned to the client are appropriate to the
	 *	link to which the client is connected.  A
	 *	server sends a Reply message to acknowledge
	 *	receipt of a Release or Decline message.
	 */
	[ FR_DHCPV6_REPLY ] = {
		.send = send_generic,
		.resume = resume_send_to_client,
		.packet_type = {

			[RLM_MODULE_FAIL]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_success,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, send_reply),
	},
	/*
	 *	A server sends a Relay-reply message to a relay
	 *	agent containing a message that the relay
	 *	agent delivers to a client.  The Relay-reply
	 *	message may be relayed by other relay agents
	 *	for delivery to the destination relay agent.
	 *	The server encapsulates the client message as
	 *	an option in the Relay-reply message, which the
	 *	relay agent extracts and relays to the client.
	 */
	[ FR_DHCPV6_RELAY_REPLY ] = {
		.send = send_generic,
		.resume = resume_send_to_relay,
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_RELAY_REPLY,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_RELAY_REPLY
		},
		.status_codes = {
			[RLM_MODULE_NOOP]	= &enum_status_code_success,
			[RLM_MODULE_OK]		= &enum_status_code_success,
			[RLM_MODULE_UPDATED]	= &enum_status_code_success,
			/* RLM_MODULE_HANDLED	- Requires the user to set status-code */

			[RLM_MODULE_FAIL]	= &enum_status_code_unspec_fail,
			/* RLM_MODULE_INVALID	- No response */
			[RLM_MODULE_REJECT]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_DISALLOW]	= &enum_status_code_unspec_fail,
			[RLM_MODULE_NOTFOUND]	= &enum_status_code_unspec_fail
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, send_relay_reply),
	},

	[ FR_DHCPV6_DO_NOT_RESPOND ] = {
		.send = send_generic,
		.resume = resume_send_generic,
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_HANDLED]	= FR_DHCPV6_DO_NOT_RESPOND,

			[RLM_MODULE_FAIL]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_DHCPV6_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_DHCPV6_DO_NOT_RESPOND
		},
		.rcode = RLM_MODULE_NOOP,
		.section_offset = offsetof(process_dhcpv6_sections_t, do_not_respond),
	}
};

static const virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Solicit",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_solicit)
	},
	{
		.name = "recv",
		.name2 = "Request",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_request)
	},
	{
		.name = "recv",
		.name2 = "Confirm",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_confirm)
	},
	{
		.name = "recv",
		.name2 = "Renew",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_renew)
	},
	{
		.name = "recv",
		.name2 = "Rebind",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_rebind)
	},
	{
		.name = "recv",
		.name2 = "Release",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_release)
	},
	{
		.name = "recv",
		.name2 = "Decline",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_decline)
	},
	{
		.name = "recv",
		.name2 = "Reconfigure",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_reconfigure)
	},
	{
		.name = "recv",
		.name2 = "Information-Request",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_information_request)
	},
	{
		.name = "recv",
		.name2 = "Relay-Forward",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(recv_relay_forward)
	},

	{
		.name = "send",
		.name2 = "Advertise",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(send_advertise)
	},
	{
		.name = "send",
		.name2 = "Reply",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(send_reply)
	},
	{
		.name = "send",
		.name2 = "Relay-Reply",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(send_relay_reply)
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(do_not_respond)
	},
	COMPILE_TERMINATOR
};

extern fr_process_module_t process_dhcpv6;
fr_process_module_t process_dhcpv6 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_dhcpv6",
//	.config		= config,
	.inst_size	= sizeof(process_dhcpv6_t),

	.bootstrap	= mod_bootstrap,

	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_dhcpv6
};
