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
 * @file src/process/dns/base.c
 * @brief DNS processing.
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/dns/dns.h>
#include <freeradius-devel/protocol/dns/rfc1034.h>

/** Update this if new rcodes are added
 */
#define FR_DNS_RCODE_MAX	FR_RCODE_VALUE_BAD_COOKIE

static fr_dict_t const *dict_dns;

extern fr_dict_autoload_t process_dns_dict[];
fr_dict_autoload_t process_dns_dict[] = {
	{ .out = &dict_dns, .proto = "dns" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_header;
static fr_dict_attr_t const *attr_id;
static fr_dict_attr_t const *attr_response_bit;
static fr_dict_attr_t const *attr_opcode;
static fr_dict_attr_t const *attr_rcode;
static fr_dict_attr_t const *attr_authoritative_bit;

extern fr_dict_attr_autoload_t process_dns_dict_attr[];
fr_dict_attr_autoload_t process_dns_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dns},
	{ .out = &attr_header, .name = "Header", .type = FR_TYPE_STRUCT, .dict = &dict_dns},
	{ .out = &attr_opcode, .name = "Header.Opcode", .type = FR_TYPE_UINT8, .dict = &dict_dns},
	{ .out = &attr_id, .name = "Header.ID", .type = FR_TYPE_UINT16, .dict = &dict_dns},
	{ .out = &attr_response_bit, .name = "Header.Query", .type = FR_TYPE_BOOL, .dict = &dict_dns},
	{ .out = &attr_rcode, .name = "Header.Rcode", .type = FR_TYPE_UINT8, .dict = &dict_dns},
	{ .out = &attr_authoritative_bit, .name = "Header.Authoritative", .type = FR_TYPE_BOOL, .dict = &dict_dns},
	DICT_AUTOLOAD_TERMINATOR
};

static fr_value_box_t const *enum_rcode_no_error;
static fr_value_box_t const *enum_rcode_format_error;
static fr_value_box_t const *enum_rcode_server_failure;
static fr_value_box_t const *enum_rcode_name_error;
static fr_value_box_t const *enum_rcode_refused;

extern fr_dict_enum_autoload_t process_dns_dict_enum[];
fr_dict_enum_autoload_t process_dns_dict_enum[] = {
	{ .out = &enum_rcode_no_error, .name = "No-Error", .attr = &attr_rcode },			/* ok/updated */
	{ .out = &enum_rcode_format_error, .name = "Format-Error", .attr = &attr_rcode },		/* invalid */
	{ .out = &enum_rcode_server_failure, .name = "Server-Failure", .attr = &attr_rcode },		/* fail */
	{ .out = &enum_rcode_name_error, .name = "Name-Error", .attr = &attr_rcode },			/* notfound */
	{ .out = &enum_rcode_refused, .name = "Refused", .attr = &attr_rcode },				/* reject */
	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	/** Request/response sections
	 *
	 */
	CONF_SECTION	*query;
	CONF_SECTION	*query_response;
	CONF_SECTION	*inverse_query;
	CONF_SECTION	*inverse_query_response;
	CONF_SECTION	*status;
	CONF_SECTION	*status_response;
	CONF_SECTION	*update;
	CONF_SECTION	*update_response;
	CONF_SECTION	*stateful_operation;
	CONF_SECTION	*stateful_operation_response;

	/** DNS rcode error sections (not the same as rlm_rcode_t values)
	 *
	 * These are called after the `recv { ... }` section runs if rcode is non-zero
	 */
	CONF_SECTION	*rcode[FR_DNS_RCODE_MAX];

	CONF_SECTION	*do_not_respond;
} process_dns_sections_t;

typedef struct {
	process_dns_sections_t	sections;
} process_dns_t;

/** Records fields from the original request so we have a known good copy
 */
typedef struct {
	uint16_t	id;		//!< Identity of the request.
	uint8_t		opcode;		//!< Opcode, what type of query this is.
} process_dns_fields_t;

#define PROCESS_PACKET_TYPE		fr_dns_packet_code_t
#define PROCESS_CODE_MAX		FR_DNS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_DNS_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_DNS_PACKET_CODE_VALID
#define PROCESS_INST			process_dns_t
#define PROCESS_RCTX_EXTRA_FIELDS	process_dns_fields_t fields;

/** Map an rlm_rcode_t to a header.rcode value
 */
#define PROCESS_STATE_EXTRA_FIELDS	fr_value_box_t const **dns_rcode[RLM_MODULE_NUMCODES];

#include <freeradius-devel/server/process.h>

static const virtual_server_compile_t compile_list[] = {
	{
		.section = SECTION_NAME("recv", "Query"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(query),
	},
	{
		.section = SECTION_NAME("send", "Query-Response"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(query_response),
	},
	{
		.section = SECTION_NAME("recv", "Inverse-Query"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(inverse_query),
	},
	{
		.section = SECTION_NAME("send", "Inverse-Query-Response"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(inverse_query_response),
	},
	{
		.section = SECTION_NAME("recv", "Status"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(status),
	},
	{
		.section = SECTION_NAME("send", "Status-Response"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(status_response),
	},
	{
		.section = SECTION_NAME("recv", "Update"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(update),
	},
	{
		.section = SECTION_NAME("send", "Update-Response"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(update_response),
	},
	{
		.section = SECTION_NAME("recv", "Stateful-Operation"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(stateful_operation),
	},
	{
		.section = SECTION_NAME("send", "Stateful-Operation-Response"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(stateful_operation_response),
	},
	{
		.section = SECTION_NAME("send", "Do-Not-Respond"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},

#define ERROR_SECTION(_name, _number) \
	{ \
		.section = SECTION_NAME("error", _name), \
		.actions = &mod_actions_postauth, \
		.offset = PROCESS_CONF_OFFSET(rcode[_number]), \
	}

	/*
	 *	Error sections that can execute after the recv { ... }
	 *	section has run.
	 */
	ERROR_SECTION("Format-Error", FR_RCODE_VALUE_FORMAT_ERROR),
	ERROR_SECTION("Server-Failure", FR_RCODE_VALUE_SERVER_FAILURE),
	ERROR_SECTION("Name-Error", FR_RCODE_VALUE_NAME_ERROR),
	ERROR_SECTION("Not-Implemented", FR_RCODE_VALUE_NOT_IMPLEMENTED),
	ERROR_SECTION("Refused", FR_RCODE_VALUE_REFUSED),
	ERROR_SECTION("YX-Domain", FR_RCODE_VALUE_YX_DOMAIN),
	ERROR_SECTION("YX-Resource-Record-Set", FR_RCODE_VALUE_YX_RESOURCE_RECORD_SET),
	ERROR_SECTION("NX-Resource-Record-Set", FR_RCODE_VALUE_NX_RESOURCE_RECORD_SET),
	ERROR_SECTION("Not-Auth", FR_RCODE_VALUE_NOT_AUTH),
	ERROR_SECTION("Not-Zone", FR_RCODE_VALUE_NOT_ZONE),
	ERROR_SECTION("DSO-Type-Not-Implemented", FR_RCODE_VALUE_DSO_TYPE_NOT_IMPLEMENTED),
	ERROR_SECTION("Bad-Signature", FR_RCODE_VALUE_BAD_SIGNATURE),
	ERROR_SECTION("Bad-Key", FR_RCODE_VALUE_BAD_KEY),
	ERROR_SECTION("Bad-Time", FR_RCODE_VALUE_BAD_TIME),
	ERROR_SECTION("Bad-Mode", FR_RCODE_VALUE_BAD_MODE),
	ERROR_SECTION("Bad-Name", FR_RCODE_VALUE_BAD_NAME),
	ERROR_SECTION("Bad-Algorithm", FR_RCODE_VALUE_BAD_ALGORITHM),
	ERROR_SECTION("Bad-Truncation", FR_RCODE_VALUE_BAD_TRUNCATION),
	ERROR_SECTION("Bad-Cookie", FR_RCODE_VALUE_BAD_COOKIE),
	COMPILE_TERMINATOR
};

/*
 *	Debug the packet if requested.
 */
static void dns_packet_debug(request_t *request, fr_packet_t const *packet, fr_pair_list_t const *list, bool received)
{
	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	if ((packet->code & 0x0f) >= FR_DNS_CODE_MAX) return;

	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s %s",
		    received ? "Received" : "Sending",
		    fr_dns_packet_names[packet->code & 0x0f]);

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
process_rctx_t *dns_fields_store(request_t *request)
{
	fr_pair_t		*header;
	fr_pair_t		*id;
	fr_pair_t		*opcode;
	process_rctx_t		*rctx;

	/*
	 *	We could use fr_find_by_da_nested, but it's more efficient
	 *	to look up the header attribute once.
	 */
	header = fr_pair_find_by_da(&request->request_pairs, NULL, attr_header);
	if (!header) {
		REDEBUG("Missing Header attribute");
		return NULL;
	}

	id = fr_pair_find_by_da(&header->vp_group, NULL, attr_id);
	if (!id) {
		REDEBUG("Missing ID attribute");
		return NULL;
	}

	opcode = fr_pair_find_by_da(&header->vp_group, NULL, attr_opcode);
	if (!opcode) {
		REDEBUG("Missing Opcode attribute");
		return NULL;
	}

	MEM(rctx = talloc(unlang_interpret_frame_talloc_ctx(request), process_rctx_t));
	rctx->fields.id = id->vp_uint16;
	rctx->fields.opcode = opcode->vp_uint8;

	return rctx;
}

/** Copy values from the request header back into the response
 *
 * If a value already exists in the response, don't overwrite it so the user has absolute control
 */
static inline CC_HINT(always_inline)
int dns_fields_restore(request_t *request, process_rctx_t *rctx)
{
	fr_pair_t *header;
	fr_pair_t *id;
	fr_pair_t *response;
	fr_pair_t *authoritative;
	fr_pair_t *opcode;
	int ret;

	MEM(pair_update_reply(&header, attr_header) >= 0);

	/*
	 *	ID should always match the request
	 *	but we allow overrides for testing.
	 */
	MEM((ret = fr_pair_update_by_da_parent(header, &id, attr_id)) != -1);
	fr_assert_msg(ret >= 0, "Failed to update header attribute %s:", fr_strerror());
	if (ret == 0) id->vp_uint16 = rctx->fields.id;

	/*
	 *	This marks the packet as a response.
	 *	Save the user from having to do this manually.
	 */
	MEM((ret = fr_pair_update_by_da_parent(header, &response, attr_response_bit)) != -1);
	fr_assert_msg(ret >= 0, "Failed to update response_bit attribute %s:", fr_strerror());
	if (ret == 0) response->vp_bool = true;

	/*
	 *	Opcode should always match the request
	 *	but we allow overrides for testing.
	 */
	MEM((ret = fr_pair_update_by_da_parent(header, &opcode, attr_opcode)) != -1);
	fr_assert_msg(ret >= 0, "Failed to update opcode attribute %s:", fr_strerror());
	if (ret == 0) opcode->vp_uint8 = rctx->fields.opcode;

	/*
	 *	Default to setting the authoritative bit if
	 *	it's not been set by something already.
	 */
	MEM((ret = fr_pair_update_by_da_parent(header, &authoritative, attr_authoritative_bit)) != -1);
	fr_assert_msg(ret >= 0, "Failed to update authoritative_bit attribute %s:", fr_strerror());
	if (ret == 0) authoritative->vp_bool = true;

	return 0;
}

/** Add/update the rcode attribute based on the last rlm_rcode value
 *
 */
static inline CC_HINT(always_inline)
void dns_rcode_add(fr_pair_t **rcode, request_t *request, fr_value_box_t const **code)
{
	fr_value_box_t const	*vb;
	int ret;

	if (!code || !*code) return;

	vb = *code;

	/*
	 *	Don't override the user status
	 *      code.
	 */
	MEM((ret = fr_pair_update_by_da_parent(request->reply_ctx, rcode, attr_rcode)) >= 0);
	if (ret == 0) {
		if (unlikely(fr_value_box_copy(*rcode, &(*rcode)->data, vb) < 0)) {
			RPEDEBUG("Failed copying rcode value");
			return;
		}
		(*rcode)->data.enumv = (*rcode)->da;	/* Hack, boxes should have their enumv field populated */
	}
}

/** Store basic information from the request, and jump into the correct processing section
 *
 */
RECV(request)
{
	process_rctx_t		*rctx;

	PROCESS_TRACE;

	rctx = dns_fields_store(request);
	if (!rctx) RETURN_UNLANG_INVALID;

	return CALL_RECV_RCTX(generic, rctx);
}

/** Sets the DNS rcode after we get a result from the recv section
 *
 * Calls error processing sections as appropriate
 */
RESUME(recv_request)
{
	process_dns_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_dns_t);
	fr_process_state_t const	*state;
	fr_pair_t			*rcode = NULL;

	PROCESS_TRACE;

	/*
	 *	Pick the next state based on the response
	 */
	UPDATE_STATE(reply);

	/*
	 *	Don't bother adding VPs if we're not going
	 *	be responding to the client.
	 */
	if (state->packet_type[RESULT_RCODE] == FR_DNS_DO_NOT_RESPOND) return CALL_RESUME(recv_generic);

	/*
	 *	Add an rcode based on the result of the `recv { ... }` section
	 */
	dns_rcode_add(&rcode, request, state->dns_rcode[RESULT_RCODE]);

	/*
	 *	Call an appropriate error section if it's been set
	 *	otherwise, just call the generic recv resume
	 *	which'll call an appropriate send section.
	 */
	if (rcode && (rcode->vp_uint8 < NUM_ELEMENTS(inst->sections.rcode)) &&
	    (inst->sections.rcode[rcode->vp_uint8])) {
		return unlang_module_yield_to_section(RESULT_P, request,
						      inst->sections.rcode[rcode->vp_uint8],
						      RLM_MODULE_NOOP,
						      /*
						       *	We ignore everything from the error section
						       *	it's only there for logging.
						       *
						       *	Jump straight to the send function.
						       */
						      state->send,
						      NULL, 0, mctx->rctx);
	}

	/*
	 *	Use that rcode to determine the processing section
	 */
	return CALL_RESUME(recv_generic);
}

/** Set defaults in the response and values copied from the request like opcode and id
 *
 */
RESUME(send_response)
{
	fr_process_state_t const	*state;
	fr_pair_t			*vp;

	UPDATE_STATE(reply);

	/*
	 *	Don't bother adding VPs if we're not going
	 *	be responding to the client.
	 */
	if (state->packet_type[RESULT_RCODE] == FR_DNS_DO_NOT_RESPOND) return CALL_RESUME(send_generic);

	/*
	 *	Add fields from the request back in,
	 *	deferring to user specified values.
	 */
	dns_fields_restore(request, talloc_get_type_abort(mctx->rctx, process_rctx_t));

	/*
	 *	Do this last, so we show everything
	 *	we'll be sending back.
	 */
	dns_packet_debug(request, request->reply, &request->reply_pairs, false);

	/*
	 *	Hack.  This is because this stupid framework uses
	 *	packet_type values to represent request and response
	 *	packet types, and DNS uses the same values for
	 *	both request and response packet types.
	 */
	(void) pair_update_reply(&vp, attr_packet_type);
	MEM(vp);
	request->reply->code = vp->vp_uint32 = state->default_reply;

	return CALL_RESUME(send_generic);
}

/** Entry point into the state machine
 */
static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_dns_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "dns";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_dns);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	dns_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

#define DNS_RCODE_COMMON \
	.dns_rcode = { \
		[RLM_MODULE_NOOP] = &enum_rcode_no_error, \
		[RLM_MODULE_OK] = &enum_rcode_no_error, \
		[RLM_MODULE_UPDATED] = &enum_rcode_no_error, \
		[RLM_MODULE_HANDLED] = &enum_rcode_no_error, \
		[RLM_MODULE_REJECT] = &enum_rcode_refused, \
		[RLM_MODULE_FAIL] = &enum_rcode_server_failure, \
		[RLM_MODULE_INVALID] = &enum_rcode_format_error, \
		[RLM_MODULE_DISALLOW] = &enum_rcode_refused, \
		[RLM_MODULE_NOTFOUND] = &enum_rcode_name_error, \
		[RLM_MODULE_TIMEOUT] = &enum_rcode_server_failure, \
	}

static fr_process_state_t const process_state[] = {
	[ FR_DNS_QUERY ] = {
		DNS_RCODE_COMMON,
		.default_reply = FR_DNS_QUERY_RESPONSE,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_request,
		.resume = resume_recv_request,
		.section_offset = PROCESS_CONF_OFFSET(query),
	},
	[ FR_DNS_INVERSE_QUERY ] = {
		DNS_RCODE_COMMON,
		.default_reply = FR_DNS_INVERSE_QUERY_RESPONSE,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_request,
		.resume = resume_recv_request,
		.section_offset = PROCESS_CONF_OFFSET(inverse_query),
	},
	[ FR_DNS_STATUS ] = {
		DNS_RCODE_COMMON,
		.default_reply = FR_DNS_STATUS_RESPONSE,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_request,
		.resume = resume_recv_request,
		.section_offset = PROCESS_CONF_OFFSET(status),
	},
	[ FR_DNS_UPDATE ] = {
		DNS_RCODE_COMMON,
		.default_reply = FR_DNS_UPDATE_RESPONSE,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_request,
		.resume = resume_recv_request,
		.section_offset = PROCESS_CONF_OFFSET(update),
	},
	[ FR_DNS_STATEFUL_OPERATION ] = {
		DNS_RCODE_COMMON,
		.default_reply = FR_DNS_STATEFUL_OPERATION_RESPONSE,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_request,
		.resume = resume_recv_request,
		.section_offset = PROCESS_CONF_OFFSET(stateful_operation),
	},
	[ FR_DNS_QUERY_RESPONSE ] = {
		.default_reply = FR_DNS_QUERY,
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_response,
		.section_offset = PROCESS_CONF_OFFSET(query_response),
	},

	[ FR_DNS_INVERSE_QUERY_RESPONSE ] = {
		.default_reply = FR_DNS_QUERY,
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_response,
		.section_offset = PROCESS_CONF_OFFSET(inverse_query_response),
	},

	[ FR_DNS_STATUS_RESPONSE ] = {
		.default_reply = FR_DNS_STATUS,
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_response,
		.section_offset = PROCESS_CONF_OFFSET(status_response),
	},

	[ FR_DNS_UPDATE_RESPONSE ] = {
		.default_reply = FR_DNS_UPDATE,
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_response,
		.section_offset = PROCESS_CONF_OFFSET(update_response),
	},

	[ FR_DNS_STATEFUL_OPERATION_RESPONSE ] = {
		.default_reply = FR_DNS_STATEFUL_OPERATION,
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_response,
		.section_offset = PROCESS_CONF_OFFSET(stateful_operation_response),
	},

	[ FR_DNS_DO_NOT_RESPOND ] = {
		.packet_type = {
			[RLM_MODULE_NOOP] = 	FR_DNS_DO_NOT_RESPOND,
			[RLM_MODULE_OK] = 	FR_DNS_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_DNS_DO_NOT_RESPOND,

			[RLM_MODULE_REJECT] =	FR_DNS_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_DNS_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_DNS_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_DNS_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_DNS_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT] =	FR_DNS_DO_NOT_RESPOND,
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_HANDLED,
		.send = send_generic,
		.resume = resume_send_response,
		.section_offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
};

extern fr_process_module_t process_dns;
fr_process_module_t process_dns = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "dns",
		MODULE_INST(process_dns_t),
		MODULE_RCTX(process_rctx_t)
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_dns,
	.packet_type	= &attr_packet_type
};
