/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_radius.c
 * @brief A RADIUS client library.
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Network RADIUS SAS
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>

#include "rlm_radius.h"

static int mode_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int status_check_type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int status_check_update_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int radius_fixups(rlm_radius_t const *inst, request_t *request);

static conf_parser_t const status_check_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("type", FR_TYPE_VOID, 0, rlm_radius_t, status_check),
	  .func = status_check_type_parse },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const status_check_update_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("update", FR_TYPE_VOID, CONF_FLAG_SUBSECTION | CONF_FLAG_REQUIRED, rlm_radius_t, status_check_map),
	  .name2 = CF_IDENT_ANY,
	  .func = status_check_update_parse },
	{ FR_CONF_OFFSET("num_answers_to_alive", rlm_radius_t, num_answers_to_alive), .dflt = STRINGIFY(3) },

	CONF_PARSER_TERMINATOR
};

/*
 *	Retransmission intervals for the packets we support.
 */
static conf_parser_t auth_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("max_rtx_count", rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", rlm_radius_t, retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t acct_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrt), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_count", rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrc), .dflt = STRINGIFY(1) },
	{ FR_CONF_OFFSET("max_rtx_duration", rlm_radius_t, retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t status_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].mrt), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_count", rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", rlm_radius_t, retry[FR_RADIUS_CODE_STATUS_SERVER].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t coa_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("max_rtx_count", rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", rlm_radius_t, retry[FR_RADIUS_CODE_COA_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t disconnect_config[] = {
	{ FR_CONF_OFFSET("initial_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].irt), .dflt = STRINGIFY(2) },
	{ FR_CONF_OFFSET("max_rtx_time", rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrt), .dflt = STRINGIFY(16) },
	{ FR_CONF_OFFSET("max_rtx_count", rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrc), .dflt = STRINGIFY(5) },
	{ FR_CONF_OFFSET("max_rtx_duration", rlm_radius_t, retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrd), .dflt = STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t const transport_config[] = {
	{ FR_CONF_OFFSET_FLAGS("secret", CONF_FLAG_REQUIRED, rlm_radius_t, secret) },

	CONF_PARSER_TERMINATOR
};

/*
 *	We only parse the pool options if we're connected.
 */
static conf_parser_t const connected_config[] = {
	{ FR_CONF_POINTER("status_check", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) status_check_config },

	{ FR_CONF_OFFSET_SUBSECTION("pool", 0, rlm_radius_t, trunk_conf, trunk_config ) },

	{ FR_CONF_POINTER("udp", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OPTIONAL, NULL), .subcs = (void const *) transport_config },

	{ FR_CONF_POINTER("tcp", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OPTIONAL, NULL), .subcs = (void const *) transport_config },

	CONF_PARSER_TERMINATOR
};

/*
 *	We only parse the pool options if we're connected.
 */
static conf_parser_t const pool_config[] = {
	{ FR_CONF_POINTER("status_check", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) status_check_config },

	{ FR_CONF_OFFSET_SUBSECTION("pool", 0, rlm_radius_t, trunk_conf, trunk_config ) },

	CONF_PARSER_TERMINATOR
};

/*
 *	A mapping of configuration file names to internal variables.
 */
static conf_parser_t const module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("mode", CONF_FLAG_REQUIRED, rlm_radius_t, mode), .func = mode_parse, .dflt = "proxy" },

	{ FR_CONF_OFFSET_REF(rlm_radius_t, fd_config, fr_bio_fd_client_config) },

	{ FR_CONF_OFFSET_FLAGS("type", CONF_FLAG_NOT_EMPTY | CONF_FLAG_MULTI | CONF_FLAG_REQUIRED, rlm_radius_t, types),
	  .func = type_parse },

	{ FR_CONF_OFFSET_FLAGS("replicate", CONF_FLAG_DEPRECATED, rlm_radius_t, replicate) },

	{ FR_CONF_OFFSET_FLAGS("synchronous", CONF_FLAG_DEPRECATED, rlm_radius_t, synchronous) },

	{ FR_CONF_OFFSET_FLAGS("originate", CONF_FLAG_DEPRECATED, rlm_radius_t, originate) },

	{ FR_CONF_OFFSET("max_packet_size", rlm_radius_t, max_packet_size), .dflt = "4096" },
	{ FR_CONF_OFFSET("max_send_coalesce", rlm_radius_t, max_send_coalesce), .dflt = "1024" },

	{ FR_CONF_OFFSET("max_attributes", rlm_radius_t, max_attributes), .dflt = STRINGIFY(RADIUS_MAX_ATTRIBUTES) },

	{ FR_CONF_OFFSET("require_message_authenticator", rlm_radius_t, require_message_authenticator),
	  .func = cf_table_parse_int,
	  .uctx = &(cf_table_parse_ctx_t){ .table = fr_radius_require_ma_table, .len = &fr_radius_require_ma_table_len },
	  .dflt = "no" },

	{ FR_CONF_OFFSET("response_window", rlm_radius_t, response_window), .dflt = STRINGIFY(20) },

	{ FR_CONF_OFFSET("zombie_period", rlm_radius_t, zombie_period), .dflt = STRINGIFY(40) },

	{ FR_CONF_OFFSET("revive_interval", rlm_radius_t, revive_interval) },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const type_interval_config[FR_RADIUS_CODE_MAX] = {
	[FR_RADIUS_CODE_ACCESS_REQUEST] = { FR_CONF_POINTER("Access-Request", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) auth_config },

	[FR_RADIUS_CODE_ACCOUNTING_REQUEST] = { FR_CONF_POINTER("Accounting-Request", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) acct_config },
	[FR_RADIUS_CODE_STATUS_SERVER] = { FR_CONF_POINTER("Status-Server", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) status_config },
	[FR_RADIUS_CODE_COA_REQUEST] = { FR_CONF_POINTER("CoA-Request", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) coa_config },
	[FR_RADIUS_CODE_DISCONNECT_REQUEST] = { FR_CONF_POINTER("Disconnect-Request", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) disconnect_config },
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_radius_dict[];
fr_dict_autoload_t rlm_radius_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_proxy_state;

static fr_dict_attr_t const *attr_error_cause;
static fr_dict_attr_t const *attr_event_timestamp;
static fr_dict_attr_t const *attr_extended_attribute_1;
static fr_dict_attr_t const *attr_message_authenticator;
static fr_dict_attr_t const *attr_eap_message;
static fr_dict_attr_t const *attr_nas_identifier;
static fr_dict_attr_t const *attr_original_packet_code;
static fr_dict_attr_t const *attr_response_length;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_radius_dict_attr[];
fr_dict_attr_autoload_t rlm_radius_dict_attr[] = {
	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_proxy_state, .name = "Proxy-State", .type = FR_TYPE_OCTETS, .dict = &dict_radius},

	{ .out = &attr_error_cause, .name = "Error-Cause", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_event_timestamp, .name = "Event-Timestamp", .type = FR_TYPE_DATE, .dict = &dict_radius},
	{ .out = &attr_extended_attribute_1, .name = "Extended-Attribute-1", .type = FR_TYPE_TLV, .dict = &dict_radius},
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_nas_identifier, .name = "NAS-Identifier", .type = FR_TYPE_STRING, .dict = &dict_radius},
	{ .out = &attr_original_packet_code, .name = "Extended-Attribute-1.Original-Packet-Code", .type = FR_TYPE_UINT32, .dict = &dict_radius},
	{ .out = &attr_response_length, .name = "Extended-Attribute-1.Response-Length", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius},

	{ NULL }
};

#include "bio.c"

static fr_table_num_sorted_t mode_names[] = {
	{ L("client"),		RLM_RADIUS_MODE_CLIENT   	},
	{ L("dynamic-proxy"),	RLM_RADIUS_MODE_XLAT_PROXY  	},
	{ L("proxy"),		RLM_RADIUS_MODE_PROXY    	},
	{ L("replicate"),	RLM_RADIUS_MODE_REPLICATE   	},
	{ L("unconnected-replicate"),	RLM_RADIUS_MODE_UNCONNECTED_REPLICATE  	},
};
static size_t mode_names_len = NUM_ELEMENTS(mode_names);


/** Set the mode of operation
 *
 * @param[in] ctx	to allocate data in (instance of rlm_radius).
 * @param[out] out	Where to write the parsed data.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mode_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
		      CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	char const		*name = cf_pair_value(cf_item_to_pair(ci));
	rlm_radius_mode_t	mode;
	rlm_radius_t		*inst = talloc_get_type_abort(parent, rlm_radius_t);
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));

	mode = fr_table_value_by_str(mode_names, name, RLM_RADIUS_MODE_INVALID);

	/*
	 *	Commented out until we upgrade the old configurations.
	 */
	if (mode == RLM_RADIUS_MODE_INVALID) {
		cf_log_err(ci, "Invalid mode name \"%s\"", name);
		return -1;
	}

	*(rlm_radius_mode_t *) out = mode;

	/*
	 *	Normally we want connected sockets, in which case we push additional configuration for
	 *	connected sockets.
	 */
	switch (mode) {
	default:
		inst->fd_config.type = FR_BIO_FD_CONNECTED;

		if (cf_section_rules_push(cs, connected_config) < 0) return -1;
		break;

	case RLM_RADIUS_MODE_XLAT_PROXY:
		inst->fd_config.type = FR_BIO_FD_UNCONNECTED; /* reset later when the home server is allocated */

		if (cf_section_rules_push(cs, pool_config) < 0) return -1;
		break;

	case RLM_RADIUS_MODE_UNCONNECTED_REPLICATE:
		inst->fd_config.type = FR_BIO_FD_UNCONNECTED;
		break;
	}

	return 0;
}


/** Set which types of packets we can parse
 *
 * @param[in] ctx	to allocate data in (instance of rlm_radius).
 * @param[out] out	Where to write the parsed data.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
		      CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));
	fr_dict_enum_value_t const	*type_enum;
	uint32_t		code;

	/*
	 *	Must be the RADIUS module
	 */
	fr_assert(cs && (strcmp(cf_section_name1(cs), "radius") == 0));

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_name(attr_packet_type, type_str, -1);
	if (!type_enum) {
	invalid_code:
		cf_log_err(ci, "Unknown or invalid RADIUS packet type '%s'", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;

	/*
	 *	Status-Server packets cannot be proxied.
	 */
	if (code == FR_RADIUS_CODE_STATUS_SERVER) {
		cf_log_err(ci, "Invalid setting of 'type = Status-Server'.  Status-Server packets cannot be proxied.");
		return -1;
	}

	if (!code ||
	    (code >= FR_RADIUS_CODE_MAX) ||
	    (!type_interval_config[code].name1)) goto invalid_code;

	/*
	 *	If we're doing async proxying, push the timers for the
	 *	various packet types.
	 */
	cf_section_rule_push(cs, &type_interval_config[code]);

	*(uint32_t *) out = code;

	return 0;
}

/** Allow for Status-Server ping checks
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write our parsed data.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int status_check_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				   CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	char const		*type_str = cf_pair_value(cf_item_to_pair(ci));
	CONF_SECTION		*cs = cf_item_to_section(cf_parent(ci));
	fr_dict_enum_value_t const	*type_enum;
	uint32_t		code;

	/*
	 *	Allow the process module to be specified by
	 *	packet type.
	 */
	type_enum = fr_dict_enum_by_name(attr_packet_type, type_str, -1);
	if (!type_enum) {
	invalid_code:
		cf_log_err(ci, "Unknown or invalid RADIUS packet type '%s'", type_str);
		return -1;
	}

	code = type_enum->value->vb_uint32;

	/*
	 *	Cheat, and reuse the "type" array for allowed packet
	 *	types.
	 */
	if (!code ||
	    (code >= FR_RADIUS_CODE_MAX) ||
	    (!type_interval_config[code].name1)) goto invalid_code;

	/*
	 *	Add irt / mrt / mrd / mrc parsing, in the parent
	 *	configuration section.
	 */
	cf_section_rule_push(cf_item_to_section(cf_parent(cs)), &type_interval_config[code]);

	memcpy(out, &code, sizeof(code));

	/*
	 *	Nothing more to do here, so we stop.
	 */
	if (code == FR_RADIUS_CODE_STATUS_SERVER) return 0;

	cf_section_rule_push(cs, status_check_update_config);

	return 0;
}

/** Allow the admin to set packet contents for Status-Server ping checks
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write our parsed data
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION specifying the things to update
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int status_check_update_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				     CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	int			rcode;
	CONF_SECTION		*cs;
	char const		*name2;
	map_list_t		*head = (map_list_t *)out;

	fr_assert(cf_item_is_section(ci));
	map_list_init(head);

	cs = cf_item_to_section(ci);
	name2 = cf_section_name2(cs);
	if (!name2 || (strcmp(name2, "request") != 0)) {
		cf_log_err(cs, "You must specify 'request' as the destination list");
		return -1;
	}

	/*
	 *	Compile the "update" section.
	 */
	{
		tmpl_rules_t	parse_rules = {
			.attr = {
				.dict_def = dict_radius,
			}
		};

		rcode = map_afrom_cs(ctx, head, cs, &parse_rules, &parse_rules, unlang_fixup_update, NULL, 128);
		if (rcode < 0) return -1; /* message already printed */
		if (map_list_empty(head)) {
			cf_log_err(cs, "'update' sections cannot be empty");
			return -1;
		}
	}

	/*
	 *	Rely on "bootstrap" to do sanity checks between 'type
	 *	= Access-Request', and 'update' containing passwords.
	 */
	return 0;
}


/** Do any RADIUS-layer fixups for proxying.
 *
 */
static int radius_fixups(rlm_radius_t const *inst, request_t *request)
{
	fr_pair_t *vp;

	if (request->packet->code == FR_RADIUS_CODE_STATUS_SERVER) {
		RWDEBUG("Status-Server is reserved for internal use, and cannot be sent manually.");
		return 0;
	}

	if (!inst->allowed[request->packet->code]) {
		REDEBUG("Packet code %s is disallowed by the configuration",
		       fr_radius_packet_name[request->packet->code]);
		return -1;
	}

	/*
	 *	Check for proxy loops.
	 *
	 *	There should _never_ be two instances of the same Proxy-State in the packet.
	 */
	if ((inst->mode == RLM_RADIUS_MODE_PROXY) && RDEBUG_ENABLED) {
		unsigned int count = 0;
		fr_dcursor_t cursor;

		for (vp = fr_pair_dcursor_by_da_init(&cursor, &request->request_pairs, attr_proxy_state);
		     vp;
		     vp = fr_dcursor_next(&cursor)) {
			if (vp->vp_length != sizeof(inst->common_ctx.proxy_state)) continue;

			if (memcmp(vp->vp_octets, &inst->common_ctx.proxy_state,
				   sizeof(inst->common_ctx.proxy_state)) == 0) {

				/*
				 *	Cancel proxying when there are two instances of the same Proxy-State
				 *	in the packet.  This limitation could be configurable, but it likely
				 *	doesn't make sense to make it configurable.
				 */
				if (count == 1) {
					RWARN("Canceling proxy due to loop of multiple %pV", vp);
					return -1;
				}

				RWARN("Proxied packet contains our own %pV", vp);
				RWARN("Check if there is a proxy loop.  Perhaps the server has been configured to proxy to itself.");
				count++;
			}
		}
	}

	if (request->packet->code != FR_RADIUS_CODE_ACCESS_REQUEST) return 0;

	if (fr_pair_find_by_da(&request->request_pairs, NULL, attr_chap_password) &&
	    !fr_pair_find_by_da(&request->request_pairs, NULL, attr_chap_challenge)) {
	    	MEM(pair_append_request(&vp, attr_chap_challenge) >= 0);
		fr_pair_value_memdup(vp, request->packet->vector, sizeof(request->packet->vector), true);
	}

	return 0;
}


/** Send packets outbound.
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_radius_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_radius_t);
	bio_thread_t		*thread = talloc_get_type_abort(mctx->thread, bio_thread_t);
	fr_client_t		*client;
	int			rcode;
	bio_request_t		*u = NULL;
	fr_retry_config_t const	*retry_config = NULL;

	if (!request->packet->code) {
		REDEBUG("You MUST specify a packet code");
		RETURN_MODULE_FAIL;
	}

	if ((request->packet->code >= FR_RADIUS_CODE_MAX) ||
	    !fr_time_delta_ispos(inst->retry[request->packet->code].irt)) { /* can't be zero */
		REDEBUG("Invalid packet code %u", request->packet->code);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Unconnected sockets use %radius.replicate(ip, port, secret),
	 *	or %radius.sendto(ip, port, secret)
	 */
	if ((inst->mode == RLM_RADIUS_MODE_UNCONNECTED_REPLICATE) ||
	    (inst->mode == RLM_RADIUS_MODE_XLAT_PROXY)) {
		REDEBUG("When using 'mode = unconnected-*', this module cannot be used in-place.  Instead, it must be called via a function call");
		RETURN_MODULE_FAIL;
	}

	client = client_from_request(request);
	if (client && client->dynamic && !client->active) {
		REDEBUG("Cannot proxy packets which define dynamic clients");
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Push the request and it's data to the IO submodule.
	 *
	 *	This may return YIELD, for "please yield", or it may
	 *	return another code which indicates what happened to
	 *	the request...
	 */
	rcode = mod_enqueue(&u, &retry_config, inst, thread->ctx.trunk, request);
	if (rcode == 0) RETURN_MODULE_NOOP;
	if (rcode < 0) RETURN_MODULE_FAIL;

	return unlang_module_yield_to_retry(request, mod_resume, mod_retry, mod_signal, 0, u, retry_config);
}


static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	size_t i, num_types;
	rlm_radius_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_radius_t);
	CONF_SECTION *conf = mctx->mi->conf;

	inst->name = mctx->mi->name;
	inst->received_message_authenticator = talloc_zero(NULL, bool);		/* Allocated outside of inst to default protection */

	/*
	 *	Allow explicit setting of mode.
	 */
	if (inst->mode != RLM_RADIUS_MODE_INVALID) goto check_others;

	/*
	 *	If not set, try to insinuate it from context.
	 */
	if (inst->replicate) {
		if (inst->originate) {
			cf_log_err(conf, "Cannot set 'replicate=true' and 'originate=true' at the same time.");
			return -1;
		}

		if (inst->synchronous) {
			cf_log_warn(conf, "Ignoring 'synchronous=true' due to 'replicate=true'");
		}

		inst->mode = RLM_RADIUS_MODE_REPLICATE;
		goto check_others;
	}

	/*
	 *	Argubly we should be allowed to do synchronous proxying _and_ originating client packets.
	 *
	 *	However, the previous code didn't really do that consistently.
	 */
	if (inst->synchronous && inst->originate) {
		cf_log_err(conf, "Cannot set 'synchronous=true' and 'originate=true'");
		return -1;
	}

	if (inst->synchronous) {
		inst->mode = RLM_RADIUS_MODE_PROXY;
	} else {
		inst->mode = RLM_RADIUS_MODE_CLIENT;
	}

check_others:
	/*
	 *	Replication is write-only, and append by default.
	 */
	if (inst->mode == RLM_RADIUS_MODE_REPLICATE) {
		if (inst->fd_config.filename && (inst->fd_config.flags != O_WRONLY)) {
			cf_log_info(conf, "Setting 'flags = write-only' for writing to a file");
		}
		inst->fd_config.flags = O_WRONLY | O_APPEND;

	} else if (inst->fd_config.filename) {
		cf_log_err(conf, "When using an output 'filename', you MUST set 'mode = replicate'");
		return -1;

	} else {
		/*
		 *	All other IO is read+write.
		 */
		inst->fd_config.flags = O_RDWR;
	}

	if (fr_bio_fd_check_config(&inst->fd_config) < 0) {
		cf_log_perr(conf, "Invalid configuration");
		return -1;
	}

	/*
	 *	Clamp max_packet_size first before checking recv_buff and send_buff
	 */
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 64);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	if (inst->mode != RLM_RADIUS_MODE_UNCONNECTED_REPLICATE) {
		/*
		 *	These limits are specific to RADIUS, and cannot be over-ridden
		 */
		FR_INTEGER_BOUND_CHECK("trunk.per_connection_max", inst->trunk_conf.max_req_per_conn, >=, 2);
		FR_INTEGER_BOUND_CHECK("trunk.per_connection_max", inst->trunk_conf.max_req_per_conn, <=, 255);
		FR_INTEGER_BOUND_CHECK("trunk.per_connection_target", inst->trunk_conf.target_req_per_conn, <=, inst->trunk_conf.max_req_per_conn / 2);
	}

	if ((inst->mode == RLM_RADIUS_MODE_UNCONNECTED_REPLICATE) ||
	    (inst->mode == RLM_RADIUS_MODE_XLAT_PROXY)) {
		if (inst->fd_config.src_port != 0) {
			cf_log_err(conf, "Cannot set 'src_port' when using this 'mode'");
			return -1;
		}
	}

	FR_TIME_DELTA_BOUND_CHECK("response_window", inst->zombie_period, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("response_window", inst->zombie_period, <=, fr_time_delta_from_sec(120));

	FR_TIME_DELTA_BOUND_CHECK("zombie_period", inst->zombie_period, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("zombie_period", inst->zombie_period, <=, fr_time_delta_from_sec(120));

	if (!inst->status_check) {
		FR_TIME_DELTA_BOUND_CHECK("revive_interval", inst->revive_interval, >=, fr_time_delta_from_sec(10));
		FR_TIME_DELTA_BOUND_CHECK("revive_interval", inst->revive_interval, <=, fr_time_delta_from_sec(3600));
	}

	num_types = talloc_array_length(inst->types);
	fr_assert(num_types > 0);

	inst->timeout_retry = (fr_retry_config_t) {
		.mrc = 1,
		.mrd = inst->response_window,
	};

	inst->common_ctx = (fr_radius_ctx_t) {
		.secret = inst->secret,
		.secret_length = inst->secret ? talloc_array_length(inst->secret) - 1 : 0,
		.proxy_state = ((uint64_t) fr_rand()) << 32 | fr_rand(),
	};

	/*
	 *	Allow for O(1) lookup later...
	 */
	for (i = 0; i < num_types; i++) {
		uint32_t code;

		code = inst->types[i];
		fr_assert(code > 0);
		fr_assert(code < FR_RADIUS_CODE_MAX);

		inst->allowed[code] = true;
	}

	fr_assert(inst->status_check < FR_RADIUS_CODE_MAX);

	/*
	 *	If we're replicating, we don't care if the other end
	 *	is alive.
	 */
	if (inst->status_check) {
		if (inst->mode == RLM_RADIUS_MODE_REPLICATE) {
			cf_log_warn(conf, "Ignoring 'status_check = %s' due to 'mode = replicate'",
				    fr_radius_packet_name[inst->status_check]);
			inst->status_check = false;

		} else if ((inst->mode == RLM_RADIUS_MODE_UNCONNECTED_REPLICATE) ||
			   (inst->mode == RLM_RADIUS_MODE_XLAT_PROXY)) {
				   cf_log_warn(conf, "Ignoring 'status_check = %s' due to 'mode' setting",
				    fr_radius_packet_name[inst->status_check]);
			inst->status_check = false;
		}
	}

	/*
	 *	If we have status checks, then do some sanity checks.
	 *	Status-Server is always allowed.  Otherwise, the
	 *	status checks have to match one of the allowed
	 *	packets.
	 */
	if (inst->status_check) {
		if (inst->status_check == FR_RADIUS_CODE_STATUS_SERVER) {
			inst->allowed[inst->status_check] = true;

		} else if (!inst->allowed[inst->status_check]) {
			cf_log_err(conf, "Using 'status_check = %s' requires also 'type = %s'",
				   fr_radius_packet_name[inst->status_check], fr_radius_packet_name[inst->status_check]);
			return -1;
		}

		/*
		 *	@todo - check the contents of the "update"
		 *	section, to be sure that (e.g.) Access-Request
		 *	contains User-Name, etc.
		 */

		if (inst->fd_config.filename) {
			cf_log_info(conf, "Disabling status checks for output file %s", inst->fd_config.filename);
			inst->status_check = 0;
		}
	}

	/*
	 *	Files and unix sockets can just have us call write().
	 */
	if (inst->fd_config.filename || inst->fd_config.path) {
		inst->max_send_coalesce = 1;
	}

	inst->trunk_conf.req_pool_headers = 4;	/* One for the request, one for the buffer, one for the tracking binding, one for Proxy-State VP */
	inst->trunk_conf.req_pool_size = 1024 + sizeof(fr_pair_t) + 20;

	/*
	 *	Only check the async timers when we're acting as a client.
	 */
	if (inst->mode != RLM_RADIUS_MODE_CLIENT) {
		return 0;
	}

	/*
	 *	Set limits on retransmission timers
	 */
	if (inst->allowed[FR_RADIUS_CODE_ACCESS_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Access-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("Access-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Access-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Access-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCESS_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	Note that RFC 5080 allows for Accounting-Request to
	 *	have mrt=mrc=mrd = 0, which means "retransmit
	 *	forever".  We allow that, with the restriction that
	 *	the server core will automatically free the request at
	 *	max_request_time.
	 */
	if (inst->allowed[FR_RADIUS_CODE_ACCOUNTING_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].irt, >=, fr_time_delta_from_sec(1));
#if 0
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Accounting-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrc, >=, 0);
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrd, >=, fr_time_delta_from_sec(0));
#endif

		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Accounting-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Accounting-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_ACCOUNTING_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	Status-Server
	 */
	if (inst->allowed[FR_RADIUS_CODE_STATUS_SERVER]) {
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.initial_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Status-Server.max_rtx_count", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_duration", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("Status-Server.initial_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_time", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Status-Server.max_rtx_count", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Status-Server.max_rtx_duration", inst->retry[FR_RADIUS_CODE_STATUS_SERVER].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	CoA
	 */
	if (inst->allowed[FR_RADIUS_CODE_COA_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("CoA-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrt, <=, fr_time_delta_from_sec(60));
		FR_INTEGER_BOUND_CHECK("CoA-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("CoA-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_COA_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

	/*
	 *	Disconnect
	 */
	if (inst->allowed[FR_RADIUS_CODE_DISCONNECT_REQUEST]) {
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].irt, >=, fr_time_delta_from_sec(1));
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrt, >=, fr_time_delta_from_sec(5));
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrc, >=, 1);
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrd, >=, fr_time_delta_from_sec(5));

		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.initial_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].irt, <=, fr_time_delta_from_sec(3));
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_time", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrt, <=, fr_time_delta_from_sec(30));
		FR_INTEGER_BOUND_CHECK("Disconnect-Request.max_rtx_count", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrc, <=, 10);
		FR_TIME_DELTA_BOUND_CHECK("Disconnect-Request.max_rtx_duration", inst->retry[FR_RADIUS_CODE_DISCONNECT_REQUEST].mrd, <=, fr_time_delta_from_sec(30));
	}

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t 		*xlat;
	rlm_radius_t const *inst = talloc_get_type_abort(mctx->mi->data, rlm_radius_t);

	switch (inst->mode) {
	case RLM_RADIUS_MODE_UNCONNECTED_REPLICATE:
		xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "sendto.ipaddr", xlat_radius_replicate, FR_TYPE_VOID);
		xlat_func_args_set(xlat, xlat_radius_send_args);
		break;

	case RLM_RADIUS_MODE_XLAT_PROXY:
		xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "sendto.ipaddr", xlat_radius_client, FR_TYPE_UINT32);
		xlat_func_args_set(xlat, xlat_radius_send_args);
		break;

	default:
		break;
	}

	return 0;
}


static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_radius_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_radius_t);

	talloc_free(inst->received_message_authenticator);
	return 0;
}

static int mod_load(void)
{
	if (fr_radius_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	fr_radius_global_free();
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_radius;
module_rlm_t rlm_radius = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "radius",
		.inst_size	= sizeof(rlm_radius_t),
		.config		= module_config,

		.onload		= mod_load,
		.unload		= mod_unload,

		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,

		.thread_inst_size	= sizeof(bio_thread_t),
		.thread_inst_type	= "bio_thread_t",
		.thread_instantiate 	= mod_thread_instantiate,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_process },
			MODULE_BINDING_TERMINATOR
		},
	}
};
