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
 * @file proto_radius.c
 * @brief RADIUS master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/server/module_rlm.h>
#include <stdbool.h>
#include "proto_radius.h"

extern fr_app_t proto_radius;

static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

static conf_parser_t const limit_config[] = {
	{ FR_CONF_OFFSET("cleanup_delay", proto_radius_t, io.cleanup_delay), .dflt = "5.0" } ,
	{ FR_CONF_OFFSET("idle_timeout", proto_radius_t, io.idle_timeout), .dflt = "30.0" } ,
	{ FR_CONF_OFFSET("dynamic_timeout", proto_radius_t, io.dynamic_timeout), .dflt = "600.0" } ,
	{ FR_CONF_OFFSET("nak_lifetime", proto_radius_t, io.nak_lifetime), .dflt = "30.0" } ,

	{ FR_CONF_OFFSET("max_connections", proto_radius_t, io.max_connections), .dflt = "1024" } ,
	{ FR_CONF_OFFSET("max_clients", proto_radius_t, io.max_clients), .dflt = "256" } ,
	{ FR_CONF_OFFSET("max_pending_packets", proto_radius_t, io.max_pending_packets), .dflt = "256" } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", proto_radius_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", proto_radius_t, num_messages) } ,

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t priority_config[] = {
	{ FR_CONF_OFFSET("Access-Request", proto_radius_t, priorities[FR_RADIUS_CODE_ACCESS_REQUEST]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "high" },
	{ FR_CONF_OFFSET("Accounting-Request", proto_radius_t, priorities[FR_RADIUS_CODE_ACCOUNTING_REQUEST]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "low" },
	{ FR_CONF_OFFSET("CoA-Request", proto_radius_t, priorities[FR_RADIUS_CODE_COA_REQUEST]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Disconnect-Request", proto_radius_t, priorities[FR_RADIUS_CODE_DISCONNECT_REQUEST]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "low" },
	{ FR_CONF_OFFSET("Status-Server", proto_radius_t, priorities[FR_RADIUS_CODE_STATUS_SERVER]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "now" },

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const log_config[] = {
	{ FR_CONF_OFFSET("ignored_clients", proto_radius_t, io.log_ignored_clients), .dflt = "yes" } ,

	CONF_PARSER_TERMINATOR
};

/** How to parse a RADIUS listen section
 *
 */
static conf_parser_t const proto_radius_config[] = {
	{ FR_CONF_OFFSET_FLAGS("type", CONF_FLAG_NOT_EMPTY, proto_radius_t, allowed_types), .func = type_parse },
	{ FR_CONF_OFFSET_TYPE_FLAGS("transport", FR_TYPE_VOID, 0, proto_radius_t, io.submodule),
	  .func = transport_parse },

	/*
	 *	Check whether or not the *trailing* bits of a
	 *	Tunnel-Password are zero, as they should be.
	 */
	{ FR_CONF_OFFSET("tunnel_password_zeros", proto_radius_t, tunnel_password_zeros) } ,

	{ FR_CONF_POINTER("limit", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	{ FR_CONF_POINTER("priority", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) priority_config },

	{ FR_CONF_POINTER("log", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) log_config },

	{ FR_CONF_OFFSET("require_message_authenticator", proto_radius_t, require_message_authenticator),
	  .func = cf_table_parse_int,
	  .uctx = &(cf_table_parse_ctx_t){ .table = fr_radius_require_ma_table, .len = &fr_radius_require_ma_table_len },
	  .dflt = "no" },

	{ FR_CONF_OFFSET("limit_proxy_state", proto_radius_t, limit_proxy_state),
	  .func = cf_table_parse_int,
	  .uctx = &(cf_table_parse_ctx_t){ .table = fr_radius_limit_proxy_state_table, .len = &fr_radius_limit_proxy_state_table_len },
	  .dflt = "auto" },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t proto_radius_dict[];
fr_dict_autoload_t proto_radius_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_proxy_state;
static fr_dict_attr_t const *attr_message_authenticator;
static fr_dict_attr_t const *attr_eap_message;
static fr_dict_attr_t const *attr_error_cause;
static fr_dict_attr_t const *attr_packet_id;
static fr_dict_attr_t const *attr_packet_authenticator;

extern fr_dict_attr_autoload_t proto_radius_dict_attr[];
fr_dict_attr_autoload_t proto_radius_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius},
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius},
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_proxy_state, .name = "Proxy-State", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_eap_message, .name = "EAP-Message", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_error_cause, .name = "Error-Cause", .type = FR_TYPE_UINT32, .dict = &dict_radius},
	{ .out = &attr_packet_id, .name = "Packet.Id", .type = FR_TYPE_UINT8, .dict = &dict_radius},
	{ .out = &attr_packet_authenticator, .name = "Packet.Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	DICT_AUTOLOAD_TERMINATOR
};

/** Translates the packet-type into a submodule name
 *
 * If we found a Packet-Type = Access-Request CONF_PAIR for example, here's we'd load
 * the proto_radius_auth module.
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to write a module_instance_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	proto_radius_t			*inst = talloc_get_type_abort(parent, proto_radius_t);
	fr_dict_enum_value_t const	*dv;
	CONF_PAIR			*cp;
	char const			*value;

	cp = cf_item_to_pair(ci);
	value = cf_pair_value(cp);

	dv = fr_dict_enum_by_name(attr_packet_type, value, -1);
	if (!dv || (dv->value->vb_uint32 >= FR_RADIUS_CODE_MAX)) {
		cf_log_err(ci, "Unknown RADIUS packet type '%s'", value);
		return -1;
	}

	inst->allowed[dv->value->vb_uint32] = true;
	*((char const **) out) = value;

	return 0;
}

static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	proto_radius_t		*inst = talloc_get_type_abort(parent, proto_radius_t);
	module_instance_t	*mi;

	if (unlikely(virtual_server_listen_transport_parse(ctx, out, parent, ci, rule) < 0)) {
		return -1;
	}

	mi = talloc_get_type_abort(*(void **)out, module_instance_t);
	inst->io.app_io = (fr_app_io_t const *)mi->exported;
	inst->io.app_io_instance = mi->data;
	inst->io.app_io_conf = mi->conf;

	return 0;
}

DIAG_OFF(format-nonliteral)
/** Log a message in a canonical format.
 *
 *  'fmt' is from our source code, so we don't care about format literals.
 */
void proto_radius_log(fr_listen_t *li, char const *name, fr_radius_decode_fail_t reason,
		      fr_socket_t const *sock, char const *fmt, ...)
{
	va_list ap;
	char *msg = NULL;

	if (!DEBUG_ENABLED2) return;

	va_start(ap, fmt);
	if (*fmt) msg = talloc_asprintf(NULL, fmt, ap);
	va_end(ap);

	if (sock) {
		DEBUG2("proto_%s - discarding packet on socket %s from client %pV port %u - %s (%s)",
		       li->app_io->common.name, name,
		       fr_box_ipaddr(sock->inet.src_ipaddr), sock->inet.src_port,
		       msg,
		       fr_radius_decode_fail_reason[reason]);
	} else {
		DEBUG2("proto_%s - discarding packet on socket %s - %s (%s)",
		       li->app_io->common.name, name, msg, fr_radius_decode_fail_reason[reason]);
	}

	talloc_free(msg);
}
DIAG_ON(format-nonliteral)

/** Decode the packet
 *
 */
static int mod_decode(void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	proto_radius_t const		*inst = talloc_get_type_abort_const(instance, proto_radius_t);
	fr_io_track_t const		*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  		*address = track->address;
	fr_client_t			*client = UNCONST(fr_client_t *, address->radclient);
	fr_radius_ctx_t			common_ctx;
	fr_radius_decode_ctx_t		decode_ctx;

	fr_radius_require_ma_t		require_message_authenticator = client->require_message_authenticator_is_set ?
									client->require_message_authenticator:
									inst->require_message_authenticator;
	fr_radius_limit_proxy_state_t	limit_proxy_state = client->limit_proxy_state_is_set ?
							    client->limit_proxy_state:
							    inst->limit_proxy_state;
	fr_pair_t			*packet_vp;

	fr_assert(data[0] < FR_RADIUS_CODE_MAX);

	common_ctx = (fr_radius_ctx_t) {
		.secret = client->secret,
		.secret_length = talloc_array_length(client->secret) - 1,
	};

	request->packet->code = data[0];

	decode_ctx = (fr_radius_decode_ctx_t) {
		.common = &common_ctx,
		.tmp_ctx = talloc(request, uint8_t),
		/* decode figures out request_authenticator */
		.end = data + data_len,
		.verify = client->active,
	};

	if (request->packet->code == FR_RADIUS_CODE_ACCESS_REQUEST) {
		/*
		 *	bit1 is set if we've seen a packet, and the auto bit in require_message_authenticator is set/
		 *	bit2 is set if we always require a message_authenticator.
		 *	If either bit is high we require a message authenticator in the packet.
		 */
		decode_ctx.require_message_authenticator = (
				(client->received_message_authenticator & require_message_authenticator) |
				(require_message_authenticator & FR_RADIUS_REQUIRE_MA_YES)
			) > 0;
		decode_ctx.limit_proxy_state = (
				(client->first_packet_no_proxy_state & limit_proxy_state) |
				(limit_proxy_state & FR_RADIUS_LIMIT_PROXY_STATE_YES)
			) > 0;
	}

	/*
	 *	The verify() routine over-writes the request packet vector.
	 *
	 *	@todo - That needs to be changed.
	 */
	request->packet->id = data[1];
	request->reply->id = data[1];
	memcpy(request->packet->vector, data + 4, sizeof(request->packet->vector));

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	/*
	 *	!client->active means a fake packet defining a dynamic client - so there will
	 *	be no secret defined yet - so can't verify.
	 */
	if (fr_radius_decode(request->request_ctx, &request->request_pairs,
			     data, data_len, &decode_ctx) < 0) {
		talloc_free(decode_ctx.tmp_ctx);
		RPEDEBUG("Failed decoding packet");
		return -1;
	}
	talloc_free(decode_ctx.tmp_ctx);

	/*
	 *	Set the rest of the fields.
	 */
	request->client = client;

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	if (request->packet->code == FR_RADIUS_CODE_ACCESS_REQUEST) {
		/*
		 *	If require_message_authenticator is "auto" then
		 *	we start requiring messages authenticator after
		 *	the first Access-Request packet containing a
		 *	verified one.  This isn't vulnerable to the same
		 *	attack as limit_proxy_state, as the attacker would
		 *	need knowledge of the secret.
		 *
		 *	Unfortunately there are too many cases where
		 *	auto mode could break things (dealing with
		 *	multiple clients behind a NAT for example).
		 */
		if (!client->received_message_authenticator &&
		    fr_pair_find_by_da(&request->request_pairs, NULL, attr_message_authenticator)) {
			/*
			 *	Don't print debugging messages if all is OK.
			 */
			if (require_message_authenticator == FR_RADIUS_REQUIRE_MA_YES) {
				client->received_message_authenticator = true;

			} else if (require_message_authenticator == FR_RADIUS_REQUIRE_MA_AUTO) {
				if (!fr_pair_find_by_da(&request->request_pairs, NULL, attr_eap_message)) {
					client->received_message_authenticator = true;

					RINFO("Packet from client %pV (%pV) contained a valid Message-Authenticator.  Setting \"require_message_authenticator = yes\"",
					      fr_box_ipaddr(client->ipaddr),
					      fr_box_strvalue_buffer(client->shortname));
				} else {
					RINFO("Packet from client %pV (%pV) contained a valid Message-Authenticator but also EAP-Message",
					      fr_box_ipaddr(client->ipaddr),
					      fr_box_strvalue_buffer(client->shortname));
					RINFO("Not changing the value of 'require_message_authenticator = auto'");
				}
			}
		}

		/*
		 *	It's important we only evaluate this on the
		 *	first packet.  Otherwise an attacker could send
		 *	Access-Requests with no Proxy-State whilst
		 *	spoofing a legitimate Proxy-Server, and causing an
		 *	outage.
		 *
		 *	The likelihood of an attacker sending a packet
		 *	to coincide with the reboot of a RADIUS
		 *	server is low. That said, 'auto' should likely
		 * 	not be enabled for internet facing servers.
		 */
		if (!client->received_message_authenticator &&
		    (limit_proxy_state == FR_RADIUS_LIMIT_PROXY_STATE_AUTO) &&
		    client->active && !client->seen_first_packet) {
			client->seen_first_packet = true;
			client->first_packet_no_proxy_state = fr_pair_find_by_da(&request->request_pairs, NULL, attr_proxy_state) == NULL;

			/* None of these should be errors */
			if (!fr_pair_find_by_da(&request->request_pairs, NULL, attr_message_authenticator)) {
				RWARN("Packet from %pV (%pV) did not contain Message-Authenticator:",
				      fr_box_ipaddr(client->ipaddr),
				      fr_box_strvalue_buffer(client->shortname));
				RWARN("- Upgrade the client, as your network is vulnerable to the BlastRADIUS attack.");
				RWARN("- Then set 'require_message_authenticator = yes' in the client definition");
			} else {
				RWARN("Packet from %pV (%pV) contains Message-Authenticator:",
				      fr_box_ipaddr(client->ipaddr),
				      fr_box_strvalue_buffer(client->shortname));
				RWARN("- Then set 'require_message_authenticator = yes' in the client definition");
			}

			RINFO("First packet from %pV (%pV) %s Proxy-State.  Setting \"limit_proxy_state = %s\"",
			      fr_box_ipaddr(client->ipaddr),
			      fr_box_strvalue_buffer(client->shortname),
			      client->first_packet_no_proxy_state ? "did not contain" : "contained",
			      client->first_packet_no_proxy_state ? "yes" : "no");

			if (!client->first_packet_no_proxy_state) {
				RERROR("Packet from %pV (%pV) contains Proxy-State, but no Message-Authenticator:",
				       fr_box_ipaddr(client->ipaddr),
				       fr_box_strvalue_buffer(client->shortname));
				RERROR("- Upgrade the client, as your network is vulnerable to the BlastRADIUS attack.");
				RERROR("- Then set 'require_message_authenticator = yes' in the client definition");
			}
		}
	}

	REQUEST_VERIFY(request);

	/*
	 *	If we're defining a dynamic client, this packet is
	 *	fake.  We don't have a secret, so we mash all of the
	 *	encrypted attributes to sane (i.e. non-hurtful)
	 *	values.
	 */
	if (!client->active) {
		fr_pair_t *vp;

		fr_assert(client->dynamic);

		request_set_dynamic_client(request);

		for (vp = fr_pair_list_head(&request->request_pairs);
		     vp != NULL;
		     vp = fr_pair_list_next(&request->request_pairs, vp)) {
			if (fr_radius_flag_encrypted(vp->da)) {
				switch (vp->vp_type) {
				default:
					break;

				case FR_TYPE_UINT32:
					vp->vp_uint32 = 0;
					break;

				case FR_TYPE_IPV4_ADDR:
					vp->vp_ipv4addr = INADDR_ANY;
					break;

				case FR_TYPE_OCTETS:
					fr_pair_value_memdup(vp, (uint8_t const *) "", 1, true);
					break;

				case FR_TYPE_STRING:
					fr_pair_value_strdup(vp, "", true);
					break;
				}
			}
		}
	}

	/*
	 *	Set the sequence to be at least one.  This will
	 *	prioritize replies to Access-Challenges over other
	 *	packets. The sequence will be updated (if necessary)
	 *	by the RADIUS state machine.  If the request yields,
	 *	it will get re-inserted with an updated sequence
	 *	number.
	 */
	if ((request->packet->code == FR_RADIUS_CODE_ACCESS_REQUEST) &&
	    fr_pair_find_by_da(&request->request_pairs, NULL, attr_state)) {
		request->sequence = 1;
	}

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		RPEDEBUG("Failed decoding 'Net.*' packet");
		return -1;
	}

	/*
	 *	Populate Packet structure with Id and Authenticator
	 */
	MEM(packet_vp = fr_pair_afrom_da_nested(request->request_ctx, &request->request_pairs, attr_packet_id));
	packet_vp->vp_uint8 = request->packet->id;
	MEM(packet_vp = fr_pair_afrom_da_nested(request->request_ctx, &request->request_pairs, attr_packet_authenticator));
	if (fr_value_box_memdup(packet_vp, &packet_vp->data, NULL, request->packet->data + 4,
				RADIUS_AUTH_VECTOR_LENGTH, true) < 0) {
		RPEDEBUG("Failed adding Authenticator pair");
		return -1;
	}

	return 0;
}

static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
	fr_io_track_t		*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;
	uint32_t		error_cause;
	ssize_t			data_len;
	fr_client_t const	*client;
	fr_radius_ctx_t		common_ctx = {};
	fr_radius_encode_ctx_t  encode_ctx;

	client = address->radclient;
	fr_assert(client);

	/*
	 *	No reply was set, and the client supports Protocol-Error.  Go create one.
	 */
	if (unlikely((buffer_len > 1) && (request->reply->code == 0) && client->protocol_error)) {
		switch (request->packet->code) {
		case FR_RADIUS_CODE_ACCESS_REQUEST:
			RDEBUG2("There was no response configured - sending Access-Reject");
			request->reply->code = FR_RADIUS_CODE_ACCESS_REJECT;
			break;

		case FR_RADIUS_CODE_COA_REQUEST:
			RDEBUG2("There was no response configured - sending CoA-NAK");
			request->reply->code = FR_RADIUS_CODE_COA_NAK;
			goto not_routable;

		case FR_RADIUS_CODE_DISCONNECT_REQUEST:
			RDEBUG2("There was no response configured - sending Disconnect-NAK");
			request->reply->code = FR_RADIUS_CODE_DISCONNECT_NAK;
			goto not_routable;

		case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
			/*
			 *	Send Protocol-Error reply.
			 *
			 *	@todo - Session-Context-Not-Found is likely the wrong error.
			 */
			RDEBUG2("There was no response configured - sending Protocol-Error");

			request->reply->code = FR_RADIUS_CODE_PROTOCOL_ERROR;
			error_cause = FR_ERROR_CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
			goto force_reply;

		default:
			RDEBUG2("There was no response configured - not sending reply");
			break;
		}
	}

	/*
	 *	Process layer NAK, or "Do not respond".
	 */
	if ((buffer_len == 1) ||
	    (request->reply->code == FR_RADIUS_CODE_DO_NOT_RESPOND) ||
	    (request->reply->code == 0) || (request->reply->code >= FR_RADIUS_CODE_MAX)) {
		track->do_not_respond = true;
		return 1;
	}

	/*
	 *	Not all clients support Protocol-Error.  The admin might have forced Protocol-Error, or we
	 *	might have received a Protocol-Error from a home server.
	 */
	if ((request->reply->code == FR_RADIUS_CODE_PROTOCOL_ERROR) && !client->protocol_error) {
		fr_pair_t *vp;

		switch (request->packet->code) {
		case FR_RADIUS_CODE_ACCESS_REQUEST:
			RWDEBUG("Client %s does not support Protocol-Error - rewriting to Access-Reject",
				client->shortname);
			request->reply->code = FR_RADIUS_CODE_ACCESS_REJECT;
			break;

		case FR_RADIUS_CODE_COA_REQUEST:
			RWDEBUG2("Client %s does not support Protocol-Error - rewriting to CoA-NAK",
				 request->client->shortname);
			request->reply->code = FR_RADIUS_CODE_COA_NAK;
			goto not_routable;

		case FR_RADIUS_CODE_DISCONNECT_REQUEST:
			RWDEBUG2("Client %s does not support Protocol-Error - rewriting to Disconnect-NAK",
				 request->client->shortname);
			request->reply->code = FR_RADIUS_CODE_DISCONNECT_NAK;

		not_routable:
			error_cause = FR_ERROR_CAUSE_VALUE_PROXY_REQUEST_NOT_ROUTABLE;

		force_reply:
			fr_pair_list_free(&request->reply_pairs);

			MEM(vp = fr_pair_afrom_da(request->reply_ctx, attr_error_cause));
			fr_pair_append(&request->reply_pairs, vp);
			vp->vp_uint32 = error_cause;
			break;

		case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
		default:
			RWDEBUG2("Client %s does not support Protocol-Error - not replying to the client",
				 request->client->shortname);
			track->do_not_respond = true;
			return 1;
		}
	}

	/*
	 *	Dynamic client stuff
	 */
	if (client->dynamic && !client->active) {
		fr_client_t *new_client;

		fr_assert(buffer_len >= sizeof(client));

		/*
		 *	We don't accept the new client, so don't do
		 *	anything.
		 */
		if (request->reply->code != FR_RADIUS_CODE_ACCESS_ACCEPT) {
			*buffer = true;
			return 1;
		}

		/*
		 *	Allocate the client.  If that fails, send back a NAK.
		 *
		 *	@todo - deal with NUMA zones?  Or just deal with this
		 *	client being in different memory.
		 *
		 *	Maybe we should create a CONF_SECTION from the client,
		 *	and pass *that* back to mod_write(), which can then
		 *	parse it to create the actual client....
		 */
		new_client = client_afrom_request(NULL, request);
		if (!new_client) {
			PERROR("Failed creating new client");
			*buffer = true;
			return 1;
		}

		memcpy(buffer, &new_client, sizeof(new_client));
		return sizeof(new_client);
	}

	/*
	 *	Overwrite the src ip address on the outbound packet
	 *	with the one specified by the client.  This is useful
	 *	to work around broken DSR implementations and other
	 *	routing issues.
	 */
	if (client->src_ipaddr.af != AF_UNSPEC) {
		request->reply->socket.inet.src_ipaddr = client->src_ipaddr;
	}

	common_ctx = (fr_radius_ctx_t) {
		.secret = client->secret,
		.secret_length = talloc_array_length(client->secret) - 1,
	};
	encode_ctx = (fr_radius_encode_ctx_t) {
		.common = &common_ctx,
		.request_authenticator = request->packet->data + 4,
		.rand_ctx = (fr_fast_rand_t) {
			.a = fr_rand(),
			.b = fr_rand(),
		},
		.request_code = request->packet->data[0],
		.code = request->reply->code,
		.id = request->reply->id,
#ifdef NAS_VIOLATES_RFC
		.allow_vulnerable_clients = client->allow_vulnerable_clients,
#endif
	};

	data_len = fr_radius_encode(&FR_DBUFF_TMP(buffer, buffer_len), &request->reply_pairs, &encode_ctx);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding RADIUS reply");
		return -1;
	}

	if (fr_radius_sign(buffer, request->packet->data + 4,
			   (uint8_t const *) client->secret, talloc_array_length(client->secret) - 1) < 0) {
		RPEDEBUG("Failed signing RADIUS reply");
		return -1;
	}

	fr_packet_net_from_pairs(request->reply, &request->reply_pairs);

	if (RDEBUG_ENABLED) {
		RDEBUG("Sending %s ID %i from %pV:%i to %pV:%i length %zu via socket %s",
		       fr_radius_packet_name[request->reply->code],
		       request->reply->id,
		       fr_box_ipaddr(request->reply->socket.inet.src_ipaddr),
		       request->reply->socket.inet.src_port,
		       fr_box_ipaddr(request->reply->socket.inet.dst_ipaddr),
		       request->reply->socket.inet.dst_port,
		       data_len,
		       request->async->listen->name);

		log_request_proto_pair_list(L_DBG_LVL_1, request, NULL, &request->reply_pairs, NULL);
	}

	return data_len;
}

static int mod_priority_set(void const *instance, uint8_t const *buffer, UNUSED size_t buflen)
{
	proto_radius_t const *inst = talloc_get_type_abort_const(instance, proto_radius_t);

	fr_assert(buffer[0] > 0);
	fr_assert(buffer[0] < FR_RADIUS_CODE_MAX);

	/*
	 *	Disallowed packet
	 */
	if (!inst->priorities[buffer[0]]) return 0;

	if (!inst->allowed[buffer[0]]) return -1;

	/*
	 *	@todo - if we cared, we could also return -1 for "this
	 *	is a bad packet".  But that's really only for
	 *	mod_inject, as we assume that app_io->read() always
	 *	returns good packets.
	 */

	/*
	 *	Return the configured priority.
	 */
	return inst->priorities[buffer[0]];
}

/** Open listen sockets/connect to external event source
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] sc	to add our file descriptor to.
 * @param[in] conf	Listen section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_open(void *instance, fr_schedule_t *sc, UNUSED CONF_SECTION *conf)
{
	proto_radius_t 	*inst = talloc_get_type_abort(instance, proto_radius_t);

	/*
	 *	io.app_io should already be set
	 */
	return fr_master_io_listen(&inst->io, sc,
				   inst->max_packet_size, inst->num_messages);
}

/** Instantiate the application
 *
 * Instantiate I/O and type submodules.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_radius_t		*inst = talloc_get_type_abort(mctx->mi->data, proto_radius_t);

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) return 0;

	/*
	 *	These timers are usually protocol specific.
	 */
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("idle_timeout", inst->io.idle_timeout, <=, fr_time_delta_from_sec(600));

	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, >=, fr_time_delta_from_sec(1));
	FR_TIME_DELTA_BOUND_CHECK("nak_lifetime", inst->io.nak_lifetime, <=, fr_time_delta_from_sec(600));

	FR_TIME_DELTA_BOUND_CHECK("cleanup_delay", inst->io.cleanup_delay, <=, fr_time_delta_from_sec(30));
	FR_TIME_DELTA_BOUND_CHECK("cleanup_delay", inst->io.cleanup_delay, >, fr_time_delta_from_sec(0));

#if 0
	/*
	 *	No Access-Request packets, then no cleanup delay.
	 */
	if (!inst->allowed[FR_RADIUS_CODE_ACCESS_REQUEST]) {
		inst->io.cleanup_delay = 0;
	}
#endif

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	/*
	 *	These configuration items are not printed by default,
	 *	because normal people shouldn't be touching them.
	 */
	if (!inst->max_packet_size && inst->io.app_io) inst->max_packet_size = inst->io.app_io->default_message_size;

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 1024);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_radius;
	inst->io.app_instance = inst;

	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.mi = mctx->mi;

	/*
	 *	Instantiate the transport module before calling the
	 *	common instantiation function.
	 */
	if (module_instantiate(inst->io.submodule) < 0) return -1;

	/*
	 *	Instantiate the master io submodule
	 */
	return fr_master_app_io.common.instantiate(MODULE_INST_CTX(inst->io.mi));
}

/** Get the authentication vector.
 *
 *  Note that we don't allow people to get the reply vector, because
 *  it doesn't exist until the reply is sent.
 *
 */
static xlat_action_t packet_vector_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx, request_t *request,
					UNUSED fr_value_box_list_t *in)
{
	fr_value_box_t	*vb;

	if (request->proto_dict != dict_radius) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_OCTETS, NULL));
	if (fr_value_box_memdup(vb, vb, NULL, request->packet->vector, sizeof(request->packet->vector), true) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


static int mod_load(void)
{
	if (fr_radius_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}


	if (!xlat_func_register(NULL, "radius.packet.vector", packet_vector_xlat, FR_TYPE_OCTETS)) return -1;

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("radius.packet.vector");

	fr_radius_global_free();
}

fr_app_t proto_radius = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "radius",
		.config			= proto_radius_config,
		.inst_size		= sizeof(proto_radius_t),
		.onload			= mod_load,
		.unload			= mod_unload,
		.instantiate		= mod_instantiate
	},
	.dict			= &dict_radius,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.priority		= mod_priority_set
};
