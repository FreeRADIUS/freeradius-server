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
 * @file proto_tacacs.c
 * @brief TACACS+ module.
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/tacacs/tacacs.h>

#include "proto_tacacs.h"

extern fr_app_t proto_tacacs;

static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule);

static conf_parser_t const limit_config[] = {
	{ FR_CONF_OFFSET("idle_timeout", proto_tacacs_t, io.idle_timeout), .dflt = "30.0" } ,
	{ FR_CONF_OFFSET("dynamic_timeout", proto_tacacs_t, io.dynamic_timeout), .dflt = "600.0" } ,

	{ FR_CONF_OFFSET("max_connections", proto_tacacs_t, io.max_connections), .dflt = "1024" } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", proto_tacacs_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", proto_tacacs_t, num_messages) } ,

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t priority_config[] = {
	{ FR_CONF_OFFSET("Authentication-Start", proto_tacacs_t, priorities[FR_TAC_PLUS_AUTHEN]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "high" },
	{ FR_CONF_OFFSET("Authentication-Continue", proto_tacacs_t, priorities[FR_TAC_PLUS_AUTHEN]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "high" },
	{ FR_CONF_OFFSET("Authorization-Request", proto_tacacs_t, priorities[FR_TAC_PLUS_AUTHOR]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "normal" },
	{ FR_CONF_OFFSET("Accounting-Request", proto_tacacs_t, priorities[FR_TAC_PLUS_ACCT]),
	  .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = channel_packet_priority, .len = &channel_packet_priority_len }, .dflt = "low" },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t proto_tacacs_config[] = {
	{ FR_CONF_OFFSET_FLAGS("type", CONF_FLAG_NOT_EMPTY, proto_tacacs_t, allowed_types), .func = type_parse },
	{ FR_CONF_OFFSET_TYPE_FLAGS("transport", FR_TYPE_VOID, 0, proto_tacacs_t, io.submodule), .func = transport_parse },

	{ FR_CONF_POINTER("limit", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	{ FR_CONF_POINTER("priority", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) priority_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t proto_tacacs_dict[];
fr_dict_autoload_t proto_tacacs_dict[] = {
 	{ .out = &dict_tacacs, .proto = "tacacs" },
	DICT_AUTOLOAD_TERMINATOR
};


static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_tacacs_user_name;

extern fr_dict_attr_autoload_t proto_tacacs_dict_attr[];
fr_dict_attr_autoload_t proto_tacacs_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tacacs},
	{ .out = &attr_tacacs_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	DICT_AUTOLOAD_TERMINATOR
};

static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	proto_tacacs_t		*inst = talloc_get_type_abort(parent, proto_tacacs_t);
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

/** Translates the packet-type into a submodule name
 *
 * If we found a Packet-Type = Authentication-Start CONF_PAIR for example, here's we'd load
 * the proto_tacacs_auth module.
 *
 * @param[in] ctx	to allocate data in (instance of proto_tacacs).
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
	proto_tacacs_t			*inst = talloc_get_type_abort(parent, proto_tacacs_t);
	fr_dict_enum_value_t const	*dv;
	CONF_PAIR			*cp;
	char const			*value;

	cp = cf_item_to_pair(ci);
	value = cf_pair_value(cp);

	dv = fr_dict_enum_by_name(attr_packet_type, value, -1);
	if (!dv || !FR_TACACS_PACKET_CODE_VALID(dv->value->vb_uint32)) {
		cf_log_err(ci, "Unknown TACACS+ packet type '%s'", value);
		return -1;
	}

	inst->allowed[dv->value->vb_uint32] = true;
	*((char const **) out) = value;

	return 0;
}

/** Decode the packet
 *
 */
static int mod_decode(UNUSED void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;
	fr_client_t const		*client;
	int			code = -1;
	fr_tacacs_packet_t const *pkt = (fr_tacacs_packet_t const *)data;
	char const		*secret;
	size_t			secretlen = 0;
	fr_dict_attr_t const	*dv = NULL;

	RHEXDUMP3(data, data_len, "proto_tacacs decode packet");

	client = address->radclient;

	/*
	 *	Clients start at ID 1, and go up by 2.
	 */
	if ((data[2] & 0x01) != 0x01) {
		REDEBUG("Invalid sequence number %02x", data[2]);
		return -1;
	}

	request->packet->id   = data[2]; // seq_no
	request->reply->id    = data[2] + 1; // seq_no, but requests are odd, replies are even! */

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	if (!client->active) {
		fr_assert(client->dynamic);
		request_set_dynamic_client(request);

		/*
		 *	For real packets, the code is extracted during packet decode,
		 *	however, we can't do that for a fake packet used to set up a
		 *	dynamic client as we don't have the secret - so set an intelligent
		 *	packet code.
		 */
		switch (request->packet->data[1]) {
		case FR_TAC_PLUS_AUTHEN:
			request->packet->code = FR_PACKET_TYPE_VALUE_AUTHENTICATION_START;
			break;
		case FR_TAC_PLUS_AUTHOR:
			request->packet->code = FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST;
			break;
		case FR_TAC_PLUS_ACCT:
			request->packet->code = FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST;
			break;
		default:
			return -1;
		}
		goto skip_decode;
	}

	secret = client->secret;
	if (secret) {
		if (!packet_is_encrypted((fr_tacacs_packet_t const *) data)) {
			REDEBUG("Expected to see encrypted packet, got unencrypted packet!");
			return -1;
		}
		secretlen = talloc_array_length(client->secret) - 1;
	}

	/*
	 *	See if there's a client-specific vendor in the "nas_type" field.
	 *
	 *	If there's no such vendor, too bad for you.
	 */
	if (client->nas_type) {
		dv = fr_dict_attr_by_name(NULL, fr_dict_root(dict_tacacs), client->nas_type);
	}

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to ???
	 */
	if (fr_tacacs_decode(request->request_ctx, &request->request_pairs, dv,
			     request->packet->data, request->packet->data_len,
			     NULL, secret, secretlen, &code) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	request->packet->code = code;
skip_decode:

	/*
	 *	RFC 8907 Section 3.6 says:
	 *
	 *	  If an error occurs but the type of the incoming packet cannot be determined, a packet with the
	 *	  identical cleartext header but with a sequence number incremented by one and the length set to
	 *	  zero MUST be returned to indicate an error.
	 *
	 *	This is substantially retarded.  It should instead just close the connection.
	 */


	/*
	 *	Set the rest of the fields.
	 */
	request->client = UNCONST(fr_client_t *, client);

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	REQUEST_VERIFY(request);

	if (RDEBUG_ENABLED) {
		fr_pair_t *vp;

		RDEBUG("Received %s ID %i from %pV:%i to %pV:%i length %zu via socket %s",
		       fr_tacacs_packet_names[request->packet->code],
		       request->packet->id,
		       fr_box_ipaddr(request->packet->socket.inet.src_ipaddr),
		       request->packet->socket.inet.src_port,
		       fr_box_ipaddr(request->packet->socket.inet.dst_ipaddr),
		       request->packet->socket.inet.dst_port,
		       request->packet->data_len,
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->request_pairs, NULL);

		/*
		 *	Maybe the shared secret is wrong?
		 */
		if (client->active &&
		    ((pkt->hdr.flags & FR_FLAGS_VALUE_UNENCRYPTED) == 0) &&
		    RDEBUG_ENABLED2 &&
		    ((vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_user_name)) != NULL) &&
		    (fr_utf8_str((uint8_t const *) vp->vp_strvalue, vp->vp_length) < 0)) {
			RWDEBUG("Unprintable characters in the %s. "
				"Double-check the shared secret on the server "
				"and the TACACS+ Client!", attr_tacacs_user_name->name);
		}
	}

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		RPEDEBUG("Failed decoding 'Net.*' packet");
		return -1;
	}

	return 0;
}

static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
	fr_io_track_t 		*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;
	ssize_t			data_len;
	fr_client_t const		*client;
	char const		*secret;
	size_t			secretlen = 0;

	/*
	 *	@todo - RFC 8907 Section 4.4. says:
	 *
	 *	  When the session is complete, the TCP connection should be handled as follows, according to
	 *	  whether Single Connection Mode was negotiated:
	 *
	 *	  * If Single Connection Mode was not negotiated, then the connection should be closed.
	 *
	 *	  * If Single Connection Mode was enabled, then the connection SHOULD be left open (see
	 *	    "Single Connection Mode" (Section 4.3)) but may still be closed after a timeout period to
	 *	    preserve deployment resources.
	 *
	 *	  * If Single Connection Mode was enabled, but an ERROR occurred due to connection issues
	 *	   (such as an incorrect secret (see Section 4.5)), then any further new sessions MUST NOT be
	 *	   accepted on the connection. If there are any sessions that have already been established,
	 *	   then they MAY be completed. Once all active sessions are completed, then the connection
	 *	   MUST be closed.
	 */

	/*
	 *	Process layer NAK, or "Do not respond".
	 */
	if ((buffer_len == 1) ||
	    !FR_TACACS_PACKET_CODE_VALID(request->reply->code)) {
		track->do_not_respond = true;
		return 1;
	}

	client = address->radclient;
	fr_assert(client);

	/*
	 *	Dynamic client stuff
	 */
	if (client->dynamic && !client->active) {
		fr_client_t *new_client;

		fr_assert(buffer_len >= sizeof(client));

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
			buffer[0] = true;
			return 1;
		}

		memcpy(buffer, &new_client, sizeof(new_client));
		return sizeof(new_client);
	}

	secret = client->secret;
	if (secret) secretlen = talloc_array_length(client->secret) - 1;

	data_len = fr_tacacs_encode(&FR_DBUFF_TMP(buffer, buffer_len), request->packet->data,
				    secret, secretlen,
				    request->reply->code, &request->reply_pairs);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding TACACS+ reply");
		return -1;
	}

	if (RDEBUG_ENABLED) {
		RDEBUG("Sending %s ID %i from %pV:%i to %pV:%i length %zu via socket %s",
		       fr_tacacs_packet_names[request->reply->code],
		       request->reply->id,
		       fr_box_ipaddr(request->reply->socket.inet.src_ipaddr),
		       request->reply->socket.inet.src_port,
		       fr_box_ipaddr(request->reply->socket.inet.dst_ipaddr),
		       request->reply->socket.inet.dst_port,
		       data_len,
		       request->async->listen->name);

		log_request_proto_pair_list(L_DBG_LVL_1, request, NULL, &request->reply_pairs, NULL);
	}

	RHEXDUMP3(buffer, data_len, "proto_tacacs encode packet");

	return data_len;
}

static int mod_priority_set(void const *instance, uint8_t const *buffer, UNUSED size_t buflen)
{
	proto_tacacs_t const *inst = talloc_get_type_abort_const(instance, proto_tacacs_t);

	fr_assert(FR_TACACS_PACKET_CODE_VALID(buffer[1]));

	/*
	 *	Disallowed packet
	 */
	if (!inst->priorities[buffer[1]]) return 0;

	/*
	 *	@todo - if we cared, we could also return -1 for "this
	 *	is a bad packet".  But that's really only for
	 *	mod_inject, as we assume that app_io->read() always
	 *	returns good packets.
	 */

	/*
	 *	Return the configured priority.
	 */
	return inst->priorities[buffer[1]];
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
	proto_tacacs_t 	*inst = talloc_get_type_abort(instance, proto_tacacs_t);

	inst->io.app = &proto_tacacs;
	inst->io.app_instance = instance;

	/*
	 *	io.app_io should already be set
	 */
	return fr_master_io_listen(&inst->io, sc, inst->max_packet_size, inst->num_messages);
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
	proto_tacacs_t		*inst = talloc_get_type_abort(mctx->mi->data, proto_tacacs_t);

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	fr_assert(dict_tacacs != NULL);

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

 	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_tacacs;
	inst->io.app_instance = inst;

	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.mi = mctx->mi;

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
	 *	Instantiate the transport module before calling the
	 *	common instantiation function.
	 */
	if (module_instantiate(inst->io.submodule) < 0) return -1;

	/*
	 *	Instantiate the master io submodule
	 */
	return fr_master_app_io.common.instantiate(MODULE_INST_CTX(inst->io.mi));
}

static int mod_load(void)
{
	if (fr_tacacs_global_init() < 0) {
		PERROR("Failed initialising tacacs");
		return -1;
	}

	return 0;
}

static void mod_unload(void)
{
	fr_tacacs_global_free();
}

fr_app_t proto_tacacs = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "tacacs",
		.config			= proto_tacacs_config,
		.inst_size		= sizeof(proto_tacacs_t),

		.onload			= mod_load,
		.unload			= mod_unload,
		.instantiate		= mod_instantiate
	},
	.dict			= &dict_tacacs,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.priority		= mod_priority_set
};
