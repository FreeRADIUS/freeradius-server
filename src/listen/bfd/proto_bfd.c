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
 * @file proto_bfd.c
 * @brief RADIUS master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/internal/internal.h>

#include "proto_bfd.h"

extern fr_app_t proto_bfd;

static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int auth_type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

/** How to parse a BFD listen section
 *
 */
static CONF_PARSER const proto_bfd_config[] = {
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_bfd_t, io.submodule),
	  .func = transport_parse },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER peer_config[] = {
	{ FR_CONF_OFFSET("min_transmit_interval", FR_TYPE_TIME_DELTA, bfd_session_t, desired_min_tx_interval ) },
	{ FR_CONF_OFFSET("min_receive_interval", FR_TYPE_TIME_DELTA, bfd_session_t, required_min_rx_interval ) },
	{ FR_CONF_OFFSET("max_timeouts", FR_TYPE_UINT32, bfd_session_t, detect_multi ) },
	{ FR_CONF_OFFSET("demand", FR_TYPE_BOOL, bfd_session_t, demand_mode ) },

	{ FR_CONF_OFFSET("auth_type", FR_TYPE_VOID, bfd_session_t, auth_type ),
	.func = auth_type_parse },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, bfd_session_t, port ) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_bfd;

extern fr_dict_autoload_t proto_bfd_dict[];
fr_dict_autoload_t proto_bfd_dict[] = {
	{ .out = &dict_bfd, .proto = "bfd" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_bfd_packet;
static fr_dict_attr_t const *attr_my_discriminator;
static fr_dict_attr_t const *attr_your_discriminator;
static fr_dict_attr_t const *attr_additional_data;

extern fr_dict_attr_autoload_t proto_bfd_dict_attr[];
fr_dict_attr_autoload_t proto_bfd_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_bfd},

	{ .out = &attr_bfd_packet, .name = "Packet", .type = FR_TYPE_STRUCT, .dict = &dict_bfd},
	{ .out = &attr_my_discriminator, .name = "Packet.my-discriminator", .type = FR_TYPE_UINT32, .dict = &dict_bfd},
	{ .out = &attr_your_discriminator, .name = "Packet.your-discriminator", .type = FR_TYPE_UINT32, .dict = &dict_bfd},

	{ .out = &attr_additional_data, .name = "Additional-Data", .type = FR_TYPE_GROUP, .dict = &dict_bfd},
	{ NULL }
};

/*
 *	They all have to be UDP.
 */
static int8_t client_cmp(void const *one, void const *two)
{
	fr_client_t const *a = one;
	fr_client_t const *b = two;

	return fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_bfd).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*name = cf_pair_value(cf_item_to_pair(ci));
	dl_module_inst_t	*parent_inst;
	proto_bfd_t		*inst;
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*transport_cs;
	dl_module_inst_t	*dl_mod_inst;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_bfd"));
	fr_assert(parent_inst);

	/*
	 *	Set the allowed codes so that we can compile them as
	 *	necessary.
	 */
	inst = talloc_get_type_abort(parent_inst->data, proto_bfd_t);
	inst->io.transport = name;

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) {
		transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);
		inst->io.app_io_conf = transport_cs;
	}

	if (dl_module_instance(ctx, &dl_mod_inst, parent_inst,
			       DL_MODULE_TYPE_SUBMODULE, name, dl_module_inst_name_from_conf(transport_cs)) < 0) return -1;
	if (dl_module_conf_parse(dl_mod_inst, transport_cs) < 0) {
		talloc_free(dl_mod_inst);
		return -1;
	}
	*((dl_module_inst_t **)out) = dl_mod_inst;

	return 0;
}

/** Parse auth_type
 *
 * @param[in] ctx	to allocate data in (instance of proto_bfd).
 * @param[out] out	Where to write the auth_type value
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int auth_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*name = cf_pair_value(cf_item_to_pair(ci));
	int			auth_type;

	auth_type = fr_table_value_by_str(bfd_auth_type_table, name, -1);
	if (auth_type < 0) {
		cf_log_err(ci, "Invalid value for 'auth_type'");
		return -1;
	}

	*(bfd_auth_type_t *) out = auth_type;

	return 0;
}


/** Decode the packet
 *
 */
static int mod_decode(UNUSED void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;
	fr_client_t const	*client;
	fr_pair_t		*vp, *reply, *my, *your;
	bfd_wrapper_t const    	*wrapper = (bfd_wrapper_t const *) data;
	bfd_packet_t const     	*bfd = (bfd_packet_t const *) wrapper->packet;

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = dict_bfd;

	client = address->radclient;

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	request->packet->code = bfd->state;
	request->packet->id = fr_nbo_to_uint32((uint8_t const *) &bfd->my_disc);
	request->reply->id = request->packet->id;

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	/*
	 *	Set the rest of the fields.
	 */
	request->client = UNCONST(fr_client_t *, client);

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	REQUEST_VERIFY(request);

	/*
	 *	Decode the packet into the reply.
	 */
	if (wrapper->type == BFD_WRAPPER_SEND_PACKET) {
		if (fr_bfd_decode(request->reply_ctx, &request->reply_pairs,
				  (uint8_t const *) bfd, bfd->length,
				  client->secret, talloc_array_length(client->secret) - 1) < 0) {
			RPEDEBUG("Failed decoding packet");
			return -1;
		}

		request->reply->code = bfd->state;

		return 0;
	}

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_radius_ok().
	 */
	if (fr_bfd_decode(request->request_ctx, &request->request_pairs,
			  (uint8_t const *) bfd, bfd->length,
			  client->secret, talloc_array_length(client->secret) - 1) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	/*
	 *	Initialize the reply.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_bfd_packet);
	if (!vp) return -1;

	reply = fr_pair_copy(request->reply_ctx, vp);
	fr_pair_append(&request->reply_pairs, reply);

	my = fr_pair_find_by_da(&reply->vp_group, NULL, attr_my_discriminator);
	your = fr_pair_find_by_da(&reply->vp_group, NULL, attr_your_discriminator);

	if (my && your) {
		uint32_t tmp = your->vp_uint32;

		your->vp_uint32 = my->vp_uint32;
		my->vp_uint32 = tmp;
	}

	/*
	 *	If we're defining a dynamic client, this packet is
	 *	fake.  We don't have a secret, so we mash all of the
	 *	encrypted attributes to sane (i.e. non-hurtful)
	 *	values.
	 */
	if (!client->active) {
		fr_assert(client->dynamic);

		for (vp = fr_pair_list_head(&request->request_pairs);
		     vp != NULL;
		     vp = fr_pair_list_next(&request->request_pairs, vp)) {
			if (!flag_encrypted(&vp->da->flags)) {
				switch (vp->da->type) {
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

	return 0;
}

static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
//	proto_bfd_t const	*inst = talloc_get_type_abort_const(instance, proto_bfd_t);
	fr_io_track_t		*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;
	fr_client_t const	*client;
	bfd_wrapper_t const    	*wrapper = (bfd_wrapper_t const *) request->packet->data;
	bfd_packet_t const	*bfd = (bfd_packet_t const *) wrapper->packet;
	fr_pair_t		*vp;
	ssize_t			slen;
	fr_dbuff_t		dbuff;

	/*
	 *	Process layer NAK, or "Do not respond".
	 */
	if ((buffer_len == 1) || (wrapper->type == BFD_WRAPPER_RECV_PACKET) || (wrapper->type == BFD_WRAPPER_STATE_CHANGE)) {
		return 0;
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
			*buffer = true;
			return 1;
		}

		memcpy(buffer, &new_client, sizeof(new_client));
		return sizeof(new_client);
	}

	fr_assert((wrapper->packet + bfd->length) == (request->packet->data + request->packet->data_len));

	/*
	 *	Don't bother re-encoding the packet.
	 */
	memcpy(buffer, bfd, bfd->length);

	fr_assert(fr_bfd_packet_ok(NULL, buffer, bfd->length));

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_additional_data);
	if (!vp) return bfd->length;

	fr_dbuff_init(&dbuff, buffer + bfd->length, buffer_len - bfd->length);
	slen =  fr_internal_encode_list(&dbuff, &vp->vp_group, NULL);
	if (slen <= 0) return bfd->length;

	return bfd->length + slen;
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
	proto_bfd_t 	*inst = talloc_get_type_abort(instance, proto_bfd_t);

	inst->io.app = &proto_bfd;
	inst->io.app_instance = instance;

	/*
	 *	io.app_io should already be set
	 */
	return fr_master_io_listen(inst, &inst->io, sc,
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
	proto_bfd_t		*inst = talloc_get_type_abort(mctx->inst->data, proto_bfd_t);

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) return 0;

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
	 *	Instantiate the master io submodule
	 */
	return fr_master_app_io.common.instantiate(MODULE_INST_CTX(inst->io.dl_inst));
}


/** Bootstrap the application
 *
 * Bootstrap I/O and type submodules.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_bfd_t 		*inst = talloc_get_type_abort(mctx->inst->data, proto_bfd_t);
	CONF_SECTION		*server;

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->io.server_cs = cf_item_to_section(cf_parent(mctx->inst->conf));

	/*
	 *	No IO module, it's an empty listener.
	 */
	if (!inst->io.submodule) return 0;

	/*
	 *	Tell the master handler about the main protocol instance.
	 */
	inst->io.app = &proto_bfd;
	inst->io.app_instance = inst;

	/*
	 *	We will need this for dynamic clients and connected sockets.
	 */
	inst->io.dl_inst = dl_module_instance_by_data(inst);
	fr_assert(inst != NULL);

	server = inst->io.server_cs;

	inst->peers = cf_data_value(cf_data_find(server, fr_rb_tree_t, "peers"));
	if (!inst->peers) {
		CONF_SECTION *cs = NULL;

		inst->peers = fr_rb_inline_talloc_alloc(inst, fr_client_t, node, client_cmp, NULL);
		if (!inst->peers) return -1;

		while ((cs = cf_section_find_next(server, cs, "peer", CF_IDENT_ANY))) {
			fr_client_t *c;
			bfd_session_t *peer;

			if (cf_section_rules_push(cs, peer_config) < 0) return -1;

			c = client_afrom_cs(cs, cs, server, sizeof(bfd_session_t));
			if (!c) {
			error:
				cf_log_err(cs, "Failed to parse peer %s", cf_section_name2(cs));
				talloc_free(inst->peers);
				return -1;
			}

			if (c->proto != IPPROTO_UDP) {
				cf_log_err(cs, "Peer must use 'proto = udp' in %s", cf_section_name2(cs));
				goto error;
			}

			peer = (bfd_session_t *) c;

			FR_TIME_DELTA_BOUND_CHECK("peer.min_transmit_interval", peer->desired_min_tx_interval, >=, fr_time_delta_from_usec(32));
			FR_TIME_DELTA_BOUND_CHECK("peer.min_transmit_interval", peer->desired_min_tx_interval, <=, fr_time_delta_from_sec(2));

			FR_TIME_DELTA_BOUND_CHECK("peer.min_recieve_interval", peer->required_min_rx_interval, >=, fr_time_delta_from_usec(32));
			FR_TIME_DELTA_BOUND_CHECK("peer.min_received_interval", peer->required_min_rx_interval, <=, fr_time_delta_from_sec(2));

			FR_INTEGER_BOUND_CHECK("peer.max_timeouts", peer->detect_multi, >=, 1);
			FR_INTEGER_BOUND_CHECK("peer.max_timeouts", peer->detect_multi, <=, 10);

			if (((c->ipaddr.af == AF_INET) && (c->ipaddr.prefix != 32)) ||
			    ((c->ipaddr.af == AF_INET6) && (c->ipaddr.prefix != 128))) {
				cf_log_err(cs, "Invalid IP prefix - cannot use ip/mask for BFD");
				goto error;
			}

			/*
			 *	Secret and auth_type handling.
			 */
			if (c->secret) {
				if (!*c->secret) {
					cf_log_err(cs, "Secret cannot be an empty string");
					goto error;
				}

				peer->secret_len = talloc_array_length(c->secret) - 1;
			}

			switch (peer->auth_type) {
			case BFD_AUTH_RESERVED:
				if (c->secret) cf_log_warn(cs, "Ignoring 'secret' due to 'auth_type = none'");
				break;

			case BFD_AUTH_SIMPLE:
			case BFD_AUTH_KEYED_MD5:
			case BFD_AUTH_MET_KEYED_MD5:
				if (!c->secret) {
					cf_log_err(cs, "A 'secret' must be specified when using 'auth_type = simple'");
					goto error;
				}

				if (strlen(c->secret) > 16) {
					cf_log_err(cs, "Length of 'secret' must be no more than 16 octets for 'auth_type = simple'");
					goto error;
				}
				break;

			case BFD_AUTH_KEYED_SHA1:
			case BFD_AUTH_MET_KEYED_SHA1:
				if (!c->secret) {
					cf_log_err(cs, "A 'secret' must be specified when using 'auth_type = ...'");
					goto error;
				}

				if (strlen(c->secret) > 20) {
					cf_log_err(cs, "Length of 'secret' must be no more than 16 octets for 'auth_type = simple'");
					goto error;
				}
				break;

			}

			c->active = true;

			if (!fr_rb_insert(inst->peers, c)) {
				cf_log_err(cs, "Failed to add peer %s", cf_section_name2(cs));
				goto error;
			}
		}

		(void) cf_data_add(server, inst->peers, "peers", false);
	}

	/*
	 *	Bootstrap the master IO handler.
	 */
	return fr_master_app_io.common.bootstrap(MODULE_INST_CTX(inst->io.dl_inst));
}

static int mod_load(void)
{
	if (fr_bfd_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	fr_bfd_free();
}

fr_app_t proto_bfd = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "bfd",
		.config			= proto_bfd_config,
		.inst_size		= sizeof(proto_bfd_t),
		.onload			= mod_load,
		.unload			= mod_unload,
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate
	},
	.dict			= &dict_bfd,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
};
