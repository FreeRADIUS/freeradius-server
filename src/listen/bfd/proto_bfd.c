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
#include "proto_bfd.h"

extern fr_app_t proto_bfd;

static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

/** How to parse a BFD listen section
 *
 */
static CONF_PARSER const proto_bfd_config[] = {
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_bfd_t, io.submodule),
	  .func = transport_parse },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_bfd;

extern fr_dict_autoload_t proto_bfd_dict[];
fr_dict_autoload_t proto_bfd_dict[] = {
	{ .out = &dict_bfd, .proto = "bfd" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_link_state;

extern fr_dict_attr_autoload_t proto_bfd_dict_attr[];
fr_dict_attr_autoload_t proto_bfd_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_bfd},
	{ .out = &attr_link_state, .name = "Link-State", .type = FR_TYPE_UINT32, .dict = &dict_bfd},
	{ NULL }
};

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

/** Decode the packet
 *
 */
static int mod_decode(void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	proto_bfd_t const	*inst = talloc_get_type_abort_const(instance, proto_bfd_t);
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;
	RADCLIENT const		*client;

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
	request->packet->code = data[1] >> 6;
	request->packet->id = fr_nbo_to_uint32(data + 4);
	request->reply->id = request->packet->id;

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_radius_ok().
	 */
	if (fr_bfd_decode(request->request_ctx, &request->request_pairs,
			  request->packet->data, request->packet->data_len,
			  client->secret, talloc_array_length(client->secret) - 1) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	/*
	 *	Set the rest of the fields.
	 */
	request->client = UNCONST(RADCLIENT *, client);

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

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

	if (!inst->io.app_io->decode) return 0;

	/*
	 *	Let the app_io do anything it needs to do.
	 */
	return inst->io.app_io->decode(inst->io.app_io_instance, request, data, data_len);
}

static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
//	proto_bfd_t const	*inst = talloc_get_type_abort_const(instance, proto_bfd_t);
	fr_io_track_t		*track = talloc_get_type_abort(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;
	ssize_t			data_len;
	RADCLIENT const		*client;

	/*
	 *	Process layer NAK, or "Do not respond".
	 */
	if (buffer_len == 1) {
		return 1;
	}

	client = address->radclient;
	fr_assert(client);

	/*
	 *	Dynamic client stuff
	 */
	if (client->dynamic && !client->active) {
		RADCLIENT *new_client;

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

	/*
	 *	Overwrite the src ip address on the outbound packet
	 *	with the one specified by the client.  This is useful
	 *	to work around broken DSR implementations and other
	 *	routing issues.
	 */
	if (client->src_ipaddr.af != AF_UNSPEC) {
		request->reply->socket.inet.src_ipaddr = client->src_ipaddr;
	}

	data_len = fr_bfd_encode(buffer, buffer_len, request->packet->data,
				 client->secret, talloc_array_length(client->secret) - 1,
				 &request->reply_pairs);
	if (data_len < 0) {
		RPEDEBUG("Failed encoding BFD reply");
		return -1;
	}

	if (RDEBUG_ENABLED) {
		RDEBUG("Sending %s ID %i from %pV:%i to %pV:%i length %zu via socket %s",
		       fr_bfd_packet_names[request->reply->code],
		       request->reply->id,
		       fr_box_ipaddr(request->reply->socket.inet.src_ipaddr),
		       request->reply->socket.inet.src_port,
		       fr_box_ipaddr(request->reply->socket.inet.dst_ipaddr),
		       request->reply->socket.inet.dst_port,
		       data_len,
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->reply_pairs, NULL);
	}

	return data_len;
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
