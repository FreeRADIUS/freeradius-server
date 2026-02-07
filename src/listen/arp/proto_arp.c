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
 * @file proto_arp.c
 * @brief RADIUS master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/packet.h>
#include <freeradius-devel/util/debug.h>
#include "proto_arp.h"

extern fr_app_t proto_arp;

/** How to parse an ARP listen section
 *
 */
static conf_parser_t const proto_arp_config[] = {
	{ FR_CONF_OFFSET("num_messages", proto_arp_t, num_messages) } ,

	{ FR_CONF_OFFSET("active", proto_arp_t, active), .dflt = "false" } ,

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_arp;

extern fr_dict_autoload_t proto_arp_dict[];
fr_dict_autoload_t proto_arp_dict[] = {
	{ .out = &dict_arp, .proto = "arp" },
	DICT_AUTOLOAD_TERMINATOR
};

#if 0
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_arp_dict_attr[];
fr_dict_attr_autoload_t proto_arp_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_arp},
	DICT_AUTOLOAD_TERMINATOR
};
#endif

/** Decode the packet
 *
 */
static int mod_decode(UNUSED void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
//	proto_arp_t const	*inst = talloc_get_type_abort_const(instance, proto_arp_t);
	fr_arp_packet_t	const	*arp;

	if (fr_arp_decode(request->request_ctx, &request->request_pairs, data, data_len) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	arp = (fr_arp_packet_t const *) data;
	request->packet->code = fr_nbo_to_uint16(arp->op);
	fr_assert(request->packet->code < FR_ARP_CODE_MAX);

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		RPEDEBUG("Failed decoding 'Net.*' packet");
		return -1;
	}

	REQUEST_VERIFY(request);

	if (RDEBUG_ENABLED) {
		RDEBUG("Received ARP %s via socket %s",
		       fr_arp_packet_codes[request->packet->code],
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->request_pairs, NULL);
	}

	return 0;
}

static uint8_t const zeros[6] = { 0 };

static ssize_t mod_encode(void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
	ssize_t			slen;
	proto_arp_t const	*inst = talloc_get_type_abort_const(instance, proto_arp_t);
	fr_arp_packet_t		*arp;

	/*
	 *	Process layer NAK, never respond, or "Do not respond".
	 */
	if ((buffer_len == 1) || !inst->active ||
	    (request->reply->code == FR_ARP_DO_NOT_RESPOND) ||
	    (request->reply->code == 0) || (request->reply->code >= FR_ARP_CODE_MAX)) {
		*buffer = false;
		return 1;
	}

	slen = fr_arp_encode(&FR_DBUFF_TMP(buffer, buffer_len), request->packet->data, &request->reply_pairs);
	if (slen <= 0) {
		RPEDEBUG("Failed encoding reply");
		return -1;
	}
	fr_assert(slen == FR_ARP_PACKET_SIZE);

	arp = (fr_arp_packet_t *) buffer;
	fr_assert(request->packet->data_len == FR_ARP_PACKET_SIZE);

	if (memcmp(arp->sha, zeros, sizeof(arp->sha)) == 0) {
		RDEBUG("WARNING: Sender-Hardware-Address of zeros will likely cause problems");
	}

	fr_packet_net_from_pairs(request->reply, &request->reply_pairs);

	if (RDEBUG_ENABLED) {
		RDEBUG("Sending %d via socket %s",
		       request->reply->code,
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->reply_pairs, NULL);
	}

	return slen;
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
static int mod_open(void *instance, fr_schedule_t *sc, CONF_SECTION *conf)
{
	fr_listen_t	*li;
	proto_arp_t 	*inst = talloc_get_type_abort(instance, proto_arp_t);

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	li = talloc_zero(inst, fr_listen_t);
	talloc_set_destructor(li, fr_io_listen_free);

	li->cs = conf;
	li->app = &proto_arp;
	li->app_instance = instance;
	li->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	li->default_message_size = FR_ARP_PACKET_SIZE;
	li->num_messages = inst->num_messages;

	li->app_io = (fr_app_io_t const *)inst->io_submodule->exported;
	li->app_io_instance = inst->io_submodule->data;
	if (li->app_io->common.thread_inst_size) {
		li->thread_instance = talloc_zero_array(NULL, uint8_t, li->app_io->common.thread_inst_size);
		talloc_set_name(li->thread_instance, "proto_%s_thread_t", li->app_io->common.name);
	}

	/*
	 *	Open the raw socket.
	 */
	if (li->app_io->open(li) < 0) {
		talloc_free(li);
		return -1;
	}
	fr_assert(li->fd >= 0);

	li->name = li->app_io->get_name(li);

	/*
	 *	Watch the directory for changes.
	 */
	if (!fr_schedule_listen_add(sc, li)) {
		talloc_free(li);
		return -1;
	}

	inst->listen = li;	/* Probably won't need it, but doesn't hurt */
	inst->sc = sc;

	return 0;
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
	proto_arp_t 		*inst = talloc_get_type_abort(mctx->mi->data, proto_arp_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));
	inst->cs = conf;

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	return 0;
}

static int mod_load(void)
{
	if (fr_arp_global_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	fr_arp_global_free();
}

fr_app_t proto_arp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "arp",
		.config			= proto_arp_config,
		.inst_size		= sizeof(proto_arp_t),
		.onload			= mod_load,
		.unload			= mod_unload,
		.instantiate		= mod_instantiate
	},
	.dict			= &dict_arp,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
};
