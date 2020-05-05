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
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>
#include "proto_arp.h"

extern fr_app_t proto_arp;

/** How to parse an ARP listen section
 *
 */
static CONF_PARSER const proto_arp_config[] = {
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_arp_t, num_messages) } ,

	{ FR_CONF_OFFSET("active", FR_TYPE_BOOL, proto_arp_t, active), .dflt = "false" } ,

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_arp;

extern fr_dict_autoload_t proto_arp_dict[];
fr_dict_autoload_t proto_arp_dict[] = {
	{ .out = &dict_arp, .proto = "arp" },
	{ NULL }
};

#if 0
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_arp_dict_attr[];
fr_dict_attr_autoload_t proto_arp_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_arp},
	{ NULL }
};
#endif

/** Decode the packet
 *
 */
static int mod_decode(UNUSED void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
//	proto_arp_t const	*inst = talloc_get_type_abort_const(instance, proto_arp_t);
	fr_arp_packet_t	const	*arp;

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = dict_arp;

	if (fr_arp_decode(request->packet, data, data_len, &request->packet->vps) < 0) {
		RPEDEBUG("Failed decoding packet");
		return -1;
	}

	arp = (fr_arp_packet_t const *) data;
	request->packet->code = (arp->op[0] << 8) | arp->op[1];
	fr_assert(request->packet->code < FR_ARP_MAX_PACKET_CODE);

	request->packet->data = talloc_memdup(request->packet, data, data_len);
	request->packet->data_len = data_len;

	request->config = main_config;
	REQUEST_VERIFY(request);

	if (RDEBUG_ENABLED) {
		RDEBUG("Received ARP %s via socket %s",
		       fr_arp_packet_codes[request->packet->code],
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");
	}

	return 0;
}

static uint8_t const zeros[6] = { 0 };

static ssize_t mod_encode(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	ssize_t			slen;
	proto_arp_t const	*inst = talloc_get_type_abort_const(instance, proto_arp_t);
	fr_arp_packet_t		*arp;

	/*
	 *	The packet timed out.  Tell the network side that the packet is dead.
	 */
	if (buffer_len == 1) {
		*buffer = true;
		return 1;
	}

	/*
	 *	"Do not respond"
	 */
	if (!inst->active ||
	    (request->reply->code == FR_ARP_CODE_DO_NOT_RESPOND) ||
	    (request->reply->code == 0) || (request->reply->code >= FR_ARP_MAX_PACKET_CODE)) {
		*buffer = false;
		return 1;
	}

	slen = fr_arp_encode(buffer, buffer_len, request->packet->data, request->reply->vps);
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

	if (RDEBUG_ENABLED) {
		RDEBUG("Sending %d via socket %s",
		       request->reply->code,
		       request->async->listen->name);

		log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
	}

	return slen;
}

static void mod_entry_point_set(void const *instance, REQUEST *request)
{
	proto_arp_t const	*inst = talloc_get_type_abort_const(instance, proto_arp_t);
	fr_app_worker_t const	*app_process;

	/*
	 *	Only one "process" function: proto_arp_process.
	 */
	app_process = (fr_app_worker_t const *) inst->app_process->module->common;

	request->server_cs = inst->server_cs;
	request->async->process = app_process->entry_point;
	request->async->process_inst = inst->process_instance;
}


/*
 *	@todo - do actual priority setting
 */
static int mod_priority_set(UNUSED void const *instance, UNUSED uint8_t const *buffer, UNUSED size_t buflen)
{
	return PRIORITY_NORMAL;
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
	fr_listen_t	*li;
	proto_arp_t 	*inst = talloc_get_type_abort(instance, proto_arp_t);

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	li = talloc_zero(inst, fr_listen_t);
	talloc_set_destructor(li, fr_io_listen_free);

	li->app = &proto_arp;
	li->app_instance = instance;
	li->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	li->default_message_size = FR_ARP_PACKET_SIZE;
	li->num_messages = inst->num_messages;

	li->app_io = inst->app_io;
	li->app_io_instance = inst->app_io_instance;
	if (li->app_io->thread_inst_size) {
		li->thread_instance = talloc_zero_array(NULL, uint8_t, li->app_io->thread_inst_size);
		talloc_set_name(li->thread_instance, "proto_%s_thread_t", inst->app_io->name);
	}

	/*
	 *	Open the raw socket.
	 */
	if (inst->app_io->open(li) < 0) {
		talloc_free(li);
		return -1;
	}
	fr_assert(li->fd >= 0);

	li->name = inst->app_io->get_name(li);

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
 * @param[in] instance	Ctx data for this application.
 * @param[in] conf	Listen section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	proto_arp_t		*inst = talloc_get_type_abort(instance, proto_arp_t);
	fr_app_worker_t const	*app_process;

	/*
	 *	Instantiate the I/O module. But DON'T instantiate the
	 *	work submodule.  We leave that until later.
	 */
	if (inst->app_io->instantiate &&
	    (inst->app_io->instantiate(inst->app_io_instance,
				       inst->app_io_conf) < 0)) {
		cf_log_err(conf, "Instantiation failed for \"%s\"", inst->app_io->name);
		return -1;
	}

	if (!inst->num_messages) inst->num_messages = 256;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	/*
	 *	Instantiate the ARP processor
	 */
	app_process = (fr_app_worker_t const *)inst->app_process->module->common;
	if (app_process->instantiate && (app_process->instantiate(inst->app_process->data,
								  inst->app_process->conf) < 0)) {
		cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
		return -1;
	}

	/*
	 *	Compile the processing sections.
	 */
	if (app_process->compile_list) {
		vp_tmpl_rules_t		parse_rules;

		memset(&parse_rules, 0, sizeof(parse_rules));
		parse_rules.dict_def = dict_arp;

		if (virtual_server_compile_sections(inst->server_cs, app_process->compile_list, &parse_rules, inst->app_process->data) < 0) {
			return -1;
		}
	}

	return 0;
}


/** Bootstrap the application
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] conf	Listen section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	proto_arp_t 		*inst = talloc_get_type_abort(instance, proto_arp_t);
	dl_module_inst_t	*parent_inst;
	fr_app_worker_t const	*app_process;

	/*
	 *	Ensure that the server CONF_SECTION is always set.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));
	inst->cs = conf;

	parent_inst = cf_data_value(cf_data_find(inst->cs, dl_module_inst_t, "proto_arp"));
	fr_assert(parent_inst);

	if (dl_module_instance(inst->cs, &inst->io_submodule, inst->cs,
			       parent_inst, "ethernet", DL_MODULE_TYPE_SUBMODULE) < 0) {
		cf_log_perr(inst->cs, "Failed to load proto_arp_ethernet");
		return -1;
	}

	/*
	 *	Parent dl_module_inst_t added in virtual_servers.c (listen_parse)
	 */
	if (dl_module_instance(inst->cs, &inst->app_process, inst->cs,
			       parent_inst, "process", DL_MODULE_TYPE_SUBMODULE) < 0) {
		cf_log_perr(inst->cs, "Failed to load proto_arp_process");
		return -1;
	}

	/*
	 *	Bootstrap the I/O module
	 */
	inst->app_io = (fr_app_io_t const *) inst->io_submodule->module->common;
	inst->app_io_instance = inst->io_submodule->data;
	inst->app_io_conf = conf;

	if (inst->app_io->bootstrap && (inst->app_io->bootstrap(inst->app_io_instance,
								inst->app_io_conf) < 0)) {
		cf_log_err(inst->app_io_conf, "Bootstrap failed for \"%s\"", inst->app_io->name);
		return -1;
	}

	/*
	 *	Bootstrap the ARP processor
	 */
	app_process = (fr_app_worker_t const *)(inst->app_process->module->common);
	if (app_process->bootstrap && (app_process->bootstrap(inst->app_process->data,
							      inst->app_process->conf) < 0)) {
		cf_log_err(conf, "Bootstrap failed for \"%s\"", app_process->name);
		return -1;
	}

	/*
	 *	Register the processing sections with the
	 *	module manager.
	 *
	 *	We have to do this ourselves because we don't call
	 *	fr_app_process_bootstrap().  That function requires a
	 *	"type = ..." configuration, which isn't used for ARP.
	 */
	if (app_process->compile_list) {
		int j;
		virtual_server_compile_t const *list = app_process->compile_list;

		for (j = 0; list[j].name != NULL; j++) {
			if (list[j].name == CF_IDENT_ANY) continue;

			if (virtual_server_section_register(&list[j]) < 0) {
				cf_log_err(conf, "Failed registering section name for %s",
					   app_process->name);
				return -1;
			}
		}
	}

	return 0;
}

static int mod_load(void)
{
	if (fr_arp_init() < 0) {
		PERROR("Failed initialising protocol library");
		return -1;
	}
	return 0;
}

static void mod_unload(void)
{
	fr_arp_free();
}

fr_app_t proto_arp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "arp",
	.config			= proto_arp_config,
	.inst_size		= sizeof(proto_arp_t),
	.dict			= &dict_arp,

	.onload			= mod_load,
	.unload			= mod_unload,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.entry_point_set	= mod_entry_point_set,
	.priority		= mod_priority_set
};
