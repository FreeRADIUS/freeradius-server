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
 * @file proto_detail.c
 * @brief Detail master protocol handler.
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/util/debug.h>

#include "proto_detail.h"

extern fr_app_t proto_detail;
static int dictionary_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

#if 0
/*
 *	When we want detailed debugging here, without detailed server
 *	debugging.
 */
#define MPRINT DEBUG
#else
#define MPRINT(x, ...)
#endif

/** How to parse a Detail listen section
 *
 */
static CONF_PARSER const proto_detail_config[] = {
	{ FR_CONF_OFFSET("dictionary", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY | FR_TYPE_REQUIRED, proto_detail_t,
			  dict), .dflt = "radius", .func = dictionary_parse },
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY | FR_TYPE_REQUIRED, proto_detail_t,
			  type_submodule), .func = type_parse },
	{ FR_CONF_OFFSET("transport", FR_TYPE_VOID, proto_detail_t, io_submodule),
	  .func = transport_parse },

	/*
	 *	Add this as a synonym so normal humans can understand it.
	 */
	{ FR_CONF_OFFSET("max_entry_size", FR_TYPE_UINT32, proto_detail_t, max_packet_size) } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_detail_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", FR_TYPE_UINT32, proto_detail_t, num_messages) } ,

	{ FR_CONF_OFFSET("priority", FR_TYPE_UINT32, proto_detail_t, priority) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t proto_detail_dict[];
fr_dict_autoload_t proto_detail_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },

	{ NULL }
};

static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_original_timestamp;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_protocol;

extern fr_dict_attr_autoload_t proto_detail_dict_attr[];
fr_dict_attr_autoload_t proto_detail_dict_attr[] = {
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_original_timestamp, .name = "Packet-Original-Timestamp", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_protocol, .name = "Protocol", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ NULL }
};

/** Wrapper around fr_dict_t* which translates the dictionary name into a dictionary
 *
 * @param[in] ctx	to allocate data in (instance of proto_detail).
 * @param[out] out	Where to write a fr_dict_t *
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dictionary_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const		*dict_str = cf_pair_value(cf_item_to_pair(ci));
	fr_dict_t const		*dict;

	dict = fr_dict_by_protocol_name(dict_str);
	if (!dict) {
		cf_log_err(ci, "Unknown dictionary");
		return -1;
	}

	*(fr_dict_t **) out = fr_dict_unconst(dict);

	return 0;
}

/** Wrapper around dl_instance which translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_detail).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	dl_module_inst_t	*process_dl;
	proto_detail_process_t	*process_inst;
	fr_dict_attr_t const	*attr_packet_type;
	proto_detail_t		*inst = talloc_get_type_abort(parent, proto_detail_t);
	int			code;

	if (!inst->dict) {
		cf_log_err(ci, "Please define 'dictionary' BEFORE 'type'");
		return -1;
	}

	attr_packet_type = fr_dict_attr_by_name(NULL, fr_dict_root(inst->dict), "Packet-Type");
	if (!attr_packet_type) {
		cf_log_err(ci, "Failed to find 'Packet-Type' attribute");
		return -1;
	}

	code = fr_app_process_type_parse(ctx, out, ci, attr_packet_type, "proto_detail",
					 NULL, 0, NULL, 0);
	if (code < 0) return -1;

	inst->code = code;

	/*
	 *	Find the process module, and tell it what dictionary
	 *	and packet type to use.
	 */
	process_dl = *(dl_module_inst_t **) out;
	process_inst = inst->process_instance = talloc_get_type_abort(process_dl->data, proto_detail_process_t);

	process_inst->dict = inst->dict;
	process_inst->attr_packet_type = attr_packet_type;

	return 0;
}

/** Wrapper around dl_instance
 *
 * @param[in] ctx	to allocate data in (instance of proto_detail).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int transport_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			   CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	char const	*name = cf_pair_value(cf_item_to_pair(ci));
	dl_module_inst_t	*parent_inst;
	CONF_SECTION	*listen_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION	*transport_cs;

	transport_cs = cf_section_find(listen_cs, name, NULL);

	/*
	 *	Allocate an empty section if one doesn't exist
	 *	this is so defaults get parsed.
	 */
	if (!transport_cs) transport_cs = cf_section_alloc(listen_cs, listen_cs, name, NULL);

	parent_inst = cf_data_value(cf_data_find(listen_cs, dl_module_inst_t, "proto_detail"));
	fr_assert(parent_inst);

	return dl_module_instance(ctx, out, transport_cs, parent_inst, name, DL_MODULE_TYPE_SUBMODULE);
}

/** Decode the packet, and set the request->process function
 *
 */
static int mod_decode(void const *instance, request_t *request, uint8_t *const data, size_t data_len)
{
	proto_detail_t const	*inst = talloc_get_type_abort_const(instance, proto_detail_t);
	int			num, lineno;
	uint8_t const		*p, *end;
	fr_pair_t		*vp;
	fr_cursor_t		cursor;
	time_t			timestamp = 0;

	RHEXDUMP3(data, data_len, "proto_detail decode packet");

	request->packet->code = inst->code;

	/*
	 *	Set default addresses
	 */
	request->packet->socket.fd = -1;
	request->packet->socket.inet.src_ipaddr.af = AF_INET;
	request->packet->socket.inet.src_ipaddr.addr.v4.s_addr = htonl(INADDR_NONE);
	request->packet->socket.inet.dst_ipaddr = request->packet->socket.inet.src_ipaddr;

	request->reply->socket.inet.src_ipaddr = request->packet->socket.inet.src_ipaddr;
	request->reply->socket.inet.dst_ipaddr = request->packet->socket.inet.src_ipaddr;

	end = data + data_len;

	MPRINT("HEADER %s", data);

	if (sscanf((char const *) data, "%*s %*s %*d %*d:%*d:%*d %d", &num) != 1) {
		REDEBUG("Malformed header '%s'", (char const *) data);
		return -1;
	}

	/*
	 *	Skip the header
	 */
	for (p = data; p < end; p++) {
		if (!*p) break;
	}

	lineno = 1;
	fr_cursor_init(&cursor, &request->request_pairs);
	fr_cursor_tail(&cursor);	/* Ensure we only free what we add on error */

	/*
	 *	Parse each individual line.
	 */
	while (p < end) {
		/*
		 *	Each record begins with a zero byte.  If the
		 *	next byte is also zero, that's the end of
		 *	record indication.
		 */
		if ((end - p) < 2) break;
		if (!p[1]) break;

		/*
		 *	Already checked in the "read" routine.  But it
		 *	doesn't hurt to re-check it here.
		 */
		if ((*p != '\0') && (*p != '\t')) {
			REDEBUG("Malformed line %d", lineno);
		error:
			fr_cursor_free_list(&cursor);
			return -1;
		}

		p += 2;

		MPRINT("LINE   :%s", p);

		/*
		 *	Skip this for backwards compatability.
		 */
		if (strncasecmp((char const *) p, "Request-Authenticator", 21) == 0) goto next;

		/*
		 *	The original time at which we received the
		 *	packet.  We need this to properly calculate
		 *	Acct-Delay-Time.
		 */
		if (strncasecmp((char const *) p, "Timestamp = ", 12) == 0) {
			p += 12;

			timestamp = atoi((char const *) p);

			vp = fr_pair_afrom_da(request->packet, attr_packet_original_timestamp);
			if (vp) {
				vp->vp_date = ((fr_time_t) timestamp) * NSEC;
				vp->type = VT_DATA;
				fr_cursor_append(&cursor, vp);
			}
			goto next;
		}

		/*
		 *	This should also have been caught.
		 */
		if (strncasecmp((char const *) p, "Donestamp", 9) == 0) {
			goto next;
		}

		/*
		 *	The parsing function appends the created VPs
		 *	to the input list, so we need to set 'vp =
		 *	NULL'.  We don't want to have multiple cursor
		 *	functions walking over the list.
		 */
		vp = NULL;
		if ((fr_pair_list_afrom_str(request->packet, request->dict, (char const *) p, &vp) > 0) && vp) {
			fr_cursor_append(&cursor, vp);
		} else {
			RWDEBUG("Ignoring line %d - :%s", lineno, p);
		}

		/*
		 *	Set the original src/dst ip/port
		 */
		if (vp) {
			if ((vp->da == attr_packet_src_ip_address) ||
			    (vp->da == attr_packet_src_ipv6_address)) {
				request->packet->socket.inet.src_ipaddr = vp->vp_ip;
			} else if ((vp->da == attr_packet_dst_ip_address) ||
				   (vp->da == attr_packet_dst_ipv6_address)) {
				request->packet->socket.inet.dst_ipaddr = vp->vp_ip;
			} else if (vp->da == attr_packet_src_port) {
				request->packet->socket.inet.src_port = vp->vp_uint16;
			} else if (vp->da == attr_packet_dst_port) {
				request->packet->socket.inet.dst_port = vp->vp_uint16;
			} else if (vp->da == attr_protocol) {
				request->dict = fr_dict_by_protocol_num(vp->vp_uint32);
				if (!request->dict) {
					REDEBUG("Invalid protocol: %pP", vp);
					goto error;
				}
			}
		}

	next:
		lineno++;
		while ((p < end) && (*p)) p++;
	}

	/*
	 *	Let the app_io take care of populating additional fields in the request
	 */
	return inst->app_io->decode(inst->app_io_instance, request, data, data_len);
}

static ssize_t mod_encode(UNUSED void const *instance, request_t *request, uint8_t *buffer, size_t buffer_len)
{
	if (buffer_len < 1) return -1;

	*buffer = request->reply->code;
	return 1;
}

static void mod_entry_point_set(void const *instance, request_t *request)
{
	proto_detail_t const *inst = talloc_get_type_abort_const(instance, proto_detail_t);
	fr_app_worker_t const *app_process;

	/*
	 *	Only one "process" function: proto_detail_process.
	 */
	app_process = (fr_app_worker_t const *)inst->type_submodule->module->common;

	request->server_cs = inst->server_cs;
	request->async->process = app_process->entry_point;
	request->async->process_inst = inst->process_instance;
}

/** Open listen sockets/connect to external event source
 *
 * @param[in] instance	Ctx data for this application.
 * @param[in] sc	to add our file descriptor to.
 * @param[in] conf	Listen section parsed to give us isntance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_open(void *instance, fr_schedule_t *sc, CONF_SECTION *conf)
{
	fr_listen_t	*li;
	proto_detail_t 	*inst = talloc_get_type_abort(instance, proto_detail_t);

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	li = talloc_zero(inst, fr_listen_t);
	talloc_set_destructor(li, fr_io_listen_free);

	li->app_io = inst->app_io;
	li->thread_instance = talloc_zero_array(NULL, uint8_t, li->app_io->thread_inst_size);
	talloc_set_name(li->thread_instance, "proto_%s_thread_t", inst->app_io->name);
	li->app_io_instance = inst->app_io_instance;

	li->app = &proto_detail;
	li->app_instance = instance;
	li->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	li->default_message_size = inst->max_packet_size;
	li->num_messages = inst->num_messages;

	/*
	 *	Open the file.
	 */
	if (inst->app_io->open(li) < 0) {
		cf_log_err(conf, "Failed opening %s interface", inst->app_io->name);
		talloc_free(li);
		return -1;
	}

	fr_assert(li->app_io->get_name);
	li->name = li->app_io->get_name(li);

	/*
	 *	Testing: allow it to read a "detail.work" file
	 *	directly.
	 */
	if (strcmp(inst->io_submodule->module->dl->name, "proto_detail_work") == 0) {
		if (!fr_schedule_listen_add(sc, li)) {
			talloc_free(li);
			return -1;
		}

		inst->listen = li;
		return 0;
	}

	/*
	 *	Watch the directory for changes.
	 */
	if (!fr_schedule_directory_add(sc, li)) {
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
 * @param[in] conf	Listen section parsed to give us isntance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	proto_detail_t		*inst = talloc_get_type_abort(instance, proto_detail_t);
	CONF_PAIR		*cp = NULL;

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

	/*
	 *	Instantiate the process module.
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type")) != NULL) {
		fr_app_worker_t const *app_process;

#ifdef __clang_analyzer__
		DEBUG("Instantiating %s", cf_pair_value(cp));
#endif

		app_process = (fr_app_worker_t const *)inst->type_submodule->module->common;
		if (app_process->instantiate && (app_process->instantiate(inst->type_submodule->data,
									  inst->type_submodule->conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}

		break;
	}

	/*
	 *	These configuration items are not printed by default,
	 *	because normal people shouldn't be touching them.
	 */
	if (!inst->max_packet_size) inst->max_packet_size = inst->app_io->default_message_size;

	if (!inst->num_messages) inst->num_messages = 2;

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 2);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 1024);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	if (!inst->priority) inst->priority = PRIORITY_NORMAL;

	/*
	 *	If the IO is "file" and not the worker, instantiate the worker now.
	 */
	if (strcmp(inst->io_submodule->module->dl->name, "proto_detail_work") != 0) {
		if (inst->work_io->instantiate && (inst->work_io->instantiate(inst->work_io_instance,
									      inst->work_io_conf) < 0)) {
			cf_log_err(inst->work_io_conf, "Instantiation failed for \"%s\"", inst->work_io->name);
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
	proto_detail_t 		*inst = talloc_get_type_abort(instance, proto_detail_t);
	CONF_PAIR		*cp = NULL;

	/*
	 *	The listener is inside of a virtual server.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));
	inst->cs = conf;
	inst->self = &proto_detail;

	virtual_server_dict_set(inst->server_cs, inst->dict, false);

	/*
	 *	Bootstrap the process module.
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		dl_module_t const	*module = talloc_get_type_abort_const(inst->type_submodule->module,
									      dl_module_t);
		fr_app_worker_t const	*app_process = (fr_app_worker_t const *)(module->common);

		if (app_process->bootstrap && (app_process->bootstrap(inst->type_submodule->data,
								      inst->type_submodule->conf) < 0)) {
			cf_log_err(conf, "Bootstrap failed for \"%s\"", app_process->name);
			return -1;
		}
	}

	/*
	 *	No IO module, it's an empty listener.  That's not
	 *	allowed for the detail file reader.
	 */
	if (!inst->io_submodule) {
		cf_log_err(conf, "Virtual server for detail files requires a 'transport' configuration");
		return -1;
	}

	/*
	 *	Bootstrap the I/O module
	 */
	inst->app_io = (fr_app_io_t const *) inst->io_submodule->module->common;
	inst->app_io_instance = inst->io_submodule->data;
	inst->app_io_conf = inst->io_submodule->conf;

	if (inst->app_io->bootstrap && (inst->app_io->bootstrap(inst->app_io_instance,
								inst->app_io_conf) < 0)) {
		cf_log_err(inst->app_io_conf, "Bootstrap failed for \"%s\"", inst->app_io->name);
		return -1;
	}

	/*
	 *	If we're not loading the work submodule directly, then try to load it here.
	 */
	if (strcmp(inst->io_submodule->module->dl->name, "proto_detail_work") != 0) {
		CONF_SECTION *transport_cs;
		dl_module_inst_t *parent_inst;

		inst->work_submodule = NULL;

		transport_cs = cf_section_find(inst->cs, "work", NULL);
		parent_inst = cf_data_value(cf_data_find(inst->cs, dl_module_inst_t, "proto_detail"));
		fr_assert(parent_inst);

		if (!transport_cs) {
			transport_cs = cf_section_dup(inst->cs, inst->cs, inst->app_io_conf,
						      "work", NULL, false);
			if (!transport_cs) {
				cf_log_err(inst->cs, "Failed to create configuration for worker");
				return -1;
			}
		}

		if (dl_module_instance(inst->cs, &inst->work_submodule, transport_cs,
				parent_inst, "work", DL_MODULE_TYPE_SUBMODULE) < 0) {
			cf_log_perr(inst->cs, "Failed to load proto_detail_work");
			return -1;
		}

		/*
		 *	Boot strap the work module.
		 */
		inst->work_io = (fr_app_io_t const *) inst->work_submodule->module->common;
		inst->work_io_instance = inst->work_submodule->data;
		inst->work_io_conf = inst->work_submodule->conf;

		if (inst->work_io->bootstrap && (inst->work_io->bootstrap(inst->work_io_instance,
									  inst->work_io_conf) < 0)) {
			cf_log_err(inst->work_io_conf, "Bootstrap failed for \"%s\"", inst->work_io->name);
			return -1;
		}
	}

	return 0;
}


fr_app_t proto_detail = {
	.magic			= RLM_MODULE_INIT,
	.name			= "detail",
	.config			= proto_detail_config,
	.inst_size		= sizeof(proto_detail_t),

	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.entry_point_set	= mod_entry_point_set
};
