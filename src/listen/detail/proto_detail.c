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
#include <freeradius-devel/util/pair_legacy.h>

#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/module_rlm.h>

#include "proto_detail.h"

extern fr_app_t proto_detail;

static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

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
static conf_parser_t const proto_detail_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("type", FR_TYPE_VOID, CONF_FLAG_NOT_EMPTY | CONF_FLAG_REQUIRED, proto_detail_t,
			  type), .func = type_parse },
	{ FR_CONF_OFFSET_TYPE_FLAGS("transport", FR_TYPE_VOID, 0, proto_detail_t, io_submodule),
	  .func = transport_parse, .dflt = "file" },

	/*
	 *	Add this as a synonym so normal humans can understand it.
	 */
	{ FR_CONF_OFFSET("max_entry_size", proto_detail_t, max_packet_size) } ,

	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", proto_detail_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", proto_detail_t, num_messages) } ,

	{ FR_CONF_OFFSET("exit_when_done", proto_detail_t, exit_when_done) },

	{ FR_CONF_OFFSET("priority", proto_detail_t, priority) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t proto_detail_dict[];
fr_dict_autoload_t proto_detail_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },

	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_original_timestamp;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_port;

extern fr_dict_attr_autoload_t proto_detail_dict_attr[];
fr_dict_attr_autoload_t proto_detail_dict_attr[] = {
	{ .out = &attr_packet_dst_ip_address, .name = "Net.Dst.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Net.Dst.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_original_timestamp, .name = "Packet-Original-Timestamp", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Net.Src.IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Net.Src.Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

/** Translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_detail).
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
	proto_detail_t		*inst = talloc_get_type_abort(parent, proto_detail_t);
	fr_dict_enum_value_t const	*type_enum;
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	char const		*value = cf_pair_value(cp);

	*((char const **) out) = value;

	inst->dict = virtual_server_dict_by_child_ci(ci);
	if (!inst->dict) {
		cf_log_err(ci, "Please define 'namespace' in this virtual server");
		return -1;
	}

	inst->attr_packet_type = fr_dict_attr_by_name(NULL, fr_dict_root(inst->dict), "Packet-Type");
	if (!inst->attr_packet_type) {
		cf_log_err(ci, "Failed to find 'Packet-Type' attribute");
		return -1;
	}

	if (!value) {
		cf_log_err(ci, "No value given for 'type'");
		return -1;
	}

	type_enum = fr_dict_enum_by_name(inst->attr_packet_type, value, -1);
	if (!type_enum) {
		cf_log_err(ci, "Invalid type \"%s\"", value);
		return -1;
	}

	inst->code = type_enum->value->vb_uint32;
	return 0;
}

static int transport_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	proto_detail_t *inst = talloc_get_type_abort(parent, proto_detail_t);

	if (unlikely(virtual_server_listen_transport_parse(ctx, out, parent, ci, rule) < 0)) {
		return -1;
	}

	/*
	 *	If we're not loading the work submodule directly, then try to load it here.
	 */
	if (strcmp(inst->io_submodule->module->dl->name, "proto_detail_work") != 0) {
		CONF_SECTION		*transport_cs;
		module_instance_t	*mi;
		char const		*inst_name;

		inst->work_submodule = NULL;

		mi = virtual_server_listener_by_data(parent);
		fr_assert(mi);

		transport_cs = cf_section_find(mi->conf, "work", NULL);
		if (!transport_cs) {
			transport_cs = cf_section_dup(mi->conf, mi->conf, inst->app_io_conf,
						      "work", NULL, false);
			if (!transport_cs) {
				cf_log_err(mi->conf, "Failed to create configuration for worker");
				return -1;
			}
		}

		if (module_instance_name_from_conf(&inst_name, transport_cs) < 0) return -1;

		/*
		 *	This *should* get bootstrapped at some point after this module
		 *	as it's inserted into the three the caller is iterating over.
		 *
		 *	We might want to revisit this, and use a linked list of modules
		 *	to iterate over instead of a tree, so we can add this to the end
		 *	of that list.
		 */
		inst->work_submodule = module_instance_alloc(mi->ml, mi, DL_MODULE_TYPE_SUBMODULE,
							     "work", inst_name, 0);
		if (inst->work_submodule == NULL) {
		error:
			cf_log_perr(mi->conf, "Failed to load proto_detail_work");
			TALLOC_FREE(inst->work_submodule);
			return -1;
		}

		if (module_instance_conf_parse(inst->work_submodule, transport_cs) < 0) goto error;

		inst->work_io = (fr_app_io_t const *) inst->work_submodule->exported;
		inst->work_io_instance = inst->work_submodule->data;
		inst->work_io_conf = inst->work_submodule->conf;
	}

	return 0;
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
	fr_pair_list_t		tmp_list;
	fr_dcursor_t		cursor;
	time_t			timestamp = 0;
	fr_pair_parse_t		root, relative;

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
	fr_pair_dcursor_init(&cursor, &request->request_pairs);
	fr_dcursor_tail(&cursor);	/* Ensure we only free what we add on error */
	fr_pair_list_init(&tmp_list);

	/*
	 *	Parse each individual line.
	 */
	while (p < end) {
		fr_slen_t slen;

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
			fr_dcursor_free_list(&cursor);
			return -1;
		}

		p += 2;

		MPRINT("LINE   :%s", p);

		/*
		 *	Skip this for backwards compatibility.
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

			vp = fr_pair_afrom_da(request->request_ctx, attr_packet_original_timestamp);
			if (vp) {
				vp->vp_date = fr_unix_time_from_sec(timestamp);
				fr_dcursor_append(&cursor, vp);
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
		 *	Reinitialize every time.
		 *
		 *	@todo - maybe we want to keep "relative' around between lines?
		 *	So that the detail file reader can read:
		 *
		 *		foo = {}
		 *		.bar = baz
		 *
		 *	and get
		 *
		 *		foo = { bar = baz }
		 *
		 *	But doing that would require updating the
		 *	detail file writer to track parent / child
		 *	relationships, which we're not yet prepared to
		 *	do.
		 *
		 *	@todo - this also doesn't create nested attributes properly,
		 *	as the write will write:
		 *
		 *		foo.bar = baz
		 *
		 *	and then the final pair "foo" is _appended_ to the input list, without paying
		 *	any attention to what's going on!
		 *
		 *	We likely just want to pass in request_pairs the parse function, AND also don't
		 *	mash "relative" between calls.
		 */
		root = (fr_pair_parse_t) {
			.ctx = request->request_ctx,
			.da = fr_dict_root(request->proto_dict),
			.list = &tmp_list,
			.dict = request->proto_dict,
			.internal = fr_dict_internal(),
			.allow_zeros = true,
		};
		relative = (fr_pair_parse_t) { };

		slen = fr_pair_list_afrom_substr(&root, &relative,
						 &FR_SBUFF_IN((char const *) p, (data + data_len) - p));
		if (slen < 0) {
			RPEDEBUG("Failed reading line");
			vp = NULL;

		} else if ((slen == 0) || fr_pair_list_empty(&tmp_list)) {
			vp = NULL;
			RWDEBUG("Ignoring line %d - %s", lineno, p);

		} else {
			vp = fr_pair_list_head(&tmp_list);
		}

		/*
		 *	Set the original src/dst ip/port
		 */
		if (vp) {
			if (vp->da == attr_packet_src_ip_address) {
				request->packet->socket.inet.src_ipaddr = vp->vp_ip;
			} else if (vp->da == attr_packet_dst_ip_address) {
				request->packet->socket.inet.dst_ipaddr = vp->vp_ip;
			} else if (vp->da == attr_packet_src_port) {
				request->packet->socket.inet.src_port = vp->vp_uint16;
			} else if (vp->da == attr_packet_dst_port) {
				request->packet->socket.inet.dst_port = vp->vp_uint16;
			}
		}

	next:
		lineno++;
		while ((p < end) && (*p)) p++;
	}

	fr_pair_list_append(&request->request_pairs, &tmp_list);

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

static int mod_priority_set(void const *instance, UNUSED uint8_t const *buffer, UNUSED size_t buflen)
{
	proto_detail_t const *inst = talloc_get_type_abort_const(instance, proto_detail_t);

	/*
	 *	Return the configured priority.
	 */
	return inst->priority;
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
	proto_detail_t 	*inst = talloc_get_type_abort(instance, proto_detail_t);

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	MEM(li = talloc_zero(inst, fr_listen_t));	/* Assigned thread steals the memory */
	talloc_set_destructor(li, fr_io_listen_free);

	li->cs = conf;
	li->app_io = inst->app_io;
	li->thread_instance = talloc_zero_array(li, uint8_t, li->app_io->common.thread_inst_size);
	talloc_set_name(li->thread_instance, "proto_%s_thread_t", inst->app_io->common.name);
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
		cf_log_err(conf, "Failed opening %s file", inst->app_io->common.name);
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

	if (li->non_socket_listener) {
		/*
		 *	Add listener.  Will insert polling timer.
		 */
		if (!fr_schedule_listen_add(sc, li)) {
			talloc_free(li);
			return -1;
		}
	} else {
		/*
		 *	Watch the directory for changes.
		 */
		if (!fr_schedule_directory_add(sc, li)) {
			talloc_free(li);
			return -1;
		}
	}

	DEBUG("Listening on %s bound to virtual server %s",
	      li->name, cf_section_name2(li->server_cs));

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
	proto_detail_t		*inst = talloc_get_type_abort(mctx->mi->data, proto_detail_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	/*
	 *	The listener is inside of a virtual server.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));
	inst->self = &proto_detail;

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
	inst->app_io = (fr_app_io_t const *) inst->io_submodule->exported;
	inst->app_io_instance = inst->io_submodule->data;
	inst->app_io_conf = inst->io_submodule->conf;

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

	return 0;
}

fr_app_t proto_detail = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "detail",
		.config			= proto_detail_config,
		.inst_size		= sizeof(proto_detail_t),

		.instantiate		= mod_instantiate,
	},
	.open			= mod_open,
	.decode			= mod_decode,
	.encode			= mod_encode,
	.priority		= mod_priority_set
};
