/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more crons.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file proto_cron.c
 * @brief CRON master protocol handler.
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>
#include "proto_cron.h"

extern fr_app_t proto_cron;
static int type_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int time_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

static conf_parser_t const limit_config[] = {
	/*
	 *	For performance tweaking.  NOT for normal humans.
	 */
	{ FR_CONF_OFFSET("max_packet_size", proto_cron_t, max_packet_size) } ,
	{ FR_CONF_OFFSET("num_messages", proto_cron_t, num_messages) } ,

	CONF_PARSER_TERMINATOR
};

/** How to parse a CRON listen section
 *
 */
static conf_parser_t const proto_cron_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("type", FR_TYPE_VOID, CONF_FLAG_NOT_EMPTY | CONF_FLAG_REQUIRED, proto_cron_t,
			  type), .func = type_parse },

	{ FR_CONF_OFFSET_FLAGS("when", CONF_FLAG_NOT_EMPTY | CONF_FLAG_REQUIRED, proto_cron_t, spec),
	  		.func = time_parse },

	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_READABLE | CONF_FLAG_REQUIRED | CONF_FLAG_NOT_EMPTY, proto_cron_t, filename ) },

	{ FR_CONF_OFFSET("priority", proto_cron_t, priority) },

	{ FR_CONF_POINTER("limit", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) limit_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_cron;

extern fr_dict_autoload_t proto_cron_dict[];
fr_dict_autoload_t proto_cron_dict[] = {
	{ .out = &dict_cron, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

/** Translates the packet-type into a submodule name
 *
 * @param[in] ctx	to allocate data in (instance of proto_cron).
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
	proto_cron_t		*inst = talloc_get_type_abort(parent, proto_cron_t);
	fr_dict_enum_t const	*type_enum;
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	char const		*value = cf_pair_value(cp);

	*((char const **) out) = value;

	inst->dict = virtual_server_namespace_by_ci(ci);
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

/*
 *	Parse a basic field with sanity checks.
 *
 *	Note that we don't (yet) convert this into an internal data
 *	structure.  Instead, we're just checking if the basic format
 *	is OK.
 */
static int parse_field(CONF_ITEM *ci, char const **start, char const *name, unsigned int min, unsigned int max)
{
	char const *p;
	char *end = NULL;
	unsigned int num, last = 0;
	bool last_is_set = false;
	bool wildcard = false;

	p = *start;
	fr_skip_whitespace(p);

	if (!*p) {
		cf_log_err(ci, "Missing field for %s", name);
		return -1;
	}

	/*
	 *	See 'man 5 crontab' for the format.
	 */
	while (p) {
		/*
		 *	Allow wildcards, but only once.
		 */
		if (*p == '*') {
			if (wildcard) {
				cf_log_err(ci, "Cannot use two wildcards for %s at %s", name, p);
				return -1;
			}

			end = UNCONST(char *, p) + 1;
			wildcard = true;
			goto check_step;
		}

		/*
		 *	If there's already a "*", we can't have another one.
		 */
		if (wildcard) {
			cf_log_err(ci, "Cannot use wildcard and numbers for %s at %s", name, p);
			return -1;
		}

		/*
		 *	If it's not a wildcard, it MUST be a number,
		 *	which is between min and max.
		 */
		num = strtoul(p, &end, 10);
		if ((num < min) || (num > max)) {
			cf_log_err(ci, "Number is invalid or out of bounds (%d..%d) for %s at %s",
				   min, max, name, p);
			return -1;
		}

		/*
		 *	Don't allow the same number to be specified
		 *	multiple times.
		 */
		if (!last_is_set) {
			last_is_set = true;

		} else if (num <= last) {
				cf_log_err(ci, "Number overlaps with previous value of %u, for %s at %s",
					   last, name, p);
				return -1;
		}
		last = num;

		/*
		 *	Ranges are allowed, with potential steps
		 */
		if (*end == '-') {
			unsigned int next;

			p = end + 1;
			next = strtoul(p, &end, 10);
			if (next <= num) {
				cf_log_err(ci, "End of range number overlaps with previous value of %u, for %s at %s",
					   num, name, p);
				return -1;
			}

			if (next > max) {
				cf_log_err(ci, "End of range number is invalid or out of bounds (%d..%d) for %s at %s",
					   min, max, name, p);
				return -1;
			}

			last = next;

		check_step:
			/*
			 *	Allow /N
			 */
			if (*end == '/') {
				p = end + 1;

				num = strtoul(p, &end, 10);
				if (num > 65535) {
					cf_log_err(ci, "Failed parsing step value for %s at %s", name, p);
					return -1;
				}
			}
		} /* end of range specifier */

		/*
		 *	We can specify multiple fields, separated by a comma.
		 */
		if (*end == ',') {
			p = end + 1;
			continue;
		}

		/*
		 *	EOS or space is end of field.
		 */
		if (!(!*end || isspace((uint8_t) *end))) {
			cf_log_err(ci, "Unexpected text for %s at %s", name, end);
			return -1;
		}
	}

	*start = end;
	return 0;
}

/*
 *	Special names, including our own extensions.
 */
static fr_table_ptr_sorted_t time_names[] = {
	{ L("annually"),	"0 0 1 1 *" },
	{ L("daily"),		"0 0 * * *" },
	{ L("hourly"),		"0 * * * *" },
	{ L("midnight"),	"0 0 * * *" },
	{ L("monthly"),		"0 0 1 * *" },
	{ L("reboot"),		"+" },
	{ L("shutdown"),	"-" },
	{ L("startup"),		"+" },
	{ L("weekly"),		"0 0 * * 0" },
	{ L("yearly"),		"0 0 1 1 *" },
};
static size_t time_names_len = NUM_ELEMENTS(time_names);

/** Checks the syntax of a cron job
 *
 * @param[in] ctx	to allocate data in (instance of proto_cron).
 * @param[out] out	Where to write a module_instance_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 *
 *	https://github.com/staticlibs/ccronexpr/blob/master/ccronexpr.c
 */
static int time_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
//	proto_cron_t		*inst = talloc_get_type_abort(parent, proto_cron_t);
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	char const		*value = cf_pair_value(cp);
	char const		*p;

	p = value;

	/*
	 *	Check for special names.
	 */
	if (*p == '@') {
		p = fr_table_value_by_str(time_names, p + 1, NULL);
		if (!p) {
			cf_log_err(ci, "Invalid time name '%s'", value);
			return -1;
		}

		/*
		 *	Over-write the special names with standard
		 *	ones, so that the rest of the parser is simpler.
		 */
		*((char const **) out) = p;
		return 0;
	}

	*((char const **) out) = value;

	if (parse_field(ci, &p, "minute", 0, 59) < 0) return -1;
	if (parse_field(ci, &p, "hour", 0, 59) < 0) return -1;
	if (parse_field(ci, &p, "day of month", 1, 31) < 0) return -1;
	if (parse_field(ci, &p, "month", 1,12) < 0) return -1;
	if (parse_field(ci, &p, "day of week", 0, 6) < 0) return -1;

	fr_skip_whitespace(p);

	if (*p) {
		cf_log_err(ci, "Unexpected text after cron time specification");
		return -1;
	}

	return 0;
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
	proto_cron_t 	*inst = talloc_get_type_abort(instance, proto_cron_t);
	fr_listen_t	*li;

	/*
	 *	Build the #fr_listen_t.  This describes the complete
	 *	path, data takes from the socket to the decoder and
	 *	back again.
	 */
	li = talloc_zero(inst, fr_listen_t);
	talloc_set_destructor(li, fr_io_listen_free);

	/*
	 *	Set to the cron_app_io, which gets the network && event list.
	 */
//	li->app_io = inst->app_io;
	li->thread_instance = talloc_zero_array(NULL, uint8_t, sizeof(proto_cron_thread_t));
	talloc_set_type(li->thread_instance, proto_cron_thread_t);
	li->app_io_instance = NULL;

	li->app = &proto_cron;
	li->app_instance = instance;
	li->server_cs = inst->server_cs;

	/*
	 *	Set configurable parameters for message ring buffer.
	 */
	li->default_message_size = inst->max_packet_size;
	li->num_messages = inst->num_messages;

	li->name = "cron";
	li->fd = -1;		/* not a real FD! */

	/*
	 *	Watch the directory for changes.
	 */
	if (!fr_schedule_listen_add(sc, li)) {
		talloc_free(li);
		return -1;
	}

	DEBUG(951, 951, "Listening on %s bound to virtual server %s",
	      li->name, cf_section_name2(li->server_cs));

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
	proto_cron_t		*inst = talloc_get_type_abort(instance, proto_cron_t);
	FILE			*fp;
	bool			done;

	/*
	 *	The listener is inside of a virtual server.
	 */
	inst->server_cs = cf_item_to_section(cf_parent(conf));
	inst->cs = conf;
	inst->self = &proto_cron;

	virtual_server_dict_set(inst->server_cs, inst->dict, false);

	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, >=, 32);
	FR_INTEGER_BOUND_CHECK("num_messages", inst->num_messages, <=, 65535);

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 1024);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	if (!inst->priority) inst->priority = PRIORITY_NORMAL;

	fp = fopen(inst->filename, "r");
	if (!fp) {
		cf_log_err(conf, "Failed opening %s - %s", inst->filename, fr_syserror(errno));
		return -1;
	}

	if (fr_pair_list_afrom_file(inst, inst->dict, &inst->vps, fp, &done, true) < 0) {
		fclose(fp);
		cf_log_err(conf, "Failed reading %s - %s", inst->filename, fr_strerror());
		return -1;
	}
	fclose(fp);

	if (!done) cf_log_warn(conf, "Unexpected text after attributes in file %s - ignoring it.", inst->filename);

	return 0;
}

fr_app_t proto_cron = {
	.magic			= RLM_MODULE_INIT,
	.name			= "cron",
	.config			= proto_cron_config,
	.inst_size		= sizeof(proto_cron_t),

	.instantiate		= mod_instantiate,
	.open			= mod_open,
};
