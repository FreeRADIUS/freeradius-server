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
 * @file proto_cron_crontab.c
 * @brief Generate crontab events.
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
#include <netdb.h>
#include <fcntl.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>

#include "proto_cron.h"

extern fr_app_io_t proto_cron_crontab;

typedef struct proto_cron_tab_s proto_cron_crontab_t;

typedef struct {
	fr_event_list_t			*el;			//!< event list
	fr_network_t			*nr;			//!< network handler

	char const			*name;			//!< socket name

	proto_cron_crontab_t const      *inst;

	fr_event_timer_t const		*ev;			//!< for writing statistics

	fr_listen_t			*parent;		//!< master IO handler

	fr_time_t			recv_time;		//!< when the timer hit.

	bool				suspended;		//!< we suspend reading from the FD.
	bool				bootstrap;		//!< get it started
} proto_cron_crontab_thread_t;

typedef struct {
	unsigned int	min;
	unsigned int	max;

	bool		wildcard;
	size_t		offset;

	uint64_t	fields;
} cron_tab_t;

struct proto_cron_tab_s {
	proto_cron_t			*parent;

	CONF_SECTION			*cs;			//!< our configuration

	char const     			*filename;		//!< where to read input packet from
	fr_pair_list_t			pair_list;		//!< for input packet

	int				code;
	char const			*spec;			//!< crontab spec

	cron_tab_t			tab[5];

	RADCLIENT			*client;		//!< static client
};


static int time_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static const CONF_PARSER crontab_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, proto_cron_crontab_t, filename) },

	{ FR_CONF_OFFSET("timespec", FR_TYPE_STRING | FR_TYPE_NOT_EMPTY | FR_TYPE_REQUIRED, proto_cron_crontab_t, spec),
	  		.func = time_parse },

	CONF_PARSER_TERMINATOR
};

/*
 *	Parse a basic field with sanity checks.
 */
static int parse_field(CONF_ITEM *ci, char const **start, char const *name,
		       cron_tab_t *tab, unsigned int min, unsigned int max, size_t offset)
{
	char const *p;
	char *end = NULL;
	unsigned int num, next, step, last = 0;
	bool last_is_set = false;
	bool wildcard = false;
	unsigned int i;
	uint64_t fields = 0;

	p = *start;
	fr_skip_whitespace(p);

	if (!*p) {
		cf_log_err(ci, "Missing field for %s", name);
		return -1;
	}

	tab->min = min;
	tab->max = max;
	tab->offset = offset;
	tab->fields = 0;

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
			num = min;
			next = max;
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

		check_step:
			last = next;

			/*
			 *	Allow /N
			 */
			if (*end == '/') {
				p = end + 1;

				step = strtoul(p, &end, 10);
				if (step >= max) {
					cf_log_err(ci, "Step value is invalid or out of bounds for %s at %s", name, p);
					return -1;
				}
			} else {
				step = 1;
			}

			/*
			 *	Set the necessary bits.
			 */
			for (i = num; i <= next; i += step) {
				fields |= ((uint64_t) 1) << i;
			}
		} /* end of range specifier */

		/*
		 *	We can specify multiple fields, separated by a comma.
		 */
		if (*end == ',') {
			fields |= ((uint64_t) 1) << num;
			p = end + 1;
			continue;
		}

		/*
		 *	EOS or space is end of field.
		 */
		if (!(!*end || isspace((int) *end))) {
			cf_log_err(ci, "Unexpected text for %s at %s", name, end);
			return -1;
		}

		/*
		 *	We're at the end of the field, stop.
		 */
		break;
	}

	/*
	 *	Set a wildcard, so we can skip a lot of the later
	 *	logic.
	 */
	tab->wildcard = true;
	for (i = min; i <= max; i++) {
		if ((fields & (((uint64_t) 1) << i)) == 0) {
			tab->wildcard = false;
			break;
		}
	}

	tab->fields = fields;
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
//	{ L("reboot"),		"+" },
	{ L("weekly"),		"0 0 * * 0" },
	{ L("yearly"),		"0 0 1 1 *" },
};
static size_t time_names_len = NUM_ELEMENTS(time_names);

/** Wrapper around dl_instance which checks the syntax of a cron job
 *
 * @param[in] ctx	to allocate data in (instance of proto_cron).
 * @param[out] out	Where to write a dl_module_inst_t containing the module handle and instance.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int time_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	proto_cron_crontab_t       	*inst = talloc_get_type_abort(parent, proto_cron_crontab_t);
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

	if (parse_field(ci, &p, "minute", 	&inst->tab[0], 0, 59, offsetof(struct tm, tm_min)) < 0) return -1;
	if (parse_field(ci, &p, "hour",		&inst->tab[1], 0, 59, offsetof(struct tm, tm_hour)) < 0) return -1;
	if (parse_field(ci, &p, "day of month", &inst->tab[2], 1, 31, offsetof(struct tm, tm_mday)) < 0) return -1;
	if (parse_field(ci, &p, "month",	&inst->tab[3], 1,12, offsetof(struct tm, tm_mon)) < 0) return -1;
	if (parse_field(ci, &p, "day of week",	&inst->tab[4], 0, 6, offsetof(struct tm, tm_wday)) < 0) return -1;

	fr_skip_whitespace(p);

	if (*p) {
		cf_log_err(ci, "Unexpected text after cron time specification");
		return -1;
	}

	return 0;
}

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup)
{
	proto_cron_crontab_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_cron_crontab_t);
	proto_cron_crontab_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_cron_crontab_thread_t);
	fr_io_address_t			*address, **address_p;

	*leftover = 0;

	/*
	 *	Suspend all activity on the FD, because we let the
	 *	timers do their work.
	 */
	if (!thread->suspended) {
		static fr_event_update_t const pause_read[] = {
			FR_EVENT_SUSPEND(fr_event_io_func_t, read),
			{ 0 }
		};

		if (fr_event_filter_update(thread->el, li->fd, FR_EVENT_FILTER_IO, pause_read) < 0) {
			fr_assert(0);
		}

		/*
		 *	Don't read from it the first time.
		 */
		thread->suspended = true;
		return 0;
	}

	/*
	 *	Where the addresses should go.  This is a special case
	 *	for proto_radius.
	 */
	address_p = (fr_io_address_t **) packet_ctx;
	address = *address_p;

	memset(address, 0, sizeof(*address));
	address->socket.inet.src_ipaddr.af = AF_INET;
	address->socket.inet.dst_ipaddr.af = AF_INET;
	address->radclient = inst->client;

	*recv_time_p = thread->recv_time;

	if (buffer_len < 1) {
		DEBUG2("proto_cron_tab read buffer is too small for input packet");
		return 0;
	}

	buffer[0] = 0;

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_cron_crontab - reading packet for %s",
	       thread->name);

	return 1;
}


static ssize_t mod_write(UNUSED fr_listen_t *li, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 UNUSED uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	return buffer_len;
}


/** Open a crontab listener
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_cron_crontab_t const	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_cron_crontab_t);
	proto_cron_crontab_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_cron_crontab_thread_t);

	fr_ipaddr_t			ipaddr;

	/*
	 *	We never read or write to this file, but we need a
	 *	readable FD in order to bootstrap the process.
	 */
	if (inst->filename == NULL) return -1;
	li->fd = open(inst->filename, O_RDONLY);

	memset(&ipaddr, 0, sizeof(ipaddr));
	ipaddr.af = AF_INET;
	li->app_io_addr = fr_socket_addr_alloc_inet_src(li, IPPROTO_UDP, 0, &ipaddr, 0);

	fr_assert((cf_parent(inst->cs) != NULL) && (cf_parent(cf_parent(inst->cs)) != NULL));	/* listen { ... } */

	thread->name = talloc_typed_asprintf(thread, "cron_crontab from filename %s", inst->filename);
	thread->parent = talloc_parent(li);

	return 0;
}


/** Decode the packet
 *
 */
static int mod_decode(void const *instance, request_t *request, UNUSED uint8_t *const data, UNUSED size_t data_len)
{
	proto_cron_crontab_t const	*inst = talloc_get_type_abort_const(instance, proto_cron_crontab_t);
	fr_io_track_t const	*track = talloc_get_type_abort_const(request->async->packet_ctx, fr_io_track_t);
	fr_io_address_t const  	*address = track->address;

	/*
	 *	Set the request dictionary so that we can do
	 *	generic->protocol attribute conversions as
	 *	the request runs through the server.
	 */
	request->dict = inst->parent->dict;

	/*
	 *	Hacks for now until we have a lower-level decode routine.
	 */
	if (inst->code) request->packet->code = inst->code;
	request->packet->id = fr_rand() & 0xff;
	request->reply->id = request->packet->id;
	memset(request->packet->vector, 0, sizeof(request->packet->vector));

	request->packet->data = talloc_zero_array(request->packet, uint8_t, 1);
	request->packet->data_len = 1;

	/*
	 *	Note that we don't set a limit on max_attributes here.
	 *	That MUST be set and checked in the underlying
	 *	transport, via a call to fr_radius_ok().
	 */
	(void) fr_pair_list_copy(request->request_ctx, &request->request_pairs, &inst->pair_list);

	/*
	 *	Set the rest of the fields.
	 */
	request->client = UNCONST(RADCLIENT *, address->radclient);

	request->packet->socket = address->socket;
	fr_socket_addr_swap(&request->reply->socket, &address->socket);

	REQUEST_VERIFY(request);

	return 0;
}

/*
 *	Get the next time interval.
 *
 *	Set the relevant "struct tm" field to its next value, and
 *	return "true"
 *
 *	Set the relevant "struct tm" field to its minimum value, and
 *	return "false".
 */
static bool get_next(struct tm *tm, cron_tab_t const *tab)
{
	unsigned int i, num = *(int *) (((uint8_t *) tm) + tab->offset);

	num++;

	/*
	 *	Simplified process for "do each thing".
	 */
	if (tab->wildcard) {
		if (num < tab->max) goto done;
		goto next;
	}

	/*
	 *	See when the next time interval is.
	 */
	for (i = num; i <= tab->max; i++) {
		if ((tab->fields & (((uint64_t) 1) << i)) != 0) {
			num = i;
			break;
		}
	}

	/*
	 *	We ran out of time intervals.  Reset this field to the
	 *	minimum, and ask the caller to go to the next
	 *	interval.
	 */
	if (i > tab->max) {
	next:
		*(int *) (((uint8_t *) tm) + tab->offset) = tab->min;
		return false;
	}

done:
	*(int *) (((uint8_t *) tm) + tab->offset) = num;
	return true;
}

/*
 *	Called when tm.tm_sec == 0.  If it isn't zero, then it means
 *	that the timer is late, and we treat it as if tm.tm_sec == 0.
 */
static void do_cron(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	proto_cron_crontab_thread_t	*thread = uctx;
	struct tm tm;
	time_t start = time(NULL), end;

	thread->recv_time = now;

	localtime_r(&start, &tm);

	/*
	 *	For now, ignore "day of week".  If the "day of week"
	 *	is a wildcard, then ignore it.  Otherwise, calculate
	 *	next based on "day of month" and also "day of week",
	 *	and then return the time which is closer.
	 */
	tm.tm_sec = 0;
	if (get_next(&tm, &thread->inst->tab[0])) goto set; /* minutes */
	if (get_next(&tm, &thread->inst->tab[1])) goto set; /* hours */

	/*
	 *	If we're running it every day of the week, just pay
	 *	attention to the day of the month.
	 */
	if (thread->inst->tab[4].wildcard) {
		if (get_next(&tm, &thread->inst->tab[2])) goto set; /* days */

		if (get_next(&tm, &thread->inst->tab[3])) goto set; /* month */

		/*
		 *	We ran out of months, so we have to go to the next year.
		 */
		tm.tm_year++;

	} else {
		/*
		 *	Pick the earliest of "day of month" and "day of week".
		 */
		struct tm m_tm = tm;
		struct tm w_tm = tm;
		int tm_wday = tm.tm_wday;
		bool m_day = get_next(&m_tm, &thread->inst->tab[2]);
		bool w_day = get_next(&w_tm, &thread->inst->tab[4]);
		time_t m_time;
		time_t w_time;

		/*
		 *	No more days this week.  Go to the
		 *	start of the next week.
		 */
		if (!w_day) {
			w_tm = tm;
			w_tm.tm_mday += (6 - tm_wday);

			(void) mktime(&w_tm); /* normalize it */

			tm_wday = w_tm.tm_wday;
#ifndef NDEBUG
			w_day = get_next(&w_tm, &thread->inst->tab[4]);
			fr_assert(w_day);
#else
			(void) get_next(&w_tm, &thread->inst->tab[4]);
#endif
		}

		/*
		 *	Next weekday is ignored by mktime(), so we
		 *	have to update the day of the month with the
		 *	new value.
		 *
		 *	Note that mktime() will also normalize the
		 *	values, so we can just add "28 + 5" for a day
		 *	of the month, and mktime() will normalize that
		 *	to the correct day for the next month.
		 */
		fr_assert(tm.tm_wday > tm_wday);
		w_tm.tm_mday += tm.tm_wday - tm_wday;

		/*
		 *	No more days this month, go to the next month,
		 *	and potentially the next year.
		 */
		if (!m_day && !get_next(&m_tm, &thread->inst->tab[3])) m_tm.tm_year++;

		/*
		 *	We now have 2 times, one for "day of month"
		 *	and another for "day of week".  Pick the
		 *	earliest one.
		 */
		m_time = mktime(&m_tm);
		w_time = mktime(&w_tm);

		if (m_time < w_time) {
			end = m_time;
		} else {
			end = w_time;
		}

		goto use_time;
	}

set:
	end = mktime(&tm);
	fr_assert(end >= start);

use_time:
	if (DEBUG_ENABLED2) {
		char buffer[256];

		ctime_r(&end, buffer);
		DEBUG("TIMER - virtual server %s next cron is at %s, in %ld seconds",
		      cf_section_name2(thread->inst->parent->server_cs), buffer, end - start);
	}

	if (fr_event_timer_at(thread, el, &thread->ev, fr_time_add(now, fr_time_delta_from_sec(end - start)),
			      do_cron, thread) < 0) {
		fr_assert(0);
	}

	/*
	 *	Don't run the event the first time.
	 */
	if (thread->bootstrap) {
		thread->bootstrap = false;
		return;
	}

	/*
	 *	Now that we've set the timer, tell the network side to
	 *	call our read routine.
	 */
	fr_network_listen_read(thread->nr, thread->parent);
}

/** Set the event list for a new socket
 *
 * @param[in] li the listener
 * @param[in] el the event list
 * @param[in] nr context from the network side
 */
static void mod_event_list_set(fr_listen_t *li, fr_event_list_t *el, void *nr)
{
	proto_cron_crontab_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_cron_crontab_t);
	proto_cron_crontab_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_cron_crontab_thread_t);

	thread->el = el;
	thread->nr = nr;
	thread->inst = inst;
	thread->bootstrap = true;

	do_cron(el, fr_time(), thread);
}

static char const *mod_name(fr_listen_t *li)
{
	proto_cron_crontab_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_cron_crontab_thread_t);

	return thread->name;
}


static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	proto_cron_crontab_t	*inst = talloc_get_type_abort(mctx->inst->data, proto_cron_crontab_t);
	CONF_SECTION		*conf = mctx->inst->data;
	dl_module_inst_t const	*dl_inst;

	/*
	 *	Find the dl_module_inst_t holding our instance data
	 *	so we can find out what the parent of our instance
	 *	was.
	 */
	dl_inst = dl_module_instance_by_data(inst);
	fr_assert(dl_inst);

	inst->parent = talloc_get_type_abort(dl_inst->parent->data, proto_cron_t);

	inst->cs = conf;

	return 0;
}

static RADCLIENT *mod_client_find(fr_listen_t *li, UNUSED fr_ipaddr_t const *ipaddr, UNUSED int ipproto)
{
	proto_cron_crontab_t const       *inst = talloc_get_type_abort_const(li->app_io_instance, proto_cron_crontab_t);

	return inst->client;
}


static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_cron_crontab_t	*inst = talloc_get_type_abort(mctx->inst->data, proto_cron_crontab_t);
	CONF_SECTION		*conf = mctx->inst->data;
	RADCLIENT		*client;
	fr_pair_t		*vp;
	FILE			*fp;
	bool			done = false;

	fr_pair_list_init(&inst->pair_list);
	inst->client = client = talloc_zero(inst, RADCLIENT);
	if (!inst->client) return 0;

	client->ipaddr.af = AF_INET;
	client->src_ipaddr = client->ipaddr;

	client->longname = client->shortname = inst->filename;
	client->secret = talloc_strdup(client, "testing123");
	client->nas_type = talloc_strdup(client, "load");
	client->use_connected = false;

	fp = fopen(inst->filename, "r");
	if (!fp) {
		cf_log_err(conf, "Failed opening %s - %s",
			   inst->filename, fr_syserror(errno));
		return -1;
	}

	if (fr_pair_list_afrom_file(inst, inst->parent->dict, &inst->pair_list, fp, &done) < 0) {
		cf_log_perr(conf, "Failed reading %s", inst->filename);
		fclose(fp);
		return -1;
	}

	fclose(fp);

	vp = fr_pair_find_by_da(&inst->pair_list, NULL, inst->parent->attr_packet_type);
	if (vp) inst->code = vp->vp_uint32;

	return 0;
}

fr_app_io_t proto_cron_crontab = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "cron_crontab",
		.config			= crontab_listen_config,
		.inst_size		= sizeof(proto_cron_crontab_t),
		.thread_inst_size	= sizeof(proto_cron_crontab_thread_t),
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate
	},
	.default_message_size	= 4096,
	.track_duplicates	= false,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.event_list_set		= mod_event_list_set,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,

	.decode			= mod_decode,
};
