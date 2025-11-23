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
 *
 * @file unit_test_module.c
 * @brief Module test framework
 *
 * @copyright 2000-2018 The FreeRADIUS server project
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/io/listen.h>

#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/version.h>

#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/radius/radius.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

/*
 *  Global variables.
 */
static bool filedone = false;
static int my_debug_lvl = 0;

char const *radiusd_version = RADIUSD_VERSION_BUILD("unit_test_module");

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_protocol;

#define PROTOCOL_NAME unit_test_module_dict[1].proto

extern fr_dict_autoload_t unit_test_module_dict[];
fr_dict_autoload_t unit_test_module_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_protocol, .proto = "radius" }, /* hacked in-place with '-p protocol' */
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_net;

extern fr_dict_attr_autoload_t unit_test_module_dict_attr[];
fr_dict_attr_autoload_t unit_test_module_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_protocol },
	{ .out = &attr_net, .name = "Net", .type = FR_TYPE_TLV, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

/*
 *	Static functions.
 */
static void usage(main_config_t const *config, int status);

static fr_client_t *client_alloc(TALLOC_CTX *ctx, char const *ip, char const *name)
{
	CONF_SECTION *cs;
	fr_client_t *client;

	cs = cf_section_alloc(ctx, NULL, "client", name);
	MEM(cf_pair_alloc(cs, "ipaddr", ip, T_OP_EQ, T_BARE_WORD, T_BARE_WORD));
	MEM(cf_pair_alloc(cs, "secret", "supersecret", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "nas_type", "test", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "shortname", "test", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "groups", "foo", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "groups", "bar", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "groups", "baz", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));

	client = client_afrom_cs(ctx, cs, NULL, 0);
	if (!client) {
		PERROR("Failed creating test client");
		fr_assert(0);
	}
	talloc_steal(client, cs);
	fr_assert(client);

	return client;
}

static void pair_mutable(fr_pair_t *vp)
{
	if (fr_type_is_leaf(vp->vp_type)) {
		vp->vp_immutable = false;

		return;
	}

	fr_assert(fr_type_is_structural(vp->vp_type));

	fr_pair_list_foreach(&vp->vp_group, child) {
		pair_mutable(child);
	}
}

static request_t *request_from_internal(TALLOC_CTX *ctx)
{
	request_t *request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_local_alloc_internal(ctx, NULL);
	if (!request->packet) request->packet = fr_packet_alloc(request, false);
	if (!request->reply) request->reply = fr_packet_alloc(request, false);

	request->packet->socket = (fr_socket_t){
		.type = SOCK_DGRAM,
		.inet = {
			.src_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.src_port = 18120,
			.dst_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.dst_port = 1812
		}
	};

	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.dst->lvl = fr_debug_lvl;

	request->master_state = REQUEST_ACTIVE;
	request->log.lvl = fr_debug_lvl;
	request->async = talloc_zero(request, fr_async_t);

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		talloc_free(request);
		fprintf(stderr, "Failed converting packet IPs to attributes");
		return NULL;
	}

	return request;
}

static request_t *request_from_file(TALLOC_CTX *ctx, FILE *fp, fr_client_t *client, CONF_SECTION *server_cs)
{
	fr_pair_t	*vp;
	request_t	*request;
	fr_dcursor_t	cursor;

	static int	number = 0;

	if (!dict_protocol) {
		fr_strerror_printf_push("%s dictionary failed to load", PROTOCOL_NAME);
		return NULL;
	}

	/*
	 *	Create and initialize the new request.
	 */
	request = request_local_alloc_external(ctx, (&(request_init_args_t){ .namespace = dict_protocol }));

	request->packet = fr_packet_alloc(request, false);
	if (!request->packet) {
	oom:
		fr_strerror_const("No memory");
	error:
		talloc_free(request);
		return NULL;
	}
	request->packet->timestamp = fr_time();

	request->reply = fr_packet_alloc(request, false);
	if (!request->reply) goto oom;

	request->client = client;
	request->number = number++;
	request->name = talloc_typed_asprintf(request, "%" PRIu64, request->number);
	request->master_state = REQUEST_ACTIVE;

	/*
	 *	Read packet from fp
	 */
	if (fr_pair_list_afrom_file(request->request_ctx, dict_protocol, &request->request_pairs, fp, &filedone) < 0) {
		goto error;
	}

	/*
	 *	Pretend that the attributes came in "over the wire".
	 *
	 *	@todo - do this only for protocol attributes, and not internal ones?
	 */
	fr_pair_list_tainted(&request->request_pairs);

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_packet_type);
	if (!vp) {
		fr_strerror_printf("Input packet does not specify a Packet-Type");
		goto error;
	}
	/*
	 *	Set the defaults for IPs, etc.
	 */
	request->packet->code = vp->vp_uint32;

	/*
	 *	Now delete the packet-type to ensure
	 *	the virtual attribute gets used in
	 *	the tests.
	 */
	fr_pair_delete_by_da(&request->request_pairs, attr_packet_type);

	request->packet->socket = (fr_socket_t){
		.type = SOCK_DGRAM,
		.inet = {
			.src_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.src_port = 18120,
			.dst_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.dst_port = 1812
		}
	};

	/*
	 *	Fill in the packet header from attributes, and then
	 *	re-realize the attributes.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL,  attr_packet_type);
	if (vp) request->packet->code = vp->vp_uint32;

	fr_packet_net_from_pairs(request->packet, &request->request_pairs);

	/*
	 *	The input might have updated only some of the Net.*
	 *	attributes.  So for consistency, we create all of them
	 *	from the packet header.
	 */
	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		fr_strerror_const("Failed converting packet IPs to attributes");
		goto error;
	}

	/*
	 *	For laziness in the tests, allow the Net.* to be mutable
	 */
	for (vp = fr_pair_dcursor_by_ancestor_init(&cursor, &request->request_pairs, attr_net);
	     vp != NULL;
	     vp = fr_dcursor_next(&cursor)) {
		pair_mutable(vp);
	}

	if (fr_debug_lvl) {
		for (vp = fr_pair_dcursor_init(&cursor, &request->request_pairs);
		     vp;
		     vp = fr_dcursor_next(&cursor)) {
			/*
			 *	Take this opportunity to verify all the fr_pair_ts are still valid.
			 */
			if (!talloc_get_type(vp, fr_pair_t)) {
				ERROR("Expected fr_pair_t pointer got \"%s\"", talloc_get_name(vp));

				fr_log_talloc_report(vp);
				fr_assert(0);
			}

			fr_log(&default_log, L_DBG, __FILE__, __LINE__, "%pP", vp);
		}
	}

	/*
	 *	Build the reply template from the request.
	 */
	fr_socket_addr_swap(&request->reply->socket, &request->packet->socket);

	request->reply->id = request->packet->id;
	request->reply->code = 0; /* UNKNOWN code */
	memcpy(request->reply->vector, request->packet->vector, sizeof(request->reply->vector));
	request->reply->data = NULL;
	request->reply->data_len = 0;

	/*
	 *	Debugging
	 */
	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.dst->lvl = fr_debug_lvl;

	request->master_state = REQUEST_ACTIVE;
	request->log.lvl = fr_debug_lvl;
	request->async = talloc_zero(request, fr_async_t);


	/*
	 *	New async listeners
	 */
	request->async = talloc_zero(request, fr_async_t);
	unlang_call_push(NULL, request, server_cs, UNLANG_TOP_FRAME);

	return request;
}


static void print_packet(FILE *fp, fr_packet_t *packet, fr_pair_list_t *list)
{
	fr_dict_enum_value_t const *dv;
	fr_log_t log;

	(void) fr_log_init_fp(&log, fp);

	dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(packet->code));
	if (dv) {
		fr_log(&default_log, L_DBG, __FILE__, __LINE__, "Packet-Type = %s", dv->name);
	} else {
		fr_log(&default_log, L_DBG, __FILE__, __LINE__, "Packet-Type = %u", packet->code);
	}

	fr_pair_list_log(&default_log, 2, list);
}

/*
 *	A common function for reports of too much text when handling xlat
 * 	and xlat_expr in do_xlats().
 * 	The convolution deals with the edge case of the line being so long
 * 	that it plus the surrounding text from the format could won't fit
 * 	in the output sbuff, along with the fact that you don't print the
 * 	%d or %.*s. OTOH it does include slen, but...
 * 	* the format string is 41 characters minus 6 for %d and %.*s
 * 	* given that slen reflects text read from line, once slen is
 * 	  large enough, we know line will fit
 */
static inline CC_HINT(always_inline) void too_much_text(fr_sbuff_t *out, ssize_t slen, fr_sbuff_t *line)
{
	char const *format = "ERROR offset %d 'Too much text' ::%.*s::";

	(void) fr_sbuff_in_sprintf(out, format, (int) slen,
				   fr_sbuff_remaining(out) - (strlen(format) - 5),
				   fr_sbuff_current(line));
}

/*
 *	Read a file composed of xlat's and expected results
 */
static bool do_xlats(fr_event_list_t *el, request_t *request, char const *filename, FILE *fp)
{
	int		lineno = 0;
	ssize_t		len;
	char		line_buff[8192];
	char		output_buff[8192];
	char		unescaped[sizeof(output_buff)];
	fr_sbuff_t	line;
	fr_sbuff_t	out;

	static fr_sbuff_escape_rules_t unprintables = {
		.name = "unprintables",
		.chr = '\\',
		.esc = {
			SBUFF_CHAR_UNPRINTABLES_LOW,
			SBUFF_CHAR_UNPRINTABLES_EXTENDED
		},
		.do_utf8 = true,
		.do_oct = true
	};

	while (fgets(line_buff, sizeof(line_buff), fp) != NULL) {
		lineno++;

		line = FR_SBUFF_IN(line_buff, sizeof(line_buff));
		if (!fr_sbuff_adv_to_chr(&line, SIZE_MAX, '\n')) {
			if (!feof(fp)) {
				fprintf(stderr, "%s[%d] Line too long\n", filename, lineno);
				return false;
			}
		} else {
			fr_sbuff_terminate(&line);
		}
		line.end = line.p;
		fr_sbuff_set_to_start(&line);

		/*
		 *	Ignore blank lines and comments
		 */
		fr_sbuff_adv_past_whitespace(&line, SIZE_MAX, NULL);
		if (*fr_sbuff_current(&line) < ' ') continue;
		if (fr_sbuff_is_char(&line, '#')) continue;

		/*
		 *	Look for "match", as it needs the output_buffer to be left alone.
		 */
		if (fr_sbuff_adv_past_str_literal(&line, "match ") > 0) {
			size_t output_len = strlen(output_buff);

			if (!fr_sbuff_is_str(&line, output_buff, output_len) || (output_len != fr_sbuff_remaining(&line))) {
				fprintf(stderr, "Mismatch at %s[%u]\n\tgot          : %s (%zu)\n\texpected     : %s (%zu)\n",
					filename, lineno,  output_buff, output_len, fr_sbuff_current(&line), fr_sbuff_remaining(&line));
				return false;
			}
			continue;
		}

		/*
		 *	The rest of the keywords create output.
		 */
		output_buff[0] = '\0';
		out = FR_SBUFF_OUT(output_buff, sizeof(output_buff));

		/*
		 *	Look for "xlat"
		 */
		if (fr_sbuff_adv_past_str_literal(&line, "xlat ") > 0) {
			ssize_t			slen;
			TALLOC_CTX		*xlat_ctx = talloc_init_const("xlat");
			xlat_exp_head_t		*head = NULL;
			fr_sbuff_parse_rules_t	p_rules = { .escapes = &fr_value_unescape_double };
			tmpl_rules_t		t_rules = (tmpl_rules_t) {
								.attr = {
									.dict_def = dict_protocol,
									.list_def = request_attr_request,
									.allow_unresolved = true,
								},
								.xlat = {
									.runtime_el = el,
								},
								.at_runtime = true,
								};


			slen = xlat_tokenize(xlat_ctx, &head, &line, &p_rules, &t_rules);
			if (slen <= 0) {
				talloc_free(xlat_ctx);
				fr_sbuff_in_sprintf(&out, "ERROR offset %d '%s'", (int) -slen, fr_strerror());
				continue;
			}

			if (fr_sbuff_remaining(&line) > 0) {
				talloc_free(xlat_ctx);
				too_much_text(&out, slen, &line);
				continue;
			}

			len = xlat_eval_compiled(unescaped, sizeof(unescaped), request, head, NULL, NULL);
			if (len < 0) {
				char const *err = fr_strerror();
				talloc_free(xlat_ctx);
				(void) fr_sbuff_in_sprintf(&out, "ERROR expanding xlat: %s", *err ? err : "no error provided");
				continue;
			}

			/*
			 *	Escape the output as if it were a double quoted string.
			 */
			fr_sbuff_in_escape(&out, unescaped, len, &unprintables);

			TALLOC_FREE(xlat_ctx); /* also frees 'head' */
			continue;
		}

		/*
		 *	Look for "xlat_expr"
		 */
		if (fr_sbuff_adv_past_str_literal(&line, "xlat_expr ") > 0) {
			ssize_t			slen;
			TALLOC_CTX		*xlat_ctx = talloc_init_const("xlat");
			xlat_exp_head_t		*head = NULL;

			slen = xlat_tokenize_expression(xlat_ctx, &head,
							&line,
							NULL,
							&(tmpl_rules_t) {
								.attr = {
									.dict_def = dict_protocol,
									.list_def = request_attr_request,
									.allow_unresolved = true,
								},
								.xlat = {
									.runtime_el = el,
								},
								.at_runtime = true,
							});
			if (slen <= 0) {
				talloc_free(xlat_ctx);
				fr_sbuff_in_sprintf(&out, "ERROR offset %d '%s'", (int) -slen - 1, fr_strerror());
				continue;
			}

			if (fr_sbuff_remaining(&line) > 0) {
				talloc_free(xlat_ctx);
				too_much_text(&out, slen, &line);
				continue;
			}

			if (xlat_resolve(head, NULL) < 0) {
				talloc_free(xlat_ctx);
				(void) fr_sbuff_in_sprintf(&out, "ERROR resolving xlat: %s", fr_strerror());
				continue;
			}

			len = xlat_eval_compiled(unescaped, sizeof(unescaped), request, head, NULL, NULL);
			if (len < 0) {
				char const *err = fr_strerror();
				talloc_free(xlat_ctx);
				(void) fr_sbuff_in_sprintf(&out, "ERROR expanding xlat: %s", *err ? err : "no error provided");
				continue;
			}

			/*
			 *	Escape the output as if it were a double quoted string.
			 */
			fr_sbuff_in_escape(&out, unescaped, len, &unprintables);

			TALLOC_FREE(xlat_ctx); /* also frees 'head' */
			continue;
		}

		fprintf(stderr, "Unknown keyword in %s[%d]\n", filename, lineno);
		return false;
	}

	return true;
}

/*
 *	Verify the result of the map.
 */
static int map_proc_verify(CONF_SECTION *cs, UNUSED void const *mod_inst, UNUSED void *proc_inst,
			   tmpl_t const *src, UNUSED map_list_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing source");

		return -1;
	}

	return 0;
}

static unlang_action_t mod_map_proc(unlang_result_t *p_result, UNUSED map_ctx_t const *mpctx,
				    UNUSED request_t *request, UNUSED fr_value_box_list_t *src,
				    UNUSED map_list_t const *maps)
{
	RETURN_UNLANG_FAIL;
}

static request_t *request_clone(request_t *old, int number, CONF_SECTION *server_cs)
{
	request_t *request;

	request = request_local_alloc_internal(NULL, (&(request_init_args_t){ .namespace = old->proto_dict }));
	if (!request) return NULL;

	if (!request->packet) request->packet = fr_packet_alloc(request, false);
	if (!request->reply) request->reply = fr_packet_alloc(request, false);

	memcpy(request->packet, old->packet, sizeof(*request->packet));
	(void) fr_pair_list_copy(request->request_ctx, &request->request_pairs, &old->request_pairs);
	request->packet->timestamp = fr_time();
	request->number = number;
	request->name = talloc_typed_asprintf(request, "%" PRIu64, request->number);

	unlang_call_push(NULL, request, server_cs, UNLANG_TOP_FRAME);

	request->master_state = REQUEST_ACTIVE;

	return request;
}

static void cancel_request(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t when, void *uctx)
{
	request_t	*request = talloc_get_type_abort(uctx, request_t);
	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
	request->rcode = RLM_MODULE_TIMEOUT;
}

fr_time_delta_t time_offset = fr_time_delta_wrap(0);

/** Sythentic time source for tests
 *
 * This allows us to artificially advance time for tests.
 */
static fr_time_t _synthetic_time_source(void)
{
	return fr_time_add_delta_time(time_offset, fr_time());
}
static xlat_arg_parser_t const xlat_func_time_advance_args[] = {
	{ .required = true, .type = FR_TYPE_TIME_DELTA, .single = true },
	XLAT_ARG_PARSER_TERMINATOR
};

static fr_timer_t *time_advance_timer = NULL;

static void time_advance_resume(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	request_t *request = talloc_get_type_abort(uctx, request_t);
	unlang_interpret_mark_runnable(request);
}

static xlat_action_t xlat_func_time_advance_resume(TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
						   UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_value_box_t *vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));
	vb->vb_time_delta = time_offset;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_time_advance(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					    UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *delta;

	XLAT_ARGS(in, &delta);

	/*
	 *	This ensures we take a pass through the timer list
	 *	otherwise the time advances can be ignored.
	 */
	if (unlikely(fr_timer_in(NULL, unlang_interpret_event_list(request)->tl, &time_advance_timer, fr_time_delta_wrap(0), true, time_advance_resume, request) < 0)) {
		RPERROR("Failed to add timer");
		return XLAT_ACTION_FAIL;
	}

	RDEBUG("Time was %pV", fr_box_date(fr_time_to_unix_time(_synthetic_time_source())));

	time_offset = fr_time_delta_add(time_offset, delta->vb_time_delta);

	RDEBUG("Time now %pV (offset +%pV)", fr_box_date(fr_time_to_unix_time(_synthetic_time_source())), fr_box_time_delta(time_offset));

	unlang_xlat_yield(request, xlat_func_time_advance_resume, NULL, 0, NULL);

	return XLAT_ACTION_YIELD;
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	int			ret = EXIT_SUCCESS;
	int			c;
	int			count = 1;
	const char 		*input_file = NULL;
	const char 		*xlat_input_file = NULL;
	const char		*output_file = NULL;
	const char		*filter_file = NULL;
	FILE			*fp = NULL;
	request_t		*request = NULL;
	fr_pair_t		*vp;
	fr_pair_list_t		filter_vps;
	bool			xlat_only = false;
	fr_event_list_t		*el = NULL;
	fr_client_t		*client = NULL;
	fr_dict_t		*dict = NULL;
	fr_dict_t const		*dict_check;
	char const 		*receipt_file = NULL;

	xlat_t			*time_advance = NULL;

	TALLOC_CTX		*autofree;
	TALLOC_CTX		*thread_ctx;

	char			*p;
	main_config_t		*config;

	CONF_SECTION		*server_cs;

#ifndef NDEBUG
	size_t			memory_used_before = 0;
	size_t			memory_used_after = 0;
#endif
	virtual_server_t const	*vs;

	fr_pair_list_init(&filter_vps);

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

	autofree = talloc_autofree_context();
	thread_ctx = talloc_new(autofree);

	config = main_config_alloc(autofree);
	if (!config) {
		fr_perror("unit_test_module");
		fr_exit_now(EXIT_FAILURE);
	}

	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		main_config_name_set_default(config, argv[0], false);
	} else {
		main_config_name_set_default(config, p + 1, false);
	}

	fr_talloc_fault_setup();

	/*
	 *	If the server was built with debugging enabled always install
	 *	the basic fatal signal handlers.
	 */
#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("%s", config->name);
		fr_exit_now(EXIT_FAILURE);
	}
#else
	fr_disable_null_tracking_on_free(autofree);
#endif

	fr_debug_lvl = 0;
	fr_time_start();

	/*
	 *	The tests should have only IPs, not host names.
	 */
	fr_hostname_lookups = fr_reverse_lookups = false;

	/*
	 *	We always log to stdout.
	 */
	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;
	default_log.print_level = true;

	/*  Process the options.  */
	while ((c = getopt(argc, argv, "c:d:D:f:hi:I:mMn:o:p:r:S:xXz")) != -1) {
		switch (c) {
			case 'c':
				count = atoi(optarg);
				break;

			case 'd':
				main_config_raddb_dir_set(config, optarg);
				break;

			case 'D':
				main_config_dict_dir_set(config, optarg);
				break;

			case 'f':
				filter_file = optarg;
				break;

			case 'h':
				usage(config, EXIT_SUCCESS);
				break;

			case 'i':
				input_file = optarg;
				break;

			case 'I':
				xlat_input_file = optarg;
				xlat_only = true;
				break;

			case 'M':
				talloc_enable_leak_report();
				break;

			case 'n':
				config->name = optarg;
				break;

			case 'o':
				output_file = optarg;
				break;

			case 'p':
				PROTOCOL_NAME = optarg;
				break;

			case 'r':
				receipt_file = optarg;
				break;

			case 'S': /* Migration support */
				if (main_config_parse_option(optarg) < 0) {
					fprintf(stderr, "%s: Unknown configuration option '%s'\n",
						config->name, optarg);
					fr_exit_now(EXIT_FAILURE);
				}
				break;

			case 'X':
				fr_debug_lvl += 2;
				default_log.print_level = true;
				break;

			case 'x':
				fr_debug_lvl++;
				if (fr_debug_lvl > 2) default_log.print_level = true;
				break;

			case 'z':
				my_debug_lvl++;
				break;

			default:
				usage(config, EXIT_FAILURE);
				break;
		}
	}

	if (receipt_file && (fr_unlink(receipt_file) < 0)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

#ifdef WITH_TLS
	/*
	 *  Mismatch between build time OpenSSL and linked SSL, better to die
	 *  here than segfault later.
	 */
	if (fr_openssl_version_consistent() < 0) EXIT_WITH_FAILURE;

	/*
	 *  Initialising OpenSSL once, here, is safer than having individual modules do it.
	 *  Must be called before display_version to ensure relevant engines are loaded.
	 *
	 *  fr_openssl_init() must be called before *ANY* OpenSSL functions are used, which is why
	 *  it's called so early.
	 */
	if (fr_openssl_init() < 0) EXIT_WITH_FAILURE;
#endif

	if (fr_debug_lvl) dependency_version_print();

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", config->name);
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/*
	 *	Initialize the DL infrastructure, which is used by the
	 *	config file parser.
	 */
	modules_init(config->lib_dir);

	if (!fr_dict_global_ctx_init(NULL, true, config->dict_dir)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

#ifdef WITH_TLS
	if (fr_tls_dict_init() < 0) EXIT_WITH_FAILURE;
#endif

	/*
	 *	Load the custom dictionary
	 */
	if (fr_dict_read(dict, config->raddb_dir, FR_DICTIONARY_FILE) == -1) {
		PERROR("Failed to initialize the dictionaries");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_autoload(unit_test_module_dict) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}
	if (fr_dict_attr_autoload(unit_test_module_dict_attr) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (request_global_init() < 0) {
		fr_perror("unit_test_module");
		EXIT_WITH_FAILURE;
	}

	if (map_proc_register(NULL, NULL, "test-fail", mod_map_proc, map_proc_verify, 0, 0) < 0) {
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Needed for the triggers.  Which are always run-time expansions.
	 */
	if (main_loop_init() < 0) {
		PERROR("Failed initialising main event loop");
		EXIT_WITH_FAILURE;
	}
	/*
	 *	Initialise the interpreter, registering operations.
	 *      This initialises
	 */
	if (unlang_global_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	time_advance = xlat_func_register(NULL, "time.advance", xlat_func_time_advance, FR_TYPE_VOID);
	if (!time_advance) EXIT_WITH_FAILURE;
	xlat_func_args_set(time_advance, xlat_func_time_advance_args);

	/*
	 *	Ensure that we load the correct virtual server for the
	 *	protocol, if necessary.
	 */
	if (!getenv("PROTOCOL")) {
		setenv("PROTOCOL", PROTOCOL_NAME, true);
	}

	/*
	 *	Setup the global structures for module lists
	 */
	if (modules_rlm_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}
	if (virtual_servers_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (main_config_init(config) < 0) {
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Create a dummy client on 127.0.0.1, if one doesn't already exist.
	 */
	client = client_find(NULL, &(fr_ipaddr_t) { .af = AF_INET, .prefix = 32, .addr.v4.s_addr = htonl(INADDR_LOOPBACK) },
			     IPPROTO_IP);
	if (!client) {
		client = client_alloc(NULL, "127.0.0.1", "test");
		client_add(NULL, client);
	}

	if (server_init(config->root_cs, config->raddb_dir, dict) < 0) EXIT_WITH_FAILURE;

	vs = virtual_server_find("default");
	if (!vs) {
		ERROR("Cannot find virtual server 'default'");
		EXIT_WITH_FAILURE;
	}

	server_cs = virtual_server_cs(vs);

	/*
	 *	Do some sanity checking.
	 */
	dict_check = virtual_server_dict_by_name("default");
	if (!dict_check || !fr_dict_compatible(dict_check, dict_protocol)) {
		ERROR("Virtual server namespace does not match requested namespace '%s'", PROTOCOL_NAME);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Get the main event list.
	 */
	el = main_loop_event_list();
	fr_assert(el != NULL);
	fr_timer_list_set_time_func(el->tl, _synthetic_time_source);

	/*
	 *	Simulate thread specific instantiation
	 */
	if (modules_rlm_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	if (virtual_servers_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	if (xlat_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	unlang_thread_instantiate(thread_ctx);

	/*
	 *  Set the panic action (if required)
	 */
	{
		char const *panic_action = NULL;

		panic_action = getenv("PANIC_ACTION");
		if (!panic_action) panic_action = config->panic_action;

		if (panic_action && (fr_fault_setup(autofree, panic_action, argv[0]) < 0)) {
			fr_perror("%s", config->name);
			EXIT_WITH_FAILURE;
		}
	}

	setlinebuf(stdout); /* unbuffered output */

#ifndef NDEBUG
	memory_used_before = talloc_total_size(autofree);
#endif

	if (!input_file && !xlat_only) input_file = "-";

	if (input_file) {
		if (strcmp(input_file, "-") == 0) {
			fp = stdin;
		} else {
			fp = fopen(input_file, "r");
			if (!fp) {
				fprintf(stderr, "Failed reading %s: %s\n",
					input_file, fr_syserror(errno));
				EXIT_WITH_FAILURE;
			}
		}

		/*
		 *	Grab the VPs from stdin, or from the file.
		 */
		request = request_from_file(autofree, fp, client, server_cs);
		if (!request) {
			fr_perror("Failed reading input from %s", input_file);
			EXIT_WITH_FAILURE;
		}
	} else {
		request = request_from_internal(autofree);
	}

	/*
	 *	For simplicity, read xlat's.
	 */
	if (xlat_only) {
		if (fp && (fp != stdin)) fclose(fp);

		fp = fopen(xlat_input_file, "r");
		if (!fp) {
			fprintf(stderr, "Failed reading %s: %s\n",
				xlat_input_file, fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}

		if (!do_xlats(el, request, xlat_input_file, fp)) ret = EXIT_FAILURE;
		if (input_file) fclose(fp);
		goto cleanup;
	}

	/*
	 *	No filter file, OR there's no more input, OR we're
	 *	reading from a file, and it's different from the
	 *	filter file.
	 */
	if (!filter_file || filedone ||
	    ((input_file != NULL) && (strcmp(filter_file, input_file) != 0))) {
		if (output_file) {
			if (fp && (fp != stdin)) fclose(fp);
			fp = NULL;
		}
		filedone = false;
	}

	/*
	 *	There is a filter file.  If necessary, open it.  If we
	 *	already are reading it via "input_file", then we don't
	 *	need to re-open it.
	 */
	if (filter_file) {
		if (!fp) {
			fp = fopen(filter_file, "r");
			if (!fp) {
				fprintf(stderr, "Failed reading %s: %s\n", filter_file, fr_syserror(errno));
				EXIT_WITH_FAILURE;
			}
		}

		if (fr_pair_list_afrom_file(request->request_ctx, dict_protocol, &filter_vps, fp, &filedone) < 0) {
			fr_perror("Failed reading attributes from %s", filter_file);
			EXIT_WITH_FAILURE;
		}

		/*
		 *	Filter files can't be empty.
		 */
		if (fr_pair_list_empty(&filter_vps)) {
			fr_perror("No attributes in filter file %s", filter_file);
			EXIT_WITH_FAILURE;
		}

		/*
		 *	FIXME: loop over input packets.
		 */
		fclose(fp);
	}

	if (count == 1) {
		fr_timer_in(request, el->tl, &request->timeout, config->worker.max_request_time, false, cancel_request, request);
		unlang_interpret_synchronous(el, request);

	} else {
		int i;
		request_t *cached = request;

		for (i = 0; i < count; i++) {
#ifndef NDEBUG
			size_t request_used_before, request_used_after;
#endif

			request = request_clone(cached, i, server_cs);

#ifndef NDEBUG
			request_used_before = talloc_total_size(autofree);

			/*
			 *	Artificially limit the number of instructions which are run.
			 */
			if (config->ins_max) {
				if (config->ins_countup) {
					request->ins_max = i + 1;
				} else {
					request->ins_max = config->ins_max;
				}

				if (request->ins_max < 10) request->ins_max = 10;

				request->ins_count = 0;
			}
#endif

			fr_timer_in(request, el->tl, &request->timeout, config->worker.max_request_time, false, cancel_request, request);
			unlang_interpret_synchronous(el, request);
			talloc_free(request);

#ifndef NDEBUG
			request_used_after = talloc_total_size(autofree);
			fr_assert(request_used_after == request_used_before);
#endif
		}

		request = cached;
	}

	if (!output_file || (strcmp(output_file, "-") == 0)) {
		fp = stdout;
	} else {
		fp = fopen(output_file, "w");
		if (!fp) {
			fprintf(stderr, "Failed writing %s: %s\n", output_file, fr_syserror(errno));
			goto cleanup;
		}
	}

	print_packet(fp, request->reply, &request->reply_pairs);

	if (output_file) fclose(fp);

	/*
	 *	Update the list with the response type, so that it can
	 *	be matched in filters.
	 *
	 *	Some state machines already include a response Packet-Type
	 *	so we need to try and update it, else we end up with two!
	 */
	if (!fr_pair_list_empty(&filter_vps)) {
		fr_pair_t const *failed[2];

		MEM(pair_update_reply(&vp, attr_packet_type) >= 0);
		vp->vp_uint32 = request->reply->code;

		if (!fr_pair_validate(failed, &filter_vps, &request->reply_pairs)) {
			fr_pair_validate_debug(failed);

			fr_perror("Output file %s does not match attributes in filter %s",
				  output_file ? output_file : "-", filter_file);
			fr_fprintf_pair_list(stderr, &filter_vps);
			ret = EXIT_FAILURE;
			goto cleanup;
		}
	}

	INFO("Exiting normally");

cleanup:
	talloc_free(request);

	/*
	 *	No leaks.
	 */
#ifndef NDEBUG
	memory_used_after = talloc_total_size(autofree);
	if (memory_used_after != memory_used_before) {
		printf("WARNING: May have leaked memory (%zd - %zd = %zd)\n",
		       memory_used_after, memory_used_before, memory_used_after - memory_used_before);
	}
#endif

	map_proc_unregister("test-fail");

	/*
	 *	Free thread data
	 */
	talloc_free(thread_ctx);

	/*
	 *	Ensure all thread local memory is cleaned up
	 *	at the appropriate time.  This emulates what's
	 *	done with worker/network threads in the
	 *	scheduler.
	 */
	fr_atexit_thread_trigger_all();

	/*
	 *	Give processes a chance to exit
	 */
	if (el) fr_event_list_reap_signal(el, fr_time_delta_from_sec(5), SIGKILL);

	main_loop_free();

	/*
	 *	Ensure all thread local memory is cleaned up
	 *	at the appropriate time.  This emulates what's
	 *	done with worker/network threads in the
	 *	scheduler.
	 */
	fr_atexit_thread_trigger_all();

	server_free();

	/*
	 *	Virtual servers need to be freed before modules
	 *	as state entries containing data with module-specific
	 *	destructors may exist.
	 */
	virtual_servers_free();

	/*
	 *	Free modules, this needs to be done explicitly
	 *	because some libraries used by modules use atexit
	 *	handlers registered after ours, and they may deinit
	 *	themselves before we free the modules and cause
	 *	crashes on exit.
	 */
	modules_rlm_free();

	/*
	 *	And now nothing should be left anywhere except the
	 *	parsed configuration items.
	 */
	main_config_free(&config);

#ifdef WITH_TLS
	fr_tls_dict_free();
#endif

	/*
	 *	Free any autoload dictionaries
	 */
	fr_dict_autofree(unit_test_module_dict);

	/*
	 *	Free our explicitly loaded internal dictionary
	 */
	if (fr_dict_free(&dict, __FILE__) < 0) {
		fr_perror("unit_test_module - dict");
		ret = EXIT_FAILURE;
	}

	/*
	 *	Free any openssl resources and the TLS dictionary
	 */
#ifdef WITH_TLS
	fr_openssl_free();
#endif

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_touch(NULL, receipt_file, 0644, true, 0755) <= 0)) {
		fr_perror("unit_test_module");
		ret = EXIT_FAILURE;
	}

	if (talloc_free(autofree) < 0) {
		fr_perror("unit_test_module - autofree");
		ret = EXIT_FAILURE;
	}

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();

	return ret;
}


/*
 *  Display the syntax for starting this program.
 */
static NEVER_RETURNS void usage(main_config_t const *config, int status)
{
	FILE *output = status ? stderr : stdout;

	fprintf(output, "Usage: %s [options]\n", config->name);
	fprintf(output, "Options:\n");
	fprintf(output, "  -c <count>         Run packets through the interpreter <count> times\n");
	fprintf(output, "  -d <raddb_dir>     Configuration files are in \"raddb_dir/*\".\n");
	fprintf(output, "  -D <dict_dir>      Dictionary files are in \"dict_dir/*\".\n");
	fprintf(output, "  -f <file>          Filter reply against attributes in 'file'.\n");
	fprintf(output, "  -h                 Print this help message.\n");
	fprintf(output, "  -i <file>          File containing request attributes.\n");
	fprintf(output, "  -m                 On SIGINT or SIGQUIT exit cleanly instead of immediately.\n");
	fprintf(output, "  -n <name>          Read raddb/name.conf instead of raddb/radiusd.conf.\n");
	fprintf(output, "  -o <file>          Output file for the reply.\n");
	fprintf(output, "  -p <radius|...>    Define which protocol namespace is used to read the file\n");
	fprintf(output, "                     Use radius, dhcpv4, or dhcpv6\n");
	fprintf(output, "  -X                 Turn on full debugging.\n");
	fprintf(output, "  -x                 Turn on additional debugging. (-xx gives more debugging).\n");
	fprintf(output, "  -r <receipt_file>  Create the <receipt_file> as a 'success' exit.\n");

	fr_exit_now(status);
}
