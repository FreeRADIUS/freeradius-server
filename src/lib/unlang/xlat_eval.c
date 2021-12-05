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
 * @file xlat_eval.c
 * @brief String expansion ("translation").  Evaluation of pre-parsed xlat epxansions.
 *
 * @copyright 2018-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#include <freeradius-devel/unlang/unlang_priv.h>	/* Remove when everything uses new xlat API */


static bool done_init = false;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

static fr_dict_autoload_t xlat_eval_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_client_ip_address;
static fr_dict_attr_t const *attr_client_shortname;
static fr_dict_attr_t const *attr_module_return_code;
static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_request_processing_stage;
static fr_dict_attr_t const *attr_virtual_server;

static fr_dict_attr_t const *attr_packet_authentication_vector;
static fr_dict_attr_t const *attr_packet_type;

static fr_dict_attr_autoload_t xlat_eval_dict_attr[] = {
	{ .out = &attr_client_ip_address, .name = "Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_client_shortname, .name = "Client-Shortname", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_return_code, .name = "Module-Return-Code", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPV6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_request_processing_stage, .name = "Request-Processing-Stage", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_virtual_server, .name = "Virtual-Server", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_packet_authentication_vector, .name = "Packet-Authentication-Vector", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

fr_table_num_sorted_t const xlat_action_table[] = {
	{ L("done"),		XLAT_ACTION_DONE	},
	{ L("fail"),		XLAT_ACTION_FAIL	},
	{ L("push-child"),	XLAT_ACTION_PUSH_CHILD	},
	{ L("yield"),		XLAT_ACTION_YIELD	}
};
size_t xlat_action_table_len = NUM_ELEMENTS(xlat_action_table);

static ssize_t xlat_eval_sync(TALLOC_CTX *ctx, char **out, request_t *request, xlat_exp_t const * const head,
			    xlat_escape_legacy_t escape, void  const *escape_ctx);

/** Reconstruct the original expansion string from an xlat tree
 *
 * @param[in] ctx	to allocate result in.
 * @param[in] node	in the tree to start printing.
 * @return
 *	- The original expansion string on success.
 *	- NULL on error.
 */
static char *xlat_fmt_aprint(TALLOC_CTX *ctx, xlat_exp_t const *node)
{
	switch (node->type) {
	case XLAT_BOX:
	case XLAT_GROUP:
		return talloc_asprintf(ctx, "%s", node->fmt);

	case XLAT_ONE_LETTER:
		return talloc_asprintf(ctx, "%%%s", node->fmt);

	case XLAT_ATTRIBUTE:
		return talloc_asprintf(ctx, "%%{%s}", node->fmt);

	case XLAT_VIRTUAL:
		return talloc_asprintf(ctx, "%%{%s}", node->call.func->name);

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		return talloc_asprintf(ctx, "%%{%u}", node->regex_index);
#endif

	case XLAT_FUNC:
	{
		xlat_exp_t const 	*child = node->child;
		char		 	*out, *n_out;
		TALLOC_CTX		*pool;
		char			open = '{', close = '}';
		bool			first_done = false;

		if (node->call.func->input_type == XLAT_INPUT_ARGS) {
			open = '(';
			close = ')';
		}
		if (!child) return talloc_asprintf(ctx, "%%%c%s:%c", open, node->call.func->name, close);

		out = talloc_asprintf(ctx, "%%%c%s:", open, node->call.func->name);
		pool = talloc_pool(NULL, 128);	/* Size of a single child (probably ok...) */
		do {
			char *child_str;

			child_str = xlat_fmt_aprint(pool, child);
			if (child_str) {
				if ((first_done) && (node->call.func->input_type == XLAT_INPUT_ARGS)) {
					n_out = talloc_strdup_append_buffer(out, " ");
					if (!n_out) {
					child_error:
						talloc_free(out);
						talloc_free(pool);
						return NULL;
					}
					out = n_out;
				}

				n_out = talloc_buffer_append_buffer(ctx, out, child_str);
				if (!n_out) goto child_error;
				out = n_out;
				first_done = true;
			}
			talloc_free_children(pool);	/* Clear pool contents */
		} while ((child = child->next));
		talloc_free(pool);

		n_out = talloc_strndup_append_buffer(out, &close, 1);
		if (!n_out) {
			talloc_free(out);
			return NULL;
		}
		return n_out;
	}

	case XLAT_ALTERNATE:
	{
		char *first, *second, *result;

		first = xlat_fmt_aprint(NULL, node->child);
		second = xlat_fmt_aprint(NULL, node->alternate);
		result = talloc_asprintf(ctx, "%%{%s:-%s}", first, second);
		talloc_free(first);
		talloc_free(second);

		return result;
	}

	default:
		return NULL;
	}
}

/** Output what we're currently expanding
 *
 * @param[in] request	The current request.
 * @param[in] node	Being processed.
 * @param[in] args	from previous expansion.
 */
static inline void xlat_debug_log_expansion(request_t *request, xlat_exp_t const *node, fr_value_box_list_t const *args)
{
	char *str;

	if (!RDEBUG_ENABLED2) return;

	str = xlat_fmt_aprint(NULL, node);
	RDEBUG2("EXPAND %s", str);

	/*
	 *	Because it's difficult to keep track of what
	 *	the function was actually called with,
	 *	we print the concatenated arguments list as
	 *	well as the original fmt string.
	 */
	if ((node->type == XLAT_FUNC) && !xlat_is_value_box(node->child)) {
		RDEBUG2("      (%%%c%s:%pM%c)",
			(node->call.func->input_type == XLAT_INPUT_ARGS) ? '(' : '{',
			node->call.func->name, args,
			(node->call.func->input_type == XLAT_INPUT_ARGS) ? ')' : '}');
	}
	talloc_free(str);
}

/** Output the list result of an expansion
 *
 * @param[in] request	The current request.
 * @param[in] result	of the expansion.
 */
static inline void xlat_debug_log_list_result(request_t *request, fr_value_box_list_t const *result)
{
	if (!RDEBUG_ENABLED2) return;

	RDEBUG2("  --> %pM", result);
}

/** Output the result of an expansion
 *
 * @param[in] request	The current request.
 * @param[in] result	of the expansion.
 */
static inline void xlat_debug_log_result(request_t *request, fr_value_box_t const *result)
{
	if (!RDEBUG_ENABLED2) return;

	RDEBUG2("  --> %pV", result);
}

/** Process an individual xlat argument value box group
 *
 * @param[in] ctx	to allocate any additional buffers in
 * @param[in,out] list	of value boxes representing one argument
 * @param[in] request	currently being processed
 * @param[in] arg	specification of current argument
 * @param[in] arg_num	number of current argument in the argument specifications
 * @return
 *	- XLAT_ACTION_DONE on success.
 *	- XLAT_ACTION_FAIL on failure.
 */
static xlat_action_t xlat_process_arg_list(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request,
					   xlat_arg_parser_t const *arg, unsigned int arg_num)
{
	fr_value_box_t *vb;

#define ESCAPE(_arg, _vb, _arg_num) \
do { \
	if ((_arg)->func && ((_vb)->tainted || (_arg)->always_escape) && \
	    ((_arg)->func(request, _vb, (_arg)->uctx) < 0)) { \
		RPEDEBUG("Failed escaping argument %u", _arg_num); \
		return XLAT_ACTION_FAIL; \
	} \
} while (0)

	if (fr_dlist_empty(list)) {
		if (arg->required) {
			REDEBUG("Required argument %u is null", arg_num);
			return XLAT_ACTION_FAIL;
		}
		return XLAT_ACTION_DONE;
	}

	vb = fr_dlist_head(list);

	/*
	 *	Concatenate child boxes, casting to desired type,
	 *	then replace group vb with first child vb
	 */
	if (arg->concat) {
		if (arg->func) {
			do ESCAPE(arg, vb, arg_num); while ((vb = fr_dlist_next(list, vb)));

			vb = fr_dlist_head(list);	/* Reset */
		}

		if (fr_value_box_list_concat_in_place(ctx,
						      vb, list, arg->type,
						      FR_VALUE_BOX_LIST_FREE, true,
						      SIZE_MAX) < 0) {
			RPEDEBUG("Failed concatenating arguments");
			return XLAT_ACTION_FAIL;
		}
		fr_assert(fr_dlist_num_elements(list) <= 1);

		return XLAT_ACTION_DONE;
	}

	/*
	 *	Only a single child box is valid here.  Check there is
	 *	just one, cast to the correct type
	 */
	if (arg->single) {
		if (fr_dlist_num_elements(list) > 1) {
			RPEDEBUG("Incorrect number of values provided to argument %u, "
				 "expected %s got %u",
				 arg_num,
				 arg->required ? "0-1" : "1",
				 fr_dlist_num_elements(list));
			return XLAT_ACTION_FAIL;
		}

		ESCAPE(arg, vb, arg_num);

		if ((arg->type != FR_TYPE_VOID) && (vb->type != arg->type)) {
		cast_error:
			if (fr_value_box_cast_in_place(ctx, vb,
						       arg->type, NULL) < 0) {
				RPEDEBUG("Failed casting argument %u", arg_num);
				return XLAT_ACTION_FAIL;
			}
		}

		return XLAT_ACTION_DONE;
	}

	/*
	 *	We're neither concatenating nor do we only expect a single value,
	 *	cast all child values to the required type.
	 */
	if (arg->type != FR_TYPE_VOID) {
		do {
 			ESCAPE(arg, vb, arg_num);
			if (vb->type == arg->type) continue;
			if (fr_value_box_cast_in_place(ctx, vb,
						       arg->type, NULL) < 0) goto cast_error;
		} while ((vb = fr_dlist_next(list, vb)));

	/*
	 *	If it's not a void type we still need to escape the values
	 */
	} else if (arg->func) {
		do ESCAPE(arg, vb, arg_num); while ((vb = fr_dlist_next(list, vb)));
	}

#undef ESCAPE

	return XLAT_ACTION_DONE;
}


/** Process list of boxed values provided as input to an xlat
 *
 * Ensures that the value boxes passed to an xlat function match the
 * requirements listed in its "args", and escapes any tainted boxes
 * using the specified escaping routine.
 *
 * @param[in] ctx		in which to allocate any buffers.
 * @param[in,out] list		value boxes provided as input.
 * 				List will be modified in accordance to rules
 * 				provided in the args array.
 * @param[in] input_type	required by xlat.
 * @param[in] args		definition of arguments required by xlat.
 */
static inline CC_HINT(always_inline)
xlat_action_t xlat_process_args(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request,
				xlat_input_type_t input_type, xlat_arg_parser_t const args[])
{
	xlat_arg_parser_t const	*arg_p = args;
	xlat_action_t		xa;
	fr_value_box_t		*vb, *next;

	/*
	 *	No args registered for this xlat
	 */
	if (!args) return XLAT_ACTION_DONE;

	/*
	 *	xlat needs no input processing just return.
	 */
	switch (input_type) {
	case XLAT_INPUT_UNPROCESSED:
		return XLAT_ACTION_DONE;

	/*
	 *	xlat takes all input as a single vb.
	 */
	case XLAT_INPUT_MONO:
		return xlat_process_arg_list(ctx, list, request, arg_p, 1);

	/*
	 *	xlat consumes a sequence of arguments.
	 */
	case XLAT_INPUT_ARGS:
		vb = fr_dlist_head(list);
		while (arg_p->type != FR_TYPE_NULL) {
			/*
			 *	Separate check to see if the group
			 *	box is there.  Check in
			 *	xlat_process_arg_list verifies it
			 *	has a value.
			 */
			if (!vb) {
				if (arg_p->required) {
					REDEBUG("Missing required argument %u", (unsigned int)((arg_p - args) + 1));
					return XLAT_ACTION_FAIL;
				}

				/*
				 *	Add a placeholder 'null' box
				 */
				MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_NULL, NULL, false));
				fr_dlist_insert_tail(list, vb);
				return XLAT_ACTION_DONE;
			}

			/*
			 *	Everything in the top level list should be
			 *	groups
			 */
			if (!fr_cond_assert(vb->type == FR_TYPE_GROUP)) return XLAT_ACTION_FAIL;

			/*
			 *	pre-advance, in case the vb is replaced
			 *	during processing.
			 */
			next = fr_dlist_next(list, vb);
			xa = xlat_process_arg_list(ctx, &vb->vb_group, request, arg_p,
						   (unsigned int)((arg_p - args) + 1));
			if (xa != XLAT_ACTION_DONE) return xa;

			/*
			 *	In some cases we replace the current
			 *	argument with the head of the group.
			 */
			if (arg_p->single || arg_p->concat) {
				/*
				 *	If the group is empty, convert
				 *	it to a null box to maintain
				 *	correct ordering in the argument
				 *	list.
				 */
				if (fr_dlist_empty(&vb->vb_group)) {
					fr_value_box_t *prev = fr_dlist_remove(list, vb);
					fr_value_box_init_null(vb);
					fr_dlist_insert_after(list, prev, vb);
				} else {
					fr_dlist_replace(list, vb, fr_dlist_pop_head(&vb->vb_group));
					talloc_free(vb);
				}
			}

			if (arg_p->variadic) {
				if (!next) break;
			} else {
				arg_p++;
			}
			vb = next;
		}
		break;
	}

	return XLAT_ACTION_DONE;
}

/** One letter expansions
 *
 * @param[in] ctx	to allocate boxed value, and buffers in.
 * @param[out] out	Where to write the boxed value.
 * @param[in] request	The current request.
 * @param[in] letter	to expand.
 * @return
 *	- #XLAT_ACTION_FAIL	on memory allocation errors.
 *	- #XLAT_ACTION_DONE	if we're done processing this node.
 *
 */
static inline CC_HINT(always_inline)
xlat_action_t xlat_eval_one_letter(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request, char letter)
{

	char		buffer[64];
	struct tm	ts;
	time_t		now;
	fr_value_box_t	*value;

	now = fr_time_to_sec(request->packet->timestamp);

	switch (letter) {
	case '%':
		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, "%", false) < 0) return XLAT_ACTION_FAIL;
		break;

	/*
	 *	RADIUS request values
	 */

	case 'I': /* Request ID */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
		value->datum.uint32 = request->packet->id;
		break;

	case 'n': /* Request number */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
		value->datum.uint64 = request->number;
		break;

	case 's': /* First request in this sequence */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
		value->datum.uint64 = request->seq_start;
		break;

	/*
	 *	Current time
	 */

	case 'c': /* Current epoch time seconds */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
		value->datum.uint64 = (uint64_t)fr_time_to_sec(fr_time());
		break;

	case 'C': /* Current epoch time microsecond component */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
		value->datum.uint64 = (uint64_t)fr_time_to_usec(fr_time()) % 1000000;
		break;

	/*
	 *	Time of the current request
	 */

	case 'd': /* Request day */
		if (!localtime_r(&now, &ts)) {
		error:
			REDEBUG("Failed converting packet timestamp to localtime: %s", fr_syserror(errno));
			return XLAT_ACTION_FAIL;
		}

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_mday;
		break;

	case 'D': /* Request date */
		if (!localtime_r(&now, &ts)) goto error;

		strftime(buffer, sizeof(buffer), "%Y%m%d", &ts);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
		break;

	case 'e': /* Request second */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_sec;
		break;

	case 'G': /* Request minute */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_min;
		break;

	case 'H': /* Request hour */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_hour;
		break;

	case 'l': /* Request timestamp as a 32-bit integer */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
		value->datum.uint32 = (uint32_t ) now;
		break;

	case 'm': /* Request month */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_mon + 1;
		break;

	case 'M': /* Request time microsecond component */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
		value->datum.uint32 = fr_time_to_msec(request->packet->timestamp) % 1000;
		break;

	case 'S': /* Request timestamp in SQL format */
		if (!localtime_r(&now, &ts)) goto error;

		strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &ts);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
		break;

	case 't': /* Request timestamp in CTIME format */
	{
		char *p;

		CTIME_R(&now, buffer, sizeof(buffer));
		p = strchr(buffer, '\n');
		if (p) *p = '\0';

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
	}
		break;

	case 'T': /* Request timestamp in ISO format */
	{
		int len = 0;

		if (!gmtime_r(&now, &ts)) goto error;

		if (!(len = strftime(buffer, sizeof(buffer) - 1, "%Y-%m-%dT%H:%M:%S", &ts))) {
			REDEBUG("Failed converting packet timestamp to gmtime: Buffer full");
			return XLAT_ACTION_FAIL;
		}
		strcat(buffer, ".");
		len++;
		snprintf(buffer + len, sizeof(buffer) - len, "%03i",
			 (int) fr_time_to_msec(request->packet->timestamp) % 1000);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
	}
		break;

	case 'Y': /* Request year */
		if (!localtime_r(&now, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT16, NULL, false));

		value->datum.int16 = ts.tm_year + 1900;
		break;

	default:
		fr_assert_fail("%%%c is not a valid one letter expansion", letter);
		return XLAT_ACTION_FAIL;
	}

	fr_dlist_insert_tail(out, value);

	return XLAT_ACTION_DONE;
}

/** Gets the value of a virtual attribute
 *
 * These attribute *may* be overloaded by the user using real attribute.
 *
 * @todo There should be a virtual attribute registry.
 *
 * @param[in] ctx	to allocate boxed value, and buffers in.
 * @param[out] out	Where to write the boxed value.
 * @param[in] request	The current request.
 * @param[in] vpt	Representing the attribute.
 * @return
 *	- #XLAT_ACTION_FAIL	on memory allocation errors.
 *	- #XLAT_ACTION_DONE	if we're done processing this node.
 */
static xlat_action_t xlat_eval_pair_virtual(TALLOC_CTX *ctx, fr_value_box_list_t *out,
					    request_t *request, tmpl_t const *vpt)
{
	fr_radius_packet_t	*packet = NULL;
	fr_value_box_t	*value;

	/*
	 *	Virtual attributes always have a count of 1
	 */
	if (tmpl_num(vpt) == NUM_COUNT) {
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
		value->datum.uint32 = 1;
		goto done;
	}

	/*
	 *	Some non-packet expansions
	 */
	if (tmpl_da(vpt) == attr_client_shortname) {
		RADCLIENT *client = client_from_request(request);
		if (!client || !client->shortname) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_bstrdup_buffer(ctx, value, tmpl_da(vpt), client->shortname, false) < 0) {
		error:
			talloc_free(value);
			return XLAT_ACTION_FAIL;
		}
		goto done;
	}

	if (tmpl_da(vpt) == attr_request_processing_stage) {
		if (!request->component) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(ctx, value, tmpl_da(vpt), request->component, false) < 0) goto error;
		goto done;
	}

	if (tmpl_da(vpt) == attr_virtual_server) {
		if (!unlang_call_current(request)) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_bstrdup_buffer(ctx, value, tmpl_da(vpt),
					       cf_section_name2(unlang_call_current(request)), false) < 0) goto error;
		goto done;
	}

	if (tmpl_da(vpt) == attr_module_return_code) {
		MEM(value = fr_value_box_alloc(ctx, tmpl_da(vpt)->type, tmpl_da(vpt), false));
		value->datum.int32 = request->rcode;
		goto done;
	}

	/*
	 *	All of the attributes must now refer to a packet.
	 *	If there's no packet, we can't print any attribute
	 *	referencing it.
	 */
	packet = tmpl_packet_ptr(request, tmpl_list(vpt));
	if (!packet) return XLAT_ACTION_DONE;

	if (tmpl_da(vpt) == attr_packet_type) {
		if (!packet || !packet->code) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc(ctx, tmpl_da(vpt)->type, NULL, false));
		value->enumv = tmpl_da(vpt);
		value->datum.int32 = packet->code;

	/*
	 *	Virtual attributes which require a temporary fr_pair_t
	 *	to be allocated. We can't use stack allocated memory
	 *	because of the talloc checks sprinkled throughout the
	 *	various VP functions.
	 */
	} else if (tmpl_da(vpt) == attr_packet_authentication_vector) {
		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_memdup(ctx, value, tmpl_da(vpt), packet->vector, sizeof(packet->vector), true);

	} else if (tmpl_da(vpt) == attr_client_ip_address) {
		RADCLIENT *client = client_from_request(request);
		if (client) {
			MEM(value = fr_value_box_alloc_null(ctx));
			fr_value_box_ipaddr(value, NULL, &client->ipaddr, false);	/* Enum might not match type */
			goto done;
		}
		goto src_ip_address;

	} else if (tmpl_da(vpt) == attr_packet_src_ip_address) {
	src_ip_address:
		if (!fr_socket_is_inet(packet->socket.proto) ||
		    (packet->socket.inet.src_ipaddr.af != AF_INET)) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.src_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_dst_ip_address) {
		if (!fr_socket_is_inet(packet->socket.proto) ||
		    (packet->socket.inet.dst_ipaddr.af != AF_INET)) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.dst_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_src_ipv6_address) {
		if (!fr_socket_is_inet(packet->socket.proto) ||
		    (packet->socket.inet.src_ipaddr.af != AF_INET6)) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.src_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_dst_ipv6_address) {
		if (!fr_socket_is_inet(packet->socket.proto) ||
		    (packet->socket.inet.dst_ipaddr.af != AF_INET6)) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.dst_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_src_port) {
		if (!fr_socket_is_inet(packet->socket.proto)) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc(ctx, tmpl_da(vpt)->type, NULL, true));
		value->datum.uint16 = packet->socket.inet.src_port;

	} else if (tmpl_da(vpt) == attr_packet_dst_port) {
		if (!fr_socket_is_inet(packet->socket.proto)) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc(ctx, tmpl_da(vpt)->type, NULL, true));
		value->datum.uint16 = packet->socket.inet.dst_port;

	} else {
		RERROR("Attribute \"%s\" incorrectly marked as virtual", tmpl_da(vpt)->name);
		return XLAT_ACTION_FAIL;
	}

done:
	fr_dlist_insert_tail(out, value);

	return XLAT_ACTION_DONE;
}


/** Gets the value of a real or virtual attribute
 *
 * @param[in] ctx	to allocate boxed value, and buffers in.
 * @param[out] out	Where to write the boxed value.
 * @param[in] request	The current request.
 * @param[in] vpt	Representing the attribute.
 * @return
 *	- #XLAT_ACTION_FAIL		we failed getting a value for the attribute.
 *	- #XLAT_ACTION_DONE		we successfully evaluated the xlat.
 */
static inline CC_HINT(always_inline) xlat_action_t
xlat_eval_pair_real(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request, tmpl_t const *vpt)
{
	fr_pair_t		*vp = NULL;
	fr_value_box_t		*value;

	fr_dcursor_t		cursor;
	tmpl_pair_cursor_ctx_t	cc;

	xlat_action_t		ret = XLAT_ACTION_DONE;

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	/*
	 *	See if we're dealing with an attribute in the request
	 *
	 *	This allows users to manipulate virtual attributes as if
	 *	they were real ones.
	 */
	vp = tmpl_pair_cursor_init(NULL, NULL, &cc, &cursor, request, vpt);

	/*
	 *	We didn't find the VP in a list, check to see if it's
	 *	virtual.
	 */
	if (!vp) {
		if (tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual) {
			ret = xlat_eval_pair_virtual(ctx, out, request, vpt);
			goto done;
		}

		/*
		 *	Zero count.
		 */
		if (tmpl_num(vpt) == NUM_COUNT) {
			value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false);
			if (!value) {
			oom:
				fr_strerror_const("Out of memory");
				ret = XLAT_ACTION_FAIL;
				goto done;
			}
			value->datum.int32 = 0;
			fr_dlist_insert_tail(out, value);
		} /* Fall through to being done */

		goto done;
	}


	switch (tmpl_num(vpt)) {
	/*
	 *	Return a count of the VPs.
	 */
	case NUM_COUNT:
	{
		uint32_t		count = 0;

		for (vp = fr_dcursor_current(&cursor);
		     vp;
		     vp = fr_dcursor_next(&cursor)) count++;

		value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false);
		value->datum.uint32 = count;
		fr_dlist_insert_tail(out, value);
		break;
	}

	/*
	 *	Output multiple #value_box_t, one per attribute.
	 */
	case NUM_ALL:
		if (!fr_dcursor_current(&cursor)) goto done;

		/*
		 *	Loop over all matching #fr_value_pair
		 *	shallow copying buffers.
		 */
		for (vp = fr_dcursor_current(&cursor);	/* Initialised above to the first matching attribute */
		     vp;
		     vp = fr_dcursor_next(&cursor)) {
		     	value = fr_value_box_alloc(ctx, vp->data.type, vp->da, vp->data.tainted);
			fr_value_box_copy(value, value, &vp->data);
			fr_dlist_insert_tail(out, value);
		}
		break;

	default:
		/*
		 *	The cursor was set to the correct
		 *	position above by tmpl_pair_cursor_init.
		 */
		vp = fr_dcursor_current(&cursor);			/* NULLness checked above */
		value = fr_value_box_alloc(ctx, vp->data.type, vp->da, vp->data.tainted);
		if (!value) goto oom;

		fr_value_box_copy(value, value, &vp->data);	/* Also dups taint */
		fr_dlist_insert_tail(out, value);
		break;
	}

done:
	tmpl_pair_cursor_clear(&cc);
	return ret;
}

/** Signal an xlat function
 *
 * @param[in] signal		function to call.
 * @param[in] exp		Xlat node that previously yielded.
 * @param[in] request		The current request.
 * @param[in] rctx		Opaque (to us), resume ctx provided by the xlat function
 *				when it yielded.
 * @param[in] action		What the request should do (the type of signal).
 */
void xlat_signal(xlat_func_signal_t signal, xlat_exp_t const *exp,
		 request_t *request, void *rctx, fr_state_signal_t action)
{
	xlat_thread_inst_t *t = xlat_thread_instance_find(exp);

	signal(XLAT_CTX(exp->call.inst, t->data, t->mctx, rctx), request, action);
}

/** Call an xlat's resumption method
 *
 * @param[in] ctx		to allocate value boxes in.
 * @param[out] out		a list of #fr_value_box_t to append to.
 * @param[in] resume		function to call.
 * @param[in] exp		Xlat node currently being processed.
 * @param[in] request		the current request.
 * @param[in] result		Previously expanded arguments to this xlat function.
 * @param[in] rctx		Opaque (to us), resume ctx provided by xlat function
 *				when it yielded.
 */
xlat_action_t xlat_frame_eval_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_func_t resume, xlat_exp_t const *exp,
				     request_t *request, fr_value_box_list_t *result, void *rctx)
{
	xlat_thread_inst_t	*t = xlat_thread_instance_find(exp);
	xlat_action_t		xa;

	/*
	 *	It's important that callbacks leave the result list
	 *	in a valid state, as it leads to all kinds of hard
	 *	to debug problems if they free or change elements
	 *	and don't remove them from the list.
	 */
	VALUE_BOX_TALLOC_LIST_VERIFY(result);
	xa = resume(ctx, out, XLAT_CTX(exp->call.inst->data, t->data, t->mctx, rctx), request, result);
	VALUE_BOX_TALLOC_LIST_VERIFY(result);

	RDEBUG2("EXPAND %%%c%s:...%c",
		(exp->call.func->input_type == XLAT_INPUT_ARGS) ? '(' : '{',
		exp->call.func->name,
		(exp->call.func->input_type == XLAT_INPUT_ARGS) ? ')' : '}');
	switch (xa) {
	default:
		break;

	case XLAT_ACTION_YIELD:
		RDEBUG2("   -- YIELD");
		break;

	case XLAT_ACTION_DONE:
		fr_dcursor_next(out);		/* Wind to the start of this functions output */
		RDEBUG2("   --> %pV", fr_dcursor_current(out));
		break;

	case XLAT_ACTION_FAIL:
		break;
	}

	return xa;
}
/** Process the result of a previous nested expansion
 *
 * @param[in] ctx		to allocate value boxes in.
 * @param[out] out		a list of #fr_value_box_t to append to.
 * @param[out] child		to evaluate.  If a child needs to be evaluated
 *				by the caller, we return XLAT_ACTION_PUSH_CHILD
 *				and place the child to be evaluated here.
 *				Once evaluation is complete, the caller
 *				should call us with the same #xlat_exp_t and the
 *				result of the nested evaluation in result.
 * @param[in,out] alternate	Whether we processed, or have previously processed
 *				the alternate.
 * @param[in] request		the current request.
 * @param[in,out] in		xlat node to evaluate.  Advanced as we process
 *				additional #xlat_exp_t.
 * @param[in] result		of a previous nested evaluation.
 */
xlat_action_t xlat_frame_eval_repeat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_exp_t const **child, bool *alternate,
				     request_t *request, xlat_exp_t const **in,
				     fr_value_box_list_t *result)
{
	xlat_exp_t const	*node = *in;

	fr_dcursor_tail(out);	/* Needed for reentrant behaviour and debugging */

	switch (node->type) {
	case XLAT_FUNC:
	{
		xlat_action_t		xa;
		xlat_thread_inst_t	*t;
		fr_value_box_list_t	result_copy;

		t = xlat_thread_instance_find(node);
		fr_assert(t);

		XLAT_DEBUG("** [%i] %s(func-async) - %%%c%s:%pM%c",
			   unlang_interpret_stack_depth(request), __FUNCTION__,
			   (node->call.func->input_type == XLAT_INPUT_ARGS) ? '(' : '{',
			   node->fmt, result,
			   (node->call.func->input_type == XLAT_INPUT_ARGS) ? ')' : '}');

		VALUE_BOX_TALLOC_LIST_VERIFY(result);

		/*
		 *	Always need to init and free the
		 *	copy list as debug level could change
		 *	when the xlat function executes.
		 */
		fr_value_box_list_init(&result_copy);

		/*
		 *	Need to copy the input list in case
		 *	the async function mucks with it.
		 */
		if (RDEBUG_ENABLED2) fr_value_box_list_acopy(NULL, &result_copy, result);
		xa = xlat_process_args(ctx, result, request, node->call.func->input_type, node->call.func->args);
		if (xa == XLAT_ACTION_FAIL) {
			fr_dlist_talloc_free(&result_copy);
			return xa;
		}

		VALUE_BOX_TALLOC_LIST_VERIFY(result);
		xa = node->call.func->func(ctx, out,
					   XLAT_CTX(node->call.inst->data, t->data, t->mctx, NULL),
					   request, result);
		VALUE_BOX_TALLOC_LIST_VERIFY(result);

		if (RDEBUG_ENABLED2) xlat_debug_log_expansion(request, *in, &result_copy);
		fr_dlist_talloc_free(&result_copy);

		switch (xa) {
		case XLAT_ACTION_FAIL:
			return xa;

		case XLAT_ACTION_PUSH_CHILD:
			RDEBUG3("   -- CHILD");
			return xa;

		case XLAT_ACTION_PUSH_UNLANG:
			RDEBUG3("   -- UNLANG");
			return xa;

		case XLAT_ACTION_YIELD:
			RDEBUG3("   -- YIELD");
			return xa;

		case XLAT_ACTION_DONE:				/* Process the result */
			fr_dcursor_next(out);
			xlat_debug_log_result(request, fr_dcursor_current(out));
			break;
		}
	}
		break;

	case XLAT_ALTERNATE:
	{
		fr_dcursor_t from;

		fr_assert(alternate);

		/*
		 *	No result from the first child, try the alternate
		 */
		if (fr_dlist_empty(result)) {
			/*
			 *	Already tried the alternate
			 */
			if (*alternate) {
				XLAT_DEBUG("** [%i] %s(alt-second) - string empty, null expansion, continuing...",
					   unlang_interpret_stack_depth(request), __FUNCTION__);
				*alternate = false;	/* Reset */

				xlat_debug_log_expansion(request, *in, NULL);
				xlat_debug_log_result(request, NULL);		/* Record the fact it's NULL */
				break;
			}

			XLAT_DEBUG("** [%i] %s(alt-first) - string empty, evaluating alternate: %s",
				   unlang_interpret_stack_depth(request), __FUNCTION__, (*in)->alternate->fmt);
			*child = (*in)->alternate;
			*alternate = true;

			return XLAT_ACTION_PUSH_CHILD;
		}

		*alternate = false;	/* Reset */

		xlat_debug_log_expansion(request, *in, NULL);
		xlat_debug_log_list_result(request, result);

		VALUE_BOX_TALLOC_LIST_VERIFY(result);
		fr_dcursor_init(&from, result);
		fr_dcursor_merge(out, &from);
		fr_assert(fr_dlist_empty(result));
	}
		break;

	case XLAT_GROUP:
	{
		fr_value_box_t	*arg;

		XLAT_DEBUG("** [%i] %s(child) - continuing %%{%s ...}", unlang_interpret_stack_depth(request), __FUNCTION__,
			   node->fmt);

		MEM(arg = fr_value_box_alloc(ctx, FR_TYPE_GROUP, NULL, false));

		if (!fr_dlist_empty(result)) {
			VALUE_BOX_TALLOC_LIST_VERIFY(result);
			fr_dlist_move(&arg->vb_group, result);
		}

		xlat_debug_log_expansion(request, *in, NULL);
		xlat_debug_log_result(request, arg);

		VALUE_BOX_VERIFY(arg);

		fr_dcursor_insert(out, arg);
	}
		break;

	default:
		fr_assert(0);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	It's easier if we get xlat_frame_eval to continue evaluating the frame.
	 */
	*in = (*in)->next;	/* advance */
	return xlat_frame_eval(ctx, out, child, request, in);
}

/** Converts xlat nodes to value boxes
 *
 * Evaluates a single level of expansions.
 *
 * @param[in] ctx		to allocate value boxes in.
 * @param[out] out		a list of #fr_value_box_t to append to.
 * @param[out] child		to evaluate.  If a child needs to be evaluated
 *				by the caller, we return XLAT_ACTION_PUSH_CHILD
 *				and place the child to be evaluated here.
 *				Once evaluation is complete, the caller
 *				should call us with the same #xlat_exp_t and the
 *				result of the nested evaluation in result.
 * @param[in] request		the current request.
 * @param[in,out] in		xlat node to evaluate.  Advanced as we process
 *				additional #xlat_exp_t.
 * @return
 *	- XLAT_ACTION_PUSH_CHILD if we need to evaluate a deeper level of nested.
 *	  child will be filled with the node that needs to be evaluated.
 *	  call #xlat_frame_eval_repeat on this node, once there are results
 *	  from the nested expansion.
 *	- XLAT_ACTION_YIELD a resumption frame was pushed onto the stack by an
 *	  xlat function and we need to wait for the request to be resumed
 *	  before continuing.
 *	- XLAT_ACTION_DONE we're done, pop the frame.
 *	- XLAT_ACTION_FAIL an xlat module failed.
 */
xlat_action_t xlat_frame_eval(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_exp_t const **child,
			      request_t *request, xlat_exp_t const **in)
{
	xlat_exp_t const	*node = *in;
	xlat_action_t		xa = XLAT_ACTION_DONE;
	fr_value_box_list_t	result;		/* tmp list so debug works correctly */

	fr_value_box_list_init(&result);

	fr_value_box_t		*value;

	*child = NULL;

	if (!node) return XLAT_ACTION_DONE;

	XLAT_DEBUG("** [%i] %s >> entered", unlang_interpret_stack_depth(request), __FUNCTION__);

	for (node = *in; node; node = (*in)->next) {
	     	*in = node;		/* Update node in our caller */
		fr_dcursor_tail(out);	/* Needed for debugging */
		VALUE_BOX_TALLOC_LIST_VERIFY(out->dlist);

		fr_assert(fr_dlist_num_elements(&result) == 0);	/* Should all have been moved */

		switch (node->type) {
		case XLAT_BOX:
			XLAT_DEBUG("** [%i] %s(value_box) - %s", unlang_interpret_stack_depth(request), __FUNCTION__, node->fmt);

			/*
			 *	Empty boxes are only allowed if
			 *      they're the only node in the expansion.
			 *
			 *	If they're found anywhere else the xlat
			 *	parser has an error.
			 */
			fr_assert(((node == *in) && !node->next) || (talloc_array_length(node->fmt) > 1));

			/*
			 *	We unfortunately need to dup the buffer
			 *	because references aren't threadsafe.
			 */
			MEM(value = fr_value_box_alloc_null(ctx));
			if (fr_value_box_copy(ctx, value, &node->data) < 0) goto fail;
			fr_dcursor_append(out, value);
			continue;

		case XLAT_ONE_LETTER:
			XLAT_DEBUG("** [%i] %s(one-letter) - %%%s", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL);
			if (xlat_eval_one_letter(ctx, &result, request, node->fmt[0]) == XLAT_ACTION_FAIL) {
			fail:
				fr_dlist_talloc_free(&result);
				xa = XLAT_ACTION_FAIL;
				goto finish;
			}
			xlat_debug_log_list_result(request, &result);
			fr_dlist_move(out->dlist, &result);
			continue;

		case XLAT_ATTRIBUTE:
			XLAT_DEBUG("** [%i] %s(attribute) - %%{%s}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL);
			if (xlat_eval_pair_real(ctx, &result, request, node->attr) == XLAT_ACTION_FAIL) goto fail;

			xlat_debug_log_list_result(request, &result);
			fr_dlist_move(out->dlist, &result);
			continue;

		case XLAT_VIRTUAL:
		{
			XLAT_DEBUG("** [%i] %s(virtual) - %%{%s}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL);
			xa = node->call.func->func(ctx, out,
						   XLAT_CTX(node->call.func->uctx, NULL, NULL, NULL),
						   request, NULL);
			fr_dcursor_next(out);

			xlat_debug_log_result(request, fr_dcursor_current(out));
		}
			continue;

		case XLAT_FUNC:
			XLAT_DEBUG("** [%i] %s(func) - %%{%s:...}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			/*
			 *	Hand back the child node to the caller
			 *	for evaluation.
			 */
			if (node->child) {
				*child = node->child;
				xa = XLAT_ACTION_PUSH_CHILD;
				goto finish;
			}

			/*
			 *	If there's no children we can just
			 *	call the function directly.
			 */
			xa = xlat_frame_eval_repeat(ctx, out, child, NULL, request, in, &result);
			if (xa != XLAT_ACTION_DONE || (!*in)) goto finish;
			continue;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
		{
			char *str = NULL;

			XLAT_DEBUG("** [%i] %s(regex) - %%{%s}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL);
			MEM(value = fr_value_box_alloc_null(ctx));
			if (regex_request_to_sub(ctx, &str, request, node->regex_index) < 0) {
				talloc_free(value);
				continue;
			}
			fr_value_box_bstrdup_buffer_shallow(NULL, value, NULL, str, false);

			xlat_debug_log_result(request, value);
			fr_dcursor_append(out, value);
		}
			continue;
#endif

		case XLAT_ALTERNATE:
			XLAT_DEBUG("** [%i] %s(alternate) - %%{%%{%s}:-%%{%s}}", unlang_interpret_stack_depth(request),
				   __FUNCTION__, node->child->fmt, node->alternate->fmt);
			fr_assert(node->child != NULL);
			fr_assert(node->alternate != NULL);

			*child = node->child;
			xa = XLAT_ACTION_PUSH_CHILD;
			goto finish;

		case XLAT_GROUP:
			XLAT_DEBUG("** [%i] %s(child) - %%{%s ...}", unlang_interpret_stack_depth(request), __FUNCTION__,
				   node->fmt);
			if (!node->child) return XLAT_ACTION_DONE;

			/*
			 *	Hand back the child node to the caller
			 *	for evaluation.
			 */
			*child = node->child;
			xa = XLAT_ACTION_PUSH_CHILD;
			goto finish;

		/*
		 *	Should have been fixed up during pass2
		 */
		case XLAT_INVALID:
		case XLAT_FUNC_UNRESOLVED:
		case XLAT_VIRTUAL_UNRESOLVED:
			fr_assert(0);
			return XLAT_ACTION_FAIL;
		}

	}

finish:
	VALUE_BOX_TALLOC_LIST_VERIFY(out->dlist);
	XLAT_DEBUG("** [%i] %s << %s", unlang_interpret_stack_depth(request),
		   __FUNCTION__, fr_table_str_by_value(xlat_action_table, xa, "<INVALID>"));

	return xa;
}

static ssize_t xlat_eval_sync(TALLOC_CTX *ctx, char **out, request_t *request, xlat_exp_t const * const head,
			      xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_value_box_list_t	result;
	bool			success = false;
	TALLOC_CTX		*pool = talloc_new(NULL);
	rlm_rcode_t		rcode;
	char			*str;

	XLAT_DEBUG("xlat_eval_sync");

	*out = NULL;

	fr_value_box_list_init(&result);
	/*
	 *	Use the unlang stack to evaluate
	 *	the async xlat up until the point
	 *	that it needs to yield.
	 */
	if (unlang_xlat_push(pool, &success, &result, request, head, true) < 0) {
		talloc_free(pool);
		return -1;
	}

	rcode = unlang_interpret_synchronous(unlang_interpret_event_list(request), request);
	switch (rcode) {
	default:
		break;

	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	eval_failed:
		RPEDEBUG("xlat evaluation failed");
		talloc_free(pool);
		return -1;
	}
	if (!success) goto eval_failed;

	if (!fr_dlist_empty(&result)) {
		if (escape) {
			fr_value_box_t *vb = NULL;

			/*
			 *	For tainted boxes perform the requested escaping
			 */
			while ((vb = fr_dlist_next(&result, vb))) {
				fr_dlist_t entry;
				size_t len, real_len;
				char *escaped;

				if (!vb->tainted) continue;

				if (fr_value_box_cast_in_place(pool, vb, FR_TYPE_STRING, NULL) < 0) {
					RPEDEBUG("Failed casting result to string");
				error:
					talloc_free(pool);
					return -1;
				}

				len = vb->vb_length * 3;
				escaped = talloc_array(pool, char, len);
				real_len = escape(request, escaped, len, vb->vb_strvalue, UNCONST(void *, escape_ctx));

				entry = vb->entry;
				fr_value_box_clear_value(vb);
				fr_value_box_bstrndup(vb, vb, NULL, escaped, real_len, false);
				vb->entry = entry;

				talloc_free(escaped);
			}
		}

		str = fr_value_box_list_aprint(ctx, &result, NULL, NULL);
		if (!str) {
			RPEDEBUG("Failed concatenating xlat result string");
			talloc_free(pool);
			goto error;
		}
	} else {
		str = talloc_strdup(ctx, "");
	}
	talloc_free(pool);	/* Memory should be in new ctx */

	*out = str;

	return talloc_array_length(str) - 1;
}

/** Replace %whatever in a string.
 *
 * See 'doc/unlang/xlat.adoc' for more information.
 *
 * @param[in] ctx		to allocate expansion buffers in.
 * @param[out] out		Where to write pointer to output buffer.
 * @param[in] outlen		Size of out.
 * @param[in] request		current request.
 * @param[in] node		the xlat structure to expand
 * @param[in] escape		function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx	pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure.
 */
static ssize_t _xlat_eval_compiled(TALLOC_CTX *ctx, char **out, size_t outlen, request_t *request,
				   xlat_exp_t const *node, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	char *buff;
	ssize_t slen;

	fr_assert(node != NULL);

	slen = xlat_eval_sync(ctx, &buff, request, node, escape, escape_ctx);
	if (slen < 0) {
		fr_assert(buff == NULL);
		if (*out) **out = '\0';
		return slen;
	}

	/*
	 *	If out doesn't point to an existing buffer
	 *	copy the pointer to our buffer over.
	 */
	if (!*out) {
		*out = buff;
		return slen;
	}

	/*
	 *	Otherwise copy the talloced buffer to the fixed one.
	 */
	strlcpy(*out, buff, outlen);
	talloc_free(buff);
	return slen;
}

/** Replace %whatever in a string.
 *
 * See 'doc/unlang/xlat.adoc' for more information.
 *
 * @param[in] ctx		to allocate expansion buffers in.
 * @param[out] out		Where to write pointer to output buffer.
 * @param[in] outlen		Size of out.
 * @param[in] request		current request.
 * @param[in] fmt		string to expand.
 * @param[in] escape		function to escape final value e.g. SQL quoting.
 * @param[in] escape_ctx	pointer to pass to escape function.
 * @return length of string written @bug should really have -1 for failure.
 */
static CC_HINT(nonnull (2, 4, 5))
ssize_t _xlat_eval(TALLOC_CTX *ctx, char **out, size_t outlen, request_t *request, char const *fmt,
		   xlat_escape_legacy_t escape, void const *escape_ctx)
{
	ssize_t len;
	xlat_exp_t *node;

	RINDENT();

	/*
	 *	Give better errors than the old code.
	 */
	len = xlat_tokenize_ephemeral(ctx, &node, unlang_interpret_event_list(request), NULL,
				      &FR_SBUFF_IN(fmt, strlen(fmt)),
				      NULL, &(tmpl_rules_t){ .dict_def = request->dict });
	if (len == 0) {
		if (*out) {
			**out = '\0';
		} else {
			*out = talloc_zero_array(ctx, char, 1);
		}
		REXDENT();
		return 0;
	}

	if (len < 0) {
		REMARKER(fmt, -(len), "%s", fr_strerror());
		if (*out) **out = '\0';
		REXDENT();
		return -1;
	}

	len = _xlat_eval_compiled(ctx, out, outlen, request, node, escape, escape_ctx);
	talloc_free(node);

	REXDENT();

	return len;
}

ssize_t xlat_eval(char *out, size_t outlen, request_t *request,
		  char const *fmt, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(done_init);

	return _xlat_eval(request, &out, outlen, request, fmt, escape, escape_ctx);
}

ssize_t xlat_eval_compiled(char *out, size_t outlen, request_t *request,
			   xlat_exp_t const *xlat, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(done_init);

	return _xlat_eval_compiled(request, &out, outlen, request, xlat, escape, escape_ctx);
}

ssize_t xlat_aeval(TALLOC_CTX *ctx, char **out, request_t *request, char const *fmt,
		   xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(done_init);

	*out = NULL;
	return _xlat_eval(ctx, out, 0, request, fmt, escape, escape_ctx);
}

ssize_t xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, request_t *request,
			    xlat_exp_t const *xlat, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	fr_assert(done_init);

	*out = NULL;
	return _xlat_eval_compiled(ctx, out, 0, request, xlat, escape, escape_ctx);
}


/** Synchronous compile xlat_tokenize_argv() into argv[] array.
 *
 *  This is mostly for synchronous evaluation.
 *
 * @param ctx		The talloc_ctx
 * @param[out] argv	the argv array of resulting strings, size is argc + 1
 * @param request	the request
 * @param xlat		from xlat_tokenize_argv()
 * @param escape	escape function
 * @param escape_ctx	context for escape function
 * @return
 *	- <=0 on error	number indicates which argument caused the problem
 *	- >0 on success	which is argc to the corresponding argv
 */
int xlat_aeval_compiled_argv(TALLOC_CTX *ctx, char ***argv, request_t *request,
			     xlat_exp_t const *xlat, xlat_escape_legacy_t escape, void const *escape_ctx)
{
	int			i;
	ssize_t			slen;
	char			**my_argv;
	size_t			count;
	xlat_exp_t const	*node;

	if (xlat->type != XLAT_GROUP) return -1;

	for (count = 0, node = xlat; node != NULL; node = node->next) count++;

	MEM(my_argv = talloc_zero_array(ctx, char *, count + 1));
	*argv = my_argv;

	fr_assert(done_init);

	for (i = 0, node = xlat; node != NULL; i++, node = node->next) {
		my_argv[i] = NULL;

		slen = _xlat_eval_compiled(my_argv, &my_argv[i], 0, request, node->child, escape, escape_ctx);
		if (slen < 0) return -i;
	}

	return count;
}

/** Turn xlat_tokenize_argv() into an argv[] array
 *
 *  This is mostly for async use.
 */
int xlat_flatten_compiled_argv(TALLOC_CTX *ctx, xlat_exp_t const ***argv, xlat_exp_t const *xlat)
{
	int			i;
	xlat_exp_t const	**my_argv;
	xlat_exp_t const	*node;
	size_t			count;

	if (xlat->type != XLAT_GROUP) return -1;

	for (count = 0, node = xlat; node != NULL; node = node->next) count++;

	MEM(my_argv = talloc_zero_array(ctx, xlat_exp_t const *, count + 1));
	*argv = my_argv;

	fr_assert(done_init);

	for (i = 0, node = xlat; node != NULL; i++, node = node->next) {
		my_argv[i] = node->child;
	}

	return count;
}

/** Expands an attribute marked with fr_pair_mark_xlat
 *
 * Writes the new value to the vp.
 *
 * @param request Current request.
 * @param vp to expand.
 * @return On failure pair will still no longer be marked for xlat expansion.
 *	- 0 if successful.
 *	- -1 On xlat failure.
 *	- -2 On parse failure.
 */
int xlat_eval_pair(request_t *request, fr_pair_t *vp)
{
	ssize_t slen;

	char *expanded = NULL;
	if (vp->type != VT_XLAT) return 0;

	vp->type = VT_DATA;

	slen = xlat_aeval(request, &expanded, request, vp->xlat, NULL, NULL);
	talloc_const_free(vp->xlat);
	vp->xlat = NULL;
	if (slen < 0) {
		return -1;
	}

	/*
	 *	Parse the string into a new value.
	 *
	 *	If the fr_pair_t is being used in a regular expression
	 *	then we just want to copy the new value in unmolested.
	 */
	if ((vp->op == T_OP_REG_EQ) || (vp->op == T_OP_REG_NE)) {
		fr_pair_value_bstrdup_buffer(vp, expanded, vp->vp_tainted);
		talloc_free(expanded);
		return 0;
	}

	if (fr_pair_value_from_str(vp, expanded, strlen(expanded), &fr_value_unescape_double, true) < 0){
		talloc_free(expanded);
		return -2;
	}

	talloc_free(expanded);

	return 0;
}

/** Walk over all xlat nodes (depth first) in a xlat expansion, calling a callback
 *
 * @param[in] exp	to evaluate.
 * @param[in] walker	callback to pass nodes to.
 * @param[in] type	if > 0 a mask of types to call walker for.
 * @param[in] uctx	to pass to walker.
 * @return
 *	- 0 on success (walker always returned 0).
 *	- <0 if walker returned <0.
 */
int xlat_eval_walk(xlat_exp_t *exp, xlat_walker_t walker, xlat_type_t type, void *uctx)
{
	xlat_exp_t	*node;
	int		ret;

	/*
	 *	Iterate over nodes at the same depth
	 */
	for (node = exp; node; node = node->next) {
		switch (node->type){
		case XLAT_FUNC:
			if (!type || (type & XLAT_FUNC)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}

			/*
			 *	Now evaluate the function's arguments
			 */
			if (node->child) {
				ret = xlat_eval_walk(node->child, walker, type, uctx);
				if (ret < 0) return ret;
			}
			break;

		case XLAT_FUNC_UNRESOLVED:
			if (!type || (type & XLAT_FUNC_UNRESOLVED)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}

			/*
			 *	Now evaluate the function's arguments
			 */
			if (node->child) {
				ret = xlat_eval_walk(node->child, walker, type, uctx);
				if (ret < 0) return ret;
			}
			break;

		case XLAT_ALTERNATE:
			if (!type || (type & XLAT_ALTERNATE)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}

			/*
			 *	Evaluate the first child
			 */
			ret = xlat_eval_walk(node->child, walker, type, uctx);
			if (ret < 0) return ret;

			/*
			 *	Evaluate the alternate expansion path
			 */
			ret = xlat_eval_walk(node->alternate, walker, type, uctx);
			if (ret < 0) return ret;
			break;

		case XLAT_GROUP:
			if (!type || (type & XLAT_GROUP)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}

			/*
			 *	Evaluate the child.
			 */
			ret = xlat_eval_walk(node->child, walker, type, uctx);
			if (ret < 0) return ret;
			break;

		default:
			if (!type || (type & node->type)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}
		}
	}

	return 0;
}

int xlat_eval_init(void)
{
	fr_assert(!done_init);

	if (fr_dict_autoload(xlat_eval_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(xlat_eval_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(xlat_eval_dict);
		return -1;
	}

	done_init = true;

	return 0;
}

void xlat_eval_free(void)
{
	fr_dict_autofree(xlat_eval_dict);

	done_init = false;
}

/** Return whether or not async is required for this xlat.
 *
 *	If the xlat is needs_async, then it MAY yield
 *	If the xlat is not needs_async, then it will NOT yield
 *
 *	If the xlat yields, then async is required.
 */
bool xlat_async_required(xlat_exp_t const *xlat)
{
	xlat_exp_t const *node;

	if (xlat->type != XLAT_GROUP) {
		return xlat->flags.needs_async;
	}

	/*
	 *	Set needs_async on the entire list.
	 */
	for (node = xlat; node != NULL; node = node->next) {
		if (node->flags.needs_async) return true;
	}

	return false;
}
