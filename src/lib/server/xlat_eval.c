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
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>
#include "xlat_priv.h"

FR_NAME_NUMBER const xlat_action_table[] = {
	{ "push-child",	XLAT_ACTION_PUSH_CHILD	},
	{ "yield",	XLAT_ACTION_YIELD	},
	{ "done",	XLAT_ACTION_DONE	},
	{ "fail",	XLAT_ACTION_FAIL	},

	{  NULL , -1 }
};

static size_t xlat_process(TALLOC_CTX *ctx, char **out, REQUEST *request, xlat_exp_t const * const head,
			   xlat_escape_t escape, void  const *escape_ctx);

/** Check to see if the expansion consists entirely of literal elements
 *
 * @param[in] exp	to check.
 * @return
 *	- true if expansion contains only literal elements.
 *	- false if expansion contains expandable elements.
 */
static inline bool xlat_is_literal(xlat_exp_t const *exp)
{
	xlat_exp_t const *node;

	for (node = exp;
	     node;
	     node = node->next) {
		if (node->type != XLAT_LITERAL) return false;
	}

	return true;
}

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
	case XLAT_LITERAL:
		return talloc_asprintf(ctx, "%s", node->fmt);

	case XLAT_ONE_LETTER:
		return talloc_asprintf(ctx, "%%%s", node->fmt);

	case XLAT_ATTRIBUTE:
		return talloc_asprintf(ctx, "%%{%s}", node->fmt);

	case XLAT_VIRTUAL:
		return talloc_asprintf(ctx, "%%{%s}", node->xlat->name);;

	case XLAT_FUNC:
	{
		xlat_exp_t const 	*child = node->child;
		char		 	*out, *n_out;
		TALLOC_CTX		*pool;

		if (!child) return talloc_asprintf(ctx, "%%{%s:}", node->xlat->name);

		out = talloc_asprintf(ctx, "%%{%s:", node->xlat->name);
		pool = talloc_pool(NULL, 128);	/* Size of a single child (probably ok...) */
		do {
			char *child_str;

			child_str = xlat_fmt_aprint(pool, child);
			if (child_str) {
				n_out = talloc_buffer_append_buffer(out, child_str);
				if (!n_out) {
					talloc_free(out);
					talloc_free(pool);
					return NULL;
				}
				out = n_out;
			}
			talloc_free_children(pool);	/* Clear pool contents */
		} while ((child = child->next));
		talloc_free(pool);

		n_out = talloc_strdup_append_buffer(out, "}");
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
static inline void xlat_debug_log_expansion(REQUEST *request, xlat_exp_t const *node, fr_value_box_t const *args)
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
	if ((node->type == XLAT_FUNC) && !xlat_is_literal(node->child)) {
		RDEBUG2("      (%%{%s:%pM})", node->xlat->name, args);
	}
	talloc_free(str);
}

/** Output the result of an expansion
 *
 * @param[in] request	The current request.
 * @param[in] result	of the expansion.
 */
static inline void xlat_debug_log_result(REQUEST *request, fr_value_box_t const *result)
{
	if (!RDEBUG_ENABLED2) return;

	RDEBUG2("  --> %pM", result);
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
static xlat_action_t xlat_eval_one_letter(TALLOC_CTX *ctx, fr_cursor_t *out, REQUEST *request, char letter)
{

	char		buffer[64];
	struct tm	ts;
	time_t		when = request->packet->timestamp.tv_sec;
	fr_value_box_t	*value;

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
	{
		struct timeval now;

		gettimeofday(&now, NULL);

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL, false));
		value->datum.uint64 = (uint64_t)now.tv_sec;
	}
		break;

	case 'C': /* Current epoch time microsecond component */
	{
		struct timeval now;

		gettimeofday(&now, NULL);

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
		value->datum.uint32 = (uint64_t)now.tv_usec;
	}
		break;

	/*
	 *	Time of the current request
	 */

	case 'd': /* Request day */
		if (!localtime_r(&when, &ts)) {
		error:
			REDEBUG("Failed converting packet timestamp to localtime: %s", fr_syserror(errno));
			return XLAT_ACTION_FAIL;
		}

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_mday;
		break;

	case 'D': /* Request date */
		if (!localtime_r(&when, &ts)) goto error;

		strftime(buffer, sizeof(buffer), "%Y%m%d", &ts);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
		break;

	case 'e': /* Request second */
		if (!localtime_r(&when, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_sec;
		break;

	case 'G': /* Request minute */
		if (!localtime_r(&when, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_min;
		break;

	case 'H': /* Request hour */
		if (!localtime_r(&when, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_hour;
		break;

	case 'l': /* Request timestamp */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_DATE, NULL, false));
		value->datum.date = when;
		break;

	case 'm': /* Request month */
		if (!localtime_r(&when, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT8, NULL, false));
		value->datum.uint8 = ts.tm_mon + 1;
		break;

	case 'M': /* Request time microsecond component */
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
		value->datum.uint32 = request->packet->timestamp.tv_usec;
		break;

	case 'S': /* Request timestamp in SQL format */
		if (!localtime_r(&when, &ts)) goto error;

		strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &ts);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
		break;

	case 't': /* Request timestamp in CTIME format */
	{
		char *p;

		CTIME_R(&when, buffer, sizeof(buffer));
		p = strchr(buffer, '\n');
		if (p) *p = '\0';

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
	}
		break;

	case 'T': /* Request timestamp in ISO format */
	{
		int len = 0;

		if (!gmtime_r(&when, &ts)) goto error;

		if (!(len = strftime(buffer, sizeof(buffer) - 1, "%Y-%m-%dT%H:%M:%S", &ts))) {
			REDEBUG("Failed converting packet timestamp to gmtime: Buffer full");
			return XLAT_ACTION_FAIL;
		}
		strcat(buffer, ".");
		len++;
		snprintf(buffer + len, sizeof(buffer) - len, "%03i", (int) request->packet->timestamp.tv_usec / 1000);

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(value, value, NULL, buffer, false) < 0) goto error;
	}
		break;

	case 'Y': /* Request year */
		if (!localtime_r(&when, &ts)) goto error;

		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT16, NULL, false));

		value->datum.int16 = ts.tm_year + 1900;
		break;

	default:
		rad_assert(0);
		return XLAT_ACTION_FAIL;
	}

	fr_cursor_append(out, value);
	fr_cursor_next(out);				/* Advance to our first value */

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
static xlat_action_t xlat_eval_pair_virtual(TALLOC_CTX *ctx, fr_cursor_t *out, REQUEST *request, vp_tmpl_t const *vpt)
{
	RADIUS_PACKET	*packet = NULL;
	fr_value_box_t	*value;

	/*
	 *	Virtual attributes always have a count of 1
	 */
	if (vpt->tmpl_num == NUM_COUNT) {
		MEM(value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false));
		value->datum.uint32 = 1;
		goto done;
	}

	/*
	 *	Some non-packet expansions
	 */
	switch (vpt->tmpl_da->attr) {
	default:
		break;		/* ignore them */

	case FR_CLIENT_SHORTNAME:
		if (!request->client || !request->client->shortname) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, false));
		if (fr_value_box_strdup_buffer(ctx, value, vpt->tmpl_da, request->client->shortname, false) < 0) {
		error:
			talloc_free(value);
			return XLAT_ACTION_FAIL;
		}
		goto done;

	case FR_REQUEST_PROCESSING_STAGE:
		if (!request->component) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, false));
		if (fr_value_box_strdup_buffer(ctx, value, vpt->tmpl_da, request->component, false) < 0) goto error;
		goto done;

	case FR_VIRTUAL_SERVER:
		if (!request->server_cs) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, false));
		if (fr_value_box_strdup_buffer(ctx, value, vpt->tmpl_da,
					       cf_section_name2(request->server_cs), false) < 0) goto error;
		goto done;

	case FR_MODULE_RETURN_CODE:
		MEM(value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, false));
		value->enumv = vpt->tmpl_da;
		value->datum.int32 = request->rcode;
		goto done;
	}

	/*
	 *	All of the attributes must now refer to a packet.
	 *	If there's no packet, we can't print any attribute
	 *	referencing it.
	 */
	packet = radius_packet(request, vpt->tmpl_list);
	if (!packet) return XLAT_ACTION_DONE;

	switch (vpt->tmpl_da->attr) {
	default:
		RERROR("Attribute \"%s\" incorrectly marked as virtual", vpt->tmpl_da->name);
		return XLAT_ACTION_FAIL;

	case FR_RESPONSE_PACKET_TYPE:
		if (packet != request->reply) {
			RWARN("%%{Response-Packet-Type} is ONLY for responses!");
		}
		packet = request->reply;

		RWARN("Please replace %%{Response-Packet-Type} with %%{reply:Packet-Type}");
		/* FALL-THROUGH */

	case FR_PACKET_TYPE:
		if (!packet || !packet->code) return XLAT_ACTION_DONE;

		MEM(value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, false));
		value->enumv = vpt->tmpl_da;
		value->datum.int32 = packet->code;
		break;

	/*
	 *	Virtual attributes which require a temporary VALUE_PAIR
	 *	to be allocated. We can't use stack allocated memory
	 *	because of the talloc checks sprinkled throughout the
	 *	various VP functions.
	 */
	case FR_PACKET_AUTHENTICATION_VECTOR:
		value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, true);
		fr_value_box_memdup(ctx, value, vpt->tmpl_da, packet->vector, sizeof(packet->vector), true);
		break;

	case FR_CLIENT_IP_ADDRESS:
		if (request->client) {
			value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, false);
			fr_value_box_ipaddr(value, NULL, &request->client->ipaddr, false);	/* Enum might not match type */
			break;
		}
		/* FALL-THROUGH */

	case FR_PACKET_SRC_IP_ADDRESS:
		if (packet->src_ipaddr.af != AF_INET) return XLAT_ACTION_DONE;

		value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, true);
		fr_value_box_ipaddr(value, vpt->tmpl_da, &packet->src_ipaddr, true);
		break;

	case FR_PACKET_DST_IP_ADDRESS:
		if (packet->dst_ipaddr.af != AF_INET) return XLAT_ACTION_DONE;

		value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, true);
		fr_value_box_ipaddr(value, vpt->tmpl_da, &packet->dst_ipaddr, true);
		break;

	case FR_PACKET_SRC_IPV6_ADDRESS:
		if (packet->src_ipaddr.af != AF_INET6) return XLAT_ACTION_DONE;

		value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, true);
		fr_value_box_ipaddr(value, vpt->tmpl_da, &packet->src_ipaddr, true);
		break;

	case FR_PACKET_DST_IPV6_ADDRESS:
		if (packet->dst_ipaddr.af != AF_INET6) return XLAT_ACTION_DONE;

		value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, true);
		fr_value_box_ipaddr(value, vpt->tmpl_da, &packet->dst_ipaddr, true);
		break;

	case FR_PACKET_SRC_PORT:
		value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, true);
		value->datum.uint16 = packet->src_port;
		break;

	case FR_PACKET_DST_PORT:
		value = fr_value_box_alloc(ctx, vpt->tmpl_da->type, NULL, true);
		value->datum.uint16 = packet->dst_port;
		break;
	}

done:
	fr_cursor_append(out, value);
	fr_cursor_next(out);				/* Advance to our first value */

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
 *	- #XLAT_ACTION_DONE		we
 */
static xlat_action_t xlat_eval_pair_real(TALLOC_CTX *ctx, fr_cursor_t *out, REQUEST *request, vp_tmpl_t const *vpt)
{
	VALUE_PAIR	*vp = NULL;
	fr_value_box_t	*value;

	fr_cursor_t	cursor;

	rad_assert((vpt->type == TMPL_TYPE_ATTR) || (vpt->type == TMPL_TYPE_LIST));

	/*
	 *	See if we're dealing with an attribute in the request
	 *
	 *	This allows users to manipulate virtual attributes as if
	 *	they were real ones.
	 */
	vp = tmpl_cursor_init(NULL, &cursor, request, vpt);

	/*
	 *	We didn't find the VP in a list, check to see if it's
	 *	virtual.
	 */
	if (!vp) {
		if (vpt->tmpl_da->flags.virtual) return xlat_eval_pair_virtual(ctx, out, request, vpt);

		/*
		 *	Zero count.
		 */
		if (vpt->tmpl_num == NUM_COUNT) {
			value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false);
			if (!value) {
			oom:
				fr_strerror_printf("Out of memory");
				return XLAT_ACTION_FAIL;
			}
			value->datum.int32 = 0;
			fr_cursor_append(out, value);
			fr_cursor_next(out);			/* Advance to our first value */

			return XLAT_ACTION_DONE;
		}

		return XLAT_ACTION_DONE;
	}


	switch (vpt->tmpl_num) {
	/*
	 *	Return a count of the VPs.
	 */
	case NUM_COUNT:
	{
		uint32_t count = 0;

		for (vp = tmpl_cursor_init(NULL, &cursor, request, vpt);
		     vp;
		     vp = fr_cursor_next(&cursor)) count++;

		value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false);
		value->datum.uint32 = count;
		fr_cursor_append(out, value);
		fr_cursor_next(out);				/* Advance to our first value */

		return XLAT_ACTION_DONE;
	}

	/*
	 *	Output multiple #value_box_t, one per attribute.
	 */
	case NUM_ALL:
		if (!fr_cursor_current(&cursor)) return XLAT_ACTION_DONE;

		/*
		 *	Loop over all matching #fr_value_pair
		 *	shallow copying buffers.
		 */
		for (vp = fr_cursor_current(&cursor);	/* Initialised above to the first matching attribute */
		     vp;
		     vp = fr_cursor_next(&cursor)) {
		     	value = fr_value_box_alloc(ctx, vp->data.type, vp->da, vp->data.tainted);
			fr_value_box_copy(value, value, &vp->data);
			fr_cursor_append(out, value);
		}
		fr_cursor_next(out);				/* Advance to our first value */

		return XLAT_ACTION_DONE;

	default:
		/*
		 *	The cursor was set to the correct
		 *	position above by tmpl_cursor_init.
		 */
		vp = fr_cursor_current(&cursor);			/* NULLness checked above */
		value = fr_value_box_alloc(ctx, vp->data.type, vp->da, vp->data.tainted);
		if (!value) goto oom;

		fr_value_box_copy(value, value, &vp->data);	/* Also dups taint */
		fr_cursor_append(out, value);
		fr_cursor_next(out);				/* Advance to our first value */

		return XLAT_ACTION_DONE;
	}
}

#ifdef DEBUG_XLAT
static const char xlat_spaces[] = "                                                                                                                                                                                                                                                                ";
#endif

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
xlat_action_t xlat_frame_eval_resume(TALLOC_CTX *ctx, fr_cursor_t *out,
				     xlat_func_resume_t resume, xlat_exp_t const *exp,
				     REQUEST *request, fr_value_box_t **result, void *rctx)
{
	xlat_thread_inst_t	*thread_inst = xlat_thread_instance_find(exp);
	xlat_action_t		xa;

	/*
	 *	It's important that callbacks leave the result list
	 *	in a valid state, as it leads to all kinds of hard
	 *	to debug problems if they free or change elements
	 *	and don't remove them from the list.
	 */
	if (*result) (void) talloc_list_get_type_abort(*result, fr_value_box_t);
	xa = resume(ctx, out, request, exp->inst, thread_inst->data, result, rctx);
	if (*result) (void) talloc_list_get_type_abort(*result, fr_value_box_t);

	RDEBUG2("EXPAND %%{%s:...}", exp->xlat->name);
	switch (xa) {
	default:
		break;

	case XLAT_ACTION_YIELD:
		RDEBUG2("   -- YIELD");
		break;

	case XLAT_ACTION_DONE:
		fr_cursor_next(out);		/* Wind to the start of this functions output */
		RDEBUG2("   --> %pM", fr_cursor_current(out));
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
xlat_action_t xlat_frame_eval_repeat(TALLOC_CTX *ctx, fr_cursor_t *out,
				     xlat_exp_t const **child, bool *alternate,
				     REQUEST *request, xlat_exp_t const **in,
				     fr_value_box_t **result)
{
	xlat_exp_t const	*node = *in;

	fr_cursor_tail(out);	/* Needed for reentrant behaviour and debugging */

	switch (node->type) {
	case XLAT_FUNC:
		switch (node->xlat->type) {
		case XLAT_FUNC_SYNC:
		{
			fr_value_box_t	*value;
			char		*str = NULL;
			char		*result_str = NULL;
			ssize_t		slen;

			if (*result) {
				(void) talloc_list_get_type_abort(*result, fr_value_box_t);
				result_str = fr_value_box_list_asprint(NULL, *result, NULL, '\0');
				if (!result_str) return XLAT_ACTION_FAIL;
			} else {
				result_str = talloc_typed_strdup(NULL, "");
			}

			if (node->xlat->buf_len > 0) {
				str = talloc_array(ctx, char, node->xlat->buf_len);
				str[0] = '\0';	/* Be sure the string is \0 terminated */
			}

			XLAT_DEBUG("** [%i] %s(func) - %%{%s:%pV}", unlang_stack_depth(request), __FUNCTION__,
				   node->fmt,
				   fr_box_strvalue_len(result_str, talloc_array_length(result_str) - 1));

			slen = node->xlat->func.sync(ctx, &str, node->xlat->buf_len,
						     node->xlat->mod_inst, NULL, request, result_str);
			xlat_debug_log_expansion(request, *in, *result);
			if (slen < 0) {
				talloc_free(result_str);
				talloc_free(str);
				return XLAT_ACTION_FAIL;
			}
			if (slen == 0) {				/* Zero length result */
				talloc_free(result_str);
				break;
			}
			(void)talloc_get_type_abort(str, char);		/* Check output buffer is sane */

			/*
			 *	Shrink the buffer
			 */
			if ((node->xlat->buf_len > 0) && (slen > 0)) MEM(str = talloc_realloc_bstr(str, (size_t)slen));

			/*
			 *	Fixup talloc lineage and assign the
			 *	output of the function to a box.
			 */
			MEM(value = fr_value_box_alloc_null(ctx));
			fr_value_box_bstrsteal(value, value, NULL, str, false);
			fr_cursor_append(out, value);			/* Append the result of the expansion */
			talloc_free(result_str);
			xlat_debug_log_result(request, value);
		}
			break;

		case XLAT_FUNC_ASYNC:
		{
			xlat_action_t		xa;
			xlat_thread_inst_t	*thread_inst;
			fr_value_box_t		*result_copy = NULL;

			thread_inst = xlat_thread_instance_find(node);

			XLAT_DEBUG("** [%i] %s(func-async) - %%{%s:%pM}", unlang_stack_depth(request), __FUNCTION__,
				   node->fmt, result);

			/*
			 *	Need to copy the input list in case
			 *	the async function mucks with it.
			 */
			if (RDEBUG_ENABLED2) fr_value_box_list_acopy(NULL, &result_copy, *result);

			if (*result) (void) talloc_list_get_type_abort(*result, fr_value_box_t);
			xa = node->xlat->func.async(ctx, out, request, node->inst->data, thread_inst->data, result);
			if (*result) (void) talloc_list_get_type_abort(*result, fr_value_box_t);

			if (RDEBUG_ENABLED2) {
				xlat_debug_log_expansion(request, *in, result_copy);
				talloc_list_free(&result_copy);
			}
			switch (xa) {
			case XLAT_ACTION_FAIL:
				return xa;

			case XLAT_ACTION_PUSH_CHILD:
				RDEBUG2("   -- CHILD");
				return xa;

			case XLAT_ACTION_YIELD:
				RDEBUG2("   -- YIELD");
				return xa;

			case XLAT_ACTION_DONE:				/* Process the result */
				fr_cursor_next(out);
				xlat_debug_log_result(request, fr_cursor_current(out));
				break;
			}
			break;
		}
		}
		break;

	case XLAT_ALTERNATE:
	{
		fr_cursor_t from;

		rad_assert(alternate);

		/*
		 *	No result from the first child, try the alternate
		 */
		if (!*result) {
			/*
			 *	Already tried the alternate
			 */
			if (*alternate) {
				XLAT_DEBUG("** [%i] %s(alt-second) - string empty, null expansion, continuing...",
					   unlang_stack_depth(request), __FUNCTION__);
				*alternate = false;	/* Reset */

				xlat_debug_log_expansion(request, *in, NULL);
				xlat_debug_log_result(request, NULL);		/* Record the fact it's NULL */
				break;
			}

			XLAT_DEBUG("** [%i] %s(alt-first) - string empty, evaluating alternate: %s",
				   unlang_stack_depth(request), __FUNCTION__, (*in)->alternate->fmt);
			*child = (*in)->alternate;
			*alternate = true;

			return XLAT_ACTION_PUSH_CHILD;
		}

		*alternate = false;	/* Reset */

		xlat_debug_log_expansion(request, *in, NULL);
		xlat_debug_log_result(request, *result);

		(void) talloc_list_get_type_abort(*result, fr_value_box_t);
		fr_cursor_init(&from, result);
		fr_cursor_merge(out, &from);
		rad_assert(!*result);
	}
		break;

	default:
		rad_assert(0);
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
xlat_action_t xlat_frame_eval(TALLOC_CTX *ctx, fr_cursor_t *out, xlat_exp_t const **child,
			      REQUEST *request, xlat_exp_t const **in)
{
	xlat_exp_t const	*node = *in;
	xlat_action_t		xa = XLAT_ACTION_DONE;
	fr_value_box_t		*value;

	*child = NULL;

	if (!node) return XLAT_ACTION_DONE;

	XLAT_DEBUG("** [%i] %s >> entered", unlang_stack_depth(request), __FUNCTION__);

	for (node = *in; node; node = (*in)->next) {
	     	*in = node;		/* Update node in our caller */
		fr_cursor_tail(out);	/* Needed for debugging */

		switch (node->type) {
		case XLAT_LITERAL:
			XLAT_DEBUG("** [%i] %s(literal) - %s", unlang_stack_depth(request), __FUNCTION__, node->fmt);

			/*
			 *	We unfortunately need to dup the buffer
			 *	because references aren't threadsafe.
			 */
			MEM(value = fr_value_box_alloc_null(ctx));
			fr_value_box_strdup_buffer(value, value, NULL, node->fmt, false);
			fr_cursor_append(out, value);
			continue;

		case XLAT_ONE_LETTER:
			XLAT_DEBUG("** [%i] %s(one-letter) - %%%s", unlang_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL);
			if (xlat_eval_one_letter(ctx, out, request, node->fmt[0]) == XLAT_ACTION_FAIL) {
			fail:
				fr_cursor_free_list(out);	/* Only frees what we've added during this call */
				xa = XLAT_ACTION_FAIL;
				goto finish;
			}
			xlat_debug_log_result(request, fr_cursor_current(out));
			continue;

		case XLAT_ATTRIBUTE:
			XLAT_DEBUG("** [%i] %s(attribute) - %%{%s}", unlang_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL);
			if (xlat_eval_pair_real(ctx, out, request, node->attr) == XLAT_ACTION_FAIL) goto fail;
			xlat_debug_log_result(request, fr_cursor_current(out));
			continue;

		case XLAT_VIRTUAL:
		{
			char	*str = NULL;
			ssize_t	slen;

			XLAT_DEBUG("** [%i] %s(virtual) - %%{%s}", unlang_stack_depth(request), __FUNCTION__,
				   node->fmt);

			xlat_debug_log_expansion(request, node, NULL);
			slen = node->xlat->func.sync(ctx, &str, node->xlat->buf_len, node->xlat->mod_inst,
						     NULL, request, NULL);
			if (slen < 0) goto fail;
			if (slen == 0) continue;

			MEM(value = fr_value_box_alloc_null(ctx));
			fr_value_box_bstrsteal(value, value, NULL, str, false);
			fr_cursor_append(out, value);
			fr_cursor_next(out);

			xlat_debug_log_result(request, fr_cursor_current(out));
		}
			continue;

		case XLAT_FUNC:
		{
			fr_value_box_t *result = NULL;

			XLAT_DEBUG("** [%i] %s(func) - %%{%s:...}", unlang_stack_depth(request), __FUNCTION__,
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
			if (xa != XLAT_ACTION_DONE) goto finish;
		}
			continue;

#ifdef HAVE_REGEX
		case XLAT_REGEX:
		{
			char *str = NULL;

			XLAT_DEBUG("** [%i] %s(regex) - %%{%s}", unlang_stack_depth(request), __FUNCTION__,
				   node->fmt);
			if (regex_request_to_sub(ctx, &str, request, node->regex_index) < 0) continue;

			/*
			 *	Above call strdups the capture data, so
			 *	we just need to fix up the talloc lineage
			 *	and box it.
			 */
			MEM(value = fr_value_box_alloc_null(ctx));
			fr_value_box_bstrsteal(value, value, NULL, str, false);
			fr_cursor_append(out, value);
		}
			continue;
#endif

		case XLAT_ALTERNATE:
			XLAT_DEBUG("** [%i] %s(alternate) - %%{%%{%s}:-%%{%s}}", unlang_stack_depth(request),
				   __FUNCTION__, node->child->fmt, node->alternate->fmt);
			rad_assert(node->child != NULL);
			rad_assert(node->alternate != NULL);

			*child = node->child;
			xa = XLAT_ACTION_PUSH_CHILD;
			goto finish;
		}
	}

finish:
	XLAT_DEBUG("** [%i] %s << %s", unlang_stack_depth(request),
		   __FUNCTION__, fr_int2str(xlat_action_table, xa, "<INVALID>"));

	return xa;
}

static char *xlat_aprint(TALLOC_CTX *ctx, REQUEST *request, xlat_exp_t const * const node,
			 xlat_escape_t escape, void const *escape_ctx,
#ifndef DEBUG_XLAT
			 UNUSED
#endif
			 int lvl)
{
	ssize_t			slen;
	char			*str = NULL, *child;
	char const		*p;
	fr_value_box_t		*head = NULL, string, *value;
	fr_cursor_t		cursor;

	fr_cursor_talloc_init(&cursor, &head, fr_value_box_t);

	XLAT_DEBUG("%.*sxlat aprint %d %s", lvl, xlat_spaces, node->type, node->fmt);

	switch (node->type) {
		/*
		 *	Don't escape this.
		 */
	case XLAT_LITERAL:
		XLAT_DEBUG("%.*sxlat_aprint LITERAL", lvl, xlat_spaces);
		return talloc_typed_strdup(ctx, node->fmt);

		/*
		 *	Do a one-character expansion.
		 */
	case XLAT_ONE_LETTER:
		if (xlat_eval_one_letter(ctx, &cursor, request, node->fmt[0]) == XLAT_ACTION_FAIL) return NULL;

		/*
		 *	Fixme - In the new xlat code we don't have to
		 *	cast to a string until we're actually doing
		 *	the concatenation.
		 */
		if (fr_value_box_cast(ctx, &string, FR_TYPE_STRING, NULL, head) < 0) {
			RPERROR("Casting one letter expansion to string failed");
			fr_cursor_free_list(&cursor);
			return NULL;
		}
		memcpy(&str, &string.vb_strvalue, sizeof(str));
		fr_cursor_free_list(&cursor);
		break;

	case XLAT_ATTRIBUTE:
		XLAT_DEBUG("xlat_aprint ATTR");
		if (xlat_eval_pair_real(ctx, &cursor, request, node->attr) == XLAT_ACTION_FAIL) return NULL;

		value = fr_cursor_head(&cursor);
		if (!value) return NULL;

		/*
		 *	Fixme - In the new xlat code we don't have to
		 *	cast to a string until we're actually doing
		 *	the concatenation.
		 */
		str = fr_value_box_asprint(ctx, value, '"');
		if (!str) {
		attr_error:
			RPERROR("Printing box to string failed");
			fr_cursor_free_list(&cursor);
			return NULL;
		}

		/*
		 *	Yes this is horrible, but it's only here
		 *	temporarily until we do aggregation with
		 *	value boxes.
		 */
		while ((value = fr_cursor_next(&cursor))) {
			char *more;

			more = fr_value_box_asprint(ctx, value, '"');
			if (!more) goto attr_error;
			str = talloc_strdup_append_buffer(str, ",");
			str = talloc_strdup_append_buffer(str, more);
			talloc_free(more);
		}
		fr_cursor_free_list(&cursor);
		break;

	case XLAT_VIRTUAL:
		XLAT_DEBUG("xlat_aprint VIRTUAL");

		if (node->xlat->buf_len > 0) {
			str = talloc_array(ctx, char, node->xlat->buf_len);
			str[0] = '\0';	/* Be sure the string is \0 terminated */
		}
		slen = node->xlat->func.sync(ctx, &str, node->xlat->buf_len, node->xlat->mod_inst, NULL, request, NULL);
		if (slen < 0) {
			talloc_free(str);
			return NULL;
		}
		RDEBUG2("EXPAND X %s", node->xlat->name);
		RDEBUG2("   --> %s", str);
		break;

	case XLAT_FUNC:
		XLAT_DEBUG("xlat_aprint MODULE");

		if (node->xlat->type == XLAT_FUNC_ASYNC) {
			REDEBUG("Async XLAT function (%s) not allowed here", node->xlat->name);
			return NULL;
		}

		if (node->child) {
			if (xlat_process(ctx, &child, request,
					 node->child, node->xlat->escape, node->xlat->mod_inst) == 0) {
				return NULL;
			}

			XLAT_DEBUG("%.*sEXPAND mod %s %s", lvl, xlat_spaces, node->fmt, node->child->fmt);
		} else {
			XLAT_DEBUG("%.*sEXPAND mod %s", lvl, xlat_spaces, node->fmt);
			child = talloc_typed_strdup(ctx, "");
		}

		XLAT_DEBUG("%.*s      ---> %s", lvl, xlat_spaces, child);

		/*
		 *	Smash \n --> CR.
		 *
		 *	The OUTPUT of xlat is a "raw" string.  The INPUT is a printable string.
		 *
		 *	This is really the reverse of fr_snprint().
		 */
		if (*child) {
			fr_type_t type;
			fr_value_box_t data;

			type = FR_TYPE_STRING;
			if (fr_value_box_from_str(ctx, &data, &type, NULL, child,
						  talloc_array_length(child) - 1, '"', false) < 0) {
				talloc_free(child);
				return NULL;
			}

			talloc_free(child);
			child = data.datum.ptr;

		} else {
			char *q;

			p = q = child;
			while (*p) {
				if (*p == '\\') switch (p[1]) {
					default:
						*(q++) = p[1];
						p += 2;
						continue;

					case 'n':
						*(q++) = '\n';
						p += 2;
						continue;

					case 't':
						*(q++) = '\t';
						p += 2;
						continue;
					}

				*(q++) = *(p++);
			}
			*q = '\0';
		}

		if (node->xlat->buf_len > 0) {
			str = talloc_array(ctx, char, node->xlat->buf_len);
			str[0] = '\0';	/* Be sure the string is \0 terminated */
		}
		slen = node->xlat->func.sync(ctx, &str, node->xlat->buf_len, node->xlat->mod_inst, NULL, request, child);
		talloc_free(child);
		if (slen < 0) {
			talloc_free(str);
			return NULL;
		}
		break;

#ifdef HAVE_REGEX
	case XLAT_REGEX:
		XLAT_DEBUG("%.*sxlat_aprint REGEX", lvl, xlat_spaces);
		if (regex_request_to_sub(ctx, &str, request, node->regex_index) < 0) return NULL;

		break;
#endif

	case XLAT_ALTERNATE:
		XLAT_DEBUG("%.*sxlat_aprint ALTERNATE", lvl, xlat_spaces);
		rad_assert(node->child != NULL);
		rad_assert(node->alternate != NULL);

		/*
		 *	Call xlat_process recursively.  The child /
		 *	alternate nodes may have "next" pointers, and
		 *	those need to be expanded.
		 */
		if (xlat_process(ctx, &str, request, node->child, escape, escape_ctx) > 0) {
			XLAT_DEBUG("%.*sALTERNATE got first string: %s", lvl, xlat_spaces, str);
		} else {
			(void) xlat_process(ctx, &str, request, node->alternate, escape, escape_ctx);
			XLAT_DEBUG("%.*sALTERNATE got alternate string %s", lvl, xlat_spaces, str);
		}
		break;
	}

	/*
	 *	If there's no data, return that, instead of an empty string.
	 */
	if (str && !str[0]) {
		talloc_free(str);
		return NULL;
	}

	/*
	 *	Escape the non-literals we found above.
	 */
	if (str && escape) {
		size_t len;
		char *escaped;
		void *mutable;

		len = talloc_array_length(str) * 3;

		escaped = talloc_array(ctx, char, len);

		memcpy(&mutable, &escape_ctx, sizeof(mutable));
		escape(request, escaped, len, str, mutable);
		talloc_free(str);
		str = escaped;
	}

	return str;
}


static size_t xlat_process(TALLOC_CTX *ctx, char **out, REQUEST *request, xlat_exp_t const * const head,
			   xlat_escape_t escape, void const *escape_ctx)
{
	int i, list;
	size_t total;
	char **array, *answer;
	xlat_exp_t const *node;

	*out = NULL;

	/*
	 *	There are no nodes to process, so the result is a zero
	 *	length string.
	 */
	if (!head) {
		*out = talloc_zero_array(ctx, char, 1);
		return 0;
	}

	/*
	 *	Hack for speed.  If it's one expansion, just allocate
	 *	that and return, instead of allocating an intermediary
	 *	array.
	 */
	if (!head->next) {
		/*
		 *	Pass the MAIN escape function.  Recursive
		 *	calls will call node-specific escape
		 *	functions.
		 */
		answer = xlat_aprint(ctx, request, head, escape, escape_ctx, 0);
		if (!answer) {
			*out = talloc_zero_array(ctx, char, 1);
			return 0;
		}
		*out = answer;
		return strlen(answer);
	}

	list = 0;		/* FIXME: calculate this once */
	for (node = head; node != NULL; node = node->next) {
		list++;
	}

	array = talloc_array(ctx, char *, list);
	if (!array) return -1;

	for (node = head, i = 0; node != NULL; node = node->next, i++) {
		array[i] = xlat_aprint(array, request, node, escape, escape_ctx, 0); /* may be NULL */
	}

	total = 0;
	for (i = 0; i < list; i++) {
		if (array[i]) total += strlen(array[i]); /* FIXME: calculate strlen once */
	}

	if (!total) {
		talloc_free(array);
		*out = talloc_zero_array(ctx, char, 1);
		return 0;
	}

	answer = talloc_array(ctx, char, total + 1);

	total = 0;
	for (i = 0; i < list; i++) {
		size_t len;

		if (array[i]) {
			len = strlen(array[i]);
			memcpy(answer + total, array[i], len);
			total += len;
		}
	}
	answer[total] = '\0';
	talloc_free(array);	/* and child entries */

	*out = answer;
	return total;
}

/** Replace %whatever in a string.
 *
 * See 'doc/configuration/variables.rst' for more information.
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
static ssize_t _xlat_eval_compiled(TALLOC_CTX *ctx, char **out, size_t outlen, REQUEST *request,
				   xlat_exp_t const *node, xlat_escape_t escape, void const *escape_ctx)
{
	char *buff;
	ssize_t len;

	rad_assert(node != NULL);

	len = xlat_process(ctx, &buff, request, node, escape, escape_ctx);
	if ((len < 0) || !buff) {
		rad_assert(buff == NULL);
		if (*out) **out = '\0';
		return len;
	}

	len = strlen(buff);

	/*
	 *	If out doesn't point to an existing buffer
	 *	copy the pointer to our buffer over.
	 */
	if (!*out) {
		*out = buff;
		return len;
	}

	/*
	 *	Otherwise copy the talloced buffer to the fixed one.
	 */
	strlcpy(*out, buff, outlen);
	talloc_free(buff);
	return len;
}

static ssize_t _xlat_eval(TALLOC_CTX *ctx, char **out, size_t outlen, REQUEST *request, char const *fmt,
			  xlat_escape_t escape, void const *escape_ctx) CC_HINT(nonnull (2, 4, 5));

/** Replace %whatever in a string.
 *
 * See 'doc/configuration/variables.rst' for more information.
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
static ssize_t _xlat_eval(TALLOC_CTX *ctx, char **out, size_t outlen, REQUEST *request, char const *fmt,
			  xlat_escape_t escape, void const *escape_ctx)
{
	ssize_t len;
	xlat_exp_t *node;

	RDEBUG2("EXPAND %s", fmt);
	RINDENT();

	/*
	 *	Give better errors than the old code.
	 */
	len = xlat_tokenize_ephemeral(ctx, request, fmt, &node);
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
		if (*out) **out = '\0';
		REXDENT();
		return -1;
	}

	len = _xlat_eval_compiled(ctx, out, outlen, request, node, escape, escape_ctx);
	talloc_free(node);

	REXDENT();
	RDEBUG2("--> %s", *out);

	return len;
}

ssize_t xlat_eval(char *out, size_t outlen, REQUEST *request,
		  char const *fmt, xlat_escape_t escape, void const *escape_ctx)
{
	return _xlat_eval(request, &out, outlen, request, fmt, escape, escape_ctx);
}

ssize_t xlat_eval_compiled(char *out, size_t outlen, REQUEST *request,
			   xlat_exp_t const *xlat, xlat_escape_t escape, void const *escape_ctx)
{
	return _xlat_eval_compiled(request, &out, outlen, request, xlat, escape, escape_ctx);
}

ssize_t xlat_aeval(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *fmt,
		   xlat_escape_t escape, void const *escape_ctx)
{
	*out = NULL;
	return _xlat_eval(ctx, out, 0, request, fmt, escape, escape_ctx);
}

ssize_t xlat_aeval_compiled(TALLOC_CTX *ctx, char **out, REQUEST *request,
			    xlat_exp_t const *xlat, xlat_escape_t escape, void const *escape_ctx)
{
	*out = NULL;
	return _xlat_eval_compiled(ctx, out, 0, request, xlat, escape, escape_ctx);
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
int xlat_eval_pair(REQUEST *request, VALUE_PAIR *vp)
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
	 *	If the VALUE_PAIR is being used in a regular expression
	 *	then we just want to copy the new value in unmolested.
	 */
	if ((vp->op == T_OP_REG_EQ) || (vp->op == T_OP_REG_NE)) {
		fr_pair_value_strsteal(vp, expanded);
		return 0;
	}

	if (fr_pair_value_from_str(vp, expanded, -1, '"', true) < 0){
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
int xlat_eval_walk(xlat_exp_t *exp, xlat_walker_t walker, xlat_state_t type, void *uctx)
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

		case XLAT_ALTERNATE:
			if (!type || (type & XLAT_ALTERNATE)) {
				ret = walker(node, uctx);
				if (ret < 0) return ret;
			}

			/*
			 *	Evaluate the alternate expansion path
			 */
			ret = xlat_eval_walk(node->alternate, walker, type, uctx);
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

