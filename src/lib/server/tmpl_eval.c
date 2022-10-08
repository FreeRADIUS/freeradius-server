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
 * @brief #fr_pair_t template functions
 * @file src/lib/server/tmpl_eval.c
 *
 * @ingroup AVP
 *
 * @copyright 2014-2020 The FreeRADIUS server project
 */
RCSID("$Id$")

#define _TMPL_PRIVATE 1

#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/exec_legacy.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/server/client.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/edit.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t tmpl_dict[];
fr_dict_autoload_t tmpl_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" }, /* @todo - remove RADIUS from the server core... */
	{ NULL }
};

static fr_dict_attr_t const *attr_client_ip_address;
static fr_dict_attr_t const *attr_client_shortname;
static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_packet_authentication_vector;
static fr_dict_attr_t const *attr_request_processing_stage;
static fr_dict_attr_t const *attr_virtual_server;
static fr_dict_attr_t const *attr_module_return_code;

static fr_dict_attr_autoload_t tmpl_dict_attr[] = {
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

/** Resolve a #tmpl_t into an #fr_pair_t
 *
 * @param[in] request containing the target lists.
 * @param[in] vpt tmpl to resolve
 * @return a pointer to the list in the #request_t.
 *
 * @This is just a temporary hack.
 */
fr_pair_t *tmpl_get_list(request_t *request, tmpl_t const *vpt)
{
	tmpl_pair_list_t list;

	if (!request) return NULL;

	if (vpt->rules.attr.list_as_attr) {
		fr_dict_attr_t const *da;
		da = ((tmpl_attr_t *)tmpl_attr_list_head(&vpt->data.attribute.ar))->ar_da;

		if (da == request_attr_request) return request->pair_list.request;
		if (da == request_attr_reply) return request->pair_list.reply;
		if (da == request_attr_control) return request->pair_list.control;
		if (da == request_attr_state) return request->pair_list.state;

		return NULL;
	}

	list = tmpl_list(vpt);

	switch (list) {
	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;

	case PAIR_LIST_REQUEST:
		return request->pair_list.request;

	case PAIR_LIST_REPLY:
		return request->pair_list.reply;

	case PAIR_LIST_CONTROL:
		return request->pair_list.control;

	case PAIR_LIST_STATE:
		return request->pair_list.state;
	}

	RWDEBUG2("List \"%s\" is not available",
		fr_table_str_by_value(pair_list_table, list, "<INVALID>"));

	return NULL;
}


/** Resolve attribute #pair_list_t value to an attribute list.
 *
 * The value returned is a pointer to the pointer of the HEAD of a #fr_pair_t list in the
 * #request_t. If the head of the list changes, the pointer will still be valid.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_list_t value to resolve to #fr_pair_t list. Will be NULL if list
 *	name couldn't be resolved.
 * @return a pointer to the HEAD of a list in the #request_t.
 *
 * @see tmpl_dcursor_init
 */
fr_pair_list_t *tmpl_list_head(request_t *request, tmpl_pair_list_t list)
{
	if (!request) return NULL;

	switch (list) {
	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;

	case PAIR_LIST_REQUEST:
		if (!request->packet) return NULL;
		return &request->request_pairs;

	case PAIR_LIST_REPLY:
		if (!request->reply) return NULL;
		return &request->reply_pairs;

	case PAIR_LIST_CONTROL:
		return &request->control_pairs;

	case PAIR_LIST_STATE:
		return &request->session_state_pairs;
	}

	RWDEBUG2("List \"%s\" is not available",
		fr_table_str_by_value(pair_list_table, list, "<INVALID>"));

	return NULL;
}

/** Return the correct TALLOC_CTX to alloc #fr_pair_t in, for a list
 *
 * Allocating new #fr_pair_t in the context of a #request_t is usually wrong.
 * #fr_pair_t should be allocated in the context of a #fr_radius_packet_t, so that if the
 * #fr_radius_packet_t is freed before the #request_t, the associated #fr_pair_t lists are
 * freed too.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_list_t value to resolve to TALLOC_CTX.
 * @return
 *	- TALLOC_CTX on success.
 *	- NULL on failure.
 *
 * @see tmpl_pair_list
 */
TALLOC_CTX *tmpl_list_ctx(request_t *request, tmpl_pair_list_t list)
{
	if (!request) return NULL;

	switch (list) {
	case PAIR_LIST_REQUEST:
		return request->request_ctx;

	case PAIR_LIST_REPLY:
		return request->reply_ctx;

	case PAIR_LIST_CONTROL:
		return request->control_ctx;

	case PAIR_LIST_STATE:
		return request->session_state_ctx;

	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;
	}

	return NULL;
}

/** Resolve a list to the #fr_radius_packet_t holding the HEAD pointer for a #fr_pair_t list
 *
 * Returns a pointer to the #fr_radius_packet_t that holds the HEAD pointer of a given list,
 * for the current #request_t.
 *
 * @param[in] request To resolve list in.
 * @param[in] list #pair_list_t value to resolve to #fr_radius_packet_t.
 * @return
 *	- #fr_radius_packet_t on success.
 *	- NULL on failure.
 *
 * @see tmpl_pair_list
 */
fr_radius_packet_t *tmpl_packet_ptr(request_t *request, tmpl_pair_list_t list)
{
	switch (list) {
	/* Don't add default */
	case PAIR_LIST_STATE:
	case PAIR_LIST_CONTROL:
	case PAIR_LIST_UNKNOWN:
		return NULL;

	case PAIR_LIST_REQUEST:
		return request->packet;

	case PAIR_LIST_REPLY:
		return request->reply;
	}

	return NULL;
}

/** Resolve a #tmpl_request_ref_t to a #request_t.
 *
 * Sometimes #request_t structs may be chained to each other, as is the case
 * when internally proxying EAP. This function resolves a #tmpl_request_ref_t
 * to a #request_t higher in the chain than the current #request_t.
 *
 * @see tmpl_pair_list
 * @param[in,out] context	#request_t to start resolving from, and where to write
 *				a pointer to the resolved #request_t back to.
 * @param[in] rql		list of request qualifiers to follow.
 * @return
 *	- 0 if request is valid in this context.
 *	- -1 if request is not valid in this context.
 */
int tmpl_request_ptr(request_t **context, FR_DLIST_HEAD(tmpl_request_list) const *rql)
{
	tmpl_request_t *rr = NULL;
	request_t *request = *context;

	while ((rr = tmpl_request_list_next(rql, rr))) {
		switch (rr->request) {
		case REQUEST_CURRENT:
			continue;	/* noop */

		case REQUEST_PARENT:	/* Navigate up one level */
			if (!request->parent) return -1;
			request = request->parent;
			break;

		case REQUEST_OUTER:	/* Navigate to the outermost request */
			if (!request->parent) return -1;
			while (request->parent) request = request->parent;
			break;

		case REQUEST_UNKNOWN:
		default:
			fr_assert(0);
			return -1;
		}
	}

	*context = request;

	return 0;
}

/** Return the native data type of the expression
 *
 * @param[in] vpt	to determine the type of.
 * @return
 *	- FR_TYPE_NULL if the type of the #tmpl_t can't be determined.
 *	- The data type we'd expect the #tmpl_t to produce at runtime
 *	  when expanded.
 */
fr_type_t tmpl_expanded_type(tmpl_t const *vpt)
{
	/*
	 *	Regexes can't be expanded
	 */
	if (tmpl_contains_regex(vpt)) return FR_TYPE_NULL;

	/*
	 *	Casts take precedence over everything.
	 */
	if (tmpl_rules_cast(vpt) != FR_TYPE_NULL) return tmpl_rules_cast(vpt);

	/*
	 *	Anything that's not a bare word will
	 *	be a string unless there's a casting
	 *	operator.
	 */
	if (vpt->quote != T_BARE_WORD) return FR_TYPE_STRING;

	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
		return tmpl_da(vpt)->type;

	case TMPL_TYPE_DATA:
		return tmpl_value_type(vpt);

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_EXEC:
		return FR_TYPE_STRING;

	default:
		break;
	}

	return FR_TYPE_NULL;
}

/** Expand a #tmpl_t to a string writing the result to a buffer
 *
 * The intended use of #tmpl_expand and #tmpl_aexpand is for modules to easily convert a #tmpl_t
 * provided by the conf parser, into a usable value.
 * The value returned should be raw and undoctored for #FR_TYPE_STRING and #FR_TYPE_OCTETS types,
 * and the printable (string) version of the data for all others.
 *
 * Depending what arguments are passed, either copies the value to buff, or writes a pointer
 * to a string buffer to out. This allows the most efficient access to the value resolved by
 * the #tmpl_t, avoiding unecessary string copies.
 *
 * @note This function is used where raw string values are needed, which may mean the string
 *	returned may be binary data or contain unprintable chars. #fr_snprint or #fr_asprint
 *	should be used before using these values in debug statements. #is_printable can be used to
 *	check if the string only contains printable chars.
 *
 * @param[out] out		Where to write a pointer to the string buffer. On return may
 *				point to buff if buff was used to store the value. Otherwise will
 *				point to a #fr_value_box_t buffer, or the name of the template.
 *				Must not be NULL.
 * @param[out] buff		Expansion buffer, may be NULL except for the following types:
 *				- #TMPL_TYPE_EXEC
 *				- #TMPL_TYPE_XLAT
 * @param[in] bufflen		Length of expansion buffer. Must be >= 2.
 * @param[in] request		Current request.
 * @param[in] vpt		to expand. Must be one of the following types:
 *				- #TMPL_TYPE_UNRESOLVED
 *				- #TMPL_TYPE_EXEC
 *				- #TMPL_TYPE_XLAT
 *				- #TMPL_TYPE_ATTR
 *				- #TMPL_TYPE_DATA
 * @param[in] escape		xlat escape function (only used for xlat types).
 * @param[in] escape_ctx	xlat escape function data.
 * @param dst_type		FR_TYPE_* matching out pointer.  @see tmpl_expand.
 * @return
 *	- -1 on failure.
 *	- The length of data written out.
 */
ssize_t _tmpl_to_type(void *out,
		      uint8_t *buff, size_t bufflen,
		      request_t *request,
		      tmpl_t const *vpt,
		      xlat_escape_legacy_t escape, void const *escape_ctx,
		      fr_type_t dst_type)
{
	fr_value_box_t		value_to_cast;
	fr_value_box_t		value_from_cast = { .type = FR_TYPE_NULL };
	fr_value_box_t const	*to_cast = &value_to_cast;
	fr_value_box_t const	*from_cast = &value_from_cast;

	fr_pair_t		*vp = NULL;

	fr_type_t		src_type = FR_TYPE_NULL;

	ssize_t			slen = -1;	/* quiet compiler */

	TMPL_VERIFY(vpt);

	fr_assert(!tmpl_is_list(vpt));
	fr_assert(!buff || (bufflen >= 2));

	switch (vpt->type) {
	case TMPL_TYPE_UNRESOLVED:
		RDEBUG4("EXPAND TMPL UNRESOLVED");
		fr_value_box_bstrndup_shallow(&value_to_cast, NULL, vpt->name, vpt->len, false);
		src_type = FR_TYPE_STRING;
		break;

	case TMPL_TYPE_EXEC:
	{
		RDEBUG4("EXPAND TMPL EXEC");
		if (!buff) {
			fr_strerror_const("Missing expansion buffer for EXEC");
			return -1;
		}

		if (radius_exec_program_legacy(request, (char *)buff, bufflen, NULL, request, vpt->name, NULL,
					true, false, fr_time_delta_from_sec(EXEC_TIMEOUT)) != 0) return -1;
		fr_value_box_strdup_shallow(&value_to_cast, NULL, (char *)buff, true);
		src_type = FR_TYPE_STRING;
	}
		break;

	case TMPL_TYPE_XLAT:
	{
		size_t len;

		RDEBUG4("EXPAND TMPL XLAT PARSED");

		/* No EXPAND <xlat> here as the xlat code does it */

		if (!buff) {
			fr_strerror_const("Missing expansion buffer for XLAT_STRUCT");
			return -1;
		}
		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_eval_compiled((char *)buff, bufflen, request, tmpl_xlat(vpt), escape, escape_ctx);
		if (slen < 0) return slen;

		RDEBUG2("   --> %s", (char *)buff);	/* Print pre-unescaping (so it's escaped) */

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		len = fr_value_str_unescape(&FR_SBUFF_IN((char *)buff, slen),
					    &FR_SBUFF_IN((char *)buff, slen), SIZE_MAX, '"');
		fr_assert(buff);
		fr_value_box_bstrndup_shallow(&value_to_cast, NULL, (char *)buff, len, true);
		src_type = FR_TYPE_STRING;
	}
		break;

	case TMPL_TYPE_ATTR:
	{
		int ret;

		RDEBUG4("EXPAND TMPL ATTR");
		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) return -2;

		to_cast = &vp->data;
		src_type = vp->da->type;
	}
		break;

	case TMPL_TYPE_DATA:
		RDEBUG4("EXPAND TMPL DATA");
		to_cast = tmpl_value(vpt);
		src_type = tmpl_value_type(vpt);
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_EXEC_UNRESOLVED:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
		return -1;
	}

	/*
	 *	Deal with casts.
	 */
	switch (src_type) {
	case FR_TYPE_STRING:
		switch (dst_type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			from_cast = to_cast;
			break;

		default:
			break;
		}
		break;

	case FR_TYPE_OCTETS:
		switch (dst_type) {
		/*
		 *	Need to use the expansion buffer for this conversion as
		 *	we need to add a \0 terminator.
		 */
		case FR_TYPE_STRING:
			if (!buff) {
				fr_strerror_const("Missing expansion buffer for octet->string cast");
				return -1;
			}
			if (bufflen <= to_cast->vb_length) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen,
						   to_cast->vb_length + 1);
				return -1;
			}
			memcpy(buff, to_cast->vb_octets, to_cast->vb_length);
			buff[to_cast->vb_length] = '\0';

			fr_value_box_bstrndup_shallow(&value_from_cast, NULL,
						      (char *)buff, to_cast->vb_length, true);
			break;

		/*
		 *	Just copy the pointer.  Length does not include \0.
		 */
		case FR_TYPE_OCTETS:
			from_cast = to_cast;
			break;

		default:
			break;
		}
		break;

	default:
	{
		int		ret;
		TALLOC_CTX	*ctx;

		/*
		 *	Same type, just set from_cast to to_cast and copy the value.
		 */
		if (src_type == dst_type) {
			from_cast = to_cast;
			break;
		}

		MEM(ctx = talloc_new(request));

		from_cast = &value_from_cast;

		/*
		 *	Data type conversion...
		 */
		ret = fr_value_box_cast(ctx, &value_from_cast, dst_type, NULL, to_cast);
		if (ret < 0) goto error;


		/*
		 *	For the dynamic types we need to copy the output
		 *	to the buffer.  Really we need a version of fr_value_box_cast
		 *	that works with buffers, but it's not a high priority...
		 */
		switch (dst_type) {
		case FR_TYPE_STRING:
			if (!buff) {
				fr_strerror_const("Missing expansion buffer to store cast output");
			error:
				talloc_free(ctx);
				return -1;
			}
			if (from_cast->vb_length >= bufflen) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen,
						   from_cast->vb_length + 1);
				goto error;
			}
			memcpy(buff, from_cast->vb_strvalue, from_cast->vb_length);
			buff[from_cast->vb_length] = '\0';

			fr_value_box_bstrndup_shallow(&value_from_cast, NULL,
						      (char *)buff, from_cast->vb_length, from_cast->tainted);
			break;

		case FR_TYPE_OCTETS:
			if (!buff) {
				fr_strerror_const("Missing expansion buffer to store cast output");
				goto error;
			}
			if (from_cast->vb_length > bufflen) {
				fr_strerror_printf("Expansion buffer too small.  "
						   "Have %zu bytes, need %zu bytes", bufflen, from_cast->vb_length);
				goto error;
			}
			memcpy(buff, from_cast->vb_octets, from_cast->vb_length);
			fr_value_box_memdup_shallow(&value_from_cast, NULL,
						    buff, from_cast->vb_length, from_cast->tainted);
			break;

		default:
			break;
		}

		talloc_free(ctx);	/* Free any dynamically allocated memory from the cast */
	}
	}

	RDEBUG4("Copying %zu bytes to %p from offset %zu",
		fr_value_box_field_sizes[dst_type], *((void **)out), fr_value_box_offsets[dst_type]);

	fr_value_box_memcpy_out(out, from_cast);

	return from_cast->vb_length;
}

/** Expand a template to a string, allocing a new buffer to hold the string
 *
 * The intended use of #tmpl_expand and #tmpl_aexpand is for modules to easily convert a #tmpl_t
 * provided by the conf parser, into a usable value.
 * The value returned should be raw and undoctored for #FR_TYPE_STRING and #FR_TYPE_OCTETS types,
 * and the printable (string) version of the data for all others.
 *
 * This function will always duplicate values, whereas #tmpl_expand may return a pointer to an
 * existing buffer.
 *
 * @note This function is used where raw string values are needed, which may mean the string
 *	returned may be binary data or contain unprintable chars. #fr_snprint or #fr_asprint should
 *	be used before using these values in debug statements. #is_printable can be used to check
 *	if the string only contains printable chars.
 *
 * @note The type (char or uint8_t) can be obtained with talloc_get_type, and may be used as a
 *	hint as to how to process or print the data.
 *
 * @param ctx		to allocate new buffer in.
 * @param out		Where to write pointer to the new buffer.
 * @param request	Current request.
 * @param vpt		to expand. Must be one of the following types:
 *			- #TMPL_TYPE_UNRESOLVED
 *			- #TMPL_TYPE_EXEC
 *			- #TMPL_TYPE_XLAT
 *			- #TMPL_TYPE_ATTR
 *			- #TMPL_TYPE_DATA
 * @param escape xlat	escape function (only used for TMPL_TYPE_XLAT_UNRESOLVED_* types).
 * @param escape_ctx	xlat escape function data (only used for TMPL_TYPE_XLAT_UNRESOLVED_* types).
 * @param dst_type	FR_TYPE_* matching out pointer.  @see tmpl_aexpand.
 * @return
 *	- -1 on failure.
 *	- The length of data written to buff, or pointed to by out.
 */
ssize_t _tmpl_to_atype(TALLOC_CTX *ctx, void *out,
		       request_t *request,
		       tmpl_t const *vpt,
		       xlat_escape_legacy_t escape, void const *escape_ctx,
		       fr_type_t dst_type)
{
	fr_value_box_t		*to_cast = NULL;
	fr_value_box_t		from_cast;

	fr_pair_t		*vp = NULL;
	fr_value_box_t		value = (fr_value_box_t){};
	bool			needs_dup = false;

	ssize_t			slen = -1;
	int			ret;

	TALLOC_CTX		*tmp_ctx = talloc_new(ctx);

	TMPL_VERIFY(vpt);

	switch (vpt->type) {
	case TMPL_TYPE_UNRESOLVED:
		RDEBUG4("EXPAND TMPL UNRESOLVED");

		fr_value_box_bstrndup_shallow(&value, NULL, vpt->name, vpt->len, false);
		to_cast = &value;
		needs_dup = true;
		break;

	case TMPL_TYPE_EXEC:
	{
		char *buff;

		RDEBUG4("EXPAND TMPL EXEC");

		MEM(fr_value_box_bstr_alloc(tmp_ctx, &buff, &value, NULL, 1024, true));
		if (radius_exec_program_legacy(request, buff, 1024, NULL, request, vpt->name, NULL,
					true, false, fr_time_delta_from_sec(EXEC_TIMEOUT)) != 0) {
		error:
			talloc_free(tmp_ctx);
			return slen;
		}
		fr_value_box_strtrim(tmp_ctx, &value);
		to_cast = &value;
	}
		break;

	case TMPL_TYPE_XLAT_UNRESOLVED:
	{
		fr_value_box_t	tmp;
		fr_type_t	src_type = FR_TYPE_STRING;
		char		*result;

		RDEBUG4("EXPAND TMPL XLAT");

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval(tmp_ctx, &result, request, vpt->name, escape, escape_ctx);
		if (slen < 0) goto error;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, src_type, NULL,
					    result, (size_t)slen,
					    NULL, false);
		if (ret < 0) goto error;

		fr_value_box_bstrndup_shallow(&value, NULL, tmp.vb_strvalue, tmp.vb_length, tmp.tainted);
		to_cast = &value;
	}
		break;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_REGEX_XLAT:
	{
		fr_value_box_t	tmp;
		fr_type_t	src_type = FR_TYPE_STRING;
		char		*result;

		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		/* No EXPAND xlat here as the xlat code does it */

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval_compiled(tmp_ctx, &result, request, tmpl_xlat(vpt), escape, escape_ctx);
		if (slen < 0) goto error;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, src_type, NULL,
					    result, (size_t)slen,
					    NULL, false);
		if (ret < 0) goto error;

		fr_value_box_bstrndup_shallow(&value, NULL, tmp.vb_strvalue, tmp.vb_length, tmp.tainted);
		to_cast = &value;
	}
		break;

	case TMPL_TYPE_ATTR:
		RDEBUG4("EXPAND TMPL ATTR");

		ret = tmpl_find_vp(&vp, request, vpt);
		if (ret < 0) {
			talloc_free(tmp_ctx);
			return -2;
		}

		fr_assert(vp);

		to_cast = &vp->data;
		switch (to_cast->type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			fr_assert(to_cast->datum.ptr);
			needs_dup = true;
			break;

		default:
			break;
		}
		break;

	case TMPL_TYPE_DATA:
	{
		RDEBUG4("EXPAND TMPL DATA");

		to_cast = UNCONST(fr_value_box_t *, tmpl_value(vpt));
		switch (to_cast->type) {
		case FR_TYPE_STRING:
		case FR_TYPE_OCTETS:
			fr_assert(to_cast->datum.ptr);
			needs_dup = true;
			break;

		default:
			break;
		}
	}
		break;

	/*
	 *	We should never be expanding these.
	 */
	case TMPL_TYPE_UNINITIALISED:
	case TMPL_TYPE_NULL:
	case TMPL_TYPE_LIST:
	case TMPL_TYPE_EXEC_UNRESOLVED:
	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
	case TMPL_TYPE_ATTR_UNRESOLVED:
	case TMPL_TYPE_MAX:
		fr_assert(0);
		goto error;
	}

	/*
	 *	Special case where we just copy the boxed value
	 *	directly instead of casting it.
	 */
	if (dst_type == FR_TYPE_VALUE_BOX) {
		fr_value_box_t	**vb_out = (fr_value_box_t **)out;

		MEM(*vb_out = fr_value_box_alloc_null(ctx));

		ret = needs_dup ? fr_value_box_copy(ctx, *vb_out, to_cast) : fr_value_box_steal(ctx, *vb_out, to_cast);
		talloc_free(tmp_ctx);
		if (ret < 0) {
			RPEDEBUG("Failed copying data to output box");
			TALLOC_FREE(*vb_out);
			return -1;
		}
		return 0;
	}

	/*
	 *	Don't dup the buffers unless we need to.
	 */
	if ((to_cast->type != dst_type) || needs_dup) {
		ret = fr_value_box_cast(ctx, &from_cast, dst_type, NULL, to_cast);
		if (ret < 0) goto error;
	} else {
		switch (to_cast->type) {
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
			/*
			 *	Ensure we don't free the output buffer when the
			 *	tmp_ctx is freed.
			 */
			if (value.datum.ptr && (talloc_parent(value.datum.ptr) == tmp_ctx)) {
				(void)talloc_reparent(tmp_ctx, ctx, value.datum.ptr);
			}
			break;

		default:
			break;
		}
		fr_value_box_copy_unsafe(&from_cast, to_cast);
	}

	RDEBUG4("Copying %zu bytes to %p from offset %zu",
		fr_value_box_field_sizes[dst_type], *((void **)out), fr_value_box_offsets[dst_type]);

	fr_value_box_memcpy_out(out, &from_cast);

	/*
	 *	Frees any memory allocated for temporary buffers
	 *	in this function.
	 */
	talloc_free(tmp_ctx);

	return from_cast.vb_length;
}

/** Copy pairs matching a #tmpl_t in the current #request_t
 *
 * @param ctx to allocate new #fr_pair_t in.
 * @param out Where to write the copied #fr_pair_t (s).
 * @param request The current #request_t.
 * @param vpt specifying the #fr_pair_t type or list to copy.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- -1 if no matching #fr_pair_t could be found.
 *	- -2 if list could not be found (doesn't exist in current #request_t).
 *	- -3 if context could not be found (no parent #request_t available).
 *	- -4 on memory allocation error.
 */
int tmpl_copy_pairs(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request, tmpl_t const *vpt)
{
	fr_pair_t		*vp;
	fr_dcursor_t		from;
	tmpl_dcursor_ctx_t	cc;
	int err;

	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	for (vp = tmpl_dcursor_init(&err, NULL, &cc, &from, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&from)) {
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(out);
			fr_strerror_const("Out of memory");
			err = -4;
			break;
		}
		fr_pair_append(out, vp);
	}
	tmpl_dcursor_clear(&cc);

	return err;
}


/** Copy children of pairs matching a #tmpl_t in the current #request_t
 *
 * @param ctx to allocate new #fr_pair_t in.
 * @param out Where to write the copied #fr_pair_t (s).
 * @param request The current #request_t.
 * @param vpt specifying the #fr_pair_t type or list to copy.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- -1 if no matching #fr_pair_t could be found.
 *	- -2 if list could not be found (doesn't exist in current #request_t).
 *	- -3 if context could not be found (no parent #request_t available).
 *	- -4 on memory allocation error.
 */
int tmpl_copy_pair_children(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request, tmpl_t const *vpt)
{
	fr_pair_t		*vp;
	fr_dcursor_t		from;
	tmpl_dcursor_ctx_t	cc;
	int err;

	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	fr_pair_list_free(out);

	for (vp = tmpl_dcursor_init(&err, NULL, &cc, &from, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&from)) {
	     	switch (vp->da->type) {
	     	case FR_TYPE_STRUCTURAL:
	     		if (fr_pair_list_copy(ctx, out, &vp->vp_group) < 0) {
	     			err = -4;
	     			goto done;
	     		}
	     		break;

		default:
			continue;
	     	}
	}
done:
	tmpl_dcursor_clear(&cc);

	return err;
}


/** Returns the first VP matching a #tmpl_t
 *
 * @param[out] out where to write the retrieved vp.
 * @param[in] request The current #request_t.
 * @param[in] vpt specifying the #fr_pair_t type to find.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- 0 on success (found matching #fr_pair_t).
 *	- -1 if no matching #fr_pair_t could be found.
 *	- -2 if list could not be found (doesn't exist in current #request_t).
 *	- -3 if context could not be found (no parent #request_t available).
 */
int tmpl_find_vp(fr_pair_t **out, request_t *request, tmpl_t const *vpt)
{
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	fr_pair_t		*vp;
	int			err;

	TMPL_VERIFY(vpt);

	vp = tmpl_dcursor_init(&err, request, &cc, &cursor, request, vpt);
	tmpl_dcursor_clear(&cc);

	if (out) *out = vp;

	return err;
}

/** Returns the first VP matching a #tmpl_t, or if no VPs match, creates a new one.
 *
 * @param[out] out where to write the retrieved or created vp.
 * @param[in] request The current #request_t.
 * @param[in] vpt specifying the #fr_pair_t type to retrieve or create.  Must be #TMPL_TYPE_ATTR.
 * @return
 *	- 1 on success a pair was created.
 *	- 0 on success a pair was found.
 *	- -1 if a new #fr_pair_t couldn't be found or created.
 *	- -2 if list could not be found (doesn't exist in current #request_t).
 *	- -3 if context could not be found (no parent #request_t available).
 */
int tmpl_find_or_add_vp(fr_pair_t **out, request_t *request, tmpl_t const *vpt)
{
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	fr_pair_t		*vp;
	int			err;

	TMPL_VERIFY(vpt);
	fr_assert(tmpl_is_attr(vpt));

	*out = NULL;

	vp = tmpl_dcursor_init(&err, NULL, &cc, &cursor, request, vpt);
	tmpl_dcursor_clear(&cc);

	switch (err) {
	case 0:
		*out = vp;
		return 0;

	case -1:
	{
		TALLOC_CTX	*ctx;
		fr_pair_list_t	*head;

		tmpl_pair_list_and_ctx(ctx, head, request, tmpl_request(vpt), tmpl_list(vpt));
		if (!head) return -1;

		MEM(vp = fr_pair_afrom_da(ctx, tmpl_da(vpt)));

		fr_pair_append(head, vp);

		*out = vp;
	}
		return 1;

	default:
		return err;
	}
}

/** Allocate and insert a leaf vp from a tmpl_t, building the parent vps if needed.
 *
 * This is the simple case - just add a vp at the first place where
 * the parents exist, or create the parents, with no attempt to handle filters.
 *
 * It is functionally equivalent to fr_pair_append_by_da_parent() but
 * uses a tmpl_t to build the nested structure rather than a fr_dict_attr_t.
 *
 * @param[in] ctx	to allocate new pair(s) in
 * @param[out] out	Leaf pair we allocated.
 * @param[in] list	to insert into.
 * @param[in] vpt	tmpl representing the attribute to add.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int pair_append_by_tmpl_parent(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list, tmpl_t const *vpt)
{
	fr_pair_t			*vp = NULL;
	TALLOC_CTX			*pair_ctx = ctx;
	tmpl_attr_t			*ar, *leaf;
	tmpl_attr_list_head_t const	*ar_list = &vpt->data.attribute.ar;

	if (!tmpl_is_attr(vpt)) {
	error:
		*out = NULL;
		return -1;
	}

	leaf = tmpl_attr_list_tail(ar_list);
	ar = tmpl_attr_list_head(ar_list);

	/*
	 *	Walk down the tmpl ar stack looking for candidate parent
	 *	attributes and then allocating the leaf.
	 */
	while (true) {
		if (unlikely(!ar)) goto error;
		/*
		 *	We're not at the leaf, look for a potential parent
		 */
		if (ar != leaf) vp = fr_pair_find_by_da(list, NULL, ar->da);

		/*
		 *	Nothing found, create the pair
		 */
		if (!vp) {
			if (fr_pair_append_by_da(pair_ctx, &vp, list, ar->da) < 0) goto error;
		}

		/*
		 *	We're at the leaf, return
		 */
		if (ar == leaf) {
			*out = vp;
			return 0;
		}

		/*
		 *	Prepare for next level
		 */
		list = &vp->vp_group;
		pair_ctx = vp;
		vp = NULL;
		ar = tmpl_attr_list_next(ar_list, ar);
	}
}

/** Insert a value-box to a list, with casting.
 *
 * @param list	to append to
 * @param box	box to cast / append
 * @param vpt	tmpl with cast.
 * @return
 *	- <0 for "cast failed"
 *	- 0 for success
 */
int tmpl_value_list_insert_tail(fr_value_box_list_t *list, fr_value_box_t *box, tmpl_t const *vpt)
{
	if (fr_type_is_null(tmpl_rules_cast(vpt)) ||
	    (box->type == tmpl_rules_cast(vpt))) {
		fr_dlist_insert_tail(list, box);
		return 0;
	}

	if (fr_value_box_cast_in_place(box, box, tmpl_rules_cast(vpt), tmpl_rules_enumv(vpt)) < 0) return -1;

	fr_dlist_insert_tail(list, box);
	return 0;
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
 *	- <0	on memory allocation errors.
 *	- 0	success.
 */
static int tmpl_eval_pair_virtual(TALLOC_CTX *ctx, fr_value_box_list_t *out,
				  request_t *request, tmpl_t const *vpt)
{
	fr_radius_packet_t *packet = NULL;
	fr_value_box_t	*value;
	fr_value_box_list_t list;

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
		if (!client || !client->shortname) return 0;

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_bstrdup_buffer(ctx, value, tmpl_da(vpt), client->shortname, false) < 0) {
		error:
			talloc_free(value);
			return -1;
		}
		goto done;
	}

	if (tmpl_da(vpt) == attr_request_processing_stage) {
		if (!request->component) return 0;

		MEM(value = fr_value_box_alloc_null(ctx));
		if (fr_value_box_strdup(ctx, value, tmpl_da(vpt), request->component, false) < 0) goto error;
		goto done;
	}

	if (tmpl_da(vpt) == attr_virtual_server) {
		if (!unlang_call_current(request)) return 0;

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
	if (!packet) return 0;

	if (tmpl_da(vpt) == attr_packet_type) {
		if (!packet || !packet->code) return 0;

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
		    (packet->socket.inet.src_ipaddr.af != AF_INET)) return 0;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.src_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_dst_ip_address) {
		if (!fr_socket_is_inet(packet->socket.proto) ||
		    (packet->socket.inet.dst_ipaddr.af != AF_INET)) return 0;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.dst_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_src_ipv6_address) {
		if (!fr_socket_is_inet(packet->socket.proto) ||
		    (packet->socket.inet.src_ipaddr.af != AF_INET6)) return 0;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.src_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_dst_ipv6_address) {
		if (!fr_socket_is_inet(packet->socket.proto) ||
		    (packet->socket.inet.dst_ipaddr.af != AF_INET6)) return 0;

		MEM(value = fr_value_box_alloc_null(ctx));
		fr_value_box_ipaddr(value, tmpl_da(vpt), &packet->socket.inet.dst_ipaddr, true);

	} else if (tmpl_da(vpt) == attr_packet_src_port) {
		if (!fr_socket_is_inet(packet->socket.proto)) return 0;

		MEM(value = fr_value_box_alloc(ctx, tmpl_da(vpt)->type, NULL, true));
		value->datum.uint16 = packet->socket.inet.src_port;

	} else if (tmpl_da(vpt) == attr_packet_dst_port) {
		if (!fr_socket_is_inet(packet->socket.proto)) return 0;

		MEM(value = fr_value_box_alloc(ctx, tmpl_da(vpt)->type, NULL, true));
		value->datum.uint16 = packet->socket.inet.dst_port;

	} else {
		RERROR("Attribute \"%s\" incorrectly marked as virtual", tmpl_da(vpt)->name);
		return -1;
	}

done:
	fr_value_box_list_init(&list);
	fr_dlist_insert_tail(&list, value);

	if (tmpl_eval_cast(ctx, &list, vpt) < 0) {
		fr_dlist_talloc_free(&list);
		return -1;
	};

	fr_dlist_move(out, &list);
	return 0;
}


/** Gets the value of a real or virtual attribute
 *
 * @param[in] ctx	to allocate boxed value, and buffers in.
 * @param[out] out	Where to write the boxed value.
 * @param[in] request	The current request.
 * @param[in] vpt	Representing the attribute.
 * @return
 *	- <0		we failed getting a value for the attribute.
 *	- 0		we successfully evaluated the tmpl
 */
int tmpl_eval_pair(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request, tmpl_t const *vpt)
{
	fr_pair_t		*vp = NULL;
	fr_value_box_t		*value;

	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;

	int			ret = 0;
	fr_value_box_list_t	list;

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	fr_value_box_list_init(&list);

	/*
	 *	See if we're dealing with an attribute in the request
	 *
	 *	This allows users to manipulate virtual attributes as if
	 *	they were real ones.
	 */
	vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);

	/*
	 *	We didn't find the VP in a list, check to see if it's
	 *	virtual.  This allows the caller to "realize" the
	 *	attribute, and we then prefer the realized version to
	 *	the virtual one.
	 */
	if (!vp) {
		if (tmpl_is_attr(vpt) && tmpl_da(vpt)->flags.virtual) {
			ret = tmpl_eval_pair_virtual(ctx, &list, request, vpt);
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
				ret = -1;
				goto fail;
			}
			value->datum.int32 = 0;
			fr_dlist_insert_tail(&list, value);
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

		while (vp != NULL) {
			count++;
			vp = fr_dcursor_next(&cursor);
		}

		value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL, false);
		if (!value) goto oom;
		value->datum.uint32 = count;
		fr_dlist_insert_tail(&list, value);
		break;
	}

	/*
	 *	Output multiple #value_box_t, one per attribute.
	 */
	case NUM_ALL:
		/*
		 *	Loop over all matching #fr_value_pair
		 *	shallow copying buffers.
		 */
		while (vp != NULL) {
			if (fr_type_is_structural(vp->da->type)) {
				value = fr_value_box_alloc(ctx, FR_TYPE_GROUP, NULL, false);
				if (!value) goto oom;

				if (fr_pair_list_copy_to_box(value, &vp->vp_group) < 0) {
					talloc_free(value);
					goto oom;
				}

			} else {
				value = fr_value_box_alloc(ctx, vp->data.type, vp->da, vp->data.tainted);
				if (!value) goto oom;
				fr_value_box_copy(value, value, &vp->data);
			}

			fr_dlist_insert_tail(&list, value);
			vp = fr_dcursor_next(&cursor);
		}
		break;

	default:
		value = fr_value_box_alloc(ctx, vp->data.type, vp->da, vp->data.tainted);
		if (!value) goto oom;

		fr_assert(fr_type_is_leaf(vp->da->type));
		fr_value_box_copy(value, value, &vp->data);	/* Also dups taint */
		fr_dlist_insert_tail(&list, value);
		break;
	}

done:
	/*
	 *	Evaluate casts if necessary.
	 */
	if (ret == 0) {
		if (tmpl_eval_cast(ctx, &list, vpt) < 0) {
			fr_dlist_talloc_free(&list);
			ret = -1;
			goto fail;
		}

		fr_dlist_move(out, &list);
	}

fail:
	tmpl_dcursor_clear(&cc);
	return ret;
}


/** Gets the value of a tmpl
 *
 *  The result is returned "raw".  The caller must do any escaping it desires.
 *
 * @param[in] ctx	to allocate boxed value, and buffers in.
 * @param[out] out	Where to write the boxed value.
 * @param[in] request	The current request.
 * @param[in] vpt	Representing the tmpl
 * @return
 *	- <0		we failed getting a value for the tmpl
 *	- 0		we successfully evaluated the tmpl
 */
int tmpl_eval(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request, tmpl_t const *vpt)
{
	char *p;
	fr_value_box_t		*value;
	fr_value_box_list_t	list;

	if (tmpl_needs_resolving(vpt)) {
		fr_strerror_const("Cannot evaluate unresolved tmpl");
		return -1;
	}

	if (tmpl_async_required(vpt)) {
		fr_strerror_const("Cannot statically evaluate asynchronous expansions");
		return -1;
	}

	if (tmpl_contains_regex(vpt)) {
		fr_strerror_const("Cannot statically evaluate regular expression");
		return -1;
	}

	if (tmpl_is_attr(vpt) || tmpl_is_list(vpt)) {
		return tmpl_eval_pair(ctx, out, request, vpt);
	}

	if (tmpl_is_data(vpt)) {
		MEM(value = fr_value_box_alloc(ctx, tmpl_value_type(vpt), NULL,
					       tmpl_value(vpt)->tainted));

		fr_value_box_copy(value, value, tmpl_value(vpt));	/* Also dups taint */
		goto done;
	}

	fr_assert(tmpl_is_xlat(vpt));

	if (xlat_async_required(tmpl_xlat(vpt))) {
		fr_strerror_const("Cannot evaluate async xlat");
		return -1;
	}

	/*
	 *	@todo - respect escaping functions.  But the sync
	 *	escaping uses a different method than the async ones.
	 *	And we then also need to escape the output of
	 *	tmpl_eval_pair(), too.
	 */
	MEM(value = fr_value_box_alloc_null(ctx));

	if (tmpl_aexpand(value, &p, request, vpt, NULL, NULL) < 0) {
		talloc_free(value);
		return -1;
	}
	fr_value_box_bstrndup_shallow(value, NULL, p, talloc_array_length(p) - 1, true);

	/*
	 *	Cast the results if necessary.
	 */
done:
	fr_value_box_list_init(&list);
	fr_dlist_insert_tail(&list, value);

	if (tmpl_eval_cast(ctx, &list, vpt) < 0) {
		fr_dlist_talloc_free(&list);
		return -1;
	};

	fr_dlist_move(out, &list);
	return 0;
}



/** Casts a value or list of values according to the tmpl
 *
 * @param[in] ctx	to allocate boxed value, and buffers in.
 * @param[in,out] list	Where to write the boxed value.
 * @param[in] vpt	Representing the attribute.
 * @return
 *	- <0		the cast failed
 *	- 0		we successfully evaluated the tmpl
 */
int tmpl_eval_cast(TALLOC_CTX *ctx, fr_value_box_list_t *list, tmpl_t const *vpt)
{
	fr_type_t cast = tmpl_rules_cast(vpt);
	fr_value_box_t *vb;
	bool tainted = false;
	ssize_t slen, vlen;
	fr_sbuff_t *agg;

	if (cast == FR_TYPE_NULL) return 0;

	/*
	 *	Apply a cast to the results if required.
	 */
	vb = fr_dlist_head(list);
	if (!vb) return 0;

	switch (cast) {
	default:
		/*
		 *	One box, we cast it as the destination type.
		 *
		 *	Many boxes, turn them into strings, and try to parse it as the
		 *	output type.
		 */
		if (!fr_dlist_next(list, vb)) {
			return fr_value_box_cast_in_place(vb, vb, cast, NULL);
		}
		FALL_THROUGH;

		/*
		 *	Strings aren't *cast* to the output.  They're *printed* to the output.
		 */
	case FR_TYPE_STRING:
		FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, 256);

		slen = fr_value_box_list_concat_as_string(&tainted, agg, list, NULL, 0,
							  (cast == FR_TYPE_STRING) ? &fr_value_escape_double : NULL,
							  FR_VALUE_BOX_LIST_FREE_BOX, true, true);
		if (slen < 0) return -1;

		MEM(vb = fr_value_box_alloc_null(ctx));
		vlen = fr_value_box_from_str(vb, vb, cast, NULL,
					     fr_sbuff_start(agg), fr_sbuff_used(agg),
					     NULL, tainted);
		if ((vlen < 0) || (slen != vlen)) return -1;

		fr_dlist_insert_tail(list, vb);
		break;

	case FR_TYPE_OCTETS:
		return fr_value_box_list_concat_in_place(vb, vb, list, cast,
							 FR_VALUE_BOX_LIST_FREE_BOX, true, SIZE_MAX);
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("Cannot cast to structural type '%s'",
				   fr_type_to_str(cast));
		return -1;
	}

	return 0;
}



int tmpl_global_init(void)
{
	if (fr_dict_autoload(tmpl_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(tmpl_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(tmpl_dict);
		return -1;
	}

	return 0;
}

void tmpl_global_free(void)
{
	fr_dict_autofree(tmpl_dict);
}
