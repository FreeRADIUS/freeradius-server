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

#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/edit.h>
#include <freeradius-devel/util/token.h>
#include <freeradius-devel/util/types.h>

#include <talloc.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t tmpl_dict[];
fr_dict_autoload_t tmpl_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" }, /* @todo - remove RADIUS from the server core... */
	{ NULL }
};

/** Placeholder attribute for uses of unspecified attribute references
 */
extern fr_dict_attr_t const *tmpl_attr_unspec;
fr_dict_attr_t const *tmpl_attr_unspec;


/** Resolve attribute #fr_pair_list_t value to an attribute list.
 *
 * The value returned is a pointer to the pointer of the HEAD of a #fr_pair_t list in the
 * #request_t. If the head of the list changes, the pointer will still be valid.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #fr_pair_list_t value to resolve to #fr_pair_t list. Will be NULL if list
 *	name couldn't be resolved.
 * @return a pointer to the HEAD of a list in the #request_t.
 *
 * @see tmpl_dcursor_init
 */
fr_pair_list_t *tmpl_list_head(request_t *request, fr_dict_attr_t const *list)
{
	if (!request) return NULL;

	if (list == request_attr_request) {
		if (!request->packet) return NULL;
		return &request->request_pairs;
	}

	if (list == request_attr_reply) {
		if (!request->reply) return NULL;
		return &request->reply_pairs;
	}

	if (list == request_attr_control) return &request->control_pairs;

	if (list == request_attr_state) return &request->session_state_pairs;

	if (list == request_attr_local) return &request->local_pairs;

	RWDEBUG2("List \"%s\" is not available", tmpl_list_name(list, "<INVALID>"));

	return NULL;
}

/** Return the correct TALLOC_CTX to alloc #fr_pair_t in, for a list
 *
 * Allocating new #fr_pair_t in the context of a #request_t is usually wrong.
 * #fr_pair_t should be allocated in the context of a #fr_packet_t, so that if the
 * #fr_packet_t is freed before the #request_t, the associated #fr_pair_t lists are
 * freed too.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #fr_pair_list_t value to resolve to TALLOC_CTX.
 * @return
 *	- TALLOC_CTX on success.
 *	- NULL on failure.
 *
 * @see tmpl_pair_list
 */
TALLOC_CTX *tmpl_list_ctx(request_t *request, fr_dict_attr_t const *list)
{
	if (!request) return NULL;

	if (list == request_attr_request) return request->request_ctx;

	if (list == request_attr_reply) return request->reply_ctx;

	if (list == request_attr_control) return request->control_ctx;

	if (list == request_attr_state) return request->session_state_ctx;

	if (list == request_attr_local) return request->local_ctx;

	return NULL;
}

/** Resolve a list to the #fr_packet_t holding the HEAD pointer for a #fr_pair_t list
 *
 * Returns a pointer to the #fr_packet_t that holds the HEAD pointer of a given list,
 * for the current #request_t.
 *
 * @param[in] request To resolve list in.
 * @param[in] list #fr_pair_list_t value to resolve to #fr_packet_t.
 * @return
 *	- #fr_packet_t on success.
 *	- NULL on failure.
 *
 * @see tmpl_pair_list
 */
fr_packet_t *tmpl_packet_ptr(request_t *request, fr_dict_attr_t const *list)
{
	if (list == request_attr_request) return request->packet;

	if (list == request_attr_reply) return request->reply;

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
		return tmpl_attr_tail_da(vpt)->type;

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
 * the #tmpl_t, avoiding unnecessary string copies.
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
 *				- #TMPL_TYPE_DATA_UNRESOLVED
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
	fr_value_box_t		value_to_cast = FR_VALUE_BOX_INITIALISER_NULL(value_to_cast);
	fr_value_box_t		value_from_cast = FR_VALUE_BOX_INITIALISER_NULL(value_from_cast);
	fr_value_box_t const	*to_cast = &value_to_cast;
	fr_value_box_t const	*from_cast = &value_from_cast;

	fr_pair_t		*vp = NULL;

	fr_type_t		src_type = FR_TYPE_NULL;

	ssize_t			slen = -1;	/* quiet compiler */

	TMPL_VERIFY(vpt);

	fr_assert(!buff || (bufflen >= 2));

	switch (vpt->type) {
	case TMPL_TYPE_DATA_UNRESOLVED:
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

		if (radius_exec_program_legacy((char *)buff, bufflen, request, vpt->name, NULL,
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
		src_type = vp->vp_type;
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
		fr_value_box_field_sizes[dst_type], out, fr_value_box_offsets[dst_type]);

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
 *			- #TMPL_TYPE_DATA_UNRESOLVED
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
	fr_value_box_t		value = FR_VALUE_BOX_INITIALISER_NULL(value);
	bool			needs_dup = false;

	ssize_t			slen = -1;
	int			ret;

	TALLOC_CTX		*tmp_ctx = talloc_new(ctx);

	TMPL_VERIFY(vpt);

	switch (vpt->type) {
	case TMPL_TYPE_DATA_UNRESOLVED:
		RDEBUG4("EXPAND TMPL DATA UNRESOLVED");

		fr_value_box_bstrndup_shallow(&value, NULL, vpt->name, vpt->len, false);
		to_cast = &value;
		needs_dup = true;
		break;

	case TMPL_TYPE_EXEC:
	{
		char *buff;

		RDEBUG4("EXPAND TMPL EXEC");

		MEM(fr_value_box_bstr_alloc(tmp_ctx, &buff, &value, NULL, 1024, true));
		if (radius_exec_program_legacy(buff, 1024, request, vpt->name, NULL,
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

		ret = needs_dup ? fr_value_box_copy(*vb_out, *vb_out, to_cast) : fr_value_box_steal(*vb_out, *vb_out, to_cast);
		talloc_free(tmp_ctx);
		if (ret < 0) {
			RPEDEBUG("Failed copying data to output box");
			TALLOC_FREE(*vb_out);
			return -1;
		}
		VALUE_BOX_VERIFY(*vb_out);
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
		fr_value_box_copy_shallow(NULL, &from_cast, to_cast);
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

	fr_assert(tmpl_is_attr(vpt));

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

	fr_assert(tmpl_is_attr(vpt));

	fr_pair_list_free(out);

	for (vp = tmpl_dcursor_init(&err, NULL, &cc, &from, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&from)) {
		switch (vp->vp_type) {
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

		if (pair_append_by_tmpl_parent(ctx, &vp, head, vpt, true) < 0) return -1;

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
 * @param[in] skip_list	skip list attr ref at the head of the tmpl.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int pair_append_by_tmpl_parent(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list, tmpl_t const *vpt, bool skip_list)
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
	if (!ar) goto error;
	if (skip_list && tmpl_attr_is_list_attr(ar)) ar = tmpl_attr_list_next(ar_list, ar);

	/*
	 *	Walk down the tmpl ar stack looking for candidate parent
	 *	attributes and then allocating the leaf.
	 */
	while (true) {
		if (unlikely(!ar)) goto error;
		/*
		 *	We're not at the leaf, look for a potential parent
		 */
		if (ar != leaf) {
			vp = fr_pair_find_by_da(list, NULL, ar->da);
			/*
			 *	HACK - Pretend we didn't see this stupid key field
			 *
			 *	If we don't have this, the code creates a key pair
			 *	and then horribly mangles its data by adding children
			 *	to it.
			 *
			 *	We just skip one level down an don't create or update
			 *	the key pair.
			 */
			if (vp && fr_dict_attr_is_key_field(ar->da) && fr_type_is_leaf(vp->data.type)) {
				ar = tmpl_attr_list_next(ar_list, ar);
				continue;
			}
		}
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
		fr_value_box_list_insert_tail(list, box);
		return 0;
	}

	if (fr_value_box_cast_in_place(box, box, tmpl_rules_cast(vpt), tmpl_rules_enumv(vpt)) < 0) return -1;

	fr_value_box_list_insert_tail(list, box);
	VALUE_BOX_LIST_VERIFY(list);
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

	fr_assert(tmpl_is_attr(vpt));

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
		/*
		 *	Zero count.
		 */
		if (tmpl_attr_tail_num(vpt) == NUM_COUNT) {
			value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL);
			if (!value) {
			oom:
				fr_strerror_const("Out of memory");
				ret = -1;
				goto fail;
			}
			value->datum.int32 = 0;
			fr_value_box_list_insert_tail(&list, value);
		} /* Fall through to being done */

		goto done;
	}

	switch (tmpl_attr_tail_num(vpt)) {
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

		value = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL);
		if (!value) goto oom;
		value->datum.uint32 = count;
		fr_value_box_list_insert_tail(&list, value);
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
			if (fr_type_is_structural(vp->vp_type)) {
				value = fr_value_box_alloc(ctx, FR_TYPE_GROUP, NULL);
				if (!value) goto oom;

				if (fr_pair_list_copy_to_box(value, &vp->vp_group) < 0) {
					talloc_free(value);
					goto oom;
				}

			} else {
				value = fr_value_box_alloc(ctx, vp->data.type, vp->da);
				if (!value) goto oom;
				fr_value_box_copy(value, value, &vp->data);
			}

			fr_value_box_list_insert_tail(&list, value);
			vp = fr_dcursor_next(&cursor);
		}
		break;

	default:
		if (!fr_type_is_leaf(vp->vp_type)) {
			fr_strerror_const("Invalid data type for evaluation");
			goto fail;
		}

		value = fr_value_box_alloc(ctx, vp->data.type, vp->da);
		if (!value) goto oom;

		fr_value_box_copy(value, value, &vp->data);	/* Also dups taint */
		fr_value_box_list_insert_tail(&list, value);
		break;
	}

done:
	/*
	 *	Evaluate casts if necessary.
	 */
	if (ret == 0) {
		if (tmpl_eval_cast_in_place(&list, request, vpt) < 0) {
			fr_value_box_list_talloc_free(&list);
			ret = -1;
			goto fail;
		}

		fr_value_box_list_move(out, &list);
	}

fail:
	tmpl_dcursor_clear(&cc);
	VALUE_BOX_LIST_VERIFY(out);
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

	if (tmpl_is_attr(vpt)) {
		return tmpl_eval_pair(ctx, out, request, vpt);
	}

	if (tmpl_is_data(vpt)) {
		MEM(value = fr_value_box_alloc(ctx, tmpl_value_type(vpt), NULL));

		fr_value_box_copy(value, value, tmpl_value(vpt));	/* Also dups taint */
		goto done;
	}

	fr_assert(tmpl_is_xlat(vpt));

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
	fr_value_box_list_insert_tail(&list, value);

	if (tmpl_eval_cast_in_place(&list, request, vpt) < 0) {
		fr_value_box_list_talloc_free(&list);
		return -1;
	}

	fr_value_box_list_move(out, &list);
	VALUE_BOX_LIST_VERIFY(out);

	return 0;
}

/** Allocate a uctx for an escaping function
 *
 * @param[in] request	The current request.
 * @param[in] escape	Describing how to escape tmpl data.
 *
 * @return the uctx to pass to the escape function.
 */
static inline void *tmpl_eval_escape_uctx_alloc(request_t *request, tmpl_escape_t const *escape)
{
	switch (escape->uctx.type) {
	case TMPL_ESCAPE_UCTX_STATIC:
		return UNCONST(void *, escape->uctx.ptr);

	case TMPL_ESCAPE_UCTX_ALLOC:
	{
		void *uctx;

		fr_assert_msg(escape->uctx.size > 0, "TMPL_ESCAPE_UCTX_ALLOC must specify uctx.size > 0");
		MEM(uctx = talloc_zero_array(NULL, uint8_t, escape->uctx.size));
		if (escape->uctx.talloc_type) talloc_set_type(uctx, escape->uctx.talloc_type);
		return uctx;
	}

	case TMPL_ESCAPE_UCTX_ALLOC_FUNC:
		fr_assert_msg(escape->uctx.func.alloc, "TMPL_ESCAPE_UCTX_ALLOC_FUNC must specify a non-null alloc.func");
		return escape->uctx.func.alloc(request, escape->uctx.func.uctx);

	default:
		fr_assert_msg(0, "Unknown escape uctx type %u", escape->uctx.type);
		return NULL;
	}
}

/** Free a uctx for an escaping function
 *
 * @param[in] escape	Describing how to escape tmpl data.
 * @param[in] uctx	The uctx to free.
 */
static inline void tmpl_eval_escape_uctx_free(tmpl_escape_t const *escape, void *uctx)
{
	switch (escape->uctx.type) {
	case TMPL_ESCAPE_UCTX_STATIC:
		return;

	case TMPL_ESCAPE_UCTX_ALLOC:
		talloc_free(uctx);
		return;

	case TMPL_ESCAPE_UCTX_ALLOC_FUNC:
		if (escape->uctx.func.free) escape->uctx.func.free(uctx);
		return;
	}
}

/** Casts a value or list of values according to the tmpl
 *
 * @param[in,out] list	Where to write the boxed value.
 * @param[in] request	The current request.
 * @param[in] vpt	Representing the attribute.
 * @return
 *	- <0		the cast failed
 *	- 0		we successfully evaluated the tmpl
 */
int tmpl_eval_cast_in_place(fr_value_box_list_t *list, request_t *request, tmpl_t const *vpt)
{
	fr_type_t cast = tmpl_rules_cast(vpt);
	bool did_concat = false;
	void *uctx = NULL;

	if (fr_type_is_structural(cast)) {
		fr_strerror_printf("Cannot cast to structural type '%s'", fr_type_to_str(cast));
		return -1;
	}

	/*
	 *	Quoting around the tmpl means everything
	 *	needs to be concatenated, either as a string
	 *	or octets string.
	 */
	switch (vpt->quote) {
	case T_DOUBLE_QUOTED_STRING:
	case T_SINGLE_QUOTED_STRING:
	case T_SOLIDUS_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
	{
		ssize_t		slen;
		fr_value_box_t	*vb;

		vb = fr_value_box_list_head(list);
		if (!vb) return 0;

		if (tmpl_escape_pre_concat(vpt)) {
			uctx = tmpl_eval_escape_uctx_alloc(request, &vpt->rules.escape);
			/*
			 *	Sets escaped values, so boxes don't get re-escaped
			 */
			if (unlikely(fr_value_box_list_escape_in_place(list, vpt->rules.escape.func,
								       vpt->rules.escape.safe_for, uctx) < 0)) {
			error:
				tmpl_eval_escape_uctx_free(&vpt->rules.escape, uctx);
				return -1;
			}
		}

		slen = fr_value_box_list_concat_in_place(vb, vb, list, FR_TYPE_STRING,
							 FR_VALUE_BOX_LIST_FREE_BOX, true, SIZE_MAX);
		if (slen < 0) goto error;
		VALUE_BOX_LIST_VERIFY(list);

		/*
		 *	If there's no cast, or it's a cast to
		 *	a string, we're done!
		 *
		 *	Otherwise we now need to re-cast the
		 *	result.
		 */
		if (fr_type_is_null(cast) || fr_type_is_string(cast)) {
		success:
			tmpl_eval_escape_uctx_free(&vpt->rules.escape, uctx);
			return 0;
		}

		did_concat = true;
	}
		break;

	default:
		break;
	}

	if (fr_type_is_null(cast)) goto success;

	/*
	 *	Quoting above handled all concatenation,
	 *	we now need to handle potentially
	 *	multivalued lists.
	 */
	fr_value_box_list_foreach_safe(list, vb) {
		if (fr_value_box_cast_in_place(vb, vb, cast, NULL) < 0) goto error;
	}}

	/*
	 *	...and finally, apply the escape function
	 *	if necessary.  This is done last so that
	 *	the escape function gets boxes of the type
	 *	it expects.
	 */
	if ((!did_concat && tmpl_escape_pre_concat(vpt)) || tmpl_escape_post_concat(vpt)) {
		uctx = tmpl_eval_escape_uctx_alloc(request, &vpt->rules.escape);
		if (unlikely(fr_value_box_list_escape_in_place(list, vpt->rules.escape.func,
							       vpt->rules.escape.safe_for, uctx) < 0)) goto error;
	}

	/*
	 *	If there's no escape function, but there is
	 *	an escaped value, mark all the boxes up with
	 *	this value.
	 *
	 *	This is mostly useful for call_env usage in
	 *	modules where certain values are implicitly safe
	 *	for consumption, like SQL statements in the SQL
	 *	module.
	 */
	if (!vpt->rules.escape.func && vpt->rules.escape.safe_for) {
		fr_value_box_list_mark_safe_for(list, vpt->rules.escape.safe_for);
	}

	VALUE_BOX_LIST_VERIFY(list);

	goto success;
}

static int _tmpl_global_free(UNUSED void *uctx)
{
	fr_dict_autofree(tmpl_dict);

	return 0;
}

static int _tmpl_global_init(UNUSED void *uctx)
{
	fr_dict_attr_t *da;

	if (fr_dict_autoload(tmpl_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}

	da = fr_dict_attr_unknown_raw_afrom_num(UNCONST(TALLOC_CTX *, dict_freeradius), fr_dict_root(dict_freeradius), 0);
	fr_assert(da != NULL);

	da->type = FR_TYPE_NULL;
	tmpl_attr_unspec = da;

	return 0;
}

int tmpl_global_init(void)
{
	int ret;

	fr_atexit_global_once_ret(&ret, _tmpl_global_init, _tmpl_global_free, NULL);

	return 0;
}
