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

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/dlist.h>

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
 * @see tmpl_pair_cursor_init
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
 * @param[in,out] context #request_t to start resolving from, and where to write
 *	a pointer to the resolved #request_t back to.
 * @param[in] name (request) to resolve.
 * @return
 *	- 0 if request is valid in this context.
 *	- -1 if request is not valid in this context.
 */
int tmpl_request_ptr(request_t **context, tmpl_request_ref_t name)
{
	request_t *request = *context;

	switch (name) {
	case REQUEST_CURRENT:
		return 0;

	case REQUEST_PARENT:	/* Navigate up one level */
		if (!request->parent) return -1;
		*context = request->parent;
		break;

	case REQUEST_OUTER:	/* Navigate to the outermost request */
		if (!request->parent) return -1;
		while (request->parent) request = request->parent;
		*context = request;
		break;

	case REQUEST_UNKNOWN:
	default:
		fr_assert(0);
		return -1;
	}

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
	if (vpt->cast != FR_TYPE_NULL) return vpt->cast;

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

		if (radius_exec_program(request, (char *)buff, bufflen, NULL, request, vpt->name, NULL,
					true, false, fr_time_delta_from_sec(EXEC_TIMEOUT)) != 0) return -1;
		fr_value_box_strdup_shallow(&value_to_cast, NULL, (char *)buff, true);
		src_type = FR_TYPE_STRING;
	}
		break;

	case TMPL_TYPE_XLAT:
	{
		size_t len;

		RDEBUG4("EXPAND TMPL XLAT PARSED");
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */
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

	memcpy(out, ((uint8_t const *) from_cast) + fr_value_box_offsets[dst_type], fr_value_box_field_sizes[dst_type]);

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
	fr_value_box_t		value;
	bool			needs_dup = false;

	ssize_t			slen = -1;
	int			ret;

	TALLOC_CTX		*tmp_ctx = talloc_new(ctx);

	TMPL_VERIFY(vpt);

	memset(&value, 0, sizeof(value));

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

		fr_value_box_bstr_alloc(tmp_ctx, &buff, &value, NULL, 1024, true);
		if (radius_exec_program(request, buff, 1024, NULL, request, vpt->name, NULL,
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

		RDEBUG4("EXPAND TMPL XLAT");

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval(tmp_ctx, (char **)&value.datum.ptr, request, vpt->name, escape, escape_ctx);
		if (slen < 0) goto error;
		value.vb_length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, src_type, NULL,
					    value.vb_strvalue, value.vb_length, '"', false);
		if (ret < 0) goto error;

		fr_value_box_bstrndup_shallow(&value, NULL, tmp.vb_strvalue, tmp.vb_length, tmp.tainted);
		to_cast = &value;
	}
		break;

	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_REGEX_XLAT:
	{
		fr_value_box_t	tmp;
		fr_type_t		src_type = FR_TYPE_STRING;

		RDEBUG4("EXPAND TMPL XLAT STRUCT");
		RDEBUG2("EXPAND %s", vpt->name); /* xlat_struct doesn't do this */

		/* Error in expansion, this is distinct from zero length expansion */
		slen = xlat_aeval_compiled(tmp_ctx, (char **)&value.datum.ptr, request, tmpl_xlat(vpt), escape, escape_ctx);
		if (slen < 0) goto error;

		value.vb_length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, src_type, NULL,
					    value.vb_strvalue, value.vb_length, '"', false);
		if (ret < 0) goto error;

		fr_value_box_bstrndup_shallow(&value, NULL, tmp.vb_strvalue, tmp.vb_length, tmp.tainted);
		to_cast = &value;

		RDEBUG2("   --> %s", value.vb_strvalue);	/* Print post-unescaping */
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
				value.datum.ptr = talloc_reparent(tmp_ctx, ctx, value.datum.ptr);
			}
			break;

		default:
			break;
		}
		memcpy(&from_cast, to_cast, sizeof(from_cast));
	}

	RDEBUG4("Copying %zu bytes to %p from offset %zu",
		fr_value_box_field_sizes[dst_type], *((void **)out), fr_value_box_offsets[dst_type]);

	memcpy(out, ((uint8_t *)&from_cast) + fr_value_box_offsets[dst_type], fr_value_box_field_sizes[dst_type]);

	/*
	 *	Frees any memory allocated for temporary buffers
	 *	in this function.
	 */
	talloc_free(tmp_ctx);

	return from_cast.vb_length;
}

/** Traverse a TLV attribute
 *
 * @param[in] list_head The head of the pair_list being evaluated.
 * @param[in] current	The pair to evaluate.
 * @param[in] ns	Tracks tree position between cursor calls.
 * @return
 *	- the next matching vp
 *	- NULL if none found
 */
static fr_pair_t *_tmpl_cursor_tlv_eval(UNUSED fr_dlist_head_t *list_head, UNUSED fr_pair_t *current, tmpl_cursor_nested_t *ns)
{
	fr_dcursor_stack_t	*cs;
	fr_dcursor_t		*cursor;
	fr_pair_t		*vp;

	cs = ns->tlv.cursor_stack;
	cursor = &cs->cursor[cs->depth - 1];

	/*
	 *	Our final stopping condition is when the shallowest
	 *      cursor returns NULL.  That means we've evaluated
	 *	the entire subtree.
	 */
	while (cs->depth > 0) {
		for (vp = fr_dcursor_current(cursor);
		     vp;
		     vp = fr_dcursor_next(cursor)) {
			/*
			 *	Exact match, we're done.
			 */
			if (fr_dict_attr_cmp(vp->da, ns->ar->ar_da) == 0) {
				fr_dcursor_next(cursor);	/* Advance to correct position for next call */
				return vp;
			}

			/*
			 *	Traverse the intermediary VP
			 */
			if ((vp->da->depth < ns->ar->ar_da->depth) &&
			    (fr_dict_attr_cmp(ns->tlv.da_stack.da[vp->da->depth], vp->da) == 0)) {
				cursor = &cs->cursor[cs->depth++];
				fr_dcursor_init(cursor, &vp->vp_group);
				continue;
			}
		}

		/*
		 *	We're done processing children at this level.
		 *
		 *	Jump up one in the cursor stack and continue.
		 */
		cursor = &cs->cursor[--cs->depth];
	}

	return NULL;
}

static inline CC_HINT(always_inline)
void _tmpl_cursor_pool_init(tmpl_pair_cursor_ctx_t *cc)
{
	if (!cc->pool) MEM(cc->pool = talloc_pool(cc->ctx, sizeof(tmpl_cursor_nested_t) * 5));
}

/** Initialise an evaluation ctx for traversing a TLV attribute
 *
 */
static inline CC_HINT(always_inline)
void _tmpl_cursor_tlv_init(TALLOC_CTX *list_ctx, fr_pair_list_t *list, tmpl_attr_t const *ar, tmpl_pair_cursor_ctx_t *cc)
{
	tmpl_attr_t		*prev = fr_dlist_prev(&cc->vpt->data.attribute.ar, ar);

	int			span;		/* Max number of nested VPs we'll need to deal with */
	bool			partial;

	tmpl_cursor_nested_t	*ns;

	/*
	 *	We may only need to re-build part of the
	 *	da stack.
	 */
	if (prev && prev->ar_da) switch (prev->ar_da->type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VSA:
	case FR_TYPE_STRUCT:
	case FR_TYPE_VENDOR:
		span = ar->ar_da->depth - prev->ar_da->depth;
		partial = true;
		break;

	default:
	no_prev:
		span = ar->ar_da->depth;
		partial = false;
		break;
	} else goto no_prev;

	_tmpl_cursor_pool_init(cc);
	MEM(ns = talloc_pooled_object(cc->pool, tmpl_cursor_nested_t,
				      1, sizeof(fr_dcursor_stack_t) + (sizeof(fr_dcursor_t) * span)));
	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_tlv_eval,
		.list_ctx = list_ctx,
		.tlv = {
			.cursor_stack = fr_dcursor_stack_alloc(ns, span)
		}
	};

	/*
	 *	Initialise the first level cursor
	 *	to point to the list or children of
	 *	a tlv or group.
	 */
	fr_dcursor_init(&ns->tlv.cursor_stack->cursor[0], list);
	ns->tlv.cursor_stack->depth = 1;

	/*
	 *	We're either looking for VPs in the path
	 *	from the dictionary root to the ref,
	 *	or between two TLVs.
	 */
	if (partial) {
		fr_proto_da_stack_build_partial(&ns->tlv.da_stack, prev->ar_da, ar->ar_da);
	} else {
		fr_proto_da_stack_build(&ns->tlv.da_stack, ar->ar_da);
	}

	fr_dlist_insert_tail(&cc->nested, ns);
}

/** Traverse a group attribute
 *
 * Here we just look for a particular group attribute in the context of its parent
 *
 * @param[in] list_head The head of the pair_list being evaluated.
 * @param[in] current	The pair to evaluate.
 * @param[in] ns	Tracks tree position between cursor calls.
 * @return
 *	- the next matching attribute
 *	- NULL if none found
 */
static fr_pair_t *_tmpl_cursor_group_eval(UNUSED fr_dlist_head_t *list_head, UNUSED fr_pair_t *current, tmpl_cursor_nested_t *ns)
{
	fr_pair_t *vp;

	for (vp = fr_dcursor_current(&ns->group.cursor);
	     vp;
	     vp = fr_dcursor_next(&ns->group.cursor)) {
		if (fr_dict_attr_cmp(ns->ar->ar_da, vp->da) == 0) {
			fr_dcursor_next(&ns->group.cursor);	/* Advance to correct position for next call */
			return vp;
		}
	}

	return NULL;
}

/** Initialise the evaluation context for traversing a group attribute
 *
 */
static inline CC_HINT(always_inline)
void _tmpl_cursor_group_init(TALLOC_CTX *list_ctx, fr_pair_list_t *list, tmpl_attr_t const *ar, tmpl_pair_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t *ns;

	_tmpl_cursor_pool_init(cc);
	MEM(ns = talloc(cc->pool, tmpl_cursor_nested_t));
	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_group_eval,
		.list_ctx = list_ctx
	};
	fr_dcursor_init(&ns->group.cursor, list);
	fr_dlist_insert_tail(&cc->nested, ns);
}

/** Find a leaf attribute
 *
 * @param[in] list_head The head of the pair_list being evaluated.
 * @param[in] curr	The current attribute to start searching from.
 * @param[in] ns	Tracks tree position between cursor calls.
 * @return
 *	- the next matching attribute
 *	- NULL if none found
 */
static fr_pair_t *_tmpl_cursor_leaf_eval(fr_dlist_head_t *list_head, fr_pair_t *curr, tmpl_cursor_nested_t *ns)
{
	fr_pair_t *vp = curr;

	while (vp) {
		if (fr_dict_attr_cmp(ns->ar->ar_da, vp->da) == 0) return vp;
		vp = fr_dlist_next(list_head, vp);
	}

	return NULL;
}

/** Initialise the evaluation context for finding a leaf attribute
 *
 */
static inline CC_HINT(always_inline)
void _tmpl_cursor_leaf_init(TALLOC_CTX *list_ctx, fr_pair_list_t *list, tmpl_attr_t const *ar, tmpl_pair_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t	*ns = &cc->leaf;

	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_leaf_eval,
		.list_ctx = list_ctx
	};
	ns->leaf.list_head = list;
	fr_dlist_insert_tail(&cc->nested, ns);
}

/** Stub list eval function until we can remove lists
 *
 */
static fr_pair_t *_tmpl_cursor_list_eval(UNUSED fr_dlist_head_t *list_head, fr_pair_t *curr, UNUSED tmpl_cursor_nested_t *ns)
{
	return curr;
}

static inline CC_HINT(always_inline)
void _tmpl_cursor_list_init(TALLOC_CTX *list_ctx, fr_pair_list_t *list, tmpl_attr_t const *ar, tmpl_pair_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t *ns;

	ns = &cc->leaf;
	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_list_eval,
		.list_ctx = list_ctx
	};
	ns->leaf.list_head = list;
	fr_dlist_insert_tail(&cc->nested, ns);
}

static inline CC_HINT(always_inline) void _tmpl_cursor_eval_pop(tmpl_pair_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t *ns = fr_dlist_pop_tail(&cc->nested);

	if (ns != &cc->leaf) talloc_free(ns);
}

/** Evaluates, then, sometimes, pops evaluation contexts from the tmpl stack
 *
 * To pop or not to pop is determined by whether evaluating the context again
 * would/should/could produce another fr_pair_t.
 *
 * @param[in] list_head The head of the pair_list being evaluated.
 * @param[in] curr	The pair to evaluate.
 * @param[in] cc	Tracks state between cursor calls.
 * @return the vp evaluated.
 */
static inline CC_HINT(always_inline)
fr_pair_t *_tmpl_cursor_eval(fr_dlist_head_t *list_head, fr_pair_t *curr, tmpl_pair_cursor_ctx_t *cc)
{
	tmpl_attr_t const	*ar;
	tmpl_cursor_nested_t	*ns;
	fr_pair_t		*iter = curr, *vp;

	ns = fr_dlist_tail(&cc->nested);
	ar = ns->ar;

	if (ar) switch (ar->ar_num) {
	/*
	 *	Get the first instance
	 */
	case NUM_ANY:
		vp = ns->func(list_head, curr, ns);
		_tmpl_cursor_eval_pop(cc);
		break;

	/*
	 *	Get all instances
	 */
	case NUM_ALL:
	case NUM_COUNT:
	all_inst:
		vp = ns->func(list_head, curr, ns);
		if (!vp) _tmpl_cursor_eval_pop(cc);	/* pop only when we're done */
		break;

	/*
	 *	Get the last instance
	 */
	case NUM_LAST:
		vp = NULL;
		while ((iter = ns->func(list_head, iter, ns))) {
			vp = iter;

			if (!fr_dlist_next(list_head, vp)) break;

			iter = fr_dlist_next(list_head,vp);
		}
		_tmpl_cursor_eval_pop(cc);
		break;

	/*
	 *	Get the n'th instance
	 */
	default:
	{
		int16_t		i = 0;

		for (;;) {
			vp = ns->func(list_head, iter, ns);
			if (!vp) break;	/* Prev and next at the correct points */

			if (++i > ar->num) break;

			iter = fr_dlist_next(list_head, vp);
		};
		_tmpl_cursor_eval_pop(cc);
	}
		break;
	} else goto all_inst;	/* Used for TMPL_TYPE_LIST */

	return vp;
}

static inline CC_HINT(always_inline)
void _tmpl_pair_cursor_init(TALLOC_CTX *list_ctx, fr_pair_list_t *list, tmpl_attr_t const *ar, tmpl_pair_cursor_ctx_t *cc)
{
	if (fr_dlist_next(&cc->vpt->data.attribute.ar, ar)) switch (ar->ar_da->type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VSA:
	case FR_TYPE_STRUCT:
	case FR_TYPE_VENDOR:
		_tmpl_cursor_tlv_init(list_ctx, list, ar, cc);
		break;

	case FR_TYPE_GROUP:
		_tmpl_cursor_group_init(list_ctx, list, ar, cc);
		break;

	default:
	leaf:
		_tmpl_cursor_leaf_init(list_ctx, list, ar, cc);
		break;
	} else goto leaf;
}

static void *_tmpl_cursor_next(fr_dlist_head_t *list, void *curr, void *uctx)
{
	tmpl_pair_cursor_ctx_t	*cc = uctx;
	tmpl_t const		*vpt = cc->vpt;

	fr_pair_t		*vp;
	fr_pair_list_t		*list_head;

	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	{
		tmpl_attr_t const	*ar = NULL;
		tmpl_cursor_nested_t	*ns = NULL;

		/*
		 *	- Continue until there are no evaluation contexts
		 *	- Push a evaluation context if evaluating the head of the
		 *	  stack yields a VP and we're not at the deepest attribute
		 *	  reference.
		 *	- Return if we have a VP and there are no more attribute
		 *	  references to push, i.e. we're at the deepest attribute
		 *	  reference.
		 */
		while ((ns = fr_dlist_tail(&cc->nested))) {
			ar = ns->ar;
			vp = _tmpl_cursor_eval(list, curr, cc);
			if (!vp) continue;

			ar = fr_dlist_next(&vpt->data.attribute.ar, ar);
			if (ar) {
				list_head = &vp->vp_group;
				_tmpl_pair_cursor_init(vp, list_head, ar, cc);
				curr = fr_pair_list_head(list_head);
				list = &list_head->head;
				continue;
			}

			return vp;
		}

	null_result:
		return NULL;
	}

	/*
	 *	Hacks for evaluating lists
	 *	Hopefully this tmpl type goes away soon...
	 */
	case TMPL_TYPE_LIST:
		if (!fr_dlist_tail(&cc->nested)) goto null_result;	/* end of list */

		vp = _tmpl_cursor_eval(list, curr, cc);
		if (!vp) goto null_result;

		return vp;

	default:
		fr_assert(0);
	}

	return NULL;
}

/** Initialise a #fr_dcursor_t to the #fr_pair_t specified by a #tmpl_t
 *
 * This makes iterating over the one or more #fr_pair_t specified by a #tmpl_t
 * significantly easier.
 *
 * @param[out] err		May be NULL if no error code is required.
 *				Will be set to:
 *				- 0 on success.
 *				- -1 if no matching #fr_pair_t could be found.
 *				- -2 if list could not be found (doesn't exist in current #request_t).
 *				- -3 if context could not be found (no parent #request_t available).
 * @param[in] ctx		to make temporary allocations under.
 * @param[in] cc		to initialise.  Tracks evaluation state.
 *				Must be explicitly cleared with tmpl_cursor_state_clear
 *				otherwise we will leak memory.
 * @param[in] cursor		to store iterator position.
 * @param[in] request		The current #request_t.
 * @param[in] vpt		specifying the #fr_pair_t type or list to iterate over.
 * @return
 *	- First #fr_pair_t specified by the #tmpl_t.
 *	- NULL if no matching #fr_pair_t found, and NULL on error.
 *
 * @see tmpl_cursor_next
 */
fr_pair_t *tmpl_pair_cursor_init(int *err, TALLOC_CTX *ctx, tmpl_pair_cursor_ctx_t *cc,
				 fr_dcursor_t *cursor, request_t *request, tmpl_t const *vpt)
{
	fr_pair_t		*vp = NULL;
	fr_pair_list_t		*list_head;
	tmpl_request_t		*rr = NULL;
	TALLOC_CTX		*list_ctx;

	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	if (err) *err = 0;

	/*
	 *	Navigate to the correct request context
	 */
	while ((rr = fr_dlist_next(&vpt->data.attribute.rr, rr))) {
		if (tmpl_request_ptr(&request, rr->request) < 0) {
			if (err) {
				*err = -3;
				fr_strerror_printf("Request context \"%s\" not available",
						   fr_table_str_by_value(tmpl_request_ref_table, rr->request, "<INVALID>"));
			}
		error:
			memset(cc, 0, sizeof(*cc));	/* so tmpl_pair_cursor_clear doesn't explode */
			return NULL;
		}
	}

	/*
	 *	Get the right list in the specified context
	 */
	list_head = tmpl_list_head(request, tmpl_list(vpt));
	if (!list_head) {
		if (err) {
			*err = -2;
			fr_strerror_printf("List \"%s\" not available in this context",
					   fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"));
		}
		goto error;
	}
	list_ctx = tmpl_list_ctx(request, tmpl_list(vpt));

	/*
	 *	Initialise the temporary cursor context
	 */
	*cc = (tmpl_pair_cursor_ctx_t){
		.vpt = vpt,
		.ctx = ctx,
		.request = request,
		.list = list_head
	};
	fr_dlist_init(&cc->nested, tmpl_cursor_nested_t, entry);

	/*
	 *	Prime the stack!
	 */
	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
		_tmpl_pair_cursor_init(list_ctx, cc->list, fr_dlist_head(&vpt->data.attribute.ar), cc);
		break;

	case TMPL_TYPE_LIST:
		_tmpl_cursor_list_init(list_ctx, cc->list, fr_dlist_head(&vpt->data.attribute.ar), cc);
		break;

	default:
		fr_assert(0);
		break;
	}

	/*
	 *	Get the first entry from the tmpl
	 */
	vp = fr_dcursor_talloc_iter_init(cursor, list_head, _tmpl_cursor_next, cc, fr_pair_t);
	if (!vp) {
		if (err) {
			*err = -1;
			if (tmpl_is_list(vpt)) {
				fr_strerror_printf("List \"%s\" is empty", vpt->name);
			} else {
				fr_strerror_printf("No matching \"%s\" pairs found", tmpl_da(vpt)->name);
			}
		}
		return NULL;
	}

	return vp;
}

/** Clear any temporary state allocations
 *
 */
void tmpl_pair_cursor_clear(tmpl_pair_cursor_ctx_t *cc)
{
	if (!fr_dlist_num_elements(&cc->nested)) return;/* Help simplify dealing with unused cursor ctxs */

	fr_dlist_remove(&cc->nested, &cc->leaf);	/* Noop if leaf isn't inserted */
	fr_dlist_talloc_free(&cc->nested);

	/*
	 *	Always free the pool because it's allocated when
	 *	any nested ctxs are used.
	 */
	TALLOC_FREE(cc->pool);
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
	tmpl_pair_cursor_ctx_t	cc;

	TMPL_VERIFY(vpt);

	int err;

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	for (vp = tmpl_pair_cursor_init(&err, NULL, &cc, &from, request, vpt);
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
	tmpl_pair_cursor_clear(&cc);

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
	tmpl_pair_cursor_ctx_t	cc;

	TMPL_VERIFY(vpt);

	int err;

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	fr_pair_list_free(out);

	for (vp = tmpl_pair_cursor_init(&err, NULL, &cc, &from, request, vpt);
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
	tmpl_pair_cursor_clear(&cc);

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
	tmpl_pair_cursor_ctx_t	cc;
	fr_pair_t		*vp;
	int			err;

	TMPL_VERIFY(vpt);

	vp = tmpl_pair_cursor_init(&err, request, &cc, &cursor, request, vpt);
	tmpl_pair_cursor_clear(&cc);

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
	tmpl_pair_cursor_ctx_t	cc;
	fr_pair_t		*vp;
	int			err;

	TMPL_VERIFY(vpt);
	fr_assert(tmpl_is_attr(vpt));

	*out = NULL;

	vp = tmpl_pair_cursor_init(&err, NULL, &cc, &cursor, request, vpt);
	tmpl_pair_cursor_clear(&cc);

	switch (err) {
	case 0:
		*out = vp;
		return 0;

	case -1:
	{
		TALLOC_CTX	*ctx;
		fr_pair_list_t	*head;

		tmpl_pair_list_and_ctx(ctx, head, request, tmpl_request(vpt), tmpl_list(vpt));

		MEM(vp = fr_pair_afrom_da(ctx, tmpl_da(vpt)));

		fr_pair_add(head, vp);

		*out = vp;
	}
		return 1;

	default:
		return err;
	}
}

/** Determines points where the reference list extends beyond the current pair tree
 *
 * If a particular branch in the VP hierarchy is incomplete, i.e. the chain of attribute
 * refers to nodes deeper than the nodes currently in the tree, then we return the
 * deepest point node in the tree which matched, and the ar that we failed to evaluate.
 *
 * If the reference list resolves to one or more structural pairs, return those as well.
 *
 * This function can be used for a number of different operations, but it's most useful
 * for determining insertion points for new attributes, or determining which attributes
 * need to be updated.
 *
 * @param[in] ctx		to allocate.  It's recommended to pass a pool with space
 *				for at least five extent structures.
 * @param[out] leaf		List of extents we discovered by evaluating all
 *				attribute references. May be NULL.
 * @param[out] interior 	List of extents that need building out, i.e. references
 *				extend beyond pairs. May be NULL.
 * @param[in] request		The current #request_t.
 * @param[in] vpt		specifying the #fr_pair_t type to retrieve or create.
 *				Must be #TMPL_TYPE_ATTR.
 * @return
 *	- 1 on success a pair was created.
 *	- 0 on success a pair was found.
 *	- -1 if a new #fr_pair_t couldn't be found or created.
 *	- -2 if list could not be found (doesn't exist in current #request_t).
 *	- -3 if context could not be found (no parent #request_t available).
 */
int tmpl_extents_find(TALLOC_CTX *ctx,
		      fr_dlist_head_t *leaf, fr_dlist_head_t *interior,
		      request_t *request, tmpl_t const *vpt)
{
	fr_pair_t		*curr = NULL;
	fr_pair_list_t		*list_head;

	TALLOC_CTX		*list_ctx = NULL;

	tmpl_pair_cursor_ctx_t	cc;
	tmpl_cursor_nested_t	*ns = NULL;

	tmpl_request_t		*rr = NULL;
	tmpl_attr_t const	*ar = NULL;

	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

#define EXTENT_ADD(_out, _ar, _list_ctx, _list) \
	do { \
		tmpl_attr_extent_t	*_extent; \
		MEM(_extent = talloc(ctx, tmpl_attr_extent_t)); \
		*_extent = (tmpl_attr_extent_t){ \
			.ar = _ar,	\
			.list_ctx = _list_ctx, \
			.list = _list	\
		}; \
		fr_dlist_insert_tail(_out, _extent); \
	} while (0)

	/*
	 *	Navigate to the correct request context
	 */
	while ((rr = fr_dlist_next(&vpt->data.attribute.rr, rr))) {
		if (tmpl_request_ptr(&request, rr->request) < 0) {
			fr_strerror_printf("Request context \"%s\" not available",
					   fr_table_str_by_value(tmpl_request_ref_table, rr->request, "<INVALID>"));
			return -3;
		}
	}

	/*
	 *	Get the right list in the specified context
	 */
	list_head = tmpl_list_head(request, tmpl_list(vpt));
	if (!list_head) {
		fr_strerror_printf("List \"%s\" not available in this context",
				   fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"));
		return -2;
	}
	list_ctx = tmpl_list_ctx(request, tmpl_list(vpt));

	/*
	 *	If it's a list, just return the list head
	 */
	if (vpt->type == TMPL_TYPE_LIST) {
	do_list:
		if (leaf) EXTENT_ADD(leaf, NULL, list_ctx, list_head);
		return 0;
	}

	/*
	 *	If it's a leaf skip all the expensive
	 *      initialisation and just return the list
	 *	it's part of.
	 *
	 *	This is only needed because lists are
	 *	treated specially.  Once lists are groups
	 *	this can be removed.
	 */
	ar = fr_dlist_head(&vpt->data.attribute.ar);
	switch (ar->ar_da->type) {
	case FR_TYPE_STRUCTURAL:
		break;

	default:
		goto do_list;
	}

	/*
	 *	Initialise the temporary cursor context
	 */
	cc = (tmpl_pair_cursor_ctx_t){
		.vpt = vpt,
		.ctx = ctx,
		.request = request,
		.list = list_head
	};
	fr_dlist_init(&cc.nested, tmpl_cursor_nested_t, entry);

	/*
	 *	Prime the stack!
	 */
	_tmpl_pair_cursor_init(list_ctx, cc.list, fr_dlist_head(&vpt->data.attribute.ar), &cc);

	/*
	 *	- Continue until there are no evaluation contexts
	 *	- Push a evaluation context if evaluating the head of the
	 *	  stack yields a VP and we're not at the deepest attribute
	 *	  reference.
	 *	- Return if we have a VP and there are no more attribute
	 *	  references to push, i.e. we're at the deepest attribute
	 *	  reference.
	 */
	curr = fr_pair_list_head(list_head);
	while ((ns = fr_dlist_tail(&cc.nested))) {
		tmpl_attr_t const *n_ar;

		list_ctx = ns->list_ctx;
		ar = ns->ar;
		curr = _tmpl_cursor_eval(&list_head->head, curr, &cc);
		if (!curr) {
			/*
			 *	References extend beyond current
			 *	pair tree.
			 */
			if (!ar->resolve_only && interior) EXTENT_ADD(interior, ar, list_ctx, list_head);
			continue;	/* Rely on _tmpl_cursor_eval popping the stack */
		}

		/*
		 *	Evaluate the next reference
		 */
		n_ar = fr_dlist_next(&vpt->data.attribute.ar, ar);
		if (n_ar) {
			ar = n_ar;
			list_head = &curr->vp_group;
			list_ctx = curr;	/* Allocations are under the group */
			_tmpl_pair_cursor_init(list_ctx, list_head, ar, &cc);
			curr = fr_pair_list_head(list_head);
			continue;
		}

		/*
		 *	VP tree may extend beyond
		 *      the reference. If the reference
		 *	was structural, record this as
		 *	an extent.
		 */
		switch (ar->da->type) {
		case FR_TYPE_STRUCTURAL:
			if (leaf) EXTENT_ADD(leaf, NULL, curr, list_head);
			continue;

		default:
			break;
		}
	}

	return 0;
}

/** Allocate interior pairs
 *
 * Builds out the pair tree to the point where leaf attributes can be added
 *
 * @param[out] leaf	List to add built out attributes to.
 * @param[in] interior	List to remove attributes from.
 * @param[in] vpt	We are evaluating.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int tmpl_extents_build_to_leaf(fr_dlist_head_t *leaf, fr_dlist_head_t *interior, tmpl_t const *vpt)
{
	tmpl_attr_extent_t	*extent = NULL;

	while ((extent = fr_dlist_head(interior))) {
		fr_pair_t		*vp;
		fr_pair_list_t		*list;
		tmpl_attr_t const	*ar;
		TALLOC_CTX		*list_ctx = extent->list_ctx;

		fr_assert(extent->ar);	/* Interior extents MUST contain an ar */

		/*
		 *	Try and allocate VPs for the
		 *	rest of the attribute references.
		 */
		for (ar = extent->ar, list = extent->list;
		     ar;
		     ar = fr_dlist_next(&vpt->data.attribute.ar, ar)) {
			switch (ar->type) {
			case TMPL_ATTR_TYPE_NORMAL:
			case TMPL_ATTR_TYPE_UNKNOWN:
				/*
				 *	Don't build leaf attributes
				 */
				switch (ar->ar_da->type) {
				case FR_TYPE_STRUCTURAL:
					break;

				default:
					continue;
				}

				MEM(vp = fr_pair_afrom_da(list_ctx, ar->ar_da));	/* Copies unknowns */
				fr_pair_append(list, vp);
				list = &vp->vp_group;
				list_ctx = vp;		/* New allocations occur under the VP */
				break;

			default:
				fr_assert_fail("references of this type should have been resolved");
				return -1;
			}
		}

		fr_dlist_remove(interior, extent);	/* Do this *before* zeroing the dlist headers */
		*extent = (tmpl_attr_extent_t){
			.list = list,
			.list_ctx = list_ctx
		};
		fr_dlist_insert_tail(leaf, extent);	/* move between in and out */
	}

	return 0;
}

void tmpl_extents_debug(fr_dlist_head_t *head)
{
	tmpl_attr_extent_t const *extent = NULL;
	fr_pair_t *vp = NULL;

	for (extent = fr_dlist_head(head);
	     extent;
	     extent = fr_dlist_next(head, extent)) {
	     	tmpl_attr_t const *ar = extent->ar;
	     	char const *ctx_name;

	     	if (ar) {
			FR_FAULT_LOG("extent-interior-attr");
			tmpl_attr_ref_debug(extent->ar, 0);
		} else {
			FR_FAULT_LOG("extent-leaf");
		}

		ctx_name = talloc_get_name(extent->list_ctx);
		if (strcmp(ctx_name, "fr_pair_t") == 0) {
			FR_FAULT_LOG("list_ctx     : %p (%s, %s)", extent->list_ctx, ctx_name,
				     ((fr_pair_t *)extent->list_ctx)->da->name);
		} else {
			FR_FAULT_LOG("list_ctx     : %p (%s)", extent->list_ctx, ctx_name);
		}
		FR_FAULT_LOG("list         : %p", extent->list);
		if (fr_pair_list_empty(extent->list)) {
			FR_FAULT_LOG("list (first) : none (%p)", extent->list);
		} else {
			vp = fr_pair_list_head(extent->list);
			FR_FAULT_LOG("list (first) : %s (%p)", vp->da->name, extent->list);
		}
	}

}
