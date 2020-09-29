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
 * @brief #VALUE_PAIR template functions
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

/** Resolve attribute #pair_list_t value to an attribute list.
 *
 * The value returned is a pointer to the pointer of the HEAD of a #VALUE_PAIR list in the
 * #REQUEST. If the head of the list changes, the pointer will still be valid.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_list_t value to resolve to #VALUE_PAIR list. Will be NULL if list
 *	name couldn't be resolved.
 * @return a pointer to the HEAD of a list in the #REQUEST.
 *
 * @see tmpl_cursor_init
 */
VALUE_PAIR **radius_list(REQUEST *request, pair_list_t list)
{
	if (!request) return NULL;

	switch (list) {
	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;

	case PAIR_LIST_REQUEST:
		if (!request->packet) return NULL;
		return &request->packet->vps;

	case PAIR_LIST_REPLY:
		if (!request->reply) return NULL;
		return &request->reply->vps;

	case PAIR_LIST_CONTROL:
		return &request->control;

	case PAIR_LIST_STATE:
		return &request->state;
	}

	RWDEBUG2("List \"%s\" is not available",
		fr_table_str_by_value(pair_list_table, list, "<INVALID>"));

	return NULL;
}

/** Resolve a list to the #RADIUS_PACKET holding the HEAD pointer for a #VALUE_PAIR list
 *
 * Returns a pointer to the #RADIUS_PACKET that holds the HEAD pointer of a given list,
 * for the current #REQUEST.
 *
 * @param[in] request To resolve list in.
 * @param[in] list #pair_list_t value to resolve to #RADIUS_PACKET.
 * @return
 *	- #RADIUS_PACKET on success.
 *	- NULL on failure.
 *
 * @see radius_list
 */
RADIUS_PACKET *radius_packet(REQUEST *request, pair_list_t list)
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

/** Return the correct TALLOC_CTX to alloc #VALUE_PAIR in, for a list
 *
 * Allocating new #VALUE_PAIR in the context of a #REQUEST is usually wrong.
 * #VALUE_PAIR should be allocated in the context of a #RADIUS_PACKET, so that if the
 * #RADIUS_PACKET is freed before the #REQUEST, the associated #VALUE_PAIR lists are
 * freed too.
 *
 * @param[in] request containing the target lists.
 * @param[in] list #pair_list_t value to resolve to TALLOC_CTX.
 * @return
 *	- TALLOC_CTX on success.
 *	- NULL on failure.
 *
 * @see radius_list
 */
TALLOC_CTX *radius_list_ctx(REQUEST *request, pair_list_t list)
{
	if (!request) return NULL;

	switch (list) {
	case PAIR_LIST_REQUEST:
		return request->packet;

	case PAIR_LIST_REPLY:
		return request->reply;

	case PAIR_LIST_CONTROL:
		return request;

	case PAIR_LIST_STATE:
		return request->state_ctx;

	/* Don't add default */
	case PAIR_LIST_UNKNOWN:
		break;
	}

	return NULL;
}

/** Resolve a #request_ref_t to a #REQUEST.
 *
 * Sometimes #REQUEST structs may be chained to each other, as is the case
 * when internally proxying EAP. This function resolves a #request_ref_t
 * to a #REQUEST higher in the chain than the current #REQUEST.
 *
 * @see radius_list
 * @param[in,out] context #REQUEST to start resolving from, and where to write
 *	a pointer to the resolved #REQUEST back to.
 * @param[in] name (request) to resolve.
 * @return
 *	- 0 if request is valid in this context.
 *	- -1 if request is not valid in this context.
 */
int radius_request(REQUEST **context, request_ref_t name)
{
	REQUEST *request = *context;

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

/** @name Resolve a #tmpl_t outputting the result in various formats
 *
 * @{
 */

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
 *	- The length of data written to buff, or pointed to by out.
 */
ssize_t _tmpl_to_type(void *out,
		      uint8_t *buff, size_t bufflen,
		      REQUEST *request,
		      tmpl_t const *vpt,
		      xlat_escape_legacy_t escape, void const *escape_ctx,
		      fr_type_t dst_type)
{
	fr_value_box_t		value_to_cast;
	fr_value_box_t		value_from_cast = { .type = FR_TYPE_INVALID };
	fr_value_box_t const	*to_cast = &value_to_cast;
	fr_value_box_t const	*from_cast = &value_from_cast;

	VALUE_PAIR		*vp = NULL;

	fr_type_t		src_type = FR_TYPE_INVALID;

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
			fr_strerror_printf("Missing expansion buffer for EXEC");
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
			fr_strerror_printf("Missing expansion buffer for XLAT_STRUCT");
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
				fr_strerror_printf("Missing expansion buffer for octet->string cast");
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
				fr_strerror_printf("Missing expansion buffer to store cast output");
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
				fr_strerror_printf("Missing expansion buffer to store cast output");
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
		       REQUEST *request,
		       tmpl_t const *vpt,
		       xlat_escape_legacy_t escape, void const *escape_ctx,
		       fr_type_t dst_type)
{
	fr_value_box_t const	*to_cast = NULL;
	fr_value_box_t		from_cast;

	VALUE_PAIR		*vp = NULL;
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
		value.datum.length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, &src_type, NULL,
					    value.vb_strvalue, value.datum.length, '"', false);
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

		value.datum.length = slen;

		/*
		 *	Undo any of the escaping that was done by the
		 *	xlat expansion function.
		 *
		 *	@fixme We need a way of signalling xlat not to escape things.
		 */
		ret = fr_value_box_from_str(tmp_ctx, &tmp, &src_type, NULL,
					    value.vb_strvalue, value.datum.length, '"', false);
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

		to_cast = tmpl_value(vpt);
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

	return from_cast.datum.length;
}

/** Traverse a TLV attribute
 *
 * @param[in] ns	Tracks tree position between cursor calls.
 * @return the number of attributes matching ar.
 */
static VALUE_PAIR *_tmpl_cursor_tlv_eval(VALUE_PAIR **prev, UNUSED VALUE_PAIR *current, tmpl_cursor_nested_t *ns)
{
	fr_cursor_stack_t	*cs;
	fr_cursor_t		*cursor;
	VALUE_PAIR		*vp;

	cs = ns->tlv.cursor_stack;
	cursor = &cs->cursor[cs->depth - 1];

	/*
	 *	Our final stopping condition is when the shallowest
	 *      cursor returns NULL.  That means we've evaluated
	 *	the entire subtree.
	 */
	while (cs->depth > 0) {
		for (vp = fr_cursor_current(cursor);
		     vp;
		     vp = fr_cursor_next(cursor)) {
			*prev = cursor->prev;

			/*
			 *	Exact match, we're done.
			 */
			if (fr_dict_attr_cmp(vp->da, ns->ar->ar_da) == 0) {
				fr_cursor_next(cursor);	/* Advance to correct position for next call */
				return vp;
			}

			/*
			 *	Traverse the intermediary VP
			 */
			if ((vp->da->depth < ns->ar->ar_da->depth) &&
			    (fr_dict_attr_cmp(ns->tlv.da_stack.da[vp->da->depth], vp->da) == 0)) {
				cursor = &cs->cursor[cs->depth++];
				fr_cursor_init(cursor, &vp->vp_group);
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

/** Initialise an evaluation ctx for traversing a TLV attribute
 *
 */
static inline CC_HINT(always_inline)
void _tmpl_cursor_tlv_init(VALUE_PAIR **children, tmpl_attr_t const *ar, tmpl_cursor_ctx_t *cc)
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

	MEM(ns = talloc_pooled_object(cc->ctx, tmpl_cursor_nested_t,
				      1, sizeof(fr_cursor_stack_t) + (sizeof(fr_cursor_t) * span)));
	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_tlv_eval,
		.tlv = {
			.cursor_stack = fr_cursor_stack_alloc(ns, span)
		}
	};

	/*
	 *	Initialise the first level cursor
	 *	to point to the list or children of
	 *	a tlv or group.
	 */
	fr_cursor_init(&ns->tlv.cursor_stack->cursor[0], children);
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
 */
static VALUE_PAIR *_tmpl_cursor_group_eval(VALUE_PAIR **prev, UNUSED VALUE_PAIR *current, tmpl_cursor_nested_t *ns)
{
	VALUE_PAIR *vp;

	for (vp = fr_cursor_current(&ns->group.cursor);
	     vp;
	     vp = fr_cursor_next(&ns->group.cursor)) {
	     	*prev = ns->group.cursor.prev;

		if (fr_dict_attr_cmp(ns->ar->ar_da, vp->da) == 0) {
			fr_cursor_next(&ns->group.cursor);	/* Advance to correct position for next call */
			return vp;
		}
	}

	return NULL;
}

/** Initialise the evaluation context for traversing a group attribute
 *
 */
static inline CC_HINT(always_inline)
void _tmpl_cursor_group_init(VALUE_PAIR **children, tmpl_attr_t const *ar, tmpl_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t *ns;

	MEM(ns = talloc(cc->ctx, tmpl_cursor_nested_t));
	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_group_eval,
	};
	fr_cursor_init(&ns->group.cursor, children);
	fr_dlist_insert_tail(&cc->nested, ns);
}

/** Find a leaf attribute
 *
 */
static VALUE_PAIR *_tmpl_cursor_leaf_eval(VALUE_PAIR **prev, VALUE_PAIR *curr, tmpl_cursor_nested_t *ns)
{
	VALUE_PAIR *vp = curr;

	while (vp) {
		if (fr_dict_attr_cmp(ns->ar->ar_da, vp->da) == 0) return vp;

		*prev = vp;
		vp = vp->next;
	}

	return NULL;
}

/** Initialise the evaluation context for finding a leaf attribute
 *
 */
static inline CC_HINT(always_inline)
void _tmpl_cursor_leaf_init(VALUE_PAIR **children, tmpl_attr_t const *ar, tmpl_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t	*ns = &cc->leaf;

	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_leaf_eval
	};
	ns->leaf.list_head = children;
	fr_dlist_insert_tail(&cc->nested, ns);
}

/** Stub list eval function until we can remove lists
 *
 */
static VALUE_PAIR *_tmpl_cursor_list_eval(UNUSED VALUE_PAIR **prev, VALUE_PAIR *curr, UNUSED tmpl_cursor_nested_t *ns)
{
	return curr;
}

static inline CC_HINT(always_inline)
void _tmpl_cursor_list_init(VALUE_PAIR **children, tmpl_attr_t const *ar, tmpl_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t *ns;

	ns = &cc->leaf;
	*ns = (tmpl_cursor_nested_t){
		.ar = ar,
		.func = _tmpl_cursor_list_eval
	};
	ns->leaf.list_head = children;
	fr_dlist_insert_tail(&cc->nested, ns);
}

static inline CC_HINT(always_inline) void _tmpl_cursor_eval_pop(tmpl_cursor_ctx_t *cc)
{
	tmpl_cursor_nested_t *ns = fr_dlist_pop_tail(&cc->nested);

	if (ns != &cc->leaf) talloc_free(ns);
}

/** Evaluates, then, sometimes, pops evaluation contexts from the tmpl stack
 *
 * To pop or not to pop is determined by whether evaluating the context again
 * would/should/could produce another VALUE_PAIR.
 */
static inline CC_HINT(always_inline)
VALUE_PAIR *_tmpl_cursor_eval(VALUE_PAIR **prev, VALUE_PAIR *curr, tmpl_cursor_ctx_t *cc)
{
	tmpl_attr_t const	*ar;
	tmpl_cursor_nested_t	*ns;
	VALUE_PAIR		*iter = curr, *vp;

	ns = fr_dlist_tail(&cc->nested);
	ar = ns->ar;

	if (ar) switch (ar->ar_num) {
	/*
	 *	Get the first instance
	 */
	case NUM_ANY:
		vp = ns->func(prev, curr, ns);
		_tmpl_cursor_eval_pop(cc);
		break;

	/*
	 *	Get all instances
	 */
	case NUM_ALL:
	case NUM_COUNT:
	all_inst:
		vp = ns->func(prev, curr, ns);
		if (!vp) _tmpl_cursor_eval_pop(cc);	/* pop only when we're done */
		break;

	/*
	 *	Get the last instance
	 */
	case NUM_LAST:
		vp = NULL;
		while ((iter = ns->func(prev, iter, ns))) {
			vp = iter;

			if (!vp->next) break;

			iter = vp->next;
			*prev = vp;
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
			vp = ns->func(prev, iter, ns);
			if (!vp) break;	/* Prev and next at the correct points */

			if (++i > ar->num) break;

			iter = vp->next;
			*prev = vp;
		};
		_tmpl_cursor_eval_pop(cc);
	}
		break;
	} else goto all_inst;	/* Used for TMPL_TYPE_LIST */

	return vp;
}

static inline CC_HINT(always_inline)
void _tmpl_cursor_init(VALUE_PAIR **children, tmpl_attr_t const *ar, tmpl_cursor_ctx_t *cc)
{
	if (fr_dlist_next(&cc->vpt->data.attribute.ar, ar)) switch (ar->ar_da->type) {
	case FR_TYPE_TLV:
	case FR_TYPE_VSA:
	case FR_TYPE_VENDOR:
		_tmpl_cursor_tlv_init(children, ar, cc);
		break;

	case FR_TYPE_GROUP:
		_tmpl_cursor_group_init(children, ar, cc);
		break;

	default:
	leaf:
		_tmpl_cursor_leaf_init(children, ar, cc);
		break;
	} else goto leaf;
}

static void *_tmpl_cursor_next(void **prev, void *curr, void *uctx)
{
	tmpl_cursor_ctx_t	*cc = uctx;
	tmpl_t const		*vpt = cc->vpt;

	VALUE_PAIR		*vp;
	VALUE_PAIR		**list_head;

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
			vp = _tmpl_cursor_eval((VALUE_PAIR **)prev, curr, cc);
			if (!vp) continue;

			ar = fr_dlist_next(&vpt->data.attribute.ar, ar);
			if (ar) {
				list_head = &vp->vp_group;
				_tmpl_cursor_init(list_head, ar, cc);
				curr = NULL;
				*prev = NULL;
				continue;
			}

			return vp;
		}

	null_result:
		*prev = curr;
		return NULL;
	}

	/*
	 *	Hacks for evaluating lists
	 *	Hopefully this tmpl type goes away soon...
	 */
	case TMPL_TYPE_LIST:
		if (!fr_dlist_tail(&cc->nested)) goto null_result;	/* end of list */

		vp = _tmpl_cursor_eval((VALUE_PAIR **)prev, curr, cc);
		if (!vp) goto null_result;

		return vp;

	default:
		fr_assert(0);
	}

	return NULL;
}

/** Initialise a #fr_cursor_t to the #VALUE_PAIR specified by a #tmpl_t
 *
 * This makes iterating over the one or more #VALUE_PAIR specified by a #tmpl_t
 * significantly easier.
 *
 * @param[out] err		May be NULL if no error code is required.
 *				Will be set to:
 *				- 0 on success.
 *				- -1 if no matching #VALUE_PAIR could be found.
 *				- -2 if list could not be found (doesn't exist in current #REQUEST).
 *				- -3 if context could not be found (no parent #REQUEST available).
 * @param[in] ctx		to make temporary allocations under.
 * @param[in] cc		to initialise.  Tracks evaluation state.
 *				Must be explicitly cleared with tmpl_cursor_state_clear
 *				otherwise we will leak memory.
 * @param[in] cursor		to store iterator position.
 * @param[in] request		The current #REQUEST.
 * @param[in] vpt		specifying the #VALUE_PAIR type or list to iterate over.
 * @return
 *	- First #VALUE_PAIR specified by the #tmpl_t.
 *	- NULL if no matching #VALUE_PAIR found, and NULL on error.
 *
 * @see tmpl_cursor_next
 */
VALUE_PAIR *tmpl_cursor_init(int *err, TALLOC_CTX *ctx, tmpl_cursor_ctx_t *cc,
			     fr_cursor_t *cursor, REQUEST *request, tmpl_t const *vpt)
{
	VALUE_PAIR		*vp = NULL, **list_head;
	tmpl_request_t		*rr = NULL;

	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	if (err) *err = 0;

	/*
	 *	Navigate to the correct request context
	 */
	while ((rr = fr_dlist_next(&vpt->data.attribute.rr, rr))) {
		if (radius_request(&request, rr->request) < 0) {
			if (err) {
				*err = -3;
				fr_strerror_printf("Request context \"%s\" not available",
						   fr_table_str_by_value(request_ref_table, rr->request, "<INVALID>"));
			}
		error:
			memset(cc, 0, sizeof(*cc));	/* so tmpl_cursor_clear doesn't explode */
			fr_dlist_init(&cc->nested, tmpl_cursor_nested_t, entry);
			return NULL;
		}
	}

	/*
	 *	Get the right list in the specified context
	 */
	list_head = radius_list(request, tmpl_list(vpt));
	if (!list_head) {
		if (err) {
			*err = -2;
			fr_strerror_printf("List \"%s\" not available in this context",
					   fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"));
		}
		goto error;
	}

	/*
	 *	Initialise the temporary cursor context
	 */
	*cc = (tmpl_cursor_ctx_t){
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
		_tmpl_cursor_init(cc->list, fr_dlist_head(&vpt->data.attribute.ar), cc);
		break;

	case TMPL_TYPE_LIST:
		_tmpl_cursor_list_init(cc->list, fr_dlist_head(&vpt->data.attribute.ar), cc);
		break;

	default:
		fr_assert(0);
		break;
	}

	/*
	 *	Get the first entry from the tmpl
	 */
	vp = fr_cursor_talloc_iter_init(cursor, list_head, _tmpl_cursor_next, cc, VALUE_PAIR);
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
void tmpl_cursor_clear(tmpl_cursor_ctx_t *cc)
{
	fr_dlist_remove(&cc->nested, &cc->leaf);	/* Noop if leaf isn't inserted */
	fr_dlist_talloc_free(&cc->nested);
}

/** Copy pairs matching a #tmpl_t in the current #REQUEST
 *
 * @param ctx to allocate new #VALUE_PAIR in.
 * @param out Where to write the copied #VALUE_PAIR (s).
 * @param request The current #REQUEST.
 * @param vpt specifying the #VALUE_PAIR type or list to copy.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 *	- -4 on memory allocation error.
 */
int tmpl_copy_vps(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, tmpl_t const *vpt)
{
	VALUE_PAIR		*vp;
	fr_cursor_t		from, to;
	tmpl_cursor_ctx_t	cc;

	TMPL_VERIFY(vpt);

	int err;

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	*out = NULL;

	fr_cursor_init(&to, out);

	for (vp = tmpl_cursor_init(&err, NULL, &cc, &from, request, vpt);
	     vp;
	     vp = fr_cursor_next(&from)) {
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(out);
			fr_strerror_printf("Out of memory");
			err = -4;
			break;
		}
		fr_cursor_append(&to, vp);
	}
	tmpl_cursor_clear(&cc);

	return err;
}

/** Returns the first VP matching a #tmpl_t
 *
 * @param[out] out where to write the retrieved vp.
 * @param[in] request The current #REQUEST.
 * @param[in] vpt specifying the #VALUE_PAIR type to find.
 *	Must be one of the following types:
 *	- #TMPL_TYPE_LIST
 *	- #TMPL_TYPE_ATTR
 * @return
 *	- 0 on success (found matching #VALUE_PAIR).
 *	- -1 if no matching #VALUE_PAIR could be found.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 */
int tmpl_find_vp(VALUE_PAIR **out, REQUEST *request, tmpl_t const *vpt)
{
	fr_cursor_t		cursor;
	tmpl_cursor_ctx_t	cc;
	VALUE_PAIR		*vp;
	int			err;

	TMPL_VERIFY(vpt);

	vp = tmpl_cursor_init(&err, request, &cc, &cursor, request, vpt);
	tmpl_cursor_clear(&cc);

	if (out) *out = vp;

	return err;
}

/** Returns the first VP matching a #tmpl_t, or if no VPs match, creates a new one.
 *
 * @param[out] out where to write the retrieved or created vp.
 * @param[in] request The current #REQUEST.
 * @param[in] vpt specifying the #VALUE_PAIR type to retrieve or create.  Must be #TMPL_TYPE_ATTR.
 * @return
 *	- 1 on success a pair was created.
 *	- 0 on success a pair was found.
 *	- -1 if a new #VALUE_PAIR couldn't be found or created.
 *	- -2 if list could not be found (doesn't exist in current #REQUEST).
 *	- -3 if context could not be found (no parent #REQUEST available).
 */
int tmpl_find_or_add_vp(VALUE_PAIR **out, REQUEST *request, tmpl_t const *vpt)
{
	fr_cursor_t		cursor;
	tmpl_cursor_ctx_t	cc;
	VALUE_PAIR		*vp;
	int			err;

	TMPL_VERIFY(vpt);
	fr_assert(tmpl_is_attr(vpt));

	*out = NULL;

	vp = tmpl_cursor_init(&err, NULL, &cc, &cursor, request, vpt);
	tmpl_cursor_clear(&cc);

	switch (err) {
	case 0:
		*out = vp;
		return 0;

	case -1:
	{
		TALLOC_CTX	*ctx;
		VALUE_PAIR	**head;

		RADIUS_LIST_AND_CTX(ctx, head, request, tmpl_request(vpt), tmpl_list(vpt));

		MEM(vp = fr_pair_afrom_da(ctx, tmpl_da(vpt)));
		*out = vp;
	}
		return 0;

	default:
		return err;
	}
}
/** @} */
