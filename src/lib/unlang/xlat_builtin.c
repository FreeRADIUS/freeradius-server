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
 * @file xlat_builtin.c
 * @brief String expansion ("translation").  Baked in expansions.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

/**
 * @defgroup xlat_functions xlat expansion functions
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/table.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <freeradius-devel/tls/openssl_user_macros.h>
#  include <openssl/evp.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>

static char const hextab[] = "0123456789abcdef";
static TALLOC_CTX *xlat_ctx;

typedef struct {
	fr_test_point_pair_decode_t	*tp_decode;
	fr_dict_t const			*dict;		//!< Restrict xlat to this namespace
} xlat_pair_decode_uctx_t;

/** Copy an argument from the input list to the output cursor.
 *
 *  For now we just move it.  This utility function will let us have
 *  value-box cursors as input arguments.
 *
 * @param[in] ctx	talloc ctx
 * @param[out] out	where the value-box will be stored
 * @param[in] in	input value-box list
 * @param[in] vb		the argument to copy
 */
void xlat_arg_copy_out(TALLOC_CTX *ctx, fr_dcursor_t *out, fr_value_box_list_t *in, fr_value_box_t *vb)
{
	fr_value_box_list_remove(in, vb);
	if (talloc_parent(vb) != ctx) {
		(void) talloc_steal(ctx, vb);
	}
	fr_dcursor_append(out, vb);
}

/*
 *	Regular xlat functions
 */
static xlat_arg_parser_t const xlat_func_debug_args[] = {
	{ .single = true, .type = FR_TYPE_INT8 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Dynamically change the debugging level for the current request
 *
 * Example:
@verbatim
%debug(3)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_debug(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *args)
{
	int level = 0;
	fr_value_box_t	*vb, *lvl_vb;

	XLAT_ARGS(args, &lvl_vb);

	/*
	 *  Expand to previous (or current) level
	 */
	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_INT8, NULL));
	vb->vb_int8 = request->log.lvl;
	fr_dcursor_append(out, vb);

	/*
	 *  Assume we just want to get the current value and NOT set it to 0
	 */
	if (!lvl_vb) goto done;

	level = lvl_vb->vb_int8;
	if (level == 0) {
		request->log.lvl = RAD_REQUEST_LVL_NONE;
	} else {
		if (level > L_DBG_LVL_MAX) level = L_DBG_LVL_MAX;
		request->log.lvl = level;
	}

done:
	return XLAT_ACTION_DONE;
}


static void xlat_debug_attr_vp(request_t *request, fr_pair_t const *vp,
			       fr_dict_attr_t const *da);

static void xlat_debug_attr_list(request_t *request, fr_pair_list_t const *list,
				 fr_dict_attr_t const *parent)
{
	fr_pair_t *vp;

	for (vp = fr_pair_list_next(list, NULL);
	     vp != NULL;
	     vp = fr_pair_list_next(list, vp)) {
		xlat_debug_attr_vp(request, vp, parent);
	}
}


static xlat_arg_parser_t const xlat_pair_cursor_args[] = {
	XLAT_ARG_PARSER_CURSOR,
	XLAT_ARG_PARSER_TERMINATOR
};

static void xlat_debug_attr_vp(request_t *request, fr_pair_t const *vp,
			       fr_dict_attr_t const *parent)
{
	fr_dict_vendor_t const		*vendor;
	fr_table_num_ordered_t const	*type;
	size_t				i;
	ssize_t				slen;
	fr_sbuff_t			sbuff;
	char				buffer[1024];

	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	/*
	 *	Squash the names down if necessary.
	 */
	if (!RDEBUG_ENABLED3) {
		slen = fr_pair_print_name(&sbuff, parent, &vp);
	} else {
		slen = fr_sbuff_in_sprintf(&sbuff, "%s %s ", vp->da->name, fr_tokens[vp->op]);
	}
	if (slen <= 0) return;

	switch (vp->vp_type) {
	case FR_TYPE_STRUCTURAL:
		RIDEBUG2("%s{", buffer);
		RINDENT();
		xlat_debug_attr_list(request, &vp->vp_group, vp->da);
		REXDENT();
		RIDEBUG2("}");
		break;

	default:
		RIDEBUG2("%s%pV", buffer, &vp->data);
	}

	if (!RDEBUG_ENABLED3) return;

	RINDENT();
	RIDEBUG3("da         : %p", vp->da);
	RIDEBUG3("is_raw     : %pV", fr_box_bool(vp->vp_raw));
	RIDEBUG3("is_unknown : %pV", fr_box_bool(vp->da->flags.is_unknown));

	if (RDEBUG_ENABLED3) {
		RIDEBUG3("parent     : %s (%p)", vp->da->parent->name, vp->da->parent);
	} else {
		RIDEBUG2("parent     : %s", vp->da->parent->name);
	}
	RIDEBUG3("attr       : %u", vp->da->attr);
	vendor = fr_dict_vendor_by_da(vp->da);
	if (vendor) RIDEBUG2("vendor     : %u (%s)", vendor->pen, vendor->name);
	RIDEBUG3("type       : %s", fr_type_to_str(vp->vp_type));

	switch (vp->vp_type) {
	case FR_TYPE_LEAF:
		if (fr_box_is_variable_size(&vp->data)) {
			RIDEBUG3("length     : %zu", vp->vp_length);
		}
		RIDEBUG3("tainted    : %pV", fr_box_bool(vp->data.tainted));
		break;
	default:
		break;
	}

	if (!RDEBUG_ENABLED4) {
		REXDENT();
		return;
	}

	for (i = 0; i < fr_type_table_len; i++) {
		int pad;

		fr_value_box_t *dst = NULL;

		type = &fr_type_table[i];

		if ((fr_type_t) type->value == vp->vp_type) goto next_type;

		/*
		 *	Don't cast TO structural, or FROM structural types.
		 */
		if (!fr_type_is_leaf(type->value) || !fr_type_is_leaf(vp->vp_type)) goto next_type;

		MEM(dst = fr_value_box_acopy(NULL, &vp->data));

		/* We expect some to fail */
		if (fr_value_box_cast_in_place(dst, dst, type->value, NULL) < 0) {
			goto next_type;
		}

		if ((pad = (11 - type->name.len)) < 0) pad = 0;

		RINDENT();
		RDEBUG4("as %s%*s: %pV", type->name.str, pad, " ", dst);
		REXDENT();

	next_type:
		talloc_free(dst);
	}

	REXDENT();
}

/** Common function to move boxes from input list to output list
 *
 * This can be used to implement safe_for functions, as the xlat framework
 * can be used for concatenation, casting, and marking up output boxes as
 * safe_for.
 */
xlat_action_t xlat_transparent(TALLOC_CTX *ctx, fr_dcursor_t *out,
			       UNUSED xlat_ctx_t const *xctx,
			       UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_list_foreach(args, vb) {
		xlat_arg_copy_out(ctx, out, args, vb);
	}

	return XLAT_ACTION_DONE;
}

/** Print out attribute info
 *
 * Prints out all instances of a current attribute, or all attributes in a list.
 *
 * At higher debugging levels, also prints out alternative decodings of the same
 * value. This is helpful to determine types for unknown attributes of long
 * passed vendors, or just crazy/broken NAS.
 *
 * This expands to a zero length string.
 *
 * Example:
@verbatim
%pairs.debug(&request)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_pairs_debug(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *args)
{
	fr_pair_t		*vp;
	fr_dcursor_t		*cursor;
	fr_value_box_t		*in_head;

	XLAT_ARGS(args, &in_head);

	if (!RDEBUG_ENABLED2) return XLAT_ACTION_DONE;	/* NOOP if debugging isn't enabled */

	cursor = fr_value_box_get_cursor(in_head);

	RDEBUG("Attributes matching \"%s\"", in_head->vb_cursor_name);

	RINDENT();
	for (vp = fr_dcursor_current(cursor);
	     vp;
	     vp = fr_dcursor_next(cursor)) {
		xlat_debug_attr_vp(request, vp, NULL);
	}
	REXDENT();

	return XLAT_ACTION_DONE;
}

#ifdef __clang__
#pragma clang diagnostic ignored "-Wgnu-designator"
#endif

static const fr_sbuff_escape_rules_t xlat_filename_escape = {
	.name = "filename",
	.chr = '_',
	.do_utf8 = true,
	.do_hex = true,

	.esc = {
		[ 0x00 ... 0x2d ] = true,		// special characters, but not '.'
		[ 0x2f ] = true,			// /
		[ 0x3A ... 0x3f ] = true,		// :;<=>?, but not "@"
		[ 0x5b ... 0x5e ] = true,		// [\]^
		[ 0x60 ] = true,			// back-tick
		[ 0x7b ... 0xff ] = true,		// {|}, and all chars which have high bit set, but aren't UTF-8
	},
};

static const fr_sbuff_escape_rules_t xlat_filename_escape_dots = {
	.name = "filename",
	.chr = '_',
	.do_utf8 = true,
	.do_hex = true,

	.esc = {
		[ 0x00 ... 0x2f ] = true,		// special characters, '.', '/', etc.
		[ 0x3A ... 0x3f ] = true,		// :;<=>?, but not "@"
		[ 0x5b ... 0x5e ] = true,		// [\]^
		[ 0x60 ] = true,			// back-tick
		[ 0x7b ... 0xff ] = true,		// {|}, and all chars which have high bit set, but aren't UTF-8
	},
};

#define FR_FILENAME_SAFE_FOR ((uintptr_t) filename_xlat_escape)

static int CC_HINT(nonnull(2,3)) filename_xlat_escape(UNUSED request_t *request, fr_value_box_t *vb, UNUSED void *uctx)
{
	fr_sbuff_t			*out = NULL;
	fr_value_box_entry_t		entry;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&out, 256, 4096);

	/*
	 *	Integers are just numbers, so they don't need to be escaped.
	 *
	 *	Except that FR_TYPE_INTEGER includes 'date' and 'time_delta', which is annoying.
	 *
	 *	'octets' get printed as hex, so they don't need to be escaped.
	 */
	switch (vb->type) {
	case FR_TYPE_BOOL:
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
	case FR_TYPE_SIZE:
	case FR_TYPE_OCTETS:
		return 0;

	case FR_TYPE_NON_LEAF:
		fr_assert(0);
		return -1;

	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_IFID:
	case FR_TYPE_ETHERNET:
	case FR_TYPE_FLOAT32:
	case FR_TYPE_FLOAT64:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_ATTR:
		/*
		 *	Printing prefixes etc. does NOT result in the escape function being called!  So
		 *	instead, we cast the results to a string, and then escape the string.
		 */
		if (fr_value_box_cast_in_place(vb, vb, FR_TYPE_STRING, NULL) < 0) return -1;

		fr_value_box_print(out, vb, &xlat_filename_escape);
		break;

	case FR_TYPE_STRING:
		/*
		 *	Note that we set ".always_escape" in the function arguments, so that we get called for
		 *	IP addresses.  Otherwise, the xlat evaluator and/or the list_concat_as_string
		 *	functions won't call us.  And the expansion will return IP addresses with '/' in them.
		 *	Which is not what we want.
		 */
		if (fr_value_box_is_safe_for(vb, FR_FILENAME_SAFE_FOR)) return 1;

		/*
		 *	If the tainted string has a leading '.', then escape _all_ periods in it.  This is so that we
		 *	don't accidentally allow a "safe" value to end with '/', and then an "unsafe" value contains
		 *	"..", and we now have a directory traversal attack.
		 *
		 *	The escape rules will escape '/' in unsafe strings, so there's no possibility for an unsafe
		 *	string to either end with a '/', or to contain "/.." itself.
		 *
		 *	Allowing '.' in the middle of the string means we can have filenames based on realms, such as
		 *	"log/aland@freeradius.org".
		 */
		if (vb->vb_strvalue[0] == '.') {
			fr_value_box_print(out, vb, &xlat_filename_escape_dots);
		} else {
			fr_value_box_print(out, vb, &xlat_filename_escape);
		}

		break;
	}

	entry = vb->entry;
	fr_value_box_clear(vb);
	(void) fr_value_box_bstrndup(vb, vb, NULL, fr_sbuff_start(out), fr_sbuff_used(out), false);
	vb->entry = entry;

	return 0;
}

static xlat_arg_parser_t const xlat_func_file_name_args[] = {
	{ .required = true,  .concat = true, .type = FR_TYPE_STRING,
	  .func = filename_xlat_escape, .safe_for = FR_FILENAME_SAFE_FOR, .always_escape = true },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_arg_parser_t const xlat_func_file_name_count_args[] = {
	{ .required = true,  .concat = true, .type = FR_TYPE_STRING,
	  .func = filename_xlat_escape, .safe_for = FR_FILENAME_SAFE_FOR, .always_escape = true },
	{ .required = false, .type = FR_TYPE_UINT32 },
	XLAT_ARG_PARSER_TERMINATOR
};


static xlat_action_t xlat_func_file_exists(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;
	struct stat	buf;

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);
	filename = vb->vb_strvalue;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, dst);

	dst->vb_bool = (stat(filename, &buf) == 0);

	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_file_head(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;
	ssize_t		len;
	int		fd;
	char		*p, buffer[256];

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);
	filename = vb->vb_strvalue;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		REDEBUG3("Failed opening file %s - %s", filename, fr_syserror(errno));
		return XLAT_ACTION_FAIL;
	}

	len = read(fd, buffer, sizeof(buffer));
	if (len < 0) {
		REDEBUG3("Failed reading file %s - %s", filename, fr_syserror(errno));
		close(fd);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Find the first CR/LF, but bail if we get any weird characters.
	 */
	for (p = buffer; p < (buffer + len); p++) {
		if ((*p == '\r') || (*p == '\n')) {
			break;
		}

		if ((*p < ' ') && (*p != '\t')) {
		invalid:
			REDEBUG("Invalid text in file %s", filename);
			close(fd);
			return XLAT_ACTION_FAIL;
		}
	}

	if ((p - buffer) > len) goto invalid;
	close(fd);

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));
	if (fr_value_box_bstrndup(dst, dst, NULL, buffer, p - buffer, false) < 0) {
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_file_size(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;
	struct stat	buf;

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);
	filename = vb->vb_strvalue;

	if (stat(filename, &buf) < 0) {
		REDEBUG3("Failed checking file %s - %s", filename, fr_syserror(errno));
		return XLAT_ACTION_FAIL;
	}

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL)); /* off_t is signed, but file sizes shouldn't be negative */
	fr_dcursor_append(out, dst);

	dst->vb_uint64 = buf.st_size;

	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_file_tail(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb, *num = NULL;
	char const	*filename;
	ssize_t		len;
	off_t		offset;
	int		fd;
	int		crlf, stop = 1;
	char		*p, *end, *found, buffer[256];

	XLAT_ARGS(args, &vb, &num);
	fr_assert(vb->type == FR_TYPE_STRING);
	filename = vb->vb_strvalue;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		REDEBUG3("Failed opening file %s - %s", filename, fr_syserror(errno));
		return XLAT_ACTION_FAIL;
	}

	offset = lseek(fd, 0, SEEK_END);
	if (offset < 0) {
		REDEBUG3("Failed seeking to end of file %s - %s", filename, fr_syserror(errno));
		goto fail;
	}

	if (offset > (off_t) sizeof(buffer)) {
		offset -= sizeof(buffer);
	} else {
		offset = 0;
	}

	if (lseek(fd, offset, SEEK_SET) < 0) {
		REDEBUG3("Failed seeking backwards from end of file %s - %s", filename, fr_syserror(errno));
		goto fail;
	}

	len = read(fd, buffer, sizeof(buffer));
	if (len < 0) {
	fail:
		REDEBUG3("Failed reading file %s - %s", filename, fr_syserror(errno));
		close(fd);
		return XLAT_ACTION_FAIL;
	}
	close(fd);

	found = buffer;
	end = buffer + len;

	/*
	 *	No data, OR just one CR / LF, we print it all out.
	 */
	if (len <= 1) goto done;

	/*
	 *	Clamp number of lines to a reasonable value.  They
	 *	still all have to fit into 256 characters, though.
	 *
	 *	@todo - have a large thread-local temporary buffer for this stuff.
	 */
	if (num) {
		fr_assert(num->type == FR_TYPE_GROUP);
		fr_assert(fr_value_box_list_num_elements(&num->vb_group) == 1);

		num = fr_value_box_list_head(&num->vb_group);
		fr_assert(num->type == FR_TYPE_UINT32);

		if (!num->vb_uint32) {
			stop = 1;

		} else if (num->vb_uint32 <= 16) {
			stop = num->vb_uint32;

		} else {
			stop = 16;
		}
	} else {
		stop = 1;
	}

	p = end - 1;
	crlf = 0;

	/*
	 *	Skip any trailing CRLF first.
	 */
	while (p > buffer) {
		/*
		 *	Could be CRLF, or just LF.
		 */
		if (*p == '\n') {
			end = p;
			p--;
			if (p == buffer) {
				goto done;
			}
			if (*p >= ' ') {
				break;
			}
		}

		if (*p == '\r') {
			end = p;
			p--;
			break;
		}

		/*
		 *	We've found CR, LF, or CRLF.  The previous
		 *	thing is either raw text, or is another CR/LF.
		 */
		break;
	}

	found = p;

	while (p > buffer) {
		crlf++;

		/*
		 *	If the current line is empty, we can stop.
		 */
		if ((crlf == stop) && (*found < ' ')) {
			found++;
			goto done;
		}

		while (*p >= ' ') {
			found = p;
			p--;
			if (p == buffer) {
				found = buffer;
				goto done;
			}
		}
		if (crlf == stop) {
			break;
		}

		/*
		 *	Check again for CRLF.
		 */
		if (*p == '\n') {
			p--;
			if (p == buffer) {
				break;
			}
			if (*p >= ' ') {
				continue;
			}
		}

		if (*p == '\r') {
			p--;
			if (p == buffer) {
				break;
			}
			continue;
		}
	}

done:

	/*
	 *	@todo - return a _list_ of value-boxes, one for each line in the file.
	 *	Which means chopping off each CRLF in the file
	 */

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));
	if (fr_value_box_bstrndup(dst, dst, NULL, found, (size_t) (end - found), false) < 0) {
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_file_cat_args[] = {
	{ .required = true,  .concat = true, .type = FR_TYPE_STRING,
	  .func = filename_xlat_escape, .safe_for = FR_FILENAME_SAFE_FOR, .always_escape = true },
	{ .required = true, .type = FR_TYPE_SIZE, .single = true },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_file_cat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*dst, *vb, *max_size;
	char const	*filename;
	ssize_t		len;
	int		fd;
	struct stat	buf;
	uint8_t		*buffer;

	XLAT_ARGS(args, &vb, &max_size);
	fr_assert(vb->type == FR_TYPE_STRING);
	filename = vb->vb_strvalue;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		RPERROR("Failed opening file %s - %s", filename, fr_syserror(errno));
		return XLAT_ACTION_FAIL;
	}

	if (fstat(fd, &buf) < 0) {
		RPERROR("Failed checking file %s - %s", filename, fr_syserror(errno));
	fail:
		close(fd);
		return XLAT_ACTION_FAIL;
	}

	if ((size_t)buf.st_size > max_size->vb_size) {
		RPERROR("File larger than specified maximum (%"PRIu64" vs %zu)", buf.st_size, max_size->vb_size);
		goto fail;
	}

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_OCTETS, NULL));
	fr_value_box_mem_alloc(dst, &buffer, dst, NULL, buf.st_size, true);

	len = read(fd, buffer, buf.st_size);
	if (len < 0) {
		RPERROR("Failed reading file %s - %s", filename, fr_syserror(errno));
		talloc_free(dst);
		goto fail;
	}
	close(fd);

	if (len < buf.st_size) {
		RPERROR("Failed reading all of file %s", filename);
		talloc_free(dst);
		goto fail;
	}

	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_file_rm(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);
	filename = vb->vb_strvalue;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, dst);

	dst->vb_bool = (unlink(filename) == 0);
	if (!dst->vb_bool) {
		REDEBUG3("Failed unlinking file %s - %s", filename, fr_syserror(errno));
	}

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_file_touch(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;
	int		fd;

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);
	filename = vb->vb_strvalue;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, dst);

	fd = open(filename, O_CREAT | O_WRONLY, 0600);
	if (fd < 0) {
		dst->vb_bool = false;
		REDEBUG3("Failed touching file %s - %s", filename, fr_syserror(errno));
		return XLAT_ACTION_DONE;
	}
	dst->vb_bool = true;

	close(fd);

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_file_mkdir(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*dirname;

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);
	dirname = vb->vb_strvalue;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, dst);

	dst->vb_bool = (fr_mkdir(NULL, dirname, -1, 0700, NULL, NULL) == 0);
	if (!dst->vb_bool) {
		REDEBUG3("Failed creating directory %s - %s", dirname, fr_syserror(errno));
	}

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_file_rmdir(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*dirname;

	XLAT_ARGS(args, &vb);
	fr_assert(vb->type == FR_TYPE_STRING);
	dirname = vb->vb_strvalue;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, dst);

	dst->vb_bool = (rmdir(dirname) == 0);
	if (!dst->vb_bool) {
		REDEBUG3("Failed removing directory %s - %s", dirname, fr_syserror(errno));
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_taint_args[] = {
	{ .required = true, .type = FR_TYPE_VOID },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_untaint(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *vb;

	fr_value_box_list_untaint(in);
	while ((vb = fr_value_box_list_pop_head(in)) != NULL) {
		fr_dcursor_append(out, vb);
	}

	return XLAT_ACTION_DONE;
}

static xlat_action_t xlat_func_taint(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *vb;

	while ((vb = fr_value_box_list_pop_head(in)) != NULL) {
		fr_value_box_t *child;

		fr_assert(vb->type == FR_TYPE_GROUP);

		while ((child = fr_value_box_list_pop_head(&vb->vb_group)) != NULL) {
			child->tainted = true;
			fr_value_box_mark_unsafe(child);

			fr_dcursor_append(out, child);
		}
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_explode_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Split a string into multiple new strings based on a delimiter
 *
@verbatim
%explode(<string>, <delim>)
@endverbatim
 *
 * Example:
@verbatim
update request {
	&Tmp-String-1 := "a,b,c"
}
"%concat(%explode(%{Tmp-String-1}, ','), '|')" == "a|b|c"g
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_explode(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t				*strings;
	fr_value_box_list_t	*list;
	fr_value_box_t				*delim_vb;
	ssize_t					delim_len;
	char const				*delim;
	fr_value_box_t				*string, *vb;

	XLAT_ARGS(args, &strings, &delim_vb);

	list = &strings->vb_group;

	/* coverity[dereference] */
	if (delim_vb->vb_length == 0) {
		REDEBUG("Delimiter must be greater than zero characters");
		return XLAT_ACTION_FAIL;
	}

	delim = delim_vb->vb_strvalue;
	delim_len = delim_vb->vb_length;

	while ((string = fr_value_box_list_pop_head(list))) {
		fr_sbuff_t		sbuff = FR_SBUFF_IN(string->vb_strvalue, string->vb_length);
		fr_sbuff_marker_t	m_start;

		/*
		 *	If the delimiter is not in the string, just move to the output
		 */
		if (!fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, delim, delim_len)) {
			fr_dcursor_append(out, string);
			continue;
		}

		fr_sbuff_set_to_start(&sbuff);
		fr_sbuff_marker(&m_start, &sbuff);

		while (fr_sbuff_remaining(&sbuff)) {
			if (fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, delim, delim_len)) {
				/*
				 *	If there's nothing before the delimiter skip
				 */
				if (fr_sbuff_behind(&m_start) == 0) goto advance;

				MEM(vb = fr_value_box_alloc_null(ctx));
				fr_value_box_bstrndup(vb, vb, NULL, fr_sbuff_current(&m_start),
						      fr_sbuff_behind(&m_start), false);
				fr_value_box_safety_copy(vb, string);
				fr_dcursor_append(out, vb);

			advance:
				fr_sbuff_advance(&sbuff, delim_len);
				fr_sbuff_set(&m_start, &sbuff);
				continue;
			}

			fr_sbuff_set_to_end(&sbuff);
			MEM(vb = fr_value_box_alloc_null(ctx));
			fr_value_box_bstrndup(vb, vb, NULL, fr_sbuff_current(&m_start),
					      fr_sbuff_behind(&m_start), false);

			fr_value_box_safety_copy(vb, string);
			fr_dcursor_append(out, vb);
			break;
		}
		talloc_free(string);
	}

	return XLAT_ACTION_DONE;
}

/** Mark one or more attributes as immutable
 *
 * Example:
@verbatim
%pairs.immutable(request.State[*])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_immutable_attr(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					      UNUSED xlat_ctx_t const *xctx,
					      request_t *request, fr_value_box_list_t *args)
{
	fr_pair_t		*vp;
	fr_dcursor_t		*cursor;
	fr_value_box_t		*in_head;

	XLAT_ARGS(args, &in_head);

	cursor = fr_value_box_get_cursor(in_head);

	RDEBUG("Attributes matching \"%s\"", in_head->vb_cursor_name);

	RINDENT();
	for (vp = fr_dcursor_current(cursor);
	     vp;
	     vp = fr_dcursor_next(cursor)) {
		fr_pair_set_immutable(vp);
	}
	REXDENT();

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_integer_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Print data as integer, not as VALUE.
 *
 * Example:
@verbatim
update request {
	&Tmp-IP-Address-0 := "127.0.0.5"
}
%integer(%{Tmp-IP-Address-0}) == 2130706437
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_integer(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*in_vb;
	char const *p;

	XLAT_ARGS(args, &in_vb);

	fr_strerror_clear(); /* Make sure we don't print old errors */

	fr_value_box_list_remove(args, in_vb);

	switch (in_vb->type) {
	default:
	error:
		RPEDEBUG("Failed converting %pR (%s) to an integer", in_vb,
			 fr_type_to_str(in_vb->type));
		talloc_free(in_vb);
		return XLAT_ACTION_FAIL;

	case FR_TYPE_NUMERIC:
		/*
		 *	Ensure enumeration is NULL so that the integer
		 *	version of a box is returned
		 */
		in_vb->enumv = NULL;

		/*
		 *	FR_TYPE_DATE and FR_TYPE_TIME_DELTA need to be cast
		 *	to int64_t so that they're printed in a
		 *	numeric format.
		 */
		if ((in_vb->type == FR_TYPE_DATE) || (in_vb->type == FR_TYPE_TIME_DELTA)) {
			if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_INT64, NULL) < 0) goto error;
		}
		break;

	case FR_TYPE_STRING:
		/*
		 *	Strings are always zero terminated.  They may
		 *	also have zeros in the middle, but if that
		 *	happens, the caller will only get the part up
		 *	to the first zero.
		 *
		 *	We check for negative numbers, just to be
		 *	nice.
		 */
		for (p = in_vb->vb_strvalue; *p != '\0'; p++) {
			if (*p == '-') break;
		}

		if (*p == '-') {
			if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_INT64, NULL) < 0) goto error;
		} else {
			if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT64, NULL) < 0) goto error;
		}
		break;

	case FR_TYPE_OCTETS:
		if (in_vb->vb_length > sizeof(uint64_t)) {
			fr_strerror_printf("Expected octets length <= %zu, got %zu", sizeof(uint64_t), in_vb->vb_length);
			goto error;
		}

		if (in_vb->vb_length > sizeof(uint32_t)) {
			if (unlikely(fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT64, NULL) < 0)) goto error;
		} else if (in_vb->vb_length > sizeof(uint16_t)) {
			if (unlikely(fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT32, NULL) < 0)) goto error;
		} else if (in_vb->vb_length > sizeof(uint8_t)) {
			if (unlikely(fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT16, NULL) < 0)) goto error;
		} else {
			if (unlikely(fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT8, NULL) < 0)) goto error;
		}

		break;

	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV4_PREFIX:
		if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT32, NULL) < 0) goto error;
		break;

	case FR_TYPE_ETHERNET:
		if (fr_value_box_cast_in_place(ctx, in_vb, FR_TYPE_UINT64, NULL) < 0) goto error;
		break;

	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV6_PREFIX:
	{
		uint128_t	ipv6int;
		char		buff[40];
		fr_value_box_t	*vb;

		/*
		 *	Needed for correct alignment (as flagged by ubsan)
		 */
		memcpy(&ipv6int, &in_vb->vb_ipv6addr, sizeof(ipv6int));

		fr_snprint_uint128(buff, sizeof(buff), ntohlll(ipv6int));

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_bstrndup(vb, vb, NULL, buff, strlen(buff), false);
		fr_dcursor_append(out, vb);
		talloc_free(in_vb);
		return XLAT_ACTION_DONE;
	}
	}

	fr_dcursor_append(out, in_vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_log_arg[] = {
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Log something at INFO level.
 *
 * Example:
@verbatim
%log("This is an informational message")
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_log_info(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;

	XLAT_ARGS(args, &vb);

	if (!vb) return XLAT_ACTION_DONE;

	RINFO("%s", vb->vb_strvalue);

	return XLAT_ACTION_DONE;
}


/** Log something at DEBUG level.
 *
 * Example:
@verbatim
%log.debug("This is a message")
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_log_debug(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;

	XLAT_ARGS(args, &vb);

	if (!vb) return XLAT_ACTION_DONE;

	RDEBUG("%s", vb->vb_strvalue);

	return XLAT_ACTION_DONE;
}


/** Log something at DEBUG level.
 *
 * Example:
@verbatim
%log.err("Big error here")
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_log_err(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;

	XLAT_ARGS(args, &vb);

	if (!vb) return XLAT_ACTION_DONE;

	REDEBUG("%s", vb->vb_strvalue);

	return XLAT_ACTION_DONE;
}


/** Log something at WARN level.
 *
 * Example:
@verbatim
%log.warn("Maybe something bad happened")
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_log_warn(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;

	XLAT_ARGS(args, &vb);

	if (!vb) return XLAT_ACTION_DONE;

	RWDEBUG("%s", vb->vb_strvalue);

	return XLAT_ACTION_DONE;
}

static int _log_dst_free(fr_log_t *log)
{
	close(log->fd);
	return 0;
}

static xlat_arg_parser_t const xlat_func_log_dst_args[] = {
	{ .required = false, .type = FR_TYPE_STRING, .concat = true },
	{ .required = false, .type = FR_TYPE_UINT32, .single = true },
	{ .required = false, .type = FR_TYPE_STRING, .concat = true },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Change the log destination to the named one
 *
 * Example:
@verbatim
%log.destination('foo')
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_log_dst(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*dst, *lvl, *file;
	fr_log_t *log, *dbg;
	uint32_t level = 2;

	XLAT_ARGS(args, &dst, &lvl, &file);

	if (!dst || !*dst->vb_strvalue) {
		request_log_prepend(request, NULL, L_DBG_LVL_DISABLE);
		return XLAT_ACTION_DONE;
	}

	log = log_dst_by_name(dst->vb_strvalue);
	if (!log) return XLAT_ACTION_FAIL;

	if (lvl) level = lvl->vb_uint32;

	if (!file || ((log->dst != L_DST_NULL) && (log->dst != L_DST_FILES))) {
		request_log_prepend(request, log, level);
		return XLAT_ACTION_DONE;
	}

	/*
	 *	Clone it.
	 */
	MEM(dbg = talloc_memdup(request, log, sizeof(*log)));
	dbg->parent = log;

	/*
	 *	Open the new filename.
	 */
	dbg->dst = L_DST_FILES;
	dbg->file = talloc_strdup(dbg, file->vb_strvalue);
	dbg->fd = open(dbg->file, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	if (dbg->fd < 0) {
		REDEBUG("Failed opening %s - %s", dbg->file, fr_syserror(errno));
		talloc_free(dbg);
		return XLAT_ACTION_DONE;
	}

	/*
	 *	Ensure that we close the file handle when done.
	 */
	talloc_set_destructor(dbg, _log_dst_free);

	request_log_prepend(request, dbg, level);
	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_map_arg[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Processes fmt as a map string and applies it to the current request
 *
 * e.g.
@verbatim
%map("User-Name := 'foo'")
@endverbatim
 *
 * Allows sets of modifications to be cached and then applied.
 * Useful for processing generic attributes from LDAP.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_map(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   request_t *request, fr_value_box_list_t *args)
{
	map_t		*map = NULL;
	int		ret;
	fr_value_box_t	*fmt_vb;
	fr_value_box_t	*vb;

	tmpl_rules_t	attr_rules = {
		.attr = {
			.dict_def = request->local_dict,
			.list_def = request_attr_request,
		},
		.xlat = {
			.runtime_el = unlang_interpret_event_list(request)
		}
	};

	XLAT_ARGS(args, &fmt_vb);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	vb->vb_bool = false;	/* Default fail value - changed to true on success */
	fr_dcursor_append(out, vb);

	fr_value_box_list_foreach(&fmt_vb->vb_group, fmt) {
		if (map_afrom_attr_str(request, &map, fmt->vb_strvalue, &attr_rules, &attr_rules) < 0) {
			RPEDEBUG("Failed parsing \"%s\" as map", fmt_vb->vb_strvalue);
			return XLAT_ACTION_FAIL;
		}

		switch (map->lhs->type) {
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_XLAT:
			break;

		default:
			REDEBUG("Unexpected type %s in left hand side of expression",
				tmpl_type_to_str(map->lhs->type));
			return XLAT_ACTION_FAIL;
		}

		switch (map->rhs->type) {
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_EXEC:
		case TMPL_TYPE_DATA:
		case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
		case TMPL_TYPE_DATA_UNRESOLVED:
		case TMPL_TYPE_XLAT:
			break;

		default:
			REDEBUG("Unexpected type %s in right hand side of expression",
				tmpl_type_to_str(map->rhs->type));
			return XLAT_ACTION_FAIL;
		}

		RINDENT();
		ret = map_to_request(request, map, map_to_vp, NULL);
		REXDENT();
		talloc_free(map);
		if (ret < 0) return XLAT_ACTION_FAIL;
	}

	vb->vb_bool = true;
	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_next_time_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Calculate number of seconds until the next n hour(s), day(s), week(s), year(s).
 *
 * For example, if it were 16:18 %time.next(1h) would expand to 2520.
 *
 * The envisaged usage for this function is to limit sessions so that they don't
 * cross billing periods. The output of the xlat should be combined with %rand() to create
 * some jitter, unless the desired effect is every subscriber on the network
 * re-authenticating at the same time.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_next_time(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *args)
{
	unsigned long  	num;

	char const	*p;
	char		*q;
	time_t		now;
	struct tm	*local, local_buff;
	fr_value_box_t	*in_head;
	fr_value_box_t	*vb;

	XLAT_ARGS(args, &in_head);

	/*
	 *	We want to limit based on _now_, not on when they logged in.
	 */
	now = time(NULL);
	local = localtime_r(&now, &local_buff);

	p = in_head->vb_strvalue;

	num = strtoul(p, &q, 10);
	if ((num == ULONG_MAX) || !q || *q == '\0') {
		REDEBUG("<int> must be followed by time period (h|d|w|m|y)");
		return XLAT_ACTION_FAIL;
	}
	if (num == 0) {
		REDEBUG("<int> must be greater than zero");
		return XLAT_ACTION_FAIL;
	}

	if (p == q) {
		num = 1;
	} else {
		p += q - p;
	}

	local->tm_sec = 0;
	local->tm_min = 0;

	switch (*p) {
	case 'h':
		local->tm_hour += num;
		break;

	case 'd':
		local->tm_hour = 0;
		local->tm_mday += num;
		break;

	case 'w':
		local->tm_hour = 0;
		local->tm_mday += (7 - local->tm_wday) + (7 * (num-1));
		break;

	case 'm':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon += num;
		break;

	case 'y':
		local->tm_hour = 0;
		local->tm_mday = 1;
		local->tm_mon = 0;
		local->tm_year += num;
		break;

	default:
		REDEBUG("Invalid time period '%c', must be h|d|w|m|y", *p);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_uint64(vb, NULL, (uint64_t)(mktime(local) - now), false);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

typedef struct {
	unlang_result_t	last_result;
	xlat_exp_head_t	*ex;
} xlat_eval_rctx_t;

/** Just serves to push the result up the stack
 *
 */
static xlat_action_t xlat_eval_resume(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	xlat_eval_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, xlat_eval_rctx_t);
	xlat_action_t		xa = XLAT_RESULT_SUCCESS(&rctx->last_result) ? XLAT_ACTION_DONE : XLAT_ACTION_FAIL;

	talloc_free(rctx);

	return xa;
}

static xlat_arg_parser_t const xlat_func_eval_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Dynamically evaluate an expansion string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_eval(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	/*
	 *	These are escaping rules applied to the
	 *	input string. They're mostly here to
	 *	allow \% and \\ to work.
	 *
	 *	Everything else should be passed in as
	 *	unescaped data.
	 */
	static fr_sbuff_unescape_rules_t const escape_rules = {
		.name = "xlat",
		.chr = '\\',
		.subs = {
			['%'] = '%',
			['\\'] = '\\',
		},
		.do_hex = false,
		.do_oct = false
	};

	xlat_eval_rctx_t	*rctx;
	fr_value_box_t		*arg = fr_value_box_list_head(args);

	XLAT_ARGS(args, &arg);

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), xlat_eval_rctx_t));

	/*
	 *	Parse the input as a literal expansion
	 */
	if (xlat_tokenize_expression(rctx,
			  &rctx->ex,
			  &FR_SBUFF_IN(arg->vb_strvalue, arg->vb_length),
			  &(fr_sbuff_parse_rules_t){
				  .escapes = &escape_rules
			  },
			  &(tmpl_rules_t){
				  .attr = {
					  .dict_def = request->local_dict,
					  .list_def = request_attr_request,
					  .allow_unknown = false,
					  .allow_unresolved = false,
					  .allow_foreign = false,
					},
				  .xlat = {
					  .runtime_el = unlang_interpret_event_list(request),
				  },
				  .at_runtime = true
			  }) < 0) {
		RPEDEBUG("Failed parsing expansion");
	error:
		talloc_free(rctx);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Call the resolution function so we produce
	 *	good errors about what function was
	 *	unresolved.
	 */
	if (rctx->ex->flags.needs_resolving &&
	    (xlat_resolve(rctx->ex, &(xlat_res_rules_t){ .allow_unresolved = false }) < 0)) {
		RPEDEBUG("Unresolved expansion functions in expansion");
		goto error;

	}

	if (unlang_xlat_yield(request, xlat_eval_resume, NULL, 0, rctx) != XLAT_ACTION_YIELD) goto error;

	if (unlang_xlat_push(ctx, &rctx->last_result, (fr_value_box_list_t *)out->dlist,
			     request, rctx->ex, UNLANG_SUB_FRAME) < 0) goto error;

	return XLAT_ACTION_PUSH_UNLANG;
}

static xlat_arg_parser_t const xlat_func_pad_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .required = true, .single = true, .type = FR_TYPE_UINT64 },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** lpad a string
 *
@verbatim
%lpad(%{Attribute-Name},  <length> [, <fill>])
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
%lpad(%{User-Name}, 5 'x') == "xxfoo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_lpad(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t				*values;
	fr_value_box_t				*pad;
	fr_value_box_t				*fill;

	fr_value_box_list_t	*list;

	size_t					pad_len;

	char const				*fill_str = NULL;
	size_t					fill_len = 0;

	fr_value_box_t				*in = NULL;

	XLAT_ARGS(args, &values, &pad, &fill);

	/* coverity[dereference] */
	list =  &values->vb_group;
	/* coverity[dereference] */
	pad_len = (size_t)pad->vb_uint64;

	/*
	 *	Fill is optional
	 */
	if (fill) {
		fill_str = fill->vb_strvalue;
		fill_len = talloc_array_length(fill_str) - 1;
	}

	if (fill_len == 0) {
		fill_str = " ";
		fill_len = 1;
	}

	while ((in = fr_value_box_list_pop_head(list))) {
		size_t			len = talloc_array_length(in->vb_strvalue) - 1;
		size_t			remaining;
		char			*buff;
		fr_sbuff_t		sbuff;
		fr_sbuff_marker_t	m_data;

		fr_dcursor_append(out, in);

		if (len >= pad_len) continue;

		if (fr_value_box_bstr_realloc(in, &buff, in, pad_len) < 0) {
			RPEDEBUG("Failed reallocing input data");
			return XLAT_ACTION_FAIL;
		}

		fr_sbuff_init_in(&sbuff, buff, pad_len);
		fr_sbuff_marker(&m_data, &sbuff);

		/*
		 *	...nothing to move if the input
		 *	string is empty.
		 */
		if (len > 0) {
			fr_sbuff_advance(&m_data, pad_len - len);	/* Mark where we want the data to go */
			fr_sbuff_move(&FR_SBUFF(&m_data), &FR_SBUFF(&sbuff), len); /* Shift the data */
		}

		if (fill_len == 1) {
			memset(fr_sbuff_current(&sbuff), *fill_str, fr_sbuff_ahead(&m_data));
			continue;
		}

		/*
		 *	Copy fill as a repeating pattern
		 */
		while ((remaining = fr_sbuff_ahead(&m_data))) {
			size_t to_copy = remaining >= fill_len ? fill_len : remaining;
			memcpy(fr_sbuff_current(&sbuff), fill_str, to_copy);	/* avoid \0 termination */
			fr_sbuff_advance(&sbuff, to_copy);
		}
		fr_sbuff_set_to_end(&sbuff);
		fr_sbuff_terminate(&sbuff);			/* Move doesn't re-terminate */
	}

	return XLAT_ACTION_DONE;
}

/** Right pad a string
 *
@verbatim
%rpad(%{Attribute-Name}, <length> [, <fill>])
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
%rpad(%{User-Name}, 5 'x') == "fooxx"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_rpad(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*values;
	fr_value_box_list_t	*list;
	fr_value_box_t		*pad;
	/* coverity[dereference] */
	size_t			pad_len;
	fr_value_box_t		*fill;
	char const		*fill_str = NULL;
	size_t			fill_len = 0;

	fr_value_box_t		*in = NULL;

	XLAT_ARGS(args, &values, &pad, &fill);

	list = &values->vb_group;
	pad_len = (size_t)pad->vb_uint64;

	/*
	 *	Fill is optional
	 */
	if (fill) {
		fill_str = fill->vb_strvalue;
		fill_len = talloc_array_length(fill_str) - 1;
	}

	if (fill_len == 0) {
		fill_str = " ";
		fill_len = 1;
	}

	while ((in = fr_value_box_list_pop_head(list))) {
		size_t		len = talloc_array_length(in->vb_strvalue) - 1;
		size_t		remaining;
		char		*buff;
		fr_sbuff_t	sbuff;

		fr_dcursor_append(out, in);

		if (len >= pad_len) continue;

		if (fr_value_box_bstr_realloc(in, &buff, in, pad_len) < 0) {
		fail:
			RPEDEBUG("Failed reallocing input data");
			return XLAT_ACTION_FAIL;
		}

		fr_sbuff_init_in(&sbuff, buff, pad_len);
		fr_sbuff_advance(&sbuff, len);

		if (fill_len == 1) {
			memset(fr_sbuff_current(&sbuff), *fill_str, fr_sbuff_remaining(&sbuff));
			continue;
		}

		/*
		 *	Copy fill as a repeating pattern
		 */
		while ((remaining = fr_sbuff_remaining(&sbuff))) {
			if (fr_sbuff_in_bstrncpy(&sbuff, fill_str, remaining >= fill_len ? fill_len : remaining) < 0) {
				goto fail;
			}
		}
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_base64_encode_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encode string or attribute as base64
 *
 * Example:
@verbatim
%base64.encode("foo") == "Zm9v"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_base64_encode(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     UNUSED xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *args)
{
	size_t		alen;
	ssize_t		elen;
	char		*buff;
	fr_value_box_t	*vb;
	fr_value_box_t	*in;

	XLAT_ARGS(args, &in);

	alen = FR_BASE64_ENC_LENGTH(in->vb_length);

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (fr_value_box_bstr_alloc(vb, &buff, vb, NULL, alen, false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	elen = fr_base64_encode(&FR_SBUFF_OUT(buff, talloc_array_length(buff)),
				&FR_DBUFF_TMP(in->vb_octets, in->vb_length), true);
	if (elen < 0) {
		RPEDEBUG("Base64 encoding failed");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	fr_assert((size_t)elen <= alen);
	fr_value_box_safety_copy_changed(vb, in);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_base64_decode_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Decode base64 string
 *
 * Example:
@verbatim
%base64.decode("Zm9v") == "foo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_base64_decode(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     UNUSED xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *args)
{
	size_t		alen;
	ssize_t		declen = 0;
	uint8_t		*decbuf;
	fr_value_box_t	*vb;
	fr_value_box_t	*in;

	XLAT_ARGS(args, &in);

	/*
	 *	Pass empty arguments through
	 *
	 *	FR_BASE64_DEC_LENGTH produces 2 for empty strings...
	 */
	if (in->vb_length == 0) {
		xlat_arg_copy_out(ctx, out, args, in);
		return XLAT_ACTION_DONE;
	}

	alen = FR_BASE64_DEC_LENGTH(in->vb_length);
	MEM(vb = fr_value_box_alloc_null(ctx));
	if (alen > 0) {
		MEM(fr_value_box_mem_alloc(vb, &decbuf, vb, NULL, alen, false) == 0);
		declen = fr_base64_decode(&FR_DBUFF_TMP(decbuf, alen),
					  &FR_SBUFF_IN(in->vb_strvalue, in->vb_length), true, true);
		if (declen < 0) {
			RPEDEBUG("Base64 string invalid");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		MEM(fr_value_box_mem_realloc(vb, NULL, vb, declen) == 0);
	}

	fr_value_box_safety_copy_changed(vb, in);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_bin_arg[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Convert hex string to binary
 *
 * Example:
@verbatim
%bin("666f6f626172") == "foobar"
@endverbatim
 *
 * @see #xlat_func_hex
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_bin(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*result;
	char const		*p, *end;
	uint8_t			*bin;
	size_t			len, outlen;
	fr_sbuff_parse_error_t	err;
	fr_value_box_t		*list, *hex;

	XLAT_ARGS(args, &list);

	while ((hex = fr_value_box_list_pop_head(&list->vb_group))) {
		len = hex->vb_length;
		if ((len > 1) && (len & 0x01)) {
			REDEBUG("Input data length must be >1 and even, got %zu", len);
			return XLAT_ACTION_FAIL;
		}

		p = hex->vb_strvalue;
		end = p + len;

		/*
		 *	Look for 0x at the start of the string, and ignore if we see it.
		 */
		if ((p[0] == '0') && (p[1] == 'x')) {
			p += 2;
			len -=2;
		}

		/*
		 *	Zero length octets string
		 */
		if (p == end) continue;

		outlen = len / 2;

		MEM(result = fr_value_box_alloc_null(ctx));
		MEM(fr_value_box_mem_alloc(result, &bin, result, NULL, outlen, false) == 0);
		fr_base16_decode(&err, &FR_DBUFF_TMP(bin, outlen), &FR_SBUFF_IN(p, end - p), true);
		if (err) {
			REDEBUG2("Invalid hex string");
			talloc_free(result);
			return XLAT_ACTION_FAIL;
		}

		fr_value_box_safety_copy_changed(result, hex);
		fr_dcursor_append(out, result);
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_block_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_TIME_DELTA },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Block for the specified duration
 *
 * This is for developer use only to simulate blocking, synchronous I/O.
 * For normal use, use the %delay() xlat instead.
 *
 * Example:
@verbatim
%block(1s)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_block(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*delay;
	fr_value_box_t		*vb;
	struct timespec		ts_in, ts_remain = {};

	XLAT_ARGS(args, &delay);

	ts_in = fr_time_delta_to_timespec(delay->vb_time_delta);

	(void)nanosleep(&ts_in, &ts_remain);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));
	vb->vb_time_delta = fr_time_delta_sub(delay->vb_time_delta,
					      fr_time_delta_from_timespec(&ts_remain));
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_cast_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	{ .type = FR_TYPE_VOID },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Cast one or more output value-boxes to the given type
 *
 * First argument of is type to cast to.
 *
 * Example:
@verbatim
%cast('string', %{request[*]}) results in all of the input boxes being cast to string/
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_cast(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*name;
	fr_value_box_t	*arg;
	fr_type_t	type;
	fr_dict_attr_t const *time_res = NULL;

	XLAT_ARGS(args, &name);

	/*
	 *	Get the type, which can be in one of a few formats.
	 */
	if (fr_type_is_numeric(name->type)) {
		if (fr_value_box_cast_in_place(name, name, FR_TYPE_UINT8, NULL) < 0) {
			RPEDEBUG("Failed parsing '%pV' as a numerical data type", name);
			return XLAT_ACTION_FAIL;
		}
		type = name->vb_uint8;

	} else {
		if (name->type != FR_TYPE_STRING) {
			if (fr_value_box_cast_in_place(name, name, FR_TYPE_STRING, NULL) < 0) {
				RPEDEBUG("Failed parsing '%pV' as a string data type", name);
				return XLAT_ACTION_FAIL;
			}
		}

		type = fr_table_value_by_str(fr_type_table, name->vb_strvalue, FR_TYPE_NULL);
		if (type == FR_TYPE_NULL) {
			if ((time_res = xlat_time_res_attr(name->vb_strvalue)) == NULL) {
				RDEBUG("Unknown data type '%s'", name->vb_strvalue);
				return XLAT_ACTION_FAIL;
			}

			type = FR_TYPE_TIME_DELTA;
		}
	}

	(void) fr_value_box_list_pop_head(args);

	/*
	 *	When we cast nothing to a string / octets, the result is an empty string/octets.
	 */
	if (unlikely(!fr_value_box_list_head(args))) {
		if ((type == FR_TYPE_STRING) || (type == FR_TYPE_OCTETS)) {
			fr_value_box_t *dst;

			MEM(dst = fr_value_box_alloc(ctx, type, NULL));
			fr_dcursor_append(out, dst);
			VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);

			return XLAT_ACTION_DONE;
		}

		RDEBUG("No data for cast to '%s'", fr_type_to_str(type));
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Cast to string means *print* to string.
	 */
	if (type == FR_TYPE_STRING) {
		fr_sbuff_t *agg;
		fr_value_box_t *dst;

		talloc_free(name);

		FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, SIZE_MAX);

		MEM(dst = fr_value_box_alloc_null(ctx));
		fr_value_box_mark_safe_for(dst, FR_VALUE_BOX_SAFE_FOR_ANY);

		if (fr_value_box_list_concat_as_string(dst, agg, args, NULL, 0, NULL,
						       FR_VALUE_BOX_LIST_FREE_BOX, FR_VALUE_BOX_SAFE_FOR_ANY, true) < 0) {
			RPEDEBUG("Failed concatenating string");
			return XLAT_ACTION_FAIL;
		}

		fr_value_box_bstrndup(dst, dst, NULL, fr_sbuff_start(agg), fr_sbuff_used(agg), false);
		fr_dcursor_append(out, dst);
		VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);

		return XLAT_ACTION_DONE;
	}

	/*
	 *	Copy inputs to outputs, casting them along the way.
	 */
	arg = NULL;
	while ((arg = fr_value_box_list_next(args, arg)) != NULL) {
		fr_value_box_t	*vb, *p;

		fr_assert(arg->type == FR_TYPE_GROUP);

		vb = fr_value_box_list_head(&arg->vb_group);
		while (vb) {
			p = fr_value_box_list_remove(&arg->vb_group, vb);

			if (fr_value_box_cast_in_place(vb, vb, type, time_res) < 0) {
				RPEDEBUG("Failed casting %pV to data type '%s'", vb, fr_type_to_str(type));
				return XLAT_ACTION_FAIL;
			}
			fr_dcursor_append(out, vb);
			vb = fr_value_box_list_next(&arg->vb_group, p);
		}
	}
	VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_concat_args[] = {
	{ .required = true, .type = FR_TYPE_VOID },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Concatenate string representation of values of given attributes using separator
 *
 * First argument of is the list of attributes to concatenate, followed
 * by an optional separator
 *
 * Example:
@verbatim
%concat(%{request.[*]}, ',') == "<attr1value>,<attr2value>,<attr3value>,..."
%concat(%{Tmp-String-0[*]}, '. ') == "<str1value>. <str2value>. <str3value>. ..."
%concat(%join(%{User-Name}, %{Calling-Station-Id}), ', ') == "bob, aa:bb:cc:dd:ee:ff"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_concat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*result;
	fr_value_box_t	*list;
	fr_value_box_t	*separator;
	fr_value_box_list_t *to_concat;
	char		*buff;
	char const	*sep;

	XLAT_ARGS(args, &list, &separator);

	sep = (separator) ? separator->vb_strvalue : "";
	to_concat = &list->vb_group;

	result = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL);
	if (!result) {
	error:
		RPEDEBUG("Failed concatenating input");
		return XLAT_ACTION_FAIL;
	}

	buff = fr_value_box_list_aprint(result, to_concat, sep, NULL);
	if (!buff) goto error;

	fr_value_box_bstrdup_buffer_shallow(NULL, result, NULL, buff, fr_value_box_list_tainted(args));

	fr_dcursor_append(out, result);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_hex_arg[] = {
	{ .required = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Print data as hex, not as VALUE.
 *
 * Example:
@verbatim
%hex("foobar") == "666f6f626172"
@endverbatim
 *
 * @see #xlat_func_bin
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hex(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   UNUSED request_t *request, fr_value_box_list_t *args)
{
	char		*new_buff;
	fr_value_box_t	*list, *bin;
	fr_value_box_t	safety;

	XLAT_ARGS(args, &list);

	while ((bin = fr_value_box_list_pop_head(&list->vb_group))) {
		fr_value_box_safety_copy(&safety, bin);

		/*
		 *	Use existing box, but with new buffer
		 */
		MEM(new_buff = talloc_zero_array(bin, char, (bin->vb_length * 2) + 1));
		if (bin->vb_length) {
			fr_base16_encode(&FR_SBUFF_OUT(new_buff, (bin->vb_length * 2) + 1),
					       &FR_DBUFF_TMP(bin->vb_octets, bin->vb_length));
			fr_value_box_clear_value(bin);
			fr_value_box_strdup_shallow(bin, NULL, new_buff, false);
		/*
		 *	Zero length binary > zero length hex string
		 */
		} else {
			fr_value_box_clear_value(bin);
			fr_value_box_strdup(bin, bin, NULL, "", false);
		}

		fr_value_box_safety_copy(bin, &safety);
		fr_dcursor_append(out, bin);
	}

	return XLAT_ACTION_DONE;
}

typedef enum {
	HMAC_MD5,
	HMAC_SHA1
} hmac_type;

static xlat_action_t xlat_hmac(TALLOC_CTX *ctx, fr_dcursor_t *out,
				fr_value_box_list_t *args, uint8_t *digest, int digest_len, hmac_type type)
{
	fr_value_box_t	*vb, *data, *key;

	XLAT_ARGS(args, &data, &key);

	if (type == HMAC_MD5) {
		/* coverity[dereference] */
		fr_hmac_md5(digest, data->vb_octets, data->vb_length, key->vb_octets, key->vb_length);
	} else if (type == HMAC_SHA1) {
		/* coverity[dereference] */
		fr_hmac_sha1(digest, data->vb_octets, data->vb_length, key->vb_octets, key->vb_length);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digest_len, false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_hmac_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Generate the HMAC-MD5 of a string or attribute
 *
 * Example:
@verbatim
%hmacmd5('foo', 'bar') == "0x31b6db9e5eb4addb42f1a6ca07367adc"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hmac_md5(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					UNUSED request_t *request, fr_value_box_list_t *in)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	return xlat_hmac(ctx, out, in, digest, MD5_DIGEST_LENGTH, HMAC_MD5);
}


/** Generate the HMAC-SHA1 of a string or attribute
 *
 * Example:
@verbatim
%hmacsha1('foo', 'bar') == "0x85d155c55ed286a300bd1cf124de08d87e914f3a"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_hmac_sha1(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 UNUSED request_t *request, fr_value_box_list_t *in)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	return xlat_hmac(ctx, out, in, digest, SHA1_DIGEST_LENGTH, HMAC_SHA1);
}

static xlat_arg_parser_t const xlat_func_join_args[] = {
	{ .required = true, .type = FR_TYPE_VOID },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_SQUASH, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Join a series of arguments to form a single list
 *
 * null boxes are not preserved.
 */
static xlat_action_t xlat_func_join(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_list_foreach(in, arg) {
		fr_assert(arg->type == FR_TYPE_GROUP);

		fr_value_box_list_foreach(&arg->vb_group, vb) {
			xlat_arg_copy_out(ctx, out, &arg->vb_group, vb);
		}
	}
	return XLAT_ACTION_DONE;
}

static void ungroup(fr_dcursor_t *out, fr_value_box_list_t *in)
{
	fr_value_box_t *vb;

	while ((vb = fr_value_box_list_pop_head(in)) != NULL) {
		if (vb->type != FR_TYPE_GROUP) {
			fr_dcursor_append(out, vb);
			continue;
		}
		talloc_free(vb);
	}
}

/** Ungroups all of its arguments into one flat list.
 *
 */
static xlat_action_t xlat_func_ungroup(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*arg = NULL;

	while ((arg = fr_value_box_list_next(in, arg)) != NULL) {
		fr_assert(arg->type == FR_TYPE_GROUP);

		ungroup(out, &arg->vb_group);
	}
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_length_args[] = {
	{ .single = true, .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the on-the-wire size of the boxes in bytes
 *
 * skips null values
 *
 * Example:
@verbatim
%length(foobar) == 6
%length(%bin("0102030005060708")) == 8
@endverbatim
 *
 * @see #xlat_func_strlen
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_length(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      UNUSED request_t *request, fr_value_box_list_t *in)

{
	fr_value_box_list_foreach(in, vb) {
		fr_value_box_t *my;

		MEM(my = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL));
		if (!fr_type_is_null(vb->type)) my->vb_size = fr_value_box_network_length(vb);
		fr_dcursor_append(out, my);
	}

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_md4_arg[] = {
	{ .concat = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Calculate the MD4 hash of a string or attribute.
 *
 * Example:
@verbatim
%md4("foo") == "0ac6700c491d70fb8650940b1ca1e4b2"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_md4(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   UNUSED request_t *request, fr_value_box_list_t *args)
{
	uint8_t		digest[MD4_DIGEST_LENGTH];
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	if (in_head) {
		fr_md4_calc(digest, in_head->vb_octets, in_head->vb_length);
	} else {
		/* Digest of empty string */
		fr_md4_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_dcursor_append(out, vb);
	VALUE_BOX_LIST_VERIFY((fr_value_box_list_t *)out->dlist);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_md5_arg[] = {
	{ .concat = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Calculate the MD5 hash of a string or attribute.
 *
 * Example:
@verbatim
%md5("foo") == "acbd18db4cc2f85cedef654fccc4a4d8"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_md5(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   UNUSED request_t *request, fr_value_box_list_t *args)
{
	uint8_t		digest[MD5_DIGEST_LENGTH];
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	if (in_head) {
		fr_md5_calc(digest, in_head->vb_octets, in_head->vb_length);
	} else {
		/* Digest of empty string */
		fr_md5_calc(digest, NULL, 0);
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Encode attributes as a series of string attribute/value pairs
 *
 * This is intended to serialize one or more attributes as a comma
 * delimited string.
 *
 * Example:
@verbatim
%pairs.print(request.[*]) == 'User-Name = "foo"User-Password = "bar"'
%concat(%pairs.print.print(request.[*]), ', ') == 'User-Name = "foo", User-Password = "bar"'
@endverbatim
 *
 * @see #xlat_func_concat
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_pairs_print(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *args)
{
	fr_pair_t		*vp;
	fr_dcursor_t		*cursor;
	fr_value_box_t		*vb;
	fr_value_box_t		*in_head;

	XLAT_ARGS(args, &in_head);

	cursor = fr_value_box_get_cursor(in_head);

	for (vp = fr_dcursor_current(cursor);
	     vp;
	     vp = fr_dcursor_next(cursor)) {
		char *buff;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (unlikely(fr_pair_aprint(vb, &buff, NULL, vp) < 0)) {
			RPEDEBUG("Failed printing pair");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, buff, false);
		fr_dcursor_append(out, vb);

		VALUE_BOX_VERIFY(vb);
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_rand_arg[] = {
	{ .required = true, .single = true, .type = FR_TYPE_UINT32 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Generate a random integer value
 *
 * For "N = %rand(MAX)", 0 <= N < MAX
 *
 * Example:
@verbatim
%rand(100) == 42
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_rand(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	int64_t		result;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head = fr_value_box_list_head(in);

	result = in_head->vb_uint32;

	/* Make sure it isn't too big */
	if (result > (1 << 30)) result = (1 << 30);

	result *= fr_rand();	/* 0..2^32-1 */
	result >>= 32;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL));
	vb->vb_uint64 = result;

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_randstr_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Generate a string of random chars
 *
 * Build strings of random chars, useful for generating tokens and passcodes
 * Format similar to String::Random.
 *
 * Format characters may include the following, and may be
 * preceded by a repetition count:
 * - "c"	lowercase letters
 * - "C" 	uppercase letters
 * - "n" 	numbers
 * - "a" 	alphanumeric
 * - "!" 	punctuation
 * - "." 	alphanumeric + punctuation
 * - "s" 	alphanumeric + "./"
 * - "o" 	characters suitable for OTP (easily confused removed)
 * - "b" 	binary data
 *
 * Example:
@verbatim
%randstr("CCCC!!cccnnn") == "IPFL>{saf874"
%randstr("42o") == "yHdupUwVbdHprKCJRYfGbaWzVwJwUXG9zPabdGAhM9"
%hex(%randstr("bbbb")) == "a9ce04f3"
%hex(%randstr("8b")) == "fe165529f9f66839"
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_randstr(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *args)
{
	/*
	 *	Lookup tables for randstr char classes
	 */
	static char	randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	static char	randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

	/*
	 *	Characters humans rarely confuse. Reduces char set considerably
	 *	should only be used for things such as one time passwords.
	 */
	static char	randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

	char const	*p, *start, *end;
	char		*endptr;
	char		*buff_p;
	unsigned int	result;
	unsigned int	reps;
	size_t		outlen = 0;
	fr_value_box_t*	vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	/** Max repetitions of a single character class
	 *
	 */
#define REPETITION_MAX 1024

	start = p = in_head->vb_strvalue;
	end = p + in_head->vb_length;

	/*
	 *	Calculate size of output
	 */
	while (p < end) {
		/*
		 *	Repetition modifiers.
		 *
		 *	We limit it to REPETITION_MAX, because we don't want
		 *	utter stupidity.
		 */
		if (isdigit((uint8_t) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) reps = REPETITION_MAX;
			outlen += reps;
			p = endptr;
		} else {
			outlen++;
		}
		p++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);

	/* Reset p to start position */
	p = start;

	while (p < end) {
		size_t i;

		if (isdigit((uint8_t) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) {
				reps = REPETITION_MAX;
				RMARKER(L_WARN, L_DBG_LVL_2, start, start - p,
					"Forcing repetition to %u", (unsigned int)REPETITION_MAX);
			}
			p = endptr;
		} else {
			reps = 1;
		}

		for (i = 0; i < reps; i++) {
			result = fr_rand();
			switch (*p) {
			/*
			 *  Lowercase letters
			 */
			case 'c':
				*buff_p++ = 'a' + (result % 26);
				break;

			/*
			 *  Uppercase letters
			 */
			case 'C':
				*buff_p++ = 'A' + (result % 26);
				break;

			/*
			 *  Numbers
			 */
			case 'n':
				*buff_p++ = '0' + (result % 10);
				break;

			/*
			 *  Alpha numeric
			 */
			case 'a':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
				break;

			/*
			 *  Punctuation
			 */
			case '!':
				*buff_p++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
				break;

			/*
			 *  Alpha numeric + punctuation
			 */
			case '.':
				*buff_p++ = '!' + (result % 95);
				break;

			/*
			 *  Alpha numeric + salt chars './'
			 */
			case 's':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
				break;

			/*
			 *  Chars suitable for One Time Password tokens.
			 *  Alpha numeric with easily confused char pairs removed.
			 */
			case 'o':
				*buff_p++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
				break;

			/*
			 *	Binary data - Copy between 1-4 bytes at a time
			 */
			case 'b':
			{
				size_t copy = (reps - i) > sizeof(result) ? sizeof(result) : reps - i;

				memcpy(buff_p, (uint8_t *)&result, copy);
				buff_p += copy;
				i += (copy - 1);	/* Loop +1 */
			}
				break;

			default:
				REDEBUG("Invalid character class '%c'", *p);
				talloc_free(vb);

				return XLAT_ACTION_FAIL;
			}
		}

		p++;
	}

	*buff_p++ = '\0';

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Convert a UUID in an array of uint32_t to the conventional string representation.
 */
static int uuid_print_vb(fr_value_box_t *vb, uint32_t vals[4])
{
	char	buffer[36];
	int	i, j = 0;

#define UUID_CHARS(_v, _num)	for (i = 0; i < _num; i++) { \
		buffer[j++] = fr_base16_alphabet_encode_lc[(uint8_t)((vals[_v] & 0xf0000000) >> 28)]; \
		vals[_v] = vals[_v] << 4; \
	}

	UUID_CHARS(0, 8)
	buffer[j++] = '-';
	UUID_CHARS(1, 4)
	buffer[j++] = '-';
	UUID_CHARS(1, 4);
	buffer[j++] = '-';
	UUID_CHARS(2, 4);
	buffer[j++] = '-';
	UUID_CHARS(2, 4);
	UUID_CHARS(3, 8);

	return fr_value_box_bstrndup(vb, vb, NULL, buffer, sizeof(buffer), false);
}

static inline void uuid_set_version(uint32_t vals[4], uint8_t version)
{
	/*
	 *	The version is indicated by the upper 4 bits of byte 7 - the 3rd byte of vals[1]
	 */
	vals[1] = (vals[1] & 0xffff0fff) | (((uint32_t)version & 0x0f) << 12);
}

static inline void uuid_set_variant(uint32_t vals[4], uint8_t variant)
{
	/*
	 *	The variant is indicated by the first 1, 2 or 3 bits of byte 9
	 *	The number of bits is determined by the variant.
	 */
	switch (variant) {
	case 0:
		vals[2] = vals[2] & 0x7fffffff;
		break;

	case 1:
		vals[2] = (vals[2] & 0x3fffffff) | 0x80000000;
		break;

	case 2:
		vals[2] = (vals[2] & 0x3fffffff) | 0xc0000000;
		break;

	case 3:
		vals[2] = vals[2] | 0xe0000000;
		break;
	}
}

/** Generate a version 4 UUID
 *
 * Version 4 UUIDs are all random except the version and variant fields
 *
 * Example:
@verbatim
%uuid.v4 == "cba48bda-641c-42ae-8173-d97aa04f888a"
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_uuid_v4(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
				       UNUSED request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;
	uint32_t	vals[4];
	int		i;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));

	/*
	 *	A type 4 UUID is all random except a few bits.
	 *	Start with 128 bits of random.
	 */
	for (i = 0; i < 4; i++) vals[i] = fr_rand();

	/*
	 *	Set the version and variant fields
	 */
	uuid_set_version(vals, 4);
	uuid_set_variant(vals, 1);

	if (uuid_print_vb(vb, vals) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

/** Generate a version 7 UUID
 *
 * Version 7 UUIDs use 48 bits of unix millisecond epoch and 74 bits of random
 *
 * Example:
@verbatim
%uuid.v7 == "019a58d8-8524-7342-aa07-c0fa2bba6a4e"
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_uuid_v7(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
				       UNUSED request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;
	uint32_t	vals[4];
	int		i;
	uint64_t	now;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));

	/*
	 *	A type 7 UUID has random data from bit 48
	 *	Start with random from bit 32 - since fr_rand is uint32
	 */
	for (i = 1; i < 4; i++) vals[i] = fr_rand();

	/*
	 *	The millisecond epoch fills the first 48 bits
	 */
	now = fr_time_to_msec(fr_time());
	now = now << 16;
	vals[0] = now >> 32;
	vals[1] = (vals[1] & 0x0000ffff) | (now & 0xffff0000);

	/*
	 *	Set the version and variant fields
	 */
	uuid_set_version(vals, 7);
	uuid_set_variant(vals, 1);

	if (uuid_print_vb(vb, vals) < 0) return XLAT_ACTION_FAIL;

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_range_arg[] = {
	{ .required = true, .type = FR_TYPE_UINT64 },
	{ .required = false, .type = FR_TYPE_UINT64 },
	{ .required = false, .type = FR_TYPE_UINT64 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Generate a range of uint64 numbers
 *
 * Example:
@verbatim
%range(end) -  0..end
%rang(start, end)
%range(start,end, step)
@endverbatim
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_range(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *start_vb, *end_vb, *step_vb;
	fr_value_box_t *dst;
	uint64_t i, start, end, step;

	XLAT_ARGS(args, &start_vb, &end_vb, &step_vb);

	if (step_vb) {
		start = fr_value_box_list_head(&start_vb->vb_group)->vb_uint64;
		end = fr_value_box_list_head(&end_vb->vb_group)->vb_uint64;
		step = fr_value_box_list_head(&step_vb->vb_group)->vb_uint64;

	} else if (end_vb) {
		start = fr_value_box_list_head(&start_vb->vb_group)->vb_uint64;
		end = fr_value_box_list_head(&end_vb->vb_group)->vb_uint64;
		step = 1;

	} else {
		start = 0;
		end = fr_value_box_list_head(&start_vb->vb_group)->vb_uint64;
		step = 1;
	}

	if (end <= start) {
		REDEBUG("Invalid range - 'start' must be less than 'end'");
		return XLAT_ACTION_FAIL;
	}

	if (!step) {
		REDEBUG("Invalid range - 'step' must be greater than zero");
		return XLAT_ACTION_FAIL;
	}

	if (step > (end - start)) {
		REDEBUG("Invalid range - 'step' must allow for at least one result");
		return XLAT_ACTION_FAIL;
	}

	if (((end - start) / step) > 1000) {
		REDEBUG("Invalid range - Too many results");
		return XLAT_ACTION_FAIL;
	}

	for (i = start; i < end; i += step) {
		MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_UINT64, NULL));
		dst->vb_uint64 = i;
		fr_dcursor_append(out, dst);
	}

	return XLAT_ACTION_DONE;
}

static int CC_HINT(nonnull(2,3)) regex_xlat_escape(UNUSED request_t *request, fr_value_box_t *vb, UNUSED void *uctx)
{
	ssize_t				slen;
	fr_sbuff_t			*out = NULL;
	fr_value_box_entry_t		entry;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&out, 256, 4096);

	slen = fr_value_box_print(out, vb, &regex_escape_rules);
	if (slen < 0) return -1;

	entry = vb->entry;
	fr_value_box_clear(vb);
	(void) fr_value_box_bstrndup(vb, vb, NULL, fr_sbuff_start(out), fr_sbuff_used(out), false);
	vb->entry = entry;

	return 0;
}

static xlat_arg_parser_t const xlat_func_regex_args[] = {
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};


/** Get named subcapture value from previous regex
 *
 * Example:
@verbatim
if ("foo" =~ /^(?<name>.*)/) {
        noop
}
%regex.match(name) == "foo"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_regex(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*in_head = fr_value_box_list_head(in);

	/*
	 *	Find the first child of the first argument group
	 */
	fr_value_box_t	*arg = fr_value_box_list_head(&in_head->vb_group);

	/*
	 *	Return the complete capture if no other capture is specified
	 */
	if (!arg) {
		fr_value_box_t	*vb;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, vb, request, 0) < 0) {
			REDEBUG2("No previous regex capture");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	switch (arg->type) {
	/*
	 *	If the input is an integer value then get an
	 *	arbitrary subcapture index.
	 */
	case FR_TYPE_NUMERIC:
	{
		fr_value_box_t	idx;
		fr_value_box_t	*vb;

		if (fr_value_box_list_next(in, in_head)) {
			REDEBUG("Only one subcapture argument allowed");
			return XLAT_ACTION_FAIL;
		}

		if (fr_value_box_cast(NULL, &idx, FR_TYPE_UINT32, NULL, arg) < 0) {
			RPEDEBUG("Bad subcapture index");
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, vb, request, idx.vb_uint32) < 0) {
			REDEBUG2("No previous numbered regex capture group '%u'", idx.vb_uint32);
			talloc_free(vb);
			return XLAT_ACTION_DONE;
		}
		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	default:
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	{
		fr_value_box_t	*vb;

		/*
		 *	Concatenate all input
		 */
		if (fr_value_box_list_concat_in_place(ctx,
						      arg, &in_head->vb_group, FR_TYPE_STRING,
						      FR_VALUE_BOX_LIST_FREE, true,
						      SIZE_MAX) < 0) {
			RPEDEBUG("Failed concatenating input");
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub_named(vb, vb, request, arg->vb_strvalue) < 0) {
			REDEBUG2("No previous named regex capture group '%s'", arg->vb_strvalue);
			talloc_free(vb);
			return XLAT_ACTION_DONE;	/* NOT an error, just an empty result */
		}
		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}
#else
	RDEBUG("Named regex captures are not supported (they require libpcre2)");
	return XLAT_ACTION_FAIL;
#endif
	}
}

static xlat_arg_parser_t const xlat_func_sha_arg[] = {
	{ .concat = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Calculate the SHA1 hash of a string or attribute.
 *
 * Example:
@verbatim
%sha1(foo) == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_sha1(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *args)
{
	uint8_t		digest[SHA1_DIGEST_LENGTH];
	fr_sha1_ctx	sha1_ctx;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	fr_sha1_init(&sha1_ctx);
	if (in_head) {
		fr_sha1_update(&sha1_ctx, in_head->vb_octets, in_head->vb_length);
	} else {
		/* sha1 of empty string */
		fr_sha1_update(&sha1_ctx, NULL, 0);
	}
	fr_sha1_final(digest, &sha1_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, sizeof(digest), false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Calculate any digest supported by OpenSSL EVP_MD
 *
 * Example:
@verbatim
%sha2_256(foo) == "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"
@endverbatim
 *
 * @ingroup xlat_functions
 */
#ifdef HAVE_OPENSSL_EVP_H
static xlat_action_t xlat_evp_md(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 UNUSED xlat_ctx_t const *xctx,
				 UNUSED request_t *request, fr_value_box_list_t *args, EVP_MD const *md)
{
	uint8_t		digest[EVP_MAX_MD_SIZE];
	unsigned int	digestlen;
	EVP_MD_CTX	*md_ctx;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	md_ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(md_ctx, md, NULL);
	if (in_head) {
		EVP_DigestUpdate(md_ctx, in_head->vb_octets, in_head->vb_length);
	} else {
		EVP_DigestUpdate(md_ctx, NULL, 0);
	}
	EVP_DigestFinal_ex(md_ctx, digest, &digestlen);
	EVP_MD_CTX_destroy(md_ctx);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(vb, vb, NULL, digest, digestlen, false);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#  define EVP_MD_XLAT(_md, _md_func) \
static xlat_action_t xlat_func_##_md(TALLOC_CTX *ctx, fr_dcursor_t *out,\
				     xlat_ctx_t const *xctx, \
				     request_t *request,\
				     fr_value_box_list_t *in)\
{\
	return xlat_evp_md(ctx, out, xctx, request, in, EVP_##_md_func());\
}

EVP_MD_XLAT(sha2_224, sha224)
EVP_MD_XLAT(sha2_256, sha256)
EVP_MD_XLAT(sha2_384, sha384)
EVP_MD_XLAT(sha2_512, sha512)

/*
 *  OpenWRT's OpenSSL library doesn't contain these by default
 */
#ifdef HAVE_EVP_BLAKE2S256
EVP_MD_XLAT(blake2s_256, blake2s256)
#endif

#ifdef HAVE_EVP_BLAKE2B512
EVP_MD_XLAT(blake2b_512, blake2b512)
#endif

EVP_MD_XLAT(sha3_224, sha3_224)
EVP_MD_XLAT(sha3_256, sha3_256)
EVP_MD_XLAT(sha3_384, sha3_384)
EVP_MD_XLAT(sha3_512, sha3_512)
#endif


static xlat_arg_parser_t const xlat_func_string_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_arg_parser_t const xlat_func_strlen_arg[] = {
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Print length of given string
 *
 * Example:
@verbatim
%strlen(foo) == 3
@endverbatim
 *
 * @see #xlat_func_length
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_strlen(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_SIZE, NULL));

	if (!in_head) {
		vb->vb_size = 0;
	} else {
		vb->vb_size = strlen(in_head->vb_strvalue);
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_str_printable_arg[] = {
	{ .concat = true, .type = FR_TYPE_STRING },
	{ .single = true, .type = FR_TYPE_BOOL },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return whether a string has only printable chars
 *
 * This function returns true if the input string contains UTF8 sequences and printable chars.
 *
 * @note "\t" and " " are considered unprintable chars, unless the second argument(relaxed) is true.
 *
 * Example:
@verbatim
%str.printable("🍉abcdef🍓") == true
%str.printable("\000\n\r\t") == false
%str.printable("\t abcd", yes) == true
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_str_printable(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     UNUSED xlat_ctx_t const *xctx,
					     UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;
	fr_value_box_t	*str;
	fr_value_box_t	*relaxed_vb;
	uint8_t const	*p, *end;
	bool		relaxed = false;

	XLAT_ARGS(args, &str, &relaxed_vb);

	if (relaxed_vb) relaxed = relaxed_vb->vb_bool;

	p = (uint8_t const *)str->vb_strvalue;
	end = p + str->vb_length;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, vb);
	vb->vb_bool = false;

	do {
		size_t clen;

		if ((*p < '!') &&
		    (!relaxed || ((*p != '\t') && (*p != ' ')))) return XLAT_ACTION_DONE;

		if (*p == 0x7f) return XLAT_ACTION_DONE;

		clen = fr_utf8_char(p, end - p);
		if (clen == 0) return XLAT_ACTION_DONE;
		p += clen;
	} while (p < end);

	vb->vb_bool = true;

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_str_utf8_arg[] = {
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return whether a string is valid UTF-8
 *
 * This function returns true if the input string is valid UTF-8, false otherwise.
 *
 * Example:
@verbatim
%str.utf8(🍉🥝🍓) == true
%str.utf8(🍉\xff🍓) == false
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_str_utf8(TALLOC_CTX *ctx, fr_dcursor_t *out,
				        UNUSED xlat_ctx_t const *xctx,
					UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	vb->vb_bool = (fr_utf8_str((uint8_t const *)in_head->vb_strvalue,
				   in_head->vb_length) >= 0);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_substr_args[] = {
	{ .single = true, .required = true, .type = FR_TYPE_VOID },
	{ .single = true, .required = true, .type = FR_TYPE_INT32 },
	{ .single = true, .type = FR_TYPE_INT32 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Extract a substring from string / octets data
 *
 * Non string / octets data is cast to a string.
 *
 * Second parameter is start position, optional third parameter is length
 * Negative start / length count from RHS of data.
 *
 * Example: (User-Name = "hello")
@verbatim
%substr(&User-Name, 1, 3) == 'ell'
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_substr(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*in = NULL, *start_vb, *len_vb, *vb;
	int32_t		start, end, len;

	XLAT_ARGS(args, &in, &start_vb, &len_vb);

	switch (in->type) {
	case FR_TYPE_OCTETS:
	case FR_TYPE_STRING:
		break;

	default:
		if (fr_value_box_cast_in_place(in, in, FR_TYPE_STRING, NULL) < 0) {
			RPEDEBUG("Failed casting value to string");
			return XLAT_ACTION_FAIL;
		}
		break;
	}

	if (start_vb->vb_int32 > (int32_t)in->vb_length) return XLAT_ACTION_DONE;

	if (start_vb->vb_int32 < 0) {
		start = in->vb_length + start_vb->vb_int32;
		if (start < 0) start = 0;
	} else {
		start = start_vb->vb_int32;
	}

	if (len_vb) {
		if (len_vb->vb_int32 < 0) {
			end = in->vb_length + len_vb->vb_int32;
			if (end < 0) return XLAT_ACTION_DONE;
		} else {
			end = start + len_vb->vb_int32;
			if (end > (int32_t)in->vb_length) end = in->vb_length;
		}
	} else {
		end = in->vb_length;
	}

	if (start >= end) return XLAT_ACTION_DONE;

	MEM(vb = fr_value_box_alloc(ctx, in->type, NULL));

	len = end - start;
	switch (in->type) {
	case FR_TYPE_STRING:
		fr_value_box_bstrndup(vb, vb, NULL, &in->vb_strvalue[start], len, false);
		break;
	case FR_TYPE_OCTETS:
	{
		uint8_t *buf;
		fr_value_box_mem_alloc(vb, &buf, vb, NULL, len, false);
		memcpy(buf, &in->vb_octets[start], len);
	}
		break;
	default:
		fr_assert(0);
	}

	fr_value_box_safety_copy(vb, in);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#ifdef HAVE_REGEX_PCRE2
/** Cache statically compiled expressions
 */
typedef struct {
	regex_t			*pattern;
	fr_regex_flags_t	flags;
} xlat_subst_regex_inst_t;

/** Pre-compile regexes where possible
 */
static int xlat_instantiate_subst_regex(xlat_inst_ctx_t const *xctx)
{
	xlat_subst_regex_inst_t	*inst = talloc_get_type_abort(xctx->inst, xlat_subst_regex_inst_t);
	xlat_exp_t		*patt_exp;
	fr_sbuff_t		sbuff;
	fr_sbuff_marker_t	start_m, end_m;

	/* args #2 (pattern) */
	patt_exp = fr_dlist_next(&xctx->ex->call.args->dlist, fr_dlist_head(&xctx->ex->call.args->dlist));
	fr_assert(patt_exp && patt_exp->type == XLAT_GROUP);	/* args must be groups */

	/* If there are dynamic expansions, we can't pre-compile */
	if (!xlat_is_literal(patt_exp->group)) return 0;
	fr_assert(fr_dlist_num_elements(&patt_exp->group->dlist) == 1);

	patt_exp = fr_dlist_head(&patt_exp->group->dlist);

	/* We can only pre-compile strings */
	if (!fr_type_is_string(patt_exp->data.type)) return 0;

	sbuff = FR_SBUFF_IN(patt_exp->data.vb_strvalue, patt_exp->data.vb_length);

	/* skip any whitesapce */
	fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, 0);

	/* Is the next char a forward slash? */
	if (fr_sbuff_next_if_char(&sbuff, '/')) {
		fr_slen_t		slen;

		fr_sbuff_marker(&start_m, &sbuff);

		if (!fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '/')) return 0;	/* Not a regex */

		fr_sbuff_marker(&end_m, &sbuff);
		fr_sbuff_next(&sbuff); /* skip trailing slash */

		if (fr_sbuff_remaining(&sbuff)) {
			slen = regex_flags_parse(NULL, &inst->flags,
						&sbuff,
						NULL, true);
			if (slen < 0) {
				PERROR("Failed parsing regex flags in \"%s\"", patt_exp->data.vb_strvalue);
				return -1;
			}
		}

		if (regex_compile(inst, &inst->pattern,
				  fr_sbuff_current(&start_m), fr_sbuff_current(&end_m) - fr_sbuff_current(&start_m),
				  &inst->flags, true, false) <= 0) {
			PERROR("Failed compiling regex \"%s\"", patt_exp->data.vb_strvalue);
			return -1;
		}
	}
	/* No... then it's not a regex */

	return 0;
}

/** Perform regex substitution TODO CHECK
 *
 * Called when %subst() pattern begins with "/"
 *
@verbatim
%subst(<subject>, /<regex>/[flags], <replace>)
@endverbatim
 *
 * Example: (User-Name = "foo")
@verbatim
%subst(%{User-Name}, /oo.*$/, 'un') == "fun"
@endverbatim
 *
 * @note References can be specified in the replacement string with $<ref>
 *
 * @see #xlat_func_subst
 *
 * @ingroup xlat_functions
 */
static int xlat_func_subst_regex(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 xlat_ctx_t const *xctx, request_t *request,
				 fr_value_box_list_t *args)
{
	xlat_subst_regex_inst_t const	*inst = talloc_get_type_abort_const(xctx->inst, xlat_subst_regex_inst_t);
	fr_sbuff_t		sbuff;
	fr_sbuff_marker_t	start_m, end_m;
	char			*buff;
	ssize_t			slen;
	regex_t			*pattern, *our_pattern = NULL;
	fr_regex_flags_t const	*flags;
	fr_regex_flags_t	our_flags = {};
	fr_value_box_t		*vb;
	fr_value_box_t		*subject_vb;
	fr_value_box_t		*regex_vb;
	fr_value_box_t		*rep_vb;

	XLAT_ARGS(args, &subject_vb, &regex_vb, &rep_vb);

	/*
	 *	Was not pre-compiled, so we need to compile it now
	 */
	if (!inst->pattern) {
		sbuff = FR_SBUFF_IN(regex_vb->vb_strvalue, regex_vb->vb_length);
		if (fr_sbuff_len(&sbuff) == 0) {
			REDEBUG("Regex must not be empty");
			return XLAT_ACTION_FAIL;
		}

		fr_sbuff_next(&sbuff); /* skip leading slash */
		fr_sbuff_marker(&start_m, &sbuff);

		if (!fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, '/')) return 1;	/* Not a regex */

		fr_sbuff_marker(&end_m, &sbuff);
		fr_sbuff_next(&sbuff); /* skip trailing slash */

		slen = regex_flags_parse(NULL, &our_flags, &sbuff, NULL, true);
		if (slen < 0) {
			RPEDEBUG("Failed parsing regex flags");
			return -1;
		}

		/*
		*	Process the substitution
		*/
		if (regex_compile(NULL, &our_pattern,
				  fr_sbuff_current(&start_m), fr_sbuff_current(&end_m) - fr_sbuff_current(&start_m),
				  &our_flags, true, true) <= 0) {
			RPEDEBUG("Failed compiling regex");
			return -1;
		}
		pattern = our_pattern;
		flags = &our_flags;
	} else {
		pattern = inst->pattern;
		flags = &inst->flags;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (regex_substitute(vb, &buff, 0, pattern, flags,
			     subject_vb->vb_strvalue, subject_vb->vb_length,
			     rep_vb->vb_strvalue, rep_vb->vb_length, NULL) < 0) {
		RPEDEBUG("Failed performing substitution");
		talloc_free(vb);
		talloc_free(pattern);
		return -1;
	}
	fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, buff, false);

	fr_value_box_safety_copy(vb, subject_vb);
	fr_value_box_safety_merge(vb, rep_vb);

	fr_dcursor_append(out, vb);

	talloc_free(our_pattern);

	return 0;
}
#endif

static xlat_arg_parser_t const xlat_func_subst_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Perform regex substitution
 *
@verbatim
%subst(<subject>, <pattern>, <replace>)
@endverbatim
 *
 * Example: (User-Name = "foobar")
@verbatim
%subst(%{User-Name}, 'oo', 'un') == "funbar"
@endverbatim
 *
 * @see xlat_func_subst_regex
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_subst(TALLOC_CTX *ctx, fr_dcursor_t *out,
#ifdef HAVE_REGEX_PCRE2
				   xlat_ctx_t const *xctx,
#else
				   UNUSED xlat_ctx_t const *xctx,
#endif
				   request_t *request, fr_value_box_list_t *args)
{
	char const		*p, *q, *end;
	char			*vb_str;

	char const		*pattern, *rep;
	size_t			pattern_len, rep_len;

	fr_value_box_t		*rep_vb, *vb;
	fr_value_box_t		*subject_vb;
	fr_value_box_t		*pattern_vb;

	XLAT_ARGS(args, &subject_vb, &pattern_vb, &rep_vb);

	/* coverity[dereference] */
	pattern = pattern_vb->vb_strvalue;
	if (*pattern == '/') {
#ifdef HAVE_REGEX_PCRE2
		switch (xlat_func_subst_regex(ctx, out, xctx, request, args)) {
		case 0:
			return XLAT_ACTION_DONE;

		case 1:
			/* Not a regex, fall through */
			break;

		case -1:
			return XLAT_ACTION_FAIL;
		}
#else
		if (memchr(pattern, '/', pattern_vb->vb_length - 1)) {
			REDEBUG("regex based substitutions require libpcre2.  "
				"Check ${features.regex-pcre2} to determine support");
		}
		return XLAT_ACTION_FAIL;
#endif
	}

	/*
	 *	Check for empty pattern
	 */
	pattern_len = pattern_vb->vb_length;
	if (pattern_len == 0) {
		REDEBUG("Empty pattern");
		return XLAT_ACTION_FAIL;
	}

	rep = rep_vb->vb_strvalue;
	rep_len = rep_vb->vb_length;

	p = subject_vb->vb_strvalue;
	end = p + subject_vb->vb_length;

	MEM(vb = fr_value_box_alloc_null(ctx));
	vb_str = talloc_bstrndup(vb, "", 0);

	while (p < end) {
		q = memmem(p, end - p, pattern, pattern_len);
		if (!q) {
			MEM(vb_str = talloc_bstr_append(vb, vb_str, p, end - p));
			break;
		}

		if (q > p) MEM(vb_str = talloc_bstr_append(vb, vb_str, p, q - p));
		if (rep_len) MEM(vb_str = talloc_bstr_append(vb, vb_str, rep, rep_len));
		p = q + pattern_len;
	}

	if (fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, vb_str, false) < 0) {
		RPEDEBUG("Failed creating output box");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_value_box_safety_copy(vb, subject_vb);
	fr_value_box_safety_merge(vb, rep_vb);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/*
 *	Debug builds only, we don't want to allow unsanitised inputs to crash the server
 */
#ifndef NDEBUG
static xlat_arg_parser_t const xlat_func_signal_raise_args[] = {
	{ .single = true, .required = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t xlat_func_signal_raise(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					    UNUSED xlat_ctx_t const *xctx, request_t *request,
					    fr_value_box_list_t *args)
{
	static fr_table_num_sorted_t const signal_table[] = {
		{ L("break"),		SIGTRAP },	/* Save flailing at the keyboard */
		{ L("BREAK"),		SIGTRAP },
		{ L("SIGABRT"),		SIGABRT },
		{ L("SIGALRM"),		SIGALRM },
#ifdef SIGBUS
		{ L("SIGBUS"),		SIGBUS },
#endif
		{ L("SIGCHLD"),		SIGCHLD },
		{ L("SIGCONT"),		SIGCONT },
		{ L("SIGFPE"),		SIGFPE },
		{ L("SIGHUP"),		SIGHUP },
		{ L("SIGILL"),		SIGILL },
		{ L("SIGINT"),		SIGINT },
		{ L("SIGKILL"),		SIGKILL },
		{ L("SIGPIPE"),		SIGPIPE },
#ifdef SIGPOLL
		{ L("SIGPOLL"),		SIGPOLL },
#endif
		{ L("SIGPROF"),		SIGPROF },
		{ L("SIGQUIT"),		SIGQUIT },
		{ L("SIGSEGV"),		SIGSEGV },
		{ L("SIGSTOP"),		SIGSTOP },
#ifdef SIGSYS
		{ L("SIGSYS"),		SIGSYS },
#endif
		{ L("SIGTERM"),		SIGTERM },
#ifdef SIGTRAP
		{ L("SIGTRAP"),		SIGTRAP },
#endif
		{ L("SIGTSTP"),		SIGTSTP },
		{ L("SIGTTIN"),		SIGTTIN },
		{ L("SIGTTOU"),		SIGTTOU },
		{ L("SIGURG"),		SIGURG },
		{ L("SIGUSR1"),		SIGUSR1 },
		{ L("SIGUSR2"),		SIGUSR2 },
		{ L("SIGVTALRM"),	SIGVTALRM },
		{ L("SIGXCPU"),		SIGXCPU },
		{ L("SIGXFSZ"),		SIGXFSZ }
	};
	static size_t signal_table_len = NUM_ELEMENTS(signal_table);

	fr_value_box_t	*signal_vb;
	int		signal;

	XLAT_ARGS(args, &signal_vb);

	signal = fr_table_value_by_substr(signal_table, signal_vb->vb_strvalue, signal_vb->vb_length, -1);
	if (signal < 0) {
		RERROR("Invalid signal \"%pV\"", signal_vb);
		return XLAT_ACTION_FAIL;
	}
	if (raise(signal) < 0) {
		RERROR("Failed raising signal %d: %s", signal, strerror(errno));
		return XLAT_ACTION_FAIL;
	}
	return XLAT_ACTION_DONE;
}
#endif

static xlat_arg_parser_t const xlat_func_time_args[] = {
	{ .required = false, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the time as a #FR_TYPE_DATE
 *
 *  Note that all operations are UTC.
 *
@verbatim
%time()
@endverbatim
 *
 * Example:
@verbatim
update reply {
	&Reply-Message := "%{%time(now) - %time(request)}"
}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_time(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t		*arg;
	fr_value_box_t		*vb;
	fr_unix_time_t		value;

	XLAT_ARGS(args, &arg);

	if (!arg || (strcmp(arg->vb_strvalue, "now") == 0)) {
		value = fr_time_to_unix_time(fr_time());

	} else if (strcmp(arg->vb_strvalue, "request") == 0) {
		value = fr_time_to_unix_time(request->packet->timestamp);

	} else if (strcmp(arg->vb_strvalue, "offset") == 0) {
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));
		vb->vb_time_delta = fr_time_gmtoff();
		goto append;

	} else if (strcmp(arg->vb_strvalue, "dst") == 0) {
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
		vb->vb_bool = fr_time_is_dst();
		goto append;

	} else if (strcmp(arg->vb_strvalue, "mday_offset") == 0) {
		struct tm tm;
		fr_unix_time_t unix_time = fr_time_to_unix_time(request->packet->timestamp);
		time_t when = fr_unix_time_to_sec(unix_time);
		int64_t nsec;

		gmtime_r(&when, &tm);

		nsec = (int64_t) 86400 * (tm.tm_mday - 1);
		nsec += when % 86400;
		nsec *= NSEC;
		nsec += fr_unix_time_unwrap(unix_time) % NSEC;

		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));
		vb->vb_time_delta = fr_time_delta_wrap(nsec);
		goto append;

	} else if (strcmp(arg->vb_strvalue, "wday_offset") == 0) {
		struct tm tm;
		fr_unix_time_t unix_time = fr_time_to_unix_time(request->packet->timestamp);
		time_t when = fr_unix_time_to_sec(unix_time);
		int64_t nsec;

		gmtime_r(&when, &tm);

		nsec = (int64_t) 86400 * tm.tm_wday;
		nsec += when % 86400;
		nsec *= NSEC;
		nsec += fr_unix_time_unwrap(unix_time) % NSEC;

		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));
		vb->vb_time_delta = fr_time_delta_wrap(nsec);
		goto append;

	} else if (fr_unix_time_from_str(&value, arg->vb_strvalue, FR_TIME_RES_SEC) < 0) {
		REDEBUG("Invalid time specification '%s'", arg->vb_strvalue);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_DATE, NULL));
	vb->vb_date = value;

append:
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Return the current time as a #FR_TYPE_DATE
 *
 *  Note that all operations are UTC.
 *
@verbatim
%time.now()
@endverbatim
 *
 * Example:
@verbatim
update reply {
	&Reply-Message := "%{%time.now() - %time.request()}"
}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_time_now(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					UNUSED request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_DATE, NULL));
	vb->vb_date = fr_time_to_unix_time(fr_time());

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Return the request receive time as a #FR_TYPE_DATE
 *
 *  Note that all operations are UTC.
 *
@verbatim
%time.request()
@endverbatim
 *
 * Example:
@verbatim
update reply {
	&Reply-Message := "%{%time.now() - %time.request()}"
}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_time_request(TALLOC_CTX *ctx, fr_dcursor_t *out,
					    UNUSED xlat_ctx_t const *xctx,
					    request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_DATE, NULL));
	vb->vb_date = fr_time_to_unix_time(request->packet->timestamp);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Return the current time offset from gmt
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_time_offset(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   UNUSED request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_TIME_DELTA, NULL));
	vb->vb_time_delta = fr_time_gmtoff();

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Return whether we are in daylight savings or not
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_time_is_dst(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   UNUSED request_t *request, UNUSED fr_value_box_list_t *args)
{
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	vb->vb_bool = fr_time_is_dst();

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/** Change case of a string
 *
 * If upper is true, change to uppercase, otherwise, change to lowercase
 */
static xlat_action_t xlat_change_case(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED request_t *request, fr_value_box_list_t *args, bool upper)
{
	char		*p;
	char const	*end;
	fr_value_box_t	*vb;

	XLAT_ARGS(args, &vb);

	p = UNCONST(char *, vb->vb_strvalue);
	end = p + vb->vb_length;

	while (p < end) {
		*(p) = upper ? toupper ((int) *(p)) : tolower((uint8_t) *(p));
		p++;
	}

	xlat_arg_copy_out(ctx, out, args, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_change_case_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};


/** Convert a string to lowercase
 *
 * Example:
@verbatim
%tolower("Bar") == "bar"
@endverbatim
 *
 * Probably only works for ASCII
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_tolower(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	return xlat_change_case(ctx, out, request, in, false);
}


/** Convert a string to uppercase
 *
 * Example:
@verbatim
%toupper("Foo") == "FOO"
@endverbatim
 *
 * Probably only works for ASCII
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_toupper(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx,
				       request_t *request, fr_value_box_list_t *in)
{
	return xlat_change_case(ctx, out, request, in, true);
}


static xlat_arg_parser_t const xlat_func_urlquote_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** URLencode special characters
 *
 * Example:
@verbatim
%urlquote("http://example.org/") == "http%3A%47%47example.org%47"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_urlquote(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					UNUSED request_t *request, fr_value_box_list_t *args)
{
	char const	*p, *end;
	char		*buff_p;
	size_t		outlen = 0;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	p = in_head->vb_strvalue;
	end = p + in_head->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (isalnum(*p) ||
		    *p == '-' ||
		    *p == '_' ||
		    *p == '.' ||
		    *p == '~') {
			outlen++;
		} else {
			outlen += 3;
		}
		p++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);
	fr_value_box_safety_copy(vb, in_head);

	/* Reset p to start position */
	p = in_head->vb_strvalue;

	while (p < end) {
		if (isalnum(*p)) {
			*buff_p++ = *p++;
			continue;
		}

		switch (*p) {
		case '-':
		case '_':
		case '.':
		case '~':
			*buff_p++ = *p++;
			break;

		default:
			/* MUST be upper case hex to be compliant */
			snprintf(buff_p, 4, "%%%02X", (uint8_t) *p++); /* %XX */

			buff_p += 3;
		}
	}

	*buff_p = '\0';

	// @todo - mark as safe for URL?
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_urlunquote_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** URLdecode special characters
 *
 * @note Remember to escape % with %% in strings, else xlat will try to parse it.
 *
 * Example:
@verbatim
%urlunquote("http%%3A%%47%%47example.org%%47") == "http://example.org/"
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_urlunquote(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	char const	*p, *end;
	char		*buff_p;
	char		*c1, *c2;
	size_t		outlen = 0;
	fr_value_box_t	*vb;
	fr_value_box_t	*in_head;

	XLAT_ARGS(args, &in_head);

	p = in_head->vb_strvalue;
	end = p + in_head->vb_length;

	/*
	 * Calculate size of output
	 */
	while (p < end) {
		if (*p == '%') {
			p += 3;
		} else {
			p++;
		}
		outlen++;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &buff_p, vb, NULL, outlen, false) == 0);
	fr_value_box_safety_copy(vb, in_head);

	/* Reset p to start position */
	p = in_head->vb_strvalue;

	while (p < end) {
		if (*p != '%') {
			*buff_p++ = *p++;
			continue;
		}
		/* Is a % char */

		/* Don't need \0 check, as it won't be in the hextab */
		if (!(c1 = memchr(hextab, tolower((uint8_t) *++p), 16)) ||
		    !(c2 = memchr(hextab, tolower((uint8_t) *++p), 16))) {
			REMARKER(in_head->vb_strvalue, p - in_head->vb_strvalue, "Non-hex char in %% sequence");
			talloc_free(vb);

			return XLAT_ACTION_FAIL;
		}
		p++;
		*buff_p++ = ((c1 - hextab) << 4) + (c2 - hextab);
	}

	*buff_p = '\0';
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_pair_decode_args[] = {
	{ .required = true, .type = FR_TYPE_VOID },
	{ .single = true, .type = FR_TYPE_ATTR },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Decode any protocol attribute / options
 *
 * Creates protocol-specific attributes based on the given binary option data
 *
 * Example:
@verbatim
%dhcpv4.decode(%{Tmp-Octets-0})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_pair_decode(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *in)
{
	int					decoded;
	fr_value_box_t				*vb, *in_head, *root_da;
	void					*decode_ctx = NULL;
	xlat_pair_decode_uctx_t const	*decode_uctx = talloc_get_type_abort(*(void * const *)xctx->inst, xlat_pair_decode_uctx_t);
	fr_test_point_pair_decode_t const	*tp_decode = decode_uctx->tp_decode;
	fr_pair_t				*vp = NULL;
	bool					created = false;

	XLAT_ARGS(in, &in_head, &root_da);

	fr_assert(in_head->type == FR_TYPE_GROUP);

	if (decode_uctx->dict && decode_uctx->dict != request->proto_dict) {
		REDEBUG2("Can't call %%%s() when in %s namespace", xctx->ex->call.func->name,
			 fr_dict_root(request->proto_dict)->name);
		return XLAT_ACTION_FAIL;
	}

	if (root_da) {
		int ret;
		if (!fr_type_is_structural(root_da->vb_attr->type)) {
			REDEBUG2("Decoding context must be a structural attribute reference");
			return XLAT_ACTION_FAIL;
		}
		ret = fr_pair_update_by_da_parent(fr_pair_list_parent(&request->request_pairs), &vp, root_da->vb_attr);
		if (ret < 0) {
			REDEBUG2("Failed creating decoding root pair");
			return XLAT_ACTION_FAIL;
		}
		if (ret == 0) created = true;
	}

	if (tp_decode->test_ctx) {
		if (tp_decode->test_ctx(&decode_ctx, ctx, request->proto_dict, root_da ? root_da->vb_attr : NULL) < 0) {
			goto fail;
		}
	}

	decoded = xlat_decode_value_box_list(root_da ? vp : request->request_ctx,
					     root_da ? &vp->vp_group : &request->request_pairs,
					     request, decode_ctx, tp_decode->func, &in_head->vb_group);
	if (decoded <= 0) {
		talloc_free(decode_ctx);
		RPERROR("Protocol decoding failed");
	fail:
		if (created) fr_pair_delete(&request->request_pairs, vp);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Create a value box to hold the decoded count, and add
	 *	it to the output list.
	 */
	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL));
	vb->vb_uint32 = decoded;
	fr_dcursor_append(out, vb);

	talloc_free(decode_ctx);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_subnet_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_IPV4_PREFIX },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Calculate the subnet mask from a IPv4 prefix
 *
 * Example:
@verbatim
%ip.v4.netmask(%{Network-Prefix})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_subnet_netmask(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
					      UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*subnet, *vb;
	XLAT_ARGS(args, &subnet);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_IPV4_ADDR, NULL));
	vb->vb_ipv4addr = htonl((uint32_t)0xffffffff << (32 - subnet->vb_ip.prefix));
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Calculate the broadcast address from a IPv4 prefix
 *
 * Example:
@verbatim
%ip.v4.broadcast(%{Network-Prefix})
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_subnet_broadcast(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
						UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t	*subnet, *vb;
	XLAT_ARGS(args, &subnet);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_IPV4_ADDR, NULL));
	vb->vb_ipv4addr = htonl( ntohl(subnet->vb_ipv4addr) | (uint32_t)0xffffffff >> subnet->vb_ip.prefix);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static int xlat_pair_dencode_instantiate(xlat_inst_ctx_t const *mctx)
{
	*(void **) mctx->inst = mctx->uctx;
	return 0;
}

static xlat_arg_parser_t const xlat_pair_encode_args[] = {
	XLAT_ARG_PARSER_CURSOR,
	{ .single = true, .type = FR_TYPE_ATTR },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encode protocol attributes / options
 *
 * Returns octet string created from the provided pairs
 *
 * Example:
@verbatim
%dhcpv4.encode(&request[*])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_pair_encode(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *args)
{
	fr_pair_t	*vp;
	fr_dcursor_t	*cursor;
	bool		tainted = false, encode_children = false;
	fr_value_box_t	*encoded;

	fr_dbuff_t	*dbuff;
	ssize_t		len = 0;
	fr_value_box_t	*in_head, *root_da;
	void		*encode_ctx = NULL;
	fr_test_point_pair_encode_t const *tp_encode;

	FR_DBUFF_TALLOC_THREAD_LOCAL(&dbuff, 2048, SIZE_MAX);

	XLAT_ARGS(args, &in_head, &root_da);

	memcpy(&tp_encode, xctx->inst, sizeof(tp_encode)); /* const issues */

	cursor = fr_value_box_get_cursor(in_head);

	/*
	 *	Create the encoding context.
	 */
	if (tp_encode->test_ctx) {
		if (tp_encode->test_ctx(&encode_ctx, cursor, request->proto_dict, root_da ? root_da->vb_attr : NULL) < 0) {
			return XLAT_ACTION_FAIL;
		}
	}

	if (root_da) {
		if (!fr_type_is_structural(root_da->vb_attr->type)) {
			REDEBUG2("Encoding context must be a structural attribute reference");
			return XLAT_ACTION_FAIL;
		}
		vp = fr_dcursor_current(cursor);
		if (!fr_dict_attr_common_parent(root_da->vb_attr, vp->da, true) && (root_da->vb_attr != vp->da)) {
			REDEBUG2("%s is not a child of %s", vp->da->name, root_da->vb_attr->name);
			return XLAT_ACTION_FAIL;
		}
		if (root_da->vb_attr == vp->da) encode_children = true;
	}

	/*
	 *	Loop over the attributes, encoding them.
	 */
	RDEBUG2("Encoding attributes");

	if (RDEBUG_ENABLED2) {
		RINDENT();
		for (vp = fr_dcursor_current(cursor);
		     vp != NULL;
		     vp = fr_dcursor_next(cursor)) {
			RDEBUG2("%pP", vp);
		}
		REXDENT();
	}

	/*
	 *	Encoders advance the cursor, so we just need to feed
	 *	in the next pair.  This was originally so we could
	 *	extend the output buffer, but with dbuffs that's
	 *	no longer necessary... we might want to refactor this
	 *	in future.
	 */
	for (vp = fr_dcursor_head(cursor);
	     vp != NULL;
	     vp = fr_dcursor_current(cursor)) {
		/*
		 *
		 *	Don't check for internal attributes, the
		 *	encoders can skip them if they need to, and the
		 *	internal encoder can encode anything, as can
		 *	things like CBOR.
		 *
		 *	Don't check the dictionaries.  By definition,
		 *	vp->da->dict==request->proto_dict, OR else we're
		 *	using the internal encoder and encoding a real
		 *	protocol.
		 *
		 *	However, we likely still want a
		 *	dictionary-specific "is encodable" function,
		 *	as AKA/SIM and DHCPv6 encode "bool"s only if
		 *	their value is true.
		 */
		if (encode_children) {
			fr_dcursor_t	child_cursor;

			fr_assert(fr_type_is_structural(vp->vp_type));

			/*
			 *	If we're given an encoding context which is the
			 *	same as the DA returned by the cursor, that means
			 *	encode the children.
			 */
			fr_pair_dcursor_init(&child_cursor, &vp->vp_group);
			while (fr_dcursor_current(&child_cursor)) {
				len = tp_encode->func(dbuff, &child_cursor, encode_ctx);
				if (len < 0) break;
			}
			fr_dcursor_next(cursor);
		} else {
			len = tp_encode->func(dbuff, cursor, encode_ctx);
		}
		if (len < 0) {
			RPEDEBUG("Protocol encoding failed");
			return XLAT_ACTION_FAIL;
		}

		tainted |= vp->vp_tainted;
	}

	/*
	 *	Pass the options string back to the caller.
	 */
	MEM(encoded = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(encoded, encoded, NULL, fr_dbuff_start(dbuff), fr_dbuff_used(dbuff), tainted);
	fr_dcursor_append(out, encoded);

	return XLAT_ACTION_DONE;
}

static int xlat_protocol_register_by_name(dl_t *dl, char const *name, fr_dict_t const *dict)
{
	fr_test_point_pair_decode_t *tp_decode;
	fr_test_point_pair_encode_t *tp_encode;
	xlat_pair_decode_uctx_t *decode_uctx;
	xlat_t *xlat;
	char buffer[256+32];

	/*
	 *	See if there's a decode function for it.
	 */
	snprintf(buffer, sizeof(buffer), "%s_tp_decode_pair", name);
	tp_decode = dlsym(dl->handle, buffer);
	if (tp_decode) {
		snprintf(buffer, sizeof(buffer), "%s.decode", name);

		/* May be called multiple times, so just skip protocols we've already registered */
		if (xlat_func_find(buffer, -1)) return 1;

		if (unlikely((xlat = xlat_func_register(NULL, buffer, xlat_pair_decode, FR_TYPE_UINT32)) == NULL)) return -1;
		xlat_func_args_set(xlat, xlat_pair_decode_args);
		decode_uctx = talloc(xlat, xlat_pair_decode_uctx_t);
		decode_uctx->tp_decode = tp_decode;
		decode_uctx->dict = dict;
		/* coverity[suspicious_sizeof] */
		xlat_func_instantiate_set(xlat, xlat_pair_dencode_instantiate, xlat_pair_decode_uctx_t *, NULL, decode_uctx);
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
	}

	/*
	 *	See if there's an encode function for it.
	 */
	snprintf(buffer, sizeof(buffer), "%s_tp_encode_pair", name);
	tp_encode = dlsym(dl->handle, buffer);
	if (tp_encode) {
		snprintf(buffer, sizeof(buffer), "%s.encode", name);

		if (xlat_func_find(buffer, -1)) return 1;

		if (unlikely((xlat = xlat_func_register(NULL, buffer, xlat_pair_encode, FR_TYPE_OCTETS)) == NULL)) return -1;
		xlat_func_args_set(xlat, xlat_pair_encode_args);
		/* coverity[suspicious_sizeof] */
		xlat_func_instantiate_set(xlat, xlat_pair_dencode_instantiate, fr_test_point_pair_encode_t *, NULL, tp_encode);
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
	}

	return 0;
}

static int xlat_protocol_register(fr_dict_t const *dict)
{
	dl_t *dl = fr_dict_dl(dict);
	char *p, name[256];

	/*
	 *	No library for this protocol, skip it.
	 *
	 *	Protocol TEST has no libfreeradius-test, so that's OK.
	 */
	if (!dl) return 0;

	strlcpy(name, fr_dict_root(dict)->name, sizeof(name));
	for (p = name; *p != '\0'; p++) {
		*p = tolower((uint8_t) *p);
	}

	return xlat_protocol_register_by_name(dl, name, dict != fr_dict_internal() ? dict : NULL);
}

static dl_loader_t *cbor_loader = NULL;

static int xlat_protocol_register_cbor(void)
{
	dl_t *dl;

	cbor_loader = dl_loader_init(NULL, NULL, false, false);
	if (!cbor_loader) return 0;

	dl = dl_by_name(cbor_loader, "libfreeradius-cbor", NULL, false);
	if (!dl) return 0;

	if (xlat_protocol_register_by_name(dl, "cbor", NULL) < 0) return -1;

	return 0;
}


/** Register xlats for any loaded dictionaries
 */
int xlat_protocols_register(void)
{
	fr_dict_t *dict;
	fr_dict_global_ctx_iter_t iter;

	for (dict = fr_dict_global_ctx_iter_init(&iter);
	     dict != NULL;
	     dict = fr_dict_global_ctx_iter_next(&iter)) {
		if (xlat_protocol_register(dict) < 0) return -1;
	}

	/*
	 *	And the internal protocol, too.
	 */
	if (xlat_protocol_register(fr_dict_internal()) < 0) return -1;

	/*
	 *	And cbor stuff
	 */
	if (xlat_protocol_register_cbor() < 0) return -1;

	return 0;
}

/** De-register all xlat functions we created
 *
 */
static int _xlat_global_free(UNUSED void *uctx)
{
	TALLOC_FREE(xlat_ctx);
	xlat_func_free();
	xlat_eval_free();
	talloc_free(cbor_loader);

	return 0;
}

/** Global initialisation for xlat
 *
 * @note Free memory with #xlat_free
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 *
 * @hidecallgraph
 */
static int _xlat_global_init(UNUSED void *uctx)
{
	xlat_t *xlat;

	xlat_ctx = talloc_init("xlat");
	if (!xlat_ctx) return -1;

	if (xlat_func_init() < 0) return -1;

	/*
	 *	Lookup attributes used by virtual xlat expansions.
	 */
	if (xlat_eval_init() < 0) return -1;

	/*
	 *	Registers async xlat operations in the `unlang` interpreter.
	 */
	unlang_xlat_init();

	/*
	 *	These are all "pure" functions.
	 */
#define XLAT_REGISTER_ARGS(_xlat, _func, _return_type, _args) \
do { \
	if (unlikely((xlat = xlat_func_register(xlat_ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_args_set(xlat, _args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

#define XLAT_NEW(_x) xlat->replaced_with = _x

	XLAT_REGISTER_ARGS("cast", xlat_func_cast, FR_TYPE_VOID, xlat_func_cast_args);

	XLAT_REGISTER_ARGS("str.concat", xlat_func_concat, FR_TYPE_STRING, xlat_func_concat_args);
	XLAT_REGISTER_ARGS("concat", xlat_func_concat, FR_TYPE_STRING, xlat_func_concat_args);
	XLAT_NEW("str.concat");

	XLAT_REGISTER_ARGS("str.split", xlat_func_explode, FR_TYPE_STRING, xlat_func_explode_args);
	XLAT_REGISTER_ARGS("explode", xlat_func_explode, FR_TYPE_STRING, xlat_func_explode_args);
	XLAT_NEW("str.split");

	XLAT_REGISTER_ARGS("file.escape", xlat_transparent, FR_TYPE_STRING, xlat_func_file_name_args);

	XLAT_REGISTER_ARGS("hmac.md5", xlat_func_hmac_md5, FR_TYPE_OCTETS, xlat_hmac_args);
	XLAT_REGISTER_ARGS("hmacmd5", xlat_func_hmac_md5, FR_TYPE_OCTETS, xlat_hmac_args);
	XLAT_NEW("hmac.md5");

	XLAT_REGISTER_ARGS("hmac.sha1", xlat_func_hmac_sha1, FR_TYPE_OCTETS, xlat_hmac_args);
	XLAT_REGISTER_ARGS("hmacsha1", xlat_func_hmac_sha1, FR_TYPE_OCTETS, xlat_hmac_args);
	XLAT_NEW("hmac.sha1");

	XLAT_REGISTER_ARGS("integer", xlat_func_integer, FR_TYPE_VOID, xlat_func_integer_args);
	xlat->deprecated = true;

	XLAT_REGISTER_ARGS("join", xlat_func_join, FR_TYPE_VOID, xlat_func_join_args);
	XLAT_REGISTER_ARGS("ungroup", xlat_func_ungroup, FR_TYPE_VOID, xlat_func_join_args);
	xlat->deprecated = true;

	XLAT_REGISTER_ARGS("length", xlat_func_length, FR_TYPE_SIZE, xlat_func_length_args);

	XLAT_REGISTER_ARGS("str.lpad", xlat_func_lpad, FR_TYPE_STRING, xlat_func_pad_args);
	XLAT_REGISTER_ARGS("lpad", xlat_func_lpad, FR_TYPE_STRING, xlat_func_pad_args);
	XLAT_NEW("str.lpad");

	XLAT_REGISTER_ARGS("str.rpad", xlat_func_rpad, FR_TYPE_STRING, xlat_func_pad_args);
	XLAT_REGISTER_ARGS("rpad", xlat_func_rpad, FR_TYPE_STRING, xlat_func_pad_args);
	XLAT_NEW("str.rpad");

	XLAT_REGISTER_ARGS("str.substr", xlat_func_substr, FR_TYPE_VOID, xlat_func_substr_args);
	XLAT_REGISTER_ARGS("substr", xlat_func_substr, FR_TYPE_VOID, xlat_func_substr_args);
	XLAT_NEW("str.substr");

	XLAT_REGISTER_ARGS("ip.v4.netmask", xlat_func_subnet_netmask, FR_TYPE_IPV4_ADDR, xlat_func_subnet_args);
	XLAT_REGISTER_ARGS("ip.v4.broadcast", xlat_func_subnet_broadcast, FR_TYPE_IPV4_ADDR, xlat_func_subnet_args);

	/*
	 *	The inputs to these functions are variable.
	 */
#undef XLAT_REGISTER_ARGS
#define XLAT_REGISTER_ARGS(_xlat, _func, _return_type, _args) \
do { \
	if (unlikely((xlat = xlat_func_register(xlat_ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_args_set(xlat, _args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

#undef XLAT_REGISTER_VOID
#define XLAT_REGISTER_VOID(_xlat, _func, _return_type) \
do { \
	if (unlikely((xlat = xlat_func_register(xlat_ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

	XLAT_REGISTER_ARGS("block", xlat_func_block, FR_TYPE_TIME_DELTA, xlat_func_block_args);
	XLAT_REGISTER_ARGS("debug", xlat_func_debug, FR_TYPE_INT8, xlat_func_debug_args);
	XLAT_REGISTER_ARGS("debug_attr", xlat_func_pairs_debug, FR_TYPE_NULL, xlat_pair_cursor_args);
	XLAT_NEW("pairs.debug");

	XLAT_REGISTER_ARGS("file.exists", xlat_func_file_exists, FR_TYPE_BOOL, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.head", xlat_func_file_head, FR_TYPE_STRING, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.rm", xlat_func_file_rm, FR_TYPE_BOOL, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.touch", xlat_func_file_touch, FR_TYPE_BOOL, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.size", xlat_func_file_size, FR_TYPE_UINT64, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.tail", xlat_func_file_tail, FR_TYPE_STRING, xlat_func_file_name_count_args);
	XLAT_REGISTER_ARGS("file.cat", xlat_func_file_cat, FR_TYPE_OCTETS, xlat_func_file_cat_args);
	XLAT_REGISTER_ARGS("file.mkdir", xlat_func_file_mkdir, FR_TYPE_BOOL, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.rmdir", xlat_func_file_rmdir, FR_TYPE_BOOL, xlat_func_file_name_args);

	XLAT_REGISTER_ARGS("immutable", xlat_func_immutable_attr, FR_TYPE_NULL, xlat_pair_cursor_args);
	XLAT_NEW("pairs.immutable");
	XLAT_REGISTER_ARGS("pairs.immutable", xlat_func_immutable_attr, FR_TYPE_NULL, xlat_pair_cursor_args);

	XLAT_REGISTER_ARGS("log.debug", xlat_func_log_debug, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.err", xlat_func_log_err, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.info", xlat_func_log_info, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.warn", xlat_func_log_warn, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.destination", xlat_func_log_dst, FR_TYPE_STRING, xlat_func_log_dst_args);

	XLAT_REGISTER_ARGS("nexttime", xlat_func_next_time, FR_TYPE_UINT64, xlat_func_next_time_args);
	XLAT_NEW("time.next");
	XLAT_REGISTER_ARGS("time.next", xlat_func_next_time, FR_TYPE_UINT64, xlat_func_next_time_args);

	XLAT_REGISTER_ARGS("pairs", xlat_func_pairs_print, FR_TYPE_STRING, xlat_pair_cursor_args);
	XLAT_NEW("pairs.print");
	XLAT_REGISTER_ARGS("pairs.print", xlat_func_pairs_print, FR_TYPE_STRING, xlat_pair_cursor_args);

	XLAT_REGISTER_ARGS("pairs.debug", xlat_func_pairs_debug, FR_TYPE_NULL, xlat_pair_cursor_args);

	XLAT_REGISTER_ARGS("str.subst", xlat_func_subst, FR_TYPE_STRING, xlat_func_subst_args);
#ifdef HAVE_REGEX_PCRE2
	xlat_func_instantiate_set(xlat, xlat_instantiate_subst_regex, xlat_subst_regex_inst_t, NULL, NULL);
#endif
	XLAT_REGISTER_ARGS("subst", xlat_func_subst, FR_TYPE_STRING, xlat_func_subst_args);
	XLAT_NEW("str.subst");
#ifdef HAVE_REGEX_PCRE2
	xlat_func_instantiate_set(xlat, xlat_instantiate_subst_regex, xlat_subst_regex_inst_t, NULL, NULL);
#endif

#ifndef NDEBUG
	XLAT_REGISTER_ARGS("signal.raise", xlat_func_signal_raise, FR_TYPE_STRING, xlat_func_signal_raise_args);
#endif

	XLAT_REGISTER_ARGS("time", xlat_func_time, FR_TYPE_VOID, xlat_func_time_args);
	XLAT_REGISTER_VOID("time.now", xlat_func_time_now, FR_TYPE_DATE);
	XLAT_REGISTER_VOID("time.request", xlat_func_time_request, FR_TYPE_DATE);
	XLAT_REGISTER_VOID("time.offset", xlat_func_time_offset, FR_TYPE_TIME_DELTA);
	XLAT_REGISTER_VOID("time.is_dst", xlat_func_time_is_dst, FR_TYPE_BOOL);

	XLAT_REGISTER_ARGS("base64.encode", xlat_func_base64_encode, FR_TYPE_STRING, xlat_func_base64_encode_arg);
	XLAT_REGISTER_ARGS("base64.decode", xlat_func_base64_decode, FR_TYPE_OCTETS, xlat_func_base64_decode_arg);
	XLAT_REGISTER_ARGS("rand", xlat_func_rand, FR_TYPE_UINT64, xlat_func_rand_arg);

	XLAT_REGISTER_ARGS("str.rand", xlat_func_randstr, FR_TYPE_STRING, xlat_func_randstr_arg);
	XLAT_REGISTER_ARGS("randstr", xlat_func_randstr, FR_TYPE_STRING, xlat_func_randstr_arg);
	XLAT_NEW("str.rand");

	XLAT_REGISTER_VOID("uuid.v4", xlat_func_uuid_v4, FR_TYPE_STRING);
	XLAT_REGISTER_VOID("uuid.v7", xlat_func_uuid_v7, FR_TYPE_STRING);

	XLAT_REGISTER_ARGS("range", xlat_func_range, FR_TYPE_UINT64, xlat_func_range_arg);

	if (unlikely((xlat = xlat_func_register(xlat_ctx, "untaint", xlat_func_untaint, FR_TYPE_VOID)) == NULL)) return -1;
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL);
	xlat_func_args_set(xlat, xlat_func_taint_args);

	if (unlikely((xlat = xlat_func_register(xlat_ctx, "taint", xlat_func_taint, FR_TYPE_VOID)) == NULL)) return -1;
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL);
	xlat_func_args_set(xlat, xlat_func_taint_args);

	/*
	 *	All of these functions are pure.
	 */
#define XLAT_REGISTER_PURE(_xlat, _func, _return_type, _arg) \
do { \
	if (unlikely((xlat = xlat_func_register(xlat_ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_args_set(xlat, _arg); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

	XLAT_REGISTER_PURE("bin", xlat_func_bin, FR_TYPE_OCTETS, xlat_func_bin_arg);
	XLAT_REGISTER_PURE("hex", xlat_func_hex, FR_TYPE_STRING, xlat_func_hex_arg);
	XLAT_REGISTER_PURE("map", xlat_func_map, FR_TYPE_BOOL, xlat_func_map_arg);
	XLAT_REGISTER_PURE("hash.md4", xlat_func_md4, FR_TYPE_OCTETS, xlat_func_md4_arg);
	XLAT_REGISTER_PURE("md4", xlat_func_md4, FR_TYPE_OCTETS, xlat_func_md4_arg);
	XLAT_NEW("hash.md4");

	XLAT_REGISTER_PURE("hash.md5", xlat_func_md5, FR_TYPE_OCTETS, xlat_func_md5_arg);
	XLAT_REGISTER_PURE("md5", xlat_func_md5, FR_TYPE_OCTETS, xlat_func_md5_arg);
	XLAT_NEW("hash.md4");

	if (unlikely((xlat = xlat_func_register(xlat_ctx, "regex.match", xlat_func_regex, FR_TYPE_STRING)) == NULL)) return -1;
	xlat_func_args_set(xlat, xlat_func_regex_args);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
	if (unlikely((xlat = xlat_func_register(xlat_ctx, "regex", xlat_func_regex, FR_TYPE_STRING)) == NULL)) return -1;
	xlat_func_args_set(xlat, xlat_func_regex_args);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
	XLAT_NEW("regex.match");

	{
		static xlat_arg_parser_t const xlat_regex_safe_args[] = {
			{ .type = FR_TYPE_STRING, .variadic = true, .concat = true },
			XLAT_ARG_PARSER_TERMINATOR
		};

		static xlat_arg_parser_t const xlat_regex_escape_args[] = {
			{ .type = FR_TYPE_STRING,
			  .func = regex_xlat_escape, .safe_for = FR_REGEX_SAFE_FOR, .always_escape = true,
			  .variadic = true, .concat = true },
			XLAT_ARG_PARSER_TERMINATOR
		};

		if (unlikely((xlat = xlat_func_register(xlat_ctx, "regex.safe",
							xlat_transparent, FR_TYPE_STRING)) == NULL)) return -1;
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
		xlat_func_args_set(xlat, xlat_regex_safe_args);
		xlat_func_safe_for_set(xlat, FR_REGEX_SAFE_FOR);

		if (unlikely((xlat = xlat_func_register(xlat_ctx, "regex.escape",
							xlat_transparent, FR_TYPE_STRING)) == NULL)) return -1;
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
		xlat_func_args_set(xlat, xlat_regex_escape_args);
		xlat_func_safe_for_set(xlat, FR_REGEX_SAFE_FOR);
	}

#define XLAT_REGISTER_HASH(_name, _func) do { \
		XLAT_REGISTER_PURE("hash." _name, _func, FR_TYPE_OCTETS, xlat_func_sha_arg); \
		XLAT_REGISTER_PURE(_name, _func, FR_TYPE_OCTETS, xlat_func_sha_arg); \
		XLAT_NEW("hash." _name); \
      	} while (0)

	XLAT_REGISTER_HASH("sha1", xlat_func_sha1);

#ifdef HAVE_OPENSSL_EVP_H
	XLAT_REGISTER_HASH("sha2_224", xlat_func_sha2_224);
	XLAT_REGISTER_HASH("sha2_256", xlat_func_sha2_256);
	XLAT_REGISTER_HASH("sha2_384", xlat_func_sha2_384);
	XLAT_REGISTER_HASH("sha2_512", xlat_func_sha2_512);
	XLAT_REGISTER_HASH("sha2", xlat_func_sha2_256);

#  ifdef HAVE_EVP_BLAKE2S256
	XLAT_REGISTER_HASH("blake2s_256", xlat_func_blake2s_256);
#  endif
#  ifdef HAVE_EVP_BLAKE2B512
	XLAT_REGISTER_HASH("blake2b_512", xlat_func_blake2b_512);
#  endif

	XLAT_REGISTER_HASH("sha3_224", xlat_func_sha3_224);
	XLAT_REGISTER_HASH("sha3_256", xlat_func_sha3_256);
	XLAT_REGISTER_HASH("sha3_384", xlat_func_sha3_384);
	XLAT_REGISTER_HASH("sha3_512", xlat_func_sha3_512);
	XLAT_REGISTER_HASH("sha3", xlat_func_sha3_256);
#endif

	XLAT_REGISTER_PURE("string", xlat_transparent, FR_TYPE_STRING, xlat_func_string_arg);
	xlat->deprecated = true;
	XLAT_REGISTER_PURE("strlen", xlat_func_strlen, FR_TYPE_SIZE, xlat_func_strlen_arg);
	XLAT_NEW("length");

	XLAT_REGISTER_PURE("str.utf8", xlat_func_str_utf8, FR_TYPE_BOOL, xlat_func_str_utf8_arg);
	XLAT_REGISTER_PURE("str.printable", xlat_func_str_printable, FR_TYPE_BOOL, xlat_func_str_printable_arg);

	XLAT_REGISTER_PURE("str.lower", xlat_func_tolower, FR_TYPE_STRING, xlat_change_case_arg);
	XLAT_REGISTER_PURE("tolower", xlat_func_tolower, FR_TYPE_STRING, xlat_change_case_arg);
	XLAT_NEW("str.lower");

	XLAT_REGISTER_PURE("str.upper", xlat_func_toupper, FR_TYPE_STRING, xlat_change_case_arg);
	XLAT_REGISTER_PURE("toupper", xlat_func_toupper, FR_TYPE_STRING, xlat_change_case_arg);
	XLAT_NEW("str.upper");

	XLAT_REGISTER_PURE("url.quote", xlat_func_urlquote, FR_TYPE_STRING, xlat_func_urlquote_arg);
	XLAT_REGISTER_PURE("urlquote", xlat_func_urlquote, FR_TYPE_STRING, xlat_func_urlquote_arg);
	XLAT_NEW("url.quote");

	XLAT_REGISTER_PURE("url.unquote", xlat_func_urlunquote, FR_TYPE_STRING, xlat_func_urlunquote_arg);
	XLAT_REGISTER_PURE("urlunquote", xlat_func_urlunquote, FR_TYPE_STRING, xlat_func_urlunquote_arg);
	XLAT_NEW("url.unquote");

	XLAT_REGISTER_PURE("eval", xlat_func_eval, FR_TYPE_VOID, xlat_func_eval_arg);

	return xlat_register_expressions();
}

int xlat_global_init(void)
{
	int ret;
	fr_atexit_global_once_ret(&ret, _xlat_global_init, _xlat_global_free, NULL);
	return ret;
}
