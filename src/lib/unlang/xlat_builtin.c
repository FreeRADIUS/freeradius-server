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
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat.h>

#include <freeradius-devel/io/test_point.h>

#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/sha1.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <freeradius-devel/tls/openssl_user_macros.h>
#  include <openssl/evp.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>

static char const hextab[] = "0123456789abcdef";

/** Return a VP from the specified request.
 *
 * @note DEPRECATED, TO NOT USE.
 *
 * @param out where to write the pointer to the resolved VP. Will be NULL if the attribute couldn't
 *	be resolved.
 * @param request current request.
 * @param name attribute name including qualifiers.
 * @return
 *	- -4 if either the attribute or qualifier were invalid.
 *	- The same error codes as #tmpl_find_vp for other error conditions.
 */
int xlat_fmt_get_vp(fr_pair_t **out, request_t *request, char const *name)
{
	int ret;
	tmpl_t *vpt;

	*out = NULL;

	if (tmpl_afrom_attr_str(request, NULL, &vpt, name,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.list_def = request_attr_request,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) return -4;

	ret = tmpl_find_vp(out, request, vpt);
	talloc_free(vpt);

	return ret;
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


static xlat_arg_parser_t const xlat_func_debug_attr_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

void xlat_debug_attr_vp(request_t *request, fr_pair_t *vp, tmpl_t const *vpt)
{
	fr_dict_vendor_t const		*vendor;
	fr_table_num_ordered_t const	*type;
	size_t				i;

	switch (vp->vp_type) {
	case FR_TYPE_STRUCTURAL:
		if (vpt) {
			RIDEBUG2("&%s.%s = {",
				 tmpl_list_name(tmpl_list(vpt), "<INVALID>"),
				 vp->da->name);
		} else {
			RIDEBUG2("%s = {", vp->da->name);
		}
		RINDENT();
		xlat_debug_attr_list(request, &vp->vp_group);
		REXDENT();
		RIDEBUG2("}");
		break;

	default:
		if (vpt) {
			RIDEBUG2("&%s.%s = %pV",
				 tmpl_list_name(tmpl_list(vpt), "<INVALID>"),
				 vp->da->name,
				 &vp->data);
		} else {
			RIDEBUG2("%s = %pV", vp->da->name, &vp->data);
		}
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
	if (vendor) RIDEBUG2("vendor     : %i (%s)", vendor->pen, vendor->name);
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

		MEM(dst = fr_value_box_alloc_null(vp));
		/* We expect some to fail */
		if (fr_value_box_cast(dst, dst, type->value, NULL, &vp->data) < 0) {
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

void xlat_debug_attr_list(request_t *request, fr_pair_list_t const *list)
{
	fr_pair_t *vp;

	for (vp = fr_pair_list_next(list, NULL);
	     vp != NULL;
	     vp = fr_pair_list_next(list, vp)) {
		xlat_debug_attr_vp(request, vp, NULL);
	}
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
%debug_attr(&request)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_debug_attr(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	fr_pair_t		*vp;
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	tmpl_t			*vpt;
	fr_value_box_t		*attr;
	char const		*fmt;

	XLAT_ARGS(args, &attr);

	if (!RDEBUG_ENABLED2) return XLAT_ACTION_DONE;	/* NOOP if debugging isn't enabled */

	fmt = attr->vb_strvalue;

	if (tmpl_afrom_attr_str(request, NULL, &vpt, fmt,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.list_def = request_attr_request,
						.allow_wildcard = true,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		xlat_debug_attr_vp(request, vp, vpt);
	}
	tmpl_dcursor_clear(&cc);
	REXDENT();

	talloc_free(vpt);

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

/** Escape the paths as necessary
 *
 */
static ssize_t xlat_file_escape_path(fr_sbuff_t *in, fr_value_box_t *vb)
{
	fr_sbuff_t our_in = FR_SBUFF(in);
	fr_sbuff_t out;
	char buffer[256];

	if (vb->type == FR_TYPE_GROUP) {
		fr_value_box_list_foreach(&vb->vb_group, box) {
			if (xlat_file_escape_path(&our_in, box) < 0) return -1;
		}

		goto done;
	}

	fr_assert(fr_type_is_leaf(vb->type));

	/*
	 *	Untainted values get passed through, as do base integer types.
	 */
	if (!vb->tainted || (vb->type == FR_TYPE_OCTETS) || fr_type_is_integer(vb->type)) {
		fr_value_box_print(&our_in, vb, NULL);
		goto done;
	}

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
	if (vb->type == FR_TYPE_STRING) {
		if (vb->vb_length == 0) goto done;

		if (vb->vb_strvalue[0] == '.') {
			fr_value_box_print(&our_in, vb, &xlat_filename_escape_dots);
		} else {
			fr_value_box_print(&our_in, vb, &xlat_filename_escape);
		}
		goto  done;
	}

	/*
	 *	Ethernet addresses have ':'.  IP prefixes have '/'.  Floats have '+' and '-' in them.
	 *	Dates have pretty much all of that, plus spaces.
	 *
	 *	Lesson: print dates as %Y() or %l().
	 *
	 *	We use an intermediate buffer to print the type, and then copy it to the output
	 *	buffer, escaping it along the way.
	 */
	out = FR_SBUFF_OUT(buffer, sizeof(buffer));
	fr_value_box_print(&out, vb, NULL);
	fr_sbuff_in_escape(&our_in, fr_sbuff_start(&out), fr_sbuff_used(&out), &xlat_filename_escape);

done:
	FR_SBUFF_SET_RETURN(in, &our_in);
}

static const char *xlat_file_name(fr_value_box_t *vb)
{
	fr_sbuff_t	*path;

	FR_SBUFF_TALLOC_THREAD_LOCAL(&path, 256, PATH_MAX + 1);

	if (xlat_file_escape_path(path, vb) < 0) return NULL;

	if (fr_sbuff_in_char(path, '\0') < 0) return NULL; /* file functions take NUL delimited strings */

	return fr_sbuff_start(path);
}

static xlat_arg_parser_t const xlat_func_file_name_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_arg_parser_t const xlat_func_file_name_count_args[] = {
	{ .required = true, .type = FR_TYPE_STRING },
	{ .required = false, .type = FR_TYPE_UINT32 },
	XLAT_ARG_PARSER_TERMINATOR
};


static xlat_action_t xlat_func_file_escape(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;

	XLAT_ARGS(args, &vb);
	filename = xlat_file_name(vb);
	if (!filename) return XLAT_ACTION_FAIL;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));
	if (fr_value_box_bstrndup(dst, dst, NULL, filename, strlen(filename), false) < 0) {
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_file_exists(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   UNUSED request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;
	struct stat	buf;

	XLAT_ARGS(args, &vb);
	filename = xlat_file_name(vb);
	if (!filename) return XLAT_ACTION_FAIL;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, dst);

	dst->vb_bool = (stat(filename, &buf) == 0);

	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_file_head(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;
	ssize_t		len;
	int		fd;
	char		*p, buffer[256];

	XLAT_ARGS(in, &vb);
	filename = xlat_file_name(vb);
	if (!filename) return XLAT_ACTION_FAIL;

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
					   request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;
	struct stat	buf;

	XLAT_ARGS(in, &vb);
	filename = xlat_file_name(vb);
	if (!filename) return XLAT_ACTION_FAIL;

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
					 request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *dst, *vb, *num = NULL;
	char const	*filename;
	ssize_t		len;
	size_t		count = 0;
	off_t		offset;
	int		fd;
	int		n, r, stop = 2;
	char		*p, *end, *found, buffer[256];

	XLAT_ARGS(in, &vb, &num);
	filename = xlat_file_name(vb);
	if (!filename) return XLAT_ACTION_FAIL;

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

	if (len == 0) {
		found = buffer;	/* count is zero, so who cares */
		goto done;
	}

	n = r = 0;		/* be agnostic over CR / LF */

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
			stop = 2;
		} else if (num->vb_uint32 < 15) {
			stop = num->vb_uint64 + 1;
		} else {
			stop = 16;
		}
	} else {
		stop = 2;
	}

	end = NULL;
	found = NULL;

	/*
	 *	Nuke any trailing CR/LF
	 */
	p = buffer + len - 1;
	while (p >= buffer) {
		if (*p == '\r') {
			r++;

			if (r == stop) break;

			if (!end) end = p;

		} else if (*p == '\n') {
			n++;

			if (n == stop) break;

			if (!end) end = p;

		} else {
			if (!r) r++; /* if we didn't get a CR/LF at EOF, pretend we did */
			if (!n) n++;

			found = p;
		}

		p--;
	}

	if (!end) end = buffer + len;

	/*
	 *	The buffer was only one line of CR/LF.
	 */
	if (!found) {
		found = buffer;
		goto done;
	}

	count = (end - found);

done:
	close(fd);

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));
	if (fr_value_box_bstrndup(dst, dst, NULL, found, count, false) < 0) {
		talloc_free(dst);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}


static xlat_action_t xlat_func_file_rm(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t *dst, *vb;
	char const	*filename;

	XLAT_ARGS(in, &vb);
	filename = xlat_file_name(vb);
	if (!filename) return XLAT_ACTION_FAIL;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, dst);

	dst->vb_bool = (unlink(filename) == 0);
	if (!dst->vb_bool) {
		REDEBUG3("Failed unlinking file %s - %s", filename, fr_syserror(errno));
	}

	return XLAT_ACTION_DONE;
}


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

	while((string = fr_value_box_list_pop_head(list))) {
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
						      fr_sbuff_behind(&m_start), string->tainted);
				fr_dcursor_append(out, vb);

			advance:
				fr_sbuff_advance(&sbuff, delim_len);
				fr_sbuff_set(&m_start, &sbuff);
				continue;
			}
			fr_sbuff_set_to_end(&sbuff);
			MEM(vb = fr_value_box_alloc_null(ctx));
			fr_value_box_bstrndup(vb, vb, NULL, fr_sbuff_current(&m_start),
					      fr_sbuff_behind(&m_start), string->tainted);
			fr_dcursor_append(out, vb);
			break;
		}
		talloc_free(string);
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_immutable_attr_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Mark one or more attributes as immutable
 *
 * Example:
@verbatim
%immutable(&request.State[*])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_immutable_attr(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					  UNUSED xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	fr_pair_t		*vp;
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	tmpl_t			*vpt;
	fr_value_box_t		*attr;
	char const		*fmt;

	XLAT_ARGS(args, &attr);

	fmt = attr->vb_strvalue;

	if (tmpl_afrom_attr_str(request, NULL, &vpt, fmt,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.list_def = request_attr_request,
						.allow_wildcard = true,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	RIDEBUG("Attributes matching \"%s\"", fmt);

	RINDENT();
	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		if (fr_type_is_leaf(vp->vp_type)) fr_value_box_set_immutable(&vp->data);
	}
	tmpl_dcursor_clear(&cc);
	REXDENT();

	talloc_free(vpt);

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
		RPEDEBUG("Failed converting %pV (%s) to an integer", in_vb,
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
		memcpy(&ipv6int, &in_vb->vb_ip.addr.v6.s6_addr, sizeof(ipv6int));

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
	{ .required = true, .type = FR_TYPE_STRING },
	{ .required = false, .type = FR_TYPE_UINT32 },
	{ .required = false, .type = FR_TYPE_STRING },
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
		request_log_prepend(request, NULL, L_DBG_LVL_OFF);
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

	/*
	 *	Open the new filename.
	 */
	dbg->dst = L_DST_FILES;
	dbg->file = talloc_strdup(dbg, file->vb_strvalue);
	dbg->fd = open(dbg->file, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	if (!dbg->fd) {
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
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Processes fmt as a map string and applies it to the current request
 *
 * e.g.
@verbatim
%map("&User-Name := 'foo'")
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
			.dict_def = request->dict,
			.list_def = request_attr_request,
			.prefix = TMPL_ATTR_REF_PREFIX_AUTO
		}
	};

	XLAT_ARGS(args, &fmt_vb);

	if (map_afrom_attr_str(request, &map, fmt_vb->vb_strvalue, &attr_rules, &attr_rules) < 0) {
		RPEDEBUG("Failed parsing \"%s\" as map", fmt_vb->vb_strvalue);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_INT8, NULL));
	vb->vb_int8 = 0;	/* Default fail value - changed to 1 on success */
	fr_dcursor_append(out, vb);

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

	vb->vb_int8 = 1;
	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const xlat_func_next_time_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Calculate number of seconds until the next n hour(s), day(s), week(s), year(s).
 *
 * For example, if it were 16:18 %nexttime(1h) would expand to 2520.
 *
 * The envisaged usage for this function is to limit sessions so that they don't
 * cross billing periods. The output of the xlat should be combined with %{rand:} to create
 * some jitter, unless the desired effect is every subscriber on the network
 * re-authenticating at the same time.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_next_time(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 UNUSED xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *args)
{
	long		num;

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
	if (!q || *q == '\0') {
		REDEBUG("nexttime: <int> must be followed by period specifier (h|d|w|m|y)");
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
		REDEBUG("nexttime: Invalid period specifier '%c', must be h|d|w|m|y", *p);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_uint64(vb, NULL, (uint64_t)(mktime(local) - now), false);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

typedef struct {
	bool		last_success;
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
	xlat_action_t		xa = rctx->last_success ? XLAT_ACTION_DONE : XLAT_ACTION_FAIL;

	talloc_free(rctx);

	return xa;
}

typedef struct {
	fr_dict_t const	*namespace;	//!< Namespace we use for evaluating runtime expansions
} xlat_eval_inst_t;

static int xlat_eval_instantiate(xlat_inst_ctx_t const *xctx)
{
	xlat_eval_inst_t *inst = talloc_get_type_abort(xctx->inst, xlat_eval_inst_t);

	inst->namespace = xctx->ex->call.dict;

	return 0;
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
				    xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *args)
{
	xlat_eval_inst_t const *inst = talloc_get_type_abort_const(xctx->inst, xlat_eval_inst_t);

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
	if (xlat_tokenize(rctx,
			  &rctx->ex,
			  &FR_SBUFF_IN(arg->vb_strvalue, arg->vb_length),
			  &(fr_sbuff_parse_rules_t){
				  .escapes = &escape_rules
			  },
			  &(tmpl_rules_t){
				  .attr = {
					  .dict_def = inst->namespace,
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

	if (unlang_xlat_push(ctx, &rctx->last_success, (fr_value_box_list_t *)out->dlist,
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
	vb->tainted = in->tainted;
	fr_value_box_set_secret(vb, fr_value_box_is_secret(in));
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

	alen = FR_BASE64_DEC_LENGTH(in->vb_length);
	MEM(vb = fr_value_box_alloc_null(ctx));
	if (alen > 0) {
		MEM(fr_value_box_mem_alloc(vb, &decbuf, vb, NULL, alen, in->tainted) == 0);
		declen = fr_base64_decode(&FR_DBUFF_TMP(decbuf, alen),
					  &FR_SBUFF_IN(in->vb_strvalue, in->vb_length), true, true);
		if (declen < 0) {
			RPEDEBUG("Base64 string invalid");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		MEM(fr_value_box_mem_realloc(vb, NULL, vb, declen) == 0);
	}

	vb->tainted = in->tainted;
	fr_value_box_set_secret(vb, fr_value_box_is_secret(in));
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_func_bin_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
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
	fr_value_box_t		*hex;

	XLAT_ARGS(args, &hex);

	len = hex->vb_length;
	if ((len > 1) && (len & 0x01)) {
		REDEBUG("Input data length must be >1 and even, got %zu", len);
		return XLAT_ACTION_FAIL;
	}

	p = hex->vb_strvalue;
	end = p + len;

	/*
	 *	Look for 0x at the start of the string
	 */
	if ((p[0] == '0') && (p[1] == 'x')) {
		p += 2;
		len -=2;
	}

	/*
	 *	Zero length octets string
	 */
	if (p == end) goto finish;

	outlen = len / 2;

	MEM(result = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(result, &bin, result, NULL, outlen, fr_value_box_list_tainted(args)) == 0);
	fr_base16_decode(&err, &FR_DBUFF_TMP(bin, outlen), &FR_SBUFF_IN(p, end - p), true);
	if (err) {
		REDEBUG2("Invalid hex string");
		talloc_free(result);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, result);

finish:
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
			RDEBUG("Unknown data type '%s'", name->vb_strvalue);
			return XLAT_ACTION_FAIL;
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
		if (fr_value_box_list_concat_as_string(NULL, NULL, agg, args, NULL, 0, NULL,
						       FR_VALUE_BOX_LIST_FREE_BOX, true) < 0) {
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

			if (fr_value_box_cast_in_place(vb, vb, type, NULL) < 0) {
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
	{ .required = true, .concat = true, .type = FR_TYPE_OCTETS },
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
	fr_value_box_t	*bin;

	XLAT_ARGS(args, &bin);

	fr_value_box_list_remove(args, bin);

	/*
	 *	Use existing box, but with new buffer
	 */
	MEM(new_buff = talloc_zero_array(bin, char, (bin->vb_length * 2) + 1));
	if (bin->vb_length) {
		fr_base16_encode(&FR_SBUFF_OUT(new_buff, (bin->vb_length * 2) + 1),
					       &FR_DBUFF_TMP(bin->vb_octets, bin->vb_length));
		fr_value_box_clear_value(bin);
		fr_value_box_strdup_shallow(bin, NULL, new_buff, bin->tainted);
	/*
	 *	Zero length binary > zero length hex string
	 */
	} else {
		fr_value_box_clear_value(bin);
		fr_value_box_strdup(bin, bin, NULL, "", bin->tainted);
	}
	fr_dcursor_append(out, bin);

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
%hmacmd5(%{string:foo}, %{string:bar}) == "0x31b6db9e5eb4addb42f1a6ca07367adc"
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
%hmacsha1(%{string:foo}, %{string:bar}) == "0x85d155c55ed286a300bd1cf124de08d87e914f3a"
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
static xlat_action_t xlat_func_join(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_list_foreach(in, arg) {
		fr_assert(arg->type == FR_TYPE_GROUP);

		fr_value_box_list_foreach_safe(&arg->vb_group, vb) {
			fr_value_box_list_remove(&arg->vb_group, vb);
			fr_dcursor_append(out, vb);
		}}
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


static xlat_arg_parser_t const xlat_func_pairs_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encode attributes as a series of string attribute/value pairs
 *
 * This is intended to serialize one or more attributes as a comma
 * delimited string.
 *
 * Example:
@verbatim
%pairs(request.[*]) == 'User-Name = "foo"User-Password = "bar"'
%concat(%pairs(request.[*]), ', ') == 'User-Name = "foo", User-Password = "bar"'
@endverbatim
 *
 * @see #xlat_func_concat
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_pairs(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *args)
{
	tmpl_t			*vpt = NULL;
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;
	fr_value_box_t		*vb;
	fr_value_box_t		*in_head;

	fr_pair_t *vp;

	XLAT_ARGS(args, &in_head);

	if (tmpl_afrom_attr_str(ctx, NULL, &vpt, in_head->vb_strvalue,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.list_def = request_attr_request,
						.allow_wildcard = true,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Invalid input");
		return XLAT_ACTION_FAIL;
	}

	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		char *buff;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (unlikely(fr_pair_aprint(vb, &buff, NULL, vp) < 0)) {
			RPEDEBUG("Failed printing pair");
			talloc_free(vb);
			tmpl_dcursor_clear(&cc);
			return XLAT_ACTION_FAIL;
		}

		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, buff, false);
		fr_dcursor_append(out, vb);
	}
	tmpl_dcursor_clear(&cc);
	talloc_free(vpt);

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


#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
/** Get named subcapture value from previous regex
 *
 * Example:
@verbatim
if ("foo" =~ /^(?<name>.*)/) {
        noop
}
%regex(name) == "foo"
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
		char		*p;

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, &p, request, 0) < 0) {
			REDEBUG2("No previous regex capture");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
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
		char		*p;

		if (fr_value_box_list_next(in, in_head)) {
			REDEBUG("Only one subcapture argument allowed");
			return XLAT_ACTION_FAIL;
		}

		if (fr_value_box_cast(NULL, &idx, FR_TYPE_UINT32, NULL, arg) < 0) {
			RPEDEBUG("Bad subcapture index");
			return XLAT_ACTION_FAIL;
		}

		MEM(vb = fr_value_box_alloc_null(ctx));
		if (regex_request_to_sub(vb, &p, request, idx.vb_uint32) < 0) {
			REDEBUG2("No previous numbered regex capture group");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}
		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}

	default:
	{
		fr_value_box_t	*vb;
		char		*p;

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
		if (regex_request_to_sub_named(vb, &p, request, arg->vb_strvalue) < 0) {
			REDEBUG2("No previous named regex capture group");
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_assert(p);
		fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, p, false);
		fr_dcursor_append(out, vb);

		return XLAT_ACTION_DONE;
	}
	}
}
#endif

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

EVP_MD_XLAT(blake2s_256, blake2s256)
EVP_MD_XLAT(blake2b_512, blake2b512)

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
EVP_MD_XLAT(sha3_224, sha3_224)
EVP_MD_XLAT(sha3_256, sha3_256)
EVP_MD_XLAT(sha3_384, sha3_384)
EVP_MD_XLAT(sha3_512, sha3_512)
#  endif
#endif


static xlat_arg_parser_t const xlat_func_string_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Print data as string, if possible.
 *
 * Concat and cast one or more input boxes to a single output box string.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_string(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      UNUSED request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*in_head = fr_value_box_list_pop_head(in);

	/*
	 *	Casting and concat is done by arg processing
	 *	so just move the value box to the output
	 */
	fr_dcursor_append(out, in_head);

	return XLAT_ACTION_DONE;
}


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


#ifdef HAVE_REGEX_PCRE2
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
 * @see #xlat_func_subst
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_subst_regex(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx, request_t *request,
					   fr_value_box_list_t *args)
{
	char const		*p, *q, *end;
	char const		*regex;
	char			*buff;
	size_t			regex_len;
	ssize_t			slen;
	regex_t			*pattern;
	fr_regex_flags_t	flags;
	fr_value_box_t		*vb;
	fr_value_box_t		*subject_vb;
	fr_value_box_t		*regex_vb;
	fr_value_box_t		*rep_vb;

	XLAT_ARGS(args, &subject_vb, &regex_vb, &rep_vb);

	/* coverity[dereference] */
	p = regex_vb->vb_strvalue;
	end = p + regex_vb->vb_length;

	if (p == end) {
		REDEBUG("Regex must not be empty");
		return XLAT_ACTION_FAIL;
	}

	p++;	/* Advance past '/' */
	regex = p;

	q = memchr(p, '/', end - p);
	if (!q) {
		REDEBUG("No terminating '/' found for regex");
		return XLAT_ACTION_FAIL;
	}
	regex_len = q - p;

	p = q + 1;

	/*
	 *	Parse '[flags]'
	 */
	memset(&flags, 0, sizeof(flags));

	slen = regex_flags_parse(NULL, &flags, &FR_SBUFF_IN(p, end), NULL, true);
	if (slen < 0) {
		RPEDEBUG("Failed parsing regex flags");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Process the substitution
	 */
	if (regex_compile(NULL, &pattern, regex, regex_len, &flags, false, true) <= 0) {
		RPEDEBUG("Failed compiling regex");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	if (regex_substitute(vb, &buff, 0, pattern, &flags,
			     subject_vb->vb_strvalue, subject_vb->vb_length,
			     rep_vb->vb_strvalue, rep_vb->vb_length, NULL) < 0) {
		RPEDEBUG("Failed performing substitution");
		talloc_free(vb);
		talloc_free(pattern);
		return XLAT_ACTION_FAIL;
	}
	fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, buff, subject_vb->tainted);
	fr_value_box_set_secret(vb, fr_value_box_is_secret(subject_vb));

	fr_dcursor_append(out, vb);

	talloc_free(pattern);

	return XLAT_ACTION_DONE;
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
%sub(<subject>, <pattern>, <replace>)
@endverbatim
 *
 * Example: (User-Name = "foobar")
@verbatim
%sub(%{User-Name}, 'oo', 'un') == "funbar"
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
		return xlat_func_subst_regex(ctx, out, xctx, request, args);
#else
		REDEBUG("regex based substitutions require libpcre2.  "
			"Check ${features.regex-pcre2} to determine support");
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

	if (fr_value_box_bstrdup_buffer_shallow(NULL, vb, NULL, vb_str, subject_vb->tainted) < 0) {
		RPEDEBUG("Failed creating output box");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_assert(vb && (vb->type != FR_TYPE_NULL));
	fr_value_box_set_secret(vb, fr_value_box_is_secret(subject_vb));
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

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


/** Change case of a string
 *
 * If upper is true, change to uppercase, otherwise, change to lowercase
 */
static xlat_action_t xlat_change_case(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
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

	fr_value_box_list_remove(args, vb);	/* Can't leave it in both lists */
	fr_dcursor_append(out, vb);

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
	fr_value_box_set_secret(vb, fr_value_box_is_secret(in_head));

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
	fr_value_box_set_secret(vb, fr_value_box_is_secret(in_head));

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

static xlat_arg_parser_t const protocol_decode_xlat_args[] = {
	{ .single = true, .variadic = XLAT_ARG_VARIADIC_EMPTY_SQUASH, .type = FR_TYPE_VOID },
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
static xlat_action_t protocol_decode_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	int					decoded;
	fr_value_box_t				*vb;
	void					*decode_ctx = NULL;
	fr_test_point_pair_decode_t const	*tp_decode = *(void * const *)xctx->inst;

	if (tp_decode->test_ctx) {
		if (tp_decode->test_ctx(&decode_ctx, ctx) < 0) {
			return XLAT_ACTION_FAIL;
		}
	}

	decoded = xlat_decode_value_box_list(request->request_ctx, &request->request_pairs,
					     request, decode_ctx, tp_decode->func, in);
	if (decoded <= 0) {
		talloc_free(decode_ctx);
		RPERROR("Protocol decoding failed");
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

static int protocol_xlat_instantiate(xlat_inst_ctx_t const *mctx)
{
	*(void **) mctx->inst = mctx->uctx;
	return 0;
}

static xlat_arg_parser_t const protocol_encode_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
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
static xlat_action_t protocol_encode_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	tmpl_t		*vpt;
	fr_pair_t	*vp;
	fr_dcursor_t	cursor;
	tmpl_dcursor_ctx_t	cc;
	bool		tainted = false;
	fr_value_box_t	*encoded;

	uint8_t		binbuf[2048];
	uint8_t		*p = binbuf, *end = p + sizeof(binbuf);
	ssize_t		len = 0;
	fr_value_box_t	*in_head;
	void		*encode_ctx = NULL;
	fr_test_point_pair_encode_t const *tp_encode;

	XLAT_ARGS(args, &in_head);

	memcpy(&tp_encode, xctx->inst, sizeof(tp_encode)); /* const issues */

	if (tmpl_afrom_attr_str(ctx, NULL, &vpt, in_head->vb_strvalue,
				&(tmpl_rules_t){
					.attr = {
						.dict_def = request->dict,
						.list_def = request_attr_request,
						.allow_wildcard = true,
						.prefix = TMPL_ATTR_REF_PREFIX_AUTO
					}
				}) <= 0) {
		RPEDEBUG("Failed parsing attribute reference");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Create the encoding context.
	 */
	if (tp_encode->test_ctx) {
		if (tp_encode->test_ctx(&encode_ctx, vpt) < 0) {
			talloc_free(vpt);
			return XLAT_ACTION_FAIL;
		}
	}

	/*
	 *	Loop over the attributes, encoding them.
	 */
	for (vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, vpt);
	     vp != NULL;
	     vp = fr_dcursor_next(&cursor)) {
		if (vp->da->flags.internal) continue;

		/*
		 *	Don't check the dictionaries.  By definition,
		 *	vp->da->dict==request->dict, OR else we're
		 *	using the internal encoder and encoding a real
		 *	protocol.
		 *
		 *	However, we likely still want a
		 *	dictionary-specific "is encodable" function,
		 *	as AKA/SIM and DHCPv6 encode "bool"s only if
		 *	their value is true.
		 */

		len = tp_encode->func(&FR_DBUFF_TMP(p, end), &cursor, encode_ctx);
		if (len < 0) {
			RPEDEBUG("Protocol encoding failed");
			tmpl_dcursor_clear(&cc);
			talloc_free(vpt);
			return XLAT_ACTION_FAIL;
		}

		tainted |= vp->vp_tainted;
		p += len;
	}

	tmpl_dcursor_clear(&cc);
	talloc_free(vpt);

	/*
	 *	Pass the options string back to the caller.
	 */
	MEM(encoded = fr_value_box_alloc_null(ctx));
	fr_value_box_memdup(encoded, encoded, NULL, binbuf, (size_t)len, tainted);
	fr_dcursor_append(out, encoded);

	return XLAT_ACTION_DONE;
}

static int xlat_protocol_register(fr_dict_t const *dict)
{
	fr_test_point_pair_decode_t *tp_decode;
	fr_test_point_pair_encode_t *tp_encode;
	xlat_t *xlat;
	dl_t *dl = fr_dict_dl(dict);
	char *p, buffer[256+32], name[256];

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

	/*
	 *	See if there's a decode function for it.
	 */
	snprintf(buffer, sizeof(buffer), "%s_tp_decode_pair", name);
	tp_decode = dlsym(dl->handle, buffer);
	if (tp_decode) {
		snprintf(buffer, sizeof(buffer), "%s.decode", name);

		/* May be called multiple times, so just skip protocols we've already registered */
		if (xlat_func_find(buffer, -1)) return 1;

		if (unlikely((xlat = xlat_func_register(NULL, buffer, protocol_decode_xlat, FR_TYPE_UINT32)) == NULL)) return -1;
		xlat_func_args_set(xlat, protocol_decode_xlat_args);
		/* coverity[suspicious_sizeof] */
		xlat_func_instantiate_set(xlat, protocol_xlat_instantiate, fr_test_point_pair_decode_t *, NULL, tp_decode);
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

		if (unlikely((xlat = xlat_func_register(NULL, buffer, protocol_encode_xlat, FR_TYPE_OCTETS)) == NULL)) return -1;
		xlat_func_args_set(xlat, protocol_encode_xlat_args);
		/* coverity[suspicious_sizeof] */
		xlat_func_instantiate_set(xlat, protocol_xlat_instantiate, fr_test_point_pair_encode_t *, NULL, tp_encode);
		xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
	}

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
int xlat_init(TALLOC_CTX *ctx)
{
	xlat_t *xlat;

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
	if (unlikely((xlat = xlat_func_register(ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_args_set(xlat, _args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

	XLAT_REGISTER_ARGS("cast", xlat_func_cast, FR_TYPE_VOID, xlat_func_cast_args);
	XLAT_REGISTER_ARGS("concat", xlat_func_concat, FR_TYPE_STRING, xlat_func_concat_args);
	XLAT_REGISTER_ARGS("explode", xlat_func_explode, FR_TYPE_STRING, xlat_func_explode_args);
	XLAT_REGISTER_ARGS("file.escape", xlat_func_file_escape, FR_TYPE_STRING, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.exists", xlat_func_file_exists, FR_TYPE_BOOL, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.head", xlat_func_file_head, FR_TYPE_STRING, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.rm", xlat_func_file_rm, FR_TYPE_BOOL, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.size", xlat_func_file_size, FR_TYPE_UINT64, xlat_func_file_name_args);
	XLAT_REGISTER_ARGS("file.tail", xlat_func_file_tail, FR_TYPE_STRING, xlat_func_file_name_count_args);
	XLAT_REGISTER_ARGS("hmacmd5", xlat_func_hmac_md5, FR_TYPE_OCTETS, xlat_hmac_args);
	XLAT_REGISTER_ARGS("hmacsha1", xlat_func_hmac_sha1, FR_TYPE_OCTETS, xlat_hmac_args);
	XLAT_REGISTER_ARGS("integer", xlat_func_integer, FR_TYPE_VOID, xlat_func_integer_args);
	XLAT_REGISTER_ARGS("join", xlat_func_join, FR_TYPE_VOID, xlat_func_join_args);
	XLAT_REGISTER_ARGS("ungroup", xlat_func_ungroup, FR_TYPE_VOID, xlat_func_join_args);
	XLAT_REGISTER_ARGS("length", xlat_func_length, FR_TYPE_SIZE, xlat_func_length_args);
	XLAT_REGISTER_ARGS("lpad", xlat_func_lpad, FR_TYPE_STRING, xlat_func_pad_args);
	XLAT_REGISTER_ARGS("rpad", xlat_func_rpad, FR_TYPE_STRING, xlat_func_pad_args);

	/*
	 *	The inputs to these functions are variable.
	 */
#undef XLAT_REGISTER_ARGS
#define XLAT_REGISTER_ARGS(_xlat, _func, _return_type, _args) \
do { \
	if (unlikely((xlat = xlat_func_register(ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_args_set(xlat, _args); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

	XLAT_REGISTER_ARGS("debug", xlat_func_debug, FR_TYPE_INT8, xlat_func_debug_args);
	XLAT_REGISTER_ARGS("debug_attr", xlat_func_debug_attr, FR_TYPE_NULL, xlat_func_debug_attr_args);
	XLAT_REGISTER_ARGS("immutable", xlat_func_immutable_attr, FR_TYPE_NULL, xlat_func_immutable_attr_args);
	XLAT_REGISTER_ARGS("log.debug", xlat_func_log_debug, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.err", xlat_func_log_err, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.info", xlat_func_log_info, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.warn", xlat_func_log_warn, FR_TYPE_NULL, xlat_func_log_arg);
	XLAT_REGISTER_ARGS("log.destination", xlat_func_log_dst, FR_TYPE_STRING, xlat_func_log_dst_args);
	XLAT_REGISTER_ARGS("nexttime", xlat_func_next_time, FR_TYPE_UINT64, xlat_func_next_time_args);
	XLAT_REGISTER_ARGS("pairs", xlat_func_pairs, FR_TYPE_STRING, xlat_func_pairs_args);
	XLAT_REGISTER_ARGS("subst", xlat_func_subst, FR_TYPE_STRING, xlat_func_subst_args);
	XLAT_REGISTER_ARGS("time", xlat_func_time, FR_TYPE_VOID, xlat_func_time_args);
	XLAT_REGISTER_ARGS("trigger", trigger_xlat, FR_TYPE_STRING, trigger_xlat_args);
	XLAT_REGISTER_ARGS("base64.encode", xlat_func_base64_encode, FR_TYPE_STRING, xlat_func_base64_encode_arg);
	XLAT_REGISTER_ARGS("base64.decode", xlat_func_base64_decode, FR_TYPE_OCTETS, xlat_func_base64_decode_arg);

	if (unlikely((xlat = xlat_func_register(ctx, "untaint", xlat_func_untaint, FR_TYPE_VOID)) == NULL)) return -1;
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL);

	if (unlikely((xlat = xlat_func_register(ctx, "taint", xlat_func_taint, FR_TYPE_VOID)) == NULL)) return -1;
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL);

	/*
	 *	All of these functions are pure.
	 */
#define XLAT_REGISTER_MONO(_xlat, _func, _return_type, _arg) \
do { \
	if (unlikely((xlat = xlat_func_register(ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_mono_set(xlat, _arg); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE | XLAT_FUNC_FLAG_INTERNAL); \
} while (0)


	XLAT_REGISTER_MONO("bin", xlat_func_bin, FR_TYPE_OCTETS, xlat_func_bin_arg);
	XLAT_REGISTER_MONO("hex", xlat_func_hex, FR_TYPE_STRING, xlat_func_hex_arg);
	XLAT_REGISTER_MONO("map", xlat_func_map, FR_TYPE_INT8, xlat_func_map_arg);
	XLAT_REGISTER_MONO("md4", xlat_func_md4, FR_TYPE_OCTETS, xlat_func_md4_arg);
	XLAT_REGISTER_MONO("md5", xlat_func_md5, FR_TYPE_OCTETS, xlat_func_md5_arg);
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	if (unlikely((xlat = xlat_func_register(ctx, "regex", xlat_func_regex, FR_TYPE_STRING)) == NULL)) return -1;
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL);
#endif
	XLAT_REGISTER_MONO("sha1", xlat_func_sha1, FR_TYPE_OCTETS, xlat_func_sha_arg);

#ifdef HAVE_OPENSSL_EVP_H
	XLAT_REGISTER_MONO("sha2_224", xlat_func_sha2_224, FR_TYPE_OCTETS, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha2_256", xlat_func_sha2_256, FR_TYPE_OCTETS, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha2_384", xlat_func_sha2_384, FR_TYPE_OCTETS, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha2_512", xlat_func_sha2_512, FR_TYPE_OCTETS, xlat_func_sha_arg);

	XLAT_REGISTER_MONO("blake2s_256", xlat_func_blake2s_256, FR_TYPE_OCTETS, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("blake2b_512", xlat_func_blake2b_512, FR_TYPE_OCTETS, xlat_func_sha_arg);

#  if OPENSSL_VERSION_NUMBER >= 0x10101000L
	XLAT_REGISTER_MONO("sha3_224", xlat_func_sha3_224, FR_TYPE_OCTETS, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha3_256", xlat_func_sha3_256, FR_TYPE_OCTETS, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha3_384", xlat_func_sha3_384, FR_TYPE_OCTETS, xlat_func_sha_arg);
	XLAT_REGISTER_MONO("sha3_512", xlat_func_sha3_512, FR_TYPE_OCTETS, xlat_func_sha_arg);
#  endif
#endif

	XLAT_REGISTER_MONO("string", xlat_func_string, FR_TYPE_STRING, xlat_func_string_arg);
	XLAT_REGISTER_MONO("strlen", xlat_func_strlen, FR_TYPE_SIZE, xlat_func_strlen_arg);
	XLAT_REGISTER_MONO("tolower", xlat_func_tolower, FR_TYPE_STRING, xlat_change_case_arg);
	XLAT_REGISTER_MONO("toupper", xlat_func_toupper, FR_TYPE_STRING, xlat_change_case_arg);
	XLAT_REGISTER_MONO("urlquote", xlat_func_urlquote, FR_TYPE_STRING, xlat_func_urlquote_arg);
	XLAT_REGISTER_MONO("urlunquote", xlat_func_urlunquote, FR_TYPE_STRING, xlat_func_urlunquote_arg);
	XLAT_REGISTER_MONO("eval", xlat_func_eval, FR_TYPE_VOID, xlat_func_eval_arg);
	xlat_func_instantiate_set(xlat, xlat_eval_instantiate, xlat_eval_inst_t, NULL, NULL);

#undef XLAT_REGISTER_MONO
#define XLAT_REGISTER_MONO(_xlat, _func, _return_type, _arg) \
do { \
	if (unlikely((xlat = xlat_func_register(ctx, _xlat, _func, _return_type)) == NULL)) return -1; \
	xlat_func_mono_set(xlat, _arg); \
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_INTERNAL); \
} while (0)

	XLAT_REGISTER_MONO("rand", xlat_func_rand, FR_TYPE_UINT64, xlat_func_rand_arg);
	XLAT_REGISTER_MONO("randstr", xlat_func_randstr, FR_TYPE_STRING, xlat_func_randstr_arg);

	return xlat_register_expressions();
}

/** De-register all xlat functions we created
 *
 */
void xlat_free(void)
{
	xlat_func_free();

	xlat_eval_free();
}
