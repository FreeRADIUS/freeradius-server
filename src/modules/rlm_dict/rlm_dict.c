/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_dict.c
 * @brief Retrieve attributes from a dict.
 *
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/xlat_func.h>

static xlat_arg_parser_t const xlat_dict_attr_by_num_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_UINT32 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Xlat for %(attr_by_num:\<number\>)
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_dict_attr_by_num(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	fr_dict_attr_t const	*da;
	fr_value_box_t		*attr = fr_value_box_list_head(in);
	fr_value_box_t		*vb;

	da = fr_dict_attr_child_by_num(fr_dict_root(request->dict), attr->vb_uint32);
	if (!da) {
		REDEBUG("No attribute found with number %pV", attr);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));

	if (fr_value_box_bstrndup(ctx, vb, NULL, da->name, strlen(da->name), false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_dict_attr_by_oid_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Xlat for %(attr_by_oid:\<oid\>)
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_dict_attr_by_oid(TALLOC_CTX *ctx, fr_dcursor_t *out,
					   UNUSED xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *in)
{
	unsigned int		attr = 0;
	fr_dict_attr_t const	*parent = fr_dict_root(request->dict);
	fr_dict_attr_t const	*da;
	ssize_t			ret;
	fr_value_box_t		*attr_vb = fr_value_box_list_head(in);
	fr_value_box_t		*vb;

	ret = fr_dict_attr_by_oid_legacy(fr_dict_internal(), &parent, &attr, attr_vb->vb_strvalue);
	if (ret <= 0) {
		REMARKER(attr_vb->vb_strvalue, -(ret), "%s", fr_strerror());
		return XLAT_ACTION_FAIL;
	}

	MEM(da = fr_dict_attr_child_by_num(parent, attr));

	MEM(vb = fr_value_box_alloc_null(ctx));

	if (fr_value_box_bstrndup(ctx, vb, NULL, da->name, strlen(da->name), false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_vendor_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the vendor of an attribute reference
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_vendor(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 UNUSED xlat_ctx_t const *xctx,
				 request_t *request, fr_value_box_list_t *in)
{
	fr_pair_t		*vp;
	fr_dict_vendor_t const	*vendor;
	fr_value_box_t		*attr = fr_value_box_list_head(in);
	fr_value_box_t		*vb;

	if ((xlat_fmt_get_vp(&vp, request, attr->vb_strvalue) < 0) || !vp) return XLAT_ACTION_FAIL;

	vendor = fr_dict_vendor_by_da(vp->da);
	if (!vendor) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc_null(ctx));

	if (fr_value_box_bstrndup(ctx, vb, NULL, vendor->name, strlen(vendor->name), false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_vendor_num_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the vendor number of an attribute reference
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_vendor_num(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	fr_pair_t	*vp;
	fr_value_box_t	*attr = fr_value_box_list_head(in);
	fr_value_box_t	*vb;

	if ((xlat_fmt_get_vp(&vp, request, attr->vb_strvalue) < 0) || !vp) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_uint32(vb, NULL, fr_dict_vendor_num_by_da(vp->da), false);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_attr_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the attribute name of an attribute reference
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_attr(TALLOC_CTX *ctx, fr_dcursor_t *out,
			       UNUSED xlat_ctx_t const *xctx,
			       request_t *request, fr_value_box_list_t *in)
{
	fr_pair_t	*vp;
	fr_value_box_t	*attr = fr_value_box_list_head(in);
	fr_value_box_t	*vb;

	if ((xlat_fmt_get_vp(&vp, request, attr->vb_strvalue) < 0) || !vp) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc_null(ctx));

	if (fr_value_box_bstrndup(ctx, vb, NULL, vp->da->name, strlen(vp->da->name), false) < 0) {
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const xlat_attr_num_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the attribute number of an attribute reference
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_attr_num(TALLOC_CTX *ctx, fr_dcursor_t *out,
				   UNUSED xlat_ctx_t const *xctx,
				   request_t *request, fr_value_box_list_t *in)
{
	fr_pair_t	*vp;
	fr_value_box_t	*attr = fr_value_box_list_head(in);
	fr_value_box_t	*vb;

	if ((xlat_fmt_get_vp(&vp, request, attr->vb_strvalue) < 0) || !vp) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc_null(ctx));

	fr_value_box_uint32(vb, NULL, vp->da->attr, false);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

#define XLAT_REGISTER(_name, _func, _type, _args) \
if (unlikely(!(xlat = xlat_func_register(NULL, _name, _func, _type)))) return -1; \
xlat_func_args_set(xlat, _args)

static int mod_load(void)
{
	xlat_t	*xlat;

	XLAT_REGISTER("attr_by_num", xlat_dict_attr_by_num, FR_TYPE_STRING, xlat_dict_attr_by_num_args);
	XLAT_REGISTER("attr_by_oid", xlat_dict_attr_by_oid, FR_TYPE_STRING, xlat_dict_attr_by_oid_args);
	XLAT_REGISTER("vendor", xlat_vendor, FR_TYPE_STRING, xlat_vendor_args);
	XLAT_REGISTER("vendor_num", xlat_vendor_num, FR_TYPE_UINT32, xlat_vendor_num_args);
	XLAT_REGISTER("attr", xlat_attr, FR_TYPE_STRING, xlat_attr_args);
	XLAT_REGISTER("attr_num", xlat_attr_num, FR_TYPE_UINT32, xlat_attr_num_args);

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("attr_by_num");
	xlat_func_unregister("attr_by_oid");
	xlat_func_unregister("vendor");
	xlat_func_unregister("vendor_num");
	xlat_func_unregister("attr");
	xlat_func_unregister("attr_num");
}

extern module_rlm_t rlm_dict;
module_rlm_t rlm_dict = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "dict",
		.onload		= mod_load,
		.unload		= mod_unload
	}
};
