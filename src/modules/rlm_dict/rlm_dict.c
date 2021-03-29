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
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>

static xlat_arg_parser_t const xlat_dict_attr_by_num_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_UINT32 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Xlat for %(attr_by_num:\<number\>)
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_dict_attr_by_num(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
					  UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					  fr_value_box_list_t *in)
{
	fr_dict_attr_t const	*da;
	fr_value_box_t		*attr = fr_dlist_head(in);
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
static xlat_action_t xlat_dict_attr_by_oid(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
					   UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
					   fr_value_box_list_t *in)
{
	unsigned int		attr = 0;
	fr_dict_attr_t const	*parent = fr_dict_root(request->dict);
	fr_dict_attr_t const	*da;
	ssize_t			ret;
	fr_value_box_t		*attr_vb = fr_dlist_head(in);
	fr_value_box_t		*vb;

	ret = fr_dict_attr_by_oid_legacy(fr_dict_internal(), &parent, &attr, attr_vb->vb_strvalue);
	if (ret <= 0) {
		REMARKER(attr_vb->vb_strvalue, -(ret), "%s", fr_strerror());
		return XLAT_ACTION_FAIL;
	}

	da = fr_dict_attr_child_by_num(parent, attr);

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
static xlat_action_t xlat_vendor(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				 UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				 fr_value_box_list_t *in)
{
	fr_pair_t		*vp;
	fr_dict_vendor_t const	*vendor;
	fr_value_box_t		*attr = fr_dlist_head(in);
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
static xlat_action_t xlat_vendor_num(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				     UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			       	     fr_value_box_list_t *in)
{
	fr_pair_t	*vp;
	fr_value_box_t	*attr = fr_dlist_head(in);
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
static xlat_action_t xlat_attr(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
			       UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			       fr_value_box_list_t *in)
{
	fr_pair_t	*vp;
	fr_value_box_t	*attr = fr_dlist_head(in);
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
static xlat_action_t xlat_attr_num(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				   UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				   fr_value_box_list_t *in)
{
	fr_pair_t	*vp;
	fr_value_box_t	*attr = fr_dlist_head(in);
	fr_value_box_t	*vb;

	if ((xlat_fmt_get_vp(&vp, request, attr->vb_strvalue) < 0) || !vp) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc_null(ctx));

	fr_value_box_uint32(vb, NULL, vp->da->attr, false);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_bootstrap(void *instance, UNUSED CONF_SECTION *conf)
{
	xlat_t	*xlat;
	xlat = xlat_register(instance, "attr_by_num", xlat_dict_attr_by_num, false);
	xlat_func_args(xlat, xlat_dict_attr_by_num_args);
	xlat = xlat_register(instance, "attr_by_oid", xlat_dict_attr_by_oid, false);
	xlat_func_args(xlat, xlat_dict_attr_by_oid_args);
	xlat = xlat_register(instance, "vendor", xlat_vendor, false);
	xlat_func_args(xlat, xlat_vendor_args);
	xlat = xlat_register(instance, "vendor_num", xlat_vendor_num, false);
	xlat_func_args(xlat, xlat_vendor_num_args);
	xlat = xlat_register(instance, "attr", xlat_attr, false);
	xlat_func_args(xlat, xlat_attr_args);
	xlat = xlat_register(instance, "attr_num", xlat_attr_num, false);
	xlat_func_args(xlat, xlat_attr_num_args);

	return 0;
}

extern module_t rlm_dict;
module_t rlm_dict = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dict",
	.bootstrap	= mod_bootstrap,
};
