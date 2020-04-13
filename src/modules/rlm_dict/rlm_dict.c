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

/** Xlat for %{attr_by_num:\<number\>}
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_dict_attr_by_num(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
				     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				     REQUEST *request, char const *fmt)
{
	char			*q;
	unsigned int		number;
	fr_dict_attr_t const	*da;

	*out = NULL;

	number = (unsigned int)strtoul(fmt, &q, 10);
	if ((q == fmt) || (*q != '\0')) {
		REDEBUG("Trailing garbage \"%s\" in attribute number string \"%s\"", q, fmt);
		return -1;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(request->dict), number);
	if (!da) {
		REDEBUG("No attribute found with number %u", number);
		return -1;
	}

	*out = talloc_typed_strdup(ctx, da->name);

	return talloc_array_length(*out) - 1;
}

/** Xlat for %{attr_by_oid:\<oid\>}
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_dict_attr_by_oid(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
				     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				     REQUEST *request, char const *fmt)
{
	unsigned int		attr = 0;
	fr_dict_attr_t const	*parent = fr_dict_root(request->dict);
	fr_dict_attr_t const	*da;
	ssize_t		ret;

	ret = fr_dict_attr_by_oid(fr_dict_internal(), &parent, &attr, fmt);
	if (ret <= 0) {
		REMARKER(fmt, -(ret), "%s", fr_strerror());
		return ret;
	}

	da = fr_dict_attr_child_by_num(parent, attr);

	*out = talloc_typed_strdup(ctx, da->name);
	return talloc_array_length(*out) - 1;
}


/** Return the vendor of an attribute reference
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_vendor(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;
	fr_dict_vendor_t const *vendor;

	fr_skip_whitespace(fmt);

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	vendor = fr_dict_vendor_by_da(vp->da);
	if (!vendor) return 0;

	*out = talloc_typed_strdup(ctx, vendor->name);
	return talloc_array_length(*out) - 1;
}

/** Return the vendor number of an attribute reference
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_vendor_num(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			       UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			       REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	fr_skip_whitespace(fmt);

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	*out = talloc_typed_asprintf(ctx, "%i", fr_dict_vendor_num_by_da(vp->da));
	return talloc_array_length(*out) - 1;
}

/** Return the attribute name of an attribute reference
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_attr(TALLOC_CTX *ctx, char **out, size_t outlen,
			 UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			 REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	fr_skip_whitespace(fmt);

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;
	strlcpy(*out, vp->da->name, outlen);

	*out = talloc_typed_strdup(ctx, vp->da->name);
	return talloc_array_length(*out) - 1;
}

/** Return the attribute number of an attribute reference
 *
 * @ingroup xlat_functions
 */
static ssize_t xlat_attr_num(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
			     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			     REQUEST *request, char const *fmt)
{
	VALUE_PAIR *vp;

	fr_skip_whitespace(fmt);

	if ((xlat_fmt_get_vp(&vp, request, fmt) < 0) || !vp) return 0;

	*out = talloc_typed_asprintf(ctx, "%i", vp->da->attr);
	return talloc_array_length(*out) - 1;
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
	xlat_register(instance, "attr_by_num", xlat_dict_attr_by_num, NULL, NULL, 0, 0, true);
	xlat_register(instance, "attr_by_oid", xlat_dict_attr_by_oid, NULL, NULL, 0, 0, true);
	xlat_register(instance, "vendor", xlat_vendor, NULL, NULL, 0, 0, true);
	xlat_register(instance, "vendor_num", xlat_vendor_num, NULL, NULL, 0, 0, true);
	xlat_register(instance, "attr", xlat_attr, NULL, NULL, 0, 0, true);
	xlat_register(instance, "attr_num", xlat_attr_num, NULL, NULL, 0, 0, true);

	return 0;
}

extern module_t rlm_dict;
module_t rlm_dict = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dict",
	.bootstrap	= mod_bootstrap,
};
