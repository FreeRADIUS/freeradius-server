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
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Xlat for %{attr_by_num:<number>}
 */
static ssize_t xlat_dict_attr_by_num(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
				     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				     REQUEST *request, char const *fmt)
{
	char			*q;
	fr_dict_t const		*dict = NULL;
	unsigned int		number;
	fr_dict_attr_t const	*da;

	*out = NULL;

	dict = fr_dict_internal;

	number = (unsigned int)strtoul(fmt, &q, 10);
	if ((q == fmt) || (*q != '\0')) {
		REDEBUG("Trailing garbage \"%s\" in attribute number string \"%s\"", q, fmt);
		return -1;
	}

	da = fr_dict_attr_child_by_num(fr_dict_root(dict), number);
	if (!da) {
		REDEBUG("No attribute found with number %u", number);
		return -1;
	}

	*out = talloc_typed_strdup(ctx, da->name);

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
	xlat_register(instance, "attr_by_num", xlat_dict_attr_by_num, NULL, NULL, 0, 0);

	return 0;
}

extern rad_module_t rlm_dict;
rad_module_t rlm_dict = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dict",
	.bootstrap	= mod_bootstrap,
};
