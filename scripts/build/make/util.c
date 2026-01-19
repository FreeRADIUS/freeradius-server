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
 * @file build/make/util.c
 * @brief Version comparison functions to avoid horrible builtins
 *
 * @copyright 2023 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <gnumake.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "log.h"

/*
 *	The only exported symbol
 */
int util_gmk_setup(void);

/*
 * GNU make insists on this in a loadable object.
 */
extern int plugin_is_GPL_compatible;
int plugin_is_GPL_compatible;

static char *make_tolower(__attribute__((unused)) char const *nm, __attribute__((unused)) unsigned int argc, char **argv)
{
	size_t	len = strlen(argv[0]);
	char	*out = gmk_alloc(len + 1);
	int	i;

	for (i = 0; i < len; i++) out[i] = tolower(argv[0][i]);
	out[i] = '\0';

	return out;
}

static char *make_toupper(__attribute__((unused)) char const *nm, __attribute__((unused)) unsigned int argc, char **argv)
{
	size_t	len = strlen(argv[0]);
	char	*out = gmk_alloc(len + 1);
	int	i;

	for (i = 0; i < len; i++) out[i] = toupper(argv[0][i]);
	out[i] = '\0';

	return out;
}

int util_gmk_setup(void)
{
	gmk_add_function("tolower", &make_tolower, 1, 1, 0); /* min 1, max 1, please expand the input string */
	gmk_add_function("toupper", &make_toupper, 1, 1, 0); /* min 1, max 1, please expand the input string */

	return 1;
}
