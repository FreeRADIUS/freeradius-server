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
 * @file build/version.c
 * @brief Version comparison functions to avoid horrible builtins
 *
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <gnumake.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"

/*
 *	The only exported symbol
 */
int version_gmk_setup(void);

/*
 * GNU make insists on this in a loadable object.
 */
extern int plugin_is_GPL_compatible;
int plugin_is_GPL_compatible;

#define IS_SEP(_c) \
	((_c == '.') || (_c == '-') || (_c == '_') || (_c == '\0'))

#define FIND_SEP(_out, _str) \
do { \
	_out = strchr(_str, '.'); \
	if (!_out) _out = strchr(_str, '-'); \
	if (!_out) _out = strchr(_str, '_'); \
	if (!_out) _out = _str + strlen(_str); \
} while(0);

static inline __attribute__((always_inline)) char *bool_to_str(bool res)
{
	char *str;

	if (res) {
		str = gmk_alloc(sizeof("true") - 1);
		strcpy(str, "true");
		return str;
	}

	str = gmk_alloc(sizeof("false") - 1);
	strcpy(str, "false");
	return str;
}

static int make_version_cmp(bool *err,
			    __attribute__((unused)) char const *nm,
			    __attribute__((unused)) unsigned int argc,
			    char **argv)
{
	char	*a = argv[0];
	char	*b = argv[1];
	char	*a_end = a + strlen(a), *b_end = b + strlen(b);
	char	*a_q;
	char	*b_q;

	*err = false;

	while ((a < a_end) && (b < b_end)) {
		unsigned long	a_num, b_num;
		size_t		a_len = 0, b_len;
		int		ret;
		bool		a_str = false;

		a_num = strtoul(a, &a_q, 10);
		if (a == a_q) {
			FIND_SEP(a_q, a);
			a_len = a_q - a;
			a_str = true;
		}

		b_num = strtoul(a, &b_q, 10);
		/*
		 *	A and B are both strings
		 */
		if (b == b_q) {
			if (!a_str) {
				ERROR("Can't compare string component to numeric component");
			error:
				*err = true;
				return 0;
			}

			FIND_SEP(b_q, b);
			b_len = b_q - b;

			if (a_len != b_len) {
				ERROR("Version component length doesn't match "
				      "\"%s\" (%zu) vs \"%s\" (%zu)", a, a_len, b, b_len);
				goto error;
			}

			/*
			 *	Probably need to do something
			 *	smarter here like compare known
			 *      strings like "rel" and "git"
			 */
			ret = strncmp(a, b, b_len);
			if (ret != 0) return ret;

			a = a_q;
			b = b_q;
		/*
		 *	A was a number but B was a string.
		 */
		} else if (a_str) {
			ERROR("Can't compare numeric component to string component");
			goto error;

		/*
		 *	A and B are both numbers.
		 */
		} else {
			ret = (a_num > b_num) - (a_num < b_num);
			if (ret != 0) return ret;
		}

		if (!IS_SEP(*a)) {
			ERROR("Missing version component separator \"%s\"", a);
			goto error;
		}

		if (!IS_SEP(*b)) {
			ERROR("Missing version component separator \"%s\"", b);
			goto error;
		}

		a++;
		b++;
	}

	if ((a < a_end) || (b < b_end)) {
		ERROR("Mismatched version string length");
		goto error;
	}

	return 0;
}

static char *make_version_gt(char const *nm, unsigned int argc, char **argv)
{
	bool	err = false;
	bool	res;

	res = (make_version_cmp(&err, nm, argc, argv) > 0);
	if (err) return NULL;

	return bool_to_str(res);
}

static char *make_version_lt(char const *nm, unsigned int argc, char **argv)
{
	bool	err = false;
	bool	res;

	res = (make_version_cmp(&err, nm, argc, argv) < 0);
	if (err) return NULL;

	return bool_to_str(res);
}

static char *make_version_eq(char const *nm, unsigned int argc, char **argv)
{
	bool	err = false;
	bool	res;

	res = (make_version_cmp(&err, nm, argc, argv) == 0);
	if (err) return NULL;

	return bool_to_str(res);
}
int version_gmk_setup(void)
{
	gmk_add_function("version_gt", &make_version_gt, 2, 2, 0); /* min 1, max 1, please expand the input string */
	gmk_add_function("version_lt", &make_version_lt, 2, 2, 0); /* min 1, max 1, please expand the input string */
	gmk_add_function("version_eq", &make_version_eq, 2, 2, 0); /* min 1, max 1, please expand the input string */

	return 1;
}
