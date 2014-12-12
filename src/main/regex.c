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

/*
 * $Id$
 *
 * @file regex.c
 * @brief Regular expression functions used by the server library.
 *
 * @copyright 2014  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_REGEX
#  ifdef HAVE_PCRE
/** Adds subcapture values to request data
 *
 * Allows use of %{n} expansions.
 *
 * @param request Current request.
 * @param value The original value.
 * @param rxmatch Pointers into value.
 * @param nmatch Sizeof rxmatch.
 */
void regex_sub_to_request(REQUEST *request, char const *value, regmatch_t rxmatch[], size_t nmatch)
{
	int i, old;
	char *p;
	int *ovector = (int *)rxmatch;

	/*
	 *	Clear out old matches
	 */
	old = (int)request_data_get(request, request, REQUEST_DATA_REGEX);
	RDEBUG4("Clearing %i previous subcapture values", old);
	for (i = 0; i < old; i++) {
		p = request_data_get(request, request, REQUEST_DATA_REGEX | (i + 1));
		if (!p) {
			RDEBUG4("%%{%i}: Empty", i);
			continue;
		}

		RDEBUG4("%%{%i}: Clearing old value \"%s\"", i, p);
		talloc_free(p);
	}

	/*
	 *	Add new %{0}, %{1}, etc.
	 */
	RDEBUG4("Storing %zu new subcapture values", nmatch);
	for (i = 0; i < (int)nmatch; i++) {
		char 	const *start;
		size_t	len;

		len = ovector[(2 * i) + 1] - ovector[2 * i];
		start = value + ovector[i * 2];

		/*
		 *	Using talloc for the buffers gives
		 *	consumers the length too.
		 */
		MEM(p = talloc_array(request, char, len + 1));
		memcpy(p, start, len);
		p[len] = '\0';

		RDEBUG4("%%{%i}: Inserting new value \"%s\"", i, p);
		/*
		 *	Copy substring, and add it to the request.
		 */
		request_data_add(request, request, REQUEST_DATA_REGEX | (i + 1), p, true);
	}

	if (nmatch > 0) request_data_add(request, request, REQUEST_DATA_REGEX, (void *)nmatch, false);
}
/*
 *	Wrapper functions for POSIX like, and extended regular
 *	expressions.  These use the system regex library.
 */
#  else
/** Adds subcapture values to request data
 *
 * Allows use of %{n} expansions.
 *
 * @param request Current request.
 * @param value The original value.
 * @param rxmatch Pointers into value.
 * @param nmatch Sizeof rxmatch.
 */
void regex_sub_to_request(REQUEST *request, char const *value, regmatch_t rxmatch[], size_t nmatch)
{
	int	i, old;
	char	*p;
	size_t	len;

	/*
	 *	Clear out old matches
	 */
	old = (int)request_data_get(request, request, REQUEST_DATA_REGEX);
	RDEBUG4("Clearing %i previous subcapture values", old);
	for (i = 0; i < old; i++) {
		p = request_data_get(request, request, REQUEST_DATA_REGEX | (i + 1));
		if (!p) {
			RDEBUG4("%%{%i}: Empty", i);
			continue;
		}

		RDEBUG4("%%{%i}: Clearing old value \"%s\"", i, p);
		talloc_free(p);
	}

	/*
	 *	Add new %{0}, %{1}, etc.
	 */
	RDEBUG4("Storing %zu new subcapture values", nmatch);
	for (i = 0; i < (int)nmatch; i++) {
		/*
		 *	Empty capture
		 */
		if (rxmatch[i].rm_eo == -1) continue;

		/*
		 *	Using talloc for the buffers gives
		 *	consumers the length too.
		 */
		len = rxmatch[i].rm_eo - rxmatch[i].rm_so;
		p = talloc_array(request, char, len + 1);
		if (!p) {
			ERROR("Out of memory");
			return;
		}

		memcpy(p, value + rxmatch[i].rm_so, len);
		p[len] = '\0';

		RDEBUG4("%%{%i}: Inserting new value \"%s\"", i, p);
		/*
		 *	Copy substring, and add it to
		 *	the request.
		 *
		 *	Note that we don't check
		 *	for out of memory, which is
		 *	the only error we can get...
		 */
		request_data_add(request, request, REQUEST_DATA_REGEX | (i + 1), p, true);
	}

	if (nmatch > 0) request_data_add(request, request, REQUEST_DATA_REGEX, (void *)nmatch, false);
}
#  endif
#endif
