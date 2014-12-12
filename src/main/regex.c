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

#define REQUEST_DATA_REGEX (0xadbeef00)

typedef struct regcapture {
	regex_t		*preg;		//!< Compiled pattern.
	char const	*value;		//!< Original string.
	regmatch_t	*rxmatch;	//!< Match vectors.
	size_t		nmatch;		//!< Number of match vectors.
} regcapture_t;

/** Adds subcapture values to request data
 *
 * Allows use of %{n} expansions.
 *
 * @param request Current request.
 * @param value The original value.
 * @param rxmatch Pointers into value.
 * @param nmatch Sizeof rxmatch.
 */
void regex_sub_to_request(REQUEST *request, char const *value, size_t len, regmatch_t rxmatch[], size_t nmatch)
{
	regcapture_t *old, *new;
	char *p;

	/*
	 *	Clear out old matches
	 */
	old = request_data_get(request, request, REQUEST_DATA_REGEX);
	if (old) {
		RDEBUG4("Clearing %zu old matches", old->nmatch);
		talloc_free(old);
	} else {
		RDEBUG4("No old matches");
	}

	if (nmatch == 0) return;

	rad_assert(rxmatch);

	RDEBUG4("Adding %zu new matches", nmatch);
	/*
	 *	Add new matches
	 */
	MEM(new = talloc(request, regcapture_t));

	MEM(new->rxmatch = talloc_memdup(new, rxmatch, sizeof(rxmatch[0]) * nmatch));
	talloc_set_type(new->rxmatch, regmatch_t *);

	MEM(p = talloc_array(new, char, len + 1));
	memcpy(p, value, len);
	p[len] = '\0';
	new->value = p;

	new->nmatch = nmatch;

	request_data_add(request, request, REQUEST_DATA_REGEX, new, true);
}

#  ifdef HAVE_PCRE
/** Extract a subcapture value from the request
 *
 * @note This is the PCRE variant of the function.
 *
 * @param ctx To allocate subcapture buffer in.
 * @param out Where to write the subcapture string.
 * @param request to extract.
 * @param num Subcapture index (0 for entire match).
 * @return 0 on success, -1 on notfound.
 */
int regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num)
{
	regcapture_t *cap;
	char const *p;
	int ret;

	cap = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!cap) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return 1;
	}

	ret = pcre_get_substring(cap->value, (int *)cap->rxmatch, (int)cap->nmatch, num, &p);
	switch (ret) {
	case PCRE_ERROR_NOMEMORY:
		MEM(NULL);

	/*
	 *	Not finding a substring is fine
	 */
	case PCRE_ERROR_NOSUBSTRING:
		RDEBUG4("%i/%zu Not found", num, cap->nmatch);
		*out = NULL;
		return -1;

	default:
		if (ret < 0) {
			*out = NULL;
			return -1;
		}

		/*
		 *	Check libpcre really is using our overloaded
		 *	malloc/free talloc wrappers.
		 */
		p = (char *)talloc_get_type_abort(p, uint8_t);
		talloc_set_type(p, char *);
		talloc_steal(ctx, p);
		memcpy(out, &p, sizeof(*out));

		RDEBUG4("%i/%zu Found: %s (%zu)", num, cap->nmatch, p, talloc_array_length(p));

		return 0;
	}
}
#  else
/** Extract a subcapture value from the request
 *
 * @note This is the POSIX variant of the function.
 *
 * @param ctx To allocate subcapture buffer in.
 * @param out Where to write the subcapture string.
 * @param request to extract.
 * @param num Subcapture index (0 for entire match).
 * @return 0 on success, -1 on notfound.
 */
int regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num)
{
	regcapture_t	*cap;
	char 		*p;
	char const	*start;
	size_t		len;

	cap = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!cap) {
		RDEBUG4("No subcapture data found", num);
		*out = NULL;
		return -1;
	}

	/*
	 *	Greater than our capture array
	 */
	if ((num >= cap->nmatch) || (cap->rxmatch[num].rm_eo == -1) || (cap->rxmatch[num].rm_so == -1)) {
		RDEBUG4("%i/%zu Not found", num, cap->nmatch);
		*out = NULL;
		return -1;
	}

	/*
	 *	Sanity checks on the offsets
	 */
	rad_assert(cap->rxmatch[num].rm_eo <= (regoff_t)talloc_array_length(cap->value));
	rad_assert(cap->rxmatch[num].rm_so <= (regoff_t)talloc_array_length(cap->value));

	start = cap->value + cap->rxmatch[num].rm_so;
	len = cap->rxmatch[num].rm_eo - cap->rxmatch[num].rm_so;

	RDEBUG4("%i/%zu Found: %.*s (%zu)", num, cap->nmatch, (int)len, start, len);
	MEM(p = talloc_array(ctx, char, len + 1));
	memcpy(p, start, len);
	p[len] = '\0';

	*out = p;

	return 0;
}
#  endif
#endif
