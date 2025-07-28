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
 * @file main/regex.c
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
#if defined(HAVE_PCRE) || defined(HAVE_PCRE2)
	regex_t		*preg;		//!< Compiled pattern.
#endif
	char const	*value;		//!< Original string.
	regmatch_t	*rxmatch;	//!< Match vectors.
	size_t		nmatch;		//!< Number of match vectors.
} regcapture_t;

/** Adds subcapture values to request data
 *
 * Allows use of %{n} expansions.
 *
 * @note After calling regex_sub_to_request *preg may no longer be valid and
 *	should be passed to talloc_free.
 *
 * @param request Current request.
 * @param preg Compiled pattern. May be set to NULL if reparented to the regcapture struct.
 * @param value The original value.
 * @param rxmatch Pointers into value.
 * @param nmatch Sizeof rxmatch.
 */
void regex_sub_to_request(REQUEST *request, regex_t **preg, char const *value, size_t len,
			  regmatch_t rxmatch[], size_t nmatch)
{
	regcapture_t *old_sc, *new_sc;	/* lldb doesn't like new *sigh* */
	char *p;

	/*
	 *	Clear out old_sc matches
	 */
	old_sc = request_data_get(request, request, REQUEST_DATA_REGEX);
	if (old_sc) {
		DEBUG4("Clearing %zu old matches", old_sc->nmatch);
		talloc_free(old_sc);
	} else {
		DEBUG4("No old matches");
	}

	if (nmatch == 0) return;

	rad_assert(preg && *preg);
	rad_assert(rxmatch);

	DEBUG4("Adding %zu matches", nmatch);

	/*
	 *	Add new_sc matches
	 */
	MEM(new_sc = talloc(request, regcapture_t));

#ifdef HAVE_PCRE2
	new_sc->rxmatch = talloc_steal(new_sc, rxmatch);
#else
	MEM(new_sc->rxmatch = talloc_memdup(new_sc, rxmatch, sizeof(rxmatch[0]) * nmatch));
	talloc_set_type(new_sc->rxmatch, regmatch_t[]);
#endif

	MEM(p = talloc_array(new_sc, char, len + 1));
	memcpy(p, value, len);
	p[len] = '\0';
	new_sc->value = p;
	new_sc->nmatch = nmatch;

#if defined(HAVE_PCRE) || defined(HAVE_PCRE2)
	if (!(*preg)->precompiled) {
		new_sc->preg = talloc_steal(new_sc, *preg);
		*preg = NULL;
	} else {
		new_sc->preg = *preg;
	}
#endif

	request_data_add(request, request, REQUEST_DATA_REGEX, new_sc, true);
}

#  ifdef HAVE_PCRE2
/** Extract a subcapture value from the request
 *
 * @note This is the PCRE2 variant of the function.
 *
 * @param ctx To allocate subcapture buffer in.
 * @param out Where to write the subcapture string.
 * @param request to extract.
 * @param num Subcapture index (0 for entire match).
 * @return 0 on success, -1 on notfound.
 */
int regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num)
{
	regcapture_t		*cap;
	char			*buff;
	int			ret;
	size_t			len;
	pcre2_match_data	*match_data;

	cap = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!cap) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}
	match_data = talloc_get_type_abort(cap->rxmatch->match_data, pcre2_match_data);

	ret = pcre2_substring_length_bynumber(match_data, num, &len);
	switch (ret) {
	case PCRE2_ERROR_NOMEMORY:
		MEM(NULL);
		/* FALL-THROUGH */

	/*
	 *	Not finding a substring is fine
	 */
	case PCRE2_ERROR_NOSUBSTRING:
		RDEBUG4("%i/%zu Not found", num, cap->nmatch);
		*out = NULL;
		return -1;

	default:
		if (ret < 0) {
			*out = NULL;
			return -1;
		}

		MEM(buff = talloc_array(ctx, char, ++len));	/* +1 for \0, it'll get reset by pcre2_substring */
		pcre2_substring_copy_bynumber(match_data, num, (PCRE2_UCHAR *)buff, &len); /* can't error */

		memcpy(out, &buff, sizeof(*out));

		RDEBUG4("%i/%zu Found: %s (%zu)", num, cap->nmatch, buff, talloc_array_length(buff));

		return 0;
	}
}

/** Extract a named subcapture value from the request
 *
 * @note This is the PCRE2 variant of the function.
 *
 * @param ctx To allocate subcapture buffer in.
 * @param out Where to write the subcapture string.
 * @param request to extract.
 * @param name of subcapture.
 * @return 0 on success, -1 on notfound.
 */
int regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *name)
{
	regcapture_t		*cap;
	char			*buff;
	int			ret;
	size_t			len;
	pcre2_match_data	*match_data;

	cap = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!cap) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}
	match_data = talloc_get_type_abort(cap->rxmatch->match_data, pcre2_match_data);

	ret = pcre2_substring_length_byname(match_data, (PCRE2_UCHAR const *)name, &len);
	switch (ret) {
	case PCRE2_ERROR_NOMEMORY:
		MEM(NULL);
		/* FALL-THROUGH */

	/*
	 *	Not finding a substring is fine
	 */
	case PCRE2_ERROR_NOSUBSTRING:
		RDEBUG4("No named capture group \"%s\"", name);
		*out = NULL;
		return -1;

	default:
		if (ret < 0) {
			*out = NULL;
			return -1;
		}

		MEM(buff = talloc_array(ctx, char, ++len));	/* +1 for \0, it'll get reset by pcre2_substring */
		pcre2_substring_copy_byname(match_data, (PCRE2_UCHAR const *)name, (PCRE2_UCHAR *)buff, &len); /* can't error */

		memcpy(out, &buff, sizeof(*out));

		RDEBUG4("Found \"%s\": %s (%zu)", name, buff, talloc_array_length(buff));

		return 0;
	}
}
#  elif defined(HAVE_PCRE)
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
		return -1;
	}

	ret = pcre_get_substring(cap->value, (int *)cap->rxmatch, (int)cap->nmatch, num, &p);
	switch (ret) {
	case PCRE_ERROR_NOMEMORY:
		MEM(NULL);
		/* FALL-THROUGH */

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

/** Extract a named subcapture value from the request
 *
 * @note This is the PCRE variant of the function.
 *
 * @param ctx To allocate subcapture buffer in.
 * @param out Where to write the subcapture string.
 * @param request to extract.
 * @param name of subcapture.
 * @return 0 on success, -1 on notfound.
 */
int regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *name)
{
	regcapture_t *cap;
	char const *p;
	int ret;

	cap = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!cap) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}

	ret = pcre_get_named_substring(cap->preg->compiled, cap->value,
				       (int *)cap->rxmatch, (int)cap->nmatch, name, &p);
	switch (ret) {
	case PCRE_ERROR_NOMEMORY:
		MEM(NULL);
		/* FALL-THROUGH */

	/*
	 *	Not finding a substring is fine
	 */
	case PCRE_ERROR_NOSUBSTRING:
		RDEBUG4("No named capture group \"%s\"", name);
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

		RDEBUG4("Found \"%s\": %s (%zu)", name, p, talloc_array_length(p));

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
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}

	/*
	 *	Greater than our capture array
	 *
	 *	-1 means no value in this capture group.
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
