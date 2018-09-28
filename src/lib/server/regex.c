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
 * @file src/lib/server/regex.c
 * @brief Regular expression functions used by the server library.
 *
 * @copyright 2014  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#ifdef HAVE_REGEX

#define REQUEST_DATA_REGEX (0xadbeef00)

typedef struct {
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	regex_t		*preg;		//!< Compiled pattern.
#endif
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_POSIX)
	char const	*value;		//!< Original string.  Only needed for original
					///< libpcre, as we're forced to strdup the
					///< subject for libpcre2 in every instance.
#endif
	regmatch_t	*rxmatch;	//!< Match vectors.
	size_t		nmatch;		//!< Number of match vectors.
} regcapture_t;

/** Adds subcapture values to request data
 *
 * Allows use of %{n} expansions.
 *
 * @note If preg was runtime-compiled, it will be consumed and *preg will be set to NULL.
 * @note rxmatch will be consumed and *rxmatch will be set to NULL.
 * @note Their lifetimes will be bound to the match request data.
 *
 * @param[in] request		Current request.
 * @param[in,out] preg		Compiled pattern. May be set to NULL if
 *				reparented to the regcapture struct.
 * @param[in] value		The original value.
 * @param[in] len		Length of the original value.
 * @param[in,out] rxmatch	Pointers into value. May be set to NULL if
 *				reparented to the regcapture struct.
 * @param[in] nmatch		Sizeof rxmatch.
 */
void regex_sub_to_request(REQUEST *request, regex_t **preg,
#ifdef HAVE_REGEX_PCRE2
			  UNUSED char const *value,
			  UNUSED size_t len,
#else
			  char const *value,
			  size_t len,
#endif
			  regmatch_t **rxmatch, size_t nmatch)
{
	regcapture_t *old_rc, *new_rc;	/* lldb doesn't like bare new *sigh* */

	/*
	 *	Clear out old_rc matches
	 */
	old_rc = request_data_get(request, request, REQUEST_DATA_REGEX);
	if (old_rc) {
		DEBUG4("Clearing %zu matches", old_rc->nmatch);
		talloc_free(old_rc);
	} else {
		DEBUG4("No matches");
	}

	if (nmatch == 0) return;

	rad_assert(preg && *preg);
	rad_assert(rxmatch);

	DEBUG4("Adding %zu matches", nmatch);

	/*
	 *	Container struct for all the match data
	 */
	MEM(new_rc = talloc(request, regcapture_t));

	/*
	 *	Steal runtime pregs, leave precompiled ones
	 */
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	if (!(*preg)->precompiled) {
		new_rc->preg = talloc_steal(new_rc, *preg);
		*preg = NULL;
	} else {
		new_rc->preg = *preg;	/* Compiled on startup, will hopefully stick around */
	}
#endif

	/*
	 *	Steal match data
	 */
	new_rc->rxmatch = talloc_steal(new_rc, *rxmatch);
	*rxmatch = NULL;
	new_rc->nmatch = nmatch;

#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_POSIX)
	/*
	 *	Have to dup the subject
	 */
	new_rc->value = talloc_bstrndup(new_rc, value, len);
#endif

	request_data_talloc_add(request, request, REQUEST_DATA_REGEX, regcapture_t, new_rc, true, false, false);
}

#  if defined(HAVE_REGEX_PCRE2)
/** Extract a subcapture value from the request
 *
 * @note This is the PCRE variant of the function.
 *
 * @param[in] ctx	To allocate subcapture buffer in.
 * @param[out] out	Where to write the subcapture string.
 * @param[in] request	to extract.
 * @param[in] num	Subcapture index (0 for entire match).
 * @return
 *	- 0 on success.
 *	- -1 on notfound.
 */
int regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num)
{
	regcapture_t		*rc;
	char			*buff;
	size_t			len;
	int			ret;
	pcre2_match_data	*match_data;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return 1;
	}
	match_data = talloc_get_type_abort(*((pcre2_match_data **)rc->rxmatch), pcre2_match_data);

	ret = pcre2_substring_length_bynumber(match_data, num, &len);
	switch (ret) {
	case PCRE2_ERROR_NOMEMORY:
		MEM(NULL);
		/*
		 *	We can't really fall through, but GCC 7.3 is
		 *	too stupid to realise that we can never get
		 *	here despite _fr_exit_now being marked as
		 *	NEVER_RETURNS.
		 *
		 *	If we did anything else, compilers and static
		 *	analysis tools would probably complain about
		 *	code that could never be executed *sigh*.
		 */
		/* FALL-THROUGH */

	/*
	 *	Not finding a substring is fine
	 */
	case PCRE2_ERROR_NOSUBSTRING:
		RDEBUG4("%i/%zu Not found", num, rc->nmatch);
		*out = NULL;
		return -1;

	default:
		if (ret < 0) {
			*out = NULL;
			return -1;
		}

		MEM(buff = talloc_array(ctx, char, ++len));	/* +1 for \0, it'll get reset by pcre2_substring */
		pcre2_substring_copy_bynumber(match_data, num, (PCRE2_UCHAR *)buff, &len); /* can't error */

		RDEBUG4("%i/%zu Found: %pV (%zu)", num, rc->nmatch,
			fr_box_strvalue_buffer(buff), talloc_array_length(buff) - 1);

		*out = buff;
		break;
	}

	return 0;
}

/** Extract a named subcapture value from the request
 *
 * @note This is the PCRE variant of the function.
 *
 * @param[in] ctx	To allocate subcapture buffer in.
 * @param[out] out	Where to write the subcapture string.
 * @param[in] request	to extract.
 * @param[in] name	of subcapture.
 * @return
 *	- 0 on success.
 *	- -1 on notfound.
 */
int regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *name)
{
	regcapture_t		*rc;
	char			*buff;
	int			ret;
	size_t			len;
	pcre2_match_data	*match_data;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return 1;
	}
	match_data = talloc_get_type_abort(*((pcre2_match_data **)rc->rxmatch), pcre2_match_data);

	ret = pcre2_substring_length_byname(match_data, (PCRE2_UCHAR const *)name, &len);
	switch (ret) {
	case PCRE2_ERROR_NOMEMORY:
		MEM(NULL);
		/*
		 *	We can't really fall through, but GCC 7.3 is
		 *	too stupid to realise that we can never get
		 *	here despite _fr_exit_now being marked as
		 *	NEVER_RETURNS.
		 *
		 *	If we did anything else, compilers and static
		 *	analysis tools would probably complain about
		 *	code that could never be executed *sigh*.
		 */
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

		RDEBUG4("Found \"%s\": %pV (%zu)", name,
			fr_box_strvalue_buffer(buff), talloc_array_length(buff) - 1);

		*out = buff;
		break;
	}

	return 0;
}
#  elif defined(HAVE_REGEX_PCRE)
/** Extract a subcapture value from the request
 *
 * @note This is the PCRE variant of the function.
 *
 * @param[in] ctx	To allocate subcapture buffer in.
 * @param[out] out	Where to write the subcapture string.
 * @param[in] request	to extract.
 * @param[in] num	Subcapture index (0 for entire match).
 * @return
 *	- 0 on success.
 *	- -1 on notfound.
 */
int regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num)
{
	regcapture_t	*rc;
	char const	*p;
	int		ret;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return 1;
	}

	ret = pcre_get_substring(rc->value, (int *)rc->rxmatch, (int)rc->nmatch, num, &p);
	switch (ret) {
	case PCRE_ERROR_NOMEMORY:
		MEM(NULL);
		/*
		 *	We can't really fall through, but GCC 7.3 is
		 *	too stupid to realise that we can never get
		 *	here despite _fr_exit_now being marked as
		 *	NEVER_RETURNS.
		 *
		 *	If we did anything else, compilers and static
		 *	analysis tools would probably complain about
		 *	code that could never be executed *sigh*.
		 */
		/* FALL-THROUGH */

	/*
	 *	Not finding a substring is fine
	 */
	case PCRE_ERROR_NOSUBSTRING:
		RDEBUG4("%i/%zu Not found", num, rc->nmatch);
		*out = NULL;
		return -1;

	default:
		if (ret < 0) {
			*out = NULL;
			return -1;
		}

		talloc_set_type(p, char);
		p = talloc_steal(ctx, p);

		RDEBUG4("%i/%zu Found: %pV (%zu)", num, rc->nmatch,
			fr_box_strvalue_buffer(p), talloc_array_length(p) - 1);

		memcpy(out, &p, sizeof(*out));
		break;
	}

	return 0;
}

/** Extract a named subcapture value from the request
 *
 * @note This is the PCRE variant of the function.
 *
 * @param[in] ctx	To allocate subcapture buffer in.
 * @param[out] out	Where to write the subcapture string.
 * @param[in] request	to extract.
 * @param[in] name	of subcapture.
 * @return
 *	- 0 on success.
 *	- -1 on notfound.
 */
int regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, REQUEST *request, char const *name)
{
	regcapture_t	*rc;
	char const	*p;
	int		ret;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return 1;
	}

	ret = pcre_get_named_substring(rc->preg->compiled, rc->value,
				       (int *)rc->rxmatch, (int)rc->nmatch, name, &p);
	switch (ret) {
	case PCRE_ERROR_NOMEMORY:
		MEM(NULL);
		/*
		 *	We can't really fall through, but GCC 7.3 is
		 *	too stupid to realise that we can never get
		 *	here despite _fr_exit_now being marked as
		 *	NEVER_RETURNS.
		 *
		 *	If we did anything else, compilers and static
		 *	analysis tools would probably complain about
		 *	code that could never be executed *sigh*.
		 */
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
		 *	memory allocation and freeing talloc wrappers.
		 */
		talloc_set_type(p, char);
		talloc_steal(ctx, p);

		RDEBUG4("Found \"%s\": %pV (%zu)", name,
			fr_box_strvalue_buffer(p), talloc_array_length(p) - 1);

		memcpy(out, &p, sizeof(*out));

		break;
	}

	return 0;
}
#  else
/** Extract a subcapture value from the request
 *
 * @note This is the POSIX variant of the function.
 *
 * @param[in] ctx	To allocate subcapture buffer in.
 * @param[out] out	Where to write the subcapture string.
 * @param[in] request	to extract.
 * @param[in] num	Subcapture index (0 for entire match).
 * @return
 *	- 0 on success.
 *	- -1 on notfound.
 */
int regex_request_to_sub(TALLOC_CTX *ctx, char **out, REQUEST *request, uint32_t num)
{
	regcapture_t	*rc;
	char 		*buff;
	char const	*start;
	size_t		len;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}

	/*
	 *	Greater than our capture array
	 *
	 *	-1 means no value in this capture group.
	 */
	if ((num >= rc->nmatch) || (rc->rxmatch[num].rm_eo == -1) || (rc->rxmatch[num].rm_so == -1)) {
		RDEBUG4("%i/%zu Not found", num, rc->nmatch);
		*out = NULL;
		return -1;
	}

	/*
	 *	Sanity checks on the offsets
	 */
	rad_assert(rc->rxmatch[num].rm_eo <= (regoff_t)talloc_array_length(rc->value));
	rad_assert(rc->rxmatch[num].rm_so <= (regoff_t)talloc_array_length(rc->value));

	start = rc->value + rc->rxmatch[num].rm_so;
	len = rc->rxmatch[num].rm_eo - rc->rxmatch[num].rm_so;

	MEM(buff = talloc_bstrndup(ctx, start, len));
	RDEBUG4("%i/%zu Found: %pV (%zu)", num, rc->nmatch, fr_box_strvalue_buffer(buff), len);

	*out = buff;

	return 0;
}
#  endif
#endif
