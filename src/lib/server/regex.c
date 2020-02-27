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
 * @copyright 2014 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/regex.h>
#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/server/rad_assert.h>

#ifdef HAVE_REGEX

#define REQUEST_DATA_REGEX (0xadbeef00)

typedef struct {
#if defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	regex_t		*preg;		//!< Compiled pattern.
#endif
	fr_regmatch_t	*regmatch;	//!< Match vectors.
} fr_regcapture_t;

/** Adds subcapture values to request data
 *
 * Allows use of %{n} expansions.
 *
 * @note If preg was runtime-compiled, it will be consumed and *preg will be set to NULL.
 * @note regmatch will be consumed and *regmatch will be set to NULL.
 * @note Their lifetimes will be bound to the match request data.
 *
 * @param[in] request		Current request.
 * @param[in,out] preg		Compiled pattern. May be set to NULL if
 *				reparented to the regcapture struct.
 * @param[in,out] regmatch	Pointers into value. May be set to NULL if
 *				reparented to the regcapture struct.
 */
void regex_sub_to_request(REQUEST *request, regex_t **preg, fr_regmatch_t **regmatch)
{
	fr_regcapture_t *old_rc, *new_rc;	/* lldb doesn't like bare new *sigh* */

	/*
	 *	Clear out old_rc matches
	 */
	old_rc = request_data_get(request, request, REQUEST_DATA_REGEX);
	if (old_rc) {
		DEBUG4("Clearing %zu matches", old_rc->regmatch->used);
		talloc_free(old_rc);
	} else {
		DEBUG4("No matches");
	}

	if (!regmatch || ((*regmatch)->used == 0)) return;

	rad_assert(preg && *preg);
	rad_assert(regmatch);

	DEBUG4("Adding %zu matches", (*regmatch)->used);

	/*
	 *	Container struct for all the match data
	 */
	MEM(new_rc = talloc(request, fr_regcapture_t));

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
	new_rc->regmatch = talloc_steal(new_rc, *regmatch);
	*regmatch = NULL;

	request_data_talloc_add(request, request, REQUEST_DATA_REGEX, fr_regcapture_t, new_rc, true, false, false);
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
	fr_regcapture_t		*rc;
	char			*buff;
	size_t			len;
	int			ret;
	pcre2_match_data	*match_data;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}
	match_data = talloc_get_type_abort(rc->regmatch->match_data, pcre2_match_data);

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
		RDEBUG4("%i/%zu Not found", num + 1, rc->regmatch->used);
		*out = NULL;
		return -1;

	default:
		if (ret < 0) {
			*out = NULL;
			return -1;
		}

		MEM(buff = talloc_array(ctx, char, ++len));	/* +1 for \0, it'll get reset by pcre2_substring */
		pcre2_substring_copy_bynumber(match_data, num, (PCRE2_UCHAR *)buff, &len); /* can't error */

		RDEBUG4("%i/%zu Found: %pV (%zu)", num + 1, rc->regmatch->used,
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
	fr_regcapture_t		*rc;
	char			*buff;
	int			ret;
	size_t			len;
	pcre2_match_data	*match_data;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}
	match_data = rc->regmatch->match_data;

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
	fr_regcapture_t	*rc;
	char const	*p;
	int		ret;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}

	ret = pcre_get_substring(rc->regmatch->subject,
				 (int *)rc->regmatch->match_data, (int)rc->regmatch->used, num, &p);
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
		RDEBUG4("%i/%zu Not found", num + 1, rc->regmatch->used);
		*out = NULL;
		return -1;

	default:
		if (ret < 0) {
			*out = NULL;
			return -1;
		}

		talloc_set_type(p, char);
		p = talloc_steal(ctx, p);

		RDEBUG4("%i/%zu Found: %pV (%zu)", num + 1, rc->regmatch->used,
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
	fr_regcapture_t	*rc;
	char const	*p;
	int		ret;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}

	ret = pcre_get_named_substring(rc->preg->compiled, rc->regmatch->subject,
				       (int *)rc->regmatch->match_data, (int)rc->regmatch->used, name, &p);
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
	fr_regcapture_t	*rc;
	char 		*buff;
	char const	*start;
	size_t		len;
	regmatch_t	*match_data;

	rc = request_data_reference(request, request, REQUEST_DATA_REGEX);
	if (!rc) {
		RDEBUG4("No subcapture data found");
		*out = NULL;
		return -1;
	}
	match_data = rc->regmatch->match_data;

	/*
	 *	Greater than our capture array
	 *
	 *	-1 means no value in this capture group.
	 */
	if ((num >= rc->regmatch->used) || (match_data[num].rm_eo == -1) || (match_data[num].rm_so == -1)) {
		RDEBUG4("%i/%zu Not found", num + 1, rc->regmatch->used);
		*out = NULL;
		return -1;
	}

	/*
	 *	Sanity checks on the offsets
	 */
	rad_assert(match_data[num].rm_eo <= (regoff_t)talloc_array_length(rc->regmatch->subject));
	rad_assert(match_data[num].rm_so <= (regoff_t)talloc_array_length(rc->regmatch->subject));

	start = rc->regmatch->subject + match_data[num].rm_so;
	len = match_data[num].rm_eo - match_data[num].rm_so;

	MEM(buff = talloc_bstrndup(ctx, start, len));
	RDEBUG4("%i/%zu Found: %pV (%zu)", num + 1, rc->regmatch->used, fr_box_strvalue_buffer(buff), len);

	*out = buff;

	return 0;
}
#  endif
#endif
