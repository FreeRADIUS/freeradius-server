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
 * @file lib/regex.c
 * @brief regex abstraction functions
 *
 * @copyright 2014  The FreeRADIUS server project
 * @copyright 2014  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

#ifdef HAVE_REGEX
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/regex.h>

/*
 *	Wrapper functions for libpcre2. Much more powerful, and guaranteed
 *	to be binary safe for both patterns and subjects but require
 *	libpcre2.
 */
#  ifdef HAVE_PCRE2
/** Free regex_t structure
 *
 * Calls libpcre specific free functions for the expression and study.
 *
 * @param preg to free.
 */
static int _regex_free(regex_t *preg)
{
	if (preg->compiled) {
		pcre2_code_free(preg->compiled);
		preg->compiled = NULL;
	}

	return 0;
}

/** Talloc wrapper for pcre2 memory allocation
 *
 * @param[in] to_alloc		How many bytes to alloc.
 * @param[in] uctx		UNUSED.
 */
static void *_pcre2_talloc(PCRE2_SIZE to_alloc, UNUSED void *uctx)
{
	return talloc_array(NULL, uint8_t, to_alloc);
}

/** Talloc wrapper for pcre2 memory freeing
 *
 * @param[in] to_free		Memory to free.
 * @param[in] uctx		UNUSED.
 */
static void _pcre2_talloc_free(void *to_free, UNUSED void *uctx)
{
	talloc_free(to_free);
}

/*
 *	A PCRE2 general context used to point to our custom alloc / free functions
 */
static pcre2_general_context	*_pcre2_gcontext = NULL;

int fr_pcre2_gcontext_setup(void)
{
	_pcre2_gcontext = pcre2_general_context_create(_pcre2_talloc, _pcre2_talloc_free, NULL);
	if (!_pcre2_gcontext) return -1;
	return 1;
}

void fr_pcre2_gcontext_free(void)
{
	pcre2_general_context_free(_pcre2_gcontext);
}

/** Wrapper around pcre_compile
 *
 * Allows the rest of the code to do compilations using one function signature.
 *
 * @note Compiled expression must be freed with talloc_free.
 *
 * @param out Where to write out a pointer to the structure containing the compiled expression.
 * @param pattern to compile.
 * @param len of pattern.
 * @param ignore_case whether to do case insensitive matching.
 * @param multiline If true $ matches newlines.
 * @param subcaptures Whether to compile the regular expression to store subcapture
 *	data.
 * @param runtime If false run the pattern through the PCRE JIT to convert it to machine code.
 *	This trades startup time (longer) for runtime performance (better).
 * @return >= 1 on success, <= 0 on error. Negative value is offset of parse error.
 */
ssize_t regex_compile(TALLOC_CTX *ctx, regex_t **out, char const *pattern, size_t len,
		      bool ignore_case, bool multiline, bool subcaptures, bool runtime)
{
	int		ret;
	PCRE2_SIZE	offset;
	int		cflags = 0;
	regex_t		*preg;
#ifdef PCRE2_CONFIG_JIT
	static bool	setup = false;
	static bool	do_jit = false;

	if (!setup) {
		pcre2_config(PCRE2_CONFIG_JIT, &do_jit);
		setup = true;
	}
#endif

	*out = NULL;

	if (len == 0) {
		fr_strerror_printf("Empty expression");
		return 0;
	}

	if (ignore_case) cflags |= PCRE2_CASELESS;
	if (multiline) cflags |= PCRE2_MULTILINE;
	if (!subcaptures) cflags |= PCRE2_NO_AUTO_CAPTURE;

	preg = talloc_zero(ctx, regex_t);
	talloc_set_destructor(preg, _regex_free);

	preg->compiled = pcre2_compile((PCRE2_SPTR8)pattern, len, cflags, &ret, &offset, NULL);
	if (!preg->compiled) {
		PCRE2_UCHAR errbuff[128];

		pcre2_get_error_message(ret, errbuff, sizeof(errbuff));
		fr_strerror_printf("%s", (char *)errbuff);
		talloc_free(preg);

		return -(ssize_t)offset;
	}
	if (!runtime) {
		preg->precompiled = true;

#ifdef PCRE2_CONFIG_JIT
		/*
		 *	This is expensive, so only do it for
		 *	expressions that are going to be
		 *	evaluated repeatedly.
		 */
		if (do_jit) do {
			ret = pcre2_jit_compile(preg->compiled, PCRE2_JIT_COMPLETE);
			if (ret < 0) {
				PCRE2_UCHAR errbuff[128];

				/*
				 *	PCRE can do JIT, but this UID
				 *	cannot allocate executable
				 *	memory.  Stop trying to JIT things.
				 */
				if (ret == PCRE2_ERROR_NOMEMORY) {
					do_jit = false;
					break;
				}

				pcre2_get_error_message(ret, errbuff, sizeof(errbuff));
				fr_strerror_printf("Pattern JIT failed: %s", (char *)errbuff);
				talloc_free(preg);

				return 0;
			}
			preg->jitd = true;
		} while (0);
#endif
	}

	*out = preg;

	return len;
}

/** Wrapper around pcre2_match
 *
 * @param preg The compiled expression.
 * @param subject to match.
 * @param len Length of subject.
 * @param pmatch Array of match pointers.
 * @param nmatch How big the match array is. Updated to number of matches.
 * @return -1 on error, 0 on no match, 1 on match.
 */
int regex_exec(regex_t *preg, char const *subject, size_t len, regmatch_t *pmatch, size_t *nmatch)
{
	int			ret;
	uint32_t		options = 0;
	bool			dup_subject = true;
	char			*our_subject = NULL;
	pcre2_match_data	*match_data;

	/*
	 *	PCRE_NO_AUTO_CAPTURE is a compile time only flag,
	 *	and can't be passed here.
	 *	We rely on the fact that matches has been set to
	 *	0 as a hint that no subcapture data should be
	 *	generated.
	 */
	if (!pmatch || !nmatch) {
		pmatch = NULL;
		if (nmatch) *nmatch = 0;
	}

	if (pmatch) {
#ifdef PCRE2_COPY_MATCHED_SUBJECT
		/*
		 *	This is apparently only supported for pcre2_match
		 *	NOT pcre2_jit_match.
		 */
#  ifdef PCRE2_CONFIG_JIT
		if (!preg->jitd) {
#  endif
			dup_subject = false;

			/*
			 *	If PCRE2_COPY_MATCHED_SUBJECT is available
			 *	and set as an options flag, pcre2_match will
			 *	strdup the subject string if pcre2_match is
			 *	successful and store a pointer to it in the
			 *	regmatch struct.
			 *
			 *	The lifetime of the string memory will be
			 *	bound to the regmatch struct.  This is more
			 *	efficient that doing it ourselves, as the
			 *	strdup only occurs if the subject matches.
			 */
			options |= PCRE2_COPY_MATCHED_SUBJECT;
#  ifdef PCRE2_CONFIG_JIT
		}
#  endif
#endif
		if (dup_subject) {
			/*
			 *	We have to dup and operate on the duplicate
			 *	of the subject, because pcre2_jit_match and
			 *	pcre2_match store a pointer to the subject
			 *	in the regmatch structure.
			 */
			subject = our_subject = talloc_bstrndup(pmatch, subject, len);
			if (!subject) {
				fr_strerror_printf("Out of memory");
				return -1;
			}
#ifndef NDEBUG
			pmatch->subject = subject; /* Stored only for tracking memory issues */
#endif
		}
	}

	/*
	 *	If we weren't given match data we need to alloc it else pcre2_match
	 *	fails when passed NULL match data.
	 */
	if (!pmatch) {
		match_data = pcre2_match_data_create_from_pattern(preg->compiled, _pcre2_gcontext);
		if (!match_data) {
			fr_strerror_printf("Failed allocating temporary match data");
			return -1;
		}
	} else {
		match_data = pmatch->match_data;
	}

#ifdef PCRE2_CONFIG_JIT
	if (preg->jitd) {
		ret = pcre2_jit_match(preg->compiled, (PCRE2_SPTR8)subject, len, 0, options,
				      match_data, NULL);
	} else
#endif
	{
		ret = pcre2_match(preg->compiled, (PCRE2_SPTR8)subject, len, 0, options,
				  match_data, NULL);
	}
	if (!pmatch) pcre2_match_data_free(match_data);
	if (ret < 0) {
		PCRE2_UCHAR	errbuff[128];

		if (dup_subject) talloc_free(our_subject);

		if (ret == PCRE2_ERROR_NOMATCH) {
			if (nmatch) *nmatch = 0;
			return 0;
		}

		pcre2_get_error_message(ret, errbuff, sizeof(errbuff));
		fr_strerror_printf("regex evaluation failed with code (%i): %s", ret, errbuff);

		return -1;
	}

	if (nmatch && (ret > 0)) *nmatch = ret;

	return 1;
}

/** Free libpcre2's matchdata
 *
 * @note Don't call directly, will be called if talloc_free is called on a #regmatch_t.
 */
static int _pcre2_match_data_free(regmatch_t *regmatch)
{
	pcre2_match_data_free(regmatch->match_data);
	return 0;
}

/** Allocate vectors to fill with match data
 *
 * @param[in] ctx	to allocate match vectors in.
 * @param[in] count	The number of vectors to allocate.
 * @return
 *	- NULL on error.
 *	- Array of match vectors.
 */
regmatch_t *regex_match_data_alloc(TALLOC_CTX *ctx, uint32_t count)
{
	regmatch_t *regmatch;

	regmatch = talloc(ctx, regmatch_t);
	if (!regmatch) {
	oom:
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	regmatch->match_data = pcre2_match_data_create(count, _pcre2_gcontext);
	if (!regmatch->match_data) {
		talloc_free(regmatch);
		goto oom;
	}
	talloc_set_type(regmatch->match_data, pcre2_match_data);

	talloc_set_destructor(regmatch, _pcre2_match_data_free);

	return regmatch;
}

/*
 *	Wrapper functions for libpcre. Much more powerful, and guaranteed
 *	to be binary safe but require libpcre.
 */
#  elif defined(HAVE_PCRE)
/** Free regex_t structure
 *
 * Calls libpcre specific free functions for the expression and study.
 *
 * @param preg to free.
 */
static int _regex_free(regex_t *preg)
{
	if (preg->compiled) {
		pcre_free(preg->compiled);
		preg->compiled = NULL;
	}

	if (preg->extra) {
#ifdef PCRE_CONFIG_JIT
		pcre_free_study(preg->extra);
#else
		pcre_free(preg->extra);
#endif
		preg->extra = NULL;
	}

	return 0;
}

/*
 *	Replace the libpcre malloc and free functions with
 *	talloc wrappers. This allows us to use the subcapture copy
 *	functions and just reparent the memory allocated.
 */
static void *_pcre_malloc(size_t to_alloc)
{
	return talloc_array(NULL, uint8_t, to_alloc);
}

static void _pcre_free(void *to_free)
{
	talloc_free(to_free);
}

/** Wrapper around pcre_compile
 *
 * Allows the rest of the code to do compilations using one function signature.
 *
 * @note Compiled expression must be freed with talloc_free.
 *
 * @param out Where to write out a pointer to the structure containing the compiled expression.
 * @param pattern to compile.
 * @param len of pattern.
 * @param ignore_case whether to do case insensitive matching.
 * @param multiline If true $ matches newlines.
 * @param subcaptures Whether to compile the regular expression to store subcapture
 *	data.
 * @param runtime If false run the pattern through the PCRE JIT to convert it to machine code.
 *	This trades startup time (longer) for runtime performance (better).
 * @return >= 1 on success, <= 0 on error. Negative value is offset of parse error.
 */
ssize_t regex_compile(TALLOC_CTX *ctx, regex_t **out, char const *pattern, size_t len,
		      bool ignore_case, bool multiline, bool subcaptures, bool runtime)
{
	char const *error;
	int offset;
	int cflags = 0;
	regex_t *preg;

	static bool setup = false;

	/*
	 *	Lets us use subcapture copy
	 */
	if (!setup) {
		pcre_malloc = _pcre_malloc;
		pcre_free = _pcre_free;
		setup = true;
	}

	*out = NULL;

	if (len == 0) {
		fr_strerror_printf("Empty expression");
		return 0;
	}

	if (ignore_case) cflags |= PCRE_CASELESS;
	if (multiline) cflags |= PCRE_MULTILINE;
	if (!subcaptures) cflags |= PCRE_NO_AUTO_CAPTURE;

	preg = talloc_zero(ctx, regex_t);
	talloc_set_destructor(preg, _regex_free);

	preg->compiled = pcre_compile(pattern, cflags, &error, &offset, NULL);
	if (!preg->compiled) {
		talloc_free(preg);
		fr_strerror_printf("Pattern compilation failed: %s", error);

		return -(ssize_t)offset;
	}
	if (!runtime) {
		preg->precompiled = true;
		preg->extra = pcre_study(preg->compiled, PCRE_STUDY_JIT_COMPILE, &error);
		if (error) {
			talloc_free(preg);
			fr_strerror_printf("Pattern study failed: %s", error);

			return 0;
		}
	}

	*out = preg;

	return len;
}

static const FR_NAME_NUMBER regex_pcre_error_str[] = {
	{ "PCRE_ERROR_NOMATCH",		PCRE_ERROR_NOMATCH },
	{ "PCRE_ERROR_NULL",		PCRE_ERROR_NULL },
	{ "PCRE_ERROR_BADOPTION",	PCRE_ERROR_BADOPTION },
	{ "PCRE_ERROR_BADMAGIC",	PCRE_ERROR_BADMAGIC },
	{ "PCRE_ERROR_UNKNOWN_OPCODE",	PCRE_ERROR_UNKNOWN_OPCODE },
	{ "PCRE_ERROR_NOMEMORY",	PCRE_ERROR_NOMEMORY },
	{ "PCRE_ERROR_NOSUBSTRING",	PCRE_ERROR_NOSUBSTRING },
	{ "PCRE_ERROR_MATCHLIMIT",	PCRE_ERROR_MATCHLIMIT },
	{ "PCRE_ERROR_CALLOUT",		PCRE_ERROR_CALLOUT },
	{ "PCRE_ERROR_BADUTF8",		PCRE_ERROR_BADUTF8 },
	{ "PCRE_ERROR_BADUTF8_OFFSET",	PCRE_ERROR_BADUTF8_OFFSET },
	{ "PCRE_ERROR_PARTIAL",		PCRE_ERROR_PARTIAL },
	{ "PCRE_ERROR_BADPARTIAL",	PCRE_ERROR_BADPARTIAL },
	{ "PCRE_ERROR_INTERNAL",	PCRE_ERROR_INTERNAL },
	{ "PCRE_ERROR_BADCOUNT",	PCRE_ERROR_BADCOUNT },
	{ "PCRE_ERROR_DFA_UITEM",	PCRE_ERROR_DFA_UITEM },
	{ "PCRE_ERROR_DFA_UCOND",	PCRE_ERROR_DFA_UCOND },
	{ "PCRE_ERROR_DFA_UMLIMIT",	PCRE_ERROR_DFA_UMLIMIT },
	{ "PCRE_ERROR_DFA_WSSIZE",	PCRE_ERROR_DFA_WSSIZE },
	{ "PCRE_ERROR_DFA_RECURSE",	PCRE_ERROR_DFA_RECURSE },
	{ "PCRE_ERROR_RECURSIONLIMIT",	PCRE_ERROR_RECURSIONLIMIT },
	{ "PCRE_ERROR_NULLWSLIMIT",	PCRE_ERROR_NULLWSLIMIT },
	{ "PCRE_ERROR_BADNEWLINE",	PCRE_ERROR_BADNEWLINE },
	{ NULL, 0 }
};

/** Wrapper around pcre_exec
 *
 * @param preg The compiled expression.
 * @param subject to match.
 * @param len Length of subject.
 * @param pmatch Array of match pointers.
 * @param nmatch How big the match array is. Updated to number of matches.
 * @return -1 on error, 0 on no match, 1 on match.
 */
int regex_exec(regex_t *preg, char const *subject, size_t len, regmatch_t pmatch[], size_t *nmatch)
{
	int	ret;
	size_t	matches;

	/*
	 *	PCRE_NO_AUTO_CAPTURE is a compile time only flag,
	 *	and can't be passed here.
	 *	We rely on the fact that matches has been set to
	 *	0 as a hint that no subcapture data should be
	 *	generated.
	 */
	if (!pmatch || !nmatch) {
		pmatch = NULL;
		if (nmatch) *nmatch = 0;
		matches = 0;
	} else {
		matches = *nmatch;
	}

	ret = pcre_exec(preg->compiled, preg->extra, subject, len, 0, 0, (int *)pmatch, matches * 3);
	if (ret < 0) {
		if (ret == PCRE_ERROR_NOMATCH) return 0;

		fr_strerror_printf("regex evaluation failed with code (%i): %s", ret,
				   fr_int2str(regex_pcre_error_str, ret, "<INVALID>"));
		return -1;
	}

	/*
	 *	0 signifies more offsets than we provided space for,
	 *	so don't touch nmatches.
	 */
	if (nmatch && (ret > 0)) *nmatch = ret;

	return 1;
}
/*
 *	Wrapper functions for POSIX like, and extended regular
 *	expressions.  These use the system regex library.
 */
#  else
/** Free heap allocated regex_t structure
 *
 * Heap allocation of regex_t is needed so regex_compile has the same signature with
 * POSIX or libpcre.
 *
 * @param preg to free.
 */
static int _regex_free(regex_t *preg)
{
	regfree(preg);

	return 0;
}

/** Binary safe wrapper around regcomp
 *
 *  If we have the BSD extensions we don't need to do any special work
 *  if we don't have the BSD extensions we need to check to see if the
 *  regular expression contains any \0 bytes.
 *
 *  If it does we fail and print the appropriate error message.
 *
 * @note Compiled expression must be freed with talloc_free.
 *
 * @param ctx To allocate memory in.
 * @param out Where to write out a pointer to the structure containing the
 *	compiled expression.
 * @param pattern to compile.
 * @param len of pattern.
 * @param ignore_case Whether the match should be case ignore_case.
 * @param multiline If true $ matches newlines.
 * @param subcaptures Whether to compile the regular expression to store subcapture
 *	data.
 * @param runtime Whether the compilation is being done at runtime.
 * @return >= 1 on success, <= 0 on error. Negative value is offset of parse error.
 *	With POSIX regex we only give the correct offset for embedded \0 errors.
 */
ssize_t regex_compile(TALLOC_CTX *ctx, regex_t **out, char const *pattern, size_t len,
		      bool ignore_case, bool multiline, bool subcaptures, UNUSED bool runtime)
{
	int ret;
	int cflags = REG_EXTENDED;
	regex_t *preg;

	if (len == 0) {
		fr_strerror_printf("Empty expression");
		return 0;
	}

	if (ignore_case) cflags |= REG_ICASE;
	if (multiline) cflags |= REG_NEWLINE;
	if (!subcaptures) cflags |= REG_NOSUB;

#ifndef HAVE_REGNCOMP
	{
		char const *p;

		p = pattern;
		p += strlen(pattern);

		if ((size_t)(p - pattern) != len) {
			fr_strerror_printf("Found null in pattern at offset %zu.  Pattern unsafe for compilation",
					   (p - pattern));
			return -(p - pattern);
		}

		preg = talloc_zero(ctx, regex_t);
		if (!preg) return 0;

		ret = regcomp(preg, pattern, cflags);
	}
#else
	preg = talloc_zero(ctx, regex_t);
	if (!preg) return 0;
	ret = regncomp(preg, pattern, len, cflags);
#endif
	if (ret != 0) {
		char errbuf[128];

		regerror(ret, preg, errbuf, sizeof(errbuf));
		fr_strerror_printf("Pattern compilation failed: %s", errbuf);

		talloc_free(preg);

		return 0;	/* POSIX expressions don't give us the failure offset */
	}

	talloc_set_destructor(preg, _regex_free);
	*out = preg;

	return len;
}

/** Binary safe wrapper around regexec
 *
 *  If we have the BSD extensions we don't need to do any special work
 *  If we don't have the BSD extensions we need to check to see if the
 *  value to be compared contains any \0 bytes.
 *
 *  If it does, we fail and print the appropriate error message.
 *
 * @param preg The compiled expression.
 * @param subject to match.
 * @param pmatch Array of match pointers.
 * @param nmatch How big the match array is. Updated to number of matches.
 * @return -1 on error, 0 on no match, 1 on match.
 */
int regex_exec(regex_t *preg, char const *subject, size_t len, regmatch_t pmatch[], size_t *nmatch)
{
	int	ret;
	size_t	matches;

	/*
	 *	Disable capturing
	 */
	if (!pmatch || !nmatch) {
		pmatch = NULL;
		if (nmatch) *nmatch = 0;
		matches = 0;
	} else {
		/* regexec does not seem to initialise unused elements */
		matches = *nmatch;
		memset(pmatch, 0, sizeof(pmatch[0]) * matches);
	}

#ifndef HAVE_REGNEXEC
	{
		char const *p;

		p = subject;
		p += strlen(subject);

		if ((size_t)(p - subject) != len) {
			fr_strerror_printf("Found null in subject at offset %zu.  String unsafe for evaluation",
					   (p - subject));
			return -1;
		}
		ret = regexec(preg, subject, matches, pmatch, 0);
	}
#else
	ret = regnexec(preg, subject, len, matches, pmatch, 0);
#endif
	if (ret != 0) {
		if (ret != REG_NOMATCH) {
			char errbuf[128];

			regerror(ret, preg, errbuf, sizeof(errbuf));

			fr_strerror_printf("regex evaluation failed: %s", errbuf);
			if (nmatch) *nmatch = 0;
			return -1;
		}
		return 0;
	}

	/*
	 *	Update *nmatch to be the maximum number of
	 *	groups that *could* have been populated,
	 *	need to check them later.
	 */
	if (nmatch && (*nmatch > preg->re_nsub)) *nmatch = preg->re_nsub + 1;

	return 1;
}
#  endif
#endif
