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

/** Wrappers around various regular expression libraries
 *
 * @file src/lib/util/regex.c
 *
 * @copyright 2014  The FreeRADIUS server project
 * @copyright 2014  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#ifdef HAVE_REGEX
#include "regex.h"

#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/thread_local.h>
#include <freeradius-devel/util/token.h>

/*
 *	Wrapper functions for libpcre. Much more powerful, and guaranteed
 *	to be binary safe but require libpcre.
 */
#ifdef HAVE_PCRE

#if (PCRE_MAJOR >= 8) && (PCRE_MINOR >= 32) && defined(PCRE_CONFIG_JIT)
#  define HAVE_PCRE_JIT_EXEC 1
#endif

#ifdef HAVE_PCRE_JIT_EXEC
fr_thread_local_setup(pcre_jit_stack *, fr_pcre_jit_stack)
#endif

/** Free regex_t structure
 *
 * Calls libpcre specific free functions for the expression and study.
 *
 * @param preg to free.
 */
static int _regex_free(regex_t *preg)
{
	if (preg->compiled) pcre_free(preg->compiled);
#ifdef PCRE_CONFIG_JIT
	if (preg->extra) pcre_free_study(preg->extra);
#else
	if (preg->extra) pcre_free(preg->extra);
#endif

	return 0;
}

/*
 *	Replace the libpcre memory allocation and freeing functions
 *	with talloc wrappers. This allows us to use the subcapture copy
 *	functions and just reparent the memory allocated.
 */
static void *_pcre_talloc_array(size_t to_alloc) {
	return talloc_array(NULL, uint8_t, to_alloc);
}

static void _pcre_talloc_free(void *to_free) {
	talloc_free(to_free);
}

/** Wrapper around pcre_compile
 *
 * Allows the rest of the code to do compilations using one function signature.
 *
 * @note Compiled expression must be freed with talloc_free.
 *
 * @param[out] out		Where to write out a pointer to the structure containing
 *				the compiled expression.
 * @param[in] pattern		to compile.
 * @param[in] len		of pattern.
 * @param[in] ignore_case	Whether to do case insensitive matching.
 * @param[in] multiline		If true $ matches newlines.
 * @param[in] subcaptures	Whether to compile the regular expression to store subcapture
 *				data.
 * @param[in] runtime		If false run the pattern through the PCRE JIT to convert it
 *				to machine code. This trades startup time (longer) for
 *				runtime performance (better).
 * @return
 *	- >= 1 on success.
 *	- <= 0 on error. Negative value is offset of parse error.
 */
ssize_t regex_compile(TALLOC_CTX *ctx, regex_t **out, char const *pattern, size_t len,
		      bool ignore_case, bool multiline, bool subcaptures, bool runtime)
{
	char const *error;
	int offset;
	int cflags = 0;
	regex_t *preg;

	static bool setup;
	static bool study_flags;

	/*
	 *	Lets us use subcapture copy
	 */
	if (!setup) {
#ifdef PCRE_CONFIG_JIT
		int *do_jit = 0;

		/*
		 *	If the headers are from >= 8.20
		 *	check at runtime to see if this version
		 *	of the libpcre library was compiled with
		 *	JIT support.
		 */
		pcre_config(PCRE_CONFIG_JIT, &do_jit);

		if (do_jit) study_flags |= PCRE_STUDY_JIT_COMPILE;
#endif
		pcre_malloc = _pcre_talloc_array;	/* pcre_malloc is a global provided by libpcre */
		pcre_free = _pcre_talloc_free;		/* pcre_free is a global provided by libpcre */
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
		preg->extra = pcre_study(preg->compiled, study_flags, &error);
		if (error) {
			talloc_free(preg);
			fr_strerror_printf("Pattern study failed: %s", error);

			return 0;
		}

#ifdef PCRE_INFO_JIT
		/*
		 *	Check to see if the JIT was successful.
		 *
		 * 	Not all platforms have JIT support, the pattern
		 *	may not be jitable, or JIT support may have been
		 *	disabled.
		 */
		if (study_flags & PCRE_STUDY_JIT_COMPILE) {
			int jitd = 0;

			pcre_fullinfo(preg->compiled, preg->extra, PCRE_INFO_JIT, &jitd);
			if (jitd) preg->jitd = true;
		}
#endif
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

#ifdef HAVE_PCRE_JIT_EXEC
/** Free a PCRE JIT stack on exit
 *
 * @param[in] stack to free.
 */
static void _pcre_jit_stack_free(void *stack)
{
	pcre_jit_stack_free(stack);
}
#endif

/** Wrapper around pcre_exec
 *
 * @param preg The compiled expression.
 * @param subject to match.
 * @param len Length of subject.
 * @param pmatch Array of match pointers.
 * @param nmatch How big the match array is. Updated to number of matches.
 * @return
 *	- -1 on failure.
 *	- 0 on no match.
 *	- 1 on match.
 */
int regex_exec(regex_t *preg, char const *subject, size_t len, regmatch_t pmatch[], size_t *nmatch)
{
	int	ret;
	size_t	matches;

#ifdef HAVE_PCRE_JIT_EXEC
	/*
	 *	Allocate thread local JIT stack
	 */
	if (!fr_pcre_jit_stack) {
		fr_thread_local_set_destructor(fr_pcre_jit_stack, _pcre_jit_stack_free, pcre_jit_stack_alloc(128, 512));
		if (!fr_pcre_jit_stack) {
			fr_strerror_printf("Allocating JIT stack failed");
			return -1;
		}
	}
#endif

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

#ifdef HAVE_PCRE_JIT_EXEC
	if (preg->jitd) {
		ret = pcre_jit_exec(preg->compiled, preg->extra, subject, len, 0, 0,
				    (int *)pmatch, matches * 3, fr_pcre_jit_stack);
	} else
#endif
	{
		ret = pcre_exec(preg->compiled, preg->extra, subject, len, 0, 0, (int *)pmatch, matches * 3);
	}
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
 * @return
 *	- >= 1 on success.
 *	- <= 0 on error. Negative value is offset of parse error.
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
 * @return
 *	- -1 on failure.
 *	- 0 on no match.
 *	- 1 on match.
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
