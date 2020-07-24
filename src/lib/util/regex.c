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
 * @copyright 2014 The FreeRADIUS server project
 * @copyright 2014 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#ifdef HAVE_REGEX

#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/thread_local.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/talloc.h>

#if defined(HAVE_REGEX_PCRE) || (defined(HAVE_REGEX_PCRE2) && defined(PCRE2_CONFIG_JIT))
#ifndef FR_PCRE_JIT_STACK_MIN
#  define FR_PCRE_JIT_STACK_MIN	(128 * 1024)
#endif
#ifndef FR_PCRE_JIT_STACK_MAX
#  define FR_PCRE_JIT_STACK_MAX (512 * 1024)
#endif
#endif

/*
 *######################################
 *#      FUNCTIONS FOR LIBPCRE2        #
 *######################################
 */
#ifdef HAVE_REGEX_PCRE2
/*
 *	Wrapper functions for libpcre2. Much more powerful, and guaranteed
 *	to be binary safe for both patterns and subjects but require
 *	libpcre2.
 */

/** Thread local storage for PCRE2
 *
 * Not all this storage is thread local, but it simplifies cleanup if
 * we bind its lifetime to the thread, and lets us get away with not
 * having specific init/free functions.
 */
typedef struct {
	TALLOC_CTX		*alloc_ctx;	//!< Context used for any allocations.
	pcre2_general_context	*gcontext;	//!< General context.
	pcre2_compile_context	*ccontext;	//!< Compile context.
	pcre2_match_context	*mcontext;	//!< Match context.
#ifdef PCRE2_CONFIG_JIT
	pcre2_jit_stack		*jit_stack;	//!< Jit stack for executing jit'd patterns.
	bool			do_jit;		//!< Whether we have runtime JIT support.
#endif
} fr_pcre2_tls_t;

/** Thread local storage for pcre2
 *
 */
static _Thread_local fr_pcre2_tls_t *fr_pcre2_tls;

/** Talloc wrapper for pcre2 memory allocation
 *
 * @param[in] to_alloc		How many bytes to alloc.
 * @param[in] uctx		UNUSED.
 */
static void *_pcre2_talloc(PCRE2_SIZE to_alloc, UNUSED void *uctx)
{
	return talloc_array(fr_pcre2_tls->alloc_ctx, uint8_t, to_alloc);
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

/** Free thread local data
 *
 * @param[in] tls	Thread local data to free.
 */
static int _pcre2_tls_free(fr_pcre2_tls_t *tls)
{
	if (tls->gcontext) pcre2_general_context_free(tls->gcontext);
	if (tls->ccontext) pcre2_compile_context_free(tls->ccontext);
	if (tls->mcontext) pcre2_match_context_free(tls->mcontext);
#ifdef PCRE2_CONFIG_JIT
	if (tls->jit_stack) pcre2_jit_stack_free(tls->jit_stack);
#endif

	return 0;
}

static void _pcre2_tls_free_on_exit(void *arg)
{
	talloc_free(arg);
}

/** Thread local init for pcre2
 *
 */
static int fr_pcre2_tls_init(void)
{
	fr_pcre2_tls_t *tls;

	if (unlikely(fr_pcre2_tls != NULL)) return 0;

	fr_pcre2_tls = tls = talloc_zero(NULL, fr_pcre2_tls_t);
	if (!tls) return -1;
	talloc_set_destructor(tls, _pcre2_tls_free);

	tls->gcontext = pcre2_general_context_create(_pcre2_talloc, _pcre2_talloc_free, NULL);
	if (!tls->gcontext) {
		fr_strerror_printf("Failed allocating general context");
		return -1;
	}

	tls->ccontext = pcre2_compile_context_create(tls->gcontext);
	if (!tls->ccontext) {
		fr_strerror_printf("Failed allocating compile context");
	error:
		fr_pcre2_tls = NULL;
		_pcre2_tls_free(tls);
		return -1;
	}

	tls->mcontext = pcre2_match_context_create(tls->gcontext);
	if (!tls->mcontext) {
		fr_strerror_printf("Failed allocating match context");
		goto error;
	}

#ifdef PCRE2_CONFIG_JIT
	pcre2_config(PCRE2_CONFIG_JIT, &tls->do_jit);
	if (tls->do_jit) {
		tls->jit_stack = pcre2_jit_stack_create(FR_PCRE_JIT_STACK_MIN, FR_PCRE_JIT_STACK_MAX, tls->gcontext);
		if (!tls->jit_stack) {
			fr_strerror_printf("Failed allocating JIT stack");
			goto error;
		}
		pcre2_jit_stack_assign(tls->mcontext, NULL, tls->jit_stack);
	}
#endif

	/*
	 *	Free on thread exit
	 */
	fr_thread_local_set_destructor(fr_pcre2_tls, _pcre2_tls_free_on_exit, tls);
	fr_pcre2_tls = tls;	/* Assign to thread local storage */

	return 0;
}

/** Free regex_t structure
 *
 * Calls libpcre specific free functions for the expression and study.
 *
 * @param preg to free.
 */
static int _regex_free(regex_t *preg)
{
	if (preg->compiled) pcre2_code_free(preg->compiled);

	return 0;
}

/** Wrapper around pcre2_compile
 *
 * Allows the rest of the code to do compilations using one function signature.
 *
 * @note Compiled expression must be freed with talloc_free.
 *
 * @param[out] out		Where to write out a pointer to the structure containing
 *				the compiled expression.
 * @param[in] pattern		to compile.
 * @param[in] len		of pattern.
 * @param[in] flags		controlling matching. May be NULL.
 * @param[in] subcaptures	Whether to compile the regular expression to store subcapture
 *				data.
 * @param[in] runtime		If false run the pattern through the PCRE JIT (if available)
 *				to convert it to machine code. This trades startup time (longer)
 *				for runtime performance (better).
 * @return
 *	- >= 1 on success.
 *	- <= 0 on error. Negative value is offset of parse error.
 */
ssize_t regex_compile(TALLOC_CTX *ctx, regex_t **out, char const *pattern, size_t len,
		      fr_regex_flags_t const *flags, bool subcaptures, bool runtime)
{
	int		ret;
	PCRE2_SIZE	offset;
	uint32_t	cflags = 0;
	regex_t		*preg;

	/*
	 *	Check inputs
	 */
	*out = NULL;

	/*
	 *	Thread local initialisation
	 */
	if (!fr_pcre2_tls && (fr_pcre2_tls_init() < 0)) return -1;

	if (len == 0) {
		fr_strerror_printf("Empty expression");
		return 0;
	}

	/*
	 *	Options
	 */
	if (flags) {
		 /* flags->global implemented by substitution function */
		if (flags->ignore_case) cflags |= PCRE2_CASELESS;
		if (flags->multiline) cflags |= PCRE2_MULTILINE;
		if (flags->dot_all) cflags |= PCRE2_DOTALL;
		if (flags->unicode) cflags |= PCRE2_UTF;
		if (flags->extended) cflags |= PCRE2_EXTENDED;
	}

	if (!subcaptures) cflags |= PCRE2_NO_AUTO_CAPTURE;

	preg = talloc_zero(ctx, regex_t);
	talloc_set_destructor(preg, _regex_free);

	preg->compiled = pcre2_compile((PCRE2_SPTR8)pattern, len,
				       cflags, &ret, &offset, fr_pcre2_tls->ccontext);
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
		if (fr_pcre2_tls->do_jit) {
			ret = pcre2_jit_compile(preg->compiled, PCRE2_JIT_COMPLETE);
			if (ret < 0) {
				PCRE2_UCHAR errbuff[128];

				pcre2_get_error_message(ret, errbuff, sizeof(errbuff));
				fr_strerror_printf("Pattern JIT failed: %s", (char *)errbuff);
				talloc_free(preg);

				return 0;
			}
			preg->jitd = true;
		}
#endif
	}

	*out = preg;

	return len;
}

/** Wrapper around pcre2_exec
 *
 * @param[in] preg	The compiled expression.
 * @param[in] subject	to match.
 * @param[in] len	Length of subject.
 * @param[in] regmatch	Array of match pointers.
 * @return
 *	- -1 on failure.
 *	- 0 on no match.
 *	- 1 on match.
 */
int regex_exec(regex_t *preg, char const *subject, size_t len, fr_regmatch_t *regmatch)
{
	int			ret;
	uint32_t		options = 0;

	char			*our_subject = NULL;
	bool			dup_subject = true;
	pcre2_match_data	*match_data;

	/*
	 *	Thread local initialisation
	 */
	if (!fr_pcre2_tls && (fr_pcre2_tls_init() < 0)) return -1;

	if (regmatch) {
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
			subject = our_subject = talloc_bstrndup(regmatch, subject, len);
			if (!subject) {
				fr_strerror_printf("Out of memory");
				return -1;
			}
#ifndef NDEBUG
			regmatch->subject = subject; /* Stored only for tracking memory issues */
#endif
		}
	}

	/*
	 *	If we weren't given match data we
	 *	need to alloc it else pcre2_match
	 *	fails when passed NULL match data.
	 */
	if (!regmatch) {
		match_data = pcre2_match_data_create_from_pattern(preg->compiled, fr_pcre2_tls->gcontext);
		if (!match_data) {
			fr_strerror_printf("Failed allocating temporary match data");
			return -1;
		}
	} else {
		match_data = regmatch->match_data;
	}

#ifdef PCRE2_CONFIG_JIT
	if (preg->jitd) {
		ret = pcre2_jit_match(preg->compiled, (PCRE2_SPTR8)subject, len, 0, options,
				      match_data, fr_pcre2_tls->mcontext);
	} else
#endif
	{
		ret = pcre2_match(preg->compiled, (PCRE2_SPTR8)subject, len, 0, options,
				  match_data, fr_pcre2_tls->mcontext);
	}
	if (!regmatch) pcre2_match_data_free(match_data);
	if (ret < 0) {
		PCRE2_UCHAR	errbuff[128];

		if (dup_subject) talloc_free(our_subject);

		if (ret == PCRE2_ERROR_NOMATCH) {
			if (regmatch) regmatch->used = 0;
			return 0;
		}

		pcre2_get_error_message(ret, errbuff, sizeof(errbuff));
		fr_strerror_printf("regex evaluation failed with code (%i): %s", ret, errbuff);

		return -1;
	}

	if (regmatch) regmatch->used = ret;

	return 1;
}

/** Wrapper around pcre2_substitute
 *
 * @param[in] ctx		to allocate output string in.
 * @param[out] out		Output string with replacements performed.
 * @param[in] max_out		Maximum length of output buffer.  If this is 0 then
 *				the output length is unlimited.
 * @param[in] preg		The compiled expression.
 * @param[in] flags		that affect matching.
 * @param[in] subject		to perform replacements on.
 * @param[in] subject_len	the length of the subject.
 * @param[in] replacement	replacement string containing substitution
 *				markers.
 * @param[in] replacement_len	Length of the replacement string.
 * @param[in] regmatch		Array of match pointers.
 * @return
 *	- >= 0 the length of the output string.
 *	- < 0 on error.
 */
int regex_substitute(TALLOC_CTX *ctx, char **out, size_t max_out, regex_t *preg, fr_regex_flags_t *flags,
		     char const *subject, size_t subject_len,
		     char const *replacement, size_t replacement_len,
		     fr_regmatch_t *regmatch)
{
	int			ret;
	uint32_t		options = 0;
	size_t			buff_len, actual_len;
	char			*buff;

#ifndef PCRE2_COPY_MATCHED_SUBJECT
	char			*our_subject = NULL;
#endif

	/*
	 *	Thread local initialisation
	 */
	if (!fr_pcre2_tls && (fr_pcre2_tls_init() < 0)) return -1;

	/*
	 *	Internally pcre2_substitute just calls pcre2_match to
	 *	generate the match data, so the same hack as the
	 *	regex_exec function above is required.
	 */
	if (regmatch) {
#ifndef PCRE2_COPY_MATCHED_SUBJECT
		/*
		 *	We have to dup and operate on the duplicate
		 *	of the subject, because pcre2_jit_match and
		 *	pcre2_match store a pointer to the subject
		 *	in the regmatch structure.
		 */
		subject = our_subject = talloc_bstrndup(regmatch, subject, subject_len);
		if (!subject) {
			fr_strerror_printf("Out of memory");
			return -1;
		}
#else
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
#endif
	}

	/*
	 *	Guess (badly) what the length of the output buffer should be
	 */
	actual_len = buff_len = subject_len + 1;	/* +1 for the \0 */
	buff = talloc_array(ctx, char, buff_len);
	if (!buff) {
#ifndef PCRE2_COPY_MATCHED_SUBJECT
		talloc_free(our_subject);
#endif
		fr_strerror_printf("Out of memory");
		return -1;
	}

	options |= PCRE2_SUBSTITUTE_OVERFLOW_LENGTH;
	if (flags->global) options |= PCRE2_SUBSTITUTE_GLOBAL;

again:
	/*
	 *	actual_len input value should be the size of the
	 *	buffer including space for '\0'.
	 *	If input buffer is too small, then actual_len will be set
	 *      to the buffer space needed including space for '\0'.
	 *	If input buffer is the correct size, then actual_len
	 *	will be set to the size of the string written to buff
	 *	without the terminating '\0'.
	 */
	ret = pcre2_substitute(preg->compiled,
			       (PCRE2_SPTR8)subject, (PCRE2_SIZE)subject_len, 0,
			       options, regmatch ? regmatch->match_data : NULL, fr_pcre2_tls->mcontext,
			       (PCRE2_UCHAR const *)replacement, replacement_len, (PCRE2_UCHAR *)buff, &actual_len);

	if (ret < 0) {
		PCRE2_UCHAR errbuff[128];

#ifndef PCRE2_COPY_MATCHED_SUBJECT
		talloc_free(our_subject);
#endif
		talloc_free(buff);

		if (ret == PCRE2_ERROR_NOMEMORY) {
			if ((max_out > 0) && (actual_len > max_out)) {
				fr_strerror_printf("String length with substitutions (%zu) "
						    "exceeds max string length (%zu)", actual_len - 1, max_out - 1);
				return -1;
			}

			/*
			 *	Check that actual_len != buff_len as that'd be
			 *	an actual error.
			 */
			if (actual_len == buff_len) {
				fr_strerror_printf("libpcre2 out of memory");
				return -1;
			}

			talloc_free(buff);
			buff_len = actual_len;	/* The length we get passed back includes the \0 */
			buff = talloc_array(ctx, char, buff_len);
			goto again;
		}

		if (ret == PCRE2_ERROR_NOMATCH) {
			if (regmatch) regmatch->used = 0;
			return 0;
		}

		pcre2_get_error_message(ret, errbuff, sizeof(errbuff));
		fr_strerror_printf("regex evaluation failed with code (%i): %s", ret, errbuff);
		return -1;
	}

	/*
	 *	Trim the replacement buffer to the correct length
	 *
	 *	buff_len includes \0.
	 *	...and as pcre2_substitute just succeeded actual_len does not include \0.
	 */
	if (actual_len < (buff_len - 1)) {
		buff = talloc_bstr_realloc(ctx, buff, actual_len);
		if (!buff) {
			fr_strerror_printf("reallocing pcre2_substitute result buffer failed");
			return -1;
		}
	}

	if (regmatch) regmatch->used = ret;
	*out = buff;

	return 1;
}


/** Returns the number of subcapture groups
 *
 * @return
 *	- >0 The number of subcaptures contained within the pattern
 *	- 0 if the number of subcaptures can't be determined.
 */
uint32_t regex_subcapture_count(regex_t const *preg)
{
	uint32_t count;

	if (pcre2_pattern_info(preg->compiled, PCRE2_INFO_CAPTURECOUNT, &count) != 0) {
		fr_strerror_printf("Error determining subcapture group count");
		return 0;
	}

	return count + 1;
}

/** Free libpcre2's matchdata
 *
 * @note Don't call directly, will be called if talloc_free is called on a #regmatch_t.
 */
static int _pcre2_match_data_free(fr_regmatch_t *regmatch)
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
fr_regmatch_t *regex_match_data_alloc(TALLOC_CTX *ctx, uint32_t count)
{
	fr_regmatch_t *regmatch;

	/*
	 *	Thread local initialisation
	 */
	if (!fr_pcre2_tls && (fr_pcre2_tls_init() < 0)) return NULL;

	regmatch = talloc(ctx, fr_regmatch_t);
	if (!regmatch) {
	oom:
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	regmatch->match_data = pcre2_match_data_create(count, fr_pcre2_tls->gcontext);
	if (!regmatch->match_data) {
		talloc_free(regmatch);
		goto oom;
	}
	talloc_set_type(regmatch->match_data, pcre2_match_data);

	talloc_set_destructor(regmatch, _pcre2_match_data_free);

	return regmatch;
}
/*
 *######################################
 *#       FUNCTIONS FOR LIBPCRE        #
 *######################################
 */
#elif defined(HAVE_REGEX_PCRE)
/*
 *	Wrapper functions for libpcre. Much more powerful, and guaranteed
 *	to be binary safe but require libpcre.
 */
#if (PCRE_MAJOR >= 8) && (PCRE_MINOR >= 32) && defined(PCRE_CONFIG_JIT)
#  define HAVE_PCRE_JIT_EXEC 1
#endif

#ifdef HAVE_PCRE_JIT_EXEC
static _Thread_local pcre_jit_stack *fr_pcre_jit_stack;
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
static void *_pcre_talloc(size_t to_alloc)
{
	return talloc_array(NULL, uint8_t, to_alloc);
}

static void _pcre_talloc_free(void *to_free)
{
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
 * @param[in] flags		controlling matching.  May be NULL.
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
		      fr_regex_flags_t const *flags, bool subcaptures, bool runtime)
{
	char const	*error;
	int		offset;
	int		cflags = 0;
	regex_t		*preg;

	static		bool setup;
	static		bool study_flags;

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
		pcre_malloc = _pcre_talloc;		/* pcre_malloc is a global provided by libpcre */
		pcre_free = _pcre_talloc_free;		/* pcre_free is a global provided by libpcre */
	}

	/*
	 *	Check inputs
	 */
	*out = NULL;

	if (len == 0) {
		fr_strerror_printf("Empty expression");
		return 0;
	}

	/*
	 *	Options
	 */
	if (flags) {
		if (flags->global) {
			fr_strerror_printf("g - Global matching/substitution not supported with libpcre");
			return 0;
		}
		if (flags->ignore_case) cflags |= PCRE_CASELESS;
		if (flags->multiline) cflags |= PCRE_MULTILINE;
		if (flags->dot_all) cflags |= PCRE_DOTALL;
		if (flags->unicode) cflags |= PCRE_UTF8;
		if (flags->extended) cflags |= PCRE_EXTENDED;
	}

	if (!subcaptures) cflags |= PCRE_NO_AUTO_CAPTURE;

	preg = talloc_zero(ctx, regex_t);
	talloc_set_destructor(preg, _regex_free);

	preg->compiled = pcre_compile(pattern, cflags, &error, &offset, NULL);
	if (!preg->compiled) {
		fr_strerror_printf("%s", error);
		talloc_free(preg);

		return -(ssize_t)offset;
	}

	if (!runtime) {
		preg->precompiled = true;
		preg->extra = pcre_study(preg->compiled, study_flags, &error);
		if (error) {
			fr_strerror_printf("Pattern study failed: %s", error);
			talloc_free(preg);

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

static fr_table_num_ordered_t const regex_pcre_error_str[] = {
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
	{ "PCRE_ERROR_BADOFFSET",	PCRE_ERROR_BADOFFSET },
	{ "PCRE_ERROR_SHORTUTF8",	PCRE_ERROR_SHORTUTF8 },
	{ "PCRE_ERROR_RECURSELOOP",	PCRE_ERROR_RECURSELOOP },
	{ "PCRE_ERROR_JIT_STACKLIMIT",	PCRE_ERROR_JIT_STACKLIMIT },
	{ "PCRE_ERROR_BADMODE",		PCRE_ERROR_BADMODE },
	{ "PCRE_ERROR_BADENDIANNESS",	PCRE_ERROR_BADENDIANNESS },
	{ "PCRE_ERROR_DFA_BADRESTART",	PCRE_ERROR_DFA_BADRESTART },
	{ "PCRE_ERROR_JIT_BADOPTION",	PCRE_ERROR_JIT_BADOPTION },
	{ "PCRE_ERROR_BADLENGTH",	PCRE_ERROR_BADLENGTH },
#ifdef PCRE_ERROR_UNSET
	{ "PCRE_ERROR_UNSET",		PCRE_ERROR_UNSET },
#endif

	{ NULL, 0 }
};
static size_t regex_pcre_error_str_len = NUM_ELEMENTS(regex_pcre_error_str);

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
 * @param[in] preg	The compiled expression.
 * @param[in] subject	to match.
 * @param[in] len	Length of subject.
 * @param[in] regmatch	Match result structure.
 * @return
 *	- -1 on failure.
 *	- 0 on no match.
 *	- 1 on match.
 */
int regex_exec(regex_t *preg, char const *subject, size_t len, fr_regmatch_t *regmatch)
{
	int	ret;
	size_t	matches;

#ifdef HAVE_PCRE_JIT_EXEC
	/*
	 *	Allocate thread local JIT stack
	 */
	if (!fr_pcre_jit_stack) {
		/*
		 *	Starts at 128K, max is 512K per thread.
		 */
		fr_thread_local_set_destructor(fr_pcre_jit_stack, _pcre_jit_stack_free,
					       pcre_jit_stack_alloc(FR_PCRE_JIT_STACK_MIN, FR_PCRE_JIT_STACK_MAX));
		if (!fr_pcre_jit_stack) {
			fr_strerror_printf("Allocating JIT stack failed");
			return -1;
		}
	}
#endif

	/*
	 *	Disable capturing
	 */
	if (!regmatch) {
		matches = 0;
	} else {
		matches = regmatch->allocd;

		/*
		 *	Reset the match result structure
		 */
		memset(regmatch->match_data, 0, sizeof(regmatch->match_data[0]) * matches);
		regmatch->used = 0;
	}

#ifdef HAVE_PCRE_JIT_EXEC
	if (preg->jitd) {
		ret = pcre_jit_exec(preg->compiled, preg->extra, subject, len, 0, 0,
				    regmatch ? (int *)regmatch->match_data : NULL, matches * 3, fr_pcre_jit_stack);
	} else
#endif
	{
		ret = pcre_exec(preg->compiled, preg->extra, subject, len, 0, 0,
				regmatch ? (int *)regmatch->match_data : NULL, matches * 3);
	}
	if (ret < 0) {
		if (ret == PCRE_ERROR_NOMATCH) return 0;

		fr_strerror_printf("regex evaluation failed with code (%i): %s", ret,
				   fr_table_str_by_value(regex_pcre_error_str, ret, "<INVALID>"));
		return -1;
	}

	/*
	 *	0 signifies more offsets than we provided space for,
	 *	so don't touch nmatches.
	 */
	if (regmatch && (ret > 0)) {
		regmatch->used = ret;

		if (regmatch->subject) talloc_const_free(regmatch->subject);
		regmatch->subject = talloc_bstrndup(regmatch, subject, len);
		if (!regmatch->subject) {
			fr_strerror_printf("Out of memory");
			return -1;
		}
	}

	return 1;
}

/** Returns the number of subcapture groups
 *
 * @return
 *	- >0 The number of subcaptures contained within the pattern
 *	- 0 if the number of subcaptures can't be determined.
 */
uint32_t regex_subcapture_count(regex_t const *preg)
{
	int count;

	if (pcre_fullinfo(preg->compiled, preg->extra, PCRE_INFO_CAPTURECOUNT, &count) != 0) {
		fr_strerror_printf("Error determining subcapture group count");
		return 0;
	}

	return (uint32_t)count + 1;
}
/*
 *######################################
 *#    FUNCTIONS FOR POSIX-REGEX      #
 *######################################
 */
#  else
/*
 *	Wrapper functions for POSIX like, and extended regular
 *	expressions.  These use the system regex library.
 */

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
 * If we have the BSD extensions we don't need to do any special work
 * if we don't have the BSD extensions we need to check to see if the
 * regular expression contains any \0 bytes.
 *
 * If it does we fail and print the appropriate error message.
 *
 * @note Compiled expression must be freed with talloc_free.
 *
 * @param[in] ctx		To allocate memory in.
 * @param[out] out		Where to write out a pointer
 *				to the structure containing the compiled expression.
 * @param[in] pattern		to compile.
 * @param[in] len		of pattern.
 * @param[in] flags		controlling matching.  May be NULL.
 * @param[in] subcaptures	Whether to compile the regular expression
 *				to store subcapture data.
 * @param[in] runtime		Whether the compilation is being done at runtime.
 * @return
 *	- >= 1 on success.
 *	- <= 0 on error. Negative value is offset of parse error.
 *	With POSIX regex we only give the correct offset for embedded \0 errors.
 */
ssize_t regex_compile(TALLOC_CTX *ctx, regex_t **out, char const *pattern, size_t len,
		      fr_regex_flags_t const *flags, bool subcaptures, UNUSED bool runtime)
{
	int ret;
	int cflags = REG_EXTENDED;
	regex_t *preg;

	if (len == 0) {
		fr_strerror_printf("Empty expression");
		return 0;
	}

	/*
	 *	Options
	 */
	if (flags) {
		if (flags->global) {
			fr_strerror_printf("g - Global matching/substitution not supported with posix-regex");
			return 0;
		}
		if (flags->dot_all) {
			fr_strerror_printf("s - Single line matching is not supported with posix-regex");
			return 0;
		}
		if (flags->unicode) {
			fr_strerror_printf("u - Unicode matching not supported with posix-regex");
			return 0;
		}
		if (flags->extended) {
			fr_strerror_printf("x - Whitespace and comments not supported with posix-regex");
			return 0;
		}

		if (flags->ignore_case) cflags |= REG_ICASE;
		if (flags->multiline) cflags |= REG_NEWLINE;
	}


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
		fr_strerror_printf("%s", errbuf);

		talloc_free(preg);

		return 0;	/* POSIX expressions don't give us the failure offset */
	}

	talloc_set_destructor(preg, _regex_free);
	*out = preg;

	return len;
}

/** Binary safe wrapper around regexec
 *
 * If we have the BSD extensions we don't need to do any special work
 * If we don't have the BSD extensions we need to check to see if the
 * value to be compared contains any \0 bytes.
 *
 * If it does, we fail and print the appropriate error message.
 *
 * @param[in] preg	The compiled expression.
 * @param[in] subject	to match.
 * @param[in] regmatch	Match result structure.
 * @return
 *	- -1 on failure.
 *	- 0 on no match.
 *	- 1 on match.
 */
int regex_exec(regex_t *preg, char const *subject, size_t len, fr_regmatch_t *regmatch)
{
	int	ret;
	size_t	matches;

	/*
	 *	Disable capturing
	 */
	if (!regmatch) {
		matches = 0;
	} else {
		matches = regmatch->allocd;

		/*
		 *	Reset the match result structure
		 */
		memset(regmatch->match_data, 0, sizeof(regmatch->match_data[0]) * matches);
		regmatch->used = 0;
	}

#ifndef HAVE_REGNEXEC
	{
		char const *p;

		p = subject;
		p += strlen(subject);

		if ((size_t)(p - subject) != len) {
			fr_strerror_printf("Found null in subject at offset %zu.  String unsafe for evaluation",
					   (p - subject));
			if (regmatch) regmatch->used = 0;
			return -1;
		}
		ret = regexec(preg, subject, matches, regmatch ? regmatch->match_data : NULL, 0);
	}
#else
	ret = regnexec(preg, subject, len, matches, regmatch ? regmatch->match_data : NULL, 0);
#endif
	if (ret != 0) {
		if (ret != REG_NOMATCH) {
			char errbuf[128];

			regerror(ret, preg, errbuf, sizeof(errbuf));

			fr_strerror_printf("regex evaluation failed: %s", errbuf);
			return -1;
		}
		return 0;
	}

	/*
	 *	Update regmatch->count to be the maximum number of
	 *	groups that *could* have been populated as we don't
	 *	have the number of matches.
	 */
	if (regmatch) {
		regmatch->used = preg->re_nsub + 1;

		if (regmatch->subject) talloc_const_free(regmatch->subject);
		regmatch->subject = talloc_bstrndup(regmatch, subject, len);
		if (!regmatch->subject) {
			fr_strerror_printf("Out of memory");
			return -1;
		}
	}
	return 1;
}

/** Returns the number of subcapture groups
 *
 * @return
 *	- 0 we can't determine this for POSIX regular expressions.
 */
uint32_t regex_subcapture_count(UNUSED regex_t const *preg)
{
	return 0;
}
#  endif

#  if defined(HAVE_REGEX_POSIX) || defined(HAVE_REGEX_PCRE)
/** Allocate vectors to fill with match data
 *
 * @param[in] ctx	to allocate match vectors in.
 * @param[in] count	The number of vectors to allocate.
 * @return
 *	- NULL on error.
 *	- Array of match vectors.
 */
fr_regmatch_t *regex_match_data_alloc(TALLOC_CTX *ctx, uint32_t count)
{
	fr_regmatch_t *regmatch;

	/*
	 *	Pre-allocate space for the match structure
	 *	and for a 128b subject string.
	 */
	regmatch = talloc_zero_pooled_object(ctx, fr_regmatch_t, 2, (sizeof(regmatch_t) * count) + 128);
	if (unlikely(!regmatch)) {
	error:
		fr_strerror_printf("Out of memory");
		talloc_free(regmatch);
		return NULL;
	}
	regmatch->match_data = talloc_array(regmatch, regmatch_t, count);
	if (unlikely(!regmatch->match_data)) goto error;

	regmatch->allocd = count;
	regmatch->used = 0;
	regmatch->subject = NULL;

	return regmatch;
}
#  endif

/*
 *########################################
 *#         UNIVERSAL FUNCTIONS          #
 *########################################
 */

/** Parse a string containing one or more regex flags
 *
 * @param[out] err		May be NULL. If not NULL will be set to:
 *				- 0 on success.
 *				- -1 on unknown flag.
 *				- -2 on duplicate.
 * @param[out] out		Flag structure to populate.  Must be initialised to zero
 *				if this is the first call to regex_flags_parse.
 * @param[in] in		Flag string to parse.
 * @param[in] len		Length of input string.
 * @param[in] err_on_dup	Error if the flag is already set.
 * @return
 *      - > 0 on success.  The number of flag bytes parsed.
 *	- <= 0 on failure.  Negative offset of first unrecognised flag.
 */
ssize_t regex_flags_parse(int *err, fr_regex_flags_t *out, char const *in, size_t len, bool err_on_dup)
{
	char const *p = in, *end = p + len;

	if (err) *err = 0;

	while (p < end) {
		switch (*p) {
#define DO_REGEX_FLAG(_f, _c) \
		case _c: \
			if (err_on_dup && out->_f) { \
				fr_strerror_printf("Duplicate regex flag '%c'", *p); \
				if (err) *err = -2; \
				return -(p - in); \
			} \
			out->_f = 1; \
			break

		DO_REGEX_FLAG(global, 'g');
		DO_REGEX_FLAG(ignore_case, 'i');
		DO_REGEX_FLAG(multiline, 'm');
		DO_REGEX_FLAG(dot_all, 's');
		DO_REGEX_FLAG(unicode, 'u');
		DO_REGEX_FLAG(extended, 'x');
#undef DO_REGEX_FLAG

		default:
			fr_strerror_printf("Unsupported regex flag '%c'", *p);
			if (err) *err = -1;
			return -(p - in);
		}
		p++;
	}
	return len;
}

/** Print the flags
 *
 * @param[out] out	where to write flags.
 * @param[in] outlen	Space in output buffer.
 * @param[in] flags	to print.
 * @return
 *	- The number of bytes written to the out buffer.
 *	- A number >= outlen if truncation has occurred.
 */
size_t regex_flags_snprint(char *out, size_t outlen, fr_regex_flags_t const flags[static REGEX_FLAG_BUFF_SIZE])
{
	char *p = out, *end = p + outlen;

#define DO_REGEX_FLAG(_f, _c) \
	do { \
		if (flags->_f) { \
			if ((end - p) <= 1) { \
				*end = '\0'; \
				return outlen + 1; \
			} \
			*p++ = _c; \
		} \
	} while(0)

	DO_REGEX_FLAG(global, 'g');
	DO_REGEX_FLAG(ignore_case, 'i');
	DO_REGEX_FLAG(multiline, 'm');
	DO_REGEX_FLAG(dot_all, 's');
	DO_REGEX_FLAG(unicode, 'u');
	DO_REGEX_FLAG(extended, 'x');
#undef DO_REGEX_FLAG

	return p - out;
}
#endif
