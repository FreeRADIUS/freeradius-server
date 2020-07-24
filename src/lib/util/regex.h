#pragma once
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
#ifdef HAVE_REGEX
/** Wrappers around various regular expression libraries
 *
 * @file src/lib/util/regex.h
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(regex_h, "$Id$")

#  ifdef __cplusplus
extern "C" {
#  endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>
#include <unistd.h>

/*
 *######################################
 *#      STRUCTURES FOR LIBPCRE2       #
 *######################################
 */
#  ifdef HAVE_REGEX_PCRE2
#    define PCRE2_CODE_UNIT_WIDTH 8
#    include <pcre2.h>
/*
 *  libpcre defines its matches as an array of ints which is a
 *  multiple of three.
 */

/** libpcre2 has its own matchdata struct, we wrap it so we can use talloc destructors
 *
 */
typedef struct {
	pcre2_match_data	*match_data;	//!< Match data containing the subject
						///< and various match offsets.
	size_t			used;		//!< Number of slots filled with match data.
#ifndef NDEBUG
	char const		*subject;	//!< Here for debugging purposes if we explicitly duped the string.
#endif
} fr_regmatch_t;

typedef struct {
	pcre2_code		*compiled;	//!< Compiled regular expression.
	uint32_t		subcaptures;	//!< Number of subcaptures contained within the expression.

	bool			precompiled;	//!< Whether this regex was precompiled,
						///< or compiled for one off evaluation.
	bool			jitd;		//!< Whether JIT data is available.
} regex_t;
/*
 *######################################
 *#      STRUCTURES FOR LIBPCRE        #
 *######################################
 */
#  elif defined(HAVE_REGEX_PCRE)
#    include <pcre.h>
/*
 *  Versions older then 8.20 didn't have the JIT functionality
 *  so, gracefully degrade.
 */
#    ifndef PCRE_STUDY_JIT_COMPILE
#      define PCRE_STUDY_JIT_COMPILE 0
#    endif
/*
 *  libpcre defines its matches as an array of ints which is a
 *  multiple of three.
 */
typedef struct {
	int a;
	int b;
	int c;
} regmatch_t;

/** Emulates the functionality of the pcre2_match_data struct
 *
 */
typedef struct {
	regmatch_t		*match_data;	//!< Slots for matches.
	size_t			allocd;		//!< Number of slots allocated for match data.
	size_t			used;		//!< Number of slots filled with match data.
	char const		*subject;	//!< A local copy of the subject.
} fr_regmatch_t;

/** Bundles compiled regular expression structures together
 *
 */
typedef struct {
	pcre			*compiled;	//!< Compiled regular expression.
	pcre_extra		*extra;		//!< Result of studying a regular expression.
	uint32_t		subcaptures;	//!< Number of subcaptures contained within the expression.

	bool			precompiled;	//!< Whether this regex was precompiled, or compiled for one off evaluation.
	bool			jitd;		//!< Whether JIT data is available.
} regex_t;
/*
 *######################################
 *#    STRUCTURES FOR POSIX-REGEX      #
 *######################################
 */
#  else
#    include <regex.h>
/*
 *  Allow REG_EXTENDED and REG_NOSUB to be or'd with flags
 *  if they're not defined.
 */
#    ifndef REG_EXTENDED
#      define REG_EXTENDED (0)
#    endif

#    ifndef REG_NOSUB
#      define REG_NOSUB (0)
#    endif

/** Emulates the functionality of the pcre2_match_data struct
 *
 */
typedef struct {
	regmatch_t		*match_data;	//!< Slots for matches.
	size_t			allocd;		//!< Number of slots allocated for match data.
	size_t			used;		//!< Number of slots filled with match data.
	char const		*subject;	//!< A local copy of the subject.
} fr_regmatch_t;

#  endif

/*
 *########################################
 *#  UNIVERSAL FUNCTIONS AND STRUCTURES  #
 *########################################
 */

/** The set of all flags implemented by the different regex libraries
 *
 * A specific library may not implement all these flags.  If an unsupported flag is high
 * then the library will produce an error.
 */
typedef struct {
	uint8_t	global:1;			//!< g - Perform global matching or substitution.
	uint8_t ignore_case:1;			//!< i - Perform case insensitive matching.
	uint8_t	multiline:1;			//!< m - Multiline search.
	uint8_t dot_all:1;			//!< s - Singleline - '.' matches everything, including newlines.
	uint8_t unicode:1;			//!< u - Use unicode properties for character with code points
						///< greater than 127.
	uint8_t extended:1;			//!< x - Permit whitespace and comments.
} fr_regex_flags_t;

#define REGEX_FLAG_BUFF_SIZE	7

ssize_t		regex_flags_parse(int *err, fr_regex_flags_t *out, char const *in, size_t len, bool err_on_dup);
size_t		regex_flags_snprint(char *out, size_t outlen,
				    fr_regex_flags_t const flags[static REGEX_FLAG_BUFF_SIZE]);
ssize_t		regex_compile(TALLOC_CTX *ctx, regex_t **out, char const *pattern, size_t len,
			      fr_regex_flags_t const *flags, bool subcaptures, bool runtime);
int		regex_exec(regex_t *preg, char const *subject, size_t len, fr_regmatch_t *regmatch);
#ifdef HAVE_REGEX_PCRE2
int		regex_substitute(TALLOC_CTX *ctx, char **out, size_t max_out, regex_t *preg, fr_regex_flags_t *flags,
		     		 char const *subject, size_t subject_len,
		     		 char const *replacement, size_t replacement_len,
				 fr_regmatch_t *regmatch);
#endif
uint32_t	regex_subcapture_count(regex_t const *preg);
fr_regmatch_t	*regex_match_data_alloc(TALLOC_CTX *ctx, uint32_t count);
#  ifdef __cplusplus
}
#  endif
#endif
