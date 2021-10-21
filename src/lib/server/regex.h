#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/regex.h
 * @brief Regular expression functions used by the server library.
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSIDH(server_regex_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_REGEX
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/talloc.h>

/*
 *	Increasing this is essentially free
 *	It just increases memory usage. 12-16 bytes for each additional subcapture.
 */
#  define REQUEST_MAX_REGEX 32

void	regex_sub_to_request(request_t *request, regex_t **preg, fr_regmatch_t **regmatch);

int	regex_request_to_sub(TALLOC_CTX *ctx, char **out, request_t *request, uint32_t num);

/*
 *	Named capture groups only supported by PCRE.
 */
#  if defined(HAVE_REGEX_PCRE2) || defined(HAVE_REGEX_PCRE)
int	regex_request_to_sub_named(TALLOC_CTX *ctx, char **out, request_t *request, char const *name);
#  endif
#endif

#ifdef __cplusplus
}
#endif
