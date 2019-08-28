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

/**
 * @file src/lib/server/password.h
 * @brief Password normalisation functions
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 */
RCSIDH(password_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/request.h>

typedef ssize_t(*password_header_lookup_t)(fr_dict_attr_t const **out, char const *header);

VALUE_PAIR *password_normify(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR const *known_good, size_t min_len);

VALUE_PAIR *password_normify_with_header(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR *known_good,
					 password_header_lookup_t func, fr_dict_attr_t const *def);

VALUE_PAIR *password_normalise(REQUEST *request, bool normalise);

int password_init(void);
void password_free(void);

#ifdef __cplusplus
}
#endif
