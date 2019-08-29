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

int			password_normalise_and_replace(REQUEST *request, bool normify);

VALUE_PAIR		*password_find(bool *ephemeral, TALLOC_CTX *ctx, REQUEST *request,
				       fr_dict_attr_t const *allowed_attrs[],
				       size_t allowed_attrs_len, bool normify);

int			password_init(void);

void			password_free(void);

#ifdef __cplusplus
}
#endif
