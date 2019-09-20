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

/** Routines to parse Ascend's filter attributes
 *
 * @file src/lib/util/ascend.h
 *
 * @copyright 2003,2006 The FreeRADIUS server project
 */
RCSIDH(ascend_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WITH_ASCEND_BINARY
#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/value.h>

/* filters.c */
int		ascend_parse_filter(fr_value_box_t *out, char const *value, size_t len);
size_t		print_abinary(size_t *need, char *out, size_t outlen, uint8_t const *data, size_t len, int8_t quote);
#endif /*WITH_ASCEND_BINARY*/

#ifdef __cplusplus
}
#endif
