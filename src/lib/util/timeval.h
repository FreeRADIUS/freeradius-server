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
 * $Id$
 *
 * @brief Functions for manipulating timeval structures
 * @file lib/util/timeval.h
 *
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(timeval_h, "$Id$")

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif
void		fr_timeval_subtract(struct timeval *out, struct timeval const *end, struct timeval const *start);
int		fr_timeval_from_str(struct timeval *out, char const *in);

#ifdef __cplusplus
}
#endif
