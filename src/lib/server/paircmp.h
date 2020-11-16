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
 * @file lib/server/paircmp.h
 * @brief Legacy paircomparison function
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(paircmp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>

/* for paircmp_register */
typedef int (*RAD_COMPARE_FUNC)(void *instance, request_t *,fr_pair_list_t *, fr_pair_t *, fr_pair_list_t *);

int		paircmp_pairs(request_t *request, fr_pair_t *check, fr_pair_t *vp);

int		paircmp(request_t *request, fr_pair_list_t *request_list, fr_pair_list_t *check_list);

int		paircmp_find(fr_dict_attr_t const *da);

int		paircmp_register_by_name(char const *name, fr_dict_attr_t const *from,
					 bool first_only, RAD_COMPARE_FUNC func, void *instance);

int		paircmp_register(fr_dict_attr_t const *attribute, fr_dict_attr_t const *from,
				 bool first_only, RAD_COMPARE_FUNC func, void *instance);

void		paircmp_unregister(fr_dict_attr_t const *attr, RAD_COMPARE_FUNC func);

void		paircmp_unregister_instance(void *instance);

int		paircmp_init(void);

void		paircmp_free(void);

#ifdef __cplusplus
}
#endif
