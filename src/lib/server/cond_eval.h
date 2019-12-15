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
 * @file lib/server/cond_eval.h
 * @brief Structures and prototypes for the condition evaluation code
 *
 * @copyright 2007 The FreeRADIUS server project
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */
RCSIDH(cond_eval_h, "$Id$")

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/value.h>

#ifdef __cplusplus
extern "C" {
#endif

/* evaluate.c */
typedef struct fr_cond_s fr_cond_t;
int	cond_eval_tmpl(REQUEST *request, int modreturn, int depth, vp_tmpl_t const *vpt);
int	cond_eval_map(REQUEST *request, int modreturn, int depth, fr_cond_t const *c);
int	cond_eval(REQUEST *request, int modreturn, int depth, fr_cond_t const *c);

#ifdef __cplusplus
}
#endif
