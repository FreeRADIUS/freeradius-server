#ifndef _RLM_EXPR_H
#define _RLM_EXPR_H
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
 *
 * Copyright 2007  The FreeRADIUS server project
 * Copyright 2007  Alan DeKok <aland@ox.org>
 */
#include <freeradius-devel/ident.h>
#include <limits.h>

RCSIDH(rlm_expr_h, "$Id$")

void pair_builtincompare_init(void);
void pair_builtincompare_detach(void);
long long strtonum(const char *nptr, long long minval, long long maxval, const char **errstr);
#endif
