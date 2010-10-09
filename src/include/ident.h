/*
 * $Id$
 *
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
 *
 * Copyright 2006 TRI-D Systems, Inc.
 */

#ifndef IDENT_H
#define IDENT_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
/* force inclusion of ident keywords in the face of optimization */
#define RCSID(id) static const char rcsid[] __attribute__ ((used)) = id;
#define RCSIDH(h, id) static const char rcsid_ ## h [] __attribute__ ((used)) = id;
#elif defined(__SUNPRO_C)
/* put ident keyword into comment section (nicer than gcc way) */
#define DO_PRAGMA(x) _Pragma(#x)
#define RCSID(id) DO_PRAGMA(sun ident id)
#define RCSIDH(h, id) DO_PRAGMA(sun ident id)
#else
#define RCSID(id)
#define RCSIDH(h, id)
#endif

#ifdef __cplusplus
}
#endif

#endif /* IDENT_H */
