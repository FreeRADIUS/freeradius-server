#ifndef RAD_ASSERT_H
#define RAD_ASSERT_H
/*
 * rad_assert.h	  Debug assertions, with logging.
 *
 * Version:	$Id$
 *
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000,2001  The FreeRADIUS server project
 */

extern void rad_assert_fail (const char *file, unsigned int line);

#ifdef NDEBUG
	#define rad_assert(expr) ((void) (0))
#else
	#define rad_assert(expr) \
		((void) ((expr) ? 0 : \
			rad_assert_fail (__FILE__, __LINE__)))
#endif

#endif
