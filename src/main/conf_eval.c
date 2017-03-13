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
 * @file conf_eval.c
 * @brief Evaluate configuration files, taking pre-parsed data and converting it into
 *	module's configuration structures.
 *
 * @copyright 2017 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000-2017  The FreeRADIUS server project
 * @copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */
 RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>
