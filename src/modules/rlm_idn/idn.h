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

/*
 * $Id$
 *
 * @brief Function prototypes and datatypes for IDN support module.
 * @file idn.h
 *
 * @copyright 2013  Brian S. Julin <bjulin@clarku.edu>
 */

RCSIDH(other_h, "$Id$")

/*
 *	Structure for module configuration
 */
typedef struct rlm_idn_t {
	char const *xlat_name;
	int UseSTD3ASCIIRules;
	int AllowUnassigned;
} rlm_idn_t;

