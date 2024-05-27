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
 * @file lib/server/section.h
 * @brief Structures which identify sections
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(section_h, "$Id$")

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Define a section name consisting of a verb and a noun
 *
 * @param[in] _name1		verb name.
 * @param[in] _name2		noun name.
 */
#define SECTION_NAME(_name1, _name2) &(section_name_t){ .name1 = _name1, .name2 = _name2 }

/** Section name identifier
 */
typedef struct {
	char const *name1;		//!< First section name.  Usually a verb like 'recv', 'send', etc...
	char const *name2;		//!< Second section name.  Usually a packet type like 'access-request', 'access-accept', etc...
} section_name_t;

int8_t section_name_cmp(void const *one, void const *two);

bool section_name_match(section_name_t const *a, section_name_t const *b);

#ifdef __cplusplus
}
#endif
