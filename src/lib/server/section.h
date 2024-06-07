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
#include <freeradius-devel/server/cf_util.h>

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

/* Compare two sections based on name2
 *
 * Respects CF_IDENT_ANY values
 *
 * @param[in] a		First section name.
 * @param[in] b		Second section name.
 *
 * @return
 *	- 1 if name2 values match.
 *	- 0 if name2 values don't match.
 */
static inline int section_name2_match(section_name_t const *a, section_name_t const *b)
{
	if ((a->name2 == CF_IDENT_ANY) || (b->name2 == CF_IDENT_ANY)) return 1;
	if (!a->name2 || !b->name2) {
		if (a->name2 == b->name2) return 1;
		return 0;
	}

	return (strcmp(a->name2, b->name2) == 0) ? 1 : 0;
}

/* Compare two section names
 *
 * Respects CF_IDENT_ANY values
 *
 * @param[in] a		First section name.
 * @param[in] b		Second section name.
 *
 * @return
 *	- 1 if the section names match.
 *	- 0 if the section names don't match.
 *	- -1 if name1 doesn't match.
 *
 */
static inline int section_name_match(section_name_t const *a, section_name_t const *b)
{
	if ((a->name1 == CF_IDENT_ANY) || (b->name2 == CF_IDENT_ANY)) goto name2;

	if (strcmp(a->name1, b->name1) != 0) return -1;

name2:
	return section_name2_match(a, b);
}

/** Return a printable string for the section name
 *
 * @param[in] name		Section name.
 */
static inline char const *section_name_str(char const *name)
{
	if (name == NULL) return "NULL";
	if (name == CF_IDENT_ANY) return "*";
	return name;
}

static inline void section_name_dup(TALLOC_CTX *ctx, section_name_t *dst, section_name_t const *src)
{
	dst->name1 = src->name1;
	dst->name2 = src->name2;

	if (dst->name1 && (dst->name1 != CF_IDENT_ANY)) dst->name1 = talloc_typed_strdup(ctx, src->name1);
	if (dst->name2 && (dst->name2 != CF_IDENT_ANY)) dst->name2 = talloc_typed_strdup(ctx, src->name2);
}

int8_t section_name_cmp(void const *one, void const *two);

#ifdef __cplusplus
}
#endif
