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
 * @file lib/server/users_file.h
 * @brief Support functions for users_file parsing.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(users_file_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/map.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>

typedef struct pair_list {
	char const		*name;		//!< Key for matching entry.
	fr_map_list_t		check;		//!< List of maps for comparison / modifying control list
	fr_map_list_t		reply;		//!< List of maps for modifying reply list
	int			order;		//!< Sequence of entry in source file
	char const		*filename;	//!< Filename entry read from
	int			lineno;		//!< Line number entry read from
	fr_dlist_t		entry;		//!< Entry in dlist of PAIR_LIST with matching name
} PAIR_LIST;

typedef struct pair_list_list {
	fr_dlist_head_t 	head;		//!< Head of the list of PAIR_LISTs.
	fr_rb_node_t		node;		//!< Entry into the tree of pair lists.
	char const		*name;		//!< Key used for matching entry.
} PAIR_LIST_LIST;

/* users_file.c */
int		pairlist_read(TALLOC_CTX *ctx, fr_dict_t const *dict, char const *file, PAIR_LIST **list, int complain);
void		pairlist_free(PAIR_LIST_LIST *);

static inline void pairlist_list_init(PAIR_LIST_LIST *list) {
	fr_dlist_talloc_init(&list->head, PAIR_LIST, entry);
}

#ifdef __cplusplus
}
#endif
