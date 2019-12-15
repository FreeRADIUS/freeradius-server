#pragma once
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

/** Non-thread-safe fifo (FIFO) implementation
 *
 * @file src/lib/util/fifo.c
 *
 * @copyright 2005,2006 The FreeRADIUS server project
 * @copyright 2005 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(fifo_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <talloc.h>

typedef struct fr_fifo_s fr_fifo_t;
typedef void (*fr_fifo_free_t)(void *);

/** Creates a fifo that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		to tie fifo lifetime to.
 *				If ctx is freed, fifo will free any nodes, calling the
 *				free function if set.
 * @param[in] _max_entries	Maximum number of entries.
 * @param[in] _talloc_type	of elements.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new fifo on success.
 *	- NULL on failure.
 */
#define fr_fifo_talloc_create(_ctx, _talloc_type, _max_entries, _node_free) \
	_fr_fifo_create(_ctx, #_talloc_type, _max_entries, _node_free)

/** Creates a fifo
 *
 * @param[in] _ctx		to tie fifo lifetime to.
 *				If ctx is freed, fifo will free any nodes, calling the
 *				free function if set.
 * @param[in] _max_entries	Maximum number of entries.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new fifo on success.
 *	- NULL on failure.
 */
#define fr_fifo_create(_ctx, _max_entries, _node_free) \
	_fr_fifo_create(_ctx, NULL, _max_entries, _node_free)

fr_fifo_t	*_fr_fifo_create(TALLOC_CTX *ctx, char const *type, int max_entries, fr_fifo_free_t free_node);
int		fr_fifo_push(fr_fifo_t *fi, void *data);
void		*fr_fifo_pop(fr_fifo_t *fi);
void		*fr_fifo_peek(fr_fifo_t *fi);
unsigned int	fr_fifo_num_elements(fr_fifo_t *fi);

#ifdef __cplusplus
}
#endif
