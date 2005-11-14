/*
 * fifo.c	Non-thread-safe fifo (FIFO) implementation, based
 *		on hash tables.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 *  Copyright 2005  The FreeRADIUS server project
 *  Copyright 2005  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] = "$Id$";

#include <freeradius-devel/autoconf.h>

#include <stdlib.h>
#include <string.h>

#include <freeradius-devel/missing.h>
#include <freeradius-devel/libradius.h>

/*
 *	The fifo is based on the hash tables, not for speed, but to
 *	allow the fifo to grow automatically.  If we put array code
 *	here to implement fifos, then we have to mix the semantics of
 *	fifo push/pull with array re-sizing, which could add bugs.
 */
struct lrad_fifo_t {
	lrad_hash_table_t *ht;
	int head;
	int tail;
	int max_entries;
};

lrad_fifo_t *lrad_fifo_create(int max_entries, void (*freeNode)(void *))
{
	lrad_fifo_t *fi;

	if ((max_entries < 2) || (max_entries > (1024 * 1024))) return NULL;

	fi = malloc(sizeof(*fi));
	if (!fi) return NULL;

	memset(fi, 0, sizeof(*fi));

	fi->ht = lrad_hash_table_create(5, freeNode, 0);
	if (!fi->ht) {
		free(fi);
		return NULL;
	}

	fi->max_entries = max_entries;

	return fi;
}

void lrad_fifo_free(lrad_fifo_t *fi)
{
	if (!fi) return;

	if (fi->ht) lrad_hash_table_free(fi->ht);

	free(fi);
}

int lrad_fifo_push(lrad_fifo_t *fi, void *data)
{
	if (!fi || !fi->ht || !data) return 0;

	if (lrad_hash_table_num_elements(fi->ht) >= fi->max_entries) return 0;

	if (!lrad_hash_table_insert(fi->ht, fi->tail, data)) return 0;

	fi->tail++;
	
	return 1;
}

void *lrad_fifo_pop(lrad_fifo_t *fi)
{
	void *data;

	if (!fi || !fi->ht) return 0;

	if (lrad_hash_table_num_elements(fi->ht) == 0) {
		fi->head = fi->tail = 0;
		return NULL;
	}

	data = lrad_hash_table_finddata(fi->ht, fi->head);
	if (!data) {
		/*
		 *	This is a SERIOUS error!
		 *	How do we recover from it?
		 *	What do we do?
		 */
		fi->head++;
		return NULL;
	}

	lrad_hash_table_delete(fi->ht, fi->head++);

	return data;
}

void *lrad_fifo_peek(lrad_fifo_t *fi)
{
	void *data;

	if (!fi || !fi->ht) return 0;

	if (lrad_hash_table_num_elements(fi->ht) == 0) {
		return NULL;
	}

	data = lrad_hash_table_finddata(fi->ht, fi->head);
	if (!data) {
		/*
		 *	This is a SERIOUS error!
		 *	How do we recover from it?
		 *	What do we do?
		 */
		return NULL;
	}

	return data;
}
