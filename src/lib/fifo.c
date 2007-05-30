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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *  Copyright 2005,2006  The FreeRADIUS server project
 *  Copyright 2005  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>

typedef struct lrad_fifo_entry_t {
	struct lrad_fifo_entry_t *next;
	void			*data;
} lrad_fifo_entry_t;

struct lrad_fifo_t {
	lrad_fifo_entry_t *head, **tail;
	lrad_fifo_entry_t *freelist;

	int num_elements;
	int max_entries;
	lrad_fifo_free_t freeNode;
};


lrad_fifo_t *lrad_fifo_create(int max_entries, lrad_fifo_free_t freeNode)
{
	lrad_fifo_t *fi;

	if ((max_entries < 2) || (max_entries > (1024 * 1024))) return NULL;

	fi = malloc(sizeof(*fi));
	if (!fi) return NULL;

	memset(fi, 0, sizeof(*fi));

	fi->max_entries = max_entries;
	fi->freeNode = freeNode;

	return fi;
}

static void lrad_fifo_free_entries(lrad_fifo_t *fi, lrad_fifo_entry_t *head)
{
	lrad_fifo_entry_t *next;

	while (head) {
		next = head->next;

		if (fi->freeNode && head->data) fi->freeNode(head->data);
		free(head);

		head = next;
	}
}

void lrad_fifo_free(lrad_fifo_t *fi)
{
	if (!fi) return;

	lrad_fifo_free_entries(fi, fi->head);
	lrad_fifo_free_entries(fi, fi->freelist);

	free(fi);
}

static lrad_fifo_entry_t *lrad_fifo_alloc_entry(lrad_fifo_t *fi)
{
	lrad_fifo_entry_t *entry;

	if (fi->freelist) {
		entry = fi->freelist;
		fi->freelist = entry->next;
	} else {
		entry = malloc(sizeof(*entry));
		if (!entry) return NULL;
	}

	memset(entry, 0, sizeof(*entry));
	return entry;
}

int lrad_fifo_push(lrad_fifo_t *fi, void *data)
{
	lrad_fifo_entry_t *entry;

	if (!fi || !data) return 0;

	if (fi->num_elements >= fi->max_entries) return 0;

	entry = lrad_fifo_alloc_entry(fi);
	if (!entry) return 0;
	entry->data = data;

	if (!fi->head) {
		fi->head = entry;
	} else {
		*fi->tail = entry;
	}
	fi->tail = &(entry->next);

	fi->num_elements++;

	return 1;
}

static void lrad_fifo_free_entry(lrad_fifo_t *fi, lrad_fifo_entry_t *entry)
{
	entry->data = NULL;
	entry->next = fi->freelist;
	fi->freelist = entry->next;
}


void *lrad_fifo_pop(lrad_fifo_t *fi)
{
	void *data;
	lrad_fifo_entry_t *entry;

	if (!fi || !fi->head) return NULL;

	entry = fi->head;
	fi->head = entry->next;

	data = entry->data;
	lrad_fifo_free_entry(fi, entry);

	fi->num_elements--;

	if (!fi->head) {
		fi->tail = NULL;
		fi->num_elements = 0;
	}

	return data;
}

void *lrad_fifo_peek(lrad_fifo_t *fi)
{
	if (!fi || !fi->head) return NULL;

	return fi->head->data;
}

int lrad_fifo_num_elements(lrad_fifo_t *fi)
{
	if (!fi) return 0;

	return fi->num_elements;
}

#ifdef TESTING

/*
 *  cc -DTESTING -I .. fifo.c -o fifo
 *
 *  ./fifo
 */

#define MAX 1024
int main(int argc, char **argv)
{
	int i, array[MAX];
	lrad_fifo_t *fi;

	fi = lrad_fifo_create(MAX, NULL);
	if (!fi) exit(1);

	for (i = 0; i < MAX; i++) {
		array[i] = i;

		if (!lrad_fifo_push(fi, &array[i])) exit(2);
	}

	for (i = 0; i < MAX; i++) {
		int *p;

		p = lrad_fifo_pop(fi);
		if (!p) {
			fprintf(stderr, "No pop at %d\n", i);
			exit(3);
		}

		if (*p != i) exit(4);
	}

	exit(0);
}
#endif
