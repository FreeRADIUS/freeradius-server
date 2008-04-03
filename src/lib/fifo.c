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

typedef struct fr_fifo_entry_t {
	struct fr_fifo_entry_t *next;
	void			*data;
} fr_fifo_entry_t;

struct fr_fifo_t {
	fr_fifo_entry_t *head, **tail;
	fr_fifo_entry_t *freelist;

	int num_elements;
	int max_entries;
	fr_fifo_free_t freeNode;
};


fr_fifo_t *fr_fifo_create(int max_entries, fr_fifo_free_t freeNode)
{
	fr_fifo_t *fi;

	if ((max_entries < 2) || (max_entries > (1024 * 1024))) return NULL;

	fi = malloc(sizeof(*fi));
	if (!fi) return NULL;

	memset(fi, 0, sizeof(*fi));

	fi->max_entries = max_entries;
	fi->freeNode = freeNode;

	return fi;
}

static void fr_fifo_free_entries(fr_fifo_t *fi, fr_fifo_entry_t *head)
{
	fr_fifo_entry_t *next;

	while (head) {
		next = head->next;

		if (fi->freeNode && head->data) fi->freeNode(head->data);
		free(head);

		head = next;
	}
}

void fr_fifo_free(fr_fifo_t *fi)
{
	if (!fi) return;

	fr_fifo_free_entries(fi, fi->head);
	fr_fifo_free_entries(fi, fi->freelist);

	free(fi);
}

static fr_fifo_entry_t *fr_fifo_alloc_entry(fr_fifo_t *fi)
{
	fr_fifo_entry_t *entry;

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

int fr_fifo_push(fr_fifo_t *fi, void *data)
{
	fr_fifo_entry_t *entry;

	if (!fi || !data) return 0;

	if (fi->num_elements >= fi->max_entries) return 0;

	entry = fr_fifo_alloc_entry(fi);
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

static void fr_fifo_free_entry(fr_fifo_t *fi, fr_fifo_entry_t *entry)
{
	entry->data = NULL;
	entry->next = fi->freelist;
	fi->freelist = entry;
}


void *fr_fifo_pop(fr_fifo_t *fi)
{
	void *data;
	fr_fifo_entry_t *entry;

	if (!fi || !fi->head) return NULL;

	entry = fi->head;
	fi->head = entry->next;

	data = entry->data;
	fr_fifo_free_entry(fi, entry);

	fi->num_elements--;

	if (!fi->head) {
		fi->tail = NULL;
		fi->num_elements = 0;
	}

	return data;
}

void *fr_fifo_peek(fr_fifo_t *fi)
{
	if (!fi || !fi->head) return NULL;

	return fi->head->data;
}

int fr_fifo_num_elements(fr_fifo_t *fi)
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
	fr_fifo_t *fi;

	fi = fr_fifo_create(MAX, NULL);
	if (!fi) exit(1);

	for (i = 0; i < MAX; i++) {
		array[i] = i;

		if (!fr_fifo_push(fi, &array[i])) exit(2);
	}

	for (i = 0; i < MAX; i++) {
		int *p;

		p = fr_fifo_pop(fi);
		if (!p) {
			fprintf(stderr, "No pop at %d\n", i);
			exit(3);
		}

		if (*p != i) exit(4);
	}

	exit(0);
}
#endif
