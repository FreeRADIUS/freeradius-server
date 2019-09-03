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
RCSID("$Id$")

#include <string.h>
#include <talloc.h>

#include <freeradius-devel/util/fifo.h>

struct fr_fifo_t {
	unsigned int	num;		//!< How many elements exist in the fifo.
	unsigned int	first, last;	//!< Head and tail indexes for the fifo.
	unsigned int	max;		//!< How many elements were created in the fifo.
	fr_fifo_free_t	free_node;	//!< Function to call to free nodes when the fifo is freed.

	char const	*type;		//!< Type of elements.

	void *data[1];
};

/** Free a fifo and optionally, any data still enqueued
 *
 * @param[in] fi	to free.
 * @return 0
 */
static int _fifo_free(fr_fifo_t *fi)
{
	unsigned int i;

	if (fi->free_node) {
		for (i = 0 ; i < fi->num; i++) {
			unsigned int element;

			element = i + fi->first;
			if (element > fi->max) {
				element -= fi->max;
			}

			fi->free_node(fi->data[element]);
			fi->data[element] = NULL;
		}
	}

	memset(fi, 0, sizeof(*fi));

	return 0;
}

/** Create a fifo queue
 *
 * The first element enqueued will be the first to be dequeued.
 *
 * @note The created fifo does not provide any thread synchronisation functionality
 *	such as mutexes.  If multiple threads are enqueueing and dequeueing data
 *	the callers must synchronise their access.
 *
 * @param[in] ctx	to allocate fifo array in.
 * @param[in] type	Talloc type of elements (may be NULL).
 * @param[in] max	The maximum number of elements allowed.
 * @param[in] free_node	Function to use to free node data if the fifo is freed.
 * @return
 *	- A new fifo queue.
 *	- NULL on error.
 */
fr_fifo_t *_fr_fifo_create(TALLOC_CTX *ctx, char const *type, int max, fr_fifo_free_t free_node)
{
	fr_fifo_t *fi;

	if ((max < 2) || (max > (1024 * 1024))) return NULL;

	fi = talloc_zero_size(ctx, (sizeof(*fi) + (sizeof(fi->data[0])*max)));
	if (!fi) return NULL;
	talloc_set_type(fi, fr_fifo_t);
	talloc_set_destructor(fi, _fifo_free);

	fi->max = max;
	fi->type = type;
	fi->free_node = free_node;

	return fi;
}

/** Push data onto the fifo
 *
 * @param[in] fi	FIFO to push data onto.
 * @param[in] data	to push.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int fr_fifo_push(fr_fifo_t *fi, void *data)
{
	if (!fi || !data) return -1;

	if (fi->num >= fi->max) return -1;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (fi->type) _talloc_get_type_abort(data, fi->type, __location__);
#endif

	fi->data[fi->last++] = data;
	if (fi->last >= fi->max) fi->last = 0;
	fi->num++;

	return 0;
}

/** Pop data off of the fifo
 *
 * @param[in] fi	FIFO to pop data from.
 * @return
 *	- The data popped.
 *	- NULL if the queue is empty.
 */
void *fr_fifo_pop(fr_fifo_t *fi)
{
	void *data;

	if (!fi || (fi->num == 0)) return NULL;

	data = fi->data[fi->first++];

	if (fi->first >= fi->max) {
		fi->first = 0;
	}
	fi->num--;

	return data;
}

/** Examine the next element that would be popped
 *
 * @param[in] fi	FIFO to peek at.
 * @return
 *	- The data at the head of the queue
 *	- NULL if the queue is empty.
 */
void *fr_fifo_peek(fr_fifo_t *fi)
{
	if (!fi || (fi->num == 0)) return NULL;

	return fi->data[fi->first];
}

/** Return the number of elements in the fifo queue
 *
 * @param[in] fi	FIFO to count elements in.
 * @return the number of elements
 */
unsigned int fr_fifo_num_elements(fr_fifo_t *fi)
{
	if (!fi) return 0;

	return fi->num;
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
	int i, j, array[MAX];
	fr_fifo_t *fi;

	fi = fr_fifo_create(NULL, MAX, NULL);
	if (!fi) fr_exit(1);

	for (j = 0; j < 5; j++) {
#define SPLIT (MAX/3)
#define COUNT ((j * SPLIT) + i)
		for (i = 0; i < SPLIT; i++) {
			array[COUNT % MAX] = COUNT;

			if (fr_fifo_push(fi, &array[COUNT % MAX]) < 0) {
				fprintf(stderr, "%d %d\tfailed pushing %d\n",
					j, i, COUNT);
				fr_exit(2);
			}

			if (fr_fifo_num_elements(fi) != (i + 1)) {
				fprintf(stderr, "%d %d\tgot size %d expected %d\n",
					j, i, i + 1, fr_fifo_num_elements(fi));
				fr_exit(1);
			}
		}

		if (fr_fifo_num_elements(fi) != SPLIT) {
			fprintf(stderr, "HALF %d %d\n",
				fr_fifo_num_elements(fi), SPLIT);
			fr_exit(1);
		}

		for (i = 0; i < SPLIT; i++) {
			int *p;

			p = fr_fifo_pop(fi);
			if (!p) {
				fprintf(stderr, "No pop at %d\n", i);
				fr_exit(3);
			}

			if (*p != COUNT) {
				fprintf(stderr, "%d %d\tgot %d expected %d\n",
					j, i, *p, COUNT);
				fr_exit(4);
			}

			if (fr_fifo_num_elements(fi) != SPLIT - (i + 1)) {
				fprintf(stderr, "%d %d\tgot size %d expected %d\n",
					j, i, SPLIT - (i + 1), fr_fifo_num_elements(fi));
				fr_exit(1);
			}
		}

		if (fr_fifo_num_elements(fi) != 0) {
			fprintf(stderr, "ZERO %d %d\n",
				fr_fifo_num_elements(fi), 0);
			fr_exit(1);
		}
	}

	talloc_free(fi);

	fr_exit(0);
}
#endif
