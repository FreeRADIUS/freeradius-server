/*
 * atomic_queue_test.c	Tests for atomic queues
 *
 * Version:	$Id$
 *
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
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/io/atomic_queue.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <freeradius-devel/server/rad_assert.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#define OFFSET	(1024)

static int		debug_lvl = 0;


/**********************************************************************/
typedef struct fr_request_s REQUEST;
REQUEST *request_alloc(UNUSED TALLOC_CTX *ctx);
void request_verify(UNUSED char const *file, UNUSED int line, UNUSED REQUEST *request);
int talloc_const_free(void const *ptr);

REQUEST *request_alloc(UNUSED TALLOC_CTX *ctx)
{
	return NULL;
}

void request_verify(UNUSED char const *file, UNUSED int line, UNUSED REQUEST *request)
{
}

int talloc_const_free(void const *ptr)
{
	void *tmp;
	if (!ptr) return 0;

	memcpy(&tmp, &ptr, sizeof(tmp));
	return talloc_free(tmp);
}
/**********************************************************************/


static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: atomic_queue_test [OPTS]\n");
	fprintf(stderr, "  -s size                set queue size.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int			c, i, rcode = 0;
	int			size;
	intptr_t		val;
	void			*data;
	fr_atomic_queue_t	*aq;
	TALLOC_CTX		*autofree = talloc_autofree_context();

	size = 4;

	while ((c = getopt(argc, argv, "hs:tx")) != -1) switch (c) {
		case 's':
			size = atoi(optarg);
			break;

		case 'x':
			debug_lvl++;
			break;

		case 'h':
		default:
			usage();
	}
#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	aq = fr_atomic_queue_create(autofree, size);

#ifndef NDEBUG
	if (debug_lvl) {
		printf("Start\n");
		fr_atomic_queue_debug(aq, stdout);

		if (debug_lvl > 1) printf("Filling with %d\n", size);
	}

#endif


	for (i = 0; i < size; i++) {
		val = i + OFFSET;
		data = (void *) val;

		if (!fr_atomic_queue_push(aq, data)) {
			fprintf(stderr, "Failed pushing at %d\n", i);
			exit(EXIT_FAILURE);
		}

#ifndef NDEBUG
		if (debug_lvl > 1) {
			printf("iteration %d\n", i);
			fr_atomic_queue_debug(aq, stdout);
		}
#endif
	}

	val = size + OFFSET;
	data = (void *) val;

	/*
	 *	Queue is full.  No more pushes are allowed.
	 */
	if (fr_atomic_queue_push(aq, data)) {
		fprintf(stderr, "Pushed an entry past the end of the queue.");
		exit(EXIT_FAILURE);
	}

#ifndef NDEBUG
	if (debug_lvl) {
		printf("Full\n");
		fr_atomic_queue_debug(aq, stdout);

		if (debug_lvl > 1) printf("Emptying\n");
	}
#endif

	/*
	 *	And now pop them all.
	 */
	for (i = 0; i < size; i++) {
		if (!fr_atomic_queue_pop(aq, &data)) {
			fprintf(stderr, "Failed popping at %d\n", i);
			exit(EXIT_FAILURE);
		}

		val = (intptr_t) data;
		if (val != (i + OFFSET)) {
			fprintf(stderr, "Pop expected %d, got %d\n",
				i + OFFSET, (int) val);
			exit(EXIT_FAILURE);
		}

#ifndef NDEBUG
		if (debug_lvl > 1) {
			printf("iteration %d\n", i);
			fr_atomic_queue_debug(aq, stdout);
		}
#endif
	}

	/*
	 *	Queue is empty.  No more pops are allowed.
	 */
	if (fr_atomic_queue_pop(aq, &data)) {
		fprintf(stderr, "Popped an entry past the end of the queue.");
		exit(EXIT_FAILURE);
	}

#ifndef NDEBUG
	if (debug_lvl) {
		printf("Empty\n");
		fr_atomic_queue_debug(aq, stdout);
	}
#endif

	return rcode;
}

