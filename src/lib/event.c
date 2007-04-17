/*
 * event.c	Non-thread-safe event handling, specific to a RADIUS
 *		server.
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
 *  Copyright 2007  The FreeRADIUS server project
 *  Copyright 2007  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/event.h>

typedef struct lrad_event_fd_t {
	int			fd;
	int			priority;
	lrad_event_callback_t	callback;
	void			*ctx;
	struct lrad_event_fd_t	*next;
} lrad_event_fd_t;

struct lrad_event_list_t {
	rbtree_t	*times;

	lrad_event_fd_t *fds;
	int		maxfd;
	fd_set		readfds;

	int		exit;

	struct timeval  now;
	int		dispatch;
};

/*
 *	Internal structure for managing events.
 */
struct lrad_event_t {
	lrad_event_callback_t	callback;
	void			*ctx;
	struct timeval		when;
};


static int lrad_event_list_time_cmp(const void *one, const void *two)
{
	const lrad_event_t *a = one;
	const lrad_event_t *b = two;

	if (a->when.tv_sec < b->when.tv_sec) return -1;
	if (a->when.tv_sec > b->when.tv_sec) return +1;

	if (a->when.tv_usec < b->when.tv_usec) return -1;
	if (a->when.tv_usec > b->when.tv_usec) return +1;

	return 0;
}


void lrad_event_list_free(lrad_event_list_t *el)
{
	if (!el) return;

	rbtree_free(el->times);
	free(el);
}


lrad_event_list_t *lrad_event_list_create(void)
{
	lrad_event_list_t *el;

	el = malloc(sizeof(*el));
	if (!el) return NULL;
	memset(el, 0, sizeof(*el));

	el->times = rbtree_create(lrad_event_list_time_cmp,
				  free, 0);
	if (!el->times) {
		lrad_event_list_free(el);
		return NULL;
	}

	return el;
}

int lrad_event_list_num_elements(lrad_event_list_t *el)
{
	if (!el) return 0;

	return rbtree_num_elements(el->times);
}


int lrad_event_delete(lrad_event_list_t *el, lrad_event_t **ev_p)
{
	if (!el || !ev_p || !*ev_p) return 0;

	rbtree_deletebydata(el->times, *ev_p);
	*ev_p = NULL;

	return 1;
}

		      
lrad_event_t *lrad_event_insert(lrad_event_list_t *el,
				lrad_event_callback_t callback,
				void *ctx, struct timeval *when)
{
	lrad_event_t *ev;

	if (!el || !callback | !when) return 0;

	ev = malloc(sizeof(*ev));
	if (!ev) return NULL;
	memset(ev, 0, sizeof(*ev));

	ev->callback = callback;
	ev->ctx = ctx;
	ev->when = *when;

	/*
	 *	There's a tiny chance that two events will be
	 *	scheduled at the same time.  If this happens, we
	 *	increase the usec counter by 1, in order to avoid the
	 *	duplicate.  If we can't insert it after 10 tries, die.
	 */
	if (!rbtree_insert(el->times, ev)) {
		if (rbtree_finddata(el->times, ev)) {
			int i;

			for (i = 0; i < 10; i++) {
				ev->when.tv_usec++;
				if (ev->when.tv_usec >= 1000000) {
					ev->when.tv_usec = 0;
					ev->when.tv_sec++;
				}

				if (rbtree_finddata(el->times, ev)) {
					continue;
				}

				if (!rbtree_insert(el->times, ev)) {
					break;
				}

				return ev;
			}
				
		}
		free(ev);
		return NULL;
	}

	return ev;
}

typedef struct lrad_event_walk_t {
	lrad_event_t *ev;
	struct timeval when;
} lrad_event_walk_t;


static int lrad_event_find_earliest(void *ctx, void *data)
{
	lrad_event_t *ev = data;
	lrad_event_walk_t *w = ctx;

	if (ev->when.tv_sec > w->when.tv_sec) {
		w->when = ev->when;
		return 1;
	}

	if ((ev->when.tv_sec == w->when.tv_sec) &&
	    (ev->when.tv_usec > w->when.tv_usec)) {
		w->when = ev->when;
		return 1;
	}

	w->ev = ev;
	return 1;	
}


int lrad_event_run(lrad_event_list_t *el, struct timeval *when)
{
	lrad_event_callback_t callback;
	void *ctx;
	lrad_event_walk_t w;

	if (!el) return 0;

	w.ev = NULL;
	w.when = *when;

	if (rbtree_num_elements(el->times) == 0) {
		when->tv_sec = 0;
		when->tv_usec = 0;
		return 0;
	}

	rbtree_walk(el->times, InOrder, lrad_event_find_earliest, &w);
	if (!w.ev) {
		*when = w.when;
		return 0;
	}

	callback = w.ev->callback;
	ctx = w.ev->ctx;

	/*
	 *	Delete the event before calling it.
	 */
	rbtree_deletebydata(el->times, w.ev);

	callback(ctx);
	return 1;
}


int lrad_event_now(lrad_event_list_t *el, struct timeval *when)
{
	if (!el || !when || !el->dispatch) return 0;

	*when = el->now;
	return 1;
}

#ifdef TESTING

/*
 *  cc -g -I .. -c rbtree.c -o rbtree.o && cc -g -I .. -c isaac.c -o isaac.o && cc -DTESTING -I .. -c event.c  -o event_mine.o && cc event_mine.o rbtree.o isaac.o -o event
 *
 *  ./event
 *
 *  And hit CTRL-S to stop the output, CTRL-Q to continue.
 *  It normally alternates printing the time and sleeping,
 *  but when you hit CTRL-S/CTRL-Q, you should see a number
 *  of events run right after each other.
 *
 *  OR
 *
 *   valgrind --tool=memcheck --leak-check=full --show-reachable=yes ./event
 */

static void print_time(void *ctx)
{
	struct timeval *when = ctx;

	printf("%d.%06d\n", when->tv_sec, when->tv_usec);
	fflush(stdout);
}

static lrad_randctx rand_pool;

static uint32_t event_rand(void)
{
	uint32_t num;

	num = rand_pool.randrsl[rand_pool.randcnt++];
	if (rand_pool.randcnt == 256) {
		lrad_isaac(&rand_pool);
		rand_pool.randcnt = 0;
	}

	return num;
}


#define MAX 100
int main(int argc, char **argv)
{
	int i, rcode;
	struct timeval array[MAX];
	struct timeval now, when;
	lrad_event_list_t *el;

	el = lrad_event_list_create();
	if (!el) exit(1);
	
	memset(&rand_pool, 0, sizeof(rand_pool));
	rand_pool.randrsl[1] = time(NULL);
	
	lrad_randinit(&rand_pool, 1);
	rand_pool.randcnt = 0;

	gettimeofday(&array[0], NULL);
	for (i = 1; i < MAX; i++) {
		array[i] = array[i - 1];

		array[i].tv_usec += event_rand() & 0xffff;
		if (array[i].tv_usec > 1000000) {
			array[i].tv_usec -= 1000000;
			array[i].tv_sec++;
		}
		lrad_event_insert(el, print_time, &array[i], &array[i]);
	}
	
	while (lrad_event_list_num_elements(el)) {
		gettimeofday(&now, NULL);
		when = now;
		if (!lrad_event_run(el, &when)) {
			int delay = (when.tv_sec - now.tv_sec) * 1000000;
			delay += when.tv_usec;
			delay -= now.tv_usec;

			printf("\tsleep %d\n", delay);
			fflush(stdout);
			usleep(delay);
		}
	}

	lrad_event_list_free(el);

	return 0;
}
#endif
