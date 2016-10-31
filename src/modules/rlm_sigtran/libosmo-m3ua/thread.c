/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <thread.h>

#include <osmocom/core/talloc.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <string.h>
#include <unistd.h>

static void *tall_ctx_thr;

static int thread_finish(struct thread_notifier *not)
{
	pthread_mutex_destroy(&not->guard);
	close(not->fd[0]);
	close(not->fd[1]);

	return 0;
}

void thread_init(void)
{
	tall_ctx_thr = talloc_named_const(NULL, 1, "threads");
}

struct thread_notifier *thread_notifier_alloc()
{
	struct thread_notifier *not = talloc_zero(tall_ctx_thr, struct thread_notifier);
	if (!not)
		return NULL;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, not->fd) == -1) {
		talloc_free(not);
		return NULL;
	}

	if (pthread_mutex_init(&not->guard, NULL) != 0) {
		close(not->fd[0]);
		close(not->fd[1]);
		talloc_free(not);
		return NULL;
	}

	not->bfd.fd = not->fd[1];
	INIT_LLIST_HEAD(&not->__head1);
	INIT_LLIST_HEAD(&not->__head2);
	not->main_head = &not->__head1;
	not->thread_head = &not->__head2;
	talloc_set_destructor(not, thread_finish);
	return not;
}

void thread_safe_add(struct thread_notifier *not, struct llist_head *_new)
{
	char c = 1;
	pthread_mutex_lock(&not->guard);

	llist_add_tail(_new, not->thread_head);
	if (!not->no_write && write(not->fd[0], &c, sizeof(c)) != 1) {
		fprintf(stderr, "BAD NEWS. Socket write failed.\n");
	}

	pthread_mutex_unlock(&not->guard);
}

void thread_swap(struct thread_notifier *not)
{
	pthread_mutex_lock(&not->guard);

	if (not->main_head == &not->__head1) {
		not->main_head = &not->__head2;
		not->thread_head = &not->__head1;
	} else {
		not->main_head = &not->__head1;
		not->thread_head = &not->__head2;
	}

	pthread_mutex_unlock(&not->guard);
}
