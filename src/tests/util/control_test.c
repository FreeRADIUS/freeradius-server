/*
 * control_test.c	Tests for control planes
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

#include <freeradius-devel/io/control.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/syserror.h>

#include <sys/event.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#undef MEM
#define MEM(x) if (!(x)) { fprintf(stderr, "%s[%u] OUT OF MEMORY\n", __FILE__, __LINE__); _exit(EXIT_FAILURE); }
#define MPRINT1 if (debug_lvl) printf
#define CONTROL_MAGIC 0xabcd6809

static int		debug_lvl = 0;
static int		kq = -1;
static fr_atomic_queue_t *aq;
static size_t		max_messages = 10;
static int		aq_size = 16;
static fr_control_t	*control = NULL;
static fr_ring_buffer_t *rb = NULL;

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
	fprintf(stderr, "usage: control_test [OPTS]\n");
	fprintf(stderr, "  -m <messages>	  Send number of messages.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(EXIT_SUCCESS);
}

typedef struct {
	uint32_t		header;
	size_t			counter;
} my_message_t;

static void *control_master(UNUSED void *arg)
{
	TALLOC_CTX *ctx;

	MEM(ctx = talloc_init("control_master"));

	MPRINT1("Master started.\n");

	/*
	 *	Busy loop.  We're stupid.
	 */
	while (true) {
		int num_events;
		ssize_t data_size;
		my_message_t m;
		struct kevent kev;

	wait_for_events:
		MPRINT1("Master waiting for events.\n");

		num_events = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (num_events < 0) {
			fprintf(stderr, "Failed reading kevent: %s\n", fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		MPRINT1("Master draining the control plane.\n");

		while (true) {
			uint32_t id;

			data_size = fr_control_message_pop(aq, &id, &m, sizeof(m));
			if (data_size == 0) goto wait_for_events;

			if (data_size < 0) {
				fprintf(stderr, "Failed reading control message\n");
				exit(EXIT_FAILURE);
			}

			fr_assert(data_size == sizeof(m));
			fr_assert(id == FR_CONTROL_ID_CHANNEL);

			MPRINT1("Master got message %zu.\n", m.counter);

			fr_assert(m.header == CONTROL_MAGIC);

			if (m.counter == (max_messages - 1)) goto do_exit;
		}
	}

do_exit:
	MPRINT1("Master exiting.\n");

	talloc_free(ctx);

	return NULL;
}

static void *control_worker(UNUSED void *arg)
{
	size_t i;
	TALLOC_CTX *ctx;

	MEM(ctx = talloc_init("control_worker"));

	MPRINT1("\tWorker started.\n");

	for (i = 0; i < max_messages; i++) {
		my_message_t m;

		m.header = CONTROL_MAGIC;
		m.counter = i;

retry:
		if (fr_control_message_send(control, rb, FR_CONTROL_ID_CHANNEL, &m, sizeof(m)) < 0) {
			MPRINT1("\tWorker retrying message %zu\n", i);
			usleep(10);
			goto retry;
		}

		MPRINT1("\tWorker sent message %zu\n", i);
	}

	MPRINT1("\tWorker exiting.\n");

	talloc_free(ctx);

	return NULL;
}



int main(int argc, char *argv[])
{
	int 			c;
	TALLOC_CTX		*autofree = talloc_autofree_context();
	pthread_attr_t		attr;
	pthread_t		master_id, worker_id;

	fr_time_start();

	while ((c = getopt(argc, argv, "hm:o:tx")) != -1) switch (c) {
		case 'x':
			debug_lvl++;
			break;

		case 'm':
			max_messages = atoi(optarg);
			break;

		case 'h':
		default:
			usage();
	}

#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	kq = kqueue();
	fr_assert(kq >= 0);

	aq = fr_atomic_queue_create(autofree, aq_size);
	fr_assert(aq != NULL);

	control = fr_control_create(autofree, kq, aq, 1024);
	if (!control) {
		fprintf(stderr, "control_test: Failed to create control plane\n");
		exit(EXIT_FAILURE);
	}

	rb = fr_ring_buffer_create(autofree, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!rb) exit(EXIT_FAILURE);

	/*
	 *	Start the two threads, with the channel.
	 */
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	(void) pthread_create(&worker_id, &attr, control_worker, NULL);
	(void) pthread_create(&master_id, &attr, control_master, NULL);

	(void) pthread_join(master_id, NULL);
	(void) pthread_join(worker_id, NULL);

	close(kq);

	exit(EXIT_SUCCESS);
}
