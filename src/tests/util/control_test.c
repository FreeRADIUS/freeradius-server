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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/time.h>

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
#define MPRINT2 if (debug_lvl >= 2) printf
#define MPRINT3 if (debug_lvl >= 3) printf
#define CONTROL_MAGIC 0xabcd6809

typedef struct {
	size_t	id;
	fr_ring_buffer_t *rb;
} worker_args_t;

static int		debug_lvl = 0;
static fr_atomic_queue_t **aq;
static size_t		max_messages = 10;
static size_t		num_workers = 1;
static int		aq_size = 16;
static fr_control_t	**control = NULL;
static fr_event_list_t	*el = NULL;
static bool		single_aq = true;
static size_t		num_aq = 1;

/**********************************************************************/

static NEVER_RETURNS void usage(void)
{
	fprintf(stderr, "usage: control_test [OPTS]\n");
	fprintf(stderr, "  -m <messages>	  Send number of messages.\n");
	fprintf(stderr, "  -w <workers>           Number of workers.\n");
	fprintf(stderr, "  -q                     Use per-worker atomic queues.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	fr_exit_now(EXIT_SUCCESS);
}

typedef struct {
	uint32_t		header;
	size_t			counter;
	size_t			worker;
} my_message_t;

typedef struct {
	size_t			num_messages;
} master_ctx_t;

static void recv_control_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	my_message_t const	*m = data;
	master_ctx_t		*master_ctx = ctx;

	fr_assert(m->header == CONTROL_MAGIC);
	fr_assert(data_size == sizeof(*m));

	MPRINT2("Master got worker %ld message %zu, size %ld.\n", m->worker, m->counter, data_size);
	if (m->counter == (max_messages - 1)) MPRINT1("Master seen all messages from worker %ld\n", m->worker);
	master_ctx->num_messages++;
}

static void *control_master(UNUSED void *arg)
{
	TALLOC_CTX *ctx;
	master_ctx_t *master_ctx;
	size_t i;
	fr_time_t start;

	MEM(ctx = talloc_init_const("control_master"));

	master_ctx = talloc_zero(ctx, master_ctx_t);

	MPRINT1("Master started.\n");

	for (i = 0; i < num_aq; i++) {
		fr_control_callback_add(&control[i], FR_CONTROL_ID_CHANNEL, master_ctx, recv_control_callback);
		fr_control_open(control[i]);
	}

	start = fr_time();
	while (master_ctx->num_messages < (max_messages * num_workers)) {
		int num_events;

		MPRINT3("Master waiting for events (seen %ld).\n", master_ctx->num_messages);

		num_events = fr_event_corral(el, fr_time(), true);
		if (num_events < 0) {
			fprintf(stderr, "Failed reading kevent: %s\n", fr_syserror(errno));
			fr_exit_now(EXIT_FAILURE);
		}
		if (num_events > 0) {
			fr_event_service(el);
		}
	}
	MPRINT1("Master exiting. Seen %zu messages. %.2f per second\n",
		master_ctx->num_messages,
		((double)master_ctx->num_messages * 1e6) /
		(double)fr_time_delta_to_usec(fr_time_sub_time_time(fr_time(), start)));

	talloc_free(ctx);

	return NULL;
}

static void *control_worker(void *arg)
{
	size_t i, aq_num;
	TALLOC_CTX *ctx;
	worker_args_t *wa = (worker_args_t *) arg;

	MEM(ctx = talloc_init_const("control_worker"));

	aq_num = single_aq ? 0 : wa->id;

	MPRINT1("\tWorker %ld started using queue %ld.\n", wa->id, aq_num);

	for (i = 0; i < max_messages; i++) {
		my_message_t m;
		int delay = 0;

		m.header = CONTROL_MAGIC;
		m.counter = i;
		m.worker = wa->id;

retry:
		if (fr_control_message_send(control[aq_num], wa->rb, FR_CONTROL_ID_CHANNEL, &m, sizeof(m)) < 0) {
			char const *err;
			MPRINT1("\tWorker %ld retrying message %zu\n", wa->id, i);
			while ((err = fr_strerror_pop())) {
				MPRINT1("\t%s\n", err);
			}
			delay += 10;
			usleep(delay);
			goto retry;
		}

		MPRINT2("\tWorker %ld sent message %zu\n", wa->id, i);
	}

	MPRINT1("\tWorker %ld exiting.\n", wa->id);

	talloc_free(ctx);

	return NULL;
}



int main(int argc, char *argv[])
{
	int 			c;
	TALLOC_CTX		*autofree = talloc_autofree_context();
	pthread_attr_t		attr;
	pthread_t		master_id, *worker_id;
	size_t			i;
	worker_args_t		*worker_args;

	fr_time_start();

	while ((c = getopt(argc, argv, "hm:qw:x")) != -1) switch (c) {
		case 'x':
			debug_lvl++;
			break;

		case 'm':
			max_messages = atoi(optarg);
			break;

		case 'q':
			single_aq = false;
			break;

		case 'w':
			num_workers = atoi(optarg);
			break;

		case 'h':
		default:
			usage();
	}

#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	main_loop_init();
	el = main_loop_event_list();

	num_aq = single_aq ? 1 : num_workers;
	aq_size = single_aq ? FR_CONTROL_MAX_MESSAGES * num_workers : FR_CONTROL_MAX_MESSAGES;
	aq = talloc_array(autofree, fr_atomic_queue_t *, num_aq);
	for (i = 0; i < num_aq; i++) {
		aq[i] = fr_atomic_queue_alloc(aq, aq_size);
		fr_assert(aq[i] != NULL);
	}

	control = talloc_array(autofree, fr_control_t *, num_aq);
	for (i = 0; i < num_aq; i++) {
		control[i] = fr_control_create(control, el, aq[i], 2);
		if (!control[i]) {
			fprintf(stderr, "control_test: Failed to create control plane\n");
			fr_exit_now(EXIT_FAILURE);
		}
	}

	/*
	 *	Start the threads, with the channel.
	 */
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	(void) pthread_create(&master_id, &attr, control_master, NULL);
	worker_id = talloc_array(autofree, pthread_t, num_workers);
	worker_args = talloc_array(autofree, worker_args_t, num_workers);
	for (i = 0; i < num_workers; i++) {
		worker_args[i].id = i;
		worker_args[i].rb = fr_ring_buffer_create(worker_args, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
		(void) pthread_create(&worker_id[i], &attr, control_worker, &worker_args[i]);
	}

	(void) pthread_join(master_id, NULL);
	for (i = 0; i < num_workers; i++) {
		(void) pthread_join(worker_id[i], NULL);
	}

	talloc_free(control);

	main_loop_free();

	fr_exit_now(EXIT_SUCCESS);
}
