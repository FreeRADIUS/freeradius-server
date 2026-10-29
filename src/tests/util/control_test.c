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
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/semaphore.h>

#include <sys/event.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sched.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#undef MEM
#define MEM(x) do { if (!(x)) { fprintf(stderr, "%s[%d] OUT OF MEMORY\n", __FILE__, __LINE__); _exit(EXIT_FAILURE); } } while (0)
#define MPRINT1 if (debug_lvl) printf
#define MPRINT2 if (debug_lvl >= 2) printf
#define MPRINT3 if (debug_lvl >= 3) printf
#define CONTROL_MAGIC 0xabcd6809

/** Events on the test's control planes
 *
 *  The test stands in for the network, and only needs one table.
 */
typedef enum control_test_event_t : uint16_t {
	CONTROL_TEST_MESSAGE = 0
} control_test_event_t;

/** Events whose messages carry a socket, numbered separately from those above
 */
typedef enum control_test_socket_event_t : uint16_t {
	CONTROL_TEST_SOCKET = 0			//!< one end of a socketpair, with the worker's id in it.
} control_test_socket_event_t;

typedef struct {
	size_t	id;
} worker_args_t;

static int		debug_lvl = 0;
static size_t		max_messages = 10;
static size_t		num_workers = 1;
static int		aq_size = 16;
static fr_control_t	**control = NULL;
static fr_event_list_t	*el = NULL;
static bool		single_aq = true;
static size_t		num_aq = 1;
static uint32_t		max_pause_usec = 0;	//!< workers pause up to this long between sends.
static uint32_t		watchdog_secs = 30;	//!< fail if the master makes no progress for this long.

static pthread_mutex_t	wd_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	wd_cond = PTHREAD_COND_INITIALIZER;
static bool		finished = false;
static _Atomic(size_t)	progress = 0;		//!< messages and sockets the master has received, for the watchdog.
static _Atomic(size_t)	master_sleeps = 0;	//!< times the master blocked.
static _Atomic(size_t)	master_rescued = 0;	//!< times announcing found messages, so it did not block.

/**********************************************************************/

static NEVER_RETURNS void usage(void)
{
	fprintf(stderr, "usage: control_test [OPTS]\n");
	fprintf(stderr, "  -m <messages>	  Send number of messages.\n");
	fprintf(stderr, "  -w <workers>           Number of workers.\n");
	fprintf(stderr, "  -q                     Use per-worker atomic queues.\n");
	fprintf(stderr, "  -P <usec>              Pause each worker up to this long between sends,\n");
	fprintf(stderr, "                         so the master runs dry and blocks (default: 0).\n");
	fprintf(stderr, "  -t <seconds>           Fail if the master receives nothing for this long (default: 30).\n");
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
	size_t			num_sockets;
} master_ctx_t;

static void recv_control_callback(void const *data, size_t data_size, UNUSED fr_time_t now, void *uctx)
{
	my_message_t const	*m = data;
	master_ctx_t		*master_ctx = uctx;

	fr_assert(m->header == CONTROL_MAGIC);
	fr_assert(data_size == sizeof(*m));

	MPRINT2("Master got worker %zu message %zu, size %zu.\n", m->worker, m->counter, data_size);
	if (m->counter == (max_messages - 1)) MPRINT1("Master seen all messages from worker %zu\n", m->worker);
	master_ctx->num_messages++;
	atomic_store_explicit(&progress, master_ctx->num_messages + master_ctx->num_sockets,
			      memory_order_relaxed);
}

/** Receive a socket, read the sending worker's id through it, send it back, and close it
 */
static void recv_socket_callback(int sock, UNUSED fr_time_t now, void *uctx)
{
	master_ctx_t		*master_ctx = uctx;
	size_t			id;
	ssize_t			slen;

	slen = read(sock, &id, sizeof(id));
	if (slen != sizeof(id)) {
		fprintf(stderr, "Read of worker id through socket %d returned %zd: %s\n", sock, slen,
			(slen < 0) ? fr_syserror(errno) : "no data");
		fr_exit_now(EXIT_FAILURE);
	}
	fr_assert(id < num_workers);
	slen = write(sock, &id, sizeof(id));
	fr_assert(slen == sizeof(id));
	close(sock);

	MPRINT1("Master got socket, read worker id %zu through it\n", id);
	master_ctx->num_sockets++;
	atomic_store_explicit(&progress, master_ctx->num_messages + master_ctx->num_sockets,
			      memory_order_relaxed);
}

/** Busy wait for a random time up to max_usec
 *
 * Deliberately a spin, so the worker never blocks and the master is
 * the only thread which sleeps.
 */
static void spin(uint32_t max_usec)
{
	fr_time_t until;

	if (!max_usec) return;

	until = fr_time_add(fr_time(), fr_time_delta_from_usec(fr_rand() % (max_usec + 1)));
	while (fr_time_lt(fr_time(), until)) {
		/* spin */
	}
}

/** Fail the test if the master stops receiving
 *
 * With the wakeup gated on the master announcing it is blocking, a
 * missed wakeup leaves the master asleep with messages queued, which
 * would otherwise hang the test rather than fail it.
 */
static void *watchdog_thread(UNUSED void *arg)
{
	size_t last = 0;

	pthread_mutex_lock(&wd_mutex);
	while (!finished) {
		struct timespec	ts;
		int		ret;
		size_t		now;

		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += watchdog_secs;

		ret = pthread_cond_timedwait(&wd_cond, &wd_mutex, &ts);
		if (finished) break;
		if (ret != ETIMEDOUT) continue;

		now = atomic_load_explicit(&progress, memory_order_relaxed);
		if (now == last) {
			fprintf(stderr, "STALL: master received %zu of %zu messages and sockets, then nothing for "
				"%u seconds, slept %zu times, rescued %zu times\n",
				now, (max_messages + 1) * num_workers, watchdog_secs,
				atomic_load_explicit(&master_sleeps, memory_order_relaxed),
				atomic_load_explicit(&master_rescued, memory_order_relaxed));
			fr_exit_now(EXIT_FAILURE);
		}
		MPRINT1("watchdog: %zu messages\n", now);
		last = now;
	}
	pthread_mutex_unlock(&wd_mutex);

	return NULL;
}

static void *control_master(void *arg)
{
	TALLOC_CTX *ctx;
	master_ctx_t *master_ctx;
	size_t i;
	fr_time_t start;
	int64_t elapsed_usec;
	fr_sem_t *master_sem = arg;

	MEM(ctx = talloc_init_const("control_master"));

	master_ctx = talloc_zero(ctx, master_ctx_t);

	MPRINT1("Master started.\n");

	for (i = 0; i < num_aq; i++) {
		fr_control_callback_add(control[i], FR_CONTROL_EVENTSET_NETWORK, CONTROL_TEST_MESSAGE,
					recv_control_callback, master_ctx);
		fr_control_socket_callback_add(control[i], FR_CONTROL_EVENTSET_NETWORK, CONTROL_TEST_SOCKET,
					       recv_socket_callback, master_ctx);
		fr_control_open(control[i]);
	}

	sem_post(master_sem);

	start = fr_time();
	while ((master_ctx->num_messages < (max_messages * num_workers)) ||
	       (master_ctx->num_sockets < num_workers)) {
		int num_events;
		bool wait = true;

		MPRINT3("Master waiting for events (seen %zu).\n", master_ctx->num_messages);

		/*
		 *	Announce that we are about to block, on every control
		 *	we read.  If any held messages, service the rest
		 *	without blocking.
		 */
		for (i = 0; i < num_aq; i++) {
			if (fr_control_sleeping(control[i])) wait = false;
		}
		if (wait) {
			atomic_fetch_add_explicit(&master_sleeps, 1, memory_order_relaxed);
		} else {
			atomic_fetch_add_explicit(&master_rescued, 1, memory_order_relaxed);
		}

		num_events = fr_event_corral(el, fr_time(), wait);
		for (i = 0; i < num_aq; i++) fr_control_awake(control[i]);
		if (num_events < 0) {
			fprintf(stderr, "Failed reading kevent: %s\n", fr_syserror(errno));
			fr_exit_now(EXIT_FAILURE);
		}
		if (num_events > 0) {
			fr_event_service(el);
		}
	}
	elapsed_usec = fr_time_delta_to_usec(fr_time_sub_time_time(fr_time(), start));
	printf("messages          %zu from %zu workers\n", master_ctx->num_messages, num_workers);
	printf("sockets           %zu\n", master_ctx->num_sockets);
	printf("master slept      %zu times\n", atomic_load_explicit(&master_sleeps, memory_order_relaxed));
	printf("rescued by drain  %zu times\n", atomic_load_explicit(&master_rescued, memory_order_relaxed));
	printf("elapsed           %.3fs, %.0f messages/s\n", (double) elapsed_usec / 1e6,
	       ((double)master_ctx->num_messages * 1e6) / (double)elapsed_usec);

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

	MPRINT1("\tWorker %zu started using queue %zu.\n", wa->id, aq_num);

	for (i = 0; i < max_messages; i++) {
		my_message_t m;

		m.header = CONTROL_MAGIC;
		m.counter = i;
		m.worker = wa->id;

		/*
		 *	Go quiet for a bit so the master runs dry, announces
		 *	and blocks.  The next send then lands on a master which
		 *	is asleep, or is in the middle of deciding to be.
		 */
		spin(max_pause_usec);

retry:
		if (fr_control_message_send(control[aq_num], FR_CONTROL_EVENTSET_NETWORK, CONTROL_TEST_MESSAGE,
					    &m, sizeof(m)) < 0) {
			char const *err;
			MPRINT1("\tWorker %zu retrying message %zu\n", wa->id, i);
			while ((err = fr_strerror_pop())) {
				MPRINT1("\t%s\n", err);
			}

			/*
			 *	The queue is full.  Give the master a chance to
			 *	drain it, without sleeping for a growing delay
			 *	which would turn the test into a benchmark of
			 *	the sleep.
			 */
			sched_yield();
			goto retry;
		}

		MPRINT2("\tWorker %zu sent message %zu\n", wa->id, i);
	}

	/*
	 *	Send the master one end of a socketpair with our id in it,
	 *	and wait for the master to send the id back before closing
	 *	either end.  On macOS, if we closed them while the end was
	 *	still in flight, the id would sometimes be gone when it
	 *	arrived.  The master gets its own descriptor for the end
	 *	it was sent.
	 */
	{
		int		sv[2];
		size_t		id;
		ssize_t		slen;

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
			fprintf(stderr, "Failed creating socketpair: %s\n", fr_syserror(errno));
			fr_exit_now(EXIT_FAILURE);
		}
		slen = write(sv[1], &wa->id, sizeof(wa->id));
		fr_assert(slen == sizeof(wa->id));

retry_socket:
		if (fr_control_socket_send(control[aq_num], FR_CONTROL_EVENTSET_NETWORK, CONTROL_TEST_SOCKET,
					   sv[0]) < 0) {
			char const *err;
			MPRINT1("\tWorker %zu retrying socket message\n", wa->id);
			while ((err = fr_strerror_pop())) {
				MPRINT1("\t%s\n", err);
			}
			sched_yield();
			goto retry_socket;
		}
		MPRINT1("\tWorker %zu sent socket\n", wa->id);

		slen = read(sv[1], &id, sizeof(id));
		fr_assert(slen == sizeof(id));
		fr_assert(id == wa->id);
		close(sv[0]);
		close(sv[1]);
	}

	MPRINT1("\tWorker %zu exiting.\n", wa->id);

	talloc_free(ctx);

	return NULL;
}



int main(int argc, char *argv[])
{
	int 			c;
	TALLOC_CTX		*autofree = talloc_autofree_context();
	pthread_attr_t		attr;
	pthread_t		master_id, *worker_id, wd_id;
	size_t			i;
	worker_args_t		*worker_args;
	fr_sem_t		*master_sem;

	fr_time_start();

	while ((c = getopt(argc, argv, "hm:P:qt:w:x")) != -1) switch (c) {
		case 'x':
			debug_lvl++;
			break;

		case 'P':
			max_pause_usec = (uint32_t) strtoul(optarg, NULL, 10);
			break;

		case 't':
			watchdog_secs = (uint32_t) strtoul(optarg, NULL, 10);
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

	control = talloc_array(autofree, fr_control_t *, num_aq);
	for (i = 0; i < num_aq; i++) {
		control[i] = fr_control_create(control, el, aq_size, FR_CONTROL_MAX_SIZE);
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

	master_sem = fr_sem_alloc();
	fr_assert(master_sem != NULL);
	(void) pthread_create(&wd_id, &attr, watchdog_thread, NULL);
	(void) pthread_create(&master_id, &attr, control_master, master_sem);
	SEM_WAIT_INTR(master_sem);

	worker_id = talloc_array(autofree, pthread_t, num_workers);
	worker_args = talloc_array(autofree, worker_args_t, num_workers);
	for (i = 0; i < num_workers; i++) {
		worker_args[i].id = i;
		(void) pthread_create(&worker_id[i], &attr, control_worker, &worker_args[i]);
	}

	(void) pthread_join(master_id, NULL);
	for (i = 0; i < num_workers; i++) {
		(void) pthread_join(worker_id[i], NULL);
	}

	pthread_mutex_lock(&wd_mutex);
	finished = true;
	pthread_cond_signal(&wd_cond);
	pthread_mutex_unlock(&wd_mutex);
	(void) pthread_join(wd_id, NULL);

	fr_sem_free(master_sem);
	talloc_free(control);

	main_loop_free();

	fflush(stdout);
	fr_exit_now(EXIT_SUCCESS);
}
