/*
 * worker_test.c	Tests for channels
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
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/syserror.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <pthread.h>
#include <signal.h>

#include <sys/event.h>

#define MAX_MESSAGES		(2048)
#define MAX_CONTROL_PLANE	(1024)
#define MAX_KEVENTS		(10)
#define MAX_WORKERS		(1024)

#define MPRINT1 if (debug_lvl) printf
#define MPRINT2 if (debug_lvl > 1) printf

typedef struct {
	int		id;			//!< ID of the worker 0..N
	pthread_t	pthread_id;		//!< pthread ID of the worker
	fr_worker_t	*worker;		//!< pointer to the worker
	fr_channel_t	*ch;			//!< channel for communicating with the worker
} fr_schedule_worker_t;

static int		debug_lvl = 0;
static int		kq_master;
static fr_atomic_queue_t *aq_master;
static fr_control_t	*control_master;
static int		max_messages = 10;
static int		max_control_plane = 0;
static int		max_outstanding = 1;
static bool		touch_memory = false;
static int		num_workers = 1;
static bool		quiet = false;
static fr_schedule_worker_t workers[MAX_WORKERS];

/**********************************************************************/
typedef struct rad_request REQUEST;

REQUEST *request_alloc(UNUSED TALLOC_CTX *ctx)
{
	return NULL;
}

void request_verify(UNUSED char const *file, UNUSED int line, UNUSED REQUEST const *request)
{
}

int talloc_const_free(void const *ptr)
{
	void *tmp;
	if (!ptr) return 0;

	memcpy(&tmp, &ptr, sizeof(tmp));
	talloc_free(tmp);
}
/**********************************************************************/

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: worker_test [OPTS]\n");
	fprintf(stderr, "  -c <control-plane>     Size of the control plane queue.\n");
	fprintf(stderr, "  -m <messages>	  Send number of messages.\n");
	fprintf(stderr, "  -o <outstanding>       Keep number of messages outstanding.\n");
	fprintf(stderr, "  -q                     quiet - suppresses worker stats.\n");
	fprintf(stderr, "  -t                     Touch memory for fake packets.\n");
	fprintf(stderr, "  -w N                   Create N workers.  Default is 1.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(EXIT_FAILURE);
}

static rlm_rcode_t test_process(UNUSED void const *inst, REQUEST *request, fr_io_action_t action)
{
	MPRINT1("\t\tPROCESS --- request %"PRIu64" action %d\n", request->number, action);
	return RLM_MODULE_OK;
}

static int test_decode(UNUSED void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	uint32_t number;

	/*
	 *	The data is the packet number.
	 */
	memcpy(&number, data, sizeof(number));
	request->number = number;

	request->async->process = test_process;

	MPRINT1("\t\tDECODE <<< request %"PRIu64" - %p data %p size %zd\n", request->number,
		request->async->packet_ctx, data, data_len);
	return 0;
}

static ssize_t test_encode(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	MPRINT1("\t\tENCODE >>> request %"PRIu64" - data %p %p size %zd\n", request->number,
		instance, data, data_len);

	return data_len;
}

static size_t test_nak(UNUSED void const *instance, void *packet_ctx, uint8_t *const packet, size_t packet_len, uint8_t *reply, UNUSED size_t reply_len)
{
	uint32_t number;

	/*
	 *	The data is the packet number.
	 */
	memcpy(&number, packet, sizeof(number));
	memcpy(reply, packet, sizeof(number));

	MPRINT1("\t\tNAK !!! request %"PRIu64" - data %p %p size %zd\n", (uint64_t) number, packet_ctx, packet, packet_len);

	return 10;
}

static fr_app_io_t app_io = {
	.name = "worker-test",
	.default_message_size = 4096,
	.nak = test_nak,
	.encode = test_encode,
	.decode = test_decode
};

static void *worker_thread(void *arg)
{
	TALLOC_CTX *ctx;
	fr_worker_t *worker;
	fr_schedule_worker_t *sw;
	fr_event_list_t *el;
	char buffer[16];

	sw = (fr_schedule_worker_t *) arg;

	MPRINT1("\tWorker %d started.\n", sw->id);

	MEM(ctx = talloc_init("worker"));

	el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!el) {
		fprintf(stderr, "worker_test: Failed to create the event list\n");
		exit(EXIT_FAILURE);
	}

	snprintf(buffer, sizeof(buffer), "%d", sw->id);
	worker = sw->worker = fr_worker_create(ctx, buffer, el, &default_log, L_DBG_LVL_MAX);
	if (!worker) {
		fprintf(stderr, "worker_test: Failed to create the worker\n");
		exit(EXIT_FAILURE);
	}

	MPRINT1("\tWorker %d looping.\n", sw->id);
	fr_worker(worker);

	sw->worker = NULL;
	MPRINT1("\tWorker %d exiting.\n", sw->id);

	talloc_free(ctx);
	return NULL;
}


static void master_process(void)
{
	bool			running, signaled_close;
	int			rcode, i, num_events, which_worker;
	int			num_outstanding, num_messages;
	int			num_replies;
	fr_message_set_t	*ms;
	TALLOC_CTX		*ctx;
	fr_channel_t		*ch;
	fr_channel_event_t	ce;
	pthread_attr_t		attr;
	fr_schedule_worker_t	*sw;
	fr_listen_t		listen = { .app_io = &app_io };
	struct kevent		events[MAX_KEVENTS];

	MEM(ctx = talloc_init("master"));

	ms = fr_message_set_create(ctx, MAX_MESSAGES, sizeof(fr_channel_data_t), MAX_MESSAGES * 1024);
	if (!ms) {
		fprintf(stderr, "Failed creating message set\n");
		exit(EXIT_FAILURE);
	}

	MPRINT1("Master started.\n");

	/*
	 *	Create the worker threads.
	 */
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (i = 0; i < num_workers; i++) {
		workers[i].id = i;
		(void) pthread_create(&workers[i].pthread_id, &attr, worker_thread, &workers[i]);
	}

	MPRINT1("Master created %d workers.\n", num_workers);

	/*
	 *	Busy loop because that's fine for the test
	 */
	num_outstanding = 0;
	while (num_outstanding < num_workers) {
		for (i = 0; i < num_workers; i++) {
			if (!workers[i].worker) continue;
			if (workers[i].ch != NULL) continue;

			/*
			 *	Create the channel and signal the
			 *	worker that it is open
			 */
			MPRINT1("Master creating channel to worker %d.\n", num_workers);
			workers[i].ch = fr_worker_channel_create(workers[i].worker, ctx, control_master);
			rad_assert(workers[i].ch != NULL);

			(void) fr_channel_master_ctx_add(workers[i].ch, &workers[i]);

			num_outstanding++;
		}
	}

	MPRINT1("Master created all channels.\n");

	/*
	 *	Bootstrap the queue with messages.
	 */
	num_replies = num_outstanding = num_messages = 0;
	which_worker = 0;

	running = true;
	signaled_close = false;

	while (running) {
		fr_time_t now;
		int num_to_send;
		fr_channel_data_t *cd, *reply;

		/*
		 *	Ensure we have outstanding messages.
		 */
		if (num_messages >= max_messages) {
			MPRINT1("Master DONE sending\n");
			goto check_close;
		}

		num_to_send = max_outstanding - num_outstanding;
		if ((num_messages + num_to_send) > max_messages) {
			num_to_send = max_messages - num_messages;
		}
		MPRINT1("Master sending %d messages\n", num_to_send);

		for (i = 0; i < num_to_send; i++) {
			cd = (fr_channel_data_t *) fr_message_alloc(ms, NULL, 100);
			rad_assert(cd != NULL);

			num_outstanding++;
			num_messages++;

			cd->m.when = fr_time();

			cd->priority = 0;
			cd->listen = &listen;

			if (touch_memory) {
				size_t j, k;

				for (j = k = 0; j < cd->m.data_size; j++) {
					k += cd->m.data[j];
				}

				cd->m.data[4] = k;
			}

			memcpy(cd->m.data, &num_messages, sizeof(num_messages));

			MPRINT1("Master sent message %d to worker %d\n", num_messages, which_worker);
			rcode = fr_channel_send_request(workers[which_worker].ch, cd, &reply);
			if (rcode < 0) {
				fprintf(stderr, "Failed sending request: %s\n", fr_syserror(errno));
			}
			which_worker++;
			if (which_worker >= num_workers) which_worker = 0;

			rad_assert(rcode == 0);
			if (reply) {
				num_replies++;
				num_outstanding--;
				MPRINT1("Master got reply %d, outstanding=%d, %d/%d sent.\n",
					num_replies, num_outstanding, num_messages, max_messages);
				fr_message_done(&reply->m);
			}
		}

		/*
		 *	Signal close only when done.
		 */
check_close:
		if (!signaled_close && (num_messages >= max_messages) && (num_outstanding == 0)) {
			MPRINT1("Master signaling workers to exit.\n");

			for (i = 0; i < num_workers; i++) {
				if (!quiet) {
					printf("Worker %d\n", i);
					fr_worker_debug(workers[i].worker, stdout);
				}

				rcode = fr_channel_signal_worker_close(workers[i].ch);
				MPRINT1("Master asked exit for worker %d.\n", workers[i].id);
				if (rcode < 0) {
					fprintf(stderr, "Failed signaling close %d: %s\n", i, fr_syserror(errno));
					exit(EXIT_FAILURE);
				}
			}
			signaled_close = true;
		}

		MPRINT1("Master waiting on events.\n");
		rad_assert(num_messages <= max_messages);

		num_events = kevent(kq_master, NULL, 0, events, MAX_KEVENTS, NULL);
		MPRINT1("Master kevent returned %d\n", num_events);

		if (num_events < 0) {
			if (errno == EINTR) continue;

			fprintf(stderr, "Failed waiting for kevent: %s\n", fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		if (num_events == 0) continue;

		/*
		 *	Service the events.
		 *
		 *	@todo this should NOT take a channel pointer
		 */
		for (i = 0; i < num_events; i++) {
			(void) fr_channel_service_kevent(workers[0].ch, control_master, &events[i]);
		}

		now = fr_time();

		MPRINT1("Master servicing control-plane\n");

		while (true) {
			uint32_t id;
			size_t data_size;
			char data[256];

			data_size = fr_control_message_pop(aq_master, &id, data, sizeof(data));
			if (!data_size) break;

			rad_assert(id == FR_CONTROL_ID_CHANNEL);

			ce = fr_channel_service_message(now, &ch, data, data_size);
			MPRINT1("Master got channel event %d\n", ce);

			switch (ce) {
			case FR_CHANNEL_DATA_READY_NETWORK:
				MPRINT1("Master got data ready signal\n");

				reply = fr_channel_recv_reply(ch);
				if (!reply) {
					MPRINT1("Master SIGNAL WITH NO DATA!\n");
					continue;
				}

				do {
					num_replies++;
					num_outstanding--;
					MPRINT1("Master got reply %d, outstanding=%d, %d/%d sent.\n",
						num_replies, num_outstanding, num_messages, max_messages);
					fr_message_done(&reply->m);
				} while ((reply = fr_channel_recv_reply(ch)) != NULL);
				break;

			case FR_CHANNEL_CLOSE:
				sw = fr_channel_master_ctx_get(ch);
				rad_assert(sw != NULL);

				MPRINT1("Master received close signal for worker %d\n", sw->id);
				rad_assert(signaled_close == true);


				/*
				 *	Tell the event loop to exit, and signal the worker
				 *	so that it stops waiting on the KQ.
				 */
				(void) fr_worker_exit(sw->worker);
				(void) pthread_kill(sw->pthread_id, SIGTERM);
				running = false;
				break;

			case FR_CHANNEL_NOOP:
				break;

			default:
				fprintf(stderr, "Master got unexpected CE %d\n", ce);

				/*
				 *	Not written yet!
				 */
				rad_assert(0 == 1);
				break;
			} /* switch over signal returned */
		} /* drain the control plane */
	} /* loop until told to exit */

	MPRINT1("Master exiting.\n");

	fr_time_t last_checked = fr_time();

	/*
	 *	Busy-wait for the workers to exit;
	 */
	do {
		fr_time_t now = fr_time();

		num_outstanding = num_workers;

		for (i = 0; i < num_workers; i++) {
			if (!workers[i].worker) num_outstanding--;
		}

		if ((now - last_checked) > (NSEC / 10)) {
			MPRINT1("still num_outstanding %d\n", num_outstanding);
		}

	} while (num_outstanding > 0);

	/*
	 *	Force all messages to be garbage collected
	 */
	MPRINT2("GC\n");
	fr_message_set_gc(ms);

	if (debug_lvl > 1) fr_message_set_debug(ms, stdout);

	/*
	 *	After the garbage collection, all messages marked "done" MUST also be marked "free".
	 */
	rcode = fr_message_set_messages_used(ms);
	MPRINT2("Master messages used = %d\n", rcode);
	rad_assert(rcode == 0);

	talloc_free(ctx);

}

static void sig_ignore(int sig)
{
	(void) signal(sig, sig_ignore);
}

int main(int argc, char *argv[])
{
	int c;
	TALLOC_CTX	*autofree = talloc_autofree_context();

	if (fr_time_start() < 0) {
		fprintf(stderr, "Failed to start time: %s\n", fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	fr_log_init(&default_log, false);

	while ((c = getopt(argc, argv, "c:hm:o:qtw:x")) != -1) switch (c) {
		case 'x':
			debug_lvl++;
			break;

		case 'c':
			max_control_plane = atoi(optarg);
			break;

		case 'm':
			max_messages = atoi(optarg);
			break;

		case 'o':
			max_outstanding = atoi(optarg);
			break;

		case 'q':
			quiet = true;
			break;

		case 't':
			touch_memory = true;
			break;

		case 'w':
			num_workers = atoi(optarg);
			if ((num_workers <= 0) || (num_workers >= MAX_WORKERS)) usage();
			break;

		case 'h':
		default:
			usage();
	}

	if (max_outstanding > max_messages) max_outstanding = max_messages;

	if (!max_control_plane) {
		max_control_plane = MAX_CONTROL_PLANE;
		if (max_outstanding > max_control_plane) max_control_plane = max_outstanding;
		if (num_workers > max_control_plane) max_control_plane = num_workers + (num_workers >> 1);
	}

#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	kq_master = kqueue();
	rad_assert(kq_master >= 0);

	aq_master = fr_atomic_queue_create(autofree, max_control_plane);
	rad_assert(aq_master != NULL);

	control_master = fr_control_create(autofree, kq_master, aq_master, 1024);
	rad_assert(control_master != NULL);

	signal(SIGTERM, sig_ignore);

	if (debug_lvl) {
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	master_process();

	close(kq_master);

	exit(EXIT_SUCCESS);
}
