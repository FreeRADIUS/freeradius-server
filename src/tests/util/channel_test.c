/*
 * channel_test.c	Tests for channels
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

#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/syserror.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <pthread.h>
#include <sys/event.h>

#define MAX_MESSAGES		(2048)
#define MAX_CONTROL_PLANE	(1024)
#define MAX_KEVENTS		(10)

#define MPRINT1 if (debug_lvl) printf
#define MPRINT2 if (debug_lvl > 1) printf

static int			debug_lvl = 0;
static int			kq_master, kq_worker;
static fr_atomic_queue_t	*aq_master, *aq_worker;
static fr_control_t		*control_master, *control_worker;
static int			max_messages = 10;
static int			max_control_plane = 0;
static int			max_outstanding = 1;
static bool			touch_memory = false;

/**********************************************************************/
typedef struct fr_request_s REQUEST;

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
	return talloc_free(tmp);
}
/**********************************************************************/

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: channel_test [OPTS]\n");
	fprintf(stderr, "  -c <control-plane>     Size of the control plane queue.\n");
	fprintf(stderr, "  -m <messages>	  Send number of messages.\n");
	fprintf(stderr, "  -o <outstanding>       Keep number of messages outstanding.\n");
	fprintf(stderr, "  -t                     Touch memory for fake packets.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(EXIT_FAILURE);
}

static void *channel_master(void *arg)
{
	bool			running, signaled_close;
	int			rcode, i, num_events;
	int			num_outstanding, num_messages;
	int			num_replies;
	fr_message_set_t	*ms;
	TALLOC_CTX		*ctx;
	fr_channel_t		*channel = arg;
	fr_channel_t		*new_channel;
	fr_channel_event_t	ce;
	struct kevent		events[MAX_KEVENTS];

	MEM(ctx = talloc_init("channel_master"));

	ms = fr_message_set_create(ctx, MAX_MESSAGES, sizeof(fr_channel_data_t), MAX_MESSAGES * 1024);
	if (!ms) {
		fprintf(stderr, "Failed creating message set\n");
		exit(EXIT_FAILURE);
	}

	MPRINT1("Master started.\n");

	/*
	 *	Signal the worker that the channel is open
	 */
	rcode = fr_channel_signal_open(channel);
	if (rcode < 0) {
		fprintf(stderr, "Failed signaling open: %s\n", fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 *	Bootstrap the queue with messages.
	 */
	num_replies = num_outstanding = num_messages = 0;

	running = true;
	signaled_close = false;

	while (running) {
		fr_time_t now;
		int num_to_send;
		fr_channel_data_t *cd, *reply;

#if 0
		/*
		 *	Drain the input queues before sleeping.
		 */
		while ((reply = fr_channel_recv_reply(channel)) != NULL) {
			num_replies++;
			num_outstanding--;
			MPRINT1("Master got reply %d, outstanding=%d, %d/%d sent.\n",
				num_replies, num_outstanding, num_messages, max_messages);
			fr_message_done(&reply->m);
		}
#endif

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

			if (touch_memory) {
				size_t j, k;

				for (j = k = 0; j < cd->m.data_size; j++) {
					k += cd->m.data[j];
				}

				cd->m.data[4] = k;
			}

			memcpy(cd->m.data, &num_messages, sizeof(num_messages));

			MPRINT1("Master sent message %d\n", num_messages);
			rcode = fr_channel_send_request(channel, cd, &reply);
			if (rcode < 0) {
				fprintf(stderr, "Failed sending request: %s\n", fr_syserror(errno));
			}
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
			MPRINT1("Master signaling worker to exit.\n");
			rcode = fr_channel_signal_worker_close(channel);
			if (rcode < 0) {
				fprintf(stderr, "Failed signaling close: %s\n", fr_syserror(errno));
				exit(EXIT_FAILURE);
			}

			signaled_close = true;
		}

		MPRINT1("Master waiting on events.\n");
		rad_assert(num_messages <= max_messages);

		num_events = kevent(kq_master, NULL, 0, events, MAX_KEVENTS, NULL);
		MPRINT1("Master kevent returned %d\n", num_events);

		if (num_events < 0) {
			if (num_events == EINTR) continue;

			fprintf(stderr, "Failed waiting for kevent: %s\n", fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		if (num_events == 0) continue;

		/*
		 *	Service the events.
		 */
		for (i = 0; i < num_events; i++) {
			(void) fr_channel_service_kevent(channel, control_master, &events[i]);
		}

		now = fr_time();

		MPRINT1("Master servicing control-plane aq %p\n", aq_master);

		while (true) {
			uint32_t id;
			size_t data_size;
			char data[256];

			data_size = fr_control_message_pop(aq_master, &id, data, sizeof(data));
			if (!data_size) break;

			rad_assert(id == FR_CONTROL_ID_CHANNEL);

			ce = fr_channel_service_message(now, &new_channel, data, data_size);
			MPRINT1("Master got channel event %d\n", ce);

			switch (ce) {
			case FR_CHANNEL_DATA_READY_NETWORK:
				MPRINT1("Master got data ready signal\n");
				rad_assert(new_channel == channel);

				reply = fr_channel_recv_reply(channel);
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
				} while ((reply = fr_channel_recv_reply(channel)) != NULL);
				break;

			case FR_CHANNEL_CLOSE:
				MPRINT1("Master received close signal\n");
				rad_assert(new_channel == channel);
				rad_assert(signaled_close == true);
				running = false;
				break;

			case FR_CHANNEL_NOOP:
				MPRINT1("Master got NOOP\n");
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

	return NULL;
}

static void *channel_worker(void *arg)
{
	bool running = true;
	int rcode, num_events;
	int worker_messages = 0;
	fr_message_set_t *ms;
	TALLOC_CTX *ctx;
	fr_channel_t *channel = arg;
	fr_channel_event_t ce;
	struct kevent events[MAX_KEVENTS];

	MEM(ctx = talloc_init("channel_worker"));

	ms = fr_message_set_create(ctx, MAX_MESSAGES, sizeof(fr_channel_data_t), MAX_MESSAGES * 1024);
	if (!ms) {
		fprintf(stderr, "Failed creating message set\n");
		exit(EXIT_FAILURE);
	}

	MPRINT1("\tWorker started.\n");

	while (running) {
		int i;
		fr_time_t now;
		fr_channel_t *new_channel;

		MPRINT1("\tWorker waiting on events.\n");

		num_events = kevent(kq_worker, NULL, 0, events, MAX_KEVENTS, NULL);
		MPRINT1("\tWorker kevent returned %d events\n", num_events);

		if (num_events < 0) {
			if (errno == EINTR) continue;

			fprintf(stderr, "Failed waiting for kevent: %s\n", fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		if (num_events == 0) continue;

		for (i = 0; i < num_events; i++) {
			(void) fr_channel_service_kevent(channel, control_worker, &events[i]);
		}

		MPRINT1("\tWorker servicing control-plane aq %p\n", aq_worker);

		now = fr_time();

		while (true) {
			uint32_t id;
			size_t data_size;
			char data[256];
			fr_channel_data_t *cd, *reply;

			data_size = fr_control_message_pop(aq_worker, &id, data, sizeof(data));
			if (!data_size) break;

			rad_assert(id == FR_CONTROL_ID_CHANNEL);

			ce = fr_channel_service_message(now, &new_channel, data, data_size);
			MPRINT1("\tWorker got channel event %d\n", ce);

			switch (ce) {

			case FR_CHANNEL_OPEN:
				MPRINT1("\tWorker received a new channel\n");
				rad_assert(new_channel == channel);
				break;

			case FR_CHANNEL_CLOSE:
				MPRINT1("\tWorker requested to close the channel.\n");
				rad_assert(new_channel == channel);
				running = false;

				/*
				 *	Drain the input before we ACK the exit.
				 */
				while ((cd = fr_channel_recv_request(channel)) != NULL) {
					worker_messages++;
					MPRINT1("\tWorker got message %d\n", worker_messages);
					fr_message_done(&cd->m);
				}

				(void) fr_channel_worker_ack_close(channel);
				break;

			case FR_CHANNEL_DATA_READY_WORKER:
				MPRINT1("\tWorker got data ready signal\n");
				rad_assert(new_channel == channel);

				cd = fr_channel_recv_request(channel);
				if (!cd) {
					MPRINT1("\tWorker SIGNAL WITH NO DATA!\n");
					break;
				}

				while (cd) {
					int message_id;

					worker_messages++;

					rad_assert(cd->m.data != NULL);
					memcpy(&message_id, cd->m.data, sizeof(message_id));
					MPRINT1("\tWorker got message %d (says %d)\n", worker_messages, message_id);

					reply = (fr_channel_data_t *) fr_message_alloc(ms, NULL, 100);
					rad_assert(reply != NULL);

					reply->m.when = fr_time();
					fr_message_done(&cd->m);

					if (touch_memory) {
						size_t j, k;

						for (j = k = 0; j < reply->m.data_size; j++) {
							k += reply->m.data[j];
						}

						reply->m.data[4] = k;
					}


					MPRINT1("\tWorker sending reply to messages %d\n", worker_messages);
					rcode = fr_channel_send_reply(channel, reply, &cd);
					if (rcode < 0) {
						fprintf(stderr, "Failed sending reply: %s\n", fr_syserror(errno));
					}
					rad_assert(rcode == 0);
				}
				break;

			case FR_CHANNEL_NOOP:
				MPRINT1("\tWorker got NOOP\n");
				rad_assert(new_channel == channel);
				break;

			default:
				fprintf(stderr, "\tWorker got unexpected CE %d\n", ce);

				/*
				 *	Not written yet!
				 */
				rad_assert(0 == 1);
				break;
			} /* switch over signals */

			/*
			 *	Get a new idea of "now".
			 */
			now = fr_time();
		} /* drain the control plane */
	}

	MPRINT1("\tWorker exiting.\n");

	/*
	 *	Force all messages to be garbage collected
	 */
	MPRINT2("Worker GC\n");
	fr_message_set_gc(ms);

	if (debug_lvl > 1) fr_message_set_debug(ms, stdout);

	/*
	 *	After the garbage collection, all messages marked "done" MUST also be marked "free".
	 */
	rcode = fr_message_set_messages_used(ms);
	fr_cond_assert(rcode == 0);

	talloc_free(ctx);

	return NULL;
}



int main(int argc, char *argv[])
{
	int			c;
	fr_channel_t		*channel;
	TALLOC_CTX		*autofree = talloc_autofree_context();
	pthread_attr_t		attr;
	pthread_t		master_id, worker_id;

	fr_time_start();

	while ((c = getopt(argc, argv, "c:hm:o:tx")) != -1) switch (c) {
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

		case 't':
			touch_memory = true;
			break;

		case 'h':
		default:
			usage();
	}

	if (max_outstanding > max_messages) max_outstanding = max_messages;

	if (!max_control_plane) {
		max_control_plane = MAX_CONTROL_PLANE;
		if (max_outstanding > max_control_plane) max_control_plane = max_outstanding;
	}

#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	kq_master = kqueue();
	rad_assert(kq_master >= 0);

	kq_worker = kqueue();
	rad_assert(kq_worker >= 0);

	aq_master = fr_atomic_queue_create(autofree, max_control_plane);
	rad_assert(aq_master != NULL);

	aq_worker = fr_atomic_queue_create(autofree, max_control_plane);
	rad_assert(aq_worker != NULL);

	control_master = fr_control_create(autofree, kq_master, aq_master, 1024);
	rad_assert(control_master != NULL);

	control_worker = fr_control_create(autofree, kq_worker, aq_worker, 1025);
	rad_assert(control_worker != NULL);

	channel = fr_channel_create(autofree, control_master, control_worker, false);
	if (!channel) {
		fprintf(stderr, "channel_test: Failed to create channel\n");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Start the two threads, with the channel.
	 */
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	(void) pthread_create(&master_id, &attr, channel_master, channel);
	(void) pthread_create(&worker_id, &attr, channel_worker, channel);

	(void) pthread_join(master_id, NULL);
	(void) pthread_join(worker_id, NULL);

	close(kq_master);
	close(kq_worker);

	fr_channel_debug(channel, stdout);

	exit(EXIT_SUCCESS);
}
