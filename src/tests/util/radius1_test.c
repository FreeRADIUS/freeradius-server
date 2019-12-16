/*
 * radius_test.c	Tests for channels
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
#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/md5.h>
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

typedef struct {
	uint8_t		vector[16];
	uint8_t		id;

	struct sockaddr_storage src;
	socklen_t	salen;
} fr_radius_packet_ctx_t;

static int		debug_lvl = 0;
static int		max_control_plane = 0;
static int		num_workers = 1;
static bool		quiet = false;

static fr_ipaddr_t	my_ipaddr;
static uint16_t		my_port;
static char const	*secret = "testing123";

static fr_schedule_worker_t workers[MAX_WORKERS];

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: radius_test [OPTS]\n");
	fprintf(stderr, "  -c <control-plane>     Size of the control plane queue.\n");
	fprintf(stderr, "  -i <address>[:port]    Set IP address and optional port.\n");
	fprintf(stderr, "  -q                     quiet - suppresses worker stats.\n");
	fprintf(stderr, "  -s <secret>            Set shared secret.\n");
	fprintf(stderr, "  -w N                   Create N workers.  Default is 1.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(EXIT_FAILURE);
}

static rlm_rcode_t test_process(UNUSED void const *instance, REQUEST *request, fr_io_action_t action)
{
	MPRINT1("\t\tPROCESS --- request %"PRIu64" action %d\n", request->number, action);
	return RLM_MODULE_OK;
}


static int test_decode(UNUSED void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	fr_radius_packet_ctx_t const *pc = talloc_get_type_abort_const(request->async->listen->app_instance,
								       fr_radius_packet_ctx_t);

	request->number = pc->id;
	request->async->process = test_process;

	if (!debug_lvl) return 0;

	MPRINT1("\t\tDECODE <<< request %"PRIu64" - %p data %p size %zd\n", request->number, pc, data, data_len);

	return 0;
}

static ssize_t test_encode(UNUSED void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	fr_md5_ctx_t	*md5_ctx;
	fr_radius_packet_ctx_t const *pc = talloc_get_type_abort_const(request->async->listen->app_instance,
								       fr_radius_packet_ctx_t);

	MPRINT1("\t\tENCODE >>> request %"PRIu64" - data %p %p room %zd\n",
		request->number, pc, buffer, buffer_len);

	buffer[0] = FR_CODE_ACCESS_ACCEPT;
	buffer[1] = pc->id;
	buffer[2] = 0;
	buffer[3] = 20;

	memcpy(buffer + 4, pc->vector, 16);

	md5_ctx = fr_md5_ctx_alloc(true);
	fr_md5_update(md5_ctx, buffer, 20);
	fr_md5_update(md5_ctx, (uint8_t const *) secret, strlen(secret));
	fr_md5_final(buffer + 4, md5_ctx);
	fr_md5_ctx_free(&md5_ctx);

	return 20;
}

static size_t test_nak(void const *instance, UNUSED void *packet_ctx, uint8_t *const packet, size_t packet_len, UNUSED uint8_t *reply, UNUSED size_t reply_len)
{
	MPRINT1("\t\tNAK !!! request %d - data %p %p size %zd\n", packet[1], instance, packet, packet_len);

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
	TALLOC_CTX		*ctx;
	fr_worker_t		*worker;
	fr_schedule_worker_t	*sw;
	fr_event_list_t		*el;

	sw = (fr_schedule_worker_t *) arg;

	MPRINT1("\tWorker %d started.\n", sw->id);

	MEM(ctx = talloc_init("worker"));

	el = fr_event_list_alloc(ctx, NULL, NULL);
	if (!el) {
		fprintf(stderr, "radius_test: Failed to create the event list\n");
		exit(EXIT_FAILURE);
	}

	worker = sw->worker = fr_worker_create(ctx, "test", el, &default_log, L_DBG_LVL_MAX);
	if (!worker) {
		fprintf(stderr, "radius_test: Failed to create the worker\n");
		exit(EXIT_FAILURE);
	}

	MPRINT1("\tWorker %d looping.\n", sw->id);
	fr_worker(worker);

	sw->worker = NULL;
	MPRINT1("\tWorker %d exiting.\n", sw->id);

	talloc_free(ctx);
	return NULL;
}


static void send_reply(int sockfd, fr_channel_data_t *reply)
{
	fr_radius_packet_ctx_t *pc = talloc_get_type_abort(reply->packet_ctx, fr_radius_packet_ctx_t);

	MPRINT1("Master got reply %d size %zd\n", pc->id, reply->m.data_size);

	if (sendto(sockfd, reply->m.data, reply->m.data_size, 0, (struct sockaddr *) &pc->src, pc->salen) < 0) {
		fprintf(stderr, "Failed sending reply: %s\n", fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	talloc_free(pc);

	fr_message_done(&reply->m);
}


static void master_process(TALLOC_CTX *ctx)
{
	bool			running;
	int			rcode, i, num_events, which_worker;
	int			num_outstanding;
	fr_message_set_t	*ms;
	fr_channel_t		*ch;
	fr_channel_event_t	ce;
	pthread_attr_t		pthread_attr;
	fr_schedule_worker_t	*sw;
	struct kevent		events[MAX_KEVENTS];
	int			kq_master;
	fr_atomic_queue_t	*aq_master;
	fr_control_t		*control_master;
	fr_listen_t		listen = { .app_io = &app_io };
	int			sockfd;

	MPRINT1("Master started.\n");

	ms = fr_message_set_create(ctx, MAX_MESSAGES, sizeof(fr_channel_data_t), MAX_MESSAGES * 1024);
	if (!ms) {
		fprintf(stderr, "Failed creating message set\n");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Create the KQ and associated sockets.
	 */
	kq_master = kqueue();
	rad_assert(kq_master >= 0);

	aq_master = fr_atomic_queue_create(ctx, max_control_plane);
	rad_assert(aq_master != NULL);

	control_master = fr_control_create(ctx, kq_master, aq_master, 1024);
	rad_assert(control_master != NULL);

	sockfd = fr_socket_server_udp(&my_ipaddr, &my_port, NULL, true);
	if (sockfd < 0) {
		fr_perror("radius_test: Failed creating socket");
		exit(EXIT_FAILURE);
	}

	if (fr_socket_bind(sockfd, &my_ipaddr, &my_port, NULL) < 0) {
		fr_perror("radius_test: Failed binding to socket");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Set up the KQ filter for reading.
	 */
	EV_SET(&events[0], sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	if (kevent(kq_master, events, 1, NULL, 0, NULL) < 0) {
		fr_perror("Failed setting KQ for EVFILT_READ");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Create the worker threads.
	 */
	(void) pthread_attr_init(&pthread_attr);
	(void) pthread_attr_setdetachstate(&pthread_attr, PTHREAD_CREATE_JOINABLE);

	for (i = 0; i < num_workers; i++) {
		workers[i].id = i;
		(void) pthread_create(&workers[i].pthread_id, &pthread_attr, worker_thread, &workers[i]);
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

	which_worker = 0;
	running = true;

	while (running) {
		bool control_plane_signal;
		fr_time_t now;
		fr_channel_data_t *cd, *reply;

		MPRINT1("Master waiting on events.\n");

		num_events = kevent(kq_master, NULL, 0, events, MAX_KEVENTS, NULL);
		MPRINT1("Master kevent returned %d\n", num_events);

		if (num_events < 0) {
			if (errno == EINTR) continue;

			fprintf(stderr, "Failed waiting for kevent: %s\n", fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		if (num_events == 0) continue;

		control_plane_signal = false;

		/*
		 *	Service the events.
		 *
		 *	@todo this should NOT take a channel pointer
		 */
		for (i = 0; i < num_events; i++) {
			uint8_t			*packet, *attr, *end;
			size_t			total_len;
			ssize_t			data_size;
			fr_radius_packet_ctx_t	*packet_ctx;

			if (events[i].filter == EVFILT_USER) {
				(void) fr_channel_service_kevent(workers[0].ch, control_master, &events[i]);
				control_plane_signal = true;
				break;
			}

			rad_assert(events[i].filter == EVFILT_READ);

			cd = (fr_channel_data_t *) fr_message_reserve(ms, 4096);
			rad_assert(cd != NULL);

			packet_ctx = talloc(ctx, fr_radius_packet_ctx_t);
			rad_assert(packet_ctx != NULL);
			packet_ctx->salen = sizeof(packet_ctx->src);

			cd->priority = 0;
			cd->packet_ctx = packet_ctx;
			cd->listen = &listen;

			data_size = recvfrom(sockfd, cd->m.data, cd->m.rb_size, 0,
					     (struct sockaddr *) &packet_ctx->src, &packet_ctx->salen);
			MPRINT1("Master got packet size %zd\n", data_size);
			if (data_size <= 20) {
				MPRINT1("Master ignoring packet (data length %zd)\n", data_size);

			discard:
				fr_message_done(&cd->m); /* yeah, re-use it for the next packet... */
				continue;
			}

			/*
			 *	Verify the packet before doing anything more with it.
			 */
			packet = cd->m.data;
			if (packet[0] != FR_CODE_ACCESS_REQUEST) {
				MPRINT1("Master ignoring packet code %u\n", packet[0]);
				goto discard;
			}

			total_len = (packet[2] << 8) | packet[3];
			if (total_len < 20) {
				MPRINT1("Master ignoring packet (header length %zu)\n", total_len);
				goto discard;
			}
			if (total_len > (size_t) data_size) {
				MPRINT1("Master ignoring truncated packet (read %zd, says %zu)\n",
					data_size, total_len);
				goto discard;
			}

			attr = packet + 20;
			end = packet + data_size;
			while (attr < end) {
				if ((end - attr) < 2) goto discard;
				if (attr[0] == 0) goto discard;
				if (attr[1] < 2) goto discard;
				if ((attr + attr[1]) > end) goto discard;

				attr += attr[1];
			}

			(void) fr_message_alloc(ms, &cd->m, total_len);

			MPRINT1("Master sending packet size %zd to worker %d\n", cd->m.data_size, which_worker);
			cd->m.when = fr_time();

			packet_ctx->id = packet[1];
			memcpy(packet_ctx->vector, packet + 4, 16);

			rcode = fr_channel_send_request(workers[which_worker].ch, cd, &reply);
			if (rcode < 0) {
				fprintf(stderr, "Failed sending request: %s\n", fr_syserror(errno));
				exit(EXIT_FAILURE);
			}
			which_worker++;
			if (which_worker >= num_workers) which_worker = 0;

			rad_assert(rcode == 0);
			if (reply) send_reply(sockfd, reply);
		}

		if (!control_plane_signal) continue;

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
			case FR_CHANNEL_DATA_READY_REQUESTOR:
				MPRINT1("Master got data ready signal\n");

				reply = fr_channel_recv_reply(ch);
				if (!reply) {
					MPRINT1("Master SIGNAL WITH NO DATA!\n");
					continue;
				}

				do {
					send_reply(sockfd, reply);
				} while ((reply = fr_channel_recv_reply(ch)) != NULL);
				break;

			case FR_CHANNEL_CLOSE:
				sw = fr_channel_master_ctx_get(ch);
				rad_assert(sw != NULL);

				MPRINT1("Master received close ack signal for worker %d\n", sw->id);

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
	close(sockfd);
}

static void sig_ignore(int sig)
{
	(void) signal(sig, sig_ignore);
}

int main(int argc, char *argv[])
{
	int		c;
	TALLOC_CTX	*autofree = talloc_autofree_context();
	uint16_t	port16 = 0;

	fr_time_start();

	fr_log_init(&default_log, false);

	memset(&my_ipaddr, 0, sizeof(my_ipaddr));
	my_ipaddr.af = AF_INET;
	my_ipaddr.prefix = 32;
	my_ipaddr.addr.v4.s_addr = htonl(INADDR_LOOPBACK);
	my_port = 1812;

	while ((c = getopt(argc, argv, "c:hi:qs:w:x")) != -1) switch (c) {
		case 'x':
			debug_lvl++;
			break;

		case 'c':
			max_control_plane = atoi(optarg);
			break;

		case 'i':
			if (fr_inet_pton_port(&my_ipaddr, &port16, optarg, -1, AF_INET, true, false) < 0) {
				fr_perror("Failed parsing ipaddr");
				exit(EXIT_FAILURE);
			}
			my_port = port16;
			break;

		case 'q':
			quiet = true;
			break;

		case 's':
			secret = optarg;
			break;

		case 'w':
			num_workers = atoi(optarg);
			if ((num_workers <= 0) || (num_workers >= MAX_WORKERS)) usage();
			break;

		case 'h':
		default:
			usage();
	}

	if (!max_control_plane) {
		max_control_plane = MAX_CONTROL_PLANE;
		if (num_workers > max_control_plane) max_control_plane = num_workers + (num_workers >> 1);
	}

#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	signal(SIGTERM, sig_ignore);

	if (debug_lvl) {
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	master_process(autofree);

	exit(EXIT_SUCCESS);
}
