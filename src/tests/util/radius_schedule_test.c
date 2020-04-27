/*
 * radius_schedule_test.c	Tests for the scheduler and receiving RADIUS packets
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

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/syserror.h>

#include <sys/event.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#define MPRINT1 if (debug_lvl) printf

typedef struct {
	uint8_t			vector[16];
	uint8_t			id;
	struct			sockaddr_storage src;
	socklen_t		salen;
} fr_test_packet_ctx_t;

typedef struct {
	int			sockfd;
	fr_ipaddr_t		ipaddr;
	uint16_t		port;
} fr_listen_test_t;

static int			debug_lvl = 0;
static fr_ipaddr_t		my_ipaddr;
static int			my_port;
static char const		*secret = "testing123";
static fr_test_packet_ctx_t	tpc;

static rlm_rcode_t test_process(UNUSED void const *instance, REQUEST *request, fr_io_action_t action)
{
	MPRINT1("\t\tPROCESS --- request %"PRIu64" action %d\n", request->number, action);
	return RLM_MODULE_OK;
}

static int test_decode(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len)
{
	fr_listen_test_t const *pc = instance;

	request->async->process = test_process;

	if (!debug_lvl) return 0;

	MPRINT1("\t\tDECODE <<< request %"PRIu64" - %p data %p size %zd\n", request->number, pc, data, data_len);

	return 0;
}

static ssize_t test_encode(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	fr_md5_ctx_t	*md5_ctx;
	fr_listen_test_t const *pc = instance;

	MPRINT1("\t\tENCODE >>> request %"PRIu64"- data %p %p room %zd\n", request->number, pc, buffer, buffer_len);

	buffer[0] = FR_CODE_ACCESS_ACCEPT;
	buffer[1] = tpc.id;
	buffer[2] = 0;
	buffer[3] = 20;

	memcpy(buffer + 4, tpc.vector, 16);

	md5_ctx = fr_md5_ctx_alloc(true);
	fr_md5_update(md5_ctx, buffer, 20);
	fr_md5_update(md5_ctx, (uint8_t const *) secret, strlen(secret));
	fr_md5_final(buffer + 4, md5_ctx);
	fr_md5_ctx_free(&md5_ctx);

	return 20;
}

static size_t test_nak(void const *ctx, UNUSED void *packet_ctx, uint8_t *const packet, size_t packet_len, UNUSED uint8_t *reply, UNUSED size_t reply_len)
{
	MPRINT1("\t\tNAK !!! request %d - data %p %p size %zd\n", packet[1], ctx, packet, packet_len);

	return 10;
}

static int test_open(void *ctx, UNUSED void const *master_ctx)
{
	fr_listen_test_t	*io_ctx = talloc_get_type_abort(ctx, fr_listen_test_t);

	io_ctx->sockfd = fr_socket_server_udp(&io_ctx->ipaddr, &io_ctx->port, NULL, true);
	if (io_ctx->sockfd < 0) {
		fr_perror("radius_test: Failed creating socket");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_socket_bind(io_ctx->sockfd, &io_ctx->ipaddr, &io_ctx->port, NULL) < 0) {
		fr_perror("radius_test: Failed binding to socket");
		fr_exit_now(EXIT_FAILURE);
	}

	return 0;
}

static fr_time_t start_time;

static ssize_t test_read(void *ctx, UNUSED void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority, bool *is_dup)
{
	ssize_t			data_size;
	fr_listen_test_t const	*io_ctx = talloc_get_type_abort(ctx, fr_listen_test_t);

	tpc.salen = sizeof(tpc.src);
	*leftover = 0;
	*is_dup = false;

	data_size = recvfrom(io_ctx->sockfd, buffer, buffer_len, 0, (struct sockaddr *) &tpc.src, &tpc.salen);
	if (data_size <= 0) return data_size;

	/*
	 *	@todo - check if it's RADIUS.
	 */
	tpc.id = buffer[1];
	memcpy(tpc.vector, buffer + 4, sizeof(tpc.vector));

	start_time = fr_time();
	*recv_time = &start_time;
	*priority = 0;

	return data_size;
}


static ssize_t test_write(void *ctx, UNUSED void *packet_ctx,  UNUSED fr_time_t request_time,
			  uint8_t *buffer, size_t buffer_len, UNUSED size_t written)
{
	ssize_t			data_size;
	fr_listen_test_t	*io_ctx = talloc_get_type_abort(ctx, fr_listen_test_t);

	tpc.salen = sizeof(tpc.src);

	data_size = sendto(io_ctx->sockfd, buffer, buffer_len, 0, (struct sockaddr *)&tpc.src, tpc.salen);
	if (data_size <= 0) return data_size;

	/*
	 *	@todo - post-write cleanups
	 */

	return data_size;
}

static int test_fd(void const *ctx)
{
	fr_listen_test_t const *io_ctx = talloc_get_type_abort_const(ctx, fr_listen_test_t);

	return io_ctx->sockfd;
}

static fr_app_io_t app_io = {
	.name = "schedule-test",
	.default_message_size = 4096,
	.open = test_open,
	.read = test_read,
	.write = test_write,
	.fd = test_fd,
	.nak = test_nak,
	.encode = test_encode,
	.decode = test_decode
};

static void entry_point_set(UNUSED void const *ctx, REQUEST *request)
{
	request->async->process = test_process;
}

static fr_app_t test_app = {
	.entry_point_set = entry_point_set,
};

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: schedule_test [OPTS]\n");
	fprintf(stderr, "  -n <num>               Start num network threads\n");
	fprintf(stderr, "  -i <address>[:port]    Set IP address and optional port.\n");
	fprintf(stderr, "  -s <secret>            Set shared secret.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	fr_exit_now(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int			c;
	int			num_networks = 1;
	int			num_workers = 2;
	uint16_t		port16 = 0;
	TALLOC_CTX		*autofree = talloc_autofree_context();
	fr_schedule_t		*sched;
	fr_listen_t		listen = { .app_io = &app_io, .app = &test_app };
	fr_listen_test_t	*app_io_inst;

	listen.app_io_instance = app_io_inst = talloc_zero(autofree, fr_listen_test_t);

	fr_time_start();

	fr_log_init(&default_log, false);
	default_log.colourise = true;

	memset(&my_ipaddr, 0, sizeof(my_ipaddr));
	my_ipaddr.af = AF_INET;
	my_ipaddr.prefix = 32;
	my_ipaddr.addr.v4.s_addr = htonl(INADDR_LOOPBACK);
	my_port = 1812;

	while ((c = getopt(argc, argv, "i:n:s:w:x")) != -1) switch (c) {
		case 'i':
			if (fr_inet_pton_port(&my_ipaddr, &port16, optarg, -1, AF_INET, true, false) < 0) {
				fr_perror("Failed parsing ipaddr");
				fr_exit_now(EXIT_FAILURE);
			}
			my_port = port16;
			break;

		case 'n':
			num_networks = atoi(optarg);
			if ((num_networks <= 0) || (num_networks > 16)) usage();
			break;

		case 's':
			secret = optarg;
			break;

		case 'w':
			num_workers = atoi(optarg);
			if ((num_workers <= 0) || (num_workers > 1024)) usage();
			break;

		case 'x':
			debug_lvl++;
			fr_debug_lvl++;
			break;

		case 'h':
		default:
			usage();
	}

#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	app_io_inst->ipaddr = my_ipaddr;
	app_io_inst->port = my_port;

	sched = fr_schedule_create(autofree, NULL, &default_log, debug_lvl, num_networks, num_workers, NULL, NULL);
	if (!sched) {
		fprintf(stderr, "schedule_test: Failed to create scheduler\n");
		fr_exit_now(EXIT_FAILURE);
	}

	if (listen.app_io->open(listen.app_io_instance, listen.app_io_instance) < 0) fr_exit_now(EXIT_FAILURE);

#if 0
	/*
	 *	Set up the KQ filter for reading.
	 */
	EV_SET(&events[0], sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	if (kevent(kq_master, events, 1, NULL, 0, NULL) < 0) {
		fr_perror("Failed setting KQ for EVFILT_READ");
		fr_exit_now(EXIT_FAILURE);
	}
#endif

	(void) fr_fault_setup(autofree, NULL, argv[0]);
	(void) fr_schedule_listen_add(sched, &listen);

	sleep(10);

	(void) fr_schedule_destroy(&sched);

	fr_exit_now(EXIT_SUCCESS);
}
