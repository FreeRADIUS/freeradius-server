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
 * Copyright 2016  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/inet.h>
#include <freeradius-devel/radius.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/event.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#define MPRINT1 if (debug_lvl) printf

typedef struct fr_packet_ctx_t {
	int		sockfd;

	uint8_t		vector[16];
	uint8_t		id;

	struct sockaddr_storage src;
	socklen_t	salen;
} fr_packet_ctx_t;

static int		debug_lvl = 0;
static fr_ipaddr_t	my_ipaddr;
static int		my_port;
static char const	*secret = "testing123";
static fr_packet_ctx_t  packet_ctx = { 0 };

/*
 *	@todo fix this...
 *
 *	Declare these here until we move all of the new field to the REQUEST.
 */
extern int		fr_socket_server_base(int proto, fr_ipaddr_t *ipaddr, int *port, char const *port_name, bool async);
extern int		fr_socket_server_bind(int sockfd, fr_ipaddr_t *ipaddr, int *port, char const *interface);
extern int		fr_fault_setup(char const *cmd, char const *program);

static int test_decode(void const *ctx, uint8_t *const data, size_t data_len, REQUEST *request)
{
	fr_packet_ctx_t const *pc = ctx;

	if (!debug_lvl) return 0;

	MPRINT1("\t\tDECODE <<< request %zd - %p data %p size %zd\n", request->number, pc, data, data_len);

	return 0;
}

static ssize_t test_encode(void const *ctx, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	FR_MD5_CTX context;
	fr_packet_ctx_t const *pc = ctx;

	MPRINT1("\t\tENCODE >>> request %zd - data %p %p room %zd\n", request->number, pc, buffer, buffer_len);

	buffer[0] = PW_CODE_ACCESS_ACCEPT;
	buffer[1] = pc->id;
	buffer[2] = 0;
	buffer[3] = 20;

	memcpy(buffer + 4, pc->vector, 16);
	
	fr_md5_init(&context);
	fr_md5_update(&context, buffer, 20);
	fr_md5_update(&context, (uint8_t const *) secret, strlen(secret));
	fr_md5_final(buffer + 4, &context);

	return 20;
}

static size_t test_nak(void const *ctx, uint8_t *const packet, size_t packet_len, UNUSED uint8_t *reply, UNUSED size_t reply_len)
{
	MPRINT1("\t\tNAK !!! request %d - data %p %p size %zd\n", packet[1], ctx, packet, packet_len);

	return 10;
}

static fr_transport_final_t test_process(REQUEST *request, fr_transport_action_t action)
{
	MPRINT1("\t\tPROCESS --- request %zd action %d\n", request->number, action);
	return FR_TRANSPORT_REPLY;
}

static ssize_t test_read(int sockfd, void *ctx, uint8_t *buffer, size_t buffer_len)
{
	ssize_t data_size;
	fr_packet_ctx_t *pc = ctx;

	pc->salen = sizeof(pc->src);

	data_size = recvfrom(sockfd, buffer, buffer_len, 0, (struct sockaddr *) &pc->src, &pc->salen);
	if (data_size <= 0) return data_size;

	/*
	 *	@todo - check if it's RADIUS.
	 */
	pc->id = buffer[1];
	memcpy(pc->vector, buffer + 4, sizeof(pc->vector));

	return data_size;
}


static ssize_t test_write(int sockfd, void *ctx, uint8_t *buffer, size_t buffer_len)
{
	ssize_t data_size;
	fr_packet_ctx_t *pc = ctx;

	pc->salen = sizeof(pc->src);

	data_size = sendto(sockfd, buffer, buffer_len, 0, (struct sockaddr *) &pc->src, pc->salen);
	if (data_size <= 0) return data_size;

	/*
	 *	@todo - post-write cleanups
	 */

	return data_size;
}


static fr_transport_t transport = {
	.name = "schedule-test",
	.id = 1,
	.default_message_size = 4096,
	.read = test_read,
	.write = test_write,
	.decode = test_decode,
	.encode = test_encode,
	.nak = test_nak,
	.process = test_process,
};

static fr_transport_t *transports = &transport;

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: schedule_test [OPTS]\n");
	fprintf(stderr, "  -n <num>               Start num network threads\n");
	fprintf(stderr, "  -i <address>[:port]    Set IP address and optional port.\n");
	fprintf(stderr, "  -s <secret>            Set shared secret.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(1);
}

int main(int argc, char *argv[])
{
	int c;
	int num_networks = 1;
	int num_workers = 2;
	uint16_t	port16 = 0;
	int sockfd;
	TALLOC_CTX	*autofree = talloc_init("main");
	fr_schedule_t	*sched;

	fr_time_start();

	fr_log_init(&default_log, false);
	default_log.colourise = true;

	memset(&my_ipaddr, 0, sizeof(my_ipaddr));
	my_ipaddr.af = AF_INET;
	my_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_LOOPBACK);
	my_port = 1812;

	while ((c = getopt(argc, argv, "i:n:s:w:x")) != EOF) switch (c) {
		case 'i':
			if (fr_inet_pton_port(&my_ipaddr, &port16, optarg, -1, AF_INET, true, false) < 0) {
				fprintf(stderr, "Failed parsing ipaddr: %s\n", fr_strerror());
				exit(1);
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

	sched = fr_schedule_create(autofree, &default_log, num_networks, num_workers, 1, &transports, NULL, NULL);
	if (!sched) {
		fprintf(stderr, "schedule_test: Failed to create scheduler\n");
		exit(1);
	}

	sockfd = fr_socket_server_base(IPPROTO_UDP, &my_ipaddr, &my_port, NULL, true);
	if (sockfd < 0) {
		fprintf(stderr, "radius_test: Failed creating socket: %s\n", fr_strerror());
		exit(1);
	}

	if (fr_socket_server_bind(sockfd, &my_ipaddr, &my_port, NULL) < 0) {
		fprintf(stderr, "radius_test: Failed binding to socket: %s\n", fr_strerror());
		exit(1);
	}

#if 0
	/*
	 *	Set up the KQ filter for reading.
	 */
	EV_SET(&events[0], sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
	if (kevent(kq_master, events, 1, NULL, 0, NULL) < 0) {
		fprintf(stderr, "Failed setting KQ for EVFILT_READ: %s\n", fr_strerror());
		exit(1);
	}
#endif

	fr_fault_setup(NULL, argv[0]);

	packet_ctx.sockfd = sockfd;

	(void) fr_schedule_socket_add(sched, sockfd, &packet_ctx, &transport);

	sleep(10);

	(void) fr_schedule_destroy(sched);

	talloc_free(autofree);

	return 0;
}
