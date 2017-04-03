/*
 * schedule_test.c	Tests for the scheduler
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

#include <freeradius-devel/util/schedule.h>
#include <freeradius-devel/util/time.h>
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
	uint8_t		vector[16];
	uint8_t		id;

	struct sockaddr_storage src;
	socklen_t	salen;
} fr_packet_ctx_t;

static int		debug_lvl = 0;
static char const	*secret = "testing123";

static int test_decode(void const *packet_ctx, uint8_t *const data, size_t data_len, REQUEST *request)
{
	fr_packet_ctx_t const *pc = packet_ctx;

	request->number = pc->id;

	if (!debug_lvl) return 0;

	MPRINT1("\t\tDECODE <<< request %zd - %p data %p size %zd\n", request->number, packet_ctx, data, data_len);

	return 0;
}

static ssize_t test_encode(void const *packet_ctx, REQUEST *request, uint8_t *buffer, size_t buffer_len)
{
	FR_MD5_CTX context;
	fr_packet_ctx_t const *pc = packet_ctx;

	MPRINT1("\t\tENCODE >>> request %zd - data %p %p room %zd\n", request->number, packet_ctx, buffer, buffer_len);

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

static size_t test_nak(void const *packet_ctx, uint8_t *const packet, size_t packet_len, UNUSED uint8_t *reply, UNUSED size_t reply_len)
{
	MPRINT1("\t\tNAK !!! request %d - data %p %p size %zd\n", packet[1], packet_ctx, packet, packet_len);

	return 10;
}

static fr_transport_final_t test_process(REQUEST *request, fr_transport_action_t action)
{
	MPRINT1("\t\tPROCESS --- request %zd action %d\n", request->number, action);
	return FR_TRANSPORT_REPLY;
}

static fr_transport_t transport = {
	.name = "schedule-test",
	.id = 1,
	.default_message_size = 4096,
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
	fprintf(stderr, "  -w <num>               Start num worker threads\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(1);
}

int main(int argc, char *argv[])
{
	int c;
	int num_networks = 1;
	int num_workers = 2;
	TALLOC_CTX	*autofree = talloc_init("main");
	fr_schedule_t	*sched;

	fr_time_start();

	fr_log_init(&default_log, false);

	while ((c = getopt(argc, argv, "n:w:x")) != EOF) switch (c) {
		case 'n':
			num_networks = atoi(optarg);
			if ((num_networks <= 0) || (num_networks > 16)) usage();
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

	sleep(1);

	(void) fr_schedule_destroy(sched);

	talloc_free(autofree);

	return 0;
}
