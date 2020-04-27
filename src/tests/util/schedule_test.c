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
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/syserror.h>

#include <sys/event.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif


static int		debug_lvl = 0;

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: schedule_test [OPTS]\n");
	fprintf(stderr, "  -n <num>               Start num network threads\n");
	fprintf(stderr, "  -w <num>               Start num worker threads\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	fr_exit_now(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int c;
	int num_networks = 1;
	int num_workers = 2;
	TALLOC_CTX	*autofree = talloc_autofree_context();
	fr_schedule_t	*sched;

	fr_time_start();

	fr_log_init(&default_log, false);

	while ((c = getopt(argc, argv, "n:w:x")) != -1) switch (c) {
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

	sched = fr_schedule_create(autofree, NULL, &default_log, L_DBG_LVL_MAX, num_networks, num_workers, NULL, NULL);
	if (!sched) {
		fprintf(stderr, "schedule_test: Failed to create scheduler\n");
		fr_exit_now(EXIT_FAILURE);
	}

	sleep(1);

	(void) fr_schedule_destroy(&sched);

	return 0;
}
