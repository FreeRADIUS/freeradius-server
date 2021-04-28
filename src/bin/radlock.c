/*
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
 */

/**
 * $Id$
 *
 * @file radlock.c
 * @brief Utility to examine semaphores used to provide exclusive running rights for a process
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/sem.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/strerror.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <assert.h>

DIAG_OFF(unused-macros)
#define INFO(fmt, ...)		fprintf(stdout, fmt "\n", ## __VA_ARGS__)
DIAG_ON(unused-macros)

typedef enum {
	RADLOCK_INVALID = 0,
	RADLOCK_LOCK,		//!< Acquire the semaphore if it's at 0.
	RADLOCK_TRYLOCK,	//!< Try and lock the semaphore and return if we can't.
	RADLOCK_UNLOCK,		//!< Unlock the semaphore.
	RADLOCK_REMOVE,		//!< Remove the semaphore.
	RADLOCK_INFO,		//!< Information about the semaphore.
	RADLOCK_PERM		//!< Modify permissions for a given semaphore.
} fr_radlock_action_t;

static fr_table_num_sorted_t const radlock_action_table[] = {
	{ L("info"),		RADLOCK_INFO	},
	{ L("lock"),		RADLOCK_LOCK	},
	{ L("perm"),		RADLOCK_PERM	},
	{ L("remove"),		RADLOCK_REMOVE	},
	{ L("trylock"),		RADLOCK_TRYLOCK	},
	{ L("unlock"),		RADLOCK_UNLOCK	}
};
static size_t radlock_action_table_len = NUM_ELEMENTS(radlock_action_table);

static void usage(int ret)
{
	fprintf(stderr, "usage: radlock <file> [lock|trylock|unlock|remove|info|perm]\n");
	fprintf(stderr, "  -u <uid>         Desired user.\n");
	fprintf(stderr, "  -g <gid>         Desired group.\n");
	fprintf(stderr, "  -m <perm>        Octal permissions string.\n");
	fprintf(stderr, "  -h               This help text.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Simple utility to query the locking state of a config file\n");
	fr_exit_now(ret);
}

#define EXIT_WITH_FAILURE exit(EXIT_FAILURE)
#define EXIT_WITH_SUCCESS exit(EXIT_SUCCESS)

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	char			c;
	fr_radlock_action_t	action;
	char const		*file;
	uid_t			uid = geteuid();
	bool			uid_set = false;
	gid_t			gid = getegid();
	bool			gid_set = false;
	long			mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
	bool			mode_set = false;
	int			sem_id;

	TALLOC_CTX		*autofree;

	autofree = talloc_autofree_context();

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radict");
		fr_exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	while ((c = getopt(argc, argv, "u:g:m:h")) != -1) switch (c) {
		case 'u':
			if (fr_perm_uid_from_str(autofree, &uid, optarg) < 0) {
				fr_perror("radlock");
				EXIT_WITH_FAILURE;
			}
			uid_set = true;
			break;

		case 'g':
			if (fr_perm_uid_from_str(autofree, &gid, optarg) < 0) {
				fr_perror("radlock");
				EXIT_WITH_FAILURE;
			}
			gid_set = true;
			break;

		case 'm':
			mode = strtol(optarg, NULL, 0);	/* 0 base plus 0 prefix = octal */
			if (errno == EINVAL) {
				fr_perror("radlock - Bad mode value");
				EXIT_WITH_FAILURE;
			}
			mode_set = true;
			break;

		case 'h':
		default:
			usage(EXIT_SUCCESS);
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		fr_perror("radlock - Need file to operate on");
		usage(64);
	};

	if (argc == 1) {
		fr_perror("radlock - Need action, must be one of (lock|trylock|unlock|remove|info|perm)");
		usage(64);
	}

	file = argv[0];
	action = fr_table_value_by_str(radlock_action_table, argv[1], RADLOCK_INVALID);
	if (action == RADLOCK_INVALID) {
		fr_perror("radlock - Action must be one of (lock|trylock|unlock|remove|info|perm), got %s", argv[1]);
		usage(64);
	}

	if (action == RADLOCK_PERM) {
		fr_perror("radlock - At least one of -u, -g, -m must be specified");
		usage(64);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radlock");
		EXIT_WITH_FAILURE;
	}

	switch (action) {
	case RADLOCK_LOCK:
	case RADLOCK_TRYLOCK:
		sem_id = fr_sem_get(file, 0, uid, gid, false, false);
		if (sem_id < 0) {
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}
		switch (fr_sem_wait(sem_id, file, false, action == RADLOCK_TRYLOCK)) {
		case 1:	/* Already locked */
		{
			pid_t pid;

			fr_sem_pid(&pid, sem_id);
			fr_perror("radlock - Can't lock \"%s\" already held by PID %u", file, pid);
			EXIT_WITH_FAILURE;
		}

		case 0:
			EXIT_WITH_SUCCESS;

		default:
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}
		break;

	case RADLOCK_UNLOCK:
		sem_id = fr_sem_get(file, 0, uid, gid, false, true);
		if (sem_id == -4) EXIT_WITH_SUCCESS;
		if (sem_id < 0) {
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}

	again:
		switch (fr_sem_post(sem_id, file, false)) {
		case 1:	/* already unlocked */
			EXIT_WITH_SUCCESS;

		case 0:
			goto again;

		default:
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}
		break;

	case RADLOCK_REMOVE:
		sem_id = fr_sem_get(file, 0, uid, gid, false, true);
		if (sem_id == -4) EXIT_WITH_SUCCESS;

		if (fr_sem_close(sem_id, file) < 0) {
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}
		break;

	case RADLOCK_INFO:
	{
		struct semid_ds	info;
		char		buff[10];
		unsigned int	perm = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
		bool		dead = false;
		pid_t		pid;
		int		ret;
		int		value;
		char const	*uid_str, *gid_str, *cuid_str, *cgid_str;

		sem_id = fr_sem_get(file, 0, uid, gid, false, true);
		if (sem_id == -4) EXIT_WITH_FAILURE;
		if (sem_id < 0) {
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}

		if (semctl(sem_id, 0, IPC_STAT, &info) < 0) {
			fr_perror("radlock - Failed getting lock info for \"%s\": %s", file, fr_syserror(errno));
			EXIT_WITH_FAILURE;
		}

		if (fr_sem_pid(&pid, sem_id) < 0) {
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}

		ret = kill(sem_id, 0);
		if ((ret < 0) && (errno == ESRCH)) dead = true;

		uid_str = fr_perm_uid_to_str(autofree, info.sem_perm.uid);
		if (!uid_str) uid_str = "";

		gid_str = fr_perm_gid_to_str(autofree, info.sem_perm.gid);
		if (!gid_str) gid_str = "";

		cuid_str = fr_perm_uid_to_str(autofree, info.sem_perm.cuid);
		if (!cuid_str) cuid_str = "";

		cgid_str = fr_perm_gid_to_str(autofree, info.sem_perm.cgid);
		if (!cgid_str) cgid_str = "";

		value = semctl(sem_id, 0, GETVAL);

		INFO("Locking information for \"%s\"", file);
		INFO("\tKey           : 0x%x", info.sem_perm._key);
		INFO("\tsemid         : %u", sem_id);
		INFO("\tPermissions   : %s", fr_perm_mode_to_str(buff, info.sem_perm.mode & perm));
		INFO("\tValue         : %u (%s)", value, value > 0 ? "locked" : "unlocked");
		INFO("Last Modified:");
		INFO("\tPID           : %u (%s)", pid, dead ? "dead" : "alive");
		INFO("\tUser          : %s (%u)", uid_str, info.sem_perm.uid);
		INFO("\tGroup         : %s (%u)", gid_str, info.sem_perm.gid);
		INFO("\tTime          : %s",
		     fr_asprintf(autofree, "%pV", fr_box_date(fr_time_from_sec(info.sem_otime))));
		INFO("Created:");
		INFO("\tUser          : %s (%u)", cuid_str, info.sem_perm.cuid);
		INFO("\tGroup         : %s (%u)", cgid_str, info.sem_perm.cgid);
		INFO("\tTime          : %s",
		     fr_asprintf(autofree, "%pV", fr_box_date(fr_time_from_sec(info.sem_ctime))));
		EXIT_WITH_SUCCESS;
	}
		break;

	case RADLOCK_PERM:
	{
		struct semid_ds	info;

		sem_id = fr_sem_get(file, 0, uid, gid, false, false);	/* Will create if does not already exist */
		if (sem_id < 0) {
			fr_perror("radlock");
			EXIT_WITH_FAILURE;
		}

		if (semctl(sem_id, 0, IPC_STAT, &info) < 0) {
			fr_perror("radlock - Failed getting lock info for \"%s\": %s",
				  fr_syserror(errno), file);
			EXIT_WITH_FAILURE;
		}

		if (uid_set) info.sem_perm.uid = uid;
		if (gid_set) info.sem_perm.gid = gid;
		if (mode_set) info.sem_perm.mode = mode;

		if (semctl(sem_id, 0, IPC_SET, &info) < 0) {
			fr_perror("radlock - Failed setting lock permissions for \"%s\": %s",
				  fr_syserror(errno), file);
			EXIT_WITH_FAILURE;
		}
	}
		break;

	case RADLOCK_INVALID:
		usage(64);
		break;
	}

	return 0;
}
