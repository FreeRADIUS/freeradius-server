/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/** Implementation of named semaphores that release on exit
 *
 * @file src/lib/util/sem.c
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <signal.h>

#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/sem.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

#define DEFAULT_PROJ_ID	((int)'f')	/* Only 8 bits are used */

/** Return the PID of the process that last operated on the semaphore
 *
 * @param[out] pid	that last modified the semaphore.
 * @param[in] sem_id	semaphore ID.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sem_pid(pid_t *pid, int sem_id)
{
	int ret;

	ret = semctl(sem_id, 0, GETPID);
	if (ret < 0) {
		fr_strerror_printf("Failed getting semaphore PID: %s", fr_syserror(errno));
		return -1;
	}

	*pid = (pid_t)ret;

	return 0;
}

/** Return the UID that last operated on the semaphore
 *
 * @param[out] uid	the last modified the semaphore.
 * @param[in] sem_id	semaphore ID.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_sem_uid(uid_t *uid, int sem_id)
{
	int		ret;
	struct semid_ds	info;

	ret = semctl(sem_id, 0, IPC_STAT, &info);
	if (ret < 0) {
		*uid = 0;

		fr_strerror_printf("Failed getting semaphore UID: %s", fr_syserror(errno));
		return -1;
	}

	*uid = info.sem_perm.uid;

	return 0;
}

/** Return the GID that last operated on the semaphore
 *
 * @param[out] gid	the last modified the semaphore.
 * @param[in] sem_id	semaphore ID.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_sem_gid(uid_t *gid, int sem_id)
{
	int		ret;
	struct semid_ds	info;

	ret = semctl(sem_id, 0, IPC_STAT, &info);
	if (ret < 0) {
		*gid = 0;

		fr_strerror_printf("Failed getting semaphore GID: %s", fr_syserror(errno));
		return -1;
	}

	*gid = info.sem_perm.gid;

	return 0;
}

/** Return the UID that created the semaphore
 *
 * @param[out] uid	the last modified the semaphore.
 * @param[in] sem_id	semaphore ID.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_sem_cuid(uid_t *uid, int sem_id)
{
	int		ret;
	struct semid_ds	info;

	ret = semctl(sem_id, 0, IPC_STAT, &info);
	if (ret < 0) {
		*uid = 0;

		fr_strerror_printf("Failed getting semaphore CUID: %s", fr_syserror(errno));
		return -1;
	}

	*uid = info.sem_perm.cuid;

	return 0;
}

/** Return the GID that created the semaphore
 *
 * @param[out] gid	the last modified the semaphore.
 * @param[in] sem_id	semaphore ID.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_sem_cgid(uid_t *gid, int sem_id)
{
	int		ret;
	struct semid_ds	info;

	ret = semctl(sem_id, 0, IPC_STAT, &info);
	if (ret < 0) {
		*gid = 0;

		fr_strerror_printf("Failed getting semaphore CGID: %s", fr_syserror(errno));
		return -1;
	}

	*gid = info.sem_perm.cgid;

	return 0;
}

/** Decrement the semaphore by 1
 *
 * @param[in] sem_id		to take.
 * @param[in] file		to use in error messages.
 * @param[in] undo_on_exit	decrement the semaphore on exit.
 * @return
 *	- 1 already at 0.
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sem_post(int sem_id, char const *file, bool undo_on_exit)
{
	unsigned int num;

	errno = 0;
	num = semctl(sem_id, 0, GETVAL);
	if (errno != 0) {
		fr_strerror_printf("Failed getting value from semaphore bound to \"%s\" - %s", file,
				   fr_syserror(errno));
		return 01;
	}
	if (num == 0) return 1;

	{
		struct sembuf sop = {
			.sem_num = 0,
			.sem_op = -1,
			.sem_flg = undo_on_exit * SEM_UNDO
		};

		if (semop(sem_id, &sop, 1) < 0) {
			fr_strerror_printf("Failed posting semaphore bound to \"%s\" - %s", file,
					   fr_syserror(errno));
			return -1;
		}
	}

	return 0;
}

/** Increment the semaphore by 1
 *
 * @param[in] sem_id		to take.
 * @param[in] file		to use in error messages.
 * @param[in] undo_on_exit	decrement the semaphore on exit.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
int fr_sem_take(int sem_id, char const *file, bool undo_on_exit)
{
	struct sembuf sop = {
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = undo_on_exit * SEM_UNDO
	};

	if (semop(sem_id, &sop, 1) < 0) {
		fr_strerror_printf("Failed waiting on semaphore bound to \"%s\" - %s", file,
				   fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Wait for a semaphore to reach 0, then increment it by 1
 *
 * @param[in] sem_id		to operate on.
 * @param[in] file		to use in error messages.
 * @param[in] undo_on_exit	If true, semaphore will be decremented if
 *      			this process exits.
 * @param[in] nonblock		If true, don't wait and return 1 if the
 *				semaphore is not at 0.
 * @return
 *	- 1 would have blocked waiting for semaphore.
 *	- 0 incremented the semaphore.
 *	- -1 permissions error (EACCES).
 *	- -2 another error occurred.
 */
int fr_sem_wait(int sem_id, char const *file, bool undo_on_exit, bool nonblock)
{
	struct sembuf sops[2];
	short flags_nonblock;
	short flags_undo;

	flags_nonblock = nonblock * IPC_NOWAIT;
	flags_undo = undo_on_exit * SEM_UNDO;

	/*
	 *	The semop operation below only completes
	 *	successfully if the semaphore is at 0
	 *	which prevents races.
	 */
	sops[0].sem_num = 0;
	sops[0].sem_op = 0;
	sops[0].sem_flg = flags_nonblock;

	sops[1].sem_num = 0;
	sops[1].sem_op = 1;
	sops[1].sem_flg = flags_nonblock | flags_undo;

	if (semop(sem_id, sops, 2) < 0) {
		pid_t	sem_pid;
		uid_t	uid;
		gid_t	gid;
		int	semop_err = errno;
		char	*uid_str;
		char	*gid_str;
		int	ret;
		bool	dead = false;

		if (semop_err == EAGAIN) return 1;

		if ((fr_sem_pid(&sem_pid, sem_id) < 0) ||
		    (fr_sem_uid(&uid, sem_id) < 0) ||
		    (fr_sem_gid(&gid, sem_id) < 0)) {
		simple_error:
			fr_strerror_printf("Failed waiting on semaphore bound to \"%s\" - %s", file,
					   fr_syserror(semop_err));
			goto done;
		}

		ret = kill(sem_pid, 0);
		if ((ret < 0) && (errno == ESRCH)) dead = true;

		uid_str = fr_perm_uid_to_str(NULL, uid);
		if (unlikely(!uid_str)) goto simple_error;

		gid_str = fr_perm_gid_to_str(NULL, gid);
		if (unlikely(!uid_str)) {
			talloc_free(uid_str);
			goto simple_error;
		}

		fr_strerror_printf("Failed waiting on semaphore bound to \"%s\" - %s.  Semaphore "
				   "owned by %s:%s PID %u%s", file, fr_syserror(semop_err),
				   uid_str, gid_str, sem_pid, dead ? " (dead)" : "");

		talloc_free(uid_str);
		talloc_free(gid_str);

	done:
		return (semop_err == EACCES ? -1 : -2);
	}

	return 0;
}

/** Remove the semaphore, this helps with permissions issues
 *
 * @param[in] sem_id	to close.
 * @param[in] file	to use in error messages.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sem_close(int sem_id, char const *file)
{
	if (semctl(sem_id, 0, IPC_RMID) < 0) {
		fr_strerror_printf("Removing semaphore on \"%s\" failed: %s",
				   file ? file : "unknown", fr_syserror(errno));
		return -1;
	}

	return 0;
}

static bool sem_check_uid(char const *file, int proj_id,
			  char const *thing, uid_t expected, uid_t got)
{
	char *expected_str, *got_str;

	if (expected == got) return true;

	expected_str = fr_perm_uid_to_str(NULL, expected);
	if (unlikely(!expected_str)) {
	simple_error:
		fr_strerror_printf("Semaphore on \"%s\" ID 0x%x - %s is incorrect",
				   file, proj_id, thing);
		return false;
	}

	got_str = fr_perm_uid_to_str(NULL, got);
	if (unlikely(!got_str)) {
		talloc_free(expected_str);

		goto simple_error;
	}
	fr_strerror_printf("Semaphore on \"%s\" ID 0x%x - %s is incorrect.  Expected \"%s\", got \"%s\"",
			   file, proj_id, thing, expected_str, got_str);

	talloc_free(expected_str);
	talloc_free(got_str);

	return false;
}

static bool sem_check_gid(char const *file, int proj_id,
			  char const *thing, gid_t expected, gid_t got)
{
	char *expected_str, *got_str;

	if (expected == got) return true;

	expected_str = fr_perm_gid_to_str(NULL, expected);
	if (unlikely(!expected_str)) {
	simple_error:
		fr_strerror_printf("Semaphore on \"%s\" ID 0x%x - %s is incorrect",
				   file, proj_id, thing);
		return false;
	}

	got_str = fr_perm_gid_to_str(NULL, got);
	if (unlikely(!got_str)) {
		talloc_free(expected_str);

		goto simple_error;
	}
	fr_strerror_printf("Semaphore on \"%s\" ID 0x%x - %s is incorrect.  Expected \"%s\", got \"%s\"",
			   file, proj_id, thing, expected_str, got_str);

	talloc_free(expected_str);
	talloc_free(got_str);

	return false;
}

/** Returns a semid for the semaphore associated with the file
 *
 * @param[in] file		to get or create sempahore from.
 * @param[in] proj_id		if 0 will default to '0xf4ee4a31'.
 * @param[in] uid		that should own the semaphore.
 * @param[in] gid		that should own the semaphore.
 * @param[in] check_perm	Verify the semaphore is owned by
 *				the specified uid/gid, and that it
 *				was created by the specified uid/gid
 *				or root.
 *				Also verify that it is not world
 *				writable.
 * @param[in] must_exist	semaphore must already exist.
 * @return
 *	- >= 0 the semaphore id.
 *      - -1 the file specified does not exist, or there is
 *	  a permissions error.
 *	- -2 failed getting semaphore.
 *	- -3 failed creating semaphore.
 *	- -4 must_exist was true, and the semaphore does not exist.
 */
int fr_sem_get(char const *file, int proj_id, uid_t uid, gid_t gid, bool check_perm, bool must_exist)
{
	key_t	sem_key;
	int	sem_id;
	bool	seen_eexist = false;

	if (proj_id == 0) proj_id = DEFAULT_PROJ_ID;

	sem_key = ftok(file, proj_id);
	if (sem_key < 0) {
		fr_strerror_printf("Failed associating semaphore with \"%s\" ID 0x%x: %s",
				   file, proj_id, fr_syserror(errno));
		return -1;
	}

	/*
	 *	Try and grab the existing semaphore
	 */
again:
	sem_id = semget(sem_key, 0, 0);
	if (sem_id < 0) {
		unsigned short mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;

		if (errno != ENOENT) {	/* Semaphore existed but we ran into an error */
			fr_strerror_printf("Failed getting semaphore on \"%s\" ID 0x%x: %s",
					   file, proj_id, fr_syserror(errno));
			return -2;
		}

		if (must_exist) return -4;

		/*
		 *	Create one semaphore, only if it doesn't
		 *	already exist, with u+rw,g+rw,o+r
		 */
		sem_id = semget(sem_key, 1, IPC_CREAT | IPC_EXCL | mode);
		if (sem_id < 0) {
			if (errno == EEXIST) {	/* Can get this with racing processes */
				if (!seen_eexist) {
					seen_eexist = true;
					goto again;
				}
			}

			fr_strerror_printf("Failed creating semaphore on \"%s\" ID 0x%x: %s",
					   file, proj_id, fr_syserror(errno));
			return -3;
		}

		/*
		 *	Set a specific uid/gid on the semaphore
		 */
		{
			struct semid_ds info = {
				.sem_perm = {
					.uid = uid,
					.gid = gid,
					.mode = mode
				}
			};

			if (semctl(sem_id, 0, IPC_SET, &info) < 0) {
				fr_strerror_printf("Failed setting permissions for semaphore on \"%s\" ID 0x%x: %s",
						   file, proj_id, fr_syserror(errno));
				fr_sem_close(sem_id, file);
				return -3;
			}
		}

	/*
	 *	Ensure that we, or a process with the same UID/GID
	 *      as ourselves, own the semaphore.
	 */
	} else if (check_perm) {
		int		ret;
		struct semid_ds	info;

		ret = semctl(sem_id, 0, IPC_STAT, &info);
		if (ret < 0) {
			fr_strerror_printf("Failed getting semaphore permissions on \"%s\" ID 0x%x: %s",
					   file, proj_id, fr_syserror(errno));
			return -2;
		}

		if (info.sem_perm.mode & S_IWOTH) {
			fr_strerror_printf("Semaphore on \"%s\" ID 0x%x is world writable (insecure)",
					   file, proj_id);
			return -2;
		}

		/*
		 *	IPC_SET allows the cuid/cgid of the semaphore
		 *	to modify its permissions, so we need to check
		 *	that they're either root or the user we want.
		 */
		if (!sem_check_uid(file, proj_id, "UID", uid, info.sem_perm.uid) ||
		    ((info.sem_perm.cuid != 0) && !sem_check_uid(file, proj_id, "CUID", uid, info.sem_perm.cuid)) ||
		    !sem_check_gid(file, proj_id, "GID", gid, info.sem_perm.gid) ||
		    ((info.sem_perm.cgid != 0) && !sem_check_gid(file, proj_id, "CGID", gid, info.sem_perm.cgid))) {
			return -1;
		}
	}

	return sem_id;
}
