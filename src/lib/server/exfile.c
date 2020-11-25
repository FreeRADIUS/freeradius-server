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

/*
 * $Id$
 *
 * @file exfile.c
 * @brief Allow multiple threads to write to the same set of files.
 *
 * @author Alan DeKok (aland@freeradius.org)
 * @copyright 2014 The FreeRADIUS server project
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <freeradius-devel/util/misc.h>

#include <sys/stat.h>
#include <fcntl.h>

typedef struct {
	int			fd;			//!< File descriptor associated with an entry.
	uint32_t		hash;			//!< Hash for cheap comparison.
	time_t			last_used;		//!< Last time the entry was used.
	dev_t			st_dev;			//!< device inode
	ino_t			st_ino;			//!< inode number
	char			*filename;		//!< Filename.
} exfile_entry_t;


struct exfile_s {
	uint32_t		max_entries;		//!< How many file descriptors we keep track of.
	uint32_t		max_idle;		//!< Maximum idle time for a descriptor.
	time_t			last_cleaned;
	pthread_mutex_t		mutex;
	exfile_entry_t		*entries;
	bool			locking;
	CONF_SECTION		*conf;			//!< Conf section to search for triggers.
	char const		*trigger_prefix;	//!< Trigger path in the global trigger section.
	fr_pair_list_t		trigger_args;		//!< Arguments to pass to trigger.
};

#define MAX_TRY_LOCK 4			//!< How many times we attempt to acquire a lock
					//!< before giving up.

/** Send an exfile trigger.
 *
 * @param[in] ef to send trigger for.
 * @param[in] request The current request.
 * @param[in] entry for the file that the event occurred on.
 * @param[in] name_suffix trigger name suffix.
 */
static inline void exfile_trigger_exec(exfile_t *ef, request_t *request, exfile_entry_t *entry, char const *name_suffix)
{
	char			name[128];
	fr_pair_t		*vp;
	fr_pair_list_t		args;
	fr_dict_attr_t const	*da;
	fr_cursor_t		cursor;

	fr_assert(ef != NULL);
	fr_assert(name_suffix != NULL);

	if (!ef->trigger_prefix) return;

	da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_EXFILE_NAME);
	if (!da) {
		ROPTIONAL(RERROR, ERROR, "Incomplete internal dictionary: Missing definition for \"Exfile-Name\"");
		return;
	}

	args = ef->trigger_args;
	fr_cursor_init(&cursor, &args);

	MEM(vp = fr_pair_afrom_da(NULL, da));
	fr_pair_value_strdup(vp, entry->filename);

	fr_cursor_prepend(&cursor, vp);

	snprintf(name, sizeof(name), "%s.%s", ef->trigger_prefix, name_suffix);
	trigger_exec(request, ef->conf, name, false, args);

	talloc_free(vp);
}


static void exfile_cleanup_entry(exfile_t *ef, request_t *request, exfile_entry_t *entry)
{
	if (entry->fd >= 0) close(entry->fd);

	entry->hash = 0;
	entry->fd = -1;

	/*
	 *	Issue close trigger *after* we've closed the fd
	 */
	exfile_trigger_exec(ef, request, entry, "close");

	/*
	 *	Trigger still needs access to filename to populate Exfile-Name
	 */
	TALLOC_FREE(entry->filename);
}


static int _exfile_free(exfile_t *ef)
{
	uint32_t i;

	pthread_mutex_lock(&ef->mutex);

	for (i = 0; i < ef->max_entries; i++) {
		if (!ef->entries[i].filename) continue;

		exfile_cleanup_entry(ef, NULL, &ef->entries[i]);
	}

	pthread_mutex_unlock(&ef->mutex);
	pthread_mutex_destroy(&ef->mutex);

	return 0;
}

/** Initialize a way for multiple threads to log to one or more files.
 *
 * @param ctx The talloc context
 * @param max_entries Max file descriptors to cache, and manage locks for.
 * @param max_idle Maximum time a file descriptor can be idle before it's closed.
 * @param locking whether or not to lock the files.
 * @return
 *	- new context.
 *	- NULL on error.
 */
exfile_t *exfile_init(TALLOC_CTX *ctx, uint32_t max_entries, uint32_t max_idle, bool locking)
{
	exfile_t *ef;

	ef = talloc_zero(NULL, exfile_t);
	if (!ef) return NULL;
	fr_pair_list_init(&ef->trigger_args);

	talloc_link_ctx(ctx, ef);

	ef->max_entries = max_entries;
	ef->max_idle = max_idle;
	ef->locking = locking;

	/*
	 *	If we're not locking the files, just return the
	 *	handle.  Each call to exfile_open() will just open a
	 *	new file descriptor.
	 */
	if (!ef->locking) return ef;

	ef->entries = talloc_zero_array(ef, exfile_entry_t, max_entries);
	if (!ef->entries) {
		talloc_free(ef);
		return NULL;
	}

	if (pthread_mutex_init(&ef->mutex, NULL) != 0) {
		talloc_free(ef);
		return NULL;
	}

	talloc_set_destructor(ef, _exfile_free);

	return ef;
}

/** Enable triggers for an exfiles handle
 *
 * @param[in] ef to enable triggers for.
 * @param[in] conf section to search for triggers in.
 * @param[in] trigger_prefix prefix to prepend to all trigger names.  Usually a path
 *	to the module's trigger configuration .e.g.
 *      @verbatim modules.<name>.file @endverbatim
 *	@verbatim <trigger name> @endverbatim is appended to form the complete path.
 * @param[in] trigger_args to make available in any triggers executed by the exfile api.
 *	Exfile-File is automatically added to this list.
 */
void exfile_enable_triggers(exfile_t *ef, CONF_SECTION *conf, char const *trigger_prefix, fr_pair_t *trigger_args)
{
	talloc_const_free(ef->trigger_prefix);
	MEM(ef->trigger_prefix = trigger_prefix ? talloc_typed_strdup(ef, trigger_prefix) : "");

	fr_pair_list_free(&ef->trigger_args);

	ef->conf = conf;

	if (!trigger_args) return;

	(void) fr_pair_list_copy(ef, &ef->trigger_args, &trigger_args);
}


/*
 *	Try to open the file. It it doesn't exist, try to
 *	create it's parent directories.
 */
static int exfile_open_mkdir(exfile_t *ef, char const *filename, mode_t permissions)
{
	int fd;

	fd = open(filename, O_RDWR | O_CREAT, permissions);
	if (fd < 0) {
		mode_t dirperm;
		char *p, *dir;

		/*
		 *	Maybe the directory doesn't exist.  Try to
		 *	create it.
		 */
		dir = talloc_typed_strdup(ef, filename);
		if (!dir) return -1;
		p = strrchr(dir, FR_DIR_SEP);
		if (!p) {
			fr_strerror_printf("No '/' in '%s'", filename);
			talloc_free(dir);
			return -1;
		}
		*p = '\0';

		/*
		 *	Ensure that the 'x' bit is set, so that we can
		 *	read the directory.
		 */
		dirperm = permissions;
		if ((dirperm & 0600) != 0) dirperm |= 0100;
		if ((dirperm & 0060) != 0) dirperm |= 0010;
		if ((dirperm & 0006) != 0) dirperm |= 0001;

		if (fr_mkdir(NULL, dir, -1, dirperm, NULL, NULL) < 0) {
			fr_strerror_printf("Failed to create directory %s: %s", dir, fr_syserror(errno));
			talloc_free(dir);
			return -1;
		}
		talloc_free(dir);

		fd = open(filename, O_RDWR | O_CREAT, permissions);
		if (fd < 0) {
			fr_strerror_printf("Failed to open file %s: %s", filename, fr_syserror(errno));
			return -1;
		}
	}

	return fd;
}


/** Open a new log file, or maybe an existing one.
 *
 * When multithreaded, the FD is locked via a mutex.  This way we're
 * sure that no other thread is writing to the file.
 *
 * @param ef The logfile context returned from exfile_init().
 * @param request The current request.
 * @param filename the file to open.
 * @param permissions to use.
 * @return
 *	- FD used to write to the file.
 *	- -1 on failure.
 */
int exfile_open(exfile_t *ef, request_t *request, char const *filename, mode_t permissions)
{
	int i, tries, unused = -1, found = -1, oldest = -1;
	bool do_cleanup = false;
	uint32_t hash;
	time_t now;
	struct stat st;

	if (!ef || !filename) return -1;

	/*
	 *	No locking: just return a new FD.
	 */
	if (!ef->locking) {
		found = exfile_open_mkdir(ef, filename, permissions);
		if (found < 0) return -1;

		(void) lseek(found, 0, SEEK_END);
		return found;
	}

	/*
	 *	It's faster to do hash comparisons of a string than
	 *	full string comparisons.
	 */
	hash = fr_hash_string(filename);
	now = time(NULL);
	unused = -1;

	pthread_mutex_lock(&ef->mutex);

	if (now > (ef->last_cleaned + 1)) do_cleanup = true;

	/*
	 *	Find the matching entry, or an unused one.
	 *
	 *	Also track which entry is the oldest, in case there
	 *	are no unused entries.
	 */
	for (i = 0; i < (int) ef->max_entries; i++) {
		if (!ef->entries[i].filename) {
			if (unused < 0) unused = i;
			continue;
		}

		if ((oldest < 0) ||
		    (ef->entries[i].last_used < ef->entries[oldest].last_used)) {
			oldest = i;
		}

		/*
		 *	Hash comparisons are fast.  String comparisons are slow.
		 *
		 *	But we still need to do string comparisons if
		 *	the hash matches, because 1/2^16 filenames
		 *	will result in a hash collision.  And that's
		 *	enough filenames in a long-running server to
		 *	ensure that it happens.
		 */
		if ((found < 0) &&
		    (ef->entries[i].hash == hash) &&
		    (strcmp(ef->entries[i].filename, filename) == 0)) {
			found = i;

			/*
			 *	If we're not cleaning up, stop now.
			 */
			if (!do_cleanup) break;

			/*
			 *	If we are cleaning up, then clean up
			 *	entries OTHER than the one we found,
			 *	do so now.
			 */
		} else if (do_cleanup) {
			if ((ef->entries[i].last_used + ef->max_idle) >= now) continue;

			exfile_cleanup_entry(ef, request, &ef->entries[i]);
		}
	}

	if (do_cleanup) ef->last_cleaned = now;

	/*
	 *	We found an existing entry, return that.
	 */
	if (found >= 0) {
		i = found;

		/*
		 *	Stat the *filename*, not the file we opened.
		 *	If that's not the file we opened, then go back
		 *	and re-open the file.
		 */
		if (stat(ef->entries[i].filename, &st) < 0) {
			goto reopen;
		}

		if ((st.st_dev != ef->entries[i].st_dev) ||
		    (st.st_ino != ef->entries[i].st_ino)) {
			close(ef->entries[i].fd);
			goto reopen;
		}

		goto try_lock;
	}

	/*
	 *	There are no unused entries, free the oldest one.
	 */
	if (unused < 0) {
		exfile_cleanup_entry(ef, request, &ef->entries[oldest]);
		unused = oldest;
	}

	/*
	 *	Create a new entry.
	 */
	i = unused;

	ef->entries[i].hash = hash;
	ef->entries[i].filename = talloc_typed_strdup(ef->entries, filename);
	ef->entries[i].fd = -1;

reopen:
	ef->entries[i].fd = exfile_open_mkdir(ef, filename, permissions);
	if (ef->entries[i].fd < 0) goto error;

	exfile_trigger_exec(ef, request, &ef->entries[i], "open");

try_lock:
	/*
	 *	Lock from the start of the file.
	 */
	if (lseek(ef->entries[i].fd, 0, SEEK_SET) < 0) {
		fr_strerror_printf("Failed to seek in file %s: %s", filename, fr_syserror(errno));

	error:
		exfile_cleanup_entry(ef, request, &ef->entries[i]);
		pthread_mutex_unlock(&(ef->mutex));
		return -1;
	}

	/*
	 *	Try to lock it.  If we can't lock it, it's because
	 *	some reader has re-named the file to "foo.work" and
	 *	locked it.  So, we close the current file, re-open it,
	 *	and try again/
	 */
	for (tries = 0; tries < MAX_TRY_LOCK; tries++) {
		if (rad_lockfd_nonblock(ef->entries[i].fd, 0) >= 0) break;

		if (errno != EAGAIN) {
			fr_strerror_printf("Failed to lock file %s: %s", filename, fr_syserror(errno));
			goto error;
		}

		close(ef->entries[i].fd);
		ef->entries[i].fd = open(filename, O_RDWR | O_CREAT, permissions);
		if (ef->entries[i].fd < 0) {
			fr_strerror_printf("Failed to open file %s: %s", filename, fr_syserror(errno));
			goto error;
		}
	}

	if (tries >= MAX_TRY_LOCK) {
		fr_strerror_printf("Failed to lock file %s: too many tries", filename);
		goto error;
	}

	/*
	 *	Maybe someone deleted the file while we were waiting
	 *	for the lock.  If so, re-open it.
	 */
	if (fstat(ef->entries[i].fd, &st) < 0) {
		fr_strerror_printf("Failed to stat file %s: %s", filename, fr_syserror(errno));
		goto reopen;
	}

	if (st.st_nlink == 0) {
		close(ef->entries[i].fd);
		goto reopen;
	}

	/*
	 *	Remember which device and inode this file is
	 *	for.
	 */
	ef->entries[i].st_dev = st.st_dev;
	ef->entries[i].st_ino = st.st_ino;

	/*
	 *	Sometimes the file permissions are changed externally.
	 *	just be sure to update the permission if necessary.
	 */
	if ((st.st_mode & ~S_IFMT)  != permissions) {
		char str_need[10], oct_need[5];
		char str_have[10], oct_have[5];

		rad_mode_to_oct(oct_need, permissions);
		rad_mode_to_str(str_need, permissions);

		rad_mode_to_oct(oct_have, st.st_mode & ~S_IFMT);
		rad_mode_to_str(str_have, st.st_mode & ~S_IFMT);

		WARN("File %s permissions are %s (%s) not %s (%s))", filename,
		     oct_have, str_have, oct_need, str_need);

		if (((st.st_mode | permissions) != st.st_mode) &&
		    (fchmod(ef->entries[i].fd, (st.st_mode & ~S_IFMT) | permissions) < 0)) {
			rad_mode_to_oct(oct_need, (st.st_mode & ~S_IFMT) | permissions);
			rad_mode_to_str(str_need, (st.st_mode & ~S_IFMT) | permissions);

			WARN("Failed resetting file %s permissions to %s (%s): %s",
			     filename, oct_need, str_need, fr_syserror(errno));
		}
	}

	/*
	 *	Seek to the end of the file before returning the FD to
	 *	the caller.
	 */
	(void) lseek(ef->entries[i].fd, 0, SEEK_END);

	/*
	 *	Return holding the mutex for the entry.
	 */
	ef->entries[i].last_used = now;

	exfile_trigger_exec(ef, request, &ef->entries[i], "reserve");

	/* coverity[missing_unlock] */
	return ef->entries[i].fd;
}

/** Close the log file.  Really just return it to the pool.
 *
 * When multithreaded, the FD is locked via a mutex. This way we're sure that no other thread is
 * writing to the file. This function will unlock the mutex, so that other threads can write to
 * the file.
 *
 * @param ef The logfile context returned from #exfile_init.
 * @param request The current request.
 * @param fd the FD to close (i.e. return to the pool).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int exfile_close(exfile_t *ef, request_t *request, int fd)
{
	uint32_t i;

	/*
	 *	No locking: just close the file.
	 */
	if (!ef->locking) {
		close(fd);
		return 0;
	}

	/*
	 *	Unlock the bytes that we had previously locked.
	 */
	for (i = 0; i < ef->max_entries; i++) {
		if (ef->entries[i].fd != fd) continue;

		(void) lseek(ef->entries[i].fd, 0, SEEK_SET);
		(void) rad_unlockfd(ef->entries[i].fd, 0);
		pthread_mutex_unlock(&(ef->mutex));

		exfile_trigger_exec(ef, request, &ef->entries[i], "release");
		return 0;
	}

	pthread_mutex_unlock(&(ef->mutex));

	fr_strerror_printf("Attempt to unlock file which is not tracked");
	return -1;
}
