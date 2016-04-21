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
 * @author Alan DeKok <aland@freeradius.org>
 * @copyright 2014  The FreeRADIUS server project
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/exfile.h>

#include <sys/stat.h>
#include <fcntl.h>

typedef struct exfile_entry_t {
	int			fd;			//!< File descriptor associated with an entry.
	int			dup;
	uint32_t		hash;			//!< Hash for cheap comparison.
	time_t			last_used;		//!< Last time the entry was used.
	char			*filename;		//!< Filename.
} exfile_entry_t;


struct exfile_t {
	uint32_t		max_entries;		//!< How many file descriptors we can possibly keep track of.
	uint32_t		max_idle;		//!< Maximum idle time for a descriptor.
	time_t			last_cleaned;
	pthread_mutex_t		mutex;
	exfile_entry_t		*entries;
	uint32_t		entries_count;		//!< Number of currently allocated entries for file descriptors.
	bool			locking;
	CONF_SECTION		*conf;			//!< Conf section to search for triggers.
	char const		*trigger_prefix;	//!< Trigger path in the global trigger section.
	VALUE_PAIR		*trigger_args;		//!< Arguments to pass to trigger.
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
static inline void exfile_trigger_exec(exfile_t *ef, REQUEST *request, exfile_entry_t *entry, char const *name_suffix)
{
	char			name[128];
	VALUE_PAIR		*vp, *args;
	fr_dict_attr_t const	*da;
	vp_cursor_t		cursor;

	rad_assert(ef != NULL);
	rad_assert(name_suffix != NULL);

	if (!ef->trigger_prefix) return;

	da = fr_dict_attr_by_num(NULL, 0, PW_EXFILE_NAME);
	if (!da) {
		ROPTIONAL(RERROR, ERROR, "Incomplete dictionary: Missing definition for \"Exfile-Name\"");
		return;
	}

	args = ef->trigger_args;
	fr_cursor_init(&cursor, &args);

	MEM(vp = fr_pair_afrom_da(NULL, da));
	fr_pair_value_strcpy(vp, entry->filename);

	fr_cursor_prepend(&cursor, vp);

	snprintf(name, sizeof(name), "%s.%s", ef->trigger_prefix, name_suffix);
	trigger_exec(request, ef->conf, name, false, args);

	talloc_free(vp);
}

static int _exfile_free(exfile_t *ef)
{
	uint32_t i;

	pthread_mutex_lock(&ef->mutex);

	for (i = 0; i < ef->entries_count; i++) {
		if (!ef->entries[i].filename) continue;

		close(ef->entries[i].fd);

		/*
		 *	Issue close trigger *after* we've closed the fd
		 */
		exfile_trigger_exec(ef, NULL, &ef->entries[i], "close");
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

	fr_talloc_link_ctx(ctx, ef);

	ef->entries_count = 64; // We allocate 64 FDs for a start, in most installations this should be enough

	ef->entries = talloc_zero_array(ef, exfile_entry_t, ef->entries_count);
	if (!ef->entries) {
		talloc_free(ef);
		return NULL;
	}

	if (pthread_mutex_init(&ef->mutex, NULL) != 0) {
		talloc_free(ef);
		return NULL;
	}

	ef->max_entries = max_entries;
	ef->max_idle = max_idle;
	ef->locking = locking;

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
void exfile_enable_triggers(exfile_t *ef, CONF_SECTION *conf, char const *trigger_prefix, VALUE_PAIR *trigger_args)
{
	rad_const_free(ef->trigger_prefix);
	MEM(ef->trigger_prefix = trigger_prefix ? talloc_typed_strdup(ef, trigger_prefix) : "");

	fr_pair_list_free(&ef->trigger_args);

	ef->conf = conf;

	if (!trigger_args) return;

	MEM(ef->trigger_args = fr_pair_list_copy(ef, trigger_args));
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
 * @param append If true seek to the end of the file.
 * @return
 *	- FD used to write to the file.
 *	- -1 on failure.
 */
int exfile_open(exfile_t *ef, REQUEST *request, char const *filename, mode_t permissions, bool append)
{
	int i, tries, unused = -1, found = -1;
	uint32_t hash;
	time_t now = time(NULL);
	struct stat st;
	exfile_entry_t *tmp;

	if (!ef || !filename) return -1;

	hash = fr_hash_string(filename);
	unused = -1;

	pthread_mutex_lock(&ef->mutex);

	/*
	 *	Find the matching entry, or an unused one.
	 */
	for (i = 0; i < (int) ef->entries_count; i++) {
		if (!ef->entries[i].filename) {
			if (unused < 0) unused = i;
			continue;
		}

		if (ef->entries[i].hash != hash) continue;

		/*
		 *	Same hash but different filename.
		 */
		if (strcmp(ef->entries[i].filename, filename) != 0) continue;

		found = i;
		break;
	}

	/*
	 *	Clean up old entries.
	 */
	if (now > (ef->last_cleaned + 1)) {
		ef->last_cleaned = now;

		for (i = 0; i < (int) ef->entries_count; i++) {
			if (i == found) continue;	/* Don't cleanup the one we're opening */

			if (!ef->entries[i].filename) continue;

			if ((ef->entries[i].last_used + ef->max_idle) >= now) continue;

			close(ef->entries[i].fd);

			/*
			 *	Issue close trigger *after* we've closed the fd
			 */
			exfile_trigger_exec(ef, request, &ef->entries[i], "close");

			/*
			 *	This will block forever if a thread is
			 *	doing something stupid.
			 */
			TALLOC_FREE(ef->entries[i].filename);
			ef->entries[i].hash = 0;
			ef->entries[i].fd = -1;
			ef->entries[i].dup = -1;
		}
	}

	/*
	 *	We found an existing entry, return that
	 */
	if (found >= 0) {
		i = found;
		goto do_return;
	}

	/*
	 *	Find an unused entry
	 */
	if (unused < 0) {
		/*
		 * Grow entries size?
		 */
		if (ef->entries_count < ef->max_entries) {
			i = ef->entries_count;
			ef->entries_count += 64;
			if (ef->entries_count > ef->max_entries)
				ef->entries_count = ef->max_entries;
			DEBUG2("Grow number of logfile entries for %s: %d -> %d", "", i, ef->entries_count);
			tmp = talloc_realloc(ef, ef->entries, exfile_entry_t, ef->entries_count);
			if (tmp) {
				ef->entries = tmp;
				memset(&(ef->entries[i]), 0, sizeof(exfile_entry_t) * (ef->max_entries - i));
				unused = i;
				goto new_entry;
			}
		}
		fr_strerror_printf("Too many different filenames");
		pthread_mutex_unlock(&(ef->mutex));
		return -1;
	}

	/*
	 *	Create a new entry.
	 */
new_entry:
	i = unused;

	ef->entries[i].hash = hash;
	ef->entries[i].filename = talloc_strdup(ef->entries, filename);
	ef->entries[i].fd = -1;
	ef->entries[i].dup = -1;

	ef->entries[i].fd = open(filename, O_RDWR | O_APPEND | O_CREAT, permissions);
	if (ef->entries[i].fd < 0) {
		mode_t dirperm;
		char *p, *dir;

		/*
		 *	Maybe the directory doesn't exist.  Try to
		 *	create it.
		 */
		dir = talloc_strdup(ef, filename);
		if (!dir) goto error;
		p = strrchr(dir, FR_DIR_SEP);
		if (!p) {
			fr_strerror_printf("No '/' in '%s'", filename);
			goto error;
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

		if (rad_mkdir(dir, dirperm, -1, -1) < 0) {
			fr_strerror_printf("Failed to create directory %s: %s",
					   dir, strerror(errno));
			talloc_free(dir);
			goto error;
		}
		talloc_free(dir);

		ef->entries[i].fd = open(filename, O_WRONLY | O_CREAT, permissions);
		if (ef->entries[i].fd < 0) {
			fr_strerror_printf("Failed to open file %s: %s",
					   filename, strerror(errno));
			goto error;
		} /* else fall through to creating the rest of the entry */

		exfile_trigger_exec(ef, request, &ef->entries[i], "create");
	} /* else the file was already opened */

	exfile_trigger_exec(ef, request, &ef->entries[i], "open");

do_return:
	/*
	 *	Lock from the start of the file.
	 */
	if (lseek(ef->entries[i].fd, 0, SEEK_SET) < 0) {
		fr_strerror_printf("Failed to seek in file %s: %s", filename, strerror(errno));

	error:
		ef->entries[i].hash = 0;
		TALLOC_FREE(ef->entries[i].filename);
		close(ef->entries[i].fd);
		ef->entries[i].fd = -1;
		ef->entries[i].dup = -1;

		pthread_mutex_unlock(&(ef->mutex));
		return -1;
	}

	/*
	 *	Try to lock it.  If we can't lock it, it's because
	 *	some reader has re-named the file to "foo.work" and
	 *	locked it.  So, we close the current file, re-open it,
	 *	and try again/
	 */
	if (ef->locking) {
		for (tries = 0; tries < MAX_TRY_LOCK; tries++) {
			if (rad_lockfd_nonblock(ef->entries[i].fd, 0) >= 0) break;

			if (errno != EAGAIN) {
				fr_strerror_printf("Failed to lock file %s: %s", filename, strerror(errno));
				goto error;
			}

			close(ef->entries[i].fd);
			ef->entries[i].fd = open(filename, O_WRONLY | O_CREAT, permissions);
			if (ef->entries[i].fd < 0) {
				fr_strerror_printf("Failed to open file %s: %s",
						   filename, strerror(errno));
				goto error;
			}
		}

		if (tries >= MAX_TRY_LOCK) {
			fr_strerror_printf("Failed to lock file %s: too many tries", filename);
			goto error;
		}
	}

	/*
	 *	Maybe someone deleted the file while we were waiting
	 *	for the lock.  If so, re-open it.
	 */
	if (fstat(ef->entries[i].fd, &st) < 0) {
		fr_strerror_printf("Failed to stat file %s: %s", filename, strerror(errno));
		goto error;
	}

	if (st.st_nlink == 0) {
		close(ef->entries[i].fd);
		ef->entries[i].fd = open(filename, O_WRONLY | O_CREAT, permissions);
		if (ef->entries[i].fd < 0) {
			fr_strerror_printf("Failed to open file %s: %s",
					   filename, strerror(errno));
			goto error;
		}
	}

	/*
	 *	Seek to the end of the file before returning the FD to
	 *	the caller.
	 */
	if (append) lseek(ef->entries[i].fd, 0, SEEK_END);

	/*
	 *	Return holding the mutex for the entry.
	 */
	ef->entries[i].last_used = now;
	ef->entries[i].dup = dup(ef->entries[i].fd);
	if (ef->entries[i].dup < 0) {
		fr_strerror_printf("Failed calling dup(): %s", strerror(errno));
		goto error;
	}

	exfile_trigger_exec(ef, request, &ef->entries[i], "reserve");

	return ef->entries[i].dup;
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
int exfile_close(exfile_t *ef, REQUEST *request, int fd)
{
	uint32_t i;

	for (i = 0; i < ef->entries_count; i++) {
		if (!ef->entries[i].filename) continue;

		/*
		 *	Unlock the bytes that we had previously locked.
		 */
		if (ef->entries[i].dup == fd) {
			if (ef->locking) (void) rad_unlockfd(ef->entries[i].dup, 0);
			close(ef->entries[i].dup); /* releases the fcntl lock */
			ef->entries[i].dup = -1;

			pthread_mutex_unlock(&(ef->mutex));

			exfile_trigger_exec(ef, request, &ef->entries[i], "release");

			return 0;
		}
	}

	pthread_mutex_unlock(&(ef->mutex));

	fr_strerror_printf("Attempt to unlock file which is not tracked");
	return -1;
}

/** Unlock the file, but leave the dup'd file descriptor open
 *
 */
int exfile_unlock(exfile_t *ef, REQUEST *request, int fd)
{
	uint32_t i;

	for (i = 0; i < ef->entries_count; i++) {
		if (!ef->entries[i].filename) continue;

		if (ef->entries[i].dup == fd) {
			ef->entries[i].dup = -1;

			pthread_mutex_unlock(&(ef->mutex));

			exfile_trigger_exec(ef, request, &ef->entries[i], "release");

			return 0;
		}
	}

	pthread_mutex_unlock(&(ef->mutex));

	fr_strerror_printf("Attempt to unlock file which does not exist");
	return -1;
}
