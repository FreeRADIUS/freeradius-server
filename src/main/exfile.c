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
#include <freeradius-devel/exfile.h>

#include <sys/stat.h>
#include <fcntl.h>

typedef struct exfile_entry_t {
	int		fd;		//!< File descriptor associated with an entry.
	int		dup;
	uint32_t	hash;		//!< Hash for cheap comparison.
	time_t		last_used;	//!< Last time the entry was used.
	char		*filename;	//!< Filename.
} exfile_entry_t;


struct exfile_t {
	uint32_t	max_entries;	//!< How many file descriptors we keep track of.
	uint32_t	max_idle;	//!< Maximum idle time for a descriptor.
	time_t		last_cleaned;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;
#endif
	exfile_entry_t *entries;
	bool		locking;
};


#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

#define MAX_TRY_LOCK 4			//!< How many times we attempt to acquire a lock
					//!< before giving up.

static int _exfile_free(exfile_t *ef)
{
	uint32_t i;

	PTHREAD_MUTEX_LOCK(&ef->mutex);

	for (i = 0; i < ef->max_entries; i++) {
		if (!ef->entries[i].filename) continue;

		close(ef->entries[i].fd);
	}

	PTHREAD_MUTEX_UNLOCK(&ef->mutex);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&ef->mutex);
#endif

	return 0;
}


/** Initialize a way for multiple threads to log to one or more files.
 *
 * @param ctx The talloc context
 * @param max_entries Max file descriptors to cache, and manage locks for.
 * @param max_idle Maximum time a file descriptor can be idle before it's closed.
 * @param locking whether or not to lock the files.
 * @return the new context, or NULL on error.
 */
exfile_t *exfile_init(TALLOC_CTX *ctx, uint32_t max_entries, uint32_t max_idle, bool locking)
{
	exfile_t *ef;

	ef = talloc_zero(ctx, exfile_t);
	if (!ef) return NULL;

	ef->entries = talloc_zero_array(ef, exfile_entry_t, max_entries);
	if (!ef->entries) {
		talloc_free(ef);
		return NULL;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&ef->mutex, NULL) != 0) {
		talloc_free(ef);
		return NULL;
	}
#endif

	ef->max_entries = max_entries;
	ef->max_idle = max_idle;
	ef->locking = locking;

	talloc_set_destructor(ef, _exfile_free);

	return ef;
}


static void exfile_cleanup_entry(exfile_entry_t *entry)
{
	TALLOC_FREE(entry->filename);

	close(entry->fd);
	entry->hash = 0;
	entry->fd = -1;
	entry->dup = -1;
}

/** Open a new log file, or maybe an existing one.
 *
 * When multithreaded, the FD is locked via a mutex.  This way we're
 * sure that no other thread is writing to the file.
 *
 * @param ef The logfile context returned from exfile_init().
 * @param filename the file to open.
 * @param permissions to use.
 * @param append If true seek to the end of the file.
 * @return an FD used to write to the file, or -1 on error.
 */
int exfile_open(exfile_t *ef, char const *filename, mode_t permissions, bool append)
{
	int i, tries, unused, oldest;
	uint32_t hash;
	time_t now = time(NULL);
	struct stat st;

	if (!ef || !filename) return -1;

	hash = fr_hash_string(filename);
	unused = -1;

	PTHREAD_MUTEX_LOCK(&ef->mutex);

	/*
	 *	Clean up idle entries.
	 */
	if (now > (ef->last_cleaned + 1)) {
		ef->last_cleaned = now;

		for (i = 0; i < (int) ef->max_entries; i++) {
			if (!ef->entries[i].filename) continue;

			if ((ef->entries[i].last_used + ef->max_idle) >= now) continue;

			/*
			 *	This will block forever if a thread is
			 *	doing something stupid.
			 */
			exfile_cleanup_entry(&ef->entries[i]);
		}
	}

	/*
	 *	Find the matching entry, or an unused one.
	 *
	 *	Also track which entry is the oldest, in case there
	 *	are no unused entries.
	 */
	oldest = -1;
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
		 */
		if (ef->entries[i].hash != hash) continue;

		/*
		 *	But we still need to do string comparisons if
		 *	the hash matches, because 1/2^16 filenames
		 *	will result in a hash collision.  And that's
		 *	enough filenames in a long-running server to
		 *	ensure that it happens.
		 */
		if (strcmp(ef->entries[i].filename, filename) != 0) continue;

		goto do_return;
	}

	/*
	 *	There are no unused entries, free the oldest one.
	 */
	if (unused < 0) {
		exfile_cleanup_entry(&ef->entries[oldest]);
		unused = oldest;
	}

	/*
	 *	Create a new entry.
	 */
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
	} /* else the file was already opened */

do_return:
	/*
	 *	Lock from the start of the file.
	 */
	if (lseek(ef->entries[i].fd, 0, SEEK_SET) < 0) {
		fr_strerror_printf("Failed to seek in file %s: %s", filename, strerror(errno));

	error:
		exfile_cleanup_entry(&ef->entries[i]);

		PTHREAD_MUTEX_UNLOCK(&(ef->mutex));
		return -1;
	}

	/*
	 *	Try to lock it.  If we can't lock it, it's because
	 *	some reader has re-named the file to "foo.work" and
	 *	locked it.  So, we close the current file, re-open it,
	 *	and try again.
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

	return ef->entries[i].dup;
}

/** Close the log file.  Really just return it to the pool.
 *
 * When multithreaded, the FD is locked via a mutex.  This way we're
 * sure that no other thread is writing to the file.  This function
 * will unlock the mutex, so that other threads can write to the file.
 *
 * @param ef The logfile context returned from exfile_init()
 * @param fd the FD to close (i.e. return to the pool)
 * @return 0 on success, or -1 on error
 */
int exfile_close(exfile_t *ef, int fd)
{
	uint32_t i;

	for (i = 0; i < ef->max_entries; i++) {
		if (!ef->entries[i].filename) continue;

		/*
		 *	Unlock the bytes that we had previously locked.
		 */
		if (ef->entries[i].dup == fd) {
			if (ef->locking) (void) rad_unlockfd(ef->entries[i].dup, 0);
			close(ef->entries[i].dup); /* releases the fcntl lock */
			ef->entries[i].dup = -1;

			PTHREAD_MUTEX_UNLOCK(&(ef->mutex));
			return 0;
		}
	}

	PTHREAD_MUTEX_UNLOCK(&(ef->mutex));

	fr_strerror_printf("Attempt to unlock file which is not tracked");
	return -1;
}

int exfile_unlock(exfile_t *ef, int fd)
{
	uint32_t i;

	for (i = 0; i < ef->max_entries; i++) {
		if (!ef->entries[i].filename) continue;

		if (ef->entries[i].dup == fd) {
			ef->entries[i].dup = -1;
			PTHREAD_MUTEX_UNLOCK(&(ef->mutex));
			return 0;
		}
	}

	PTHREAD_MUTEX_UNLOCK(&(ef->mutex));

	fr_strerror_printf("Attempt to unlock file which does not exist");
	return -1;
}
