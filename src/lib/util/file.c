/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Various miscellaneous functions to manipulate files and paths
 *
 * @file src/lib/util/file.c
 *
 * @copyright 2019 The FreeRADIUS project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <sys/param.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

#include <freeradius-devel/util/file.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/value.h>

static ssize_t _fr_mkdir(int *fd_out, char *start, char *path, mode_t mode, fr_mkdir_func_t func, void *uctx)
{
	int		ret, fd;
	char		*p;

	/*
	 *	Try to make the path.  If it exists, chmod it.
	 *	If a path doesn't exist, that's OK.  Otherwise
	 *	return with an error.
	 *
	 *	Directories permissions are initially set so
	 *	that only we should have access. This prevents
	 *	an attacker removing them and swapping them
	 *	out for a link to somewhere else.
	 *	We change them to the correct permissions later.
	 */
	ret = mkdir(path, 0700);
	if (ret >= 0) {
		fd = open(path, O_DIRECTORY);
		if (fd < 0) {
			fr_strerror_printf("Failed opening directory we created: %s",
					   fr_syserror(errno));
		mkdir_error:
			p = strrchr(path, FR_DIR_SEP);
			if (!p) return start - path;

			return start - p;
		}

		if (fchmod(fd, mode) < 0) {
			fr_strerror_printf("Failed setting permissions on directory "
					   "we created: %s", fr_syserror(errno));
			close(fd);
			goto mkdir_error;
		}
		*fd_out = fd;
		return strlen(start);
	}

	/*
	 *	EEXIST is only OK when we're calling mkdir on the
	 *	whole path, and it exists which should have been
	 *	caught by fr_mkdir before calling this function.
	 *
	 *	Unless we're running in an environment with multiple
	 *	processes, in which case EEXIST means that another
	 *	process created this directory in between our check
	 *	and our creation.
	 */
	if (errno == EEXIST) {
		fd = open(path, O_DIRECTORY);
		if (fd < 0) {
			fr_strerror_printf("Failed opening existing directory: %s", fr_syserror(errno));
			goto mkdir_error;
		}
		*fd_out = fd;
		return strlen(start);
	}

	/*
	 *	ENOENT means we're trying to create too much path
	 *	at once.  Recurse to discover the deepest path
	 *	component that already exists.
	 */
	if (errno != ENOENT) {
		fr_strerror_printf("Failed creating directory path: %s", fr_syserror(errno));
		goto mkdir_error;
	}

	/*
	 *	A component in the path doesn't
	 *	exist.  Look for the LAST path name.  Try
	 *	to create that.  If there's an error, we leave
	 *	the path path as the one at which the
	 *	error occurred.
	 */
	p = strrchr(path, FR_DIR_SEP);
	if (!p || (p == path)) return start - path;	/* last path component and we've previously failed */

	*p = '\0';
	if (_fr_mkdir(fd_out, start, path, mode, func, uctx) <= 0) return start - p;

	fr_assert_msg((*fd_out) >= 0, "Logic error - Bad FD %i", *fd_out);

	/*
	 *	At this point *fd_out, should be an FD
	 *	for the containing directory.
	 *
	 *	Dir may already exist if we're racing
	 *	other processes as we do in CI.
	 */
	if (mkdirat(*fd_out, p + 1, 0700) < 0) {
		/*
		 *	This is usually because of a race with
		 *	other processes trying to create the
		 *	same directory.
		 */
		if (errno == EEXIST) {
			fd = openat(*fd_out, p + 1, O_DIRECTORY);
			if (fd < 0) {
				fr_strerror_printf_push("Failed opening existing directory path component: %s",
							fr_syserror(errno));
				goto mkdirat_error;
			}
			*p = FR_DIR_SEP;
			goto done;
		}

		fr_strerror_printf_push("Failed creating directory path component: %s", fr_syserror(errno));

	mkdirat_error:
		close(*fd_out);
		*fd_out = -1;
		return start - p;
	}

	fd = openat(*fd_out, p + 1, O_DIRECTORY);
	if (fd < 0) {
		fr_strerror_printf_push("Failed opening directory we "
					"created: %s", fr_syserror(errno));
		goto mkdirat_error;
	}

	if (fchmod(fd, mode) < 0) {
		fr_strerror_printf_push("Failed setting permissions on "
					"directory we created: %s", fr_syserror(errno));
		goto mkdirat_error;
	}

	*p = FR_DIR_SEP;

	/*
	 *	Call the user function
	 */
	if (func && (func(fd, path, uctx) < 0)) {
		fr_strerror_printf_push("Callback failed processing directory \"%s\"", path);
		goto mkdirat_error;
	}

	/*
	 *	Swap active *fd_out to point to the dir
	 *      we just created.
	 */
done:
	close(*fd_out);
	*fd_out = fd;

	return strlen(start);
}

/** Create directories that are missing in the specified path
 *
 * @param[out] fd_out	If not NULL, will contain a file descriptor
 *			for the deepest path component created.
 * @param[in] path	to populate with directories.
 * @param[in] len	Length of the path string.
 * @param[in] mode	for new directories.
 * @param[in] func	to call each time a new directory is created.
 * @param[in] uctx	to pass to func.
 * @return
 *	- >0 on success.
 *	- <= 0 on failure. Negative offset pointing to the
 *	  path separator of the path component that caused the error.
 */
ssize_t fr_mkdir(int *fd_out, char const *path, ssize_t len, mode_t mode, fr_mkdir_func_t func, void *uctx)
{
	char	*our_path;
	int	fd = -1;
	ssize_t	slen;

	if (len < 0) len = strlen(path);
	if (len == 0) return 0;

	/*
	 *	Fast path (har har)
	 *
	 *	Avoids duping the input for the
	 *	common case.
	 */
	fd = open(path, O_DIRECTORY);
	if (fd >= 0) goto done;

	/*
	 *	Dup the amount of input path
	 *      we need.
	 */
	our_path = talloc_bstrndup(NULL, path, (size_t)len);
	if (!our_path) {
		fr_strerror_const("Out of memory");
		return -1;
	}

	fr_strerror_clear();	/* We make liberal use of push */

	/*
	 *	Call the recursive function to
	 *	create any missing dirs in the
	 *	specified path.
	 */
	slen = _fr_mkdir(&fd, our_path, our_path, mode, func, uctx);
	talloc_free(our_path);
	if (slen <= 0) return slen;

done:
	if (fd_out) {
		*fd_out = fd;
	} else {
		close(fd);
	}

	return len;
}

/** Convenience wrapper around realpath
 *
 * Wraps realpath, but takes a path with an explicit length, and returns
 * the result in a talloced buffer.
 *
 * On error, errno is set, and the string version of the error is
 * available with fr_strerror().
 *
 * @param[in] ctx	in which to allocate the result.
 * @param[in] path	To convert to an absolute path.
 * @param[in] len	How much of 'path' to read.  If < 0, then
 *			the entire path will be used.
 * @return
 *	- NULL on error.
 *	- The absolute version of the input path on success.
 */
char *fr_realpath(TALLOC_CTX *ctx, char const *path, ssize_t len)
{
	char		*tmp_path = NULL, *abs_path, *talloc_abs_path;

	if (len > 0) path = tmp_path = talloc_bstrndup(NULL, path, (size_t)len);

	abs_path = realpath(path, NULL);
	if (!abs_path) {
		fr_strerror_printf("Failed resolving path \"%pV\": %s",
				   fr_box_strvalue_buffer(path), fr_syserror(errno));
		talloc_free(tmp_path);
		return NULL;
	}

	talloc_free(tmp_path);

	talloc_abs_path = talloc_strdup(ctx, abs_path);
	free(abs_path);
	if (!talloc_abs_path) {
		fr_strerror_const("Out of Memory");
		return NULL;
	}

	return talloc_abs_path;
}

/** Create an empty file
 *
 * @param[out] fd_out	If not NULL, will contain a file descriptor
 *			for the file we just opened.
 * @param[in] filename	path to file.
 * @param[in] mode	Specifies the file mode bits be applied.
 * @param[in] mkdir	Whether we should create directories
 *			for any missing path components.
 * @param[in] dir_mode	Mode of any directories created.
 * @return
 *	- >0 on success.
 *	- <= 0 on failure. Error available in error stack (use fr_strerror())
 */
ssize_t fr_touch(int *fd_out, char const *filename, mode_t mode, bool mkdir, mode_t dir_mode) {
	int fd;

	fd = open(filename, O_WRONLY | O_CREAT, mode);
	if (fd < 0) {
		ssize_t slen = 0;
		char	*q;

		if (mkdir && (errno == ENOENT) && (q = strrchr(filename, FR_DIR_SEP))) {
			int dir_fd;

			slen = fr_mkdir(&dir_fd, filename, q - filename, dir_mode, NULL, NULL);
			if (slen <= 0) return slen;

			fd = openat(dir_fd, q + 1, O_WRONLY | O_CREAT, mode);
			if (fd >= 0) {
				close(dir_fd);
				close(fd);
				return strlen(filename);
			}
			close(dir_fd);
			slen = -(q - filename);
		}
		fr_strerror_printf("Failed creating file: %s", fr_syserror(errno));
		return slen;
	}

	if (fd_out) {
		*fd_out = fd;
	} else {
		close(fd);
	}

	return strlen(filename);
}

/** Remove a regular file from the filesystem
 *
 * @param[in] filename path to file.
 * @return
 * 	- -1 On error.
 * 	- 0 if the file was removed.
 * 	- 1 if the file didn't exist.
 */
int fr_unlink(char const *filename) {
	if (unlink(filename) == 0) return 0;

	if (errno == ENOENT) return 1;

	fr_strerror_printf("Failed removing regular file \"%s\": %s", filename, fr_syserror(errno));

	return -1;
}

/** Intended to be used in logging functions to make output more readable
 *
 * This function is not performant and should probably not be used at runtime.
 *
 * @param[in] filename	to strip working directory from.
 * @return Position in filename after our working directory.
 */
char const *fr_cwd_strip(char const *filename)
{
	static char our_wd[MAXPATHLEN];
	char *found;

	if (!getcwd(our_wd, sizeof(our_wd))) return filename;

	found = strstr(filename, our_wd);
	if (found && (found == our_wd)) {
		filename += strlen(our_wd);
		while (*filename == '/') filename++;
		return filename;
	}

	return filename;
}

/** From a pathname, return fd and filename needed for *at() functions
 *
 * @param[in] dirfd	points to place to store the dirfd
 * @param[in] filename	points to placd to store a pointer into pathname
 *			that points to the filename
 * @param[in] pathname	the full pathname of the file
 *
 * @return
 *	- -1 on error
 *	-  0 on success
 */
int fr_dirfd(int *dirfd, char const **filename, char const *pathname)
{
	char const *last_slash = strrchr(pathname, '/');

	if (last_slash == NULL) {
		*filename = pathname;
		*dirfd = AT_FDCWD;
		return 0;
	}
	{
		char dirpath[(last_slash - pathname) + 1];

		memcpy(dirpath, pathname, last_slash - pathname);
		dirpath[last_slash - pathname] = '\0';
		*filename = last_slash + 1;
		*dirfd = open(dirpath, O_DIRECTORY);
		return (*dirfd < 0) ? -1 : 0;
	}
}
