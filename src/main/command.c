/*
 * command.c	Command socket processing.
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
 * Copyright 2008 The FreeRADIUS server project
 * Copyright 2008 Alan DeKok <aland@deployingradius.com>
 */

#ifdef WITH_COMMAND_SOCKET

#include <freeradius-devel/parser.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/conduit.h>
#include <freeradius-devel/state.h>

#include <libgen.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <pwd.h>
#include <grp.h>

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#  include <gperftools/profiler.h>
#endif

typedef struct fr_command_table_t fr_command_table_t;

typedef int (*fr_command_func_t)(rad_listen_t *, int, char *argv[]);

#define FR_READ  (1)
#define FR_WRITE (2)

#define CMD_FAIL FR_CONDUIT_FAIL
#define CMD_OK   FR_CONDUIT_SUCCESS

struct fr_command_table_t {
	char const *command;
	int mode;		/* read/write */
	char const *help;
	fr_command_func_t func;
	fr_command_table_t *table;
};

#define COMMAND_SOCKET_MAGIC (0xffdeadee)
typedef struct fr_command_socket_t {
	uint32_t	magic;
	char const	*path;
	char		*copy;		/* <sigh> */
	gid_t		gid;		//!< Additional group authorized to connect to socket.
	char const	*gid_name;	//!< Name of additional group (resolved to gid later).
	char const	*mode_name;
	bool		peercred;
	bool		blocking;
	char		user[256];

	/*
	 *	The next few entries handle fake packets injected by
	 *	the control socket.
	 */
	fr_ipaddr_t	src_ipaddr; /* src_port is always 0 */
	fr_ipaddr_t	dst_ipaddr;
	uint16_t	dst_port;
	rad_listen_t	*inject_listener;
	RADCLIENT	*inject_client;

	fr_cs_buffer_t  co;
} fr_command_socket_t;

static const CONF_PARSER command_config[] = {
	{ FR_CONF_OFFSET("socket", PW_TYPE_STRING, fr_command_socket_t, path), .dflt = "${run_dir}/radiusd.sock" },
	{ FR_CONF_DEPRECATED("uid", PW_TYPE_STRING, fr_command_socket_t, NULL) },
	{ FR_CONF_OFFSET("gid", PW_TYPE_STRING, fr_command_socket_t, gid_name) },
	{ FR_CONF_OFFSET("mode", PW_TYPE_STRING, fr_command_socket_t, mode_name) },
	{ FR_CONF_OFFSET("peercred", PW_TYPE_BOOLEAN, fr_command_socket_t, peercred), .dflt = "yes" },
	{ FR_CONF_OFFSET("blocking", PW_TYPE_BOOLEAN, fr_command_socket_t, blocking),  },
	CONF_PARSER_TERMINATOR
};

static FR_NAME_NUMBER mode_names[] = {
	{ "ro", FR_READ },
	{ "read-only", FR_READ },
	{ "read-write", FR_READ | FR_WRITE },
	{ "rw", FR_READ | FR_WRITE },
	{ NULL, 0 }
};

static char debug_log_file_buffer[1024];
extern fr_cond_t *debug_condition;
extern fr_log_t debug_log;

#if !defined(HAVE_GETPEEREID) && defined(SO_PEERCRED)
static int getpeereid(int s, uid_t *euid, gid_t *egid)
{
	struct ucred cr;
	socklen_t cl = sizeof(cr);

	if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0) {
		return -1;
	}

	*euid = cr.uid;
	*egid = cr.gid;
	return 0;
}

/* we now have getpeereid() in this file */
#define HAVE_GETPEEREID (1)

#endif /* HAVE_GETPEEREID */

#if 0
/*
 *	Enable this function if you're running on OSX and want to use
 *	valgrind.  Valgrind doesn't implement openat() etc., so this
 *	old / shorter function works.
 */
static int fr_server_domain_socket(char const *path, UNUSED gid_t gid)
{
        int sockfd;
	size_t len;
	socklen_t socklen;
        struct sockaddr_un salocal;
	struct stat buf;

	len = strlen(path);
	if (len >= sizeof(salocal.sun_path)) {
		fr_strerror_printf("Path length (%zu) exceeds system limit for unix socket paths (%zu)",
				   len, sizeof(salocal.sun_path));
		return -1;
	}

        if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fr_strerror_printf("Failed creating socket: %s",
			fr_syserror(errno));
		return -1;
        }

	memset(&salocal, 0, sizeof(salocal));
        salocal.sun_family = AF_UNIX;
	memcpy(salocal.sun_path, path, len + 1); /* SUN_LEN does strlen */

	socklen = SUN_LEN(&salocal);

	/*
	 *	Check the path.
	 */
	if (stat(path, &buf) < 0) {
		if (errno != ENOENT) {
			fr_strerror_printf("Failed to stat %s: %s",
			       path, fr_syserror(errno));
			close(sockfd);
			return -1;
		}

		/*
		 *	FIXME: Check the enclosing directory?
		 */
	} else {		/* it exists */
		if (!S_ISREG(buf.st_mode)
#ifdef S_ISSOCK
		    && !S_ISSOCK(buf.st_mode)
#endif
			) {
			fr_strerror_printf("Cannot turn %s into socket", path);
			close(sockfd);
			return -1;
		}

		/*
		 *	Refuse to open sockets not owned by us.
		 */
		if (buf.st_uid != geteuid()) {
			fr_strerror_printf("We do not own %s", path);
			close(sockfd);
			return -1;
		}

		if (unlink(path) < 0) {
			fr_strerror_printf("Failed to delete %s: %s",
			       path, fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}

        if (bind(sockfd, (struct sockaddr *)&salocal, socklen) < 0) {
		fr_strerror_printf("Failed binding to %s: %s",
			path, fr_syserror(errno));
		close(sockfd);
		return -1;
        }

	/*
	 *	FIXME: There's a race condition here.  But Linux
	 *	doesn't seem to permit fchmod on domain sockets.
	 */
	if (chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0) {
		fr_strerror_printf("Failed setting permissions on %s: %s",
		       path, fr_syserror(errno));
		close(sockfd);
		return -1;
	}

	if (listen(sockfd, 8) < 0) {
		fr_strerror_printf("Failed listening to %s: %s",
			path, fr_syserror(errno));
		close(sockfd);
		return -1;
        }

#ifdef O_NONBLOCK
	{
		int flags;

		if ((flags = fcntl(sockfd, F_GETFL, NULL)) < 0)  {
			fr_strerror_printf("Failure getting socket flags: %s",
				fr_syserror(errno));
			close(sockfd);
			return -1;
		}

		flags |= O_NONBLOCK;
		if( fcntl(sockfd, F_SETFL, flags) < 0) {
			fr_strerror_printf("Failure setting socket flags: %s",
				fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}
#endif

	return sockfd;
}
#else  /* OSX VALGRIND */

#if !defined(HAVE_OPENAT) || !defined(HAVE_MKDIRAT) || !defined(HAVE_UNLINKAT) || !defined(HAVE_FCHMODAT) || !defined(HAVE_FCHOWNAT)
static int fr_server_domain_socket(UNUSED char const *path, UNUSED gid_t gid)
{
	fr_strerror_printf("Unable to initialise control socket.  Upgrade to POSIX-2008 compliant libc");
	return -1;
}
#else
/** Create a unix socket, and enforce permissions using the file system
 *
 * The way it does this depends on the operating system. On Linux systems permissions
 * can be set on the socket directly and the system will enforce them.
 *
 * On most other systems fchown and fchmod fail when called with socket descriptors,
 * and although permissions can be changed in other ways, they're not enforced.
 *
 * For these systems we use the permissions on the parent directory to enforce
 * permissions on the socket. It's not safe to modify these permissions ourselves
 * due to TOCTOU attacks, so if they don't match what we require, we error out and
 * get the user to change them (which arguably isn't any safer, but releases us of
 * the responsibility).
 *
 * @note must be called without effective root permissions (#fr_suid_down).
 *
 * @param path where domain socket should be created.
 * @param gid Alternative group to grant read/write access to the socket.
 * @return
 *	- A file descriptor for the bound socket on success.
 *	- -1 on failure.
 */
static int fr_server_domain_socket(char const *path, gid_t gid, bool blocking)
{
	int			dir_fd = -1, path_fd = -1, sock_fd = -1, parent_fd = -1;
	char const		*name;
	char			*buff = NULL, *dir = NULL, *p;

	uid_t			euid, suid;
	gid_t			egid;

	mode_t			perm = 0;
	mode_t			dir_perm;
	struct stat		st;

	size_t			len;

	socklen_t		socklen;
	struct sockaddr_un	salocal;

	rad_assert(path);

	euid = geteuid();
	egid = getegid();

	/*
	 *	In the Linux implementation, sockets which are visible in the
	 *	filesystem honor the permissions of the directory they are in.  Their
	 *	owner, group, and permissions can be changed.  Creation of a new
	 *	socket will fail if the process does not have write and search
	 *	(execute) permission on the directory the socket is created in.
	 *	Connecting to the socket object requires read/write permission.
	 */
	perm = (S_IREAD | S_IWRITE);
	dir_perm = (S_IREAD | S_IWRITE | S_IEXEC);
	if (gid != (gid_t) -1) {
		perm |= (S_IRGRP | S_IWGRP);
		dir_perm |= (S_IRGRP | S_IXGRP);
	}

	buff = talloc_strdup(NULL, path);
	if (!buff) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	/*
	 *	Some implementations modify it in place others use internal
	 *	storage *sigh*. dirname also formats the path else we wouldn't
	 *	be using it.
	 */
	dir = dirname(buff);
	if (dir != buff) {
		dir = talloc_strdup(NULL, dir);
		MEM(dir);
		talloc_free(buff);
	}

	p = strrchr(dir, FR_DIR_SEP);
	if (!p) {
		fr_strerror_printf("Failed determining parent directory");
	error:
		talloc_free(dir);
		if (dir_fd >= 0) close(dir_fd);
		if (path_fd >= 0) close(path_fd);
		if (sock_fd >= 0) close(sock_fd);
		if (parent_fd >= 0) close(parent_fd);
		return -1;
	}

	*p = '\0';

	/*
	 *	Ensure the parent of the control socket directory exists,
	 *	and the euid we're running under has access to it.
	 *
	 *	This must be done suid_down, so we can't be tricked into
	 *	accessing a directory owned by root.
	 */
	parent_fd = open(dir, O_DIRECTORY);
	if (parent_fd < 0) {
		struct passwd *user;
		struct group *group;

		if (errno != ENOENT) {
			fr_strerror_printf("Can't open directory \"%s\": %s", dir, fr_syserror(errno));
			goto error;
		}

		if (rad_getpwuid(NULL, &user, euid) < 0) {
			fr_strerror_printf("Failed resolving euid to user: %s", fr_strerror());
			goto error;
		}
		if (rad_getgrgid(NULL, &group, egid) < 0) {
			fr_strerror_printf("Failed resolving egid to group: %s", fr_strerror());
			talloc_free(user);
			goto error;
		}

		fr_strerror_printf("Can't open directory \"%s\": Create it and allow writing by "
				   "user %s or group %s", dir, user->pw_name, group->gr_name);

		talloc_free(user);
		talloc_free(group);
		goto error;
	}

	*p = FR_DIR_SEP;

	dir_fd = openat(parent_fd, p + 1, O_NOFOLLOW | O_DIRECTORY);
	if (dir_fd < 0) {
		int ret = 0;

		if (errno != ENOENT) {
			rad_file_error(errno);
			fr_strerror_printf("Failed opening control socket directory \"%s\": %s", dir, fr_strerror());
			goto error;
		}

		/*
		 *	This fails if the radius user can't write
		 *	to the parent directory.
		 */
	 	if (mkdirat(parent_fd, p + 1, dir_perm) < 0) {
			rad_file_error(errno);
			fr_strerror_printf("Failed creating control socket directory \"%s\": %s", dir, fr_strerror());
			goto error;
	 	}

		dir_fd = openat(parent_fd, p + 1, O_NOFOLLOW | O_DIRECTORY);
		if (dir_fd < 0) {
			fr_strerror_printf("Failed opening the control socket directory we created: %s",
					   fr_syserror(errno));
			goto error;
		}

		/*
		 *	Can't set groups other than ones we belong
		 *	to unless we suid_up.
		 */
		rad_suid_up();
		if (gid != (gid_t)-1) ret = fchown(dir_fd, euid, gid);
		rad_suid_down();
		if (ret < 0) {
			fr_strerror_printf("Failed changing group of control socket directory: %s",
					   fr_syserror(errno));
			goto error;
		}
	/*
	 *	Control socket dir already exists, but we still need to
	 *	check the permissions are what we expect.
	 */
	} else {
		int ret;
		int client_fd;

		ret = fstat(dir_fd, &st);
		if (ret < 0) {
			fr_strerror_printf("Failed checking permissions of control socket directory: %s",
					   fr_syserror(errno));
			goto error;
		}

		if (st.st_uid != euid) {
			struct passwd *need_user, *have_user;

			if (rad_getpwuid(NULL, &need_user, euid) < 0) {
				fr_strerror_printf("Failed resolving socket dir uid to user: %s", fr_strerror());
				goto error;
			}
			if (rad_getpwuid(NULL, &have_user, st.st_uid) < 0) {
				fr_strerror_printf("Failed resolving socket dir gid to group: %s", fr_strerror());
				talloc_free(need_user);
				goto error;
			}
			fr_strerror_printf("Socket directory \"%s\" must be owned by user %s, currently owned "
					   "by user %s", dir, need_user->pw_name, have_user->pw_name);
			talloc_free(need_user);
			talloc_free(have_user);
			goto error;
		}

		if ((gid != (gid_t)-1) && (st.st_gid != gid)) {
			/*
			 *	Can't set groups other than ones we belong
			 *	to unless we suid_up.
			 */
			rad_suid_up();
			if (gid != (gid_t)-1) ret = fchown(dir_fd, euid, gid);
			rad_suid_down();
			if (ret < 0) {
				struct group *need_group, *have_group;

				if (rad_getgrgid(NULL, &need_group, gid) < 0) {
					fr_strerror_printf("Failed resolving socket directory uid to user: %s",
							   fr_strerror());
					goto error;
				}
				if (rad_getgrgid(NULL, &have_group, st.st_gid) < 0) {
					fr_strerror_printf("Failed resolving socket directory gid to group: %s",
							   fr_strerror());
					talloc_free(need_group);
					goto error;
				}
				fr_strerror_printf("Failed changing ownership of socket directory \"%s\" from "
						   "group %s, to group %s", dir,
						   need_group->gr_name, have_group->gr_name);
				talloc_free(need_group);
				talloc_free(have_group);

				goto error;
			}
		}

		if ((dir_perm & 0777) != (st.st_mode & 0777) &&
		    (fchmod(dir_fd, (st.st_mode & 7000) | dir_perm)) < 0) {
			char str_need[10], oct_need[5];
			char str_have[10], oct_have[5];

			rad_mode_to_str(str_need, dir_perm);
			rad_mode_to_oct(oct_need, dir_perm);
			rad_mode_to_str(str_have, st.st_mode);
			rad_mode_to_oct(oct_have, st.st_mode);
			fr_strerror_printf("Failed changing permissions on socket directory \"%s\" from %s "
					   "(%s) to %s (%s): %s", dir, str_have, oct_have,
					   str_need, oct_need, fr_syserror(errno));

			goto error;
		}

		/*
		 *	Check if a server is already listening on the
		 *	socket?
		 */
		client_fd = fr_socket_client_unix(path, false);
		if (client_fd >= 0) {
			fr_strerror_printf("Control socket '%s' is already in use", path);
			close(client_fd);
			goto error;
		}
		fr_strerror();	/* Clear any errors */
	}

	name = strrchr(path, FR_DIR_SEP);
	if (!name) {
		fr_strerror_printf("Can't determine socket name");
		goto error;
	}
	name++;

	/*
	 *	We've checked the containing directory has the permissions
	 *	we expect, and as we have the FD, and aren't following
	 *	symlinks no one can trick us into changing or creating a
	 *	file elsewhere.
	 *
	 *	It's possible an attacker may still be able to create hard
	 *	links, for the socket file. But they would need write
	 *	access to the directory we just created or verified, so
	 *	this attack vector is unlikely.
	 */
	rad_suid_up();	/* Need to be root to change euid and egid */
	suid = geteuid();

	/*
	 *	Group needs to be changed first, because if we change
	 *	to a non root user, we can no longer set it.
	 */
	if ((gid != (gid_t)-1) && (rad_segid(gid) < 0)) {
		fr_strerror_printf("Failed setting egid: %s", fr_strerror());
		rad_suid_down();
		goto error;
	}

	/*
	 *	Reset euid back to FreeRADIUS user
	 */
	if (rad_seuid(euid) < 0) {
		fr_strerror_printf("Failed restoring euid: %s", fr_strerror());
		rad_segid(egid);
		rad_suid_down();
		goto error;
	}

	/*
	 *	The original code, did openat, used fstat to figure out
	 *	what type the file was and then used unlinkat to unlink
	 *	it. Except on OSX (at least) openat refuses to open
	 *	socket files. So we now rely on the fact that unlinkat
	 *	has sane and consistent behaviour, and will not unlink
	 *	directories. unlinkat should also fail if the socket user
	 *	hasn't got permission to modify the socket.
	 */
	if ((unlinkat(dir_fd, name, 0) < 0) && (errno != ENOENT)) {
		fr_strerror_printf("Failed removing stale socket: %s", fr_syserror(errno));
	sock_error:
		/*
		 *	Restore suid to ensure rad_suid_up continues
		 *	to work correctly.
		 */
		rad_seuid(suid);
		if (gid != (gid_t)-1) rad_segid(egid);
		/*
		 *	Then SUID down, to ensure rad_suid_up/down continues
		 *	to work correctly.
		 */
		rad_suid_down();
		goto error;
	}

	/*
	 *	At this point we should have established a secure directory
	 *	to house our socket, and cleared out any stale sockets.
	 */
	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		fr_strerror_printf("Failed opening socket: %s", fr_syserror(errno));
		goto sock_error;
	}

#ifdef HAVE_BINDAT
	len = strlen(name);
#else
	len = strlen(path);
#endif
	if (len >= sizeof(salocal.sun_path)) {
		fr_strerror_printf("Path length (%zu) exceeds system limit for unix socket paths (%zu)",
				   len, sizeof(salocal.sun_path));
		goto sock_error;
	}

	memset(&salocal, 0, sizeof(salocal));
	salocal.sun_family = AF_UNIX;

#ifdef HAVE_BINDAT
	memcpy(salocal.sun_path, name, len + 1); /* SUN_LEN does strlen */
#else
	memcpy(salocal.sun_path, path, len + 1); /* SUN_LEN does strlen */
#endif
	socklen = SUN_LEN(&salocal);

	/*
	 *	The correct function to use here is bindat(), but only
	 *	quite recent versions of FreeBSD actually have it, and
	 *	it's definitely not POSIX.
	 */
#ifdef HAVE_BINDAT
	if (bindat(dir_fd, sock_fd, (struct sockaddr *)&salocal, socklen) < 0) {
#else
	if (bind(sock_fd, (struct sockaddr *)&salocal, socklen) < 0) {
#endif
		fr_strerror_printf("Failed binding socket: %s", fr_syserror(errno));
		goto sock_error;
	}

	/*
	 *	Previous code used fchown to set ownership before the
	 *	socket was bound.  Unfortunately this only seemed to
	 *	work on Linux, on OSX and FreeBSD this operation would
	 *	throw an EINVAL error.
	 */
        if (fchownat(dir_fd, name, euid, gid, AT_SYMLINK_NOFOLLOW) < 0) {
                struct passwd *user;
                struct group *group;
                int fchown_err = errno;


                if (rad_getpwuid(NULL, &user, euid) < 0) {
                        fr_strerror_printf("Failed resolving socket uid to user: %s", fr_strerror());
                        goto sock_error;
                }
                if (rad_getgrgid(NULL, &group, gid) < 0) {
                        fr_strerror_printf("Failed resolving socket gid to group: %s", fr_strerror());
                        talloc_free(user);
                        goto sock_error;
                }

                fr_strerror_printf("Failed changing socket ownership to %s:%s: %s", user->pw_name, group->gr_name,
                                   fr_syserror(fchown_err));
                talloc_free(user);
                talloc_free(group);
                goto sock_error;
        }

	/*
	 *	Direct socket permissions are only useful on Linux which
	 *	actually enforces them. BSDs may not... or they may...
	 *	OSX 10.11.x (EL-Capitan) seems to.
	 *
	 *	Previous code used fchmod on sock_fd before the bind,
	 *	but this didn't always set the correct permissions.
	 *
	 *	fchmodat seems to work more reliably, and has the same
	 *	resistance against TOCTOU attacks.
	 *
	 *	AT_SYMLINK_NOFOLLOW causes this to fail on Linux.
	 */
	if (fchmodat(dir_fd, name, perm, 0) < 0) {
		char str_need[10], oct_need[5];

		rad_mode_to_str(str_need, perm);
		rad_mode_to_oct(oct_need, perm);
		fr_strerror_printf("Failed changing socket permissions to %s (%s): %s", str_need, oct_need,
				   fr_syserror(errno));
		goto sock_error;
	}

	if (listen(sock_fd, 8) < 0) {
		fr_strerror_printf("Failed listening on socket: %s", fr_syserror(errno));
		goto sock_error;
	}

	if (!blocking && (fr_nonblock(sock_fd) < 0)) {
		fr_strerror_printf("Failed setting nonblock on socket: %s", fr_strerror());
		goto sock_error;
	}

	/*
	 *	Restore suid to ensure rad_suid_up continues
	 *	to work correctly.
	 */
	rad_seuid(suid);
	if (gid != (gid_t)-1) rad_segid(egid);
	rad_suid_down();

	close(dir_fd);
	if (path_fd >= 0) close(path_fd);
	close(parent_fd);

	return sock_fd;
}
#endif	/* HAVE_OPENAT, etc. */
#endif	/* OSX VALGRIND */

/*
 *	Turn off all debugging.  But don't touch the debug condition.
 */
static void command_debug_off(void)
{
	debug_log.dst = L_DST_NULL;
	debug_log.file = NULL;
	debug_log.cookie = NULL;
	debug_log.cookie_write = NULL;
}


static void command_close_socket(rad_listen_t *this)
{
	this->status = RAD_LISTEN_STATUS_EOL;

	if (debug_log.cookie == this) {
		command_debug_off();
	}

	/*
	 *	This removes the socket from the event fd, so no one
	 *	will be calling us any more.
	 */
	radius_update_listener(this);
}


#if defined(HAVE_FOPENCOOKIE) || defined (HAVE_FUNOPEN)
static pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 *	Callback from log.c, so that we can write debug output to the
 *	radmin socket.
 *
 *	We only have one debug condition, so we only need one mutex.
 */
#ifdef HAVE_FOPENCOOKIE
static ssize_t command_socket_write(void *cookie, char const *buffer, size_t len)
#else
static int command_socket_write(void *cookie, char const *buffer, int len)
#endif
{
	ssize_t r;
	rad_listen_t *listener = cookie;

	if (listener->status == RAD_LISTEN_STATUS_EOL) return 0;

	pthread_mutex_lock(&debug_mutex);

	r = fr_conduit_write(listener->fd, FR_CONDUIT_STDOUT, buffer, len);

	pthread_mutex_unlock(&debug_mutex);

	if (r <= 0) {
		command_close_socket(listener);
	}

	return r;
}
#endif

static ssize_t CC_HINT(format (printf, 2, 3)) cprintf(rad_listen_t *listener, char const *fmt, ...)
{
	ssize_t r, len;
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (listener->status == RAD_LISTEN_STATUS_EOL) return 0;

	r = fr_conduit_write(listener->fd, FR_CONDUIT_STDOUT, buffer, len);
	if (r <= 0) command_close_socket(listener);

	/*
	 *	FIXME: Keep writing until done?
	 */
	return r;
}

static ssize_t CC_HINT(format (printf, 2, 3)) cprintf_error(rad_listen_t *listener, char const *fmt, ...)
{
	ssize_t r, len;
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (listener->status == RAD_LISTEN_STATUS_EOL) return 0;

	r = fr_conduit_write(listener->fd, FR_CONDUIT_STDERR, buffer, len);
	if (r <= 0) command_close_socket(listener);

	/*
	 *	FIXME: Keep writing until done?
	 */
	return r;
}

static int command_hup(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t *instance;

	if (argc == 0) {
		radius_signal_self(RADIUS_SIGNAL_SELF_HUP);
		return CMD_OK;
	}

	/*
	 *	Hack a "main" HUP thingy
	 */
	if (strcmp(argv[0], "main.log") == 0) {
		hup_logfile();
		return CMD_OK;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		cprintf_error(listener, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	cprintf_error(listener, "HUP - NYI in version 4");

	return CMD_FAIL;
}

static int command_terminate(UNUSED rad_listen_t *listener,
			     UNUSED int argc, UNUSED char *argv[])
{
	radius_signal_self(RADIUS_SIGNAL_SELF_TERM);

	return CMD_OK;
}

static int command_uptime(rad_listen_t *listener,
			  UNUSED int argc, UNUSED char *argv[])
{
	char buffer[128];

	CTIME_R(&fr_start_time, buffer, sizeof(buffer));
	cprintf(listener, "Up since %s", buffer); /* no \r\n */

	return CMD_OK;
}

static int command_show_config(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_ITEM *ci;
	CONF_PAIR *cp;
	char const *value;

	if (argc != 1) {
		cprintf_error(listener, "No path was given\n");
		return CMD_FAIL;
	}

	ci = cf_reference_item(main_config.config, main_config.config, argv[0]);
	if (!ci) return CMD_FAIL;

	if (!cf_item_is_pair(ci)) return CMD_FAIL;

	cp = cf_item_to_pair(ci);
	value = cf_pair_value(cp);
	if (!value) return CMD_FAIL;

	cprintf(listener, "%s\n", value);

	return CMD_OK;
}

static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

/*
 *	FIXME: Recurse && indent?
 */
static void cprint_conf_parser(rad_listen_t *listener, int indent, CONF_SECTION *cs,
			       void const *base)

{
	int i;
	char const *name1 = cf_section_name1(cs);
	char const *name2 = cf_section_name2(cs);
	CONF_PARSER const *variables = cf_section_parse_table(cs);

	if (name2) {
		cprintf(listener, "%.*s%s %s {\n", indent, tabs, name1, name2);
	} else {
		cprintf(listener, "%.*s%s {\n", indent, tabs, name1);
	}

	indent++;

	/*
	 *	Print
	 */
	if (variables) for (i = 0; variables[i].name != NULL; i++) {
		void const *data;
		char buffer[INET6_ADDRSTRLEN];

		/*
		 *	No base struct offset, data must be the pointer.
		 *	If data doesn't exist, ignore the entry, there
		 *	must be something wrong.
		 */
		if (!base) {
			if (!variables[i].data) {
				continue;
			}

			data = variables[i].data;

		} else if (variables[i].data) {
			data = variables[i].data;

		} else {
			data = (((char const *)base) + variables[i].offset);
		}

		/*
		 *	Ignore the various flags
		 */
		switch (variables[i].type & 0xff) {
		default:
			cprintf(listener, "%.*s%s = ?\n", indent, tabs,
				variables[i].name);
			break;

		case PW_TYPE_INTEGER:
			cprintf(listener, "%.*s%s = %u\n", indent, tabs,
				variables[i].name, *(int const *) data);
			break;

		case PW_TYPE_IPV4_ADDR:
			inet_ntop(AF_INET, data, buffer, sizeof(buffer));
			break;

		case PW_TYPE_IPV6_ADDR:
			inet_ntop(AF_INET6, data, buffer, sizeof(buffer));
			break;

		case PW_TYPE_BOOLEAN:
			cprintf(listener, "%.*s%s = %s\n", indent, tabs,
				variables[i].name,
				((*(bool const *) data) == false) ? "no" : "yes");
			break;

		case PW_TYPE_STRING:
		case PW_TYPE_FILE_INPUT:
		case PW_TYPE_FILE_OUTPUT:
			/*
			 *	FIXME: Escape things in the string!
			 */
			if (*(char const * const *) data) {
				cprintf(listener, "%.*s%s = \"%s\"\n", indent, tabs,
					variables[i].name, *(char const * const *) data);
			} else {
				cprintf(listener, "%.*s%s = \n", indent, tabs,
					variables[i].name);
			}

			break;
		}
	}

	indent--;

	cprintf(listener, "%.*s}\n", indent, tabs);
}

static int command_show_module_config(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t *instance;

	if (argc != 1) {
		cprintf_error(listener, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		cprintf_error(listener, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	cprint_conf_parser(listener, 0, instance->cs, instance->data);

	return CMD_OK;
}

static char const *method_names[MOD_COUNT] = {
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"session",
	"pre-proxy",
	"post-proxy",
	"post-auth"
};


static int command_show_module_methods(rad_listen_t *listener, int argc, char *argv[])
{
	int i;
	CONF_SECTION *cs;
	module_instance_t const *instance;

	if (argc != 1) {
		cprintf_error(listener, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		cprintf_error(listener, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	for (i = 0; i < MOD_COUNT; i++) {
		if (instance->module->methods[i]) cprintf(listener, "%s\n", method_names[i]);
	}

	return CMD_OK;
}


static int command_show_module_flags(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t const *instance;

	if (argc != 1) {
		cprintf_error(listener, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		cprintf_error(listener, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	if ((instance->module->type & RLM_TYPE_THREAD_UNSAFE) != 0) cprintf(listener, "thread-unsafe\n");

	return CMD_OK;
}

static int command_show_module_status(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_SECTION *cs;
	const module_instance_t *instance;

	if (argc != 1) {
		cprintf_error(listener, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		cprintf_error(listener, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	if (!instance->force) {
		cprintf(listener, "alive\n");
	} else {
		cprintf(listener, "%s\n", fr_int2str(mod_rcode_table, instance->code, "<invalid>"));
	}


	return CMD_OK;
}


/*
 *	Show all loaded modules
 */
static int command_show_modules(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	CONF_SECTION *cs, *subcs;

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	subcs = NULL;
	while ((subcs = cf_subsection_find_next(cs, subcs, NULL)) != NULL) {
		char const *name1 = cf_section_name1(subcs);
		char const *name2 = cf_section_name2(subcs);

		module_instance_t *instance;

		if (name2) {
			instance = module_find(cs, name2);
			if (!instance) continue;

			cprintf(listener, "%s (%s)\n", name2, name1);
		} else {
			instance = module_find(cs, name1);
			if (!instance) continue;

			cprintf(listener, "%s\n", name1);
		}
	}

	return CMD_OK;
}

#ifdef WITH_PROXY
static int command_show_home_servers(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	int i;
	home_server_t *home;
	char const *type, *state, *proto;

	char buffer[INET6_ADDRSTRLEN];

	for (i = 0; i < 256; i++) {
		home = home_server_bynumber(i);
		if (!home) break;

		/*
		 *	Internal "virtual" home server.
		 */
		if (home->ipaddr.af == AF_UNSPEC) continue;

		if (home->type == HOME_TYPE_AUTH) {
			type = "auth";

		} else if (home->type == HOME_TYPE_ACCT) {
			type = "acct";

		} else if (home->type == HOME_TYPE_AUTH_ACCT) {
			type = "auth+acct";

#ifdef WITH_COA
		} else if (home->type == HOME_TYPE_COA) {
			type = "coa";
#endif

		} else continue;

		if (home->proto == IPPROTO_UDP) {
			proto = "udp";
		}
#ifdef WITH_TCP
		else if (home->proto == IPPROTO_TCP) {
			proto = "tcp";
		}
#endif
		else proto = "??";

		if (home->state == HOME_STATE_ALIVE) {
			state = "alive";

		} else if (home->state == HOME_STATE_ZOMBIE) {
			state = "zombie";

		} else if (home->state == HOME_STATE_IS_DEAD) {
			state = "dead";

		} else if (home->state == HOME_STATE_UNKNOWN) {
			time_t now = time(NULL);

			/*
			 *	We've recently received a packet, so
			 *	the home server seems to be alive.
			 *
			 *	The *reported* state changes because
			 *	the internal state machine NEEDS THE
			 *	RIGHT STATE.  However, reporting that
			 *	to the admin will confuse them.
			 *	So... we lie.  No, that dress doesn't
			 *	make you look fat...
			 */
			if ((home->last_packet_recv + (int)home->ping_interval) >= now) {
				state = "alive";
			} else {
				state = "unknown";
			}

		} else continue;

		cprintf(listener, "%s\t%s\t%d\t%s\t%s\t%s\t%d\n",
			fr_inet_ntoh(&home->ipaddr, buffer, sizeof(buffer)),
			home->name, home->port, proto, type, state,
			home->currently_outstanding);
	}

	return CMD_OK;
}
#endif

static int command_show_clients(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	int i;
	RADCLIENT *client;
	char buffer[256];
	char ipaddr[256];

	for (i = 0; i < 256; i++) {
		client = client_findbynumber(NULL, i);
		if (!client) break;

		fr_inet_ntoh(&client->ipaddr, buffer, sizeof(buffer));

		if (((client->ipaddr.af == AF_INET) &&
		     (client->ipaddr.prefix != 32)) ||
		    ((client->ipaddr.af == AF_INET6) &&
		     (client->ipaddr.prefix != 128))) {
			snprintf(ipaddr, sizeof(ipaddr), "%s/%d", buffer, client->ipaddr.prefix);
		} else {
			snprintf(ipaddr, sizeof(ipaddr), "%s", buffer);
		}

		cprintf(listener, "%s\t%s\t%s\t%s\n", ipaddr,
			client->shortname ? client->shortname : "\t",
			client->nas_type ? client->nas_type : "\t",
			client->server ? client->server : "\t");
	}

	return CMD_OK;
}


static int command_show_version(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	cprintf(listener, "%s\n", radiusd_version);
	return CMD_OK;
}

static int command_debug_level_global(rad_listen_t *listener, int argc, char *argv[])
{
	int number;

	if (argc == 0) {
		cprintf_error(listener, "Must specify <number>\n");
		return -1;
	}

	number = atoi(argv[0]);
	if ((number < 0) || (number > 4)) {
		cprintf_error(listener, "<number> must be between 0 and 4\n");
		return -1;
	}

	INFO("Global debug level set to %i, was %i", number, fr_debug_lvl);
	fr_debug_lvl = rad_debug_lvl = number;

	return CMD_OK;
}

static int command_debug_level_request(rad_listen_t *listener, int argc, char *argv[])
{
	int number;

	if (argc == 0) {
		cprintf_error(listener, "Must specify <number>\n");
		return -1;
	}

	number = atoi(argv[0]);
	if ((number < 0) || (number > 4)) {
		cprintf_error(listener, "<number> must be between 0 and 4\n");
		return -1;
	}

	INFO("Request debug level set to %i, was %i", number, req_debug_lvl);
	req_debug_lvl = number;

	return CMD_OK;
}

#ifndef NDEBUG
static void _command_talloc_report(const void *ptr, int depth, int max_depth, int is_ref, void *_f)
{
	const char *name = talloc_get_name(ptr);
	rad_listen_t *listener = talloc_get_type_abort(_f, rad_listen_t);

	if (is_ref) {
		cprintf(listener, "%*sreference to: %s\n", depth * 4, "", name);
		return;
	}

	if (depth == 0) {
		cprintf(listener,
			"%stalloc report on '%s' (total %6lu bytes in %3lu blocks)\n",
			(max_depth < 0 ? "full " :""), name,
			(unsigned long)talloc_total_size(ptr),
			(unsigned long)talloc_total_blocks(ptr));
		return;
	}

	cprintf(listener,
		"%*s%-30s contains %6lu bytes in %3lu blocks (ref %d) %p\n",
		depth * 4, "",
		name,
		(unsigned long)talloc_total_size(ptr),
		(unsigned long)talloc_total_blocks(ptr),
		(int)talloc_reference_count(ptr), ptr);
}

static int command_show_memory_report(rad_listen_t *listener, int argc, UNUSED char *argv[])
{
	if (argc != 0) {
		cprintf_error(listener, "Command takes no arguments");
	}

	if (!main_config.talloc_memory_report) {
		cprintf(listener, "Memory debugging not enabled.  To enable, pass -Ms when starting the server\n");
		return CMD_OK;
	}

	INFO("Writing talloc memory report to command socket");

	talloc_report_depth_cb(talloc_null_ctx(), 0, -1, _command_talloc_report, listener);

	return CMD_OK;
}
#endif

#if defined(HAVE_FOPENCOOKIE) || defined (HAVE_FUNOPEN)
static int command_debug_socket(rad_listen_t *listener, int argc, char *argv[])
{
	uint32_t notify;

	if (rad_debug_lvl && default_log.dst == L_DST_STDOUT) {
		cprintf_error(listener, "Cannot redirect debug logs to a socket when already in debugging mode.\n");
		return -1;
	}

	if ((argc == 0) || (strcmp(argv[0], "off") == 0)) {
		notify = htonl(FR_NOTIFY_BUFFERED);

		/*
		 *	Tell radmin to go into buffered mode.
		 */
		(void) fr_conduit_write(listener->fd, FR_CONDUIT_NOTIFY, &notify, sizeof(notify));

		command_debug_off();
		return CMD_OK;
	}

	if (strcmp(argv[0], "on") != 0) {
		cprintf_error(listener, "Syntax error: got '%s', expected [on|off]", argv[0]);
		return -1;
	}

	/*
	 *	Don't allow people to stomp on each other.
	 */
	if ((debug_log.cookie != NULL) &&
	    (debug_log.cookie != listener)) {
		cprintf_error(listener, "ERROR: Someone else is already using the debug socket");
		return -1;
	}

	/*
	 *	Disable logging while we're mucking with the buffer.
	 */
	command_debug_off();

	debug_log.cookie = listener;
	debug_log.cookie_write = command_socket_write;
	debug_log.dst = L_DST_EXTRA;

	notify = htonl(FR_NOTIFY_UNBUFFERED);

	/*
	 *	Tell radmin to go into unbuffered mode.
	 */
	(void) fr_conduit_write(listener->fd, FR_CONDUIT_NOTIFY, &notify, sizeof(notify));

	return CMD_OK;
}
#endif

static int command_debug_file(rad_listen_t *listener, int argc, char *argv[])
{
	if (rad_debug_lvl && default_log.dst == L_DST_STDOUT) {
		cprintf_error(listener, "Cannot redirect debug logs to a file when already in debugging mode.\n");
		return -1;
	}

	if ((argc > 0) && (strchr(argv[0], FR_DIR_SEP) != NULL)) {
		cprintf_error(listener, "Cannot direct debug logs to absolute path.\n");
		return -1;
	}

	if (argc == 0) {
		command_debug_off();
		return CMD_OK;
	}

	/*
	 *	Disable logging while we're mucking with the buffer.
	 */
	command_debug_off();

	/*
	 *	This looks weird, but it's here to avoid locking
	 *	a mutex for every log message.
	 */
	memset(debug_log_file_buffer, 0, sizeof(debug_log_file_buffer));

	/*
	 *	Debug files always go to the logging directory.
	 */
	snprintf(debug_log_file_buffer, sizeof(debug_log_file_buffer),
		 "%s/%s", radlog_dir, argv[0]);

	debug_log.file = &debug_log_file_buffer[0];
	debug_log.dst = L_DST_FILES;

	INFO("Global debug log set to \"%s\"", debug_log.file);

	return CMD_OK;
}

static int command_debug_condition(rad_listen_t *listener, int argc, char *argv[])
{
	int i;
	char const *error;
	ssize_t slen = 0;
	fr_cond_t *new_condition = NULL;
	char *p, buffer[1024];

	/*
	 *	Disable it.
	 */
	if (argc == 0) {
		TALLOC_FREE(debug_condition);
		debug_condition = NULL;
		return CMD_OK;
	}

	if (!((argc == 1) &&
	      ((argv[0][0] == '"') || (argv[0][0] == '\'')))) {
		p = buffer;
		*p = '\0';
		for (i = 0; i < argc; i++) {
			size_t len;

			len = strlcpy(p, argv[i], buffer + sizeof(buffer) - p);
			p += len;
			*(p++) = ' ';
			*p = '\0';
		}

	} else {
		/*
		 *	Backwards compatibility.  De-escape the string.
		 */
		char quote;
		char *q;

		p = argv[0];
		q = buffer;

		quote = *(p++);

		while (true) {
			if (!*p) {
				error = "Unexpected end of string";
				slen = -strlen(argv[0]);
				p = argv[0];

				goto parse_error;
			}

			if (*p == quote) {
				if (p[1]) {
					error = "Unexpected text after end of string";
					slen = -(p - argv[0]);
					p = argv[0];

					goto parse_error;
				}
				*q = '\0';
				break;
			}

			if (*p == '\\') {
				*(q++) = p[1];
				p += 2;
				continue;
			}

			*(q++) = *(p++);
		}
	}

	p = buffer;

	slen = fr_cond_tokenize(NULL, NULL, p, &new_condition, &error, FR_COND_ONE_PASS);
	if (slen <= 0) {
		char *spaces, *text;

	parse_error:
		fr_canonicalize_error(NULL, &spaces, &text, slen, p);

		ERROR("Parse error in condition");
		ERROR("%s", p);
		ERROR("%s^ %s", spaces, error);

		cprintf_error(listener, "Parse error in condition \"%s\": %s\n", p, error);

		talloc_free(spaces);
		talloc_free(text);
		return CMD_FAIL;
	}

	/*
	 *	Delete old condition.
	 *
	 *	This is thread-safe because the condition is evaluated
	 *	in the main server thread, along with this code.
	 */
	TALLOC_FREE(debug_condition);
	debug_condition = new_condition;

	return CMD_OK;
}

#ifdef HAVE_GPERFTOOLS_PROFILER_H
static char profiler_log_buffer[1024];
/** Start the gperftools profiler
 *
 */
static int command_profiler_cpu_start(rad_listen_t *listener, int argc, char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (argc == 0) {
		cprintf_error(listener, "Need filename for profiler to write to.\n");
		return -1;
	}

	if ((argc > 0) && (strchr(argv[0], FR_DIR_SEP) != NULL)) {
		cprintf_error(listener, "Profiler file must be a relative path.\n");
		return -1;
	}

	/*
	 *	We get an error if we don't stop the current
	 *	profiler first.
	 */
	if (state.enabled) {
		ProfilerFlush();
		ProfilerStop();
	}

	/*
	 *	Profiler files always go to the logging directory.
	 */
	snprintf(profiler_log_buffer, sizeof(profiler_log_buffer),
		 "%s/%s", radlog_dir, argv[0]);

	errno = 0;
	if (ProfilerStart(profiler_log_buffer) == 0) {
		cprintf_error(listener, "Failed enabling profiler: %s\n",
			      errno ? fr_syserror(errno) : "unknown error");
		return -1;
	}

	return CMD_OK;
}

/** Stop the gperftools cpu profiler
 *
 */
static int command_profiler_cpu_stop(UNUSED rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	ProfilerFlush();
	ProfilerStop();

	return CMD_OK;
}

/** Show gperftools cpu profiler output file
 *
 */
static int command_profiler_cpu_show_file(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (!state.enabled) {
		cprintf_error(listener, "Profiler not enabled.\n");
		return -1;
	}

	cprintf(listener, "%s\n", state.profile_name);

	return CMD_OK;
}

/** Show gperftools cpu profiler samples collected
 *
 */
static int command_profiler_cpu_show_samples(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (!state.enabled) {
		cprintf_error(listener, "Profiler not enabled.\n");
		return -1;
	}

	cprintf(listener, "%i\n", state.samples_gathered);

	return CMD_OK;
}

/** Show gperftools cpu profiler start_time
 *
 */
static int command_profiler_cpu_show_start_time(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	char buffer[128];
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (!state.enabled) {
		cprintf_error(listener, "Profiler not enabled.\n");
		return -1;
	}

	CTIME_R(&state.start_time, buffer, sizeof(buffer));
	cprintf(listener, "%s", buffer);

	return CMD_OK;
}

/** Show gperftools cpu profiler status
 *
 */
static int command_profiler_cpu_show_status(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (state.enabled) {
		cprintf(listener, "running\n");
	} else {
		cprintf(listener, "stopped\n");
	}

	return CMD_OK;
}
#endif

static int command_show_debug_condition(rad_listen_t *listener,
					UNUSED int argc, UNUSED char *argv[])
{
	char buffer[1024];

	if (!debug_condition) {
		cprintf(listener, "\n");
		return CMD_OK;
	}

	cond_snprint(buffer, sizeof(buffer), debug_condition);

	cprintf(listener, "%s\n", buffer);
	return CMD_OK;
}


static int command_show_debug_file(rad_listen_t *listener,
					UNUSED int argc, UNUSED char *argv[])
{
	if (!debug_log.file) return CMD_FAIL;

	cprintf(listener, "%s\n", debug_log.file);
	return CMD_OK;
}


static int command_show_debug_level_global(rad_listen_t *listener,
					   UNUSED int argc, UNUSED char *argv[])
{
	cprintf(listener, "%d\n", rad_debug_lvl);
	return CMD_OK;
}

static int command_show_debug_level_request(rad_listen_t *listener,
					    UNUSED int argc, UNUSED char *argv[])
{
	cprintf(listener, "%d\n", req_debug_lvl);
	return CMD_OK;
}

static RADCLIENT *get_client(rad_listen_t *listener, int argc, char *argv[])
{
	RADCLIENT *client;
	fr_ipaddr_t ipaddr;
	int myarg;
	int proto = IPPROTO_UDP;
	RADCLIENT_LIST *list = NULL;

	if (argc < 1) {
		cprintf_error(listener, "Must specify <ipaddr>\n");
		return NULL;
	}

	/*
	 *	First arg is IP address.
	 */
	if (fr_inet_hton(&ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		cprintf_error(listener, "Failed parsing IP address; %s\n",
			fr_strerror());
		return NULL;
	}
	myarg = 1;

	while (myarg < argc) {
		if (strcmp(argv[myarg], "udp") == 0) {
			proto = IPPROTO_UDP;
			myarg++;
			continue;
		}

#ifdef WITH_TCP
		if (strcmp(argv[myarg], "tcp") == 0) {
			proto = IPPROTO_TCP;
			myarg++;
			continue;
		}
#endif

		if (strcmp(argv[myarg], "listen") == 0) {
			uint16_t server_port;
			fr_ipaddr_t server_ipaddr;

			if ((argc - myarg) < 2) {
				cprintf_error(listener, "Must specify listen <ipaddr> <port>\n");
				return NULL;
			}

			if (fr_inet_hton(&server_ipaddr, ipaddr.af, argv[myarg + 1], false) < 0) {
				cprintf_error(listener, "Failed parsing IP address; %s\n",
					      fr_strerror());
				return NULL;
			}

			server_port = atoi(argv[myarg + 2]);

			list = listener_find_client_list(&server_ipaddr, server_port, proto);
			if (!list) {
				cprintf_error(listener, "No such listener %s %s\n", argv[myarg + 1], argv[myarg + 2]);
				return NULL;
			}
			myarg += 3;
			continue;
		}

		cprintf_error(listener, "Unknown argument %s.\n", argv[myarg]);
		return NULL;
	}

	client = client_find(list, &ipaddr, proto);
	if (!client) {
		cprintf_error(listener, "No such client\n");
		return NULL;
	}

	return client;
}

#ifdef WITH_PROXY
static home_server_t *get_home_server(rad_listen_t *listener, int argc,
				    char *argv[], int *last)
{
	int myarg;
	home_server_t *home;
	uint16_t port;
	int proto = IPPROTO_UDP;
	fr_ipaddr_t ipaddr;

	if (argc < 2) {
		cprintf_error(listener, "Must specify <ipaddr> <port> [udp|tcp]\n");
		return NULL;
	}

	if (fr_inet_hton(&ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		cprintf_error(listener, "Failed parsing IP address; %s\n",
			fr_strerror());
		return NULL;
	}

	port = atoi(argv[1]);

	myarg = 2;

	while (myarg < argc) {
		if (strcmp(argv[myarg], "udp") == 0) {
			proto = IPPROTO_UDP;
			myarg++;
			continue;
		}

#ifdef WITH_TCP
		if (strcmp(argv[myarg], "tcp") == 0) {
			proto = IPPROTO_TCP;
			myarg++;
			continue;
		}
#endif

		/*
		 *	Unknown argument.  Leave it for the caller.
		 */
		break;
	}

	home = home_server_find(&ipaddr, port, proto);
	if (!home) {
		cprintf_error(listener, "No such home server\n");
		return NULL;
	}

	if (last) *last = myarg;

	return home;
}

static int command_set_home_server_state(rad_listen_t *listener, int argc, char *argv[])
{
	int last;
	home_server_t *home;

	if (argc < 3) {
		cprintf_error(listener, "Must specify <ipaddr> <port> [udp|tcp] <state>\n");
		return CMD_FAIL;
	}

	home = get_home_server(listener, argc, argv, &last);
	if (!home) {
		return CMD_FAIL;
	}

	if (strcmp(argv[last], "alive") == 0) {
		revive_home_server(NULL, home);

	} else if (strcmp(argv[last], "dead") == 0) {
		struct timeval now;

		gettimeofday(&now, NULL); /* we do this WAY too ofetn */
		mark_home_server_dead(home, &now);

	} else {
		cprintf_error(listener, "Unknown state \"%s\"\n", argv[last]);
		return CMD_FAIL;
	}

	return CMD_OK;
}

static int command_show_home_server_state(rad_listen_t *listener, int argc, char *argv[])
{
	home_server_t *home;

	home = get_home_server(listener, argc, argv, NULL);
	if (!home) return CMD_FAIL;

	switch (home->state) {
	case HOME_STATE_ALIVE:
		cprintf(listener, "alive\n");
		break;

	case HOME_STATE_IS_DEAD:
		cprintf(listener, "dead\n");
		break;

	case HOME_STATE_ZOMBIE:
		cprintf(listener, "zombie\n");
		break;

	case HOME_STATE_UNKNOWN:
		cprintf(listener, "unknown\n");
		break;

	default:
		cprintf(listener, "invalid\n");
		break;
	}

	return CMD_OK;
}
#endif

static int command_show_listener_enabled(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	if (main_config.drop_requests) {
		cprintf(listener, "no\n");
	} else {
		cprintf(listener, "yes\n");
	}

	return CMD_OK;
}

/*
 *	For encode/decode stuff
 */
static int null_socket_dencode(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	return 0;
}

static int null_socket_send(UNUSED rad_listen_t *listener, REQUEST *request)
{
	vp_cursor_t cursor;
	char *output_file;
	FILE *fp;

	output_file = request_data_reference(request, (void *)null_socket_send, 0);
	if (!output_file) {
		ERROR("No output file for injected packet %" PRIu64 "", request->number);
		return 0;
	}

	fp = fopen(output_file, "w");
	if (!fp) {
		ERROR("Failed to send injected file to %s: %s", output_file, fr_syserror(errno));
		return 0;
	}

	if (request->reply->code != 0) {
		char const *what = "reply";
		VALUE_PAIR *vp;
		char buffer[1024];

		if (request->reply->code < FR_MAX_PACKET_CODE) {
			what = fr_packet_codes[request->reply->code];
		}

		fprintf(fp, "%s\n", what);

		if (rad_debug_lvl) {
			RDEBUG("Injected %s packet to host %s port 0 code=%d, id=%d", what,
			       inet_ntop(request->reply->src_ipaddr.af,
					 &request->reply->src_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
					 request->reply->code, request->reply->id);
		}

		RINDENT();
		for (vp = fr_cursor_init(&cursor, &request->reply->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			fr_pair_snprint(buffer, sizeof(buffer), vp);
			fprintf(fp, "%s\n", buffer);
			RDEBUG("%s", buffer);
		}
		REXDENT();
	}
	fclose(fp);

	return 0;
}

static rad_listen_t *get_socket(rad_listen_t *listener, int argc,
			       char *argv[], int *last)
{
	rad_listen_t *sock;
	uint16_t port;
	int proto = IPPROTO_UDP;
	fr_ipaddr_t ipaddr;

	if (argc < 2) {
		cprintf_error(listener, "Must specify <ipaddr> <port> [udp|tcp]\n");
		return NULL;
	}

	if (fr_inet_hton(&ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		cprintf_error(listener, "Failed parsing IP address; %s\n",
			fr_strerror());
		return NULL;
	}

	port = atoi(argv[1]);

	if (last) *last = 2;
	if (argc > 2) {
		if (strcmp(argv[2], "udp") == 0) {
			proto = IPPROTO_UDP;
			if (last) *last = 3;
		}
#ifdef WITH_TCP
		if (strcmp(argv[2], "tcp") == 0) {
			proto = IPPROTO_TCP;
			if (last) *last = 3;
		}
#endif
	}

	sock = listener_find_byipaddr(&ipaddr, port, proto);
	if (!sock) {
		cprintf_error(listener, "No such listen section\n");
		return NULL;
	}

	return sock;
}


static int command_inject_to(rad_listen_t *listener, int argc, char *argv[])
{
	fr_command_socket_t *sock = listener->data;
	listen_socket_t *data;
	rad_listen_t *found;

	found = get_socket(listener, argc, argv, NULL);
	if (!found) {
		return 0;
	}

	data = found->data;
	sock->inject_listener = found;
	sock->dst_ipaddr = data->my_ipaddr;
	sock->dst_port = data->my_port;

	return CMD_OK;
}

static int command_inject_from(rad_listen_t *listener, int argc, char *argv[])
{
	RADCLIENT *client;
	fr_command_socket_t *sock = listener->data;

	if (argc < 1) {
		cprintf_error(listener, "No <ipaddr> was given\n");
		return 0;
	}

	if (!sock->inject_listener) {
		cprintf_error(listener, "You must specify \"inject to\" before using \"inject from\"\n");
		return 0;
	}

	sock->src_ipaddr.af = AF_UNSPEC;
	if (fr_inet_hton(&sock->src_ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		cprintf_error(listener, "Failed parsing IP address; %s\n",
			fr_strerror());
		return 0;
	}

	client = client_listener_find(sock->inject_listener, &sock->src_ipaddr,
				      0);
	if (!client) {
		cprintf_error(listener, "No such client %s\n", argv[0]);
		return 0;
	}
	sock->inject_client = client;

	return CMD_OK;
}

static int command_inject_file(rad_listen_t *listener, int argc, char *argv[])
{
	static int inject_id = 0;
	int ret;
	bool filedone;
	fr_command_socket_t *sock = listener->data;
	rad_listen_t *fake;
	RADIUS_PACKET *packet;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	FILE *fp;
	RAD_REQUEST_FUNP fun = NULL;
	char buffer[2048];

	if (argc < 2) {
		cprintf_error(listener, "You must specify <input-file> <output-file>\n");
		return 0;
	}

	if (!sock->inject_listener) {
		cprintf_error(listener, "You must specify \"inject to\" before using \"inject file\"\n");
		return 0;
	}

	if (!sock->inject_client) {
		cprintf_error(listener, "You must specify \"inject from\" before using \"inject file\"\n");
		return 0;
	}

	/*
	 *	Output files always go to the logging directory.
	 */
	snprintf(buffer, sizeof(buffer), "%s/%s", radlog_dir, argv[1]);

	fp = fopen(argv[0], "r");
	if (!fp ) {
		cprintf_error(listener, "Failed opening %s: %s\n",
			argv[0], fr_syserror(errno));
		return 0;
	}

	ret = fr_pair_list_afrom_file(NULL, &vp, fp, &filedone);
	fclose(fp);
	if (ret < 0) {
		cprintf_error(listener, "Failed reading attributes from %s: %s\n",
			argv[0], fr_strerror());
		return 0;
	}

	fake = talloc(NULL, rad_listen_t);
	memcpy(fake, sock->inject_listener, sizeof(*fake));

	/*
	 *	Re-write the IO for the listener.
	 */
	fake->encode = null_socket_dencode;
	fake->decode = null_socket_dencode;
	fake->send = null_socket_send;

	packet = fr_radius_alloc(NULL, false);
	packet->src_ipaddr = sock->src_ipaddr;
	packet->src_port = 0;

	packet->dst_ipaddr = sock->dst_ipaddr;
	packet->dst_port = sock->dst_port;
	packet->vps = vp;
	packet->id = inject_id++;

	if (fake->type == RAD_LISTEN_AUTH) {
		packet->code = PW_CODE_ACCESS_REQUEST;
		fun = rad_authenticate;

	} else {
#ifdef WITH_ACCOUNTING
		packet->code = PW_CODE_ACCOUNTING_REQUEST;
		fun = rad_accounting;
#else
		cprintf_error(listener, "This server was built without accounting support.\n");
		fr_radius_free(&packet);
		talloc_free(fake);
		return 0;
#endif
	}

	if (rad_debug_lvl) {
		DEBUG("Injecting %s packet from host %s port 0 code=%d, id=%d",
		      fr_packet_codes[packet->code],
		      inet_ntop(packet->src_ipaddr.af,
				&packet->src_ipaddr.ipaddr,
				buffer, sizeof(buffer)),
		      packet->code, packet->id);

		for (vp = fr_cursor_init(&cursor, &packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			fr_pair_snprint(buffer, sizeof(buffer), vp);
			DEBUG("\t%s", buffer);
		}

		WARN("INJECTION IS LEAKING MEMORY!");
	}

	if (!request_receive(NULL, fake, packet, sock->inject_client, fun)) {
		cprintf_error(listener, "Failed to inject request.  See log file for details\n");
		fr_radius_free(&packet);
		talloc_free(fake);
		return 0;
	}

#if 0
	/*
	 *	Remember what the output file is, and remember to
	 *	delete the fake listener when done.
	 */
	request_data_add(request, null_socket_send, 0, talloc_typed_strdup(NULL, buffer), true, false, false);
	request_data_add(request, null_socket_send, 1, fake, true, false, false);

#endif

	return CMD_OK;
}


static fr_command_table_t command_table_inject[] = {
	{ "to", FR_WRITE,
	  "inject to <ipaddr> <port> - Inject packets to the destination IP and port.",
	  command_inject_to, NULL },

	{ "from", FR_WRITE,
	  "inject from <ipaddr> - Inject packets as if they came from <ipaddr>",
	  command_inject_from, NULL },

	{ "file", FR_WRITE,
	  "inject file <input-file> <output-file> - Inject packet from <input-file>, with results sent to <output-file>",
	  command_inject_file, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_debug_level[] = {
	{ "global", FR_WRITE,
	  "debug level global <number> - Set debug level for global server events and requests written to the main server log.",
	  command_debug_level_global, NULL },

	{ "request", FR_WRITE,
	  "debug level request <number> - Set debug level for requests written to debug file or debug socket.",
	  command_debug_level_request, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_debug[] = {
	{ "condition", FR_WRITE,
	  "debug condition [condition] - Enable debugging for requests matching [condition]",
	  command_debug_condition, NULL },

	{ "file", FR_WRITE,
	  "debug file [filename] - Send all request debug output to [filename]",
	  command_debug_file, NULL },

#if defined(HAVE_FOPENCOOKIE) || defined (HAVE_FUNOPEN)
	{ "socket", FR_WRITE,
	  "debug socket [on|off] - Send all request debug output to radmin socket.",
	  command_debug_socket, NULL },
#endif

	{ "level", FR_READ,
	  "debug level <command> - Set debug levels",
	  NULL, command_table_debug_level },

	{ NULL, 0, NULL, NULL, NULL }
};

#ifdef HAVE_GPERFTOOLS_PROFILER_H
/** Commands to control the gperftools profiler
 *
 */
static fr_command_table_t command_table_profiler_cpu[] = {
	{ "start", FR_WRITE,
	  "profiler cpu start <filename> - Start gperftools cpu profiler, writing output to filename",
	  command_profiler_cpu_start, NULL },

	{ "stop", FR_WRITE,
	  "profiler cpu stop - Stop gperftools cpu profiler, and flush results to disk",
	  command_profiler_cpu_stop, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_profiler[] = {
	{ "cpu", FR_WRITE,
	  "profiler cpu <command> do sub-command of cpu profiler",
	  NULL, command_table_profiler_cpu },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table_show_debug_level[] = {
	{ "global", FR_WRITE,
	  "show debug level global - Show debug level for global server events and requests written to the main server log.  Higher is more debugging.",
	  command_show_debug_level_global, NULL },

	{ "request", FR_WRITE,
	  "show debug level request - Show debug level for requests written to debug file or debug socket.  Higher is more debugging",
	  command_show_debug_level_request, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_show_debug[] = {
	{ "condition", FR_READ,
	  "show debug condition - Shows current debugging condition.",
	  command_show_debug_condition, NULL },

	{ "file", FR_READ,
	  "show debug file - Shows current debugging file.",
	  command_show_debug_file, NULL },

	{ "level", FR_READ,
	  "show debug level <command> - Shows current global or request debug level.",
	  NULL, command_table_show_debug_level },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_show_module[] = {
	{ "config", FR_READ,
	  "show module config <module> - show configuration for given module",
	  command_show_module_config, NULL },
	{ "flags", FR_READ,
	  "show module flags <module> - show other module properties",
	  command_show_module_flags, NULL },
	{ "list", FR_READ,
	  "show module list - shows list of loaded modules",
	  command_show_modules, NULL },
	{ "methods", FR_READ,
	  "show module methods <module> - show sections where <module> may be used",
	  command_show_module_methods, NULL },
	{ "status", FR_READ,
	  "show module status <module> - show the module status",
	  command_show_module_status, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_show_client[] = {
	{ "list", FR_READ,
	  "show client list - shows list of global clients",
	  command_show_clients, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

#ifdef WITH_PROXY
static fr_command_table_t command_table_show_home[] = {
	{ "list", FR_READ,
	  "show home_server list - shows list of home servers",
	  command_show_home_servers, NULL },

	{ "state", FR_READ,
	  "show home_server state <ipaddr> <port> [udp|tcp] - shows state of given home server",
	  command_show_home_server_state, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table_show_listener[] = {
	{ "enabled", FR_READ,
	  "show listener all enabled - shows whether the server is configured to accept packets",
	  command_show_listener_enabled, NULL},

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_show_listeners[] = {
	{ "all", FR_READ,
	  "show listener all - shows global listener state",
	  NULL, command_table_show_listener },

	{ NULL, 0, NULL, NULL, NULL }
};

#ifdef HAVE_GPERFTOOLS_PROFILER_H
static fr_command_table_t command_table_show_profiler_cpu[] = {
	{ "file", FR_WRITE,
	  "show profiler cpu file - show where profile data is being written",
	  command_profiler_cpu_show_file, NULL },

	{ "samples", FR_WRITE,
	  "show profiler cpu samples - show how many profiler samples have been collected",
	  command_profiler_cpu_show_samples, NULL },

	{ "start_time", FR_WRITE,
	  "show profiler cpu start_time - show when profiling last started",
	  command_profiler_cpu_show_start_time, NULL },

	{ "status", FR_WRITE,
	  "show profiler cpu status - show the current profiler state (running or stopped)",
	  command_profiler_cpu_show_status, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_show_profiler[] = {
	{ "cpu", FR_WRITE,
	  "show profiler cpu <command> do sub-command of cpu profiler",
	  NULL, command_table_show_profiler_cpu },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table_show[] = {
	{ "client", FR_READ,
	  "show client <command> - do sub-command of client",
	  NULL, command_table_show_client },
	{ "config", FR_READ,
	  "show config <path> - shows the value of configuration option <path>",
	  command_show_config, NULL },
	{ "debug", FR_READ,
	  "show debug <command> - show debug properties",
	  NULL, command_table_show_debug },
#ifdef WITH_PROXY
	{ "home_server", FR_READ,
	  "show home_server <command> - do sub-command of home_server",
	  NULL, command_table_show_home },
#endif
	{ "listener", FR_READ,
	  "show listener <command> - do sub-command of listener",
	  NULL, command_table_show_listeners },

#ifndef NDEBUG
	{ "memory-report", FR_READ,
	  "show memory-report - show currently talloced memory",
	  command_show_memory_report, NULL },
#endif

	{ "module", FR_READ,
	  "show module <command> - do sub-command of module",
	  NULL, command_table_show_module },

#ifdef HAVE_GPERFTOOLS_PROFILER_H
	{ "profiler", FR_READ,
	  "show profiler <command> - do sub-command of profiler",
	  NULL, command_table_show_profiler },
#endif

	{ "uptime", FR_READ,
	  "show uptime - shows time at which server started",
	  command_uptime, NULL },
	{ "version", FR_READ,
	  "show version - Prints version of the running server",
	  command_show_version, NULL },
	{ NULL, 0, NULL, NULL, NULL }
};

static int command_set_module_config(rad_listen_t *listener, int argc, char *argv[])
{
	int i, rcode;
	CONF_PAIR *cp;
	CONF_SECTION *cs;
	module_instance_t *instance;
	CONF_PARSER const *variables;
	void *data;

	if (argc < 3) {
		cprintf_error(listener, "No module name or variable was given\n");
		return 0;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return 0;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		cprintf_error(listener, "No such module \"%s\"\n", argv[0]);
		return 0;
	}

	variables = cf_section_parse_table(instance->cs);
	if (!variables) {
		cprintf_error(listener, "Cannot find configuration for module\n");
		return 0;
	}

	rcode = -1;
	for (i = 0; variables[i].name != NULL; i++) {
		/*
		 *	FIXME: Recurse into sub-types somehow...
		 */
		if (PW_BASE_TYPE(variables[i].type) == PW_TYPE_SUBSECTION) continue;

		if (strcmp(variables[i].name, argv[1]) == 0) {
			rcode = i;
			break;
		}
	}

	if (rcode < 0) {
		cprintf_error(listener, "No such variable \"%s\"\n", argv[1]);
		return 0;
	}

	i = rcode;		/* just to be safe */

	/*
	 *	It's not part of the dynamic configuration.  The module
	 *	needs to re-parse && validate things.
	 */
	if (variables[i].data) {
		cprintf_error(listener, "Variable cannot be dynamically updated\n");
		return 0;
	}

	data = ((char *) instance->data) + variables[i].offset;

	cp = cf_pair_find(instance->cs, argv[1]);
	if (!cp) return 0;

	/*
	 *	Replace the OLD value in the configuration file with
	 *	the NEW value.
	 *
	 *	FIXME: Parse argv[2] depending on it's data type!
	 *	If it's a string, look for leading single/double quotes,
	 *	end then call tokenize functions???
	 */
	cf_pair_replace(instance->cs, cp, argv[2]);

	rcode = cf_pair_parse(instance->cs, argv[1], variables[i].type, data, argv[2], T_DOUBLE_QUOTED_STRING);
	if (rcode < 0) {
		cprintf_error(listener, "Failed to parse value\n");
		return 0;
	}

	return CMD_OK;
}

static int command_set_module_status(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t *instance;

	if (argc < 2) {
		cprintf_error(listener, "No module name or status was given\n");
		return 0;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return 0;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		cprintf_error(listener, "No such module \"%s\"\n", argv[0]);
		return 0;
	}


	if (strcmp(argv[1], "alive") == 0) {
		instance->force = false;

	} else if (strcmp(argv[1], "dead") == 0) {
		instance->code = RLM_MODULE_FAIL;
		instance->force = true;

	} else {
		int rcode;

		rcode = fr_str2int(mod_rcode_table, argv[1], -1);
		if (rcode < 0) {
			cprintf_error(listener, "Unknown status \"%s\"\n", argv[1]);
			return 0;
		}

		instance->code = rcode;
		instance->force = true;
	}

	return CMD_OK;
}

static int command_set_listener_enabled(rad_listen_t *listener, int argc, char *argv[])
{
	if (argc < 1) {
		cprintf_error(listener, "No value was provided\n");
		return 0;
	}

	if ((strcmp(argv[0], "yes") == 0) || (strcmp(argv[0], "true") == 0)) {
		INFO("Server has resumed accepting requests");
		main_config.drop_requests = false;
	} else if ((strcmp(argv[0], "no") == 0) || (strcmp(argv[0], "false") == 0)) {
		INFO("Server is no longer accepting new requests");
		main_config.drop_requests = true;
	}

	return CMD_OK;
}

#ifdef WITH_STATS
static char const *elapsed_names[8] = {
	"1us", "10us", "100us", "1ms", "10ms", "100ms", "1s", "10s"
};

#undef PU
#ifdef WITH_STATS_64BIT
#ifdef PRIu64
#define PU "%" PRIu64
#else
#define PU "%lu"
#endif
#else
#ifdef PRIu32
#define PU "%" PRIu32
#else
#define PU "%u"
#endif
#endif

static int command_print_stats(rad_listen_t *listener, fr_stats_t *stats,
			       int auth, int server)
{
	int i;

	cprintf(listener, "requests\t" PU "\n", stats->total_requests);
	cprintf(listener, "responses\t" PU "\n", stats->total_responses);

	if (auth) {
		cprintf(listener, "accepts\t\t" PU "\n",
			stats->total_access_accepts);
		cprintf(listener, "rejects\t\t" PU "\n",
			stats->total_access_rejects);
		cprintf(listener, "challenges\t" PU "\n",
			stats->total_access_challenges);
	}

	cprintf(listener, "dup\t\t" PU "\n", stats->total_dup_requests);
	cprintf(listener, "invalid\t\t" PU "\n", stats->total_invalid_requests);
	cprintf(listener, "malformed\t" PU "\n", stats->total_malformed_requests);
	cprintf(listener, "bad_authenticator\t" PU "\n", stats->total_bad_authenticators);
	cprintf(listener, "dropped\t\t" PU "\n", stats->total_packets_dropped);
	cprintf(listener, "unknown_types\t" PU "\n", stats->total_unknown_types);

	if (server) {
		cprintf(listener, "timeouts\t" PU "\n", stats->total_timeouts);
	}

	cprintf(listener, "last_packet\t%" PRId64 "\n", (int64_t) stats->last_packet);
	for (i = 0; i < 8; i++) {
		cprintf(listener, "elapsed.%s\t%u\n",
			elapsed_names[i], stats->elapsed[i]);
	}

	return CMD_OK;
}

static int command_stats_state(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	cprintf(listener, "states_created\t\t%" PRIu64 "\n", fr_state_entries_created(global_state));
	cprintf(listener, "states_timeout\t\t%" PRIu64 "\n", fr_state_entries_timeout(global_state));
	cprintf(listener, "states_tracked\t\t%" PRIu32 "\n", fr_state_entries_tracked(global_state));

	return CMD_OK;
}

#ifndef NDEBUG
static int command_stats_memory(rad_listen_t *listener, int argc, char *argv[])
{
	if (!main_config.talloc_memory_report) {
		cprintf(listener, "Memory debugging not enabled.  To enable, pass -Ms when starting the server\n");
		return CMD_OK;
	}

	if (argc == 0) goto fail;

	if (strcmp(argv[0], "total") == 0) {
		cprintf(listener, "%zd\n", talloc_total_size(NULL));
		return CMD_OK;
	}

	if (strcmp(argv[0], "blocks") == 0) {
		cprintf(listener, "%zd\n", talloc_total_blocks(NULL));
		return CMD_OK;
	}

fail:
	cprintf_error(listener, "Must use 'stats memory [blocks|total]'\n");
	return CMD_FAIL;
}
#endif

#ifdef WITH_DETAIL
static FR_NAME_NUMBER state_names[] = {
	{ "unopened", STATE_UNOPENED },
	{ "unlocked", STATE_UNLOCKED },
	{ "processing", STATE_PROCESSING },

	{ "header", STATE_HEADER },
	{ "vps", STATE_VPS },
	{ "queued", STATE_QUEUED },
	{ "running", STATE_RUNNING },
	{ "no-reply", STATE_NO_REPLY },
	{ "replied", STATE_REPLIED },

	{ NULL, 0 }
};

static int command_stats_detail(rad_listen_t *listener, int argc, char *argv[])
{
	rad_listen_t *this;
	listen_detail_t *data, *needle;
	struct stat buf;

	if (argc == 0) {
		cprintf_error(listener, "Must specify <filename>\n");
		return 0;
	}

	data = NULL;
	for (this = main_config.listen; this != NULL; this = this->next) {
		if (this->type != RAD_LISTEN_DETAIL) continue;

		needle = this->data;
		if (!strcmp(argv[0], needle->filename)) {
			data = needle;
			break;
		}
	}

	if (!data) {
		cprintf_error(listener, "No detail file listener\n");
		return 0;
	}

	cprintf(listener, "state\t%s\n",
		fr_int2str(state_names, data->file_state, "?"));

	if ((data->file_state == STATE_UNOPENED) ||
	    (data->file_state == STATE_UNLOCKED)) {
		return CMD_OK;
	}

	/*
	 *	Race conditions: file might not exist.
	 */
	if (stat(data->filename_work, &buf) < 0) {
		cprintf(listener, "packets\t0\n");
		cprintf(listener, "tries\t0\n");
		cprintf(listener, "offset\t0\n");
		cprintf(listener, "size\t0\n");
		return CMD_OK;
	}

	cprintf(listener, "packets\t%d\n", data->packets);
	cprintf(listener, "tries\t%d\n", data->tries);
	cprintf(listener, "offset\t%u\n", (unsigned int) data->offset);
	cprintf(listener, "size\t%u\n", (unsigned int) buf.st_size);

	return CMD_OK;
}
#endif

#ifdef WITH_PROXY
static int command_stats_home_server(rad_listen_t *listener, int argc, char *argv[])
{
	home_server_t *home;

	if (argc == 0) {
		cprintf_error(listener, "Must specify [auth|acct|coa|disconnect] OR <ipaddr> <port>\n");
		return 0;
	}

	if (argc == 1) {
		if (strcmp(argv[0], "auth") == 0) {
			return command_print_stats(listener,
						   &proxy_auth_stats, 1, 1);
		}

#ifdef WITH_ACCOUNTING
		if (strcmp(argv[0], "acct") == 0) {
			return command_print_stats(listener,
						   &proxy_acct_stats, 0, 1);
		}
#endif

#ifdef WITH_ACCOUNTING
		if (strcmp(argv[0], "coa") == 0) {
			return command_print_stats(listener,
						   &proxy_coa_stats, 0, 1);
		}
#endif

#ifdef WITH_ACCOUNTING
		if (strcmp(argv[0], "disconnect") == 0) {
			return command_print_stats(listener,
						   &proxy_dsc_stats, 0, 1);
		}
#endif

		cprintf_error(listener, "Should specify [auth|acct|coa|disconnect]\n");
		return 0;
	}

	home = get_home_server(listener, argc, argv, NULL);
	if (!home) return 0;

	command_print_stats(listener, &home->stats,
			    (home->type == HOME_TYPE_AUTH), 1);
	cprintf(listener, "outstanding\t%d\n", home->currently_outstanding);
	return CMD_OK;
}
#endif

static int command_stats_client(rad_listen_t *listener, int argc, char *argv[])
{
	bool auth = true;
	fr_stats_t *stats;
	RADCLIENT *client, fake;

	if (argc < 1) {
		cprintf_error(listener, "Must specify [auth/acct]\n");
		return 0;
	}

	if (argc == 1) {
		/*
		 *	Global statistics.
		 */
		fake.auth = radius_auth_stats;
#ifdef WITH_ACCOUNTING
		fake.acct = radius_acct_stats;
#endif
#ifdef WITH_COA
		fake.coa = radius_coa_stats;
		fake.dsc = radius_dsc_stats;
#endif
		client = &fake;

	} else {
		/*
		 *	Per-client statistics.
		 */
		client = get_client(listener, argc - 1, argv + 1);
		if (!client) return 0;
	}

	if (strcmp(argv[0], "auth") == 0) {
		auth = true;
		stats = &client->auth;

	} else if (strcmp(argv[0], "acct") == 0) {
#ifdef WITH_ACCOUNTING
		auth = false;
		stats = &client->acct;
#else
		cprintf_error(listener, "This server was built without accounting support.\n");
		return 0;
#endif

	} else if (strcmp(argv[0], "coa") == 0) {
#ifdef WITH_COA
		auth = false;
		stats = &client->coa;
#else
		cprintf_error(listener, "This server was built without CoA support.\n");
		return 0;
#endif

	} else if (strcmp(argv[0], "disconnect") == 0) {
#ifdef WITH_COA
		auth = false;
		stats = &client->dsc;
#else
		cprintf_error(listener, "This server was built without CoA support.\n");
		return 0;
#endif

	} else {
		cprintf_error(listener, "Unknown statistics type\n");
		return 0;
	}

	/*
	 *	Global results for all client.
	 */
	if (argc == 1) {
#ifdef WITH_ACCOUNTING
		if (!auth) {
			return command_print_stats(listener,
						   &radius_acct_stats, auth, 0);
		}
#endif
		return command_print_stats(listener, &radius_auth_stats, auth, 0);
	}

	return command_print_stats(listener, stats, auth, 0);
}


static int command_stats_socket(rad_listen_t *listener, int argc, char *argv[])
{
	bool auth = true;
	rad_listen_t *sock;

	sock = get_socket(listener, argc, argv, NULL);
	if (!sock) return 0;

	if (sock->type != RAD_LISTEN_AUTH) auth = false;

	return command_print_stats(listener, &sock->stats, auth, 0);
}
#endif	/* WITH_STATS */


#ifdef WITH_DYNAMIC_CLIENTS
static int command_add_client_file(rad_listen_t *listener, int argc, char *argv[])
{
	RADCLIENT *c;

	if (argc < 1) {
		cprintf_error(listener, "<file> is required\n");
		return 0;
	}

	/*
	 *	Read the file and generate the client.
	 */
	c = client_read(argv[0], NULL, false);
	if (!c) {
		cprintf_error(listener, "Unknown error reading client file.\n");
		return 0;
	}

	if (!client_add(NULL, c)) {
		cprintf_error(listener, "Unknown error inserting new client.\n");
		client_free(c);
		return 0;
	}

	return CMD_OK;
}


static int command_del_client(rad_listen_t *listener, int argc, char *argv[])
{
	RADCLIENT *client;

	client = get_client(listener, argc, argv);
	if (!client) return 0;

	if (!client->dynamic) {
		cprintf_error(listener, "Client %s was not dynamically defined.\n", argv[0]);
		return 0;
	}

	/*
	 *	DON'T delete it.  Instead, mark it as "dead now".  The
	 *	next time we receive a packet for the client, it will
	 *	be deleted.
	 *
	 *	If we don't receive a packet from it, the client
	 *	structure will stick around for a while.  Oh well...
	 */
	client->lifetime = 1;

	return CMD_OK;
}


static fr_command_table_t command_table_del_client[] = {
	{ "ipaddr", FR_WRITE,
	  "del client ipaddr <ipaddr> [udp|tcp] [listen <ipaddr> <port>] - Delete a dynamically created client",
	  command_del_client, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_del[] = {
	{ "client", FR_WRITE,
	  "del client <command> - Delete client configuration commands",
	  NULL, command_table_del_client },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_add_client[] = {
	{ "file", FR_WRITE,
	  "add client file <filename> - Add new client definition from <filename>",
	  command_add_client_file, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_add[] = {
	{ "client", FR_WRITE,
	  "add client <command> - Add client configuration commands",
	  NULL, command_table_add_client },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

#ifdef WITH_PROXY
static fr_command_table_t command_table_set_home[] = {
	{ "state", FR_WRITE,
	  "set home_server state <ipaddr> <port> [udp|tcp] [alive|dead] - set state for given home server",
	  command_set_home_server_state, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table_set_module[] = {
	{ "config", FR_WRITE,
	  "set module config <module> variable value - set configuration for <module>",
	  command_set_module_config, NULL },

	{ "status", FR_WRITE,
	  "set module status <module> [alive|...] - set the module status to be alive (operating normally), or force a particular code (ok,fail, etc.)",
	  command_set_module_status, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_set_listener[] = {
	{ "enabled", FR_WRITE,
	  "set listener all enabled <bool> - enable or disable all listeners",
	  command_set_listener_enabled, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_set_listeners[] = {
	{ "all", FR_WRITE,
	  "set listener all - change state of all listeners",
	  NULL, command_table_set_listener },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_set[] = {
	{ "module", FR_WRITE,
	  "set module <command> - set module commands",
	  NULL, command_table_set_module },
#ifdef WITH_PROXY
	{ "home_server", FR_WRITE,
	  "set home_server <command> - set home server commands",
	  NULL, command_table_set_home },
#endif
	{ "listener", FR_WRITE,
	  "set listener <command> - set listener commands",
	  NULL, command_table_set_listeners },

	{ NULL, 0, NULL, NULL, NULL }
};


#ifdef WITH_STATS
static fr_command_table_t command_table_stats[] = {
	{ "client", FR_READ,
	  "stats client [auth/acct] <ipaddr> [udp|tcp] [listen <ipaddr> <port>] "
	  "- show statistics for given client, or for all clients (auth or acct)",
	  command_stats_client, NULL },

#ifdef WITH_DETAIL
	{ "detail", FR_READ,
	  "stats detail <filename> - show statistics for the given detail file",
	  command_stats_detail, NULL },
#endif

#ifdef WITH_PROXY
	{ "home_server", FR_READ,
	  "stats home_server [<ipaddr>|auth|acct|coa|disconnect] <port> [udp|tcp] - show statistics for given home server (ipaddr and port), or for all home servers (auth or acct)",
	  command_stats_home_server, NULL },
#endif

	{ "state", FR_READ,
	  "stats state - show statistics for states",
	  command_stats_state, NULL },

	{ "socket", FR_READ,
	  "stats socket <ipaddr> <port> [udp|tcp] "
	  "- show statistics for given socket",
	  command_stats_socket, NULL },

#ifndef NDEBUG
	{ "memory", FR_READ,
	  "stats memory [blocks|total] - show statistics on used memory",
	  command_stats_memory, NULL },
#endif

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table[] = {
#ifdef WITH_DYNAMIC_CLIENTS
	{ "add", FR_WRITE, NULL, NULL, command_table_add },
#endif
	{ "debug", FR_WRITE,
	  "debug <command> - debugging commands",
	  NULL, command_table_debug },
#ifdef WITH_DYNAMIC_CLIENTS
	{ "del", FR_WRITE, NULL, NULL, command_table_del },
#endif
	{ "hup", FR_WRITE,
	  "hup [module] - sends a HUP signal to the server, or optionally to one module",
	  command_hup, NULL },
	{ "inject", FR_WRITE,
	  "inject <command> - commands to inject packets into a running server",
	  NULL, command_table_inject },

#ifdef HAVE_GPERFTOOLS_PROFILER_H
	{ "profiler", FR_WRITE,
	  "profiler <command> - commands to alter the state of the gperftools profiler",
	  NULL, command_table_profiler },
#endif
	{ "reconnect", FR_READ,
	  "reconnect - reconnect to a running server",
	  NULL, NULL },		/* just here for "help" */
	{ "terminate", FR_WRITE,
	  "terminate - terminates the server, and cause it to exit",
	  command_terminate, NULL },
	{ "set", FR_WRITE, NULL, NULL, command_table_set },
	{ "show",  FR_READ, NULL, NULL, command_table_show },
#ifdef WITH_STATS
	{ "stats",  FR_READ, NULL, NULL, command_table_stats },
#endif

	{ NULL, 0, NULL, NULL, NULL }
};


static int _command_socket_free(fr_command_socket_t *cmd)
{
	/*
	 *	If it's a TCP socket, don't do anything.
	 */
	if (cmd->magic != COMMAND_SOCKET_MAGIC) return 0;

	if (!cmd->copy) return 0;
	unlink(cmd->copy);

	return 0;
}


/*
 *	Parse the unix domain sockets.
 *
 *	FIXME: TCP + SSL, after RadSec is in.
 */
static int command_socket_parse_unix(CONF_SECTION *cs, rad_listen_t *this)
{
	fr_command_socket_t *sock;

	sock = this->data;
	talloc_set_destructor(sock, _command_socket_free);

	if (cf_section_parse(cs, sock, command_config) < 0) return -1;

	/*
	 *	Can't get uid or gid of connecting user, so can't do
	 *	peercred authentication.
	 */
#ifndef HAVE_GETPEEREID
	if (sock->peercred && (sock->uid_name || sock->gid_name)) {
		ERROR("System does not support uid or gid authentication for sockets");
		return -1;
	}
#endif

	sock->magic = COMMAND_SOCKET_MAGIC;
	sock->copy = NULL;
	if (sock->path) sock->copy = talloc_typed_strdup(sock, sock->path);

	if (sock->gid_name) {
		if (rad_getgid(cs, &sock->gid, sock->gid_name) < 0) {
			ERROR("Failed resolving gid of group %s: %s", sock->gid_name, fr_strerror());
			return -1;
		}
	} else {
		sock->gid = -1;
	}

	if (!sock->mode_name) {
		sock->co.mode = FR_READ;
	} else {
		sock->co.mode = fr_str2int(mode_names, sock->mode_name, 0);
		if (!sock->co.mode) {
			ERROR("Invalid mode name \"%s\"", sock->mode_name);
			return -1;
		}
	}

	return 0;
}

static int command_socket_open_unix(UNUSED CONF_SECTION *cs, rad_listen_t *this)
{
	fr_command_socket_t *sock;

	sock = this->data;

	this->fd = fr_server_domain_socket(sock->path, sock->gid, sock->blocking);
	if (this->fd < 0) {
		ERROR("%s", fr_strerror());
		if (sock->copy) TALLOC_FREE(sock->copy);
		return -1;
	}

	return 0;
}

static int command_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode;
	CONF_PAIR const *cp;
	listen_socket_t *sock;

	cp = cf_pair_find(cs, "socket");
	if (cp) return command_socket_parse_unix(cs, this);

	rcode = common_socket_parse(cs, this);
	if (rcode < 0) return -1;

#ifdef WITH_TLS
	if (this->tls) {
		cf_log_err_cs(cs,
			   "TLS is not supported for control sockets");
		return -1;
	}
#endif

	sock = this->data;
	if (sock->proto != IPPROTO_TCP) {
		cf_log_err_cs(cs,
			   "UDP is not supported for control sockets");
		return -1;
	}

	return 0;
}

static int command_socket_open(CONF_SECTION *cs, rad_listen_t *this)
{
	CONF_PAIR const *cp;

	cp = cf_pair_find(cs, "socket");
	if (cp) return command_socket_open_unix(cs, this);

	return common_socket_open(cs, this);
}

static int command_socket_print(rad_listen_t const *this, char *buffer, size_t bufsize)
{
	fr_command_socket_t *sock = this->data;

	if (sock->magic != COMMAND_SOCKET_MAGIC) {
		return common_socket_print(this, buffer, bufsize);
	}

	snprintf(buffer, bufsize, "command file %s", sock->path);
	return 1;
}


/*
 *	String split routine.  Splits an input string IN PLACE
 *	into pieces, based on spaces.
 */
static int dict_str_to_argvX(char *str, char **argv, int max_argc)
{
	int argc = 0;

	while (*str) {
		if (argc >= max_argc) return argc;

		/*
		 *	Chop out comments early.
		 */
		if (*str == '#') {
			*str = '\0';
			break;
		}

		while ((*str == ' ') ||
		       (*str == '\t') ||
		       (*str == '\r') ||
		       (*str == '\n')) *(str++) = '\0';

		if (!*str) return argc;

		argv[argc++] = str;

		if ((*str == '\'') || (*str == '"')) {
			char quote = *str;
			char *p = str + 1;

			while (true) {
				if (!*p) return -1;

				if (*p == quote) {
					str = p + 1;
					break;
				}

				/*
				 *	Handle \" and nothing else.
				 */
				if (*p == '\\') {
					p += 2;
					continue;
				}

				p++;
			}
		}

		while (*str &&
		       (*str != ' ') &&
		       (*str != '\t') &&
		       (*str != '\r') &&
		       (*str != '\n')) str++;
	}

	return argc;
}

static void print_help(rad_listen_t *listener, int argc, char *argv[],
		       fr_command_table_t *table, int recursive)
{
	int i;

	/* this should never happen, but if it does then just return gracefully */
	if (!table) return;

	for (i = 0; table[i].command != NULL; i++) {
		if (argc > 0) {
			if (strcmp(table[i].command, argv[0]) == 0) {
				if (table[i].table) {
					print_help(listener, argc - 1, argv + 1, table[i].table, recursive);
				} else {
					if (table[i].help) {
						cprintf(listener, "%s\n", table[i].help);
					}
				}
				return;
			}

			continue;
		}

		if (table[i].help) {
			cprintf(listener, "%s\n",
				table[i].help);
		} else {
			cprintf(listener, "%s <command> - do sub-command of %s\n",
				table[i].command, table[i].command);
		}

		if (recursive && table[i].table) {
			print_help(listener, 0, NULL, table[i].table, recursive);
		}
	}
}

#define MAX_ARGV (16)

/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int command_domain_recv_co(rad_listen_t *listener, fr_cs_buffer_t *co)
{
	int i;
	uint32_t status;
	ssize_t r, len;
	int argc;
	fr_conduit_type_t conduit;
	char *my_argv[MAX_ARGV], **argv;
	fr_command_table_t *table;
	uint8_t *command;

	r = fr_conduit_drain(listener->fd, &conduit, co->buffer, sizeof(co->buffer) - 1, &command, &co->offset);
	if ((r < 0) && ((errno == EINTR) || (errno == EAGAIN))) return 0;

	if (r <= 0) {
	do_close:
		command_close_socket(listener);
		return 0;
	}

	/*
	 *	We need more data.  Go read it.
	 */
	if (conduit == FR_CONDUIT_WANT_MORE) {
		return 0;
	}

	status = 0;
	command[r] = '\0';
	DEBUG("radmin> %s", command);

	argc = dict_str_to_argvX((char *) command, my_argv, MAX_ARGV);
	if (argc == 0) goto do_next; /* empty strings are OK */

	if (argc < 0) {
		cprintf_error(listener, "Failed parsing command '%s'.\n",
			command);
		goto do_next;
	}

	argv = my_argv;

	for (len = 0; len <= co->offset; len++) {
		if (command[len] < 0x20) {
			command[len] = '\0';
			break;
		}
	}

	/*
	 *	Hard-code exit && quit.
	 */
	if ((strcmp(argv[0], "exit") == 0) ||
	    (strcmp(argv[0], "quit") == 0)) goto do_close;

	table = command_table;
 retry:
	len = 0;
	for (i = 0; table[i].command != NULL; i++) {
		if (strcmp(table[i].command, argv[0]) == 0) {
			/*
			 *	Check permissions.
			 */
			if (((co->mode & FR_WRITE) == 0) &&
			    ((table[i].mode & FR_WRITE) != 0)) {
				cprintf_error(listener, "You do not have write permission.  See \"mode = rw\" in the \"listen\" section for this socket.\n");
				goto do_next;
			}

			if (table[i].table) {
				/*
				 *	This is the last argument, but
				 *	there's a sub-table.  Print help.
				 *
				 */
				if (argc == 1) {
					table = table[i].table;
					goto do_help;
				}

				argc--;
				argv++;
				table = table[i].table;
				goto retry;
			}

			if ((argc == 2) && (strcmp(argv[1], "?") == 0)) goto do_help;

			if (!table[i].func) {
				cprintf_error(listener, "Invalid command\n");
				goto do_next;
			}

			status = table[i].func(listener, argc - 1, argv + 1);
			goto do_next;
		}
	}

	/*
	 *	No such command
	 */
	if (!len) {
		if ((strcmp(argv[0], "help") == 0) ||
		    (strcmp(argv[0], "?") == 0)) {
			int recursive;

		do_help:
			if ((argc > 1) && (strcmp(argv[1], "-r") == 0)) {
				recursive = true;
				argc--;
				argv++;
			} else {
				recursive = false;
			}

			print_help(listener, argc - 1, argv + 1, table, recursive);
			goto do_next;
		}

		cprintf_error(listener, "Unknown command \"%s\"\n",
			      argv[0]);
	}

 do_next:
	/*
	 * Reset offset now that command has been fully read
	 */
	co->offset = 0;

	r = fr_conduit_write(listener->fd, FR_CONDUIT_CMD_STATUS, &status, sizeof(status));
	if (r <= 0) goto do_close;

	return 0;
}


static int command_tcp_recv(rad_listen_t *this)
{
	ssize_t r;
	listen_socket_t *sock = this->data;
	fr_cs_buffer_t *co = (void *) sock->packet;
	fr_conduit_type_t conduit;

	if (!co) {
	do_close:
		command_close_socket(this);
		return 0;
	}

	if (!co->auth) {
		uint8_t *data;
		uint8_t expected[16];

		r = fr_conduit_drain(this->fd, &conduit, co->buffer, sizeof(co->buffer) - 1, &data, &co->offset);
		if ((r < 0) && ((errno == EINTR) || (errno == EAGAIN))) return 0;

		if (r <= 0) goto do_close;

		/*
		 *	We need more data.  Go read it.
		 */
		if (conduit == FR_CONDUIT_WANT_MORE) {
			return 0;
		}

		if ((r != sizeof(expected)) || (conduit != FR_CONDUIT_AUTH_RESPONSE)) goto do_close;

		fr_hmac_md5(expected, (void const *) sock->client->secret,
			    strlen(sock->client->secret),
			    data, sizeof(expected));

		if (fr_radius_digest_cmp(expected, data + sizeof(expected), sizeof(expected)) != 0) {
			ERROR("radmin failed challenge: Closing socket");
			goto do_close;
		}

		co->auth = true;
		co->offset = 0;
	}

	return command_domain_recv_co(this, co);
}

/*
 *	Should never be called.  The functions should just call write().
 */
static int command_tcp_send(UNUSED rad_listen_t *listener, UNUSED REQUEST *request)
{
	return 0;
}

static int command_domain_recv(rad_listen_t *listener)
{
	fr_command_socket_t *sock = listener->data;

	return command_domain_recv_co(listener, &sock->co);
}

/*
 *	Write 32-bit magic number && version information.
 */
static int command_magic_recv(rad_listen_t *this, fr_cs_buffer_t *co, bool challenge)
{
	int i;
	ssize_t r;
	uint32_t magic;
	fr_conduit_type_t conduit;
	uint8_t *data;

	/*
	 *	Start off by reading 4 bytes of magic, followed by 4 bytes of zero.
	 */
	r = fr_conduit_drain(this->fd, &conduit, co->buffer, sizeof(co->buffer) - 1, &data, &co->offset);
	if ((r < 0) && ((errno == EINTR) || (errno == EAGAIN))) return 0;

	if (r <= 0) {
		ERROR("Failed reading magic: %s", fr_syserror(errno));

	do_close:
		command_close_socket(this);
		return 0;
	}

	/*
	 *	We need more data.  Go read it.
	 */
	if (conduit == FR_CONDUIT_WANT_MORE) {
		return 0;
	}

	if ((r != 8) || (conduit != FR_CONDUIT_INIT_ACK)) goto do_close;

	magic = htonl(0xf7eead16);
	if (memcmp(&magic, data, sizeof(magic)) != 0) {
		ERROR("Incompatible versions");
		goto do_close;
	}

	/*
	 *	Ack the magic + 4 bytes of zero back.
	 */
	r = fr_conduit_write(this->fd, FR_CONDUIT_INIT_ACK, data, 8);
	if (r <= 0) {
		ERROR("Failed writing magic: %s", fr_syserror(errno));
		goto do_close;
	}

	if (challenge) {
		for (i = 0; i < 16; i++) {
			co->buffer[i] = fr_rand();
		}

		r = fr_conduit_write(this->fd, FR_CONDUIT_AUTH_CHALLENGE, co->buffer, 16);
		if (r <= 0) {
			ERROR("Failed writing auth challenge: %s", fr_syserror(errno));
			goto do_close;
		}

	}

	/*
	 * Reset offset now that version has been fully read
	 */
	co->offset = 0;

	return 1;
}

static int command_init_recv(rad_listen_t *this)
{
	int rcode;
	fr_command_socket_t *sock = this->data;

	if (sock->magic == COMMAND_SOCKET_MAGIC) {
		rcode = command_magic_recv(this, &sock->co, false);
		if (rcode <= 0) return rcode;

		this->recv = command_domain_recv;
	} else {
		listen_socket_t *sock2 = this->data;

		rcode = command_magic_recv(this, (fr_cs_buffer_t *) sock2->packet, true);
		if (rcode <= 0) return rcode;

		this->recv = command_tcp_recv;
	}

	return 0;
}


static int command_domain_accept(rad_listen_t *listener)
{
	int newfd;
	rad_listen_t *this;
	socklen_t salen;
	struct sockaddr_storage src;
	fr_command_socket_t *sock = listener->data;

	salen = sizeof(src);

	DEBUG2(" ... new connection request on command socket");

	newfd = accept(listener->fd, (struct sockaddr *) &src, &salen);
	if (newfd < 0) {
		/*
		 *	Non-blocking sockets must handle this.
		 */
		if (errno == EWOULDBLOCK) {
			return 0;
		}

		DEBUG2(" ... failed to accept connection");
		return 0;
	}

	/*
	 *	Is likely redundant as newfd should inherit blocking
	 *	from listener->fd.  But better to be safe.
	 */
	if (!sock->blocking) fr_nonblock(newfd);

#ifdef HAVE_GETPEEREID
	/*
	 *	Perform user authentication.
	 */
	if (sock->peercred) {
		uid_t uid;
		gid_t gid;

		if (getpeereid(newfd, &uid, &gid) < 0) {
			ERROR("Failed getting peer credentials for %s: %s",
			       sock->path, fr_syserror(errno));
			close(newfd);
			return 0;
		}

		/*
		 *	Only do UID checking if the caller is
		 *	non-root.  The superuser can do anything, so
		 *	we might as well let them.
		 */
		if ((uid != 0) && (uid != geteuid()) && (sock->gid_name && (sock->gid != gid))) {
			ERROR("Unauthorized connection to %s from uid %ld, gid %ld",
			      sock->path, (long int) uid, (long int) gid);
			close(newfd);
			return 0;
		}
	}
#endif

	/*
	 *	Add the new listener.
	 */
	this = listen_alloc(listener, listener->type, listener->proto);
	if (!this) return 0;

	/*
	 *	Copy everything, including the pointer to the socket
	 *	information.
	 */
	sock = this->data;
	memcpy(this, listener, sizeof(*this));
	this->status = RAD_LISTEN_STATUS_INIT;
	this->next = NULL;
	this->data = sock;	/* fix it back */

	sock->magic = COMMAND_SOCKET_MAGIC;
	sock->user[0] = '\0';
	sock->path = ((fr_command_socket_t *) listener->data)->path;
	sock->co.offset = 0;
	sock->co.mode = ((fr_command_socket_t *) listener->data)->co.mode;

	this->fd = newfd;

	/*
	 *	Start off by sending the magic handshake.
	 */
	this->recv = command_init_recv;

	/*
	 *	Tell the event loop that we have a new FD
	 */
	radius_update_listener(this);

	return 0;
}


/*
 *	Send an authentication response packet
 */
static int command_domain_send(UNUSED rad_listen_t *listener,
			       UNUSED REQUEST *request)
{
	return 0;
}


static int command_socket_encode(UNUSED rad_listen_t *listener,
				 UNUSED REQUEST *request)
{
	return 0;
}


static int command_socket_decode(UNUSED rad_listen_t *listener,
				 UNUSED REQUEST *request)
{
	return 0;
}

#endif /* WITH_COMMAND_SOCKET */
