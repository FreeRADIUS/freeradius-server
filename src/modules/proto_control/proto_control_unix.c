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
 * @file proto_control_unix.c
 * @brief Control handler for Unix sockets.
 *
 * @copyright 2018 The FreeRADIUS server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#include <netdb.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/trie.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/io.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/rad_assert.h>
#include "proto_control.h"

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <fcntl.h>
#include <libgen.h>
#include <pwd.h>
#include <grp.h>

typedef struct {
	char const			*name;			//!< socket name
	CONF_SECTION			*cs;			//!< our configuration

	int				sockfd;

	fr_event_list_t			*el;			//!< for cleanup timers on Access-Request
	fr_network_t			*nr;			//!< for fr_network_listen_read();

	char const     			*filename;     		//!< filename of control socket
	char const     			*uid_name;		//!< name of UID to require
	char const     			*gid_name;     		//!< name of GID to require
	uid_t				uid;			//!< UID value
	gid_t				gid;			//!< GID value

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.

	fr_stats_t			stats;			//!< statistics for this socket

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	bool				peercred;		//!< whether we use peercred or not

	fr_io_address_t			*connection;		//!< for connected sockets.
	RADCLIENT			radclient;		//!< for faking out clients

	fr_io_data_read_t		read;			//!< function to process data *after* reading

} proto_control_unix_t;

static const CONF_PARSER unix_listen_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_STRING | FR_TYPE_REQUIRED, proto_control_unix_t, filename),
	.dflt = "${run_dir}/radiusd.sock}" },
	{ FR_CONF_OFFSET("uid", FR_TYPE_STRING, proto_control_unix_t, uid_name) },
	{ FR_CONF_OFFSET("git", FR_TYPE_STRING, proto_control_unix_t, gid_name) },
	{ FR_CONF_OFFSET("peercred", FR_TYPE_BOOL, proto_control_unix_t, peercred), .dflt = "yes" },

	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, proto_control_unix_t, recv_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, proto_control_unix_t, max_packet_size), .dflt = "4096" } ,

	CONF_PARSER_TERMINATOR
};


/*
 *	Process an initial connection request.
 */
static ssize_t mod_read_command(void *instance, UNUSED void **packet_ctx, UNUSED fr_time_t **recv_time, uint8_t *buffer, UNUSED size_t buffer_len, UNUSED size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup
)
{
	proto_control_unix_t		*inst = talloc_get_type_abort(instance, proto_control_unix_t);
	fr_conduit_hdr_t		*hdr = (fr_conduit_hdr_t *) buffer;
	uint32_t			status;
	uint8_t				*cmd = buffer + sizeof(*hdr);

	hdr->length = ntohl(hdr->length);

	DEBUG("Received text length %d '%.*s'", hdr->length, (int) hdr->length, cmd);

	if ((hdr->length == 9) && (memcmp(cmd, "terminate", 9) == 0)) {
		radius_signal_self(RADIUS_SIGNAL_SELF_TERM);
		goto success;
	}

	// if the command starts with "worker ...", then return it
	// otherwise run the command here.

	(void) fr_conduit_write(inst->sockfd, FR_CONDUIT_STDOUT, "\n", 1);

success:
	status = FR_CONDUIT_SUCCESS;
	(void) fr_conduit_write(inst->sockfd, FR_CONDUIT_CMD_STATUS, &status, sizeof(status));

	return 0;
}

/*
 *	Process an initial connection request.
 */
static ssize_t mod_read_init(void *instance, UNUSED void **packet_ctx, UNUSED fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, UNUSED size_t *leftover, UNUSED uint32_t *priority, UNUSED bool *is_dup
)
{
	proto_control_unix_t		*inst = talloc_get_type_abort(instance, proto_control_unix_t);
	fr_conduit_hdr_t		*hdr = (fr_conduit_hdr_t *) buffer;
	uint32_t			magic;

	if (htonl(hdr->conduit) != FR_CONDUIT_INIT_ACK) {
		DEBUG("ERROR: Connection is missing initial ACK packet.");
		return -1;
	}

	if (buffer_len < sizeof(*hdr)) {
		DEBUG("ERROR: Initial ACK is malformed");
		return -1;
	}

	if (htonl(hdr->length) != 8) {
		DEBUG("ERROR: Initial ACK has wrong length (%lu).", (size_t) htonl(hdr->length));
		return -1;
	}

	memcpy(&magic, buffer + sizeof(*hdr), sizeof(magic));
	magic = htonl(magic);
	if (magic != FR_CONDUIT_MAGIC) {
		DEBUG("ERROR: Connection from incompatible version of radmin.");
		return -1;
	}

	/*
	 *	Next 4 bytes are zero, we ignore them.
	 */
	if (write(inst->sockfd, buffer, buffer_len) < (ssize_t) buffer_len) {
		DEBUG("ERROR: Blocking write to socket... oops");
		return -1;
	}

	inst->read = mod_read_command;

	return 0;
}

static ssize_t mod_read(void *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority, bool *is_dup)
{
	proto_control_unix_t		*inst = talloc_get_type_abort(instance, proto_control_unix_t);
	ssize_t				data_size;

	fr_time_t			*recv_time_p;
	fr_conduit_type_t		conduit;

	recv_time_p = *recv_time;

	/*
	 *      Read data into the buffer.
	 */
	data_size = fr_conduit_read_async(inst->sockfd, &conduit, buffer, buffer_len, leftover);
	if (data_size < 0) {
		DEBUG2("proto_control_unix got read error %zd: %s", data_size, fr_strerror());
		return data_size;
	}

	/*
	 *	Note that we return ERROR for all bad packets, as
	 *	there's no point in reading packets from a TCP
	 *	connection which isn't sending us properly formatted
	 *	packets.
	 */

	/*
	 *	Not enough for a full packet, ask the caller to read more.
	 */
	if (conduit == FR_CONDUIT_WANT_MORE) {
		return 0;
	}

	// @todo - maybe convert timestamp?
	*recv_time_p = fr_time();
	*leftover = 0;

	/*
	 *	proto_control sets the priority
	 */

	/*
	 *	Print out what we received.
	 */
	DEBUG2("proto_control_unix - Received command packet length %d on %s",
	       (int) data_size, inst->name);

	/*
	 *	Run the state machine to process the rest of the packet.
	 */
	return inst->read(instance, packet_ctx, recv_time, buffer, (size_t) data_size, leftover, priority, is_dup);
}


static ssize_t mod_write(void *instance, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_control_unix_t		*inst = talloc_get_type_abort(instance, proto_control_unix_t);
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_control
	 *	can update them, too.. <sigh>
	 */
	inst->stats.total_responses++;

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = write(inst->sockfd, buffer + written, buffer_len - written);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

	return data_size + written;
}


/** Close a UNIX listener for RADIUS
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_close(void *instance)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}

static int mod_connection_set(void *instance, fr_io_address_t *connection)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	inst->connection = connection;

	// @todo - set name to path + peer ID of other end?

	return 0;
}

static void mod_network_get(UNUSED void *instance, int *ipproto, bool *dynamic_clients, fr_trie_t const **trie)
{
	*ipproto = IPPROTO_TCP;
	*dynamic_clients = false;
	*trie = NULL;
}

/** Initialise a socket for use with peercred authentication
 *
 * This function initialises a socket and path in a way suitable for use with
 * peercred.
 *
 * @param path to socket.
 * @param uid that should own the socket (linux only).
 * @param gid that should own the socket (linux only).
 * @return 0 on success -1 on failure.
 */
#ifdef __linux__
static int fr_server_domain_socket_peercred(char const *path, uid_t uid, gid_t gid)
#else
static int fr_server_domain_socket_peercred(char const *path, uid_t UNUSED uid, UNUSED gid_t gid)
#endif
{
	int sockfd;
	size_t len;
	socklen_t socklen;
	struct sockaddr_un salocal;
	struct stat buf;

	if (!path) {
		fr_strerror_printf("No path provided, was NULL");
		return -1;
	}

	len = strlen(path);
	if (len >= sizeof(salocal.sun_path)) {
		fr_strerror_printf("Path too long in socket filename");
		return -1;
	}

	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fr_strerror_printf("Failed creating socket: %s", fr_syserror(errno));
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
			fr_strerror_printf("Failed to stat %s: %s", path, fr_syserror(errno));
			close(sockfd);
			return -1;
		}

		/*
		 *	FIXME: Check the enclosing directory?
		 */
	} else {		/* it exists */
		int client_fd;

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

		/*
		 *	Check if a server is already listening on the
		 *	socket?
		 */
		client_fd = fr_socket_client_unix(path, false);
		if (client_fd >= 0) {
			fr_strerror_printf("Control socket '%s' is already in use", path);
			close(client_fd);
			close(sockfd);
			return -1;
		}

		if (unlink(path) < 0) {
		       fr_strerror_printf("Failed to delete %s: %s", path, fr_syserror(errno));
		       close(sockfd);
		       return -1;
		}
	}

	if (bind(sockfd, (struct sockaddr *)&salocal, socklen) < 0) {
		fr_strerror_printf("Failed binding to %s: %s", path, fr_syserror(errno));
		close(sockfd);
		return -1;
	}

	/*
	 *	FIXME: There's a race condition here.  But Linux
	 *	doesn't seem to permit fchmod on domain sockets.
	 */
	if (chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) < 0) {
		fr_strerror_printf("Failed setting permissions on %s: %s", path, fr_syserror(errno));
		close(sockfd);
		return -1;
	}

	if (listen(sockfd, 8) < 0) {
		fr_strerror_printf("Failed listening to %s: %s", path, fr_syserror(errno));
		close(sockfd);
		return -1;
	}

#ifdef O_NONBLOCK
	{
		int flags;

		if ((flags = fcntl(sockfd, F_GETFL, NULL)) < 0)  {
			fr_strerror_printf("Failure getting socket flags: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}

		flags |= O_NONBLOCK;
		if( fcntl(sockfd, F_SETFL, flags) < 0) {
			fr_strerror_printf("Failure setting socket flags: %s", fr_syserror(errno));
			close(sockfd);
			return -1;
		}
	}
#endif

	/*
	 *	Changing socket permissions only works on linux.
	 *	BSDs ignore socket permissions.
	 */
#ifdef __linux__
	/*
	 *	Don't chown it from (possibly) non-root to root.
	 *	Do chown it from (possibly) root to non-root.
	 */
	if ((uid != (uid_t) -1) || (gid != (gid_t) -1)) {
		/*
		 *	Don't do chown if it's already owned by us.
		 */
		if (fstat(sockfd, &buf) < 0) {
			fr_strerror_printf("Failed reading %s: %s", path, fr_syserror(errno));
			close(sockfd);
			return -1;
		}

		if ((buf.st_uid != uid) || (buf.st_gid != gid)) {
			rad_suid_up();
			if (fchown(sockfd, uid, gid) < 0) {
				fr_strerror_printf("Failed setting ownership of %s to (%d, %d): %s",
				      path, uid, gid, fr_syserror(errno));
				rad_suid_down();
				close(sockfd);
				return -1;
			}
			rad_suid_down();
		}
	}
#endif

	return sockfd;
}

#if !defined(HAVE_OPENAT) || !defined(HAVE_MKDIRAT) || !defined(HAVE_UNLINKAT)
static int fr_server_domain_socket_perm(UNUSED char const *path, UNUSED uid_t uid, UNUSED gid_t gid)
{
	fr_strerror_printf("Unable to initialise control socket.  Set peercred = yes or update to "
			   "POSIX-2008 compliant libc");
	return -1;
}
#else
/** Alternative function for creating Unix domain sockets and enforcing permissions
 *
 * Unlike fr_server_unix_socket which is intended to be used with peercred auth
 * this function relies on the file system to enforce access.
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
 * @note must be called without effective root permissions (fr_suid_down).
 *
 * @param path where domain socket should be created.
 * @return a file descriptor for the bound socket on success, -1 on failure.
 */
static int fr_server_domain_socket_perm(char const *path, uid_t uid, gid_t gid)
{
	int			dir_fd = -1, sock_fd = -1, parent_fd = -1;
	char const		*name;
	char			*buff = NULL, *dir = NULL, *p;

	uid_t			euid;
	gid_t			egid;

	mode_t			perm = 0;
	struct stat		st;

	size_t			len;

	socklen_t		socklen;
	struct sockaddr_un	salocal;

	rad_assert(path);

	euid = geteuid();
	egid = getegid();

	/*
	 *	Determine the correct permissions for the socket, or its
	 *	containing directory.
	 */
	perm |= S_IREAD | S_IWRITE | S_IEXEC;
	if (gid != (gid_t) -1) perm |= S_IRGRP | S_IWGRP | S_IXGRP;

	buff = talloc_strdup(NULL, path);
	if (!buff) return -1;

	/*
	 *	Some implementations modify it in place others use internal
	 *	storage *sigh*. dirname also formats the path else we wouldn't
	 *	be using it.
	 */
	dir = dirname(buff);
	if (dir != buff) {
		dir = talloc_strdup(NULL, dir);
		if (!dir) return -1;
		talloc_free(buff);
	}

	p = strrchr(dir, FR_DIR_SEP);
	if (!p) {
		fr_strerror_printf("Failed determining parent directory");
	error:
		talloc_free(dir);
		if (sock_fd >= 0) close(sock_fd);
		if (dir_fd >= 0) close(dir_fd);
		if (parent_fd >= 0) close(parent_fd);
		return -1;
	}

	*p = '\0';

	/*
	 *	Ensure the parent of the control socket directory exists,
	 *	and the euid we're running under has access to it.
	 */
	parent_fd = open(dir, O_DIRECTORY);
	if (parent_fd < 0) {
		struct passwd *user;
		struct group *group;

		if (rad_getpwuid(NULL, &user, euid) < 0) goto error;
		if (rad_getgrgid(NULL, &group, egid) < 0) {
			talloc_free(user);
			goto error;
		}
		fr_strerror_printf("Can't open directory \"%s\": %s.  Must be created manually, or modified, "
				   "with permissions that allow writing by user %s or group %s", dir,
				   user->pw_name, group->gr_name, fr_syserror(errno));
		talloc_free(user);
		talloc_free(group);
		goto error;
	}

	*p = FR_DIR_SEP;

	dir_fd = openat(parent_fd, p + 1, O_NOFOLLOW | O_DIRECTORY);
	if (dir_fd < 0) {
		int ret = 0;

		if (errno != ENOENT) {
			fr_strerror_printf("Failed opening control socket directory: %s", fr_syserror(errno));
			goto error;
		}

		/*
		 *	This fails if the radius user can't write
		 *	to the parent directory.
		 */
	 	if (mkdirat(parent_fd, p + 1, 0700) < 0) {
			fr_strerror_printf("Failed creating control socket directory: %s", fr_syserror(errno));
			goto error;
	 	}

		dir_fd = openat(parent_fd, p + 1, O_NOFOLLOW | O_DIRECTORY);
		if (dir_fd < 0) {
			fr_strerror_printf("Failed opening the control socket directory we created: %s",
					   fr_syserror(errno));
			goto error;
		}
		if (fchmod(dir_fd, perm) < 0) {
			fr_strerror_printf("Failed setting permissions on control socket directory: %s",
					   fr_syserror(errno));
			goto error;
		}

		rad_suid_up();
		if ((uid != (uid_t)-1) || (gid != (gid_t)-1)) ret = fchown(dir_fd, uid, gid);
		rad_suid_down();
		if (ret < 0) {
			fr_strerror_printf("Failed changing ownership of control socket directory: %s",
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

		if ((uid != (uid_t)-1) && (st.st_uid != uid)) {
			struct passwd *need_user, *have_user;

			if (rad_getpwuid(NULL, &need_user, uid) < 0) goto error;
			if (rad_getpwuid(NULL, &have_user, st.st_uid) < 0) {
				talloc_free(need_user);
				goto error;
			}
			fr_strerror_printf("Control socket directory must be owned by user %s, "
					   "currently owned by %s", need_user->pw_name, have_user->pw_name);
			talloc_free(need_user);
			talloc_free(have_user);
			goto error;
		}

		if ((gid != (gid_t)-1) && (st.st_gid != gid)) {
			struct group *need_group, *have_group;

			if (rad_getgrgid(NULL, &need_group, gid) < 0) goto error;
			if (rad_getgrgid(NULL, &have_group, st.st_gid) < 0) {
				talloc_free(need_group);
				goto error;
			}
			fr_strerror_printf("Control socket directory \"%s\" must be owned by group %s, "
					   "currently owned by %s", dir, need_group->gr_name, have_group->gr_name);
			talloc_free(need_group);
			talloc_free(have_group);
			goto error;
		}

		if ((perm & 0x0c) != (st.st_mode & 0x0c)) {
			char str_need[10], oct_need[5];
			char str_have[10], oct_have[5];

			rad_mode_to_str(str_need, perm);
			rad_mode_to_oct(oct_need, perm);
			rad_mode_to_str(str_have, st.st_mode);
			rad_mode_to_oct(oct_have, st.st_mode);
			fr_strerror_printf("Control socket directory must have permissions %s (%s), current "
					   "permissions are %s (%s)", str_need, oct_need, str_have, oct_have);
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
	if ((uid != (uid_t)-1) && (rad_seuid(uid) < 0)) goto error;
	if ((gid != (gid_t)-1) && (rad_segid(gid) < 0)) {
		rad_seuid(euid);
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
		if (uid != (uid_t)-1) rad_seuid(euid);
		if (gid != (gid_t)-1) rad_segid(egid);
		close(sock_fd);

		goto error;
	}

	/*
	 *	At this point we should have established a secure directory
	 *	to house our socket, and cleared out any stale sockets.
	 */
	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		fr_strerror_printf("Failed creating socket: %s", fr_syserror(errno));
		goto sock_error;
	}

#ifdef HAVE_BINDAT
	len = strlen(name);
#else
	len = strlen(path);
#endif
	if (len >= sizeof(salocal.sun_path)) {
		fr_strerror_printf("Path too long in socket filename");
		goto error;
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
	 *	Direct socket permissions are only useful on Linux which
	 *	actually enforces them. BSDs don't. They also need to be
	 *	set before binding the socket to a file.
	 */
#ifdef __linux__
	if (fchmod(sock_fd, perm) < 0) {
		char str_need[10], oct_need[5];

		rad_mode_to_str(str_need, perm);
		rad_mode_to_oct(oct_need, perm);
		fr_strerror_printf("Failed changing socket permissions to %s (%s)", str_need, oct_need);

		goto sock_error;
	}

	if (fchown(sock_fd, uid, gid) < 0) {
		struct passwd *user;
		struct group *group;

		if (rad_getpwuid(NULL, &user, uid) < 0) goto sock_error;
		if (rad_getgrgid(NULL, &group, gid) < 0) {
			talloc_free(user);
			goto sock_error;
		}

		fr_strerror_printf("Failed changing ownership of socket to %s:%s", user->pw_name, group->gr_name);
		talloc_free(user);
		talloc_free(group);
		goto sock_error;
	}
#endif
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

	if (listen(sock_fd, 8) < 0) {
		fr_strerror_printf("Failed listening on socket: %s", fr_syserror(errno));
		goto sock_error;
	}

#ifdef O_NONBLOCK
	{
		int flags;

		flags = fcntl(sock_fd, F_GETFL, NULL);
		if (flags < 0)  {
			fr_strerror_printf("Failed getting socket flags: %s", fr_syserror(errno));
			goto sock_error;
		}

		flags |= O_NONBLOCK;
		if (fcntl(sock_fd, F_SETFL, flags) < 0) {
			fr_strerror_printf("Failed setting nonblocking socket flag: %s", fr_syserror(errno));
			goto sock_error;
		}
	}
#endif

	if (uid != (uid_t)-1) rad_seuid(euid);
	if (gid != (gid_t)-1) rad_segid(egid);

	if (dir_fd >= 0) close(dir_fd);
	if (parent_fd >= 0) close(parent_fd);

	return sock_fd;
}
#endif

/** Open a UNIX listener for RADIUS
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int mod_open(void *instance)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	int				sockfd = 0;
	CONF_SECTION			*server_cs;
	CONF_ITEM			*ci;

	rad_assert(!inst->connection);

	rad_assert(inst->name != NULL);

	if (inst->peercred) {
		sockfd = fr_server_domain_socket_peercred(inst->filename, inst->uid, inst->gid);
	} else {
		uid_t uid = inst->uid;
		gid_t gid = inst->gid;

		if (uid == ((uid_t)-1)) uid = 0;
		if (gid == ((gid_t)-1)) gid = 0;

		sockfd = fr_server_domain_socket_perm(inst->filename, uid, gid);
	}
	if (sockfd < 0) {
		PERROR("Failed opening UNIX path %s", inst->filename);
		return -1;
	}

	inst->sockfd = sockfd;

	ci = cf_parent(inst->cs); /* listen { ... } */
	rad_assert(ci != NULL);
	ci = cf_parent(ci);
	rad_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	// @todo - also print out auth / acct / coa, etc.
	DEBUG("Listening on control address %s bound to virtual server %s",
	      inst->name, cf_section_name2(server_cs));

	return 0;
}

/** Get the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @return the file descriptor
 */
static int mod_fd(void const *instance)
{
	proto_control_unix_t const *inst = talloc_get_type_abort_const(instance, proto_control_unix_t);

	return inst->sockfd;
}

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

/** Set the file descriptor for this socket.
 *
 * @param[in] instance of the RADIUS UNIX I/O path.
 * @param[in] fd the FD to set
 */
static int mod_fd_set(void *instance, int fd)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);


#ifdef HAVE_GETPEEREID
	/*
	 *	Perform user authentication.
	 */
	if (inst->peercred && (inst->uid_name || inst->gid_name)) {
		uid_t uid;
		gid_t gid;

		if (getpeereid(fd, &uid, &gid) < 0) {
			ERROR("Failed getting peer credentials for %s: %s",
			       inst->filename, fr_syserror(errno));
			return -1;
		}

		/*
		 *	Only do UID checking if the caller is
		 *	non-root.  The superuser can do anything, so
		 *	we might as well let them.
		 */
		if (uid != 0) do {
			/*
			 *	Allow entry if UID or GID matches.
			 */
			if (inst->uid_name && (inst->uid == uid)) break;
			if (inst->gid_name && (inst->gid == gid)) break;

			if (inst->uid_name && (inst->uid != uid)) {
				ERROR("Unauthorized connection to %s from uid %ld",

				       inst->filename, (long int) uid);
				return -1;
			}

			if (inst->gid_name && (inst->gid != gid)) {
				ERROR("Unauthorized connection to %s from gid %ld",
				       inst->filename, (long int) gid);
				return -1;
			}

		} while (0);
	}
#endif

	inst->sockfd = fd;
	inst->read= mod_read_init;

	return 0;
}


static int mod_instantiate(void *instance, UNUSED CONF_SECTION *cs)
{
	proto_control_unix_t *inst = talloc_get_type_abort(instance, proto_control_unix_t);

	if (!inst->connection) {
		inst->name = talloc_typed_asprintf(inst, "proto unix server %s filename %s",
						   "???", inst->filename);

	} else {
		inst->name = talloc_typed_asprintf(inst, "proto unix via filename %s",
						   inst->filename);
	}

	return 0;
}


static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	proto_control_unix_t	*inst = talloc_get_type_abort(instance, proto_control_unix_t);

	inst->cs = cs;

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

#ifndef HAVE_GETPEEREID
	if (inst->peercred && (inst->uid_name || inst->gid_name)) {
		ERROR("System does not support uid or gid authentication for sockets");
		return -1;
	}
#endif

	if (inst->uid_name) {
		struct passwd *pwd;

		if (rad_getpwnam(cs, &pwd, inst->uid_name) < 0) {
			ERROR("Failed getting uid for %s: %s", inst->uid_name, fr_strerror());
			return -1;
		}
		inst->uid = pwd->pw_uid;
		talloc_free(pwd);
	} else {
		inst->uid = -1;
	}

	if (inst->gid_name) {
		if (rad_getgid(cs, &inst->gid, inst->gid_name) < 0) {
			ERROR("Failed getting gid for %s: %s", inst->gid_name, fr_strerror());
			return -1;
		}
	} else {
		inst->gid = -1;
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 20);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	/*
	 *	Set up the fake client
	 */
	inst->radclient.longname = inst->filename;
	inst->radclient.ipaddr.af = AF_INET;
	inst->radclient.src_ipaddr.af = AF_INET;

	inst->radclient.server_cs = cf_item_to_section(cf_parent(cf_parent(cs)));
	rad_assert(inst->radclient.server_cs != NULL);
	inst->radclient.server = cf_section_name2(inst->radclient.server_cs);

	return 0;
}

static RADCLIENT *mod_client_find(void *instance, UNUSED fr_ipaddr_t const *ipaddr, UNUSED int ipproto)
{
	proto_control_unix_t	*inst = talloc_get_type_abort(instance, proto_control_unix_t);

	return &inst->radclient;
}

#if 0
static int mod_detach(void *instance)
{
	proto_control_unix_t	*inst = talloc_get_type_abort(instance, proto_control_unix_t);

	if (inst->sockfd >= 0) close(inst->sockfd);
	inst->sockfd = -1;

	return 0;
}
#endif

extern fr_app_io_t proto_control_unix;
fr_app_io_t proto_control_unix = {
	.magic			= RLM_MODULE_INIT,
	.name			= "control_unix",
	.config			= unix_listen_config,
	.inst_size		= sizeof(proto_control_unix_t),
//	.detach			= mod_detach,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,

	.default_message_size	= 4096,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.close			= mod_close,
	.fd			= mod_fd,
	.fd_set			= mod_fd_set,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
};
