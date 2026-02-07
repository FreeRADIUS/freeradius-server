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
#include <freeradius-devel/server/main_config.h>

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/schedule.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/util/file.h>

#include <netdb.h>

#include "proto_control.h"

#include <freeradius-devel/bio/fd.h>

#ifdef HAVE_SYS_STAT_H
#endif

#include <fcntl.h>
#include <libgen.h>

typedef struct {
	char const			*name;			//!< socket name

	int				sockfd;

	fr_bio_t			*fd_bio;

	fr_stats_t			stats;			//!< statistics for this socket

	fr_io_address_t			*connection;		//!< for connected sockets.


	fr_io_data_read_t		read;			//!< function to process data *after* reading
	FILE				*stdout_fp;
	FILE				*stderr_fp;

	fr_conduit_type_t      		misc_conduit;
	FILE				*misc;
	fr_cmd_info_t			*info;			//!< for running commands

	fr_client_t			radclient;		//!< for faking out clients
} proto_control_unix_thread_t;

typedef struct {
	CONF_SECTION			*cs;			//!< our configuration

	char const     			*filename;     		//!< filename of control socket
	char const     			*uid_name;		//!< name of UID to require
	char const     			*gid_name;     		//!< name of GID to require
	uid_t				uid;			//!< UID value
	gid_t				gid;			//!< GID value

	uint32_t			recv_buff;		//!< How big the kernel's receive buffer should be.

	uint32_t			max_packet_size;	//!< for message ring buffer.

	char const			*mode_name;
	bool				read_only;

	bool				recv_buff_is_set;	//!< Whether we were provided with a receive
								//!< buffer value.
	char const     			*peer_uid_name;		//!< name of UID to require
	char const     			*peer_gid_name;     	//!< name of GID to require
	uid_t				peer_uid;		//!< UID value
	gid_t				peer_gid;		//!< GID value

} proto_control_unix_t;

static const conf_parser_t peercred_config[] = {
	{ FR_CONF_OFFSET("uid", proto_control_unix_t, peer_uid_name) },
	{ FR_CONF_OFFSET("gid", proto_control_unix_t, peer_gid_name) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t unix_listen_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_REQUIRED, proto_control_unix_t, filename),
	.dflt = "${run_dir}/radiusd.sock}" },
	{ FR_CONF_OFFSET("uid", proto_control_unix_t, uid_name) },
	{ FR_CONF_OFFSET("gid", proto_control_unix_t, gid_name) },
	{ FR_CONF_OFFSET("mode", proto_control_unix_t, mode_name) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, proto_control_unix_t, recv_buff) },

	{ FR_CONF_OFFSET("max_packet_size", proto_control_unix_t, max_packet_size), .dflt = "4096" } ,

	{ FR_CONF_POINTER("peercred", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) peercred_config },

	CONF_PARSER_TERMINATOR
};

#define FR_READ  (1)
#define FR_WRITE (2)

static fr_table_num_sorted_t mode_names[] = {
	{ L("read-only"),		FR_READ			},
	{ L("read-write"),		FR_READ | FR_WRITE	},
	{ L("ro"),			FR_READ			},
	{ L("rw"),			FR_READ | FR_WRITE	}
};
static size_t mode_names_len = NUM_ELEMENTS(mode_names);

#undef INT
#define INT size_t
#define SINT ssize_t

static SINT write_stdout(void *instance, char const *buffer, INT buffer_size)
{
	proto_control_unix_thread_t *thread = talloc_get_type_abort(instance, proto_control_unix_thread_t);

	return fr_conduit_write(thread->sockfd, FR_CONDUIT_STDOUT, buffer, buffer_size);
}

static SINT write_stderr(void *instance, char const *buffer, INT buffer_size)
{
	proto_control_unix_thread_t *thread = talloc_get_type_abort(instance, proto_control_unix_thread_t)
;
	return fr_conduit_write(thread->sockfd, FR_CONDUIT_STDERR, buffer, buffer_size);
}

static SINT write_misc(void *instance, char const *buffer, INT buffer_size)
{
	proto_control_unix_thread_t *thread = talloc_get_type_abort(instance, proto_control_unix_thread_t);

	return fr_conduit_write(thread->sockfd, thread->misc_conduit, buffer, buffer_size);
}


/*
 *	Run a command.
 */
static ssize_t mod_read_command(fr_listen_t *li, UNUSED void **packet_ctx, UNUSED fr_time_t *recv_time_p, uint8_t *buffer, UNUSED size_t buffer_len, UNUSED size_t *leftover)
{
	proto_control_unix_t const     	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_control_unix_t);
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);
	fr_conduit_hdr_t		*hdr = (fr_conduit_hdr_t *) buffer;
	uint32_t			status;
	uint8_t				*cmd = buffer + sizeof(*hdr);
	int				rcode;
	char				string[1024];

	hdr->length = ntohl(hdr->length);
	if (hdr->length >= sizeof(string)) goto fail;

	/*
	 *	If the write gives us nothing, send an empty SUCCESS back.
	 */
	if (!hdr->length) {
		status = FR_CONDUIT_SUCCESS;
		goto done;
	}

	/*
	 *	fr_command_run() expects a zero-terminated string...
	 */
	memcpy(string, cmd, hdr->length);
	string[hdr->length] = '\0';

	/*
	 *	Content is the string we need help for.
	 */
	if (htons(hdr->conduit) == FR_CONDUIT_HELP) {
		fr_radmin_help(thread->stdout_fp, string);
		// @todo - have in-band signalling saying that the help is done?
		// we want to be able to say that *this* help is done.
		// the best way to do that is to have a token, and every command
		// from the other end sends a token, and we echo it back here...
		// Or, since we currently can't do streaming commands, it's OK?
		// Or, we assume that origin 0 is for interactive commands,
		// and that the other origins are for streaming output...
		status = FR_CONDUIT_SUCCESS;
		goto done;
	}

	if (htons(hdr->conduit) == FR_CONDUIT_COMPLETE) {
		uint16_t start;

		if (hdr->length < 2) goto fail;

		start = (string[0] << 8) | string[1];

		thread->misc_conduit = FR_CONDUIT_COMPLETE;

		fr_radmin_complete(thread->misc, string + 2, start);
		thread->misc_conduit = FR_CONDUIT_STDOUT;
		status = FR_CONDUIT_SUCCESS;
		goto done;
	}

	if (htons(hdr->conduit) != FR_CONDUIT_STDIN) {
		DEBUG("ERROR: Ignoring data which is from wrong input");
		return 0;
	}

	DEBUG("radmin-remote> %.*s", (int) hdr->length, cmd);

	rcode = fr_radmin_run(thread->info, thread->stdout_fp, thread->stderr_fp, string, inst->read_only);
	if (rcode < 0) {
fail:
		status = FR_CONDUIT_FAIL;

	} else if (rcode == 0) {
		/*
		 *	The other end should keep track of it's
		 *	context, and send us full lines.
		 */
		(void) fr_command_clear(0, thread->info);
		status = FR_CONDUIT_PARTIAL;
	} else {
		status = FR_CONDUIT_SUCCESS;
	}

done:
	status = htonl(status);
	(void) fr_conduit_write(thread->sockfd, FR_CONDUIT_CMD_STATUS, &status, sizeof(status));

	return 0;
}

/*
 *	Process an initial connection request.
 */
static ssize_t mod_read_init(fr_listen_t *li, UNUSED void **packet_ctx, UNUSED fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, UNUSED size_t *leftover)
{
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);
	fr_conduit_hdr_t		*hdr = (fr_conduit_hdr_t *) buffer;
	uint32_t			magic;

	if (htons(hdr->conduit) != FR_CONDUIT_INIT_ACK) {
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
	if (write(thread->sockfd, buffer, buffer_len) < (ssize_t) buffer_len) {
		DEBUG("ERROR: Blocking write to socket... oops");
		return -1;
	}

	thread->read = mod_read_command;

	return 0;
}

static ssize_t mod_read(fr_listen_t *li, void **packet_ctx, fr_time_t *recv_time_p, uint8_t *buffer, size_t buffer_len, size_t *leftover)
{
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);
	ssize_t				data_size;

	fr_conduit_type_t		conduit;
	bool				want_more;

	/*
	 *      Read data into the buffer.
	 */
	data_size = fr_conduit_read_async(thread->sockfd, &conduit, buffer, buffer_len, leftover, &want_more);
	if (data_size < 0) {
		DEBUG2("proto_control_unix got read error %zd: %s", data_size, fr_syserror(errno));
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
	if (want_more) {
		return 0;
	}

	// @todo - maybe convert timestamp?
	*recv_time_p = fr_time();
	*leftover = 0;

	/*
	 *	Print out what we received.
	 */
	DEBUG3("proto_control_unix - Received command packet length %d on %s",
	       (int) data_size, thread->name);

	/*
	 *	Run the state machine to process the rest of the packet.
	 */
	return thread->read(li, packet_ctx, recv_time_p, buffer, (size_t) data_size, leftover);
}


static ssize_t mod_write(fr_listen_t *li, UNUSED void *packet_ctx, UNUSED fr_time_t request_time,
			 uint8_t *buffer, size_t buffer_len, size_t written)
{
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);
	ssize_t				data_size;

	/*
	 *	@todo - share a stats interface with the parent?  or
	 *	put the stats in the listener, so that proto_control
	 *	can update them, too.. <sigh>
	 */
	thread->stats.total_responses++;

	/*
	 *	Only write replies if they're RADIUS packets.
	 *	sometimes we want to NOT send a reply...
	 */
	data_size = write(thread->sockfd, buffer + written, buffer_len - written);

	/*
	 *	This socket is dead.  That's an error...
	 */
	if (data_size <= 0) return data_size;

#ifdef __COVERITY__
	/*
	 *      data_size and written have type size_t, so
	 *      their sum can at least in theory exceed SSIZE_MAX.
	 * 	We add this check to placate Coverity.
	 *
	 *      When Coverity examines this function it doesn't have
	 * 	the caller context to see that it's honoring needed
	 * 	preconditions (buffer_len <=SSIZE_MAX, and the loop
	 * 	schema needed to use this function).
	 */
	if (data_size + written > SSIZE_MAX) return -1;
#endif

	return data_size + written;
}


static int mod_connection_set(fr_listen_t *li, fr_io_address_t *connection)
{
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);

	thread->connection = connection;

	// @todo - set name to path + peer ID of other end?

	return 0;
}

static void mod_network_get(int *ipproto, bool *dynamic_clients, fr_trie_t const **trie, UNUSED void *instance)
{
	*ipproto = IPPROTO_TCP;
	*dynamic_clients = false;
	*trie = NULL;
}

/** Open a UNIX listener for control sockets
 *
 */
static int mod_open(fr_listen_t *li)
{
	proto_control_unix_t const     	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_control_unix_t);
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);

	CONF_ITEM			*ci;
	CONF_SECTION			*server_cs;

	fr_bio_fd_info_t const		*info;
	fr_bio_fd_config_t     		cfg;

	fr_assert(!thread->connection);

	cfg = (fr_bio_fd_config_t) {
		.type = FR_BIO_FD_LISTEN,
		.socket_type = SOCK_STREAM,
		.path = inst->filename,
		.uid = inst->uid,
		.gid = inst->gid,
		.perm = 0600,
		.async = true,
	};

	thread->fd_bio = fr_bio_fd_alloc(thread, &cfg, 0);
	if (!thread->fd_bio) {
		cf_log_err(li->cs, "Failed opening UNIX path %s - ", inst->filename, fr_strerror());
		return -1;
	}

	info = fr_bio_fd_info(thread->fd_bio);
	fr_assert(info != NULL);

	li->fd = thread->sockfd = info->socket.fd;

	ci = cf_parent(inst->cs); /* listen { ... } */
	fr_assert(ci != NULL);
	ci = cf_parent(ci);
	fr_assert(ci != NULL);

	server_cs = cf_item_to_section(ci);

	thread->name = talloc_typed_asprintf(thread, "control_unix from filename %s", inst->filename);

	/*
	 *	Set up the fake client
	 */
	thread->radclient.longname = inst->filename;
	thread->radclient.ipaddr.af = AF_INET;
	thread->radclient.src_ipaddr.af = AF_INET;

	thread->radclient.server_cs = server_cs;
	fr_assert(thread->radclient.server_cs != NULL);
	thread->radclient.server = cf_section_name2(thread->radclient.server_cs);

	return 0;
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

static int _close_cookies(proto_control_unix_thread_t *thread)
{
	if (thread->stdout_fp) fclose(thread->stdout_fp);
	if (thread->stderr_fp) fclose(thread->stderr_fp);
	if (thread->misc) fclose(thread->misc);

	return 0;
}

/** Set the file descriptor for this socket.
 *
 */
static int mod_fd_set(fr_listen_t *li, int fd)
{
	proto_control_unix_t const     	*inst = talloc_get_type_abort_const(li->app_io_instance, proto_control_unix_t);
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);

	cookie_io_functions_t io;

#ifdef HAVE_GETPEEREID
	/*
	 *	Perform user authentication.
	 *
	 *	@todo - this really belongs in the accept() callback,
	 *	so that we don't create an entirely new listener and
	 *	then close it.
	 */
	if (inst->peer_uid || inst->peer_gid) {
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
		 *	we might as well let them do anything.
		 */
		if (uid != 0) do {
				/*
				 *	Allow entry if UID or GID matches.
				 */
				if (inst->peer_uid_name && (inst->peer_uid == uid)) break;
				if (inst->peer_gid_name && (inst->peer_gid == gid)) break;

				if (inst->peer_uid_name && (inst->peer_uid != uid)) {
					ERROR("Unauthorized connection to %s from uid %ld",
					      inst->filename, (long int) uid);
					return -1;
				}

				if (inst->peer_gid_name && (inst->peer_gid != gid)) {
					ERROR("Unauthorized connection to %s from gid %ld",
					      inst->filename, (long int) gid);
					return -1;
				}

			} while (0);

		thread->name = talloc_typed_asprintf(thread, "proto unix filename %s from peer UID %u GID %u",
						     inst->filename,
						     (unsigned int) uid, (unsigned int) gid);
	} else
#endif


	thread->name = talloc_typed_asprintf(thread, "proto unix filename %s", inst->filename);

	thread->sockfd = fd;
	thread->read = mod_read_init;

	/*
	 *	These must be set separately as they have different prototypes.
	 */
	io.read = NULL;
	io.seek = NULL;
	io.close = NULL;
	io.write = write_stdout;

	thread->stdout_fp = fopencookie(thread, "w", io);

	io.write = write_stderr;
	thread->stderr_fp = fopencookie(thread, "w", io);

	io.write = write_misc;
	thread->misc = fopencookie(thread, "w", io);

	talloc_set_destructor(thread, _close_cookies);

	/*
	 *	@todo - if we move to a binary protocol, then we
	 *	should change this to a small (i.e. 1K) buffer.  The
	 *	data should be sent over to the remote side as quickly
	 *	as possible.
	 */
	(void) setvbuf(thread->stdout_fp, NULL, _IOLBF, 0);
	(void) setvbuf(thread->stderr_fp, NULL, _IOLBF, 0);
	(void) setvbuf(thread->misc, NULL, _IOLBF, 0);

	thread->info = talloc_zero(thread, fr_cmd_info_t);
	fr_command_info_init(thread, thread->info);

	return 0;
}

static char const *mod_name(fr_listen_t *li)
{
	proto_control_unix_thread_t	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);

	return thread->name;
}


static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	proto_control_unix_t	*inst = talloc_get_type_abort(mctx->mi->data, proto_control_unix_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	inst->cs = conf;

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, 32);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	if (inst->uid_name) {
		struct passwd *pwd;

		if (fr_perm_getpwnam(conf, &pwd, inst->uid_name) < 0) {
			PERROR("Failed getting uid for %s", inst->uid_name);
			return -1;
		}
		inst->uid = pwd->pw_uid;
		talloc_free(pwd);

	} else if (main_config->server_uid) {
		inst->uid = main_config->server_uid;

	} else {
		inst->uid = getuid();
	}

	if (inst->gid_name) {
		if (fr_perm_gid_from_str(conf, &inst->gid, inst->gid_name) < 0) {
			PERROR("Failed getting gid for %s", inst->gid_name);
			return -1;
		}

	} else if (main_config->server_gid) {
		inst->gid = main_config->server_gid;

	} else {
		inst->gid = getgid();
	}

	/*
	 *	And for peer creds
	 */
	if (inst->peer_uid_name) {
		struct passwd *pwd;

		if (fr_perm_getpwnam(conf, &pwd, inst->peer_uid_name) < 0) {
			PERROR("Failed getting peer uid for %s", inst->peer_uid_name);
			return -1;
		}
		inst->peer_uid = pwd->pw_uid;
		talloc_free(pwd);
	}

	if (inst->peer_gid_name) {
		if (fr_perm_gid_from_str(conf, &inst->peer_gid, inst->peer_gid_name) < 0) {
			PERROR("Failed getting peer gid for %s", inst->peer_gid_name);
			return -1;
		}
	}

	if (!inst->mode_name) {
		inst->read_only = true;
	} else {
		int mode;

		mode = fr_table_value_by_str(mode_names, inst->mode_name, 0);
		if (!mode) {
			ERROR("Invalid mode name \"%s\"",
			      inst->mode_name);
			return -1;
		}

		if ((mode & FR_WRITE) == 0) {
			inst->read_only = true;
		} else {
			inst->read_only = false;
		}
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 20);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65536);

	return 0;
}

static fr_client_t *mod_client_find(fr_listen_t *li, UNUSED fr_ipaddr_t const *ipaddr, UNUSED int ipproto)
{
	proto_control_unix_thread_t    	*thread = talloc_get_type_abort(li->thread_instance, proto_control_unix_thread_t);

	return &thread->radclient;
}

extern fr_app_io_t proto_control_unix;
fr_app_io_t proto_control_unix = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "control_unix",
		.config			= unix_listen_config,
		.inst_size		= sizeof(proto_control_unix_t),
		.thread_inst_size	= sizeof(proto_control_unix_thread_t),
		.instantiate		= mod_instantiate
	},
	.default_message_size	= 4096,

	.open			= mod_open,
	.read			= mod_read,
	.write			= mod_write,
	.fd_set			= mod_fd_set,
	.connection_set		= mod_connection_set,
	.network_get		= mod_network_get,
	.client_find		= mod_client_find,
	.get_name      		= mod_name,
};
