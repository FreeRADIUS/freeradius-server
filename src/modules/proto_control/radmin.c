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
 * @file proto_control/radmin.c
 * @brief Control a running radiusd process.
 *
 * @copyright 2012-2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2012 Alan DeKok (aland@deployingradius.com)
 */
RCSID("$Id$")

#include <assert.h>

#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#ifdef HAVE_LIBREADLINE

# include <stdio.h>

DIAG_OFF(strict-prototypes)
#if defined(HAVE_READLINE_READLINE_H)
#  include <readline/readline.h>
#  define USE_READLINE (1)
#elif defined(HAVE_READLINE_H)
#  include <readline.h>
#  define USE_READLINE (1)
#endif /* !defined(HAVE_READLINE_H) */
DIAG_ON(strict-prototypes)

#ifdef HAVE_READLINE_HISTORY
#  if defined(HAVE_READLINE_HISTORY_H)
#    include <readline/history.h>
#    define USE_READLINE_HISTORY (1)
#  elif defined(HAVE_HISTORY_H)
#    include <history.h>
#    define USE_READLINE_HISTORY (1)
#endif /* defined(HAVE_READLINE_HISTORY_H) */
#endif /* HAVE_READLINE_HISTORY */
#endif /* HAVE_LIBREADLINE */

#define LOG_PREFIX "radmin - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/radmin.h>

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/socket.h>

#ifndef READLINE_MAX_HISTORY_LINES
#	define READLINE_MAX_HISTORY_LINES 1000
#endif

#include "conduit.h"

/*
 *	For configuration file stuff.
 */
static char const *progname = "radmin";
static char const *radmin_version = RADIUSD_VERSION_STRING_BUILD("radmin");

typedef enum {
	RADMIN_CONN_NONE = 0,				//!< Don't know, never connected.
	RADMIN_CONN_UNIX,				//!< Connect via unix socket.
	RADMIN_CONN_TCP					//!< Connect via TCP.
} radmin_conn_type_t;

/** A connection to a server
 *
 */
typedef struct {
	fr_event_list_t		*event_list;		//!< Event list this fd is serviced by.
	int			fd;			//!< Control socket descriptor.

	char			*last_command;		//!< Last command we executed on this connection.
	char			*server;		//!< Path or FQDN of server we're connected to.
	char			*secret;		//!< We use to authenticate ourselves to the server.

	bool			nonblock;		//!< Whether this connection should operate in
							//!< non-blocking mode.
	bool			connected;		//!< Whether this connection is currently connected.
	fr_cs_buffer_t		co;
	radmin_conn_type_t	type;			//!< Type of connection.
} radmin_conn_t;

/** Radmin state
 *
 * Many of the readline functions don't take callbacks, so we need
 * to use a global structure to communicate radmin state.
 */
typedef struct {
	fr_event_list_t		*event_list;		//!< Our main event list.

	radmin_conn_t		*active_conn;		//!< Connection to remote entity.
} radmin_state_t;

/** Main radmin state
 *
 */
//static radmin_state_t state;

static bool echo = false;
static char const *secret = NULL;
static bool unbuffered = false;
static fr_log_t radmin_log = {
	.dst = L_DST_NULL,
	.colourise = false,
	.timestamp = L_TIMESTAMP_ON,
	.fd = -1,
	.file = NULL,
};
static int sockfd = -1;
static char io_buffer[65536];

#ifdef USE_READLINE
#define CMD_MAX_EXPANSIONS (128)
static int radmin_num_expansions = 0;
static char *radmin_expansions[CMD_MAX_EXPANSIONS] = {0};
#endif

#define MAX_STACK (64)
static int stack_depth;
static char cmd_buffer[65536];
static char *stack[MAX_STACK];
static fr_cmd_t *local_cmds = NULL;

static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;
	fprintf(output, "Usage: %s [ args ]\n", progname);
	fprintf(output, "  -d raddb_dir    Configuration files are in \"raddbdir/*\".\n");
	fprintf(output, "  -D <dictdir>    Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(output, "  -e command      Execute 'command' and then exit.\n");
	fprintf(output, "  -E              Echo commands as they are being executed.\n");
	fprintf(output, "  -f socket_file  Open socket_file directly, without reading radius.conf\n");
	fprintf(output, "  -h              Print usage help information.\n");
	fprintf(output, "  -i input_file   Read commands from 'input_file'.\n");
	fprintf(output, "  -l <log_file>   Commands which are executed will be written to this file.\n");
	fprintf(output, "  -n name         Read raddb/name.conf instead of raddb/radiusd.conf\n");
	fprintf(output, "  -q              Reduce output verbosity\n");
	fprintf(output, "  -s <server>     Look in named server for name of control socket.\n");
	fprintf(output, "  -S <secret>     Use argument as shared secret for authentication to the server.\n");
	fprintf(output, "  -x              Increase output verbosity\n");
	exit(status);
}

static int client_socket(char const *server)
{
	int fd;
	uint16_t port;
	fr_ipaddr_t ipaddr;
	char *p, buffer[1024];

	strlcpy(buffer, server, sizeof(buffer));

	p = strchr(buffer, ':');
	if (!p) {
		port = FR_RADMIN_PORT;
	} else {
		port = atoi(p + 1);
		*p = '\0';
	}

	if (fr_inet_hton(&ipaddr, AF_INET, buffer, false) < 0) {
		fprintf(stderr, "%s: Failed looking up host %s: %s\n",
			progname, buffer, fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	fd = fr_socket_client_tcp(NULL, &ipaddr, port, false);
	if (fd < 0) {
		fprintf(stderr, "%s: Failed opening socket %s: %s\n",
			progname, server, fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	return fd;
}

static ssize_t do_challenge(int fd)
{
	ssize_t r;
	fr_conduit_type_t conduit;
	uint8_t challenge[16];

	challenge[0] = 0x00;

	/*
	 *	When connecting over a socket, the server challenges us.
	 */
	r = fr_conduit_read(fd, &conduit, challenge, sizeof(challenge));
	if (r <= 0) return r;

	if ((r != 16) || (conduit != FR_CONDUIT_AUTH_CHALLENGE)) {
		fprintf(stderr, "%s: Failed to read challenge.\n",
			progname);
		exit(EXIT_FAILURE);
	}

	fr_hmac_md5(challenge, (uint8_t const *) secret, strlen(secret),
		    challenge, sizeof(challenge));

	r = fr_conduit_write(fd, FR_CONDUIT_AUTH_RESPONSE, challenge, sizeof(challenge));
	if (r <= 0) return r;

	/*
	 *	If the server doesn't like us, it just closes the
	 *	socket.  So we don't look for an ACK.
	 */

	return r;
}


/*
 *	Returns -1 on failure.  0 on connection failed.  +1 on OK.
 */
static ssize_t flush_conduits(int fd, char *buffer, size_t bufsize)
{
	ssize_t r;
	char *p, *str;
	uint32_t status;
	fr_conduit_type_t conduit;

	while (true) {
		uint32_t notify;

		r = fr_conduit_read(fd, &conduit, buffer, bufsize - 1);
		if (r <= 0) return r;

		buffer[r] = '\0';	/* for C strings */

		switch (conduit) {
		case FR_CONDUIT_STDOUT:
			fprintf(stdout, "%s", buffer);
			break;

		case FR_CONDUIT_STDERR:
			fprintf(stderr, "ERROR: %s", buffer);
			break;

		case FR_CONDUIT_CMD_STATUS:
			if (r < 4) return 1;

			memcpy(&status, buffer, sizeof(status));
			status = ntohl(status);
			return status;

		case FR_CONDUIT_NOTIFY:
			if (r < 4) return -1;

			memcpy(&notify, buffer, sizeof(notify));
			notify = ntohl(notify);

			if (notify == FR_NOTIFY_UNBUFFERED) unbuffered = true;
			if (notify == FR_NOTIFY_BUFFERED) unbuffered = false;

			break;

		case FR_CONDUIT_COMPLETE:
			str = buffer;

			for (p = buffer; p < (buffer + r); p++) {
				if (*p == '\n') {
					size_t len;

					len = p - str;

					radmin_expansions[radmin_num_expansions] = malloc(len + 1);
					memcpy(radmin_expansions[radmin_num_expansions], str, len);
					radmin_expansions[radmin_num_expansions][len] = '\0';
					radmin_num_expansions++;

					str = p + 1;
				}

				if (radmin_num_expansions >= CMD_MAX_EXPANSIONS) break;
			}
			break;

		default:
			fprintf(stderr, "Unexpected response %02x\n", conduit);
			return -1;
		}
	}

	/* never gets here */
}


/*
 *	Returns -1 on failure.  0 on connection failed.  +1 on OK.
 */
static ssize_t run_command(int fd, char const *command,
			   char *buffer, size_t bufsize)
{
	ssize_t r;

	if (echo) {
		fprintf(stdout, "%s\n", command);
	}

	/*
	 *	Write the text to the socket.
	 */
	r = fr_conduit_write(fd, FR_CONDUIT_STDIN, command, strlen(command));
	if (r <= 0) return r;

	return flush_conduits(fd, buffer, bufsize);
}

static int do_connect(int *out, char const *file, char const *server)
{
	int fd;
	ssize_t r;
	fr_conduit_type_t conduit;
	char buffer[65536];

	uint32_t magic;

	/*
	 *	Close stale file descriptors
	 */
	if (*out != -1) {
		close(*out);
		*out = -1;
	}

	if (file) {
		/*
		 *	FIXME: Get destination from command line, if possible?
		 */
		fd = fr_socket_client_unix(file, false);
		if (fd < 0) {
			fr_perror("radmin");
			if (errno == ENOENT) {
					fprintf(stderr, "Perhaps you need to run the commands:");
					fprintf(stderr, "\tcd /etc/raddb\n");
					fprintf(stderr, "\tln -s sites-available/control-socket "
						"sites-enabled/control-socket\n");
					fprintf(stderr, "and then re-start the server?\n");
			}
			return -1;
		}
	} else {
		fd = client_socket(server);
	}

	/*
	 *	Only works for BSD, but Linux allows us
	 *	to mask SIGPIPE, so that's fine.
	 */
#ifdef SO_NOSIGPIPE
	{
		int set = 1;

		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	}
#endif

	/*
	 *	Set up the initial header data.
	 */
	magic = FR_CONDUIT_MAGIC;
	magic = htonl(magic);
	memcpy(buffer, &magic, sizeof(magic));
	memset(buffer + sizeof(magic), 0, sizeof(magic));

	r = fr_conduit_write(fd, FR_CONDUIT_INIT_ACK, buffer, 8);
	if (r <= 0) {
	do_close:
		fprintf(stderr, "%s: Error in socket: %s\n",
			progname, fr_syserror(errno));
		close(fd);
		return -1;
	}

	r = fr_conduit_read(fd, &conduit, buffer + 8, 8);
	if (r <= 0) goto do_close;

	if ((r != 8) || (conduit != FR_CONDUIT_INIT_ACK) ||
	    (memcmp(buffer, buffer + 8, 8) != 0)) {
		fprintf(stderr, "%s: Incompatible versions\n", progname);
		close(fd);
		return -1;
	}

	if (secret) {
		r = do_challenge(fd);
		if (r <= 0) goto do_close;
	}

	*out = fd;

	return 0;
}


static char *readline_buffer[1024];

/*
 *	Wrapper around readline which does the "right thing" depending
 *	on whether we're reading from a file or not.  It also ignores
 *	blank lines and comments, which the main readline() API
 *	doesn't do.
 */
static char *my_readline(char const *prompt, FILE *fp_in, FILE *fp_out)
{
	char *line, *p;

#ifdef USE_READLINE
	if (fp_in == stdin) return readline(prompt);
#endif

	if (prompt && *prompt) puts(prompt);
	fflush(fp_out);

	line = fgets((char *) readline_buffer, sizeof(readline_buffer), fp_in);
	if (!line) return NULL;

	p = strchr(line, '\n');
	if (!p) {
		fprintf(stderr, "Input line too long\n");
		fr_exit_now(EXIT_FAILURE);
	}

	*p = '\0';

	/*
	 *	Strip off leading spaces.
	 */
	for (p = line; *p != '\0'; p++) {
		if ((p[0] == ' ') ||
		    (p[0] == '\t')) {
			line = p + 1;
			continue;
		}

		/*
		 *	Return an empty string.
		 */
		if (p[0] == '#') {
			line[0] = '\0';
			break;
		}

		break;
	}

	/*
	 *	Comments: keep going.
	 */
	if (!line) return line;

	/*
	 *	Strip off CR / LF
	 */
	for (p = line; *p != '\0'; p++) {
		if ((p[0] == '\r') ||
		    (p[0] == '\n')) {
			p[0] = '\0';
			break;
		}
	}

	return line;
}

static void radmin_free(char *line, FILE *fp_in)
{
#ifdef USE_READLINE
	/*
	 *	Was read from stdin, so "line" == "readline_buffer"
	 */
	if (fp_in != stdin) return;
#endif

	free(line);
}

#ifdef USE_READLINE
static ssize_t cmd_copy(char const *cmd)
{
	size_t len;
	char *p = stack[stack_depth];

	if (stack_depth > 0) *(p++) = ' ';

	/*
	 *	No input, allow a trailing space so that tab
	 *	completion works.
	 */
	if (!*cmd) {
		return p - cmd_buffer;
	}

	len = strlcpy(p, cmd, cmd_buffer + sizeof(cmd_buffer) - p);
	if ((p + len) >= (cmd_buffer + sizeof(cmd_buffer))) {
		fprintf(stderr, "Command too long\n");
		return -1;
	}

	/*
	 *	Trash trailing spaces.
	 */
	for (p += len;
	     p > cmd_buffer;
	     p--) {
		if (!isspace((int) p[-1])) break;
		p[-1] = '\0';
	}

	return p - cmd_buffer;
}

static int radmin_help(UNUSED int count, UNUSED int key)
{
	ssize_t len;

	printf("\n");

	len = cmd_copy(rl_line_buffer);
	if (len < 0) return 0;

	/*
	 *	Special-case help for local commands.
	 */
	if ((len >= 5) && strncmp(cmd_buffer, "local", 5) == 0) {
		(void) fr_command_print_help(stdout, local_cmds, cmd_buffer);
		rl_on_new_line();
		return 0;
	}

	if (len > 0) {
		(void) fr_conduit_write(sockfd, FR_CONDUIT_HELP, cmd_buffer, len);
	} else {
		/*
		 *	Don't write zero bytes to the other side...
		 */
		(void) fr_conduit_write(sockfd, FR_CONDUIT_HELP, " ", 1);
	}

	(void) flush_conduits(sockfd, io_buffer, sizeof(io_buffer));

	rl_on_new_line();
	return 0;
}

static char *
radmin_expansion_walk(UNUSED const char *text, int state)
{
    static int current;
    char *name;

    if (!state) {
	    current = 0;
    }

    /*
     *	fr_command_completions() takes care of comparing things to
     *	suppress expansions which don't match "text"
     */
    if (current >= radmin_num_expansions) return NULL;

    name = radmin_expansions[current];

    radmin_expansions[current++] = NULL;

    return name;
}

static char **
radmin_completion(const char *text, int start, UNUSED int end)
{
	ssize_t len;

	rl_attempted_completion_over = 1;

	radmin_num_expansions = 0;

	len = cmd_copy(rl_line_buffer);
	if (len < 0) return NULL;

	/*
	 *	Handle local commands specially.
	 */
	if (strncmp(cmd_buffer, "local", 5) == 0) {
		int num;
		char **expansions = &radmin_expansions[0];
		char const **expansions_const;

		memcpy(&expansions_const, &expansions, sizeof(expansions)); /* const issues */
		num = fr_command_complete(local_cmds, cmd_buffer, start,
					  CMD_MAX_EXPANSIONS, expansions_const);
		if (num <= 0) return NULL;

		radmin_num_expansions = num;
		return rl_completion_matches(text, radmin_expansion_walk);
	}

	start += len;

	if (start > 65535) return NULL;

	io_buffer[0] = (start >> 8) & 0xff;
	io_buffer[1] = start & 0xff;

	/*
	 *	Note that "text" is the PARTIAL thing we're trying to complete.
	 *	And "start" is the OFFSET from rl_line_buffer where we want to
	 *	do the completion.  It's all rather idiotic.
	 */
	memcpy(io_buffer + 2, cmd_buffer, len);

	(void) fr_conduit_write(sockfd, FR_CONDUIT_COMPLETE, io_buffer, len + 2);

	(void) flush_conduits(sockfd, io_buffer, sizeof(io_buffer));

	return rl_completion_matches(text, radmin_expansion_walk);
}

#endif

#ifndef USE_READLINE_HISTORY
#	define add_history(line)
#	define stifle_history(line)
#	define read_history()
#	define write_history(history_file)
#endif

static int check_server(CONF_SECTION *subcs, uid_t uid, gid_t gid, char const **file_p, char const **server_p)
{
	int		rcode;
	char const	*value, *file = NULL;
	CONF_SECTION	*cs;
	CONF_PAIR	*cp;
	char const	*uid_name = NULL;
	char const	*gid_name = NULL;
	char const 	*server;
	struct passwd	*pwd;
	struct group	*grp;

	cp = cf_pair_find(subcs, "namespace");
	if (!cp) return 0;

	value = cf_pair_value(cp);
	if (!value) return 0;

	if (strcmp(value, "control") != 0) return 0;

	server = cf_section_name2(subcs);
	*server_p = server;	/* need this for error messages */

	/*	listen {} */
	cs = cf_section_find(subcs, "listen", NULL);
	if (!cs) {
		fprintf(stderr, "%s: Failed parsing 'listen{}' section in 'server %s {...}'\n", progname, server);
		return -1;
	}

	/*	transport = <transport> */
	cp = cf_pair_find(cs, "transport");
	if (!cp) return 0;

	value = cf_pair_value(cp);
	if (!value) return 0;

	/*	<transport> { ... } */
	subcs = cf_section_find(cs, value, NULL);
	if (!subcs) {
		fprintf(stderr, "%s: Failed parsing the '%s {}' section in 'server %s {...}'\n",
			progname, cf_section_name1(subcs), server);
		return -1;
	}

	/*
	 *	Now find the socket name (sigh)
	 */
	rcode = cf_pair_parse(NULL, subcs, "filename",
			      FR_ITEM_POINTER(FR_TYPE_STRING, &file), NULL, T_DOUBLE_QUOTED_STRING);
	if (rcode < 0) {
		fprintf(stderr, "%s: Failed parsing listen section 'socket'\n", progname);
		return -1;
	}

	if (!file) {
		fprintf(stderr, "%s: No path given for socket\n", progname);
		return -1;
	}

	*file_p = file;

	/*
	 *	If we're root, just use the first one we find
	 */
	if (uid == 0) return 1;

	/*
	 *	Check UID and GID.
	 */
	rcode = cf_pair_parse(NULL, subcs, "uid",
			      FR_ITEM_POINTER(FR_TYPE_STRING, &uid_name), NULL, T_DOUBLE_QUOTED_STRING);
	if (rcode < 0) {
		fprintf(stderr, "%s: Failed parsing listen section 'uid'\n", progname);
		return -1;
	}

	if (!uid_name || !*uid_name) return 1;

	pwd = getpwnam(uid_name);
	if (!pwd) {
		fprintf(stderr, "%s: Failed getting UID for user %s: %s\n", progname, uid_name,
			fr_syserror(errno));
		return -1;
	}

	if (uid != pwd->pw_uid) return 0;

	rcode = cf_pair_parse(NULL, subcs, "gid",
			      FR_ITEM_POINTER(FR_TYPE_STRING, &gid_name), NULL, T_DOUBLE_QUOTED_STRING);
	if (rcode < 0) {
		fprintf(stderr, "%s: Failed parsing listen section 'gid'\n", progname);
		return -1;
	}

	if (!gid_name || !*gid_name) return 1;

	grp = getgrnam(gid_name);
	if (!grp) {
		fprintf(stderr, "%s: Failed resolving gid of group %s: %s\n",
			progname, gid_name, fr_syserror(errno));
		return -1;
	}

	if (gid != grp->gr_gid) return 0;

	return 1;
}

static int cmd_test(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	fprintf(fp, "We're testing stuff!\n");

	return 0;
}

/*
 *	Local radmin commands
 */
static fr_cmd_table_t cmd_table[] = {
	{
		.parent = "local",
		.name = "test",
		.func = cmd_test,
		.help = "Test stuff",
		.read_only = true
	},

	CMD_TABLE_END
};

static fr_cmd_info_t local_info;

static int local_command(char *line)
{
	int argc, rcode;

	argc = fr_command_str_to_argv(local_cmds, &local_info, line);
	if (argc < 0) {
		fprintf(stderr, "Failed parsing local command: %s\n", fr_strerror());
		return -1;
	}

	if (!local_info.runnable) {
		return 0;
	}

	rcode = fr_command_run(stderr, stdout, &local_info, false);
	fflush(stdout);
	fflush(stderr);

	/*
	 *	reset "info" to be a top-level context again.
	 */
	(void) fr_command_clear(0, &local_info);

	if (rcode < 0) return rcode;

	return 1;

}


#define MAX_COMMANDS (4)

int main(int argc, char **argv)
{
	int		c;
	bool		quiet = false;
	char		*line = NULL;
	ssize_t		result;
	char const	*file = NULL;
	char const	*name = "radiusd";
	char const	*input_file = NULL;
	FILE		*inputfp = stdin;
	char const	*server = NULL;
	fr_dict_t	*dict = NULL;

	char const	*raddb_dir = RADIUS_DIR;
	char const	*dict_dir = DICTDIR;
	char 		history_file[PATH_MAX];

	TALLOC_CTX	*autofree = talloc_autofree_context();

	char *commands[MAX_COMMANDS];
	int num_commands = -1;

	int exit_status = EXIT_SUCCESS;

	char const *prompt = "radmin> ";
	char prompt_buffer[1024];

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radmin");
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	if ((progname = strrchr(argv[0], FR_DIR_SEP)) == NULL) {
		progname = argv[0];
	} else {
		progname++;
	}

	fr_debug_lvl = L_DBG_LVL_1;

	while ((c = getopt(argc, argv, "d:D:hi:e:Ef:n:qs:S:x")) != -1) switch (c) {
		case 'd':
			if (file) {
				fprintf(stderr, "%s: -d and -f cannot be used together.\n", progname);
				exit(EXIT_FAILURE);
			}
			raddb_dir = optarg;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'e':
			num_commands++; /* starts at -1 */
			if (num_commands >= MAX_COMMANDS) {
				fprintf(stderr, "%s: Too many '-e'\n", progname);
				exit(EXIT_FAILURE);
			}

			commands[num_commands] = optarg;
			break;

		case 'E':
			echo = true;
			break;

		case 'f':
			raddb_dir = NULL;
			file = optarg;
			break;

		default:
		case 'h':
			usage(0);	/* never returns */

		case 'i':
			/*
			 *	optarg check is to quiet clang scan
			 */
			if (optarg && (strcmp(optarg, "-") != 0)) input_file = optarg;
			quiet = true;
			break;

		case 'l':
			radmin_log.file = optarg;
			break;

		case 'n':
			name = optarg;
			break;

		case 'q':
			quiet = true;
			if (fr_debug_lvl > 0) fr_debug_lvl--;
			break;

		case 's':
			if (file) {
				fprintf(stderr, "%s: -s and -f cannot be used together.\n", progname);
				usage(1);
			}
			server = optarg;
			break;

		case 'S':
			secret = optarg;
			break;

		case 'x':
			fr_debug_lvl++;
			break;
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radmin");
		exit(EXIT_FAILURE);
	}

	if (raddb_dir) {
		int		rcode;
		uid_t		uid;
		gid_t		gid;
		CONF_SECTION	*cs, *subcs;
		CONF_PAIR 	*cp;

		file = NULL;	/* MUST read it from the conf_file now */

		snprintf(io_buffer, sizeof(io_buffer), "%s/%s.conf", raddb_dir, name);

		/*
		 *	Need to read in the dictionaries, else we may get
		 *	validation errors when we try and parse the config.
		 */
		if (fr_dict_global_init(autofree, dict_dir) < 0) {
			fr_perror("radmin");
			exit(64);
		}

		if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR) < 0) {
			fr_perror("radmin");
			exit(64);
		}

		if (fr_dict_read(dict, raddb_dir, FR_DICTIONARY_FILE) == -1) {
			fr_perror("radmin");
			exit(64);
		}

		cs = cf_section_alloc(autofree, NULL, "main", NULL);
		if (!cs) exit(EXIT_FAILURE);

		if ((cf_file_read(cs, io_buffer) < 0) || (cf_section_pass2(cs) < 0)) {
			fprintf(stderr, "%s: Errors reading or parsing %s\n", progname, io_buffer);
		error:
			exit(EXIT_FAILURE);
		}

		uid = getuid();
		gid = getgid();

		/*
		 *	We are looking for: server whatever { namespace="control" ...	}
		 */
		if (server) {
			subcs = cf_section_find(cs, "server", server);
			if (subcs) {
				fprintf(stderr, "%s: Could not find virtual server %s {}\n", progname, server);
				goto error;
			}

			rcode = check_server(subcs, uid, gid, &file, &server);
			if (rcode < 0) goto error;
			if (rcode == 0) file = NULL;

		} else {
			for (subcs = cf_section_find_next(cs, NULL, "server", CF_IDENT_ANY);
			     subcs != NULL;
			     subcs = cf_section_find_next(cs, subcs, "server", CF_IDENT_ANY)) {
				rcode = check_server(subcs, uid, gid, &file, &server);
				if (rcode < 0) goto error;
				if (rcode == 1) break;
			}
		}

		if (!file) {
			fprintf(stderr, "%s: Could not find control socket in %s (server %s {})\n", progname, io_buffer, server);
			goto error;
		}

		/*
		 *	Log the commands we've run.
		 */
		if (!radmin_log.file) {
			subcs = cf_section_find(cs, "log", NULL);
			if (subcs) {
				cp = cf_pair_find(subcs, "radmin");
				if (cp) {
					radmin_log.file = cf_pair_value(cp);

					if (!radmin_log.file) {
						fprintf(stderr, "%s: Invalid value for 'radmin' log destination", progname);
						goto error;
					}
				}
			}
		}

		if (radmin_log.file) {
			radmin_log.fd = open(radmin_log.file, O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
			if (radmin_log.fd < 0) {
				fprintf(stderr, "%s: Failed opening %s: %s\n", progname, radmin_log.file, fr_syserror(errno));
				goto error;
			}

			radmin_log.dst = L_DST_FILES;
		}
	}

	if (input_file) {
		inputfp = fopen(input_file, "r");
		if (!inputfp) {
			fprintf(stderr, "%s: Failed opening %s: %s\n", progname, input_file, fr_syserror(errno));
			goto error;
		}
	}

	if (!file) {
		fprintf(stderr, "%s: Failed to find socket file name\n",
			progname);
		goto error;
	}

	/*
	 *	Check if stdin is a TTY only if input is from stdin
	 */
	if (input_file || !isatty(STDIN_FILENO)) quiet = true;

	if (!quiet) {
#ifdef USE_READLINE_HISTORY
		using_history();
		stifle_history(READLINE_MAX_HISTORY_LINES);
		snprintf(history_file, sizeof(history_file), "%s/%s", getenv("HOME"), ".radmin_history");
		read_history(history_file);
#endif
#ifdef USE_READLINE
		rl_attempted_completion_function = radmin_completion;
#endif
	} else {
		prompt = NULL;
	}

	/*
	 *	Prevent SIGPIPEs from terminating the process
	 */
	signal(SIGPIPE, SIG_IGN);

	if (do_connect(&sockfd, file, server) < 0) exit(EXIT_FAILURE);

	/*
	 *	Register local commands.
	 */
	if (fr_command_add_multi(autofree, &local_cmds, NULL, NULL, cmd_table) < 0) {
		fprintf(stderr, "%s: Failed registering local commands: %s\n",
			progname, fr_strerror());
		goto error;
	}

	fr_command_info_init(autofree, &local_info);

	/*
	 *	Run commands from the command-line.
	 */
	if (num_commands >= 0) {
		int i;

		for (i = 0; i <= num_commands; i++) {
			result = run_command(sockfd, commands[i], io_buffer, sizeof(io_buffer));
			if (result < 0) exit(EXIT_FAILURE);

			if (result == FR_CONDUIT_FAIL) {
				exit_status = EXIT_FAILURE;
				goto exit;
			}
		}

		if (unbuffered) {
			while (true) flush_conduits(sockfd, io_buffer, sizeof(io_buffer));
		}

		/*
		 *	We're done all of the commands, exit now.
		 */
		goto exit;
	}

	if (!quiet) {
		printf("%s - FreeRADIUS Server administration tool.\n", radmin_version);
		printf("Copyright 2008-2019 The FreeRADIUS server project and contributors.\n");
		printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
		printf("PARTICULAR PURPOSE.\n");
		printf("You may redistribute copies of FreeRADIUS under the terms of the\n");
		printf("GNU General Public License v2.\n");
	}

	/*
	 *	FIXME: Do login?
	 */

#ifdef USE_READLINE
	(void) rl_bind_key('?', radmin_help);
#endif

	stack_depth = 0;
	stack[0] = cmd_buffer;

	while (1) {
		int retries;
		ssize_t len;

		line = my_readline(prompt, inputfp, stdout);

		if (!line) break;

		if (!*line) goto next;

		/*
		 *	Radmin supports a number of commands which are
		 *	valid in any context.
		 */
		if (strcmp(line, "reconnect") == 0) {
			if (do_connect(&sockfd, file, server) < 0) exit(EXIT_FAILURE);
			goto next;
		}

		if (!secret && !stack_depth && (strncmp(line, "secret ", 7) == 0)) {
			secret = line + 7;
			do_challenge(sockfd);
			goto next;
		}

		/*
		 *	Quit the program
		 */
		if (strcmp(line, "quit") == 0) {
			break;
		}

		/*
		 *	Exit the current context.
		 */
		if (strcmp(line, "exit") == 0) {
			if (!stack_depth) break;

			stack_depth--;
			*stack[stack_depth] = '\0';

			if (stack_depth == 0) {
				prompt = "radmin> ";
			} else {
				snprintf(prompt_buffer, sizeof(prompt_buffer), "... %s> ",
					 stack[stack_depth - 1]);
				prompt = prompt_buffer;
			}

			goto next;
		}

		/*
		 *	Radmin also supports local commands which
		 *	modifies it's behavior.  These commands MUST
		 */
		if (!stack_depth && (strncmp(line, "local", 5) == 0)) {
			if (!isspace((int) line[5])) {
				fprintf(stderr, "'local' commands MUST be specified all on one line");
				goto next;
			}

			/*
			 *	Parse and run the local command.
			 */
			local_command(line);
			goto next;
		}

		/*
		 *	Any other input is sent to the server.
		 */
		retries = 0;

		/*
		 *	If required, log commands to a radmin log file.
		 */
		if (radmin_log.dst == L_DST_FILES) {
			fr_log(&radmin_log, L_INFO, __FILE__, __LINE__, "%s", line);
		}

		len = cmd_copy(line);
		if (len < 0) {
			exit_status = EXIT_FAILURE;
			break;
		}

	retry:

		result = run_command(sockfd, cmd_buffer, io_buffer, sizeof(io_buffer));
		if (result < 0) {
			if (!quiet) fprintf(stderr, "... reconnecting ...\n");

			if (do_connect(&sockfd, file, server) < 0) {
				exit(EXIT_FAILURE);
			}

			retries++;
			if (retries < 2) goto retry;

			fprintf(stderr, "Failed to connect to server\n");
			exit(EXIT_FAILURE);

		} else if (result == FR_CONDUIT_FAIL) {
			fprintf(stderr, "Failed running command\n");
			exit_status = EXIT_FAILURE;

		} else if (result == FR_CONDUIT_PARTIAL) {
			char *p = stack[stack_depth];

			if (stack_depth >= MAX_STACK) {
				fprintf(stderr, "Too many sub-contexts running command\n");
				exit_status = EXIT_FAILURE;
				break;
			}

			/*
			 *	Point the stack to the last entry.
			 */
			p += strlen(p);
			stack_depth++;
			stack[stack_depth] = p;

			snprintf(prompt_buffer, sizeof(prompt_buffer), "... %s> ",
				 stack[stack_depth - 1]);
			prompt = prompt_buffer;

		} else {
			/*
			 *	Add only successful commands to the history.
			 *
			 *	Don't add exit / quit / secret / etc.
			 */
			if (!quiet) {
				add_history(cmd_buffer);
				write_history(history_file);
			}
		}

		/*
		 *	SUCCESS and PARTIAL end up here too.
		 */
	next:
		radmin_free(line, inputfp);
	}

exit:
	if (inputfp != stdin) fclose(inputfp);

	if (radmin_log.dst == L_DST_FILES) close(radmin_log.fd);

	if (sockfd >= 0) close(sockfd);

	if (!quiet) fprintf(stdout, "\n");

	return exit_status;
}
