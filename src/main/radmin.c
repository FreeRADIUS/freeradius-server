/*
 * radmin.c	RADIUS Administration tool.
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
 * Copyright 2012   The FreeRADIUS server project
 * Copyright 2012   Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/channel.h>

#include <pwd.h>
#include <grp.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#ifdef HAVE_LIBREADLINE

# include <stdio.h>
#if defined(HAVE_READLINE_READLINE_H)
#  include <readline/readline.h>
#  define USE_READLINE (1)
#elif defined(HAVE_READLINE_H)
#  include <readline.h>
#  define USE_READLINE (1)
#endif /* !defined(HAVE_READLINE_H) */

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

/*
 *	For configuration file stuff.
 */
static char const *progname = "radmin";
static char const *radmin_version = "radmin version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
#ifndef ENABLE_REPRODUCIBLE_BUILDS
", built on " __DATE__ " at " __TIME__
#endif
;


/*
 *	The rest of this is because the conffile.c, etc. assume
 *	they're running inside of the server.  And we don't (yet)
 *	have a "libfreeradius-server", or "libfreeradius-util".
 */
main_config_t main_config;

static bool echo = false;
static char const *secret = "testing123";

#include <sys/wait.h>

#ifdef HAVE_PTHREAD_H
pid_t rad_fork(void)
{
	return fork();
}
pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}
#endif

static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;
	fprintf(output, "Usage: %s [ args ]\n", progname);
	fprintf(output, "  -d raddb_dir    Configuration files are in \"raddbdir/*\".\n");
	fprintf(stderr, "  -D <dictdir>    Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(output, "  -e command      Execute 'command' and then exit.\n");
	fprintf(output, "  -E              Echo commands as they are being executed.\n");
	fprintf(output, "  -f socket_file  Open socket_file directly, without reading radius.conf\n");
	fprintf(output, "  -h              Print usage help information.\n");
	fprintf(output, "  -i input_file   Read commands from 'input_file'.\n");
	fprintf(output, "  -n name         Read raddb/name.conf instead of raddb/radiusd.conf\n");
	fprintf(output, "  -q              Quiet mode.\n");

	exit(status);
}

static int client_socket(char const *server)
{
	int sockfd;
	uint16_t port;
	fr_ipaddr_t ipaddr;
	char *p, buffer[1024];

	strlcpy(buffer, server, sizeof(buffer));

	p = strchr(buffer, ':');
	if (!p) {
		port = PW_RADMIN_PORT;
	} else {
		port = atoi(p + 1);
		*p = '\0';
	}

	if (ip_hton(&ipaddr, AF_INET, buffer, false) < 0) {
		fprintf(stderr, "%s: Failed looking up host %s: %s\n",
			progname, buffer, fr_syserror(errno));
		exit(1);
	}

	sockfd = fr_socket_client_tcp(NULL, &ipaddr, port, false);
	if (sockfd < 0) {
		fprintf(stderr, "%s: Failed opening socket %s: %s\n",
			progname, server, fr_syserror(errno));
		exit(1);
	}

	return sockfd;
}

static ssize_t do_challenge(int sockfd)
{
	ssize_t r;
	fr_channel_type_t channel;
	uint8_t challenge[16];

	challenge[0] = 0;

	/*
	 *	When connecting over a socket, the server challenges us.
	 */
	r = fr_channel_read(sockfd, &channel, challenge, sizeof(challenge));
	if (r <= 0) return r;

	if ((r != 16) || (channel != FR_CHANNEL_AUTH_CHALLENGE)) {
		fprintf(stderr, "%s: Failed to read challenge.\n",
			progname);
		exit(1);
	}

	fr_hmac_md5(challenge, (uint8_t const *) secret, strlen(secret),
		    challenge, sizeof(challenge));

	r = fr_channel_write(sockfd, FR_CHANNEL_AUTH_RESPONSE, challenge, sizeof(challenge));
	if (r <= 0) return r;

	/*
	 *	If the server doesn't like us, he just closes the
	 *	socket.  So we don't look for an ACK.
	 */

	return r;
}


/*
 *	Returns -1 on error.  0 on connection failed.  +1 on OK.
 */
static ssize_t run_command(int sockfd, char const *command,
			   char *buffer, size_t bufsize)
{
	ssize_t r;
	uint32_t status;
	fr_channel_type_t channel;

	if (echo) {
		fprintf(stdout, "%s\n", command);
	}

	/*
	 *	Write the text to the socket.
	 */
	r = fr_channel_write(sockfd, FR_CHANNEL_STDIN, command, strlen(command));
	if (r <= 0) return r;

	while (true) {
		r = fr_channel_read(sockfd, &channel, buffer, bufsize - 1);
		if (r <= 0) return r;

		buffer[r] = '\0';	/* for C strings */

		switch (channel) {
		case FR_CHANNEL_STDOUT:
			fprintf(stdout, "%s", buffer);
			break;

		case FR_CHANNEL_STDERR:
			fprintf(stderr, "ERROR: %s", buffer);
			break;

		case FR_CHANNEL_CMD_STATUS:
			if (r < 4) return 1;

			memcpy(&status, buffer, sizeof(status));
			status = ntohl(status);
			return status;

		default:
			fprintf(stderr, "Unexpected response\n");
			return -1;
		}
	}

	/* never gets here */
}

static int do_connect(int *out, char const *file, char const *server)
{
	int sockfd;
	ssize_t r;
	fr_channel_type_t channel;
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
		sockfd = fr_socket_client_unix(file, false);
		if (sockfd < 0) {
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
		sockfd = client_socket(server);
	}

	/*
	 *	Only works for BSD, but Linux allows us
	 *	to mask SIGPIPE, so that's fine.
	 */
#ifdef SO_NOSIGPIPE
	{
		int set = 1;

		setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	}
#endif

	/*
	 *	Set up the initial header data.
	 */
	magic = 0xf7eead16;
	magic = htonl(magic);
	memcpy(buffer, &magic, sizeof(magic));
	memset(buffer + sizeof(magic), 0, sizeof(magic));

	r = fr_channel_write(sockfd, FR_CHANNEL_INIT_ACK, buffer, 8);
	if (r <= 0) {
	do_close:
		fprintf(stderr, "%s: Error in socket: %s\n",
			progname, fr_syserror(errno));
		close(sockfd);
			return -1;
	}

	r = fr_channel_read(sockfd, &channel, buffer + 8, 8);
	if (r <= 0) goto do_close;

	if ((r != 8) || (channel != FR_CHANNEL_INIT_ACK) ||
	    (memcmp(buffer, buffer + 8, 8) != 0)) {
		fprintf(stderr, "%s: Incompatible versions\n", progname);
		close(sockfd);
		return -1;
	}

	if (server && secret) {
		r = do_challenge(sockfd);
		if (r <= 0) goto do_close;
	}

	*out = sockfd;

	return 0;
}

#define MAX_COMMANDS (4)

int main(int argc, char **argv)
{
	int		argval;
	bool		quiet = false;
	int		sockfd = -1;
	char		*line = NULL;
	ssize_t		len;
	char const	*file = NULL;
	char const	*name = "radiusd";
	char		*p, buffer[65536];
	char const	*input_file = NULL;
	FILE		*inputfp = stdin;
	char const	*server = NULL;

	char const	*radius_dir = RADIUS_DIR;
	char const	*dict_dir = DICTDIR;

	char *commands[MAX_COMMANDS];
	int num_commands = -1;

	int exit_status = EXIT_SUCCESS;

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
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

	while ((argval = getopt(argc, argv, "d:D:hi:e:Ef:n:qs:S")) != EOF) {
		switch (argval) {
		case 'd':
			if (file) {
				fprintf(stderr, "%s: -d and -f cannot be used together.\n", progname);
				exit(1);
			}
			if (server) {
				fprintf(stderr, "%s: -d and -s cannot be used together.\n", progname);
				exit(1);
			}
			radius_dir = optarg;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'e':
			num_commands++; /* starts at -1 */
			if (num_commands >= MAX_COMMANDS) {
				fprintf(stderr, "%s: Too many '-e'\n",
					progname);
				exit(1);
			}

			commands[num_commands] = optarg;
			break;

		case 'E':
			echo = true;
			break;

		case 'f':
			radius_dir = NULL;
			file = optarg;
			break;

		default:
		case 'h':
			usage(0);	/* never returns */

		case 'i':
			if (strcmp(optarg, "-") != 0) {
				input_file = optarg;
			}
			quiet = true;
			break;

		case 'n':
			name = optarg;
			break;

		case 'q':
			quiet = true;
			break;

		case 's':
			if (file) {
				fprintf(stderr, "%s: -s and -f cannot be used together.\n", progname);
				usage(1);
			}
			radius_dir = NULL;
			server = optarg;
			break;

		case 'S':
			secret = NULL;
			break;
		}
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radmin");
		exit(1);
	}

	if (radius_dir) {
		int rcode;
		CONF_SECTION *cs, *subcs;
		uid_t		uid;
		gid_t		gid;
		char const	*uid_name = NULL;
		char const	*gid_name = NULL;
		struct passwd	*pwd;
		struct group	*grp;

		file = NULL;	/* MUST read it from the conffile now */

		snprintf(buffer, sizeof(buffer), "%s/%s.conf", radius_dir, name);

		/*
		 *	Need to read in the dictionaries, else we may get
		 *	validation errors when we try and parse the config.
		 */
		if (dict_init(dict_dir, RADIUS_DICTIONARY) < 0) {
			fr_perror("radmin");
			exit(64);
		}

		if (dict_read(radius_dir, RADIUS_DICTIONARY) == -1) {
			fr_perror("radmin");
			exit(64);
		}

		cs = cf_section_alloc(NULL, "main", NULL);
		if (!cs) exit(1);

		if (cf_file_read(cs, buffer) < 0) {
			fprintf(stderr, "%s: Errors reading or parsing %s\n", progname, buffer);
			talloc_free(cs);
			usage(1);
		}

		uid = getuid();
		gid = getgid();

		subcs = NULL;
		while ((subcs = cf_subsection_find_next(cs, subcs, "listen")) != NULL) {
			char const *value;
			CONF_PAIR *cp = cf_pair_find(subcs, "type");

			if (!cp) continue;

			value = cf_pair_value(cp);
			if (!value) continue;

			if (strcmp(value, "control") != 0) continue;

			/*
			 *	Now find the socket name (sigh)
			 */
			rcode = cf_item_parse(subcs, "socket", FR_ITEM_POINTER(PW_TYPE_STRING, &file), NULL);
			if (rcode < 0) {
				fprintf(stderr, "%s: Failed parsing listen section 'socket'\n", progname);
				exit(1);
			}

			if (!file) {
				fprintf(stderr, "%s: No path given for socket\n", progname);
				usage(1);
			}

			/*
			 *	If we're root, just use the first one we find
			 */
			if (uid == 0) break;

			/*
			 *	Check UID and GID.
			 */
			rcode = cf_item_parse(subcs, "uid", FR_ITEM_POINTER(PW_TYPE_STRING, &uid_name), NULL);
			if (rcode < 0) {
				fprintf(stderr, "%s: Failed parsing listen section 'uid'\n", progname);
				exit(1);
			}

			if (!uid_name) break;

			pwd = getpwnam(uid_name);
			if (!pwd) {
				fprintf(stderr, "%s: Failed getting UID for user %s: %s\n", progname, uid_name, strerror(errno));
				exit(1);
			}

			if (uid != pwd->pw_uid) continue;

			rcode = cf_item_parse(subcs, "gid", FR_ITEM_POINTER(PW_TYPE_STRING, &gid_name), NULL);
			if (rcode < 0) {
				fprintf(stderr, "%s: Failed parsing listen section 'gid'\n", progname);
				exit(1);
			}

			if (!gid_name) break;

			grp = getgrnam(gid_name);
			if (!grp) {
				fprintf(stderr, "%s: Failed getting GID for group %s: %s\n", progname, gid_name, strerror(errno));
				exit(1);
			}

			if (gid != grp->gr_gid) continue;

			break;
		}

		if (!file) {
			fprintf(stderr, "%s: Could not find control socket in %s\n", progname, buffer);
			exit(1);
		}
	}

	if (input_file) {
		inputfp = fopen(input_file, "r");
		if (!inputfp) {
			fprintf(stderr, "%s: Failed opening %s: %s\n", progname, input_file, fr_syserror(errno));
			exit(1);
		}
	}

	if (!file && !server) {
		fprintf(stderr, "%s: Must use one of '-d' or '-f' or '-s'\n",
			progname);
		exit(1);
	}

	/*
	 *	Check if stdin is a TTY only if input is from stdin
	 */
	if (input_file && !quiet && !isatty(STDIN_FILENO)) quiet = true;

#ifdef USE_READLINE
	if (!quiet) {
#ifdef USE_READLINE_HISTORY
		using_history();
#endif
		rl_bind_key('\t', rl_insert);
	}
#endif

	/*
	 *	Prevent SIGPIPEs from terminating the process
	 */
	signal(SIGPIPE, SIG_IGN);

	if (do_connect(&sockfd, file, server) < 0) exit(1);

	/*
	 *	Run one command.
	 */
	if (num_commands >= 0) {
		int i;

		for (i = 0; i <= num_commands; i++) {
			len = run_command(sockfd, commands[i], buffer, sizeof(buffer));
			if (len < 0) exit(1);

			if (len == FR_CHANNEL_FAIL) exit_status = EXIT_FAILURE;
		}
		exit(exit_status);
	}

	if (!quiet) {
		printf("%s - FreeRADIUS Server administration tool.\n", radmin_version);
		printf("Copyright (C) 2008-2017 The FreeRADIUS server project and contributors.\n");
		printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
		printf("PARTICULAR PURPOSE.\n");
		printf("You may redistribute copies of FreeRADIUS under the terms of the\n");
		printf("GNU General Public License v2.\n");
	}

	/*
	 *	FIXME: Do login?
	 */

	while (1) {
		int retries;

#ifndef USE_READLINE
		if (!quiet) {
			printf("radmin> ");
			fflush(stdout);
		}
#else
		if (!quiet) {
			line = readline("radmin> ");

			if (!line) break;

			if (!*line) {
				free(line);
				continue;
			}

#ifdef USE_READLINE_HISTORY
			add_history(line);
#endif
		} else		/* quiet, or no readline */
#endif
		{
			line = fgets(buffer, sizeof(buffer), inputfp);
			if (!line) break;

			p = strchr(buffer, '\n');
			if (!p) {
				fprintf(stderr, "%s: Input line too long\n",
					progname);
				exit(1);
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

				if (p[0] == '#') {
					line = NULL;
					break;
				}

				break;
			}

			/*
			 *	Comments: keep going.
			 */
			if (!line) continue;

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
		}

		if (strcmp(line, "reconnect") == 0) {
			if (do_connect(&sockfd, file, server) < 0) exit(1);
			line = NULL;
			continue;
		}

		if (memcmp(line, "secret ", 7) == 0) {
			if (!secret) {
				secret = line + 7;
				do_challenge(sockfd);
			}
			line = NULL;
			continue;
		}

		/*
		 *	Exit, done, etc.
		 */
		if ((strcmp(line, "exit") == 0) ||
		    (strcmp(line, "quit") == 0)) {
			break;
		}

		if (server && !secret) {
			fprintf(stderr, "ERROR: You must enter 'secret <SECRET>' before running any commands\n");
			line = NULL;
			continue;
		}

		retries = 0;
	retry:
		len = run_command(sockfd, line, buffer, sizeof(buffer));
		if (len < 0) {
			if (!quiet) fprintf(stderr, "... reconnecting ...\n");

			if (do_connect(&sockfd, file, server) < 0) {
				exit(1);
			}

			retries++;
			if (retries < 2) goto retry;

			fprintf(stderr, "Failed to connect to server\n");
			exit(1);

		} else if (len == FR_CHANNEL_SUCCESS) {
			break;

		} else if (len == FR_CHANNEL_FAIL) {
			exit_status = EXIT_FAILURE;
		}
	}

	fprintf(stdout, "\n");

	if (inputfp != stdin) fclose(inputfp);

	return exit_status;
}

