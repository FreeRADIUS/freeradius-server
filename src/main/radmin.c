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
 * Copyright 2008   The FreeRADIUS server project
 * Copyright 2008   Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radpaths.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_LIBREADLINE

#if defined(HAVE_READLINE_READLINE_H)
#include <readline/readline.h>
#define USE_READLINE (1)
#elif defined(HAVE_READLINE_H)
#include <readline.h>
#define USE_READLINE (1)
#endif /* !defined(HAVE_READLINE_H) */

#endif /* HAVE_LIBREADLINE */

#ifdef HAVE_READLINE_HISTORY
#if defined(HAVE_READLINE_HISTORY_H)
#include <readline/history.h>
#define USE_READLINE_HISTORY (1)
#elif defined(HAVE_HISTORY_H)
#include <history.h>
#define USE_READLINE_HISTORY (1)
#endif /* defined(HAVE_READLINE_HISTORY_H) */

#endif /* HAVE_READLINE_HISTORY */

/*
 *	For configuration file stuff.
 */
const char *radius_dir = RADDBDIR;
const char *progname = "radmin";

/*
 *	The rest of this is because the conffile.c, etc. assume
 *	they're running inside of the server.  And we don't (yet)
 *	have a "libfreeradius-server", or "libfreeradius-util".
 */
int debug_flag = 0;
struct main_config_t mainconfig;
char *request_log_file = NULL;
char *debug_log_file = NULL;
int radius_xlat(UNUSED char *out, UNUSED int outlen, UNUSED const char *fmt,
		UNUSED REQUEST *request, UNUSED RADIUS_ESCAPE_STRING func)
{
	return -1;
}

static FILE *outputfp = NULL;
static int echo = FALSE;

static int fr_domain_socket(const char *path)
{
	int sockfd = -1;
#ifdef HAVE_SYS_UN_H
	size_t len;
	socklen_t socklen;
        struct sockaddr_un saremote;

	len = strlen(path);
	if (len >= sizeof(saremote.sun_path)) {
		fprintf(stderr, "%s: Path too long in filename\n", progname);
		return -1;
	}

        if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "%s: Failed creating socket: %s\n",
			progname, strerror(errno));
		return -1;
        }

        saremote.sun_family = AF_UNIX;
	memcpy(saremote.sun_path, path, len + 1); /* SUN_LEN does strlen */
	
	socklen = SUN_LEN(&saremote);

        if (connect(sockfd, (struct sockaddr *)&saremote, socklen) < 0) {
		struct stat buf;

		close(sockfd);
		fprintf(stderr, "%s: Failed connecting to %s: %s\n",
			progname, path, strerror(errno));

		/*
		 *	The file doesn't exist.  Tell the user how to
		 *	fix it.
		 */
		if ((stat(path, &buf) < 0) &&
		    (errno == ENOENT)) {
			fprintf(stderr, "  Perhaps you need to run the commands:\n\tcd /etc/raddb\n\tln -s sites-available/control-socket sites-enabled/control-socket\n  and then re-start the server?\n");
		}

		return -1;
        }

#ifdef O_NONBLOCK
	{
		int flags;
		
		if ((flags = fcntl(sockfd, F_GETFL, NULL)) < 0)  {
			fprintf(stderr, "%s: Failure getting socket flags: %s",
				progname, strerror(errno));
			close(sockfd);
			return -1;
		}
		
		flags |= O_NONBLOCK;
		if( fcntl(sockfd, F_SETFL, flags) < 0) {
			fprintf(stderr, "%s: Failure setting socket flags: %s",
				progname, strerror(errno));
			close(sockfd);
			return -1;
		}
	}
#endif
#endif
	return sockfd;
}

static int usage(void)
{
	printf("Usage: %s [ args ]\n", progname);
	printf("  -d raddb_dir    Configuration files are in \"raddbdir/*\".\n");
	printf("  -e command      Execute 'command' and then exit.\n");
	printf("  -E              Echo commands as they are being executed.\n");
	printf("  -f socket_file  Open socket_file directly, without reading radius.conf\n");
	printf("  -h              Print usage help information.\n");
	printf("  -i input_file   Read commands from 'input_file'.\n");
	printf("  -n name         Read raddb/name.conf instead of raddb/radiusd.conf\n");
	printf("  -o output_file  Write commands to 'output_file'.\n");
	printf("  -q              Quiet mode.\n");

	exit(1);
}

static ssize_t run_command(int sockfd, const char *command,
			   char *buffer, size_t bufsize)
{
	char *p;
	ssize_t size, len;

	if (echo) {
		fprintf(outputfp, "%s\n", command);
	}

	/*
	 *	Write the text to the socket.
	 */
	if (write(sockfd, command, strlen(command)) < 0) return -1;
	if (write(sockfd, "\r\n", 2) < 0) return -1;

	/*
	 *	Read the response
	 */
	size = 0;
	buffer[0] = '\0';

	memset(buffer, 0, bufsize);

	while (1) {
		int rcode;
		fd_set readfds;

		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

		rcode = select(sockfd + 1, &readfds, NULL, NULL, NULL);
		if (rcode < 0) {
			if (errno == EINTR) continue;

			fprintf(stderr, "%s: Failed selecting: %s\n",
				progname, strerror(errno));
			exit(1);
		}

		if (rcode == 0) {
			fprintf(stderr, "%s: Server closed the connection.\n",
				progname);
			exit(1);
		}

#ifdef MSG_DONTWAIT
		len = recv(sockfd, buffer + size,
			   bufsize - size - 1, MSG_DONTWAIT);
#else
		/*
		 *	Read one byte at a time (ugh)
		 */
		len = recv(sockfd, buffer + size, 1, 0);
#endif
		if (len < 0) {
			/*
			 *	No data: keep looping
			 */
			if ((errno == EAGAIN) || (errno == EINTR)) {
				continue;
			}

			fprintf(stderr, "%s: Error reading socket: %s\n",
				progname, strerror(errno));
			exit(1);
		}
		if (len == 0) return 0;	/* clean exit */

		size += len;
		buffer[size] = '\0';

		/*
		 *	There really is a better way of doing this.
		 */
		p = strstr(buffer, "radmin> ");
		if (p &&
		    ((p == buffer) || 
		     (p[-1] == '\n') ||
		     (p[-1] == '\r'))) {
			*p = '\0';

			if (p[-1] == '\n') p[-1] = '\0';
			break;
		}
	}

	/*
	 *	Blank prompt.  Go get another command.
	 */
	if (!buffer[0]) return 1;

	buffer[size] = '\0'; /* this is at least right */

	return 2;
}

#define MAX_COMMANDS (4)

int main(int argc, char **argv)
{
	int argval, quiet = 0;
	int done_license = 0;
	int sockfd;
	uint32_t magic;
	char *line = NULL;
	ssize_t len, size;
	const char *file = NULL;
	const char *name = "radiusd";
	char *p, buffer[65536];
	const char *input_file = NULL;
	FILE *inputfp = stdin;
	const char *output_file = NULL;
	
	char *commands[MAX_COMMANDS];
	int num_commands = -1;

	outputfp = stdout;	/* stdout is not a constant value... */

	if ((progname = strrchr(argv[0], FR_DIR_SEP)) == NULL)
		progname = argv[0];
	else
		progname++;

	while ((argval = getopt(argc, argv, "d:hi:e:Ef:n:o:q")) != EOF) {
		switch(argval) {
		case 'd':
			if (file) {
				fprintf(stderr, "%s: -d and -f cannot be used together.\n", progname);
				exit(1);
			}
			radius_dir = optarg;
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
			echo = TRUE;
			break;

		case 'f':
			radius_dir = NULL;
			file = optarg;
			break;

		default:
		case 'h':
			usage();
			break;

		case 'i':
			if (strcmp(optarg, "-") != 0) {
				input_file = optarg;
			}
			quiet = 1;
			break;

		case 'n':
			name = optarg;
			break;

		case 'o':
			if (strcmp(optarg, "-") != 0) {
				output_file = optarg;
			}
			quiet = 1;
			break;

		case 'q':
			quiet = 1;
			break;
		}
	}

	if (radius_dir) {
		int rcode;
		CONF_SECTION *cs, *subcs;

		file = NULL;	/* MUST read it from the conffile now */

		snprintf(buffer, sizeof(buffer), "%s/%s.conf",
			 radius_dir, name);

		cs = cf_file_read(buffer);
		if (!cs) {
			fprintf(stderr, "%s: Errors reading %s\n",
				progname, buffer);
			exit(1);
		}

		subcs = NULL;
		while ((subcs = cf_subsection_find_next(cs, subcs, "listen")) != NULL) {
			const char *value;
			CONF_PAIR *cp = cf_pair_find(subcs, "type");
			
			if (!cp) continue;

			value = cf_pair_value(cp);
			if (!value) continue;

			if (strcmp(value, "control") != 0) continue;

			/*
			 *	Now find the socket name (sigh)
			 */
			rcode = cf_item_parse(subcs, "socket",
					      PW_TYPE_STRING_PTR,
					      &file, NULL);
			if (rcode < 0) {
				fprintf(stderr, "%s: Failed parsing listen section\n", progname);
				exit(1);
			}

			if (!file) {
				fprintf(stderr, "%s: No path given for socket\n",
					progname);
				exit(1);
			}
			break;
		}

		if (!file) {
			fprintf(stderr, "%s: Could not find control socket in %s\n",
				progname, buffer);
			exit(1);
		}
	}

	if (input_file) {
		inputfp = fopen(input_file, "r");
		if (!inputfp) {
			fprintf(stderr, "%s: Failed opening %s: %s\n",
				progname, input_file, strerror(errno));
			exit(1);
		}
	}

	if (output_file) {
		outputfp = fopen(output_file, "w");
		if (!outputfp) {
			fprintf(stderr, "%s: Failed creating %s: %s\n",
				progname, output_file, strerror(errno));
			exit(1);
		}
	}

	/*
	 *	Check if stdin is a TTY only if input is from stdin
	 */
	if (input_file && !quiet && !isatty(STDIN_FILENO)) quiet = 1;

#ifdef USE_READLINE
	if (!quiet) {
#ifdef USE_READLINE_HISTORY
		using_history();
#endif
		rl_bind_key('\t', rl_insert);
	}
#endif

 reconnect:
	/*
	 *	FIXME: Get destination from command line, if possible?
	 */
	sockfd = fr_domain_socket(file);
	if (sockfd < 0) {
		exit(1);
	}

	/*
	 *	Read initial magic && version information.
	 */
	for (size = 0; size < 8; size += len) {
		len = read(sockfd, buffer + size, 8 - size);
		if (len < 0) {
			fprintf(stderr, "%s: Error reading initial data from socket: %s\n",
				progname, strerror(errno));
			exit(1);
		}
	}

	memcpy(&magic, buffer, 4);
	magic = ntohl(magic);
	if (magic != 0xf7eead15) {
		fprintf(stderr, "%s: Socket %s is not FreeRADIUS administration socket\n", progname, file);
		exit(1);
	}
	
	memcpy(&magic, buffer + 4, 4);
	magic = ntohl(magic);
	if (magic != 1) {
		fprintf(stderr, "%s: Socket version mismatch: Need 1, got %d\n",
			progname, magic);
		exit(1);
	}	

	/*
	 *	Run one command.
	 */
	if (num_commands >= 0) {
		int i;

		for (i = 0; i <= num_commands; i++) {
			size = run_command(sockfd, commands[i],
					   buffer, sizeof(buffer));
			if (size < 0) exit(1);
			
			if (buffer[0]) {
				fputs(buffer, outputfp);
				fprintf(outputfp, "\n");
				fflush(outputfp);
			}
		}
		exit(0);
	}

	if (!done_license && !quiet) {
		printf("radmin " RADIUSD_VERSION " - FreeRADIUS Server administration tool.\n");
		printf("Copyright (C) 2008-2011 The FreeRADIUS server project and contributors.\n");
		printf("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\n");
		printf("PARTICULAR PURPOSE.\n");
		printf("You may redistribute copies of FreeRADIUS under the terms of the\n");
		printf("GNU General Public License v2.\n");

		done_license = 1;
	}

	/*
	 *	FIXME: Do login?
	 */

	while (1) {
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
			close(sockfd);
			line = NULL;
			goto reconnect;
		}

		/*
		 *	Exit, done, etc.
		 */
		if ((strcmp(line, "exit") == 0) ||
		    (strcmp(line, "quit") == 0)) {
			break;
		}

		size = run_command(sockfd, line, buffer, sizeof(buffer));
		if (size <= 0) break; /* error, or clean exit */

		if (size == 1) continue; /* no output. */

		fputs(buffer, outputfp);
		fflush(outputfp);
		fprintf(outputfp, "\n");
	}

	fprintf(outputfp, "\n");

	return 0;
}

