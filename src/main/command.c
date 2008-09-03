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

#include <freeradius-devel/modpriv.h>
/*
 *	FIXME: configure checks.
 */
#include <sys/un.h>

typedef struct fr_command_table_t fr_command_table_t;

typedef int (*fr_command_func_t)(rad_listen_t *, int, char *argv[]);

struct fr_command_table_t {
	const char *command;
	const char *help;
	fr_command_func_t func;
	fr_command_table_t *table;
};

#define COMMAND_BUFFER_SIZE (1024)

typedef struct fr_command_socket_t {
	char	*path;
	char user[256];
	ssize_t offset;
	ssize_t next;
	char buffer[COMMAND_BUFFER_SIZE];
} fr_command_socket_t;


static ssize_t cprintf(rad_listen_t *listener, const char *fmt, ...)
#ifdef __GNUC__
		__attribute__ ((format (printf, 2, 3)))
#endif
;


static int fr_server_domain_socket(const char *path)
{
        int sockfd;
	size_t len;
	socklen_t socklen;
        struct sockaddr_un salocal;

	len = strlen(path);
	if (len >= sizeof(salocal.sun_path)) {
		fprintf(stderr, "Path too long in filename\n");
		return -1;
	}

        if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Failed creating socket: %s\n",
			strerror(errno));
		return -1;
        }

        salocal.sun_family = AF_UNIX;
	memcpy(salocal.sun_path, path, len); /* not zero terminated */
	
	socklen = sizeof(salocal.sun_family) + len;

	/*
	 *	FIXME: stat it, first, to see who owns it,
	 *	and who owns the directory above it.
	 */
	if (unlink(path) < 0) {
		fprintf(stderr, "Failed to delete %s: %s\n",
			path, strerror(errno));
	}

        if (bind(sockfd, (struct sockaddr *)&salocal, socklen) < 0) {
		fprintf(stderr, "Failed binding to %s: %s\n",
			path, strerror(errno));
		close(sockfd);
		return -1;
        }

	if (listen(sockfd, 8) < 0) {
		fprintf(stderr, "Failed listening to %s: %s\n",
			path, strerror(errno));
		close(sockfd);
		return -1;
        }

#ifdef O_NONBLOCK
	{
		int flags;
		
		if ((flags = fcntl(sockfd, F_GETFL, NULL)) < 0)  {
			fprintf(stderr, "Failure getting socket flags: %s",
				strerror(errno));
			close(sockfd);
			return -1;
		}
		
		flags |= O_NONBLOCK;
		if( fcntl(sockfd, F_SETFL, flags) < 0) {
			fprintf(stderr, "Failure setting socket flags: %s",
				strerror(errno));
			close(sockfd);
			return -1;
		}
	}
#endif

	return sockfd;
}


static ssize_t cprintf(rad_listen_t *listener, const char *fmt, ...)
{
	ssize_t len;
	va_list ap;
	char buffer[256];

	va_start(ap, fmt);
	len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (listener->status == RAD_LISTEN_STATUS_CLOSED) return 0;

	len = write(listener->fd, buffer, len);
	if (len < 0) {
		listener->status = RAD_LISTEN_STATUS_CLOSED;
		event_new_fd(listener);
	}

	/*
	 *	FIXME: Keep writing until done?
	 */
	return len;
}

static int command_hup(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t *mi;

	if (argc == 0) {
		radius_signal_self(RADIUS_SIGNAL_SELF_HUP);
		return 1;
	}

	cs = cf_section_find("modules");
	if (!cs) return 0;

	mi = find_module_instance(cs, argv[0], 0);
	if (!mi) {
		cprintf(listener, "ERROR: No such module \"%s\"\n", argv[0]);
		return 0;
	}

	if (!module_hup_module(mi->cs, mi, time(NULL))) {
		cprintf(listener, "ERROR: Failed to reload module\n");
		return 0;
	}

	return 1;		/* success */
}

static int command_terminate(UNUSED rad_listen_t *listener,
			     UNUSED int argc, UNUSED char *argv[])
{
	radius_signal_self(RADIUS_SIGNAL_SELF_TERM);

	return 1;		/* success */
}

extern time_t fr_start_time;

static int command_uptime(rad_listen_t *listener,
			  UNUSED int argc, UNUSED char *argv[])
{
	char buffer[128];

	CTIME_R(&fr_start_time, buffer, sizeof(buffer));
	cprintf(listener, "Up since %s", buffer); /* no \r\n */

	return 1;		/* success */
}

static int command_show_config(UNUSED rad_listen_t *listener,
			       UNUSED int argc, UNUSED char *argv[])
{

	return 1;		/* success */
}

static const char *tabs = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

/*
 *	FIXME: Recurse && indent?
 */
static void cprint_conf_parser(rad_listen_t *listener, int indent, CONF_SECTION *cs,
			       const void *base)
			       
{
	int i;
	const void *data;
	const char *name1 = cf_section_name1(cs);
	const char *name2 = cf_section_name2(cs);
	const CONF_PARSER *variables = cf_section_parse_table(cs);

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
		/*
		 *	No base struct offset, data must be the pointer.
		 *	If data doesn't exist, ignore the entry, there
		 *	must be something wrong.
		 */
		if (!base) {
			if (!variables[i].data) {
				continue;
			}
			
			data = variables[i].data;;
			
		} else if (variables[i].data) {
			data = variables[i].data;;
			
		} else {
			data = (((char *)base) + variables[i].offset);
		}
		
		switch (variables[i].type) {
		default:
			cprintf(listener, "%.*s%s = ?\n", indent, tabs,
				variables[i].name);
			break;
			
		case PW_TYPE_INTEGER:
			cprintf(listener, "%.*s%s = %u\n", indent, tabs,
				variables[i].name, *(int *) data);
			break;
			
		case PW_TYPE_BOOLEAN:
			cprintf(listener, "%.*s%s = %s\n", indent, tabs,
				variables[i].name, 
				((*(int *) data) == 0) ? "no" : "yes");
			break;
			
		case PW_TYPE_STRING_PTR:
		case PW_TYPE_FILENAME:
			/*
			 *	FIXME: Escape things in the string!
			 */
			if (*(char **) data) {
				cprintf(listener, "%.*s%s = \"%s\"\n", indent, tabs,
					variables[i].name, *(char **) data);
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
	module_instance_t *mi;

	if (argc != 1) {
		cprintf(listener, "ERROR: No module name was given\n");
		return 0;
	}

	cs = cf_section_find("modules");
	if (!cs) return 0;

	mi = find_module_instance(cs, argv[0], 0);
	if (!mi) {
		cprintf(listener, "ERROR: No such module \"%s\"\n", argv[0]);
		return 0;
	}

	cprint_conf_parser(listener, 0, mi->cs, mi->insthandle);

	return 1;		/* success */
}

static const char *method_names[RLM_COMPONENT_COUNT] = {
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
	const module_instance_t *mi;
	const module_t *mod;

	if (argc != 1) {
		cprintf(listener, "ERROR: No module name was given\n");
		return 0;
	}

	cs = cf_section_find("modules");
	if (!cs) return 0;

	mi = find_module_instance(cs, argv[0], 0);
	if (!mi) {
		cprintf(listener, "ERROR: No such module \"%s\"\n", argv[0]);
		return 0;
	}

	mod = mi->entry->module;

	for (i = 0; i < RLM_COMPONENT_COUNT; i++) {
		if (mod->methods[i]) cprintf(listener, "\t%s\n", method_names[i]);
	}

	return 1;		/* success */
}


static int command_show_module_flags(rad_listen_t *listener, int argc, char *argv[])
{
	CONF_SECTION *cs;
	const module_instance_t *mi;
	const module_t *mod;

	if (argc != 1) {
		cprintf(listener, "ERROR: No module name was given\n");
		return 0;
	}

	cs = cf_section_find("modules");
	if (!cs) return 0;

	mi = find_module_instance(cs, argv[0], 0);
	if (!mi) {
		cprintf(listener, "ERROR: No such module \"%s\"\n", argv[0]);
		return 0;
	}

	mod = mi->entry->module;

	if ((mod->type & RLM_TYPE_THREAD_SAFE) != 0)
		cprintf(listener, "\tthread-safe\n");


	if ((mod->type & RLM_TYPE_CHECK_CONFIG_SAFE) != 0)
		cprintf(listener, "\twill-check-config\n");


	if ((mod->type & RLM_TYPE_HUP_SAFE) != 0)
		cprintf(listener, "\treload-on-hup\n");

	return 1;		/* success */
}


/*
 *	Show all loaded modules
 */
static int command_show_modules(rad_listen_t *listener, UNUSED int argc, UNUSED char *argv[])
{
	CONF_SECTION *cs, *subcs;

	cs = cf_section_find("modules");
	if (!cs) return 0;

	subcs = NULL;
	while ((subcs = cf_subsection_find_next(cs, subcs, NULL)) != NULL) {
		const char *name1 = cf_section_name1(subcs);
		const char *name2 = cf_section_name2(subcs);

		module_instance_t *mi;

		if (name2) {
			mi = find_module_instance(cs, name2, 0);
			if (!mi) continue;

			cprintf(listener, "\t%s (%s)\n", name2, name1);
		} else {
			mi = find_module_instance(cs, name1, 0);
			if (!mi) continue;

			cprintf(listener, "\t%s\n", name1);
		}
	}

	return 1;		/* success */
}


static fr_command_table_t command_table_show_module[] = {
	{ "config",
	  "show module config <module> - show configuration for <module>",
	  command_show_module_config, NULL },
	{ "methods",
	  "show module methods <module> - show sections where <module> may be used",
	  command_show_module_methods, NULL },
	{ "flags",
	  "show module flags <module> - show other module properties",
	  command_show_module_flags, NULL },

	{ NULL, NULL, NULL, NULL }
};


static fr_command_table_t command_table_show[] = {
	{ "config",
	  "show config - show configuration stuff",
	  command_show_config, NULL },
	{ "module",
	  "show module <command> - do sub-command of module",
	  NULL, command_table_show_module },
	{ "modules",
	  "show modules - shows list of loaded modules",
	  command_show_modules, NULL },
	{ "uptime",
	  "show uptime - shows time at which server started",
	  command_uptime, NULL },

	{ NULL, NULL, NULL, NULL }
};


static int command_set_module_config(rad_listen_t *listener, int argc, char *argv[])
{
	int i, rcode;
	CONF_PAIR *cp;
	CONF_SECTION *cs;
	module_instance_t *mi;
	const CONF_PARSER *variables;
	void *data;

	if (argc < 3) {
		cprintf(listener, "ERROR: No module name or variable was given\n");
		return 0;
	}

	cs = cf_section_find("modules");
	if (!cs) return 0;

	mi = find_module_instance(cs, argv[0], 0);
	if (!mi) {
		cprintf(listener, "ERROR: No such module \"%s\"\n", argv[0]);
		return 0;
	}

	variables = cf_section_parse_table(mi->cs);
	if (!variables) {
		cprintf(listener, "ERROR: Cannot find configuration for module\n");
		return 0;
	}

	rcode = -1;
	for (i = 0; variables[i].name != NULL; i++) {
		/*
		 *	FIXME: Recurse into sub-types somehow...
		 */
		if (variables[i].type == PW_TYPE_SUBSECTION) continue;

		if (strcmp(variables[i].name, argv[1]) == 0) {
			rcode = i;
			break;
		}
	}

	if (rcode < 0) {
		cprintf(listener, "ERROR: No such variable \"%s\"\n", argv[1]);
		return 0;
	}

	i = rcode;		/* just to be safe */

	/*
	 *	It's not part of the dynamic configuration.  The module
	 *	needs to re-parse && validate things.
	 */
	if (variables[i].data) {
		cprintf(listener, "ERROR: Variable cannot be dynamically updated\n");
		return 0;
	}

	data = ((char *) mi->insthandle) + variables[i].offset;

	cp = cf_pair_find(mi->cs, argv[1]);
	if (!cp) return 0;

	/*
	 *	Replace the OLD value in the configuration file with
	 *	the NEW value.
	 *
	 *	FIXME: Parse argv[2] depending on it's data type!
	 *	If it's a string, look for leading single/double quotes,
	 *	end then call tokenize functions???
	 */
#if 0
	cf_pair_replace(mi->cs, cp, argv[2]);

	rcode = cf_item_parse(mi->cs, argv[1], variables[i].type,
			      data, argv[2]);
	if (rcode < 0) {
		cprintf(listener, "ERROR: Failed to parse value\n");
		return 0;
	}
#endif

	return 1;		/* success */
}


static fr_command_table_t command_table_set_module[] = {
	{ "config",
	  "set module config <module> variable value - set configuration for <module>",
	  command_set_module_config, NULL },

	{ NULL, NULL, NULL, NULL }
};


static fr_command_table_t command_table_set[] = {
	{ "module", NULL, NULL, command_table_set_module },

	{ NULL, NULL, NULL, NULL }
};


static fr_command_table_t command_table[] = {
	{ "hup",
	  "hup [module] - sends a HUP signal to the server, or optionally to one module",
	  command_hup, NULL },
	{ "terminate",
	  "terminate - terminates the server, and causes it to exit",
	  command_terminate, NULL },
	{ "show", NULL, NULL, command_table_show },
	{ "set", NULL, NULL, command_table_set },

	{ NULL, NULL, NULL, NULL }
};


/*
 *	FIXME: Unix domain sockets!
 */
static int command_socket_parse(UNUSED CONF_SECTION *cs, rad_listen_t *this)
{
	int rcode;
	fr_command_socket_t *sock;

	sock = this->data;

	rcode = cf_item_parse(cs, "socket", PW_TYPE_STRING_PTR,
			      &sock->path, "${run_dir}/radiusd.sock");
	if (rcode < 0) return -1;

	/*
	 *	FIXME: check for absolute pathnames?
	 *	check for uid/gid on the other end...	 
	 */

	this->fd = fr_server_domain_socket(sock->path);
	if (this->fd < 0) {
		return -1;
	}

	return 0;
}

static int command_socket_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	fr_command_socket_t *sock = this->data;

	snprintf(buffer, bufsize, "command file %s", sock->path);
	return 1;
}


/*
 *	String split routine.  Splits an input string IN PLACE
 *	into pieces, based on spaces.
 */
static int str2argv(char *str, char **argv, int max_argc)
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

		argv[argc] = str;
		argc++;

		while (*str &&
		       (*str != ' ') &&
		       (*str != '\t') &&
		       (*str != '\r') &&
		       (*str != '\n')) str++;
	}

	return argc;
}

#define MAX_ARGV (16)

/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int command_domain_recv(rad_listen_t *listener,
			       UNUSED RAD_REQUEST_FUNP *pfun,
			       UNUSED REQUEST **prequest)
{
	int i, rcode;
	ssize_t len;
	int argc;
	char *my_argv[MAX_ARGV], **argv;
	fr_command_table_t *table;
	fr_command_socket_t *co = listener->data;

	do {
		ssize_t c;
		char *p;

		len = recv(listener->fd, co->buffer + co->offset,
			   sizeof(co->buffer) - co->offset - 1, 0);
		if (len == 0) goto close_socket; /* clean close */

		if (len < 0) {
			if ((errno == EAGAIN) || (errno == EINTR)) {
				return 0;
			}
			goto close_socket;
		}

		/*
		 *	CTRL-D
		 */
		if ((co->offset == 0) && (co->buffer[0] == 0x04)) {
		close_socket:
			listener->status = RAD_LISTEN_STATUS_CLOSED;
			event_new_fd(listener);
			return 0;
		}

		/*
		 *	See if there are multiple lines in the buffer.
		 */
		p = co->buffer + co->offset;
		rcode = 0;
		p[len] = '\0';
		for (c = 0; c < len; c++) {
			if ((*p == '\r') || (*p == '\n')) {
				rcode = 1;
				*p = '\0';

				/*
				 *	FIXME: do real buffering...
				 *	handling of CTRL-C, etc.
				 */

			} else if (rcode) {
				/*
				 *	\r \n followed by ASCII...
				 */
				break;
			}

			p++;
		}

		co->offset += len;

		/*
		 *	Saw CR/LF.  Set next element, and exit.
		 */
		if (rcode) {
			co->next = p - co->buffer;
			break;
		}

		if (co->offset >= (ssize_t) (sizeof(co->buffer) - 1)) {
			radlog(L_ERR, "Line too long!");
			goto close_socket;
		}

		co->offset++;
	} while (1);

	argc = str2argv(co->buffer, my_argv, MAX_ARGV);
	if (argc == 0) goto do_next;
	argv = my_argv;

	for (len = 0; len <= co->offset; len++) {
		if (co->buffer[len] < 0x20) {
			co->buffer[len] = '\0';
			break;
		}
	}

	/*
	 *	Hard-code exit && quit.
	 */
	if ((strcmp(argv[0], "exit") == 0) ||
	    (strcmp(argv[0], "quit") == 0)) goto close_socket;

#if 0
	if (!co->user[0]) {
		if (strcmp(argv[0], "login") != 0) {
			cprintf(listener, "ERROR: Login required\n");
			goto do_next;
		}

		if (argc < 3) {
			cprintf(listener, "ERROR: login <user> <password>\n");
			goto do_next;
		}

		/*
		 *	FIXME: Generate && process fake RADIUS request.
		 */
		if ((strcmp(argv[1], "root") == 0) &&
		    (strcmp(argv[2], "password") == 0)) {
			strlcpy(co->user, argv[1], sizeof(co->user));
			goto do_next;
		}

		cprintf(listener, "ERROR: Login incorrect\n");
		goto do_next;
	}
#endif

	table = command_table;
 retry:
	len = 0;
	for (i = 0; table[i].command != NULL; i++) {
		if (strcmp(table[i].command, argv[0]) == 0) {
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

			len = 1;
			rcode = table[i].func(listener,
					      argc - 1, argv + 1);
			break;
		}
	}

	/*
	 *	No such command
	 */
	if (!len) {
		if (strcmp(argv[0], "help") == 0) {
		do_help:
			for (i = 0; table[i].command != NULL; i++) {
				if (table[i].help) {
					cprintf(listener, "%s\n",
						table[i].help);
				} else {
					cprintf(listener, "%s <command> - do sub-command of %s\n",
						table[i].command, table[i].command);
				}
			}
			goto do_next;
		}

		cprintf(listener, "ERROR: Unknown command \"%s\"\r\n",
			argv[0]);
	}

 do_next:
	cprintf(listener, "radmin> ");

	if (co->next <= co->offset) {
		co->offset = 0;
	} else {
		memmove(co->buffer, co->buffer + co->next,
			co->offset - co->next);
		co->offset -= co->next;
	}

	return 0;
}


static int command_domain_accept(rad_listen_t *listener,
				 UNUSED RAD_REQUEST_FUNP *pfun,
				 UNUSED REQUEST **prequest)
{
	int newfd;
	rad_listen_t *this;
	socklen_t salen;
	struct sockaddr_storage src;
	listen_socket_t *sock;
	fr_command_socket_t *co;
	
	salen = sizeof(src);

	DEBUG2(" ... new connection request on command socket.");
	
	newfd = accept(listener->fd, (struct sockaddr *) &src, &salen);
	if (newfd < 0) {
		/*
		 *	Non-blocking sockets must handle this.
		 */
		if (errno == EWOULDBLOCK) {
			return 0;
		}

		DEBUG2(" ... failed to accept connection.");
		return -1;
	}

#if 0
struct ucred cr;
 int cl=sizeof(cr);

 if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl)==0) {
   printf("Peer's pid=%d, uid=%d, gid=%d\n",
           cr.pid, cr.uid, cr.gid);
#endif

	/*
	 *	Add the new listener.
	 */
	this = listen_alloc(listener->type);
	if (!this) return -1;

	/*
	 *	Copy everything, including the pointer to the socket
	 *	information.
	 */
	free(this->data);
	this->data = rad_malloc(sizeof(fr_command_socket_t));
	sock = this->data;
	memcpy(this->data, listener->data, sizeof(*sock));
	memcpy(this, listener, sizeof(*this));
	this->next = NULL;
	this->data = sock;	/* fix it back */

	co = this->data;
	co->offset = 0;
	co->user[0] = '\0';

	this->fd = newfd;
	this->recv = command_domain_recv;

	/*
	 *	FIXME: set O_NONBLOCK on the accept'd fd.
	 *	See djb's portability rants for details.
	 */

	/*
	 *	Tell the event loop that we have a new FD
	 */
	event_new_fd(this);

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
