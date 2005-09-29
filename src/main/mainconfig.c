/*
 * mainconf.c	Handle the server's configuration.
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2002  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include "autoconf.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "radiusd.h"
#include "rad_assert.h"
#include "conffile.h"
#include "token.h"
#include "modules.h"
#include "request_list.h"

#include <sys/resource.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>


#ifdef HAVE_SYSLOG_H
#	include <syslog.h>
#endif

struct main_config_t mainconfig;

/*
 *	Temporary local variables for parsing the configuration
 *	file.
 */
static uid_t server_uid;
static gid_t server_gid;

/*
 *	These are not used anywhere else..
 */
static const char *localstatedir = NULL;
static const char *prefix = NULL;
static char *syslog_facility = NULL;
static const LRAD_NAME_NUMBER str2fac[] = {
#ifdef LOG_KERN
	{ "kern", LOG_KERN },
#endif	
#ifdef LOG_USER
	{ "user", LOG_USER },
#endif
#ifdef LOG_MAIL
	{ "mail", LOG_MAIL },
#endif
#ifdef LOG_DAEMON
	{ "daemon", LOG_DAEMON },
#endif
#ifdef LOG_AUTH
	{ "auth", LOG_AUTH },
#endif
#ifdef LOG_LPR
	{ "lpr", LOG_LPR },
#endif
#ifdef LOG_NEWS
	{ "news", LOG_NEWS },
#endif
#ifdef LOG_UUCP
	{ "uucp", LOG_UUCP },
#endif
#ifdef LOG_CRON
	{ "cron", LOG_CRON },
#endif
#ifdef LOG_AUTHPRIV
	{ "authpriv", LOG_AUTHPRIV },
#endif
#ifdef LOG_FTP
	{ "ftp", LOG_FTP },
#endif
#ifdef LOG_LOCAL0
	{ "local0", LOG_LOCAL0 },
#endif
#ifdef LOG_LOCAL1
	{ "local1", LOG_LOCAL1 },
#endif
#ifdef LOG_LOCAL2
	{ "local2", LOG_LOCAL2 },
#endif
#ifdef LOG_LOCAL3
	{ "local3", LOG_LOCAL3 },
#endif
#ifdef LOG_LOCAL4
	{ "local4", LOG_LOCAL4 },
#endif
#ifdef LOG_LOCAL5
	{ "local5", LOG_LOCAL5 },
#endif
#ifdef LOG_LOCAL6
	{ "local6", LOG_LOCAL6 },
#endif
#ifdef LOG_LOCAL7
	{ "local7", LOG_LOCAL7 },
#endif
	{ NULL, -1 }
};

/*
 *  Map the proxy server configuration parameters to variables.
 */
static const CONF_PARSER proxy_config[] = {
	{ "retry_delay",  PW_TYPE_INTEGER, 0, &mainconfig.proxy_retry_delay, Stringify(RETRY_DELAY) },
	{ "retry_count",  PW_TYPE_INTEGER, 0, &mainconfig.proxy_retry_count, Stringify(RETRY_COUNT) },
	{ "default_fallback", PW_TYPE_BOOLEAN, 0, &mainconfig.proxy_fallback, "no" },
	{ "dead_time",    PW_TYPE_INTEGER, 0, &mainconfig.proxy_dead_time, Stringify(DEAD_TIME) },
	{ "wake_all_if_all_dead", PW_TYPE_BOOLEAN, 0, &mainconfig.wake_all_if_all_dead, "no" },
	{ "proxy_fail_type", PW_TYPE_STRING_PTR, 0, &mainconfig.proxy_fail_type, NULL},
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *  Security configuration for the server.
 */
static const CONF_PARSER security_config[] = {
	{ "max_attributes",  PW_TYPE_INTEGER, 0, &librad_max_attributes, Stringify(0) },
	{ "reject_delay",  PW_TYPE_INTEGER, 0, &mainconfig.reject_delay, Stringify(0) },
	{ "status_server", PW_TYPE_BOOLEAN, 0, &mainconfig.status_server, "no"},
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *  syslog configuration for the server.
 */
static const CONF_PARSER log_config[] = {
	{ "syslog_facility",  PW_TYPE_STRING_PTR, 0, &syslog_facility, Stringify(0) },
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *  A mapping of configuration file names to internal variables
 */
static const CONF_PARSER server_config[] = {
	/*
	 *	FIXME: 'prefix' is the ONLY one which should be
	 *	configured at compile time.  Hard-coding it here is
	 *	bad.  It will be cleaned up once we clean up the
	 *	hard-coded defines for the locations of the various
	 *	files.
	 */
	{ "prefix",             PW_TYPE_STRING_PTR, 0, &prefix,            "/usr/local"},
	{ "localstatedir",      PW_TYPE_STRING_PTR, 0, &localstatedir,     "${prefix}/var"},
	{ "logdir",             PW_TYPE_STRING_PTR, 0, &radlog_dir,        "${localstatedir}/log"},
	{ "libdir",             PW_TYPE_STRING_PTR, 0, &radlib_dir,        "${prefix}/lib"},
	{ "radacctdir",         PW_TYPE_STRING_PTR, 0, &radacct_dir,       "${logdir}/radacct" },
	{ "hostname_lookups",   PW_TYPE_BOOLEAN,    0, &librad_dodns,      "no" },
#ifdef WITH_SNMP
	{ "snmp",   		PW_TYPE_BOOLEAN,    0, &mainconfig.do_snmp,      "no" },
#endif
	{ "max_request_time", PW_TYPE_INTEGER, 0, &mainconfig.max_request_time, Stringify(MAX_REQUEST_TIME) },
	{ "cleanup_delay", PW_TYPE_INTEGER, 0, &mainconfig.cleanup_delay, Stringify(CLEANUP_DELAY) },
	{ "max_requests", PW_TYPE_INTEGER, 0, &mainconfig.max_requests, Stringify(MAX_REQUESTS) },
	{ "delete_blocked_requests", PW_TYPE_INTEGER, 0, &mainconfig.kill_unresponsive_children, Stringify(FALSE) },
	{ "allow_core_dumps", PW_TYPE_BOOLEAN, 0, &mainconfig.allow_core_dumps, "no" },
	{ "log_stripped_names", PW_TYPE_BOOLEAN, 0, &log_stripped_names,"no" },

	{ "log_file", PW_TYPE_STRING_PTR, -1, &mainconfig.log_file, "${logdir}/radius.log" },
	{ "log_auth", PW_TYPE_BOOLEAN, -1, &mainconfig.log_auth, "no" },
	{ "log_auth_badpass", PW_TYPE_BOOLEAN, 0, &mainconfig.log_auth_badpass, "no" },
	{ "log_auth_goodpass", PW_TYPE_BOOLEAN, 0, &mainconfig.log_auth_goodpass, "no" },
	{ "pidfile", PW_TYPE_STRING_PTR, 0, &mainconfig.pid_file, "${run_dir}/radiusd.pid"},
	{ "user", PW_TYPE_STRING_PTR, 0, &mainconfig.uid_name, NULL},
	{ "group", PW_TYPE_STRING_PTR, 0, &mainconfig.gid_name, NULL},
	{ "checkrad", PW_TYPE_STRING_PTR, 0, &mainconfig.checkrad, "${sbindir}/checkrad" },

	{ "debug_level", PW_TYPE_INTEGER, 0, &mainconfig.debug_level, "0"},

	{ "proxy_requests", PW_TYPE_BOOLEAN, 0, &mainconfig.proxy_requests, "yes" },
	{ "log", PW_TYPE_SUBSECTION, 0, NULL,  (const void *) log_config},
	{ "proxy", PW_TYPE_SUBSECTION, 0, NULL, (const void *) proxy_config },
	{ "security", PW_TYPE_SUBSECTION, 0, NULL, (const void *) security_config },
	{ NULL, -1, 0, NULL, NULL }
};


#define MAX_ARGV (256)
/*
 *	Xlat for %{config:section.subsection.attribute}
 */
static int xlat_config(void *instance, REQUEST *request,
		       char *fmt, char *out,
		       size_t outlen,
		       RADIUS_ESCAPE_STRING func)
{
	CONF_SECTION *cs;
	CONF_PAIR *cp;
	int i, argc, left;
	const char *from, *value;
	char *to;
	char myfmt[1024];
	char argv_buf[1024];
	char *argv[MAX_ARGV];

	request = request;	/* -Wunused */
	instance = instance;	/* -Wunused */

	cp = NULL;
	cs = NULL;

	/*
	 *	Split the string into argv's BEFORE doing radius_xlat...
	 *	Copied from exec.c
	 */
	from = fmt;
	to = myfmt; 
	argc = 0;
	while (*from) {
		int flag, length;
		
		flag = 0;
		argv[argc] = to;
		argc++;
		
		if (argc >= (MAX_ARGV - 1)) break;
		
		/*
		 *	Copy the argv over to our buffer.
		 */
		while (*from) {
			if (to >= myfmt + sizeof(myfmt) - 1) {
				return 0; /* no error msg */
			}

			switch (*from) {
			case '%':
				if (from[1] == '{') {
					*(to++) = *(from++);
					
					length = rad_copy_variable(to, from);
					if (length < 0) {
						return -1;
					}
					from += length;
					to += length;
				} else { /* FIXME: catch %%{ ? */
					*(to++) = *(from++);
				}
				break;

			case '[':
				if (flag != 0) {
					radlog(L_ERR, "config: Unexpected nested '[' in \"%s\"", fmt);
					return 0;
				}
				flag++;
				*(to++) = *(from++);
				break;

			case ']':
				if (flag == 0) {
					radlog(L_ERR, "config: Unbalanced ']' in \"%s\"", fmt);
					return 0;
				}
				if (from[1] != '.') {
					radlog(L_ERR, "config: Unexpected text after ']' in \"%s\"", fmt);
					return 0;
				}

				flag--;
				*(to++) = *(from++);
				break;

			case '.':
				if (flag == 0) break;
				/* FALL-THROUGH */

			default:
				*(to++) = *(from++);
				break;
			}

			if ((*from == '.') && (flag == 0)) {
				from++;
				break;
			}
		} /* end of string, or found a period */

		if (flag != 0) {
			radlog(L_ERR, "config: Unbalanced '[' in \"%s\"", fmt);
			return 0;
		}

		*(to++) = '\0';	/* terminate the string. */
	}

	/*
	 *	Expand each string, as appropriate
	 */
	to = argv_buf;
	left = sizeof(argv_buf);
	for (i = 0; i < argc; i++) {
		int sublen;

		/*
		 *	Don't touch argv's which won't be translated.
		 */
		if (strchr(argv[i], '%') == NULL) continue;

		sublen = radius_xlat(to, left - 1, argv[i], request, NULL);
		if (sublen <= 0) {
			/*
			 *	Fail to be backwards compatible.
			 *
			 *	It's yucky, but it won't break anything,
			 *	and it won't cause security problems.
			 */
			sublen = 0;
		}
		
		argv[i] = to;
		to += sublen;
		*(to++) = '\0';
		left -= sublen;
		left--;

		if (left <= 0) {
			return 0;
		}
	}
	argv[argc] = NULL;

	cs = cf_section_find(NULL); /* get top-level section */

	/*
	 *	Root through section & subsection references.
	 *	The last entry of argv MUST be the CONF_PAIR.
	 */
	for (i = 0; i < argc - 1; i++) {
		char *name2 = NULL;
		CONF_SECTION *subcs;

		/*
		 *	FIXME: What about RADIUS attributes containing '['?
		 */
		name2 = strchr(argv[i], '[');
		if (name2) {
			char *p = strchr(name2, ']');
			rad_assert(p != NULL);
			rad_assert(p[1] =='\0');
			*p = '\0';
			*name2 = '\0';
			name2++;
		}

		if (name2) {
			subcs = cf_section_sub_find_name2(cs, argv[i],
							  name2);
			if (!subcs) {
			  radlog(L_ERR, "config: section \"%s %s {}\" not found while dereferencing \"%s\"", argv[i], name2, fmt);
			  return 0;
			}
		} else {
			subcs = cf_section_sub_find(cs, argv[i]);
			if (!subcs) {
			  radlog(L_ERR, "config: section \"%s {}\" not found while dereferencing \"%s\"", argv[i], fmt);
			  return 0;
			}
		}
		cs = subcs;
	} /* until argc - 1 */

	/*
	 *	This can now have embedded periods in it.
	 */
	cp = cf_pair_find(cs, argv[argc - 1]);
	if (!cp) {
		radlog(L_ERR, "config: item \"%s\" not found while dereferencing \"%s\"", argv[argc], fmt);
		return 0;
	}

	/*
	 *  Ensure that we only copy what's necessary.
	 *
	 *  If 'outlen' is too small, then the output is chopped to fit.
	 */
	value = cf_pair_value(cp);
	if (value) {
		if (outlen > strlen(value)) {
			outlen = strlen(value) + 1;
		}
	}

	return func(out, outlen, value);
}


/*
 *	Recursively make directories.
 */
static int r_mkdir(const char *part)
{
	char *ptr, parentdir[500];
	struct stat st;

	if (stat(part, &st) == 0)
		return(0);

	ptr = strrchr(part, '/');

	if (ptr == part)
		return(0);

	snprintf(parentdir, (ptr - part)+1, "%s", part);

	if (r_mkdir(parentdir) != 0)
		return(1);

	if (mkdir(part, 0770) != 0) {
		radlog(L_ERR, "mkdir(%s) error: %s\n", part, strerror(errno));
		return(1);
	}

	return(0);
}

/*
 *	Checks if the log directory is writeable by a particular user.
 */
static int radlogdir_iswritable(const char *effectiveuser)
{
	struct passwd *pwent;

	if (radlog_dir[0] != '/')
		return(0);

	if (r_mkdir(radlog_dir) != 0)
		return(1);

	/* FIXME: do we have this function? */
	if (strstr(radlog_dir, "radius") == NULL)
		return(0);

	/* we have a logdir that mentions 'radius', so it's probably
	 * safe to chown the immediate directory to be owned by the normal
	 * process owner. we gotta do it before we give up root.  -chad
	 */

	if (!effectiveuser) {
		return 1;
	}

	pwent = getpwnam(effectiveuser);

	if (pwent == NULL) /* uh oh! */
		return(1);

	if (chown(radlog_dir, pwent->pw_uid, -1) != 0)
		return(1);

	return(0);
}


/*
 *  Switch UID and GID to what is specified in the config file
 */
static int switch_users(void)
{
	/*  Set GID.  */
	if (mainconfig.gid_name != NULL) {
		struct group *gr;

		gr = getgrnam(mainconfig.gid_name);
		if (gr == NULL) {
			if (errno == ENOMEM) {
				radlog(L_ERR|L_CONS, "Cannot switch to Group %s: out of memory", mainconfig.gid_name);
			} else {
				radlog(L_ERR|L_CONS, "Cannot switch group; %s doesn't exist", mainconfig.gid_name);
			}
			exit(1);
		}
		server_gid = gr->gr_gid;
		if (setgid(server_gid) < 0) {
			radlog(L_ERR|L_CONS, "Failed setting Group to %s: %s",
			       mainconfig.gid_name, strerror(errno));
			exit(1);
		}
	} else {
		server_gid = getgid();
	}

	/*  Set UID.  */
	if (mainconfig.uid_name != NULL) {
		struct passwd *pw;

		pw = getpwnam(mainconfig.uid_name);
		if (pw == NULL) {
			if (errno == ENOMEM) {
				radlog(L_ERR|L_CONS, "Cannot switch to User %s: out of memory", mainconfig.uid_name);
			} else {
				radlog(L_ERR|L_CONS, "Cannot switch user; %s doesn't exist", mainconfig.uid_name);
			}
			exit(1);
		}
		server_uid = pw->pw_uid;
#ifdef HAVE_INITGROUPS
		if (initgroups(mainconfig.uid_name, server_gid) < 0) {
			if (errno != EPERM) {
				radlog(L_ERR|L_CONS, "Failed setting supplementary groups for User %s: %s", mainconfig.uid_name, strerror(errno));
				exit(1);
			}
		}
#endif
		if (setuid(server_uid) < 0) {
			radlog(L_ERR|L_CONS, "Failed setting User to %s: %s", mainconfig.uid_name, strerror(errno));
			exit(1);
		}
	}

	/*
	 *	We've probably written to the log file already as
	 *	root.root, so if we have switched users, we've got to
	 *	update the ownership of the file.
	 */
	if ((debug_flag == 0) &&
	    (mainconfig.radlog_dest == RADLOG_FILES) &&
	    (mainconfig.log_file != NULL)) {
		chown(mainconfig.log_file, server_uid, server_gid);
	}
	return(0);
}


/*
 * Create the linked list of realms from the new configuration type
 * This way we don't have to change to much in the other source-files
 */
static int generate_realms(const char *filename)
{
	CONF_SECTION *cs;
	REALM *my_realms = NULL;
	REALM *c, **tail;
	char *s, *t, *authhost, *accthost;
	const char *name2;

	tail = &my_realms;
	for (cs = cf_subsection_find_next(mainconfig.config, NULL, "realm");
	     cs != NULL;
	     cs = cf_subsection_find_next(mainconfig.config, cs, "realm")) {
		name2 = cf_section_name2(cs);
		if (!name2) {
			radlog(L_CONS|L_ERR, "%s[%d]: Missing realm name",
			       filename, cf_section_lineno(cs));
			return -1;
		}
		/*
		 * We've found a realm, allocate space for it
		 */
		c = rad_malloc(sizeof(REALM));
		memset(c, 0, sizeof(REALM));

		c->secret[0] = '\0';

		/*
		 *	No authhost means LOCAL.
		 */
		if ((authhost = cf_section_value_find(cs, "authhost")) == NULL) {
			c->ipaddr.af = AF_INET;
			c->ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
			c->auth_port = 0;
		} else {
			if ((s = strchr(authhost, ':')) != NULL) {
				*s++ = 0;
				c->auth_port = atoi(s);
			} else {
				c->auth_port = PW_AUTH_UDP_PORT;
			}
			if (strcmp(authhost, "LOCAL") == 0) {
				/*
				 *	Local realms don't have an IP address,
				 *	secret, or port.
				 */
				c->ipaddr.af = AF_INET;
				c->ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
				c->auth_port = 0;
			} else {
				if (ip_hton(authhost, AF_INET,
					    &c->ipaddr) < 0) {
					radlog(L_ERR, "%s[%d]: Host %s not found",
					       filename, cf_section_lineno(cs),
					       authhost);
					return -1;
				}
			}

			/*
			 * Double check length, just to be sure!
			 */
			if (strlen(authhost) >= sizeof(c->server)) {
				radlog(L_ERR, "%s[%d]: Server name of length %u is greater than allowed: %u",
				       filename, cf_section_lineno(cs),
				       strlen(authhost),
				       sizeof(c->server) - 1);
				return -1;
			}
		}

		/*
		 *	No accthost means LOCAL
		 */
		if ((accthost = cf_section_value_find(cs, "accthost")) == NULL) {
			c->acct_ipaddr.af = AF_INET;
			c->acct_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
			c->acct_port = 0;
		} else {
			if ((s = strchr(accthost, ':')) != NULL) {
				*s++ = 0;
				c->acct_port = atoi(s);
			} else {
				c->acct_port = PW_ACCT_UDP_PORT;
			}
			if (strcmp(accthost, "LOCAL") == 0) {
				/*
				 *	Local realms don't have an IP address,
				 *	secret, or port.
				 */
				c->acct_ipaddr.af = AF_INET;
				c->acct_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
				c->acct_port = 0;
			} else {
				if (ip_hton(accthost, AF_INET,
					    &c->acct_ipaddr) < 0) {
					radlog(L_ERR, "%s[%d]: Host %s not found",
					       filename, cf_section_lineno(cs),
					       accthost);
					return -1;
				}
			}

			if (strlen(accthost) >= sizeof(c->acct_server)) {
				radlog(L_ERR, "%s[%d]: Server name of length %u is greater than allowed: %u",
				       filename, cf_section_lineno(cs),
				       strlen(accthost),
				       sizeof(c->acct_server) - 1);
				return -1;
			}
		}

		if (strlen(name2) >= sizeof(c->realm)) {
			radlog(L_ERR, "%s[%d]: Realm name of length %u is greater than allowed %u",
			       filename, cf_section_lineno(cs),
			       strlen(name2),
			       sizeof(c->server) - 1);
			return -1;
		}

		strcpy(c->realm, name2);
                if (authhost) strcpy(c->server, authhost);
		if (accthost) strcpy(c->acct_server, accthost);

		/*
		 *	If one or the other of authentication/accounting
		 *	servers is set to LOCALHOST, then don't require
		 *	a shared secret.
		 */
		rad_assert(c->ipaddr.af == AF_INET);
		rad_assert(c->acct_ipaddr.af == AF_INET);
		if ((c->ipaddr.ipaddr.ip4addr.s_addr != htonl(INADDR_NONE)) ||
		    (c->acct_ipaddr.ipaddr.ip4addr.s_addr != htonl(INADDR_NONE))) {
			if ((s = cf_section_value_find(cs, "secret")) == NULL ) {
				radlog(L_ERR, "%s[%d]: No shared secret supplied for realm: %s",
				       filename, cf_section_lineno(cs), name2);
				return -1;
			}

			if (strlen(s) >= sizeof(c->secret)) {
				radlog(L_ERR, "%s[%d]: Secret of length %u is greater than the allowed maximum of %u.",
				       filename, cf_section_lineno(cs),
				       strlen(s), sizeof(c->secret) - 1);
				return -1;
			}
			strNcpy((char *)c->secret, s, sizeof(c->secret));
		}

		c->striprealm = 1;

		if ((cf_section_value_find(cs, "nostrip")) != NULL)
			c->striprealm = 0;
		if ((cf_section_value_find(cs, "noacct")) != NULL)
			c->acct_port = 0;
		if ((cf_section_value_find(cs, "trusted")) != NULL)
			c->trusted = 1;
		if ((cf_section_value_find(cs, "notrealm")) != NULL)
			c->notrealm = 1;
		if ((cf_section_value_find(cs, "notsuffix")) != NULL)
			c->notrealm = 1;
		if ((t = cf_section_value_find(cs,"ldflag")) != NULL) {
			static const LRAD_NAME_NUMBER ldflags[] = {
				{ "fail_over",   0 },
				{ "round_robin", 1 },
				{ NULL, 0 }
			};

			c->ldflag = lrad_str2int(ldflags, t, -1);
			if (c->ldflag == -1) {
				radlog(L_ERR, "%s[%d]: Unknown value \"%s\" for ldflag",
				       filename, cf_section_lineno(cs),
				       t);
				return -1;
			}

		} else {
			c->ldflag = 0; /* non, make it fail-over */
		}
		c->active = TRUE;
		c->acct_active = TRUE;

		c->next = NULL;
		*tail = c;
		tail = &c->next;
	}

	/*
	 *	And make these realms preferred over the ones
	 *	in the 'realms' file.
	 */
	*tail = mainconfig.realms;
	mainconfig.realms = my_realms;

	/*
	 *  Ensure that all of the flags agree for the realms.
	 *
	 *	Yeah, it's O(N^2), but it's only once, and the
	 *	maximum number of realms is small.
	 */
	for(c = mainconfig.realms; c != NULL; c = c->next) {
		REALM *this;

		/*
		 *	Check that we cannot load balance to LOCAL
		 *	realms, as that doesn't make any sense.
		 */
		rad_assert(c->ipaddr.af == AF_INET);
		rad_assert(c->acct_ipaddr.af == AF_INET);
		if ((c->ldflag == 1) &&
		    ((c->ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_NONE)) ||
		     (c->acct_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_NONE)))) {
			radlog(L_ERR | L_CONS, "ERROR: Realm %s cannot be load balanced to LOCAL",
			       c->realm);
			exit(1);
		}

		/*
		 *	Compare this realm to all others, to ensure
		 *	that the configuration is consistent.
		 */
		for (this = c->next; this != NULL; this = this->next) {
			if (strcasecmp(c->realm, this->realm) != 0) {
				continue;
			}

			/*
			 *	Same realm: Different load balancing
			 *	flag: die.
			 */
			if (c->ldflag != this->ldflag) {
				radlog(L_ERR | L_CONS, "ERROR: Inconsistent value in realm %s for load balancing 'ldflag' attribute",
				       c->realm);
				exit(1);
			}
		}
	}

	return 0;
}


static const LRAD_NAME_NUMBER str2dest[] = {
	{ "null", RADLOG_NULL },
	{ "files", RADLOG_FILES },
	{ "syslog", RADLOG_SYSLOG },
	{ "stdout", RADLOG_STDOUT },
	{ "stderr", RADLOG_STDERR },
	{ NULL, RADLOG_NUM_DEST }
};


/*
 *	Read config files.
 *
 *	This function can ONLY be called from the main server process.
 */
int read_mainconfig(int reload)
{
	struct rlimit core_limits;
	static int old_debug_level = -1;
	char buffer[1024];
	CONF_SECTION *cs, *oldcs;
	rad_listen_t *listener;

	if (!reload) {
		radlog(L_INFO, "Starting - reading configuration files ...");
	} else {
		radlog(L_INFO, "Reloading configuration files.");
	}

	/* Initialize the dictionary */
	DEBUG2("read_config_files:  reading dictionary");
	if (dict_init(radius_dir, RADIUS_DICTIONARY) != 0) {
		radlog(L_ERR|L_CONS, "Errors reading dictionary: %s",
				librad_errstr);
		cf_section_free(&cs);
		return -1;
	}

	/* Read the configuration file */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s",
		 radius_dir, mainconfig.radiusd_conf);
	if ((cs = conf_read(NULL, 0, buffer, NULL)) == NULL) {
		radlog(L_ERR|L_CONS, "Errors reading %s", buffer);
		return -1;
	}

	/*
	 *	This allows us to figure out where, relative to
	 *	radiusd.conf, the other configuration files exist.
	 */
	cf_section_parse(cs, NULL, server_config);

#if 0
	/*
	 *	Merge the old with the new.
	 */
	if (reload) {
		CONF_SECTION *newcs;

		newcs = cf_section_sub_find(cs, "modules");
		oldcs = cf_section_sub_find(mainconfig.config, "modules");
		if (newcs && oldcs) {
			if (!cf_section_migrate(newcs, oldcs)) {
				radlog(L_ERR|L_CONS, "Fatal error migrating configuration data");
				return -1;
			}
		}
	}
#endif

	/*
	 *	Debug flag 1 MAY go to files.
	 *	Debug flag 2 ALWAYS goes to stdout
	 */
	if (debug_flag < 2) {
		int rcode;
		char *radlog_dest = NULL;

		rcode = cf_item_parse(cs, "log_destination",
				      PW_TYPE_STRING_PTR, &radlog_dest,
				      "files");
		if (rcode < 0) return -1;
	
		mainconfig.radlog_dest = lrad_str2int(str2dest, radlog_dest, RADLOG_NUM_DEST);
		if (mainconfig.radlog_dest == RADLOG_NUM_DEST) {
			fprintf(stderr, "radiusd: Error: Unknown log_destination %s\n",
				radlog_dest);
			cf_section_free(&cs);
			return -1;
		}
		
		if (mainconfig.radlog_dest == RADLOG_SYSLOG) {
			mainconfig.syslog_facility = lrad_str2int(str2fac, syslog_facility, -1);
			if (mainconfig.syslog_facility < 0) {
				fprintf(stderr, "radiusd: Error: Unknown syslog_facility %s\n",
					syslog_facility);
				cf_section_free(&cs);
				return -1;
			}
		}
	}

	/*
	 *	Free the old configuration items, and replace them
	 *	with the new ones.
	 *
	 *	Note that where possible, we do atomic switch-overs,
	 *	to ensure that the pointers are always valid.
	 */
	oldcs = mainconfig.config;
	mainconfig.config = cs;
	cf_section_free(&oldcs);

	/*
	 *	Old-style realms file.
	 */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s", radius_dir, RADIUS_REALMS);
	DEBUG2("read_config_files:  reading realms");
	if (read_realms_file(buffer) < 0) {
		radlog(L_ERR|L_CONS, "Errors reading realms");
		return -1;
	}

	/*
	 *	If there isn't any realms it isn't fatal..
	 */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s",
		 radius_dir, mainconfig.radiusd_conf);
	if (generate_realms(buffer) < 0) {
		return -1;
	}

	/*
	 *  Register the %{config:section.subsection} xlat function.
	 */
	xlat_register("config", xlat_config, NULL);

	/*
	 *	Set the libraries debugging flag to whatever the main
	 *	flag is.  Note that on a SIGHUP, to turn the debugging
	 *	off, we do other magic.
	 *
	 *	Increase the debug level, if the configuration file
	 *	says to, OR, if we're decreasing the debug from what it
	 *	was before, allow that, too.
	 */
	if ((mainconfig.debug_level > debug_flag) ||
	    (mainconfig.debug_level <= old_debug_level)) {
		debug_flag = mainconfig.debug_level;
	}
	librad_debug = debug_flag;
	old_debug_level = mainconfig.debug_level;

	/*
	 *  Go update our behaviour, based on the configuration
	 *  changes.
	 */

	/*  Get the current maximum for core files.  */
	if (getrlimit(RLIMIT_CORE, &core_limits) < 0) {
		radlog(L_ERR|L_CONS, "Failed to get current core limit:  %s", strerror(errno));
		exit(1);
	}

	if (mainconfig.allow_core_dumps) {
		if (setrlimit(RLIMIT_CORE, &core_limits) < 0) {
			radlog(L_ERR|L_CONS, "Cannot update core dump limit: %s",
					strerror(errno));
			exit(1);

			/*
			 *  If we're running as a daemon, and core
			 *  dumps are enabled, log that information.
			 */
		} else if ((core_limits.rlim_cur != 0) && !debug_flag)
			radlog(L_INFO|L_CONS, "Core dumps are enabled.");

	} else if (!debug_flag) {
		/*
		 *  Not debugging.  Set the core size to zero, to
		 *  prevent security breaches.  i.e. People
		 *  reading passwords from the 'core' file.
		 */
		struct rlimit limits;

		limits.rlim_cur = 0;
		limits.rlim_max = core_limits.rlim_max;

		if (setrlimit(RLIMIT_CORE, &limits) < 0) {
			radlog(L_ERR|L_CONS, "Cannot disable core dumps: %s",
					strerror(errno));
			exit(1);
		}
	}

	/*
	 * 	The first time around, ensure that we can write to the
	 *	log directory.
	 */
	if (!reload) {
		/*
		 *	We need root to do mkdir() and chown(), so we
		 *	do this before giving up root.
		 */
		radlogdir_iswritable(mainconfig.uid_name);
	}

	/*
	 *	We should really switch users earlier in the process.
	 */
	switch_users();

	/*
	 *	Sanity check the configuration for internal
	 *	consistency.
	 */
	if (mainconfig.reject_delay > mainconfig.cleanup_delay) {
		mainconfig.reject_delay = mainconfig.cleanup_delay;
	}

	/*
	 *	Initialize the old "bind_address" and "port", first.
	 */
	listener = NULL;

	/*
	 *	Read the list of listeners.
	 */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s",
		 radius_dir, mainconfig.radiusd_conf);
	if (listen_init(buffer, &listener) < 0) {
		exit(1);
	}

	if (!listener) {
		radlog(L_ERR|L_CONS, "Server is not configured to listen on any ports.  Exiting.");
		exit(1);
	}

	listen_free(&mainconfig.listen);
	mainconfig.listen = listener;

	/*
	 *	Walk through the listeners.  If we're listening on acct
	 *	or auth, read in the clients files, else ignore them.
	 */
	for (listener = mainconfig.listen;
	     listener != NULL;
	     listener = listener->next) {
		if ((listener->type == RAD_LISTEN_AUTH) ||
		    (listener->type == RAD_LISTEN_ACCT)) {
			break;
		}
	}

	if (listener != NULL) {
		RADCLIENT_LIST *clients, *old_clients;

		/*
		 *	Create the new clients first, and add them
		 *	to the CONF_SECTION, where they're automagically
		 *	freed if anything goes wrong.
		 */
		snprintf(buffer, sizeof(buffer), "%.200s/%.50s",
			 radius_dir, mainconfig.radiusd_conf);
		clients = clients_parse_section(buffer, mainconfig.config);
		if (!clients) {
			return -1;
		}

		/*
		 *	Free the old trees AFTER replacing them with
		 *	the new ones...
		 */
		old_clients = mainconfig.clients;
		mainconfig.clients = clients;
	}

	rl_init_proxy();

	/*  Reload the modules.  */
	DEBUG2("radiusd:  entering modules setup");
	if (setup_modules(reload) < 0) {
		radlog(L_ERR|L_CONS, "Errors setting up modules");
		return -1;
	}
	return 0;
}

/*
 *	Free the configuration.
 */
int free_mainconfig(void)
{
	/*
	 *	Clean up the configuration data
	 *	structures.
	 */
	cf_section_free(&mainconfig.config);
	realm_free(mainconfig.realms);
	listen_free(&mainconfig.listen);

	return 0;
}
