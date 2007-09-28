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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002,2006-2007  The FreeRADIUS server project
 * Copyright 2002  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_SYS_PRTCL_H
#include <sys/prctl.h>
#endif

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
	{ "max_request_time", PW_TYPE_INTEGER, 0, &mainconfig.max_request_time, Stringify(MAX_REQUEST_TIME) },
	{ "cleanup_delay", PW_TYPE_INTEGER, 0, &mainconfig.cleanup_delay, Stringify(CLEANUP_DELAY) },
	{ "max_requests", PW_TYPE_INTEGER, 0, &mainconfig.max_requests, Stringify(MAX_REQUESTS) },
#ifdef DELETE_BLOCKED_REQUESTS
	{ "delete_blocked_requests", PW_TYPE_INTEGER, 0, &mainconfig.kill_unresponsive_children, Stringify(FALSE) },
#endif
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

	cs = request->root->config;

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
#ifdef HAVE_GETPWNAM
	struct passwd *pwent;
#endif

	if (!radlog_dir || radlog_dir[0] != '/')
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

#ifdef HAVE_GETPWNAM
	pwent = getpwnam(effectiveuser);

	if (pwent == NULL) /* uh oh! */
		return(1);

	if (chown(radlog_dir, pwent->pw_uid, -1) != 0)
		return(1);
#endif

	return(0);
}


/*
 *  Switch UID and GID to what is specified in the config file
 */
static int switch_users(void)
{
#ifdef HAVE_SYS_RESOURCE_H
	struct rlimit core_limits;
#endif

#ifdef HAVE_GRP_H
	/*  Set GID.  */
	if (mainconfig.gid_name != NULL) {
		struct group *gr;

		gr = getgrnam(mainconfig.gid_name);
		if (gr == NULL) {
			if (errno == ENOMEM) {
				radlog(L_ERR, "Cannot switch to Group %s: out of memory", mainconfig.gid_name);
			} else {
				radlog(L_ERR, "Cannot switch group; %s doesn't exist", mainconfig.gid_name);
			}
			return 0;
		}
		server_gid = gr->gr_gid;
		if (setgid(server_gid) < 0) {
			radlog(L_ERR, "Failed setting Group to %s: %s",
			       mainconfig.gid_name, strerror(errno));
			return 0;
		}
	} else {
		server_gid = getgid();
	}
#endif

#ifdef HAVE_PWD_H
	/*  Set UID.  */
	if (mainconfig.uid_name != NULL) {
		struct passwd *pw;

		pw = getpwnam(mainconfig.uid_name);
		if (pw == NULL) {
			if (errno == ENOMEM) {
				radlog(L_ERR, "Cannot switch to User %s: out of memory", mainconfig.uid_name);
			} else {
				radlog(L_ERR, "Cannot switch user; %s doesn't exist", mainconfig.uid_name);
			}
			return 0;
		}
		server_uid = pw->pw_uid;
#ifdef HAVE_INITGROUPS
		if (initgroups(mainconfig.uid_name, server_gid) < 0) {
			if (errno != EPERM) {
				radlog(L_ERR, "Failed setting supplementary groups for User %s: %s", mainconfig.uid_name, strerror(errno));
				return 0;
			}
		}
#endif
		if (setuid(server_uid) < 0) {
			radlog(L_ERR, "Failed setting User to %s: %s", mainconfig.uid_name, strerror(errno));
			return 0;
		}
	}
#endif

#ifdef HAVE_SYS_RESOURCE_H
	/*  Get the current maximum for core files.  */
	if (getrlimit(RLIMIT_CORE, &core_limits) < 0) {
		radlog(L_ERR, "Failed to get current core limit:  %s", strerror(errno));
		return 0;
	}
#endif

	if (mainconfig.allow_core_dumps) {
#ifdef HAVE_SYS_PRTCL_H
#ifdef PR_SET_DUMPABLE
		if (prctl(PR_SET_DUMPABLE, 1) < 0) {
			radlog(L_ERR,"Cannot enable core dumps: prctl(PR_SET_DUMPABLE) failed: '%s'",
			       strerror(errno));
		}
#endif
#endif

#ifdef HAVE_SYS_RESOURCE_H
		if (setrlimit(RLIMIT_CORE, &core_limits) < 0) {
			radlog(L_ERR, "Cannot update core dump limit: %s",
					strerror(errno));
			return 0;

			/*
			 *  If we're running as a daemon, and core
			 *  dumps are enabled, log that information.
			 */
		} else if ((core_limits.rlim_cur != 0) && !debug_flag)
			radlog(L_INFO, "Core dumps are enabled.");
#endif

	} else if (!debug_flag) {
#ifdef HAVE_SYS_RESOURCE_H
		/*
		 *  Not debugging.  Set the core size to zero, to
		 *  prevent security breaches.  i.e. People
		 *  reading passwords from the 'core' file.
		 */
		struct rlimit limits;

		limits.rlim_cur = 0;
		limits.rlim_max = core_limits.rlim_max;

		if (setrlimit(RLIMIT_CORE, &limits) < 0) {
			radlog(L_ERR, "Cannot disable core dumps: %s",
					strerror(errno));
			return 0;
		}
#endif
	}

#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
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
#endif
	return 1;
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
	static int old_debug_level = -1;
	char buffer[1024];
	CONF_SECTION *cs, *templates;
	rad_listen_t *listener;
	struct stat statbuf;

	if (stat(radius_dir, &statbuf) < 0) {
		radlog(L_ERR, "Errors reading %s: %s",
		       radius_dir, strerror(errno));
		return -1;
	}

#ifdef S_IWOTH
	if ((statbuf.st_mode & S_IWOTH) != 0) {
		radlog(L_ERR, "Configuration directory %s is globally writable.  Refusing to start due to insecure configuration.",
		       radius_dir);
	  return -1;
	}
#endif

#ifdef S_IROTH
	if (0 && (statbuf.st_mode & S_IROTH) != 0) {
		radlog(L_ERR, "Configuration directory %s is globally readable.  Refusing to start due to insecure configuration.",
		       radius_dir);
		return -1;
	}
#endif

	/* Read the configuration file */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s",
		 radius_dir, mainconfig.radiusd_conf);
	if ((cs = cf_file_read(buffer)) == NULL) {
		radlog(L_ERR, "Errors reading %s", buffer);
		return -1;
	}

	/*
	 *	Add templates to each kind of subsection.
	 */
	templates = cf_section_sub_find(cs, "templates");
	if (templates) {
		CONF_SECTION *ts, *mycs;

		/*
		 *	Loop over the templates, adding them to the
		 *	sections in the main configuration file.
		 */
		for (ts = cf_subsection_find_next(templates, NULL, NULL);
		     ts != NULL;
		     ts = cf_subsection_find_next(templates, ts, NULL)) {
			const char *name1 = cf_section_name1(ts);

			/*
			 *	Loop over sections in the main config
			 *	file, adding templats.
			 */
			for (mycs = cf_subsection_find_next(cs, NULL, name1);
			     mycs != NULL;
			     mycs = cf_subsection_find_next(cs, mycs, name1)) {
				const char *value;

				value = cf_section_value_find(mycs, "template");
				if (value) {
					CONF_SECTION *tts;

					tts = cf_section_sub_find_name2(templates,
									name1,
									value);
					if (!tts) {
						radlog(L_ERR, "%s[%d]: Section refers to non-existent template \"%s\"",
						       cf_section_filename(mycs), cf_section_lineno(mycs), value);
						return -1;
					}
					cf_section_template(mycs, tts);
				} else {
					cf_section_template(mycs, ts);
				}
			}
		}
	}

	/*
	 *	Debug flag 1 MAY go to files.
	 *	Debug flag 2 ALWAYS goes to stdout
	 *
	 *	Parse the log_destination before printing anything else.
	 *	All messages before this MUST be errors, which log.c
	 *	will print to stderr, since log_file is NULL, too.
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
			free(radlog_dest);
			cf_section_free(&cs);
			return -1;
		}

		if (mainconfig.radlog_dest == RADLOG_SYSLOG) {
			static const CONF_PARSER syslog_config[] = {
				{ "log", PW_TYPE_SUBSECTION, 0, NULL,  (const void *) log_config},
				{ NULL, -1, 0, NULL, NULL }
			};
			cf_section_parse(cs, NULL, syslog_config);

			/*
			 *	Make sure syslog_facility isn't NULL before using it
			 */
			if (!syslog_facility) {
				fprintf(stderr, "radiusd: Error: Unknown syslog chosen but no facility spedified\n");
				free(radlog_dest);
				cf_section_free(&cs);
				return -1;
			}
			mainconfig.syslog_facility = lrad_str2int(str2fac, syslog_facility, -1);
			if (mainconfig.syslog_facility < 0) {
				fprintf(stderr, "radiusd: Error: Unknown syslog_facility %s\n",
					syslog_facility);
				free(radlog_dest);
				free(syslog_facility);
				cf_section_free(&cs);
				return -1;
			}
		}

		if (mainconfig.radlog_dest == RADLOG_FILES) {
			static const CONF_PARSER file_config[] = {
				{ "log_file", PW_TYPE_STRING_PTR, -1, &mainconfig.log_file, "${logdir}/radius.log" },
				{ NULL, -1, 0, NULL, NULL }
			};

			cf_section_parse(cs, NULL, file_config);
		}

		free(radlog_dest);
	} else {
		mainconfig.radlog_dest = RADLOG_STDOUT;
		mainconfig.radlog_fd = STDOUT_FILENO;
	}

	if (!reload) {
		radlog(L_INFO, "Starting - reading configuration files ...");
	} else {
		radlog(L_INFO, "Reloading - reading configuration files...");
	}

	/* Initialize the dictionary */
	DEBUG2("read_config_files:  reading dictionary");
	if (dict_init(radius_dir, RADIUS_DICTIONARY) != 0) {
		radlog(L_ERR, "Errors reading dictionary: %s",
				librad_errstr);
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
				radlog(L_ERR, "Fatal error migrating configuration data");
				return -1;
			}
		}
	}
#endif

	/*
	 *	Free the old configuration items, and replace them
	 *	with the new ones.
	 *
	 *	Note that where possible, we do atomic switch-overs,
	 *	to ensure that the pointers are always valid.
	 */
	cf_section_free(&mainconfig.config);
	mainconfig.config = cs;

	if (!realms_init(cs)) {
		return -1;
	}

	/*
	 *  Register the %{config:section.subsection} xlat function.
	 */
	xlat_register("config", xlat_config, NULL);

	/*
	 *	Reload: change debug flag if it's changed in the
	 *	configuration file.
	 */
	if (reload) {
		if (mainconfig.debug_level != old_debug_level) {
			debug_flag = mainconfig.debug_level;
		}

	} else if (debug_flag == 0) {

		/*
		 *	Starting the server, WITHOUT "-x" on the
		 *	command-line: use whatever's in the config
		 *	file.
		 */
		debug_flag = mainconfig.debug_level;
	}
	librad_debug = debug_flag;
	old_debug_level = mainconfig.debug_level;

	/*
	 *  Go update our behaviour, based on the configuration
	 *  changes.
	 */

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
	if (!switch_users()) exit(1);

	/*
	 *	Sanity check the configuration for internal
	 *	consistency.
	 */
	if (mainconfig.reject_delay > mainconfig.cleanup_delay) {
		mainconfig.reject_delay = mainconfig.cleanup_delay;
	}
	if (mainconfig.reject_delay < 0) mainconfig.reject_delay = 0;

	/*
	 *	Initialize the old "bind_address" and "port", first.
	 */
	listener = NULL;

	/*
	 *	Read the list of listeners.
	 *
	 *	This also takes care of initializing the clients.
	 */
	if (listen_init(cs, &listener) < 0) {
		exit(1);
	}

	if (!listener) {
		radlog(L_ERR, "Server is not configured to listen on any ports.  Exiting.");
		exit(1);
	}

	listen_free(&mainconfig.listen);
	mainconfig.listen = listener;

	/*  Reload the modules.  */
	DEBUG2("radiusd:  entering modules setup");
	if (setup_modules(reload, mainconfig.config) < 0) {
		radlog(L_ERR, "Errors setting up modules");
		return -1;
	}
	return 0;
}

/*
 *	Free the configuration.  Called only when the server is exiting.
 */
int free_mainconfig(void)
{
	/*
	 *	Clean up the configuration data
	 *	structures.
	 */
	cf_section_free(&mainconfig.config);
	free(mainconfig.radiusd_conf);
	realms_free();
	listen_free(&mainconfig.listen);
	xlat_free();
	dict_free();
	lt_dlexit();

	return 0;
}
