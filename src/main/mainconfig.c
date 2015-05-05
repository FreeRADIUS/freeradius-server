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

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

main_config_t		main_config;				//!< Main server configuration.
extern fr_cond_t	*debug_condition;
fr_cond_t		*debug_condition;			//!< Condition used to mark packets up for checking.
bool			event_loop_started = false;		//!< Whether the main event loop has been started yet.

typedef struct cached_config_t {
	struct cached_config_t *next;
	time_t		created;
	CONF_SECTION	*cs;
} cached_config_t;

static cached_config_t	*cs_cache = NULL;

/*
 *	Temporary local variables for parsing the configuration
 *	file.
 */
#ifdef HAVE_SETUID
/*
 *	Systems that have set/getresuid also have setuid.
 */
static uid_t server_uid = 0;
static gid_t server_gid = 0;
static char const *uid_name = NULL;
static char const *gid_name = NULL;
#endif
static char const *chroot_dir = NULL;
static bool allow_core_dumps = false;
static char const *radlog_dest = NULL;

/*
 *	These are not used anywhere else..
 */
static char const	*localstatedir = NULL;
static char const	*prefix = NULL;
static char const	*my_name = NULL;
static char const	*sbindir = NULL;
static char const	*run_dir = NULL;
static char const	*syslog_facility = NULL;
static bool		do_colourise = false;

static char const	*radius_dir = NULL;	//!< Path to raddb directory


/*
 *  Security configuration for the server.
 */
static const CONF_PARSER security_config[] = {
	{ "max_attributes",  FR_CONF_POINTER(PW_TYPE_INTEGER, &fr_max_attributes), STRINGIFY(0) },
	{ "reject_delay",  FR_CONF_POINTER(PW_TYPE_TIMEVAL, &main_config.reject_delay), STRINGIFY(0) },
	{ "status_server", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &main_config.status_server), "no"},
#ifdef ENABLE_OPENSSL_VERSION_CHECK
	{ "allow_vulnerable_openssl", FR_CONF_POINTER(PW_TYPE_STRING, &main_config.allow_vulnerable_openssl), "no"},
#endif
	{ NULL, -1, 0, NULL, NULL }
};


/*
 *	Logging configuration for the server.
 */
static const CONF_PARSER logdest_config[] = {
	{ "destination",  FR_CONF_POINTER(PW_TYPE_STRING, &radlog_dest), "files" },
	{ "syslog_facility",  FR_CONF_POINTER(PW_TYPE_STRING, &syslog_facility), STRINGIFY(0) },

	{ "file",  FR_CONF_POINTER(PW_TYPE_STRING, &main_config.log_file), "${logdir}/radius.log" },
	{ "requests",  FR_CONF_POINTER(PW_TYPE_STRING, &default_log.file), NULL },
	{ NULL, -1, 0, NULL, NULL }
};


static const CONF_PARSER serverdest_config[] = {
	{ "log",  FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) logdest_config },
	{ "log_file",  FR_CONF_POINTER(PW_TYPE_STRING, &main_config.log_file), NULL },
	{ "log_destination", FR_CONF_POINTER(PW_TYPE_STRING, &radlog_dest), NULL },
	{ "use_utc", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &log_dates_utc), NULL },
	{ NULL, -1, 0, NULL, NULL }
};


static const CONF_PARSER log_config_nodest[] = {
	{ "stripped_names", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &log_stripped_names),"no" },
	{ "auth", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &main_config.log_auth), "no" },
	{ "auth_badpass", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &main_config.log_auth_badpass), "no" },
	{ "auth_goodpass", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &main_config.log_auth_goodpass), "no" },
	{ "msg_badpass", FR_CONF_POINTER(PW_TYPE_STRING, &main_config.auth_badpass_msg), NULL},
	{ "msg_goodpass", FR_CONF_POINTER(PW_TYPE_STRING, &main_config.auth_goodpass_msg), NULL},
	{ "colourise",FR_CONF_POINTER(PW_TYPE_BOOLEAN, &do_colourise), NULL },
	{ "use_utc", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &log_dates_utc), NULL },
	{ "msg_denied", FR_CONF_POINTER(PW_TYPE_STRING, &main_config.denied_msg),
	  "You are already logged in - access denied" },

	{ NULL, -1, 0, NULL, NULL }
};


static const CONF_PARSER resources[] = {
	/*
	 *	Don't set a default here.  It's set in the code, below.  This means that
	 *	the config item will *not* get printed out in debug mode, so that no one knows
	 *	it exists.
	 */
	{ "talloc_pool_size", FR_CONF_POINTER(PW_TYPE_INTEGER, &main_config.talloc_pool_size), NULL },

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
	{ "name", FR_CONF_POINTER(PW_TYPE_STRING, &my_name), "radiusd"},
	{ "prefix", FR_CONF_POINTER(PW_TYPE_STRING, &prefix), "/usr/local"},
	{ "localstatedir", FR_CONF_POINTER(PW_TYPE_STRING, &localstatedir), "${prefix}/var"},
	{ "sbindir", FR_CONF_POINTER(PW_TYPE_STRING, &sbindir), "${prefix}/sbin"},
	{ "logdir", FR_CONF_POINTER(PW_TYPE_STRING, &radlog_dir), "${localstatedir}/log"},
	{ "run_dir", FR_CONF_POINTER(PW_TYPE_STRING, &run_dir), "${localstatedir}/run/${name}"},
	{ "libdir", FR_CONF_POINTER(PW_TYPE_STRING, &radlib_dir), "${prefix}/lib"},
	{ "radacctdir", FR_CONF_POINTER(PW_TYPE_STRING, &radacct_dir), "${logdir}/radacct" },
	{ "panic_action", FR_CONF_POINTER(PW_TYPE_STRING, &main_config.panic_action), NULL},
	{ "hostname_lookups", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &fr_dns_lookups), "no" },
	{ "max_request_time", FR_CONF_POINTER(PW_TYPE_INTEGER, &main_config.max_request_time), STRINGIFY(MAX_REQUEST_TIME) },
	{ "cleanup_delay", FR_CONF_POINTER(PW_TYPE_INTEGER, &main_config.cleanup_delay), STRINGIFY(CLEANUP_DELAY) },
	{ "max_requests", FR_CONF_POINTER(PW_TYPE_INTEGER, &main_config.max_requests), STRINGIFY(MAX_REQUESTS) },
	{ "pidfile", FR_CONF_POINTER(PW_TYPE_STRING, &main_config.pid_file), "${run_dir}/radiusd.pid"},
	{ "checkrad", FR_CONF_POINTER(PW_TYPE_STRING, &main_config.checkrad), "${sbindir}/checkrad" },

	{ "debug_level", FR_CONF_POINTER(PW_TYPE_INTEGER, &main_config.debug_level), "0"},

#ifdef WITH_PROXY
	{ "proxy_requests", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &main_config.proxy_requests), "yes" },
#endif
	{ "log", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) log_config_nodest },

	{ "resources", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) resources },

	/*
	 *	People with old configs will have these.  They are listed
	 *	AFTER the "log" section, so if they exist in radiusd.conf,
	 *	it will prefer "log_foo = bar" to "log { foo = bar }".
	 *	They're listed with default values of NULL, so that if they
	 *	DON'T exist in radiusd.conf, then the previously parsed
	 *	values for "log { foo = bar}" will be used.
	 */
	{ "log_auth", FR_CONF_POINTER(PW_TYPE_BOOLEAN | PW_TYPE_DEPRECATED, &main_config.log_auth), NULL },
	{ "log_auth_badpass", FR_CONF_POINTER(PW_TYPE_BOOLEAN | PW_TYPE_DEPRECATED, &main_config.log_auth_badpass), NULL },
	{ "log_auth_goodpass", FR_CONF_POINTER(PW_TYPE_BOOLEAN | PW_TYPE_DEPRECATED, &main_config.log_auth_goodpass), NULL },
	{ "log_stripped_names", FR_CONF_POINTER(PW_TYPE_BOOLEAN | PW_TYPE_DEPRECATED, &log_stripped_names), NULL },

	{  "security", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) security_config },

	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER bootstrap_security_config[] = {
#ifdef HAVE_SETUID
	{ "user",  FR_CONF_POINTER(PW_TYPE_STRING, &uid_name), NULL },
	{ "group", FR_CONF_POINTER(PW_TYPE_STRING, &gid_name), NULL },
#endif
	{ "chroot",  FR_CONF_POINTER(PW_TYPE_STRING, &chroot_dir), NULL },
	{ "allow_core_dumps", FR_CONF_POINTER(PW_TYPE_BOOLEAN, &allow_core_dumps), "no" },

	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER bootstrap_config[] = {
	{  "security", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) bootstrap_security_config },

	/*
	 *	For backwards compatibility.
	 */
#ifdef HAVE_SETUID
	{ "user",  FR_CONF_POINTER(PW_TYPE_STRING | PW_TYPE_DEPRECATED, &uid_name), NULL },
	{ "group",  FR_CONF_POINTER(PW_TYPE_STRING | PW_TYPE_DEPRECATED, &gid_name), NULL },
#endif
	{ "chroot",  FR_CONF_POINTER(PW_TYPE_STRING | PW_TYPE_DEPRECATED, &chroot_dir), NULL },
	{ "allow_core_dumps", FR_CONF_POINTER(PW_TYPE_BOOLEAN | PW_TYPE_DEPRECATED, &allow_core_dumps), NULL },

	{ NULL, -1, 0, NULL, NULL }
};

static size_t config_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	size_t len = 0;
	static char const disallowed[] = "%{}\\'\"`";

	while (in[0]) {
		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32)) {
			if (outlen <= 3) break;

			snprintf(out, outlen, "=%02X", (unsigned char) in[0]);
			in++;
			out += 3;
			outlen -= 3;
			len += 3;
			continue;

		} else if (strchr(disallowed, *in) != NULL) {
			if (outlen <= 2) break;

			out[0] = '\\';
			out[1] = *in;
			in++;
			out += 2;
			outlen -= 2;
			len += 2;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (outlen <= 1) {
			break;
		}

		/*
		 *	Allowed character.
		 */
		*out = *in;
		out++;
		in++;
		outlen--;
		len++;
	}
	*out = '\0';
	return len;
}

/*
 *	Xlat for %{config:section.subsection.attribute}
 */
static ssize_t xlat_config(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen)
{
	char const *value;
	CONF_PAIR *cp;
	CONF_ITEM *ci;
	char buffer[1024];

	/*
	 *	Expand it safely.
	 */
	if (radius_xlat(buffer, sizeof(buffer), request, fmt, config_escape_func, NULL) < 0) {
		return 0;
	}

	ci = cf_reference_item(request->root->config,
			       request->root->config, buffer);
	if (!ci || !cf_item_is_pair(ci)) {
		REDEBUG("Config item \"%s\" does not exist", fmt);
		*out = '\0';
		return -1;
	}

	cp = cf_item_to_pair(ci);

	/*
	 *  Ensure that we only copy what's necessary.
	 *
	 *  If 'outlen' is too small, then the output is chopped to fit.
	 */
	value = cf_pair_value(cp);
	if (!value) {
		out[0] = '\0';
		return 0;
	}

	if (outlen > strlen(value)) {
		outlen = strlen(value) + 1;
	}

	strlcpy(out, value, outlen);

	return strlen(out);
}


/*
 *	Xlat for %{client:foo}
 */
static ssize_t xlat_client(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen)
{
	char const *value = NULL;
	CONF_PAIR *cp;

	if (!fmt || !out || (outlen < 1)) return 0;

	if (!request->client) {
		RWDEBUG("No client associated with this request");
		*out = '\0';
		return 0;
	}

	cp = cf_pair_find(request->client->cs, fmt);
	if (!cp || !(value = cf_pair_value(cp))) {
		if (strcmp(fmt, "shortname") == 0) {
			strlcpy(out, request->client->shortname, outlen);
			return strlen(out);
		}
		*out = '\0';
		return 0;
	}

	strlcpy(out, value, outlen);

	return strlen(out);
}

/*
 *	Xlat for %{getclient:<ipaddr>.foo}
 */
static ssize_t xlat_getclient(UNUSED void *instance, REQUEST *request, char const *fmt, char *out, size_t outlen)
{
	char const *value = NULL;
	char buffer[INET6_ADDRSTRLEN], *q;
	char const *p = fmt;
	fr_ipaddr_t ip;
	CONF_PAIR *cp;
	RADCLIENT *client = NULL;

	if (!fmt || !out || (outlen < 1)) return 0;

	q = strrchr(p, '.');
	if (!q || (q == p) || (((size_t)(q - p)) > sizeof(buffer))) {
		REDEBUG("Invalid client string");
		goto error;
	}

	strlcpy(buffer, p, (q + 1) - p);
	if (fr_pton(&ip, buffer, -1, false) < 0) {
		REDEBUG("\"%s\" is not a valid IPv4 or IPv6 address", buffer);
		goto error;
	}

	fmt = q + 1;

	client = client_find(NULL, &ip, IPPROTO_IP);
	if (!client) {
		RDEBUG("No client found with IP \"%s\"", buffer);
		*out = '\0';
		return 0;
	}

	cp = cf_pair_find(client->cs, fmt);
	if (!cp || !(value = cf_pair_value(cp))) {
		if (strcmp(fmt, "shortname") == 0) {
			strlcpy(out, request->client->shortname, outlen);
			return strlen(out);
		}
		*out = '\0';
		return 0;
	}

	strlcpy(out, value, outlen);
	return strlen(out);

error:
	*out = '\0';
	return -1;
}

#ifdef HAVE_SETUID
/*
 *  Do chroot, if requested.
 *
 *  Switch UID and GID to what is specified in the config file
 */
static int switch_users(CONF_SECTION *cs)
{
	/*
	 *	Get the current maximum for core files.  Do this
	 *	before anything else so as to ensure it's properly
	 *	initialized.
	 */
	if (fr_set_dumpable_init() < 0) {
		fr_perror("radiusd");
		return 0;
	}

	/*
	 *	Don't do chroot/setuid/setgid if we're in debugging
	 *	as non-root.
	 */
	if (rad_debug_lvl && (getuid() != 0)) return 1;

	if (cf_section_parse(cs, NULL, bootstrap_config) < 0) {
		fprintf(stderr, "radiusd: Error: Failed to parse user/group information.\n");
		return 0;
	}


#ifdef HAVE_GRP_H
	/*  Set GID.  */
	if (gid_name) {
		struct group *gr;

		gr = getgrnam(gid_name);
		if (gr == NULL) {
			fprintf(stderr, "%s: Cannot get ID for group %s: %s\n",
				progname, gid_name, fr_syserror(errno));
			return 0;
		}
		server_gid = gr->gr_gid;
	} else {
		server_gid = getgid();
	}
#endif

	/*  Set UID.  */
	if (uid_name) {
		struct passwd *user;

		if (rad_getpwnam(cs, &user, uid_name) < 0) {
			fprintf(stderr, "%s: Cannot get passwd entry for user %s: %s\n",
				progname, uid_name, fr_strerror());
			return 0;
		}

		if (getuid() == user->pw_uid) {
			uid_name = NULL;
		} else {

			server_uid = user->pw_uid;
#ifdef HAVE_INITGROUPS
			if (initgroups(uid_name, server_gid) < 0) {
				fprintf(stderr, "%s: Cannot initialize supplementary group list for user %s: %s\n",
					progname, uid_name, fr_syserror(errno));
				talloc_free(user);
				return 0;
			}
#endif
		}
		talloc_free(user);
	} else {
		server_uid = getuid();
	}

	if (chroot_dir) {
		if (chroot(chroot_dir) < 0) {
			fprintf(stderr, "%s: Failed to perform chroot %s: %s",
				progname, chroot_dir, fr_syserror(errno));
			return 0;
		}

		/*
		 *	Note that we leave chdir alone.  It may be
		 *	OUTSIDE of the root.  This allows us to read
		 *	the configuration from "-d ./etc/raddb", with
		 *	the chroot as "./chroot/" for example.  After
		 *	the server has been loaded, it does a "cd
		 *	${logdir}" below, so that core files (if any)
		 *	go to a logging directory.
		 *
		 *	This also allows the configuration of the
		 *	server to be outside of the chroot.  If the
		 *	server is statically linked, then the only
		 *	things needed inside of the chroot are the
		 *	logging directories.
		 */
	}

#ifdef HAVE_GRP_H
	/*  Set GID.  */
	if (gid_name && (setgid(server_gid) < 0)) {
		fprintf(stderr, "%s: Failed setting group to %s: %s",
			progname, gid_name, fr_syserror(errno));
		return 0;
	}
#endif

	/*
	 *	Just before losing root permissions, ensure that the
	 *	log files have the correct owner && group.
	 *
	 *	We have to do this because the log file MAY have been
	 *	specified on the command-line.
	 */
	if (uid_name || gid_name) {
		if ((default_log.dst == L_DST_FILES) &&
		    (default_log.fd < 0)) {
			default_log.fd = open(main_config.log_file,
					      O_WRONLY | O_APPEND | O_CREAT, 0640);
			if (default_log.fd < 0) {
				fprintf(stderr, "radiusd: Failed to open log file %s: %s\n", main_config.log_file, fr_syserror(errno));
				return 0;
			}

			if (chown(main_config.log_file, server_uid, server_gid) < 0) {
				fprintf(stderr, "%s: Cannot change ownership of log file %s: %s\n",
					progname, main_config.log_file, fr_syserror(errno));
				return 0;
			}
		}
	}

	if (uid_name) {
		rad_suid_set_down_uid(server_uid);
		rad_suid_down();
	}

	/*
	 *	This also clears the dumpable flag if core dumps
	 *	aren't allowed.
	 */
	if (fr_set_dumpable(allow_core_dumps) < 0) {
		ERROR("%s", fr_strerror());
	}

	if (allow_core_dumps) {
		INFO("Core dumps are enabled");
	}

	return 1;
}
#endif	/* HAVE_SETUID */

/** Set the global radius config directory.
 *
 * @param ctx Where to allocate the memory for the path string.
 * @param path to config dir root e.g. /usr/local/etc/raddb
 */
void set_radius_dir(TALLOC_CTX *ctx, char const *path)
{
	if (radius_dir) {
		char *p;

		memcpy(&p, &radius_dir, sizeof(p));
		talloc_free(p);
		radius_dir = NULL;
	}
	if (path) radius_dir = talloc_typed_strdup(ctx, path);
}

/** Get the global radius config directory.
 *
 * @return the global radius config directory.
 */
char const *get_radius_dir(void)
{
	return radius_dir;
}

/*
 *	Read config files.
 *
 *	This function can ONLY be called from the main server process.
 */
int main_config_init(void)
{
	char const *p = NULL;
	CONF_SECTION *cs, *subcs;
	struct stat statbuf;
	cached_config_t *cc;
	char buffer[1024];

	if (stat(radius_dir, &statbuf) < 0) {
		ERROR("Errors reading %s: %s",
		       radius_dir, fr_syserror(errno));
		return -1;
	}

#ifdef S_IWOTH
	if ((statbuf.st_mode & S_IWOTH) != 0) {
		ERROR("Configuration directory %s is globally writable.  Refusing to start due to insecure configuration.",
		       radius_dir);
	  return -1;
	}
#endif

#if 0 && defined(S_IROTH)
	if (statbuf.st_mode & S_IROTH != 0) {
		ERROR("Configuration directory %s is globally readable.  Refusing to start due to insecure configuration.",
		       radius_dir);
		return -1;
	}
#endif
	INFO("Starting - reading configuration files ...");

	/*
	 *	We need to load the dictionaries before reading the
	 *	configuration files.  This is because of the
	 *	pre-compilation in conffile.c.  That should probably
	 *	be fixed to be done as a second stage.
	 */
	if (!main_config.dictionary_dir) {
		main_config.dictionary_dir = talloc_typed_strdup(NULL, DICTDIR);
	}

	/*
	 *	About sizeof(REQUEST) + sizeof(RADIUS_PACKET) * 2 + sizeof(VALUE_PAIR) * 400
	 *
	 *	Which should be enough for many configurations.
	 */
	main_config.talloc_pool_size = 32 * 1024; /* default */

	/*
	 *	Read the distribution dictionaries first, then
	 *	the ones in raddb.
	 */
	DEBUG2("including dictionary file %s/%s", main_config.dictionary_dir, RADIUS_DICTIONARY);
	if (dict_init(main_config.dictionary_dir, RADIUS_DICTIONARY) != 0) {
		ERROR("Errors reading dictionary: %s",
		      fr_strerror());
		return -1;
	}

#define DICT_READ_OPTIONAL(_d, _n) \
do {\
	switch (dict_read(_d, _n)) {\
	case -1:\
		ERROR("Errors reading %s/%s: %s", _d, _n, fr_strerror());\
		return -1;\
	case 0:\
		DEBUG2("including dictionary file %s/%s", _d,_n);\
		break;\
	default:\
		break;\
	}\
} while (0)

	/*
	 *	Try to load protocol-specific dictionaries.  It's OK
	 *	if they don't exist.
	 */
#ifdef WITH_DHCP
	DICT_READ_OPTIONAL(main_config.dictionary_dir, "dictionary.dhcp");
#endif

#ifdef WITH_VMPS
	DICT_READ_OPTIONAL(main_config.dictionary_dir, "dictionary.vqp");
#endif

	/*
	 *	It's OK if this one doesn't exist.
	 */
	DICT_READ_OPTIONAL(radius_dir, RADIUS_DICTIONARY);

	cs = cf_section_alloc(NULL, "main", NULL);
	if (!cs) return -1;

	/*
	 *	Add a 'feature' subsection off the main config
	 *	We check if it's defined first, as the user may
	 *	have defined their own feature flags, or want
	 *	to manually override the ones set by modules
	 *	or the server.
	 */
	subcs = cf_section_sub_find(cs, "feature");
	if (!subcs) {
		subcs = cf_section_alloc(cs, "feature", NULL);
		if (!subcs) return -1;

		cf_section_add(cs, subcs);
	}
	version_init_features(subcs);

	/*
	 *	Add a 'version' subsection off the main config
	 *	We check if it's defined first, this is for
	 *	backwards compatibility.
	 */
	subcs = cf_section_sub_find(cs, "version");
	if (!subcs) {
		subcs = cf_section_alloc(cs, "version", NULL);
		if (!subcs) return -1;
		cf_section_add(cs, subcs);
	}
	version_init_numbers(subcs);

	/* Read the configuration file */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s.conf",
		 radius_dir, main_config.name);
	if (cf_file_read(cs, buffer) < 0) {
		ERROR("Errors reading or parsing %s", buffer);
		talloc_free(cs);

		return -1;
	}

	/*
	 *	If there was no log destination set on the command line,
	 *	set it now.
	 */
	if (default_log.dst == L_DST_NULL) {
		if (cf_section_parse(cs, NULL, serverdest_config) < 0) {
			fprintf(stderr, "radiusd: Error: Failed to parse log{} section.\n");
			cf_file_free(cs);
			return -1;
		}

		if (!radlog_dest) {
			fprintf(stderr, "radiusd: Error: No log destination specified.\n");
			cf_file_free(cs);
			return -1;
		}

		default_log.dst = fr_str2int(log_str2dst, radlog_dest,
					      L_DST_NUM_DEST);
		if (default_log.dst == L_DST_NUM_DEST) {
			fprintf(stderr, "radiusd: Error: Unknown log_destination %s\n",
				radlog_dest);
			cf_file_free(cs);
			return -1;
		}

		if (default_log.dst == L_DST_SYSLOG) {
			/*
			 *	Make sure syslog_facility isn't NULL
			 *	before using it
			 */
			if (!syslog_facility) {
				fprintf(stderr, "radiusd: Error: Syslog chosen but no facility was specified\n");
				cf_file_free(cs);
				return -1;
			}
			main_config.syslog_facility = fr_str2int(syslog_facility_table, syslog_facility, -1);
			if (main_config.syslog_facility < 0) {
				fprintf(stderr, "radiusd: Error: Unknown syslog_facility %s\n",
					syslog_facility);
				cf_file_free(cs);
				return -1;
			}

#ifdef HAVE_SYSLOG_H
			/*
			 *	Call openlog only once, when the
			 *	program starts.
			 */
			openlog(progname, LOG_PID, main_config.syslog_facility);
#endif

		} else if (default_log.dst == L_DST_FILES) {
			if (!main_config.log_file) {
				fprintf(stderr, "radiusd: Error: Specified \"files\" as a log destination, but no log filename was given!\n");
				cf_file_free(cs);
				return -1;
			}
		}
	}

#ifdef HAVE_SETUID
	/*
	 *	Switch users as early as possible.
	 */
	if (!switch_users(cs)) fr_exit(1);
#endif

	/*
	 *	Open the log file AFTER switching uid / gid.  If we
	 *	did switch uid/gid, then the code in switch_users()
	 *	took care of setting the file permissions correctly.
	 */
	if ((default_log.dst == L_DST_FILES) &&
	    (default_log.fd < 0)) {
		default_log.fd = open(main_config.log_file,
					    O_WRONLY | O_APPEND | O_CREAT, 0640);
		if (default_log.fd < 0) {
			fprintf(stderr, "radiusd: Failed to open log file %s: %s\n", main_config.log_file, fr_syserror(errno));
			cf_file_free(cs);
			return -1;
		}
	}

	/*
	 *	This allows us to figure out where, relative to
	 *	radiusd.conf, the other configuration files exist.
	 */
	if (cf_section_parse(cs, NULL, server_config) < 0) return -1;

	/*
	 *	We ignore colourization of output until after the
	 *	configuration files have been parsed.
	 */
	p = getenv("TERM");
	if (do_colourise && p && isatty(default_log.fd) && strstr(p, "xterm")) {
		default_log.colourise = true;
	} else {
		default_log.colourise = false;
	}

	/*
	 *	Starting the server, WITHOUT "-x" on the
	 *	command-line: use whatever is in the config
	 *	file.
	 */
	if (rad_debug_lvl == 0) {
		rad_debug_lvl = main_config.debug_level;
	}
	fr_debug_lvl = rad_debug_lvl;

	FR_INTEGER_COND_CHECK("max_request_time", main_config.max_request_time,
			      (main_config.max_request_time != 0), 100);

	/*
	 *	reject_delay can be zero.  OR 1 though 10.
	 */
	if ((main_config.reject_delay.tv_sec != 0) || (main_config.reject_delay.tv_usec != 0)) {
		FR_TIMEVAL_BOUND_CHECK("reject_delay", &main_config.reject_delay, >=, 1, 0);
	}
	FR_TIMEVAL_BOUND_CHECK("reject_delay", &main_config.reject_delay, <=, 10, 0);

	FR_INTEGER_BOUND_CHECK("cleanup_delay", main_config.cleanup_delay, <=, 10);

	FR_INTEGER_BOUND_CHECK("resources.talloc_pool_size", main_config.talloc_pool_size, >=, 16 * 1024);
	FR_INTEGER_BOUND_CHECK("resources.talloc_pool_size", main_config.talloc_pool_size, <=, 1024 * 1024);

	/*
	 * Set default initial request processing delay to 1/3 of a second.
	 * Will be updated by the lowest response window across all home servers,
	 * if it is less than this.
	 */
	main_config.init_delay.tv_sec = 0;
	main_config.init_delay.tv_usec = 2* (1000000 / 3);

	/*
	 *	Free the old configuration items, and replace them
	 *	with the new ones.
	 *
	 *	Note that where possible, we do atomic switch-overs,
	 *	to ensure that the pointers are always valid.
	 */
	rad_assert(main_config.config == NULL);
	root_config = main_config.config = cs;

	DEBUG2("%s: #### Loading Realms and Home Servers ####", main_config.name);
	if (!realms_init(cs)) {
		return -1;
	}

	DEBUG2("%s: #### Loading Clients ####", main_config.name);
	if (!client_list_parse_section(cs, false)) {
		return -1;
	}

	/*
	 *  Register the %{config:section.subsection} xlat function.
	 */
	xlat_register("config", xlat_config, NULL, NULL);
	xlat_register("client", xlat_client, NULL, NULL);
	xlat_register("getclient", xlat_getclient, NULL, NULL);

	/*
	 *  Go update our behaviour, based on the configuration
	 *  changes.
	 */

	/*
	 *	Sanity check the configuration for internal
	 *	consistency.
	 */
	FR_TIMEVAL_BOUND_CHECK("reject_delay", &main_config.reject_delay, <=, main_config.cleanup_delay, 0);

	if (chroot_dir) {
		if (chdir(radlog_dir) < 0) {
			ERROR("Failed to 'chdir %s' after chroot: %s",
			       radlog_dir, fr_syserror(errno));
			return -1;
		}
	}

	cc = talloc_zero(NULL, cached_config_t);
	if (!cc) return -1;

	cc->cs = talloc_steal(cc ,cs);
	rad_assert(cs_cache == NULL);
	cs_cache = cc;

	/* Clear any unprocessed configuration errors */
	(void) fr_strerror();

	return 0;
}

/*
 *	Free the configuration.  Called only when the server is exiting.
 */
int main_config_free(void)
{
	virtual_servers_free(0);

	/*
	 *	Clean up the configuration data
	 *	structures.
	 */
	client_list_free(NULL);
	realms_free();
	listen_free(&main_config.listen);

	/*
	 *	Frees current config and any previous configs.
	 */
	TALLOC_FREE(cs_cache);
	dict_free();

	return 0;
}

void hup_logfile(void)
{
	int fd, old_fd;

	if (default_log.dst != L_DST_FILES) return;

	fd = open(main_config.log_file,
		  O_WRONLY | O_APPEND | O_CREAT, 0640);
	if (fd >= 0) {
		/*
		 *	Atomic swap. We'd like to keep the old
		 *	FD around so that callers don't
		 *	suddenly find the FD closed, and the
		 *	writes go nowhere.  But that's hard to
		 *	do.  So... we have the case where a
		 *	log message *might* be lost on HUP.
		 */
		old_fd = default_log.fd;
		default_log.fd = fd;
		close(old_fd);
	}
}

void main_config_hup(void)
{
	cached_config_t *cc;
	CONF_SECTION *cs;
	char buffer[1024];

	INFO("HUP - Re-reading configuration files");

	cs = cf_section_alloc(NULL, "main", NULL);
	if (!cs) return;

	/* Read the configuration file */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s.conf",
		 radius_dir, main_config.name);
	if (cf_file_read(cs, buffer) < 0) {
		ERROR("Failed to re-read or parse %s", buffer);
		talloc_free(cs);
		return;
	}

	cc = talloc_zero(cs_cache, cached_config_t);
	if (!cc) {
		ERROR("Out of memory");
		return;
	}

	/*
	 *	Save the current configuration.  Note that we do NOT
	 *	free older ones.  We should probably do so at some
	 *	point.  Doing so will require us to mark which modules
	 *	are still in use, and which aren't.  Modules that
	 *	can't be HUPed always use the original configuration.
	 *	Modules that can be HUPed use one of the newer
	 *	configurations.
	 */
	cc->created = time(NULL);
	cc->cs = talloc_steal(cc, cs);
	cc->next = cs_cache;
	cs_cache = cc;

	/*
	 *	Re-open the log file.  If we can't, then keep logging
	 *	to the old log file.
	 *
	 *	The "open log file" code is here rather than in log.c,
	 *	because it makes that function MUCH simpler.
	 */
	hup_logfile();

	INFO("HUP - loading modules");

	/*
	 *	Prefer the new module configuration.
	 */
	modules_hup(cf_section_sub_find(cs, "modules"));

	/*
	 *	Load new servers BEFORE freeing old ones.
	 */
	virtual_servers_load(cs);

	virtual_servers_free(cc->created - (main_config.max_request_time * 4));
}
