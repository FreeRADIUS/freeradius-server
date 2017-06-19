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
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/map_proc.h>
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
extern fr_log_t		debug_log;

fr_cond_t		*debug_condition = NULL;		//!< Condition used to mark packets up for checking.
fr_log_t		debug_log = { .fd = -1, .dst = L_DST_NULL };
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
static char const	*sbindir = NULL;
static char const	*run_dir = NULL;
static char const	*syslog_facility = NULL;
static bool		do_colourise = false;

static bool		*log_timestamp = false;
static bool		log_timestamp_is_set = false;

static char const	*radius_dir = NULL;	//!< Path to raddb directory

/**********************************************************************
 *
 *	We need to figure out where the logs go, before doing anything
 *	else.  This is so that the log messages go to the correct
 *	place.
 *
 *	BUT, we want the settings from the command line to over-ride
 *	the ones in the configuration file.  So, these items are
 *	parsed ONLY if there is no "-l foo" on the command line.
 *
 **********************************************************************/

/*
 *	Log destinations
 */
static const CONF_PARSER initial_log_subsection_config[] = {
	{ FR_CONF_POINTER("destination", FR_TYPE_STRING, &radlog_dest), .dflt = "files" },
	{ FR_CONF_POINTER("syslog_facility", FR_TYPE_STRING, &syslog_facility), .dflt = STRINGIFY(0) },

	{ FR_CONF_POINTER("localstatedir", FR_TYPE_STRING, &localstatedir), .dflt = "${prefix}/var"},
	{ FR_CONF_POINTER("logdir", FR_TYPE_STRING, &radlog_dir), .dflt = "${localstatedir}/log"},
	{ FR_CONF_POINTER("file", FR_TYPE_STRING, &main_config.log_file), .dflt = "${logdir}/radius.log" },
	{ FR_CONF_POINTER("requests", FR_TYPE_STRING | FR_TYPE_DEPRECATED, &default_log.file) },
	CONF_PARSER_TERMINATOR
};


/*
 *	Basic configuration for the server.
 */
static const CONF_PARSER initial_logging_config[] = {
	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) initial_log_subsection_config },

	{ FR_CONF_POINTER("prefix", FR_TYPE_STRING, &prefix), .dflt = "/usr/local" },

	{ FR_CONF_POINTER("log_file", FR_TYPE_STRING, &main_config.log_file) },
	{ FR_CONF_POINTER("log_destination", FR_TYPE_STRING, &radlog_dest) },
	{ FR_CONF_POINTER("use_utc", FR_TYPE_BOOL, &log_dates_utc) },
	{ FR_CONF_IS_SET_POINTER("timestamp", FR_TYPE_BOOL, &log_timestamp) },
	CONF_PARSER_TERMINATOR
};


/**********************************************************************
 *
 *	Now that we've parsed the log destination, AND the security
 *	items, we can parse the rest of the configuration items.
 *
 **********************************************************************/
static const CONF_PARSER log_config[] = {
	{ FR_CONF_POINTER("stripped_names", FR_TYPE_BOOL, &log_stripped_names), .dflt = "no" },
	{ FR_CONF_POINTER("auth", FR_TYPE_BOOL, &main_config.log_auth), .dflt = "no" },
	{ FR_CONF_POINTER("auth_badpass", FR_TYPE_BOOL, &main_config.log_auth_badpass), .dflt = "no" },
	{ FR_CONF_POINTER("auth_goodpass", FR_TYPE_BOOL, &main_config.log_auth_goodpass), .dflt = "no" },
	{ FR_CONF_POINTER("msg_badpass", FR_TYPE_STRING, &main_config.auth_badpass_msg) },
	{ FR_CONF_POINTER("msg_goodpass", FR_TYPE_STRING, &main_config.auth_goodpass_msg) },
	{ FR_CONF_POINTER("colourise", FR_TYPE_BOOL, &do_colourise) },
	{ FR_CONF_POINTER("timestamp", FR_TYPE_BOOL, &log_timestamp) },
	{ FR_CONF_POINTER("use_utc", FR_TYPE_BOOL, &log_dates_utc) },
	{ FR_CONF_POINTER("msg_denied", FR_TYPE_STRING, &main_config.denied_msg), .dflt = "You are already logged in - access denied" },
#ifdef WITH_CONF_WRITE
	{ FR_CONF_POINTER("write_dir", FR_TYPE_STRING, &main_config.write_dir), .dflt = NULL },
#endif
	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER resources[] = {
	/*
	 *	Don't set a default here.  It's set in the code, below.  This means that
	 *	the config item will *not* get printed out in debug mode, so that no one knows
	 *	it exists.
	 */
	{ FR_CONF_POINTER("talloc_pool_size", FR_TYPE_SIZE, &main_config.talloc_pool_size) },			/* DO NOT SET DEFAULT */
	{ FR_CONF_POINTER("talloc_memory_limit", FR_TYPE_SIZE, &main_config.talloc_memory_limit) },		/* DO NOT SET DEFAULT */
	{ FR_CONF_POINTER("talloc_memory_report", FR_TYPE_BOOL, &main_config.talloc_memory_report) },	/* DO NOT SET DEFAULT */
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER server_config[] = {
	/*
	 *	FIXME: 'prefix' is the ONLY one which should be
	 *	configured at compile time.  Hard-coding it here is
	 *	bad.  It will be cleaned up once we clean up the
	 *	hard-coded defines for the locations of the various
	 *	files.
	 */
	{ FR_CONF_POINTER("prefix", FR_TYPE_STRING, &prefix), .dflt = "/usr/local" },
	{ FR_CONF_POINTER("localstatedir", FR_TYPE_STRING, &localstatedir), .dflt = "${prefix}/var"},
	{ FR_CONF_POINTER("sbindir", FR_TYPE_STRING, &sbindir), .dflt = "${prefix}/sbin"},
	{ FR_CONF_POINTER("logdir", FR_TYPE_STRING, &radlog_dir), .dflt = "${localstatedir}/log"},
	{ FR_CONF_POINTER("run_dir", FR_TYPE_STRING, &run_dir), .dflt = "${localstatedir}/run/${name}"},
	{ FR_CONF_POINTER("libdir", FR_TYPE_STRING, &radlib_dir), .dflt = "${prefix}/lib"},
	{ FR_CONF_POINTER("radacctdir", FR_TYPE_STRING, &radacct_dir), .dflt = "${logdir}/radacct" },
	{ FR_CONF_POINTER("panic_action", FR_TYPE_STRING, &main_config.panic_action) },
	{ FR_CONF_POINTER("hostname_lookups", FR_TYPE_BOOL, &fr_dns_lookups), .dflt = "no" },
	{ FR_CONF_POINTER("max_request_time", FR_TYPE_UINT32, &main_config.max_request_time), .dflt = STRINGIFY(MAX_REQUEST_TIME) },
	{ FR_CONF_POINTER("cleanup_delay", FR_TYPE_UINT32, &main_config.cleanup_delay), .dflt = STRINGIFY(CLEANUP_DELAY) },
	{ FR_CONF_POINTER("continuation_timeout", FR_TYPE_UINT32, &main_config.continuation_timeout), .dflt = "15" },
	{ FR_CONF_POINTER("max_requests", FR_TYPE_UINT32, &main_config.max_requests), .dflt = STRINGIFY(MAX_REQUESTS) },
	{ FR_CONF_POINTER("pidfile", FR_TYPE_STRING, &main_config.pid_file), .dflt = "${run_dir}/radiusd.pid"},
	{ FR_CONF_POINTER("checkrad", FR_TYPE_STRING, &main_config.checkrad), .dflt = "${sbindir}/checkrad" },

	{ FR_CONF_POINTER("debug_level", FR_TYPE_UINT32, &main_config.debug_level), .dflt = "0" },

#ifdef WITH_PROXY
	{ FR_CONF_POINTER("proxy_requests", FR_TYPE_BOOL, &main_config.proxy_requests), .dflt = "yes" },
#endif
	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) log_config },

	{ FR_CONF_POINTER("resources", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) resources },

	/*
	 *	People with old configs will have these.  They are listed
	 *	AFTER the "log" section, so if they exist in radiusd.conf,
	 *	it will prefer "log_foo = bar" to "log { foo = bar }".
	 *	They're listed with default values of NULL, so that if they
	 *	DON'T exist in radiusd.conf, then the previously parsed
	 *	values for "log { foo = bar}" will be used.
	 */
	{ FR_CONF_POINTER("log_auth", FR_TYPE_BOOL | FR_TYPE_DEPRECATED, &main_config.log_auth) },
	{ FR_CONF_POINTER("log_auth_badpass", FR_TYPE_BOOL | FR_TYPE_DEPRECATED, &main_config.log_auth_badpass) },
	{ FR_CONF_POINTER("log_auth_goodpass", FR_TYPE_BOOL | FR_TYPE_DEPRECATED, &main_config.log_auth_goodpass) },
	{ FR_CONF_POINTER("log_stripped_names", FR_TYPE_BOOL | FR_TYPE_DEPRECATED, &log_stripped_names) },

	CONF_PARSER_TERMINATOR
};


/**********************************************************************
 *
 *	The next few items are here as a "bootstrap" for security.
 *	They allow the server to switch users, chroot, while still
 *	opening the various output files with the correct permission.
 *
 *	It's rare (or impossible) to have parse errors here, so we
 *	don't worry too much about that.  In contrast, when we parse
 *	the rest of the configuration, we CAN get parse errors.  We
 *	want THOSE parse errors to go to the log file, and we want the
 *	log file to have the correct permissions.
 *
 **********************************************************************/
static const CONF_PARSER bootstrap_security_config[] = {
#ifdef HAVE_SETUID
	{ FR_CONF_POINTER("user", FR_TYPE_STRING, &uid_name) },
	{ FR_CONF_POINTER("group", FR_TYPE_STRING, &gid_name) },
#endif
	{ FR_CONF_POINTER("chroot", FR_TYPE_STRING, &chroot_dir) },
	{ FR_CONF_POINTER("allow_core_dumps", FR_TYPE_BOOL, &allow_core_dumps), .dflt = "no" },

	{ FR_CONF_POINTER("max_attributes", FR_TYPE_UINT32, &fr_max_attributes), .dflt = STRINGIFY(0) },
	{ FR_CONF_POINTER("reject_delay", FR_TYPE_TIMEVAL, &main_config.reject_delay), .dflt = STRINGIFY(0) },
	{ FR_CONF_POINTER("status_server", FR_TYPE_BOOL, &main_config.status_server), .dflt = "no" },

	/*
	 *	No default, so it isn't printed in debug mode.
	 */
	{ FR_CONF_POINTER("tunnel_password_zeros", FR_TYPE_BOOL, &fr_tunnel_password_zeros) },

#ifdef ENABLE_OPENSSL_VERSION_CHECK
	{ FR_CONF_POINTER("allow_vulnerable_openssl", FR_TYPE_STRING, &main_config.allow_vulnerable_openssl), .dflt = "no" },
#endif
	{ FR_CONF_POINTER("server_id", FR_TYPE_UINT8, &main_config.state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER bootstrap_config[] = {
	{ FR_CONF_POINTER("security", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) bootstrap_security_config },

	{ FR_CONF_POINTER("prefix", FR_TYPE_STRING, &prefix), .dflt = "/usr/local" },
	{ FR_CONF_POINTER("localstatedir", FR_TYPE_STRING, &localstatedir), .dflt = "${prefix}/var"},

	{ FR_CONF_POINTER("run_dir", FR_TYPE_STRING, &run_dir), .dflt = "${localstatedir}/run/${name}"},

	/*
	 *	For backwards compatibility.
	 */
#ifdef HAVE_SETUID
	{ FR_CONF_POINTER("user", FR_TYPE_STRING | FR_TYPE_DEPRECATED, &uid_name) },
	{ FR_CONF_POINTER("group", FR_TYPE_STRING | FR_TYPE_DEPRECATED, &gid_name) },
#endif
	{ FR_CONF_POINTER("chroot", FR_TYPE_STRING | FR_TYPE_DEPRECATED, &chroot_dir) },
	{ FR_CONF_POINTER("allow_core_dumps", FR_TYPE_BOOL | FR_TYPE_DEPRECATED, &allow_core_dumps) },
	CONF_PARSER_TERMINATOR
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
static ssize_t xlat_config(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	char const *value;
	CONF_PAIR *cp;
	CONF_ITEM *ci;
	char buffer[1024];

	/*
	 *	Expand it safely.
	 */
	if (xlat_eval(buffer, sizeof(buffer), request, fmt, config_escape_func, NULL) < 0) return 0;

	ci = cf_reference_item(request->root->config,
			       request->root->config, buffer);
	if (!ci || !cf_item_is_pair(ci)) {
		REDEBUG("Config item \"%s\" does not exist", fmt);
		return -1;
	}

	cp = cf_item_to_pair(ci);

	/*
	 *  Ensure that we only copy what's necessary.
	 *
	 *  If 'outlen' is too small, then the output is chopped to fit.
	 */
	value = cf_pair_value(cp);
	if (!value) return 0;

	if (outlen > strlen(value)) outlen = strlen(value) + 1;

	strlcpy(*out, value, outlen);

	return strlen(*out);
}

/*
 *	Xlat for %{listen:foo}
 */
static ssize_t xlat_listen(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	char const *value = NULL;
	CONF_PAIR *cp;

	if (!request->listener) {
		RWDEBUG("No listener associated with this request");
		return 0;
	}

	cp = cf_pair_find(request->listener->cs, fmt);
	if (!cp || !(value = cf_pair_value(cp))) {
		RDEBUG("Listener does not contain config item \"%s\"", fmt);
		return 0;
	}

	strlcpy(*out, value, outlen);

	return strlen(*out);
}


#ifdef HAVE_SETUID
/*
 *  Do chroot, if requested.
 *
 *  Switch UID and GID to what is specified in the config file
 */
static int switch_users(CONF_SECTION *cs)
{
	bool do_suid = false;
	bool do_sgid = false;

	/*
	 *	Get the current maximum for core files.  Do this
	 *	before anything else so as to ensure it's properly
	 *	initialized.
	 */
	if (fr_set_dumpable_init() < 0) {
		fr_perror("%s", main_config.name);
		return 0;
	}

	if (cf_section_rules_push(cs, bootstrap_config) < 0) {
		fprintf(stderr, "%s: Error: Failed pushing parse rules for user/group information.\n",
			main_config.name);
		return 0;
	}

	if (cf_section_parse(NULL, NULL, cs) < 0) {
		fprintf(stderr, "%s: Error: Failed to parse user/group information.\n",
			main_config.name);
		return 0;
	}

	/*
	 *	Don't do chroot/setuid/setgid if we're in debugging
	 *	as non-root.
	 */
	if (rad_debug_lvl && (getuid() != 0)) return 1;

#ifdef HAVE_GRP_H
	/*
	 *	Get the correct GID for the server.
	 */
	server_gid = getgid();

	if (gid_name) {
		struct group *gr;

		gr = getgrnam(gid_name);
		if (!gr) {
			fprintf(stderr, "%s: Cannot get ID for group %s: %s\n",
				main_config.name, gid_name, fr_syserror(errno));
			return 0;
		}

		if (server_gid != gr->gr_gid) {
			server_gid = gr->gr_gid;
			do_sgid = true;
		}
	}
#endif

	/*
	 *	Get the correct UID for the server.
	 */
	server_uid = getuid();

	if (uid_name) {
		struct passwd *user;

		if (rad_getpwnam(cs, &user, uid_name) < 0) {
			fprintf(stderr, "%s: Cannot get passwd entry for user %s: %s\n",
				main_config.name, uid_name, fr_strerror());
			return 0;
		}

		/*
		 *	We're not the correct user.  Go set that.
		 */
		if (server_uid != user->pw_uid) {
			server_uid = user->pw_uid;
			do_suid = true;
#ifdef HAVE_INITGROUPS
			if (initgroups(uid_name, server_gid) < 0) {
				fprintf(stderr, "%s: Cannot initialize supplementary group list for user %s: %s\n",
					main_config.name, uid_name, fr_syserror(errno));
				talloc_free(user);
				return 0;
			}
#endif
		}

		talloc_free(user);
	}

	/*
	 *	Set the user/group we're going to use
	 *	to check read permissions on configuration files.
	 */
	cf_file_check_user(server_uid ? server_uid : (uid_t)-1, server_gid ? server_gid : (gid_t)-1);

	/*
	 *	Do chroot BEFORE changing UIDs.
	 */
	if (chroot_dir) {
		if (chroot(chroot_dir) < 0) {
			fprintf(stderr, "%s: Failed to perform chroot %s: %s",
				main_config.name, chroot_dir, fr_syserror(errno));
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
	/*
	 *	Set the GID.  Don't bother checking it.
	 */
	if (do_sgid) {
		if (setgid(server_gid) < 0){
			fprintf(stderr, "%s: Failed setting group to %s: %s",
				main_config.name, gid_name, fr_syserror(errno));
			return 0;
		}
	}
#endif

	/*
	 *	The directories for PID files and logs must exist.  We
	 *	need to create them if we're told to write files to
	 *	those directories.
	 *
	 *	Because this creation is new in 3.0.9, it's a soft
	 *	fail.
	 *
	 */
	if (main_config.write_pid) {
		char *my_dir;

		/*
		 *	Control sockets may be accessible by users
		 *	other than the freeradius user, so we need
		 *	to allow 'other' to traverse the run
		 *	directory.
		 *
		 *	The freeradius user should be the only one
		 *	allowed to write to this directory however.
		 */
		my_dir = talloc_strdup(NULL, run_dir);
		if (rad_mkdir(my_dir, 0755, server_uid, server_gid) < 0) {
			DEBUG("Failed to create run_dir %s: %s",
			      my_dir, strerror(errno));
		}
		talloc_free(my_dir);
	}

	if ((default_log.dst == L_DST_FILES) && radlog_dir) {
		char *my_dir;

		/*
		 *	Every other Linux daemon allows 'other'
		 *	to traverse the log directory.  That doesn't
		 *	mean the actual files should be world
		 *	readable.
		 */
		my_dir = talloc_strdup(NULL, radlog_dir);
		if (rad_mkdir(my_dir, 0755, server_uid, server_gid) < 0) {
			DEBUG("Failed to create logdir %s: %s",
			      my_dir, strerror(errno));
		}
		talloc_free(my_dir);
	}

	/*
	 *	If we don't already have a log file open, open one
	 *	now.  We may not have been logging anything yet.  The
	 *	server normally starts up fairly quietly.
	 */
	if ((default_log.dst == L_DST_FILES) &&
	    (default_log.fd < 0)) {
		default_log.fd = open(main_config.log_file,
				      O_WRONLY | O_APPEND | O_CREAT, 0640);
		if (default_log.fd < 0) {
			fprintf(stderr, "%s: Failed to open log file %s: %s\n",
				main_config.name, main_config.log_file, fr_syserror(errno));
			return 0;
		}
	}

	/*
	 *	If we need to change UID, ensure that the log files
	 *	have the correct owner && group.
	 *
	 *	We have to do this because some log files MAY already
	 *	have been written as root.  We need to change them to
	 *	have the correct ownership before proceeding.
	 */
	if ((do_suid || do_sgid) &&
	    (default_log.dst == L_DST_FILES)) {
		if (fchown(default_log.fd, server_uid, server_gid) < 0) {
			fprintf(stderr, "%s: Cannot change ownership of log file %s: %s\n",
				main_config.name, main_config.log_file, fr_syserror(errno));
			return 0;
		}
	}

	/*
	 *	Once we're done with all of the privileged work,
	 *	permanently change the UID.
	 */
	if (do_suid) {
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
	char const		*p = NULL;
	CONF_SECTION		*cs, *subcs;
	struct stat		statbuf;
	cached_config_t 	*cc;
	char			buffer[1024];

	if (stat(radius_dir, &statbuf) < 0) {
		ERROR("Error reading %s: %s",
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
	 *	pre-compilation in conf_file.c.  That should probably
	 *	be fixed to be done as a second stage.
	 */
	if (!main_config.dictionary_dir) main_config.dictionary_dir = talloc_typed_strdup(NULL, DICTDIR);

	/*
	 *	About sizeof(REQUEST) + sizeof(RADIUS_PACKET) * 2 + sizeof(VALUE_PAIR) * 400
	 *
	 *	Which should be enough for many configurations.
	 */
	main_config.talloc_pool_size = 8 * 1024; /* default */

	/*
	 *	Read the distribution dictionaries first, then
	 *	the ones in raddb.
	 */
	DEBUG2("Including dictionary file \"%s/%s\"", main_config.dictionary_dir, FR_DICTIONARY_FILE);
	if (fr_dict_from_file(NULL, &main_config.dict, main_config.dictionary_dir, FR_DICTIONARY_FILE, "radius") != 0) {
		ERROR("Errors reading dictionary: %s",
		      fr_strerror());
		return -1;
	}

#define DICT_READ_OPTIONAL(_d, _n) \
do {\
	switch (fr_dict_read(main_config.dict, _d, _n)) {\
	case -1:\
		ERROR("Error reading %s/%s: %s", _d, _n, fr_strerror());\
		return -1;\
	case 0:\
		DEBUG2("Including dictionary file \"%s/%s\"", _d,_n);\
		break;\
	default:\
		break;\
	}\
} while (0)

	/*
	 *	It's OK if this one doesn't exist.
	 */
	DICT_READ_OPTIONAL(radius_dir, FR_DICTIONARY_FILE);

	cs = cf_section_alloc(NULL, "main", NULL);
	if (!cs) return -1;

	/*
	 *	Add a 'feature' subsection off the main config
	 *	We check if it's defined first, as the user may
	 *	have defined their own feature flags, or want
	 *	to manually override the ones set by modules
	 *	or the server.
	 */
	subcs = cf_section_find(cs, "feature", NULL);
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
	subcs = cf_section_find(cs, "version", NULL);
	if (!subcs) {
		subcs = cf_section_alloc(cs, "version", NULL);
		if (!subcs) return -1;
		cf_section_add(cs, subcs);
	}
	version_numbers_init(subcs);

	/* Read the configuration file */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s.conf", radius_dir, main_config.name);
	if (cf_file_read(cs, buffer) < 0) {
		ERROR("Error reading or parsing %s", buffer);
		talloc_free(cs);
		return -1;
	}

	/*
	 *	If there was no log destination set on the command line,
	 *	set it now.
	 */
	if (default_log.dst == L_DST_NULL) {
		if (cf_section_rules_push(cs, initial_logging_config) < 0) {
			fprintf(stderr, "%s: Error: Failed pushing rules for log {} section.\n",
				main_config.name);
			cf_file_free(cs);
			return -1;
		}

		if (cf_section_parse(NULL, NULL, cs) < 0) {
			fprintf(stderr, "%s: Error: Failed to parse log{} section.\n",
				main_config.name);
			cf_file_free(cs);
			return -1;
		}

		if (!radlog_dest) {
			fprintf(stderr, "%s: Error: No log destination specified.\n",
				main_config.name);
			cf_file_free(cs);
			return -1;
		}

		default_log.dst = fr_str2int(log_str2dst, radlog_dest,
					      L_DST_NUM_DEST);
		if (default_log.dst == L_DST_NUM_DEST) {
			fprintf(stderr, "%s: Error: Unknown log_destination %s\n",
				main_config.name, radlog_dest);
			cf_file_free(cs);
			return -1;
		}

		if (default_log.dst == L_DST_SYSLOG) {
			/*
			 *	Make sure syslog_facility isn't NULL
			 *	before using it
			 */
			if (!syslog_facility) {
				fprintf(stderr, "%s: Error: Syslog chosen but no facility was specified\n",
					main_config.name);
				cf_file_free(cs);
				return -1;
			}
			main_config.syslog_facility = fr_str2int(syslog_facility_table, syslog_facility, -1);
			if (main_config.syslog_facility < 0) {
				fprintf(stderr, "%s: Error: Unknown syslog_facility %s\n",
					main_config.name, syslog_facility);
				cf_file_free(cs);
				return -1;
			}

#ifdef HAVE_SYSLOG_H
			/*
			 *	Call openlog only once, when the
			 *	program starts.
			 */
			openlog(main_config.name, LOG_PID, main_config.syslog_facility);
#endif

		} else if (default_log.dst == L_DST_FILES) {
			if (!main_config.log_file) {
				fprintf(stderr, "%s: Error: Specified \"files\" as a log destination, but no log filename was given!\n",
					main_config.name);
				cf_file_free(cs);
				return -1;
			}
		}
	}

	/*
	 *	Only set timestamp logging from the config file if no value was
	 *	specified on the command line.
	 */
	if (log_timestamp_is_set && (default_log.timestamp == L_TIMESTAMP_AUTO)) {
		default_log.timestamp = log_timestamp ? L_TIMESTAMP_ON : L_TIMESTAMP_OFF;
	}

#ifdef HAVE_SETUID
	/*
	 *	Switch users as early as possible.
	 */
	if (!switch_users(cs)) fr_exit(1);
#endif

	/*
	 *	This allows us to figure out where, relative to
	 *	radiusd.conf, the other configuration files exist.
	 */
	if (cf_section_rules_push(cs, server_config) < 0) return -1;
	if (cf_section_rules_push(cs, virtual_servers_config) < 0) return -1;
	if (cf_section_parse(NULL, NULL, cs) < 0) return -1;

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
	if (rad_debug_lvl == 0) rad_debug_lvl = main_config.debug_level;

	/*
	 *	Set the same debug level for the global log
	 *	for requests, and for libfreeradius, and for requests.
	 */
	fr_debug_lvl = req_debug_lvl = rad_debug_lvl;

	INFO("Switching to configured log settings");

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

	FR_TIMEVAL_BOUND_CHECK("reject_delay", &main_config.reject_delay, <=, main_config.cleanup_delay, 0);

	FR_SIZE_BOUND_CHECK("resources.talloc_pool_size", main_config.talloc_pool_size, >=, (size_t)(2 * 1024));
	FR_SIZE_BOUND_CHECK("resources.talloc_pool_size", main_config.talloc_pool_size, <=, (size_t)(1024 * 1024));

	if (main_config.talloc_memory_limit) {
		FR_SIZE_BOUND_CHECK("resources.talloc_memory_limit", main_config.talloc_memory_limit, >=,
				    (size_t)1024 * 1024 * 10);

		FR_SIZE_BOUND_CHECK("resources.talloc_memory_limit", main_config.talloc_memory_limit, <=,
				    ((((size_t)1024) * 1024 * 1024) * 16));
	}

	/*
	 *	Set default initial request processing delay to 1/3 of a second.
	 *	Will be updated by the lowest response window across all home servers,
	 *	if it is less than this.
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
	main_config.config = cs;

	DEBUG2("%s: #### Loading Realms and Home Servers ####", main_config.name);
	if (!realms_init(cs)) {
		return -1;
	}

	DEBUG2("%s: #### Loading Clients ####", main_config.name);
	if (!client_list_parse_section(cs, false)) {
		return -1;
	}

	/*
	 *	Register the %{config:section.subsection} xlat function.
	 */
	xlat_register(NULL, "config", xlat_config, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);

	/*
	 *	...and the client and listen xlats which need to be
	 *	defined before we start parsing the config.
	 */
	xlat_register(NULL, "listen", xlat_listen, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN);

	/*
	 *	Ensure cwd is inside the chroot.
	 */
	if (chroot_dir) {
		if (chdir(radlog_dir) < 0) {
			ERROR("Failed to 'chdir %s' after chroot: %s",
			       radlog_dir, fr_syserror(errno));
			return -1;
		}
	}

#ifdef WITH_CONF_WRITE
	if (main_config.write_dir) {
		cf_section_write(NULL, cs, -1);
	}
#endif

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
	/*
	 *	Clean up the configuration data
	 *	structures.
	 */
	client_list_free();
	realms_free();
	listen_free(&main_config.listen);

	/*
	 *	Frees current config and any previous configs.
	 */
	TALLOC_FREE(cs_cache);
	TALLOC_FREE(main_config.dict);

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
	time_t		when;

	static time_t	last_hup = 0;

	/*
	 *	Re-open the log file.  If we can't, then keep logging
	 *	to the old log file.
	 *
	 *	The "open log file" code is here rather than in log.c,
	 *	because it makes that function MUCH simpler.
	 */
	hup_logfile();

	/*
	 *	Only check the config files every few seconds.
	 */
	when = time(NULL);
	if ((last_hup + 2) >= when) {
		INFO("HUP - Last HUP was too recent.  Ignoring");
		return;
	}
	last_hup = when;

#if 0
	rcode = cf_file_changed(cs_cache->cs, hup_callback);
	if (rcode == CF_FILE_NONE) {
		INFO("HUP - No files changed.  Ignoring");
		return;
	}

	if (rcode == CF_FILE_ERROR) {
		INFO("HUP - Cannot read configuration files.  Ignoring");
		return;
	}
#endif

	INFO("HUP - NYI in version 4");	/* Not yet implemented in v4 */
}
