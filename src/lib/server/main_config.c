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
 * @brief Handle the the main server's (radiusd) configuration.
 * @file src/lib/server/main_config.c
 *
 * @copyright 2002,2006-2007 The FreeRADIUS server project
 * @copyright 2002 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/client.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/dependency.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/util.h>
#include <freeradius-devel/server/virtual_servers.h>

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/file.h>
#include <freeradius-devel/util/hw.h>
#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/sem.h>

#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#include <unistd.h>
#include <sys/types.h>

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif

#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif

main_config_t const	*main_config;				//!< Main server configuration.

extern fr_cond_t	*debug_condition;
extern fr_log_t		debug_log;

fr_cond_t		*debug_condition = NULL;		//!< Condition used to mark packets up for checking.
fr_log_t		debug_log = { .fd = -1, .dst = L_DST_NULL };

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

static int reverse_lookups_parse(TALLOC_CTX *ctx, void *out, void *parent,CONF_ITEM *ci, CONF_PARSER const *rule);
static int hostname_lookups_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static int num_networks_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int num_workers_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int lib_dir_on_read(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static int talloc_pool_size_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static int max_request_time_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

static int name_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);

/*
 *	Log destinations
 */
static const CONF_PARSER initial_log_subsection_config[] = {
	{ FR_CONF_OFFSET("destination", FR_TYPE_STRING, main_config_t, log_dest), .dflt = "files" },
	{ FR_CONF_OFFSET("syslog_facility", FR_TYPE_VOID, main_config_t, syslog_facility), .dflt = "daemon",
		.func = cf_table_parse_int,
			.uctx = &(cf_table_parse_ctx_t){
				.table = syslog_facility_table,
				.len = &syslog_facility_table_len
			}
		},
	{ FR_CONF_OFFSET("local_state_dir", FR_TYPE_STRING, main_config_t, local_state_dir), .dflt = "${prefix}/var"},
	{ FR_CONF_OFFSET("logdir", FR_TYPE_STRING, main_config_t, log_dir), .dflt = "${local_state_dir}/log"},
	{ FR_CONF_OFFSET("file", FR_TYPE_STRING, main_config_t, log_file), .dflt = "${logdir}/radius.log" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Basic configuration for the server.
 */
static const CONF_PARSER initial_logging_config[] = {
	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) initial_log_subsection_config },

	CONF_PARSER_TERMINATOR
};

/*
 *	Basic configuration for the server.
 */
static const CONF_PARSER lib_dir_on_read_config[] = {
	{ FR_CONF_OFFSET("prefix", FR_TYPE_STRING, main_config_t, prefix), .dflt = "/usr/local" },

	{ FR_CONF_OFFSET("use_utc", FR_TYPE_BOOL, main_config_t, log_dates_utc) },
	{ FR_CONF_OFFSET_IS_SET("timestamp", FR_TYPE_BOOL, main_config_t, log_timestamp) },

	{ FR_CONF_OFFSET("libdir", FR_TYPE_STRING, main_config_t, lib_dir), .dflt = "${prefix}/lib",
	  .on_read = lib_dir_on_read },

	CONF_PARSER_TERMINATOR
};

/**********************************************************************
 *
 *	Now that we've parsed the log destination, AND the security
 *	items, we can parse the rest of the configuration items.
 *
 **********************************************************************/
static const CONF_PARSER log_config[] = {
	{ FR_CONF_OFFSET("colourise", FR_TYPE_BOOL, main_config_t, do_colourise) },
	{ FR_CONF_OFFSET("line_number", FR_TYPE_BOOL, main_config_t, log_line_number) },
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, main_config_t, log_timestamp) },
	{ FR_CONF_OFFSET("use_utc", FR_TYPE_BOOL, main_config_t, log_dates_utc) },
	CONF_PARSER_TERMINATOR
};


static const CONF_PARSER resources[] = {
	/*
	 *	Don't set a default here.  It's set in the code, below.  This means that
	 *	the config item will *not* get printed out in debug mode, so that no one knows
	 *	it exists.
	 */
	{ FR_CONF_OFFSET("talloc_pool_size", FR_TYPE_SIZE | FR_TYPE_HIDDEN, main_config_t, talloc_pool_size), .func = talloc_pool_size_parse },			/* DO NOT SET DEFAULT */
	{ FR_CONF_OFFSET("talloc_memory_report", FR_TYPE_BOOL | FR_TYPE_HIDDEN, main_config_t, talloc_memory_report) },						/* DO NOT SET DEFAULT */
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER thread_config[] = {
	{ FR_CONF_OFFSET("num_networks", FR_TYPE_UINT32, main_config_t, max_networks), .dflt = STRINGIFY(1),
	  .func = num_networks_parse },
	{ FR_CONF_OFFSET("num_workers", FR_TYPE_UINT32, main_config_t, max_workers), .dflt = STRINGIFY(0),
	  .func = num_workers_parse },

	{ FR_CONF_OFFSET("stats_interval", FR_TYPE_TIME_DELTA | FR_TYPE_HIDDEN, main_config_t, stats_interval), },

#ifdef HAVE_OPENSSL_CRYPTO_H
	{ FR_CONF_OFFSET("openssl_async_pool_init", FR_TYPE_SIZE, main_config_t, openssl_async_pool_init), .dflt = "64" },
	{ FR_CONF_OFFSET("openssl_async_pool_max", FR_TYPE_SIZE, main_config_t, openssl_async_pool_max), .dflt = "1024" },
#endif

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
	{ FR_CONF_OFFSET("prefix", FR_TYPE_STRING, main_config_t, prefix), .dflt = "/usr/local" },
	{ FR_CONF_OFFSET("local_state_dir", FR_TYPE_STRING, main_config_t, local_state_dir), .dflt = "${prefix}/var"},
	{ FR_CONF_OFFSET("sbin_dir", FR_TYPE_STRING, main_config_t, sbin_dir), .dflt = "${prefix}/sbin"},
	{ FR_CONF_OFFSET("logdir", FR_TYPE_STRING, main_config_t, log_dir), .dflt = "${local_state_dir}/log"},
	{ FR_CONF_OFFSET("run_dir", FR_TYPE_STRING, main_config_t, run_dir), .dflt = "${local_state_dir}/run/${name}"},
	{ FR_CONF_OFFSET("radacctdir", FR_TYPE_STRING, main_config_t, radacct_dir), .dflt = "${logdir}/radacct" },
	{ FR_CONF_OFFSET("panic_action", FR_TYPE_STRING, main_config_t, panic_action) },
	{ FR_CONF_OFFSET("reverse_lookups", FR_TYPE_BOOL, main_config_t, reverse_lookups), .dflt = "no", .func = reverse_lookups_parse },
	{ FR_CONF_OFFSET("hostname_lookups", FR_TYPE_BOOL, main_config_t, hostname_lookups), .dflt = "yes", .func = hostname_lookups_parse },
	{ FR_CONF_OFFSET("max_request_time", FR_TYPE_TIME_DELTA, main_config_t, max_request_time), .dflt = STRINGIFY(MAX_REQUEST_TIME), .func = max_request_time_parse },
	{ FR_CONF_OFFSET("pidfile", FR_TYPE_STRING, main_config_t, pid_file), .dflt = "${run_dir}/radiusd.pid"},

	{ FR_CONF_OFFSET("debug_level", FR_TYPE_UINT32 | FR_TYPE_HIDDEN, main_config_t, debug_level), .dflt = "0" },
	{ FR_CONF_OFFSET("max_requests", FR_TYPE_UINT32, main_config_t, max_requests), .dflt = "0" },

	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) log_config },

	{ FR_CONF_POINTER("resources", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) resources },

	{ FR_CONF_POINTER("thread", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) thread_config, .ident2 = CF_IDENT_ANY },

	CONF_PARSER_TERMINATOR
};


/**********************************************************************
 *
 *	The next few items are here to allow for switching of users
 *	while still opening the various output files with the correct
 *	permission.
 *
 *	It's rare (or impossible) to have parse errors for these
 *	configuration items, so we don't worry too much about that.
 *	In contrast, when we parse the rest of the configuration, we
 *	CAN get parse errors.  We want THOSE parse errors to go to the
 *	log file, and we want the log file to have the correct
 *	permissions.
 *
 **********************************************************************/
static const CONF_PARSER security_config[] = {
#ifdef HAVE_SETUID
	{ FR_CONF_OFFSET_IS_SET("user", FR_TYPE_VOID, main_config_t, uid), .func = cf_parse_uid },
	{ FR_CONF_OFFSET_IS_SET("group", FR_TYPE_VOID, main_config_t, gid), .func = cf_parse_gid },
#endif
	{ FR_CONF_OFFSET("chroot", FR_TYPE_STRING, main_config_t, chroot_dir) },
	{ FR_CONF_OFFSET("allow_core_dumps", FR_TYPE_BOOL, main_config_t, allow_core_dumps), .dflt = "no" },

#ifdef ENABLE_OPENSSL_VERSION_CHECK
	{ FR_CONF_OFFSET("allow_vulnerable_openssl", FR_TYPE_STRING, main_config_t, allow_vulnerable_openssl), .dflt = "no" },
#endif

#ifdef HAVE_OPENSSL_CRYPTO_H
	{ FR_CONF_OFFSET_IS_SET("openssl_fips_mode", FR_TYPE_BOOL, main_config_t, openssl_fips_mode), .dflt = "no" },
#endif

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER switch_users_config[] = {
	{ FR_CONF_POINTER("security", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) security_config },

	{ FR_CONF_OFFSET("name", FR_TYPE_STRING, main_config_t, name), .func = name_parse },							/* DO NOT SET DEFAULT */

	{ FR_CONF_OFFSET("prefix", FR_TYPE_STRING, main_config_t, prefix), .dflt = "/usr/local" },
	{ FR_CONF_OFFSET("local_state_dir", FR_TYPE_STRING, main_config_t, local_state_dir), .dflt = "${prefix}/var"},

	{ FR_CONF_OFFSET("run_dir", FR_TYPE_STRING, main_config_t, run_dir), .dflt = "${local_state_dir}/run/${name}"},

	/*
	 *	For backwards compatibility.
	 */
#ifdef HAVE_SETUID
	{ FR_CONF_OFFSET("user", FR_TYPE_VOID | FR_TYPE_DEPRECATED, main_config_t, uid) },
	{ FR_CONF_OFFSET("group", FR_TYPE_VOID | FR_TYPE_DEPRECATED, main_config_t, gid) },
#endif
	{ FR_CONF_DEPRECATED("chroot", FR_TYPE_STRING, main_config_t, NULL) },
	{ FR_CONF_DEPRECATED("allow_core_dumps", FR_TYPE_BOOL, main_config_t, NULL) },
	CONF_PARSER_TERMINATOR
};

static int reverse_lookups_parse(TALLOC_CTX *ctx, void *out, void *parent,
				 CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int	ret;

	if ((ret = cf_pair_parse_value(ctx, out, parent, ci, rule)) < 0) return ret;

	memcpy(&fr_reverse_lookups, out, sizeof(fr_reverse_lookups));

	return 0;
}

static int hostname_lookups_parse(TALLOC_CTX *ctx, void *out, void *parent,
				  CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int	ret;

	if ((ret = cf_pair_parse_value(ctx, out, parent, ci, rule)) < 0) return ret;

	memcpy(&fr_hostname_lookups, out, sizeof(fr_hostname_lookups));

	return 0;
}

static int talloc_pool_size_parse(TALLOC_CTX *ctx, void *out, void *parent,
				  CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int	ret;
	size_t	value;

	if ((ret = cf_pair_parse_value(ctx, out, parent, ci, rule)) < 0) return ret;

	memcpy(&value, out, sizeof(value));

	FR_SIZE_BOUND_CHECK("resources.talloc_pool_size", value, >=, (size_t)(2 * 1024));
	FR_SIZE_BOUND_CHECK("resources.talloc_pool_size", value, <=, (size_t)(1024 * 1024));

	memcpy(out, &value, sizeof(value));

	return 0;
}

static int max_request_time_parse(TALLOC_CTX *ctx, void *out, void *parent,
				  CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int		ret;
	uint32_t	value;

	if ((ret = cf_pair_parse_value(ctx, out, parent, ci, rule)) < 0) return ret;

	memcpy(&value, out, sizeof(value));

	FR_INTEGER_COND_CHECK("max_request_time", value, (value != 0), 100);

	memcpy(out, &value, sizeof(value));

	return 0;
}

static int lib_dir_on_read(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
			 CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	CONF_PAIR	*cp = cf_item_to_pair(ci);
	char const	*value;

	fr_assert(main_config != NULL);
	value = cf_pair_value(cp);
	if (value) {
		main_config_t *config;

		memcpy(&config, &main_config, sizeof(config)); /* const issues */

		config->lib_dir = value;
	}

	/*
	 *	Initialize the DL infrastructure, which is used by the
	 *	config file parser.  And also add in the search path.
	 */
	if (!dl_module_loader_init(main_config->lib_dir)) {
		cf_log_perr(ci, "Failed initializing 'lib_dir'");
		return -1;
	}

	return 0;
}

/** Configured server name takes precedence over default values
 *
 */
static int name_parse(TALLOC_CTX *ctx, void *out, void *parent,
		      CONF_ITEM *ci, CONF_PARSER const *rule)
{
	main_config_t *config = parent;

	if (*((char **)out)) {
		if (config->overwrite_config_name) return 0;		/* Don't change */

		talloc_free(*((char **)out));				/* Free existing buffer */
	}

	return cf_pair_parse_value(ctx, out, parent, ci, rule);		/* Set new value */
}

static int num_networks_parse(TALLOC_CTX *ctx, void *out, void *parent,
			      CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int		ret;
	uint32_t	value;

	if ((ret = cf_pair_parse_value(ctx, out, parent, ci, rule)) < 0) return ret;

	memcpy(&value, out, sizeof(value));

	FR_INTEGER_BOUND_CHECK("thread.num_networks", value, ==, 1);

	memcpy(out, &value, sizeof(value));

	return 0;
}

static int num_workers_parse(TALLOC_CTX *ctx, void *out, void *parent,
			     CONF_ITEM *ci, CONF_PARSER const *rule)
{
	int		ret;
	uint32_t	value;
	main_config_t	*conf = parent;

	if ((ret = cf_pair_parse_value(ctx, out, parent, ci, rule)) < 0) return ret;

	memcpy(&value, out, sizeof(value));

	/*
	 *	If no value is specified, try and
	 *	discover it automatically.
	 */
	if (value == 0) {
		char *strvalue;

		value = fr_hw_num_cores_active();

		/*
		 *	If we've got more than four times
		 *	the number of cores as we have
		 *	networks, then set the number of
		 *	workers to the number of cores
		 *	minus networks.
		 *
		 *	This ensures at a least a 4:1
		 *	ratio of workers to networks,
		 *      which seems like a sensible ratio.
		 */
		if ((conf->max_networks * 4) < value) {
			value -= conf->max_networks;
		}

		strvalue = talloc_asprintf(ci, "%u", value);
		(void) cf_pair_replace(cf_item_to_section(cf_parent(ci)), cf_item_to_pair(ci), strvalue);
		talloc_free(strvalue);

		/*
		 *	Otherwise just create as many
		 *	workers as we have cores.
		 */
		cf_log_info(ci, "Setting thread.workers = %u", value);
	} else {
		FR_INTEGER_BOUND_CHECK("thread.num_workers", value, >=, 1);
		FR_INTEGER_BOUND_CHECK("thread.num_workers", value, <=, 128);
	}

	memcpy(out, &value, sizeof(value));

	return 0;
}


static int xlat_config_escape(UNUSED request_t *request, fr_value_box_t *vb, UNUSED void *uctx)
{
	static char const	disallowed[] = "%{}\\'\"`";
	size_t 			outmax = vb->vb_length * 3;
	size_t			outlen = 0;
	char 			escaped[outmax];
	char const		*in, *end;
	char			*out = escaped;

	fr_assert(vb->type == FR_TYPE_STRING);
	in = vb->vb_strvalue;
	end = in + vb->vb_length;

	do {
		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32)) {
			if (outlen >= (outmax - 3)) return -1;

			snprintf(out, outlen, "=%02X", (unsigned char) in[0]);
			out += 3;
			outlen += 3;
			continue;

		} else if (strchr(disallowed, *in) != NULL) {
			if (outlen >= (outmax - 2)) return -1;

			out[0] = '\\';
			out[1] = *in;
			out += 2;
			outlen += 2;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (outlen >= (outmax - 1)) return -1;

		/*
		 *	Allowed character.
		 */
		*out = *in;
		out++;
		outlen++;
	} while (++in < end);
	*out = '\0';

	/*
	 *	If the output length is greater than the input length
	 *	something has been escaped - replace the original string
	 */
	if (outlen > vb->vb_length) {
		char	*outbuff;
		fr_value_box_bstr_realloc(vb, &outbuff, vb, outlen);
		memcpy(outbuff, escaped, outlen);
	}

	return 0;

}

static xlat_arg_parser_t const xlat_config_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING, .always_escape = true, .func = xlat_config_escape },
	XLAT_ARG_PARSER_TERMINATOR
};

/** xlat to get config values
 *
@verbatim
%(config:section.subsection.attribute)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_config(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
				 UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
				 fr_value_box_list_t *in)
{
	char const	*value;
	CONF_PAIR	*cp;
	CONF_ITEM	*ci;
	fr_value_box_t	*in_head = fr_dlist_head(in);
	fr_value_box_t	*vb;

	ci = cf_reference_item(main_config->root_cs, main_config->root_cs, in_head->vb_strvalue);
	if (!ci || !cf_item_is_pair(ci)) {
		REDEBUG("Config item \"%pV\" does not exist", in_head);
		return XLAT_ACTION_FAIL;
	}

	cp = cf_item_to_pair(ci);

	value = cf_pair_value(cp);
	if (!value) return XLAT_ACTION_DONE;

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_bstrndup(ctx, vb, NULL, value, strlen(value), false);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

#ifdef HAVE_SETUID
static int mkdir_chown(int fd, char const *path, void *uctx)
{
	main_config_t *config = uctx;
	int ret = 0;

	if ((config->server_uid != (uid_t)-1) || (config->server_gid != (gid_t)-1)) {
		rad_suid_up();
		ret = fchown(fd, config->server_uid, config->server_gid);
		if (ret < 0) fr_strerror_printf("Failed changing ownership on directory \"%s\": %s",
						path, fr_syserror(errno));
		rad_suid_down();
	}

	return ret;
}
/*
 *  Do chroot, if requested.
 *
 *  Switch UID and GID to what is specified in the config file
 */
static int switch_users(main_config_t *config, CONF_SECTION *cs)
{
	bool do_suid = false;
	bool do_sgid = false;

	/*
	 *	Get the current maximum for core files.  Do this
	 *	before anything else so as to ensure it's properly
	 *	initialized.
	 */
	if (fr_set_dumpable_init() < 0) {
		fr_perror("%s", config->name);
		return -1;
	}

	if (cf_section_rules_push(cs, switch_users_config) < 0) {
		fprintf(stderr, "%s: Error: Failed pushing parse rules for user/group information.\n",
			config->name);
		return -1;
	}

	DEBUG("Parsing security rules to bootstrap UID / GID / chroot / etc.");
	if (cf_section_parse(config, config, cs) < 0) {
		fprintf(stderr, "%s: Error: Failed to parse user/group information.\n",
			config->name);
		return -1;
	}

	/*
	 *	Don't do chroot/setuid/setgid if we're in debugging
	 *	as non-root.
	 */
	if (DEBUG_ENABLED && (getuid() != 0)) {
		WARN("Ignoring configured UID / GID / chroot as we're running in debug mode");
		return 0;
	}
#ifdef HAVE_GRP_H
	/*
	 *	Get the correct GID for the server.
	 */
	config->server_gid = getgid();
	if (config->gid_is_set && (config->server_gid != config->gid)) {
		config->server_gid = config->gid;
		do_sgid = true;
	}
#endif

	/*
	 *	Get the correct UID for the server.
	 */
	config->server_uid = getuid();
	if (config->uid_is_set && (config->server_uid != config->uid)) {
		/*
		 *	We're not the correct user.  Go set that.
		 */
		config->server_uid = config->uid;
		do_suid = true;

#ifdef HAVE_INITGROUPS
		{
			struct passwd *user;

			if (fr_perm_getpwuid(config, &user, config->uid) < 0) {
				fprintf(stderr, "%s: Failed resolving UID %i: %s\n",
					config->name, (int)config->uid, fr_syserror(errno));
				return -1;
			}

			if (initgroups(user->pw_name, config->server_gid) < 0) {
				fprintf(stderr, "%s: Cannot initialize supplementary group list "
					"for user %s: %s\n",
					config->name, user->pw_name, fr_syserror(errno));
				talloc_free(user);
				return -1;
			}

			talloc_free(user);
		}
#endif
	}

	/*
	 *	Set the user/group we're going to use
	 *	to check read permissions on configuration files.
	 */
	cf_file_check_user(config->server_uid ? config->server_uid : (uid_t)-1,
			   config->server_gid ? config->server_gid : (gid_t)-1);

	/*
	 *	Do chroot BEFORE changing UIDs.
	 */
	if (config->chroot_dir) {
		if (chroot(config->chroot_dir) < 0) {
			fprintf(stderr, "%s: Failed to perform chroot %s: %s",
				config->name, config->chroot_dir, fr_syserror(errno));
			return -1;
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
		if (setgid(config->server_gid) < 0) {
			struct group *group;

			if (fr_perm_getgrgid(config, &group, config->gid) < 0) {
					fprintf(stderr, "%s: Failed resolving GID %i: %s\n",
						config->name, (int)config->gid, fr_syserror(errno));
					return -1;
			}

			fprintf(stderr, "%s: Failed setting group to %s: %s",
				config->name, group->gr_name, fr_syserror(errno));
			return -1;
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
	if (config->write_pid) {
		/*
		 *	Control sockets may be accessible by users
		 *	other than the freeradius user, so we need
		 *	to allow 'other' to traverse the run
		 *	directory.
		 *
		 *	The freeradius user should be the only one
		 *	allowed to write to this directory however.
		 */
		if (fr_mkdir(NULL, config->run_dir, -1, 0755, mkdir_chown, config) < 0) {
			WARN("Failed creating run_dir %s: %s", config->run_dir, fr_syserror(errno));
		}
	}

	if ((default_log.dst == L_DST_FILES) && config->log_dir) {
		/*
		 *	Every other Linux daemon allows 'other'
		 *	to traverse the log directory.  That doesn't
		 *	mean the actual files should be world
		 *	readable.
		 */
		if (fr_mkdir(NULL, config->log_dir, -1, 0755, mkdir_chown, config) < 0) {
			WARN("Failed creating log_dir %s: %s", config->log_dir, fr_syserror(errno));
		}
	}

	/*
	 *	If we don't already have a log file open, open one
	 *	now.  We may not have been logging anything yet.  The
	 *	server normally starts up fairly quietly.
	 */
	if ((default_log.dst == L_DST_FILES) &&
	    (default_log.fd < 0)) {
		default_log.fd = open(config->log_file,
				      O_WRONLY | O_APPEND | O_CREAT, 0640);
		if (default_log.fd < 0) {
			fprintf(stderr, "%s: Failed to open log file %s: %s\n",
				config->name, config->log_file, fr_syserror(errno));
			return -1;
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
		if (fchown(default_log.fd, config->server_uid, config->server_gid) < 0) {
			fprintf(stderr, "%s: Cannot change ownership of log file %s: %s\n",
				config->name, config->log_file, fr_syserror(errno));
			return -1;
		}
	}

	/*
	 *	Once we're done with all of the privileged work,
	 *	permanently change the UID.
	 */
	if (do_suid) {
		rad_suid_set_down_uid(config->server_uid);
		rad_suid_down();
	}

	return 0;
}
#endif	/* HAVE_SETUID */


/** Set the server name
 *
 * @note Will only add pair if one does not already exist
 *
 * @param[in] config		to alter.
 * @param[in] name		to set e.g. "radiusd".
 * @param[in] overwrite_config	replace any CONF_PAIRs with this value.
 */
void main_config_name_set_default(main_config_t *config, char const *name, bool overwrite_config)
{
	if (config->name) {
		char *p;

		memcpy(&p, &config->name, sizeof(p));
		talloc_free(p);
		config->name = NULL;
	}
	if (name) config->name = talloc_typed_strdup(config, name);

	config->overwrite_config_name = overwrite_config;
}

/** Set the global radius config directory.
 *
 * @param[in] config	to alter.
 * @param[in] name	to set as dir root e.g. /usr/local/etc/raddb.
 */
void main_config_raddb_dir_set(main_config_t *config, char const *name)
{
	if (config->raddb_dir) {
		talloc_const_free(config->raddb_dir);
		config->raddb_dir = NULL;
	}
	if (name) config->raddb_dir = talloc_typed_strdup(config, name);
}

/** Clean up the semaphore when the main config is freed
 *
 * This helps with permissions issues if the user is switching between
 * running the process under something like systemd and running it under
 * debug mode.
 */
void main_config_exclusive_proc_done(main_config_t const *config)
{
	if (config->multi_proc_sem_id >= 0) fr_sem_close(config->multi_proc_sem_id, NULL);
}

/** Increment the semaphore in the child process so that it's not released when the parent exits
 *
 * @param[in] config	specifying the path to the main config file.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int main_config_exclusive_proc_child(main_config_t const *config)
{
	return fr_sem_take(config->multi_proc_sem_id, config->multi_proc_sem_path, true);
}

/** Check to see if we're the only process using this configuration file
 *
 * @param[in] config	specifying the path to the main config file.
 * @return
 *	- 1 if another process is running with this config file
 *	- 0 if no other process is running with this config file.
 *	- -1 on error.
 */
int main_config_exclusive_proc(main_config_t *config)
{
	char *path;
	int sem_id;
	int ret;
	static bool sem_initd;

	if (unlikely(sem_initd)) return 0;

	MEM(path = talloc_asprintf(config, "%s/%s.conf", config->raddb_dir, config->name));
	sem_id = fr_sem_get(path, 0,
			    main_config->uid_is_set ? main_config->uid : geteuid(),
			    main_config->gid_is_set ? main_config->gid : getegid(),
			    true, false);
	if (sem_id < 0) {
		talloc_free(path);
		return -1;
	}

	config->multi_proc_sem_id = -1;

	ret = fr_sem_wait(sem_id, path, true, true);
	switch (ret) {
	case 0:	/* we have the semaphore */
		config->multi_proc_sem_id = sem_id;
		config->multi_proc_sem_path = path;
		sem_initd = true;
		break;

	case 1:	/* another process has the semaphore */
	{
		pid_t pid;

		fr_sem_pid(&pid, sem_id);
		fr_strerror_printf("Refusing to start - PID %u already running with \"%s\"", pid, path);
		talloc_free(path);
	}
		break;

	default:
		talloc_free(path);
		break;
	}


	return ret;
}

/** Set the global dictionary directory.
 *
 * @param[in] config	to alter.
 * @param[in] name	to set as dict dir root e.g. /usr/local/share/freeradius.
 */
void main_config_dict_dir_set(main_config_t *config, char const *name)
{
	if (config->dict_dir) {
		talloc_const_free(config->dict_dir);
		config->dict_dir = NULL;
	}
	if (name) config->dict_dir = talloc_typed_strdup(config, name);
}

/** Allocate a main_config_t struct, setting defaults
 *
 */
main_config_t *main_config_alloc(TALLOC_CTX *ctx)
{
	main_config_t *config;

	config = talloc_zero(ctx, main_config_t);
	if (!config) {
		fr_strerror_const("Failed allocating main config");
		return NULL;
	}

	/*
	 *	Set the defaults from compile time arguments
	 *	these can be overridden later on the command line.
	 */
	main_config_raddb_dir_set(config, RADDBDIR);
	main_config_dict_dir_set(config, DICTDIR);

	main_config = config;

	return config;
}

static int _dlhandle_free(void **dl_handle)
{
	dlclose(*dl_handle);
	return 0;
}

/*
 *	Read config files.
 *
 *	This function can ONLY be called from the main server process.
 */
int main_config_init(main_config_t *config)
{
	char const	*p = NULL;
	CONF_SECTION	*cs = NULL, *subcs;
	struct stat	statbuf;
	bool		can_colourise = false;
	char		buffer[1024];
	xlat_t		*xlat;

	if (stat(config->raddb_dir, &statbuf) < 0) {
		ERROR("Error checking raddb_dir \"%s\": %s", config->raddb_dir, fr_syserror(errno));
		return -1;
	}

#ifdef S_IWOTH
	if ((statbuf.st_mode & S_IWOTH) != 0) {
		ERROR("Configuration directory %s is globally writable. "
		      "Refusing to start due to insecure configuration", config->raddb_dir);
		return -1;
	}
#endif

#if 0 && defined(S_IROTH)
	if (statbuf.st_mode & S_IROTH != 0) {
		ERROR("Configuration directory %s is globally readable. "
		      "Refusing to start due to insecure configuration", config->raddb_dir);
		return -1;
	}
#endif
	INFO("Starting - reading configuration files ...");

	/*
	 *	About sizeof(request_t) + sizeof(fr_radius_packet_t) * 2 + sizeof(fr_pair_t) * 400
	 *
	 *	Which should be enough for many configurations.
	 */
	config->talloc_pool_size = 8 * 1024; /* default */

	if (fr_dict_internal_afrom_file(&config->dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		PERROR("Failed reading internal dictionaries");
		goto failure;
	}

#define DICT_READ_OPTIONAL(_d, _n) \
do {\
	switch (fr_dict_read(config->dict, _d, _n)) {\
	case -1:\
		PERROR("Error reading dictionary \"%s/%s\"", _d, _n);\
		goto failure;\
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
	DICT_READ_OPTIONAL(config->raddb_dir, FR_DICTIONARY_FILE);

	cs = cf_section_alloc(NULL, NULL, "main", NULL);
	if (!cs) return -1;

	/*
	 *	Special-case things.  If the output is a TTY, AND
	 *	we're debugging, colourise things.  This flag also
	 *	removes the "Debug : " prefix from the log messages.
	 */
	p = getenv("TERM");
	if (p && isatty(default_log.fd) && strstr(p, "xterm") && fr_debug_lvl) {
		can_colourise = default_log.colourise = true;
	} else {
		can_colourise = default_log.colourise = false;
	}
	default_log.line_number = config->log_line_number;

	/*
	 *	Add a 'feature' subsection off the main config
	 *	We check if it's defined first, as the user may
	 *	have defined their own feature flags, or want
	 *	to manually override the ones set by modules
	 *	or the server.
	 */
	subcs = cf_section_find(cs, "feature", NULL);
	if (!subcs) {
		subcs = cf_section_alloc(cs, cs, "feature", NULL);
		if (!subcs) {
		failure:
			talloc_free(cs);
			return -1;
		}
	}
	dependency_features_init(subcs);

	/*
	 *	Add a 'version' subsection off the main config
	 *	We check if it's defined first, this is for
	 *	backwards compatibility.
	 */
	subcs = cf_section_find(cs, "version", NULL);
	if (!subcs) {
		subcs = cf_section_alloc(cs, cs, "version", NULL);
		if (!subcs) goto failure;
	}
	dependency_version_numbers_init(subcs);

	/*
	 *	@todo - not quite done yet... these dictionaries have
	 *	to be loaded from raddb_dir.  But the
	 *	fr_dict_autoload_t has a base_dir pointer
	 *	there... it's probably best to pass raddb_dir into
	 *	fr_dict_autoload() and have it use that instead.
	 *
	 *	Once that's done, the proto_foo dictionaries SHOULD be
	 *	autoloaded, AND loaded before the configuration files
	 *	are read.
	 *
	 *	And then all of the modules have to be updated to use
	 *	their local dict pointer, instead of NULL.
	 */
	if (cf_section_rules_push(cs, lib_dir_on_read_config) < 0) goto failure;
	if (cf_section_rules_push(cs, virtual_servers_on_read_config) < 0) goto failure;

	/* Read the configuration file */
	snprintf(buffer, sizeof(buffer), "%.200s/%.50s.conf", config->raddb_dir, config->name);
	if (cf_file_read(cs, buffer) < 0) {
		ERROR("Error reading or parsing %s", buffer);
		goto failure;
	}

	/*
	 *	Do any fixups here that might be used in references
	 */
	if (config->name) {
		CONF_PAIR *cp;

		cp = cf_pair_find(cs, "name");
		if (cp){
			if (config->overwrite_config_name && (cf_pair_replace(cs, cp, config->name) < 0)) {
				ERROR("Failed adding/replacing \"name\" config item");
				goto failure;
			}
		} else {
			MEM(cp = cf_pair_alloc(cs, "name", config->name, T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
		}
	}

	if (cf_section_pass2(cs) < 0) goto failure;

	/*
	 *	Parse environment variables first.
	 */
	subcs = cf_section_find(cs, "ENV", NULL);
	if (subcs) {
		char const *attr, *value;
		CONF_PAIR *cp;
		CONF_ITEM *ci;

		for (ci = cf_item_next(subcs, NULL);
		     ci != NULL;
		     ci = cf_item_next(subcs, ci)) {
			if (cf_item_is_data(ci)) continue;

			if (!cf_item_is_pair(ci)) {
				cf_log_err(ci, "Unexpected item in ENV section");
				goto failure;
			}

			cp = cf_item_to_pair(ci);
			if (cf_pair_operator(cp) != T_OP_EQ) {
				cf_log_err(ci, "Invalid operator for item in ENV section");
				goto failure;
			}

			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);
			if (!value) {
				if (unsetenv(attr) < 0) {
					cf_log_err(ci, "Failed deleting environment variable %s: %s",
						   attr, fr_syserror(errno));
					goto failure;
				}
			} else {
				void *handle;
				void **handle_p;

				if (setenv(attr, value, 1) < 0) {
					cf_log_err(ci, "Failed setting environment variable %s: %s",
						   attr, fr_syserror(errno));
					goto failure;
				}

				/*
				 *	Hacks for LD_PRELOAD.
				 */
				if (strcmp(attr, "LD_PRELOAD") != 0) continue;

				handle = dlopen(value, RTLD_NOW | RTLD_GLOBAL);
				if (!handle) {
					cf_log_err(ci, "Failed loading library %s: %s", value, dlerror());
					goto failure;
				}

				/*
				 *	Wrap the pointer, so we can set a destructor.
				 */
				MEM(handle_p = talloc(NULL, void *));
				*handle_p = handle;
				talloc_set_destructor(handle_p, _dlhandle_free);
				(void) cf_data_add(subcs, handle_p, value, true);
			}
		} /* loop over pairs in ENV */
	} /* there's an ENV subsection */

	/*
	 *	If there was no log destination set on the command line,
	 *	set it now.
	 */
	if (default_log.dst == L_DST_NULL) {
		if (cf_section_rules_push(cs, initial_logging_config) < 0) {
			fprintf(stderr, "%s: Error: Failed pushing rules for log {} section.\n",
				config->name);
			goto failure;
		}

		DEBUG("Parsing initial logging configuration.");
		if (cf_section_parse(config, config, cs) < 0) {
			fprintf(stderr, "%s: Error: Failed to parse log{} section.\n",
				config->name);
			goto failure;
		}

		if (!config->log_dest) {
			fprintf(stderr, "%s: Error: No log destination specified.\n",
				config->name);
			goto failure;
		}

		default_log.dst = fr_table_value_by_str(log_destination_table, config->log_dest, L_DST_NUM_DEST);

		switch (default_log.dst) {
		case L_DST_NUM_DEST:
			fprintf(stderr, "%s: Error: Unknown log_destination %s\n",
				config->name, config->log_dest);
			goto failure;

#ifdef HAVE_SYSLOG_H
		case L_DST_SYSLOG:
			/*
			 *	Call openlog only once, when the
			 *	program starts.
			 */
			openlog(config->name, LOG_PID, config->syslog_facility);
			break;
#endif

		case L_DST_FILES:
			if (!config->log_file) {
				fprintf(stderr, "%s: Error: Specified \"files\" as a log destination, but no log filename was given!\n",
					config->name);
				goto failure;
			}
			break;

		default:
			break;
		}
	}

	/*
	 *	Only set timestamp logging from the config file if no value was
	 *	specified on the command line.
	 */
	if (config->log_timestamp_is_set && (default_log.timestamp == L_TIMESTAMP_AUTO)) {
		default_log.timestamp = config->log_timestamp ? L_TIMESTAMP_ON : L_TIMESTAMP_OFF;
	}

#ifdef HAVE_SETUID
	/*
	 *	Switch users as early as possible.
	 */
	if (switch_users(config, cs) < 0) goto failure;
#endif

	/*
	 *	This also clears the dumpable flag if core dumps
	 *	aren't allowed.
	 */
	if (fr_set_dumpable(config->allow_core_dumps) < 0) PERROR("Failed enabling core dumps");
	if (config->allow_core_dumps) INFO("Core dumps are enabled");

	/*
	 *	This allows us to figure out where, relative to
	 *	radiusd.conf, the other configuration files exist.
	 */
	if (cf_section_rules_push(cs, server_config) < 0) goto failure;
	if (cf_section_rules_push(cs, virtual_servers_config) < 0) goto failure;

	DEBUG("Parsing main configuration.");
	if (cf_section_parse(config, config, cs) < 0) goto failure;

	/*
	 *	Reset the colourisation state.  The configuration
	 *	files can disable colourisation if the terminal
	 *	supports it.  The configation files *cannot* enable
	 *	colourisation if the terminal window doesn't support
	 *	it.
	 */
	if (can_colourise && !config->do_colourise) {
		default_log.colourise = false;
	}

	/*
	 *	Starting the server, WITHOUT "-x" on the
	 *	command-line: use whatever is in the config
	 *	file.
	 */
	if (fr_debug_lvl == 0) fr_debug_lvl = config->debug_level;

	INFO("Switching to configured log settings");

	/*
	 *	Free the old configuration items, and replace them
	 *	with the new ones.
	 *
	 *	Note that where possible, we do atomic switch-overs,
	 *	to ensure that the pointers are always valid.
	 */
	fr_assert(config->root_cs == NULL);

	DEBUG2("%s: #### Loading Clients ####", config->name);
	if (!client_list_parse_section(cs, 0, false)) goto failure;

	/*
	 *	Register the %(config:section.subsection) xlat function.
	 */
	xlat = xlat_register(NULL, "config", xlat_config, false);
	xlat_func_args(xlat, xlat_config_args);

	/*
	 *	Ensure cwd is inside the chroot.
	 */
	if (config->chroot_dir) {
		if (chdir(config->log_dir) < 0) {
			ERROR("Failed to 'chdir %s' after chroot: %s", config->log_dir, fr_syserror(errno));
			goto failure;
		}
	}

	config->root_cs = cs;	/* Do this last to avoid dangling pointers on error */

	/* Clear any unprocessed configuration errors */
	fr_strerror_clear();

	return 0;
}

/*
 *	Free the configuration.  Called only when the server is exiting.
 */
int main_config_free(main_config_t **config)
{
	/*
	 *	Clean up the configuration data
	 *	structures.
	 */
	client_list_free();

	/*
	 *	Frees current config and any previous configs.
	 */
	TALLOC_FREE((*config)->root_cs);
	fr_dict_free(&(*config)->dict, __FILE__);
	TALLOC_FREE(*config);

	return 0;
}

void hup_logfile(main_config_t *config)
{
	int fd, old_fd;

	if (default_log.dst != L_DST_FILES) return;

	fd = open(config->log_file, O_WRONLY | O_APPEND | O_CREAT, 0640);
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

void main_config_hup(main_config_t *config)
{
	fr_time_t		when;

	static fr_time_t	last_hup = fr_time_wrap(0);

	/*
	 *	Re-open the log file.  If we can't, then keep logging
	 *	to the old log file.
	 *
	 *	The "open log file" code is here rather than in log.c,
	 *	because it makes that function MUCH simpler.
	 */
	hup_logfile(config);

	/*
	 *	Only check the config files every few seconds.
	 */
	when = fr_time();
	if (fr_time_gteq(fr_time_add(last_hup, fr_time_delta_from_sec(2)), when)) {
		INFO("HUP - Last HUP was too recent.  Ignoring");
		return;
	}
	last_hup = when;

	INFO("HUP - NYI in version 4");	/* Not yet implemented in v4 */
}
