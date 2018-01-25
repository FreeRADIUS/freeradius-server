/*
 * rlm_linelog.c
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
 * Copyright 2004,2006  The FreeRADIUS server project
 * Copyright 2004  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/exfile.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>

#ifndef LOG_INFO
#define LOG_INFO (0)
#endif
#endif

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_linelog_t {
	CONF_SECTION	*cs;
	char const	*filename;

	bool		escape;			//!< do filename escaping, yes / no

	xlat_escape_t escape_func;	//!< escape function

	char const	*syslog_facility;	//!< Syslog facility string.
	char const	*syslog_severity;	//!< Syslog severity string.
	int		syslog_priority;	//!< Bitwise | of severity and facility.

	uint32_t	permissions;
	char const	*group;
	char const	*line;
	char const	*reference;
	exfile_t	*ef;
} rlm_linelog_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_OUTPUT | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_linelog_t, filename), NULL },
	{ "escape_filenames", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_linelog_t, escape), "no" },
	{ "syslog_facility", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_linelog_t, syslog_facility), NULL },
	{ "syslog_severity", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_linelog_t, syslog_severity), "info" },
	{ "permissions", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_linelog_t, permissions), "0600" },
	{ "group", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_linelog_t, group), NULL },
	{ "format", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_linelog_t, line), NULL },
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_linelog_t, reference), NULL },
	CONF_PARSER_TERMINATOR
};


/*
 *	Instantiate the module.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_linelog_t *inst = instance;
	int num;

	if (!inst->filename) {
		cf_log_err_cs(conf, "No value provided for 'filename'");
		return -1;
	}

	/*
	 *	Escape filenames only if asked.
	 */
	if (inst->escape) {
		inst->escape_func = rad_filename_escape;
	} else {
		inst->escape_func = rad_filename_make_safe;
	}

#ifndef HAVE_SYSLOG_H
	if (strcmp(inst->filename, "syslog") == 0) {
		cf_log_err_cs(conf, "Syslog output is not supported on this system");
		return -1;
	}
#else

	if (inst->syslog_facility) {
		num = fr_str2int(syslog_facility_table, inst->syslog_facility, -1);
		if (num < 0) {
			cf_log_err_cs(conf, "Invalid syslog facility \"%s\"", inst->syslog_facility);
			return -1;
		}

		inst->syslog_priority |= num;
	}

	num = fr_str2int(syslog_severity_table, inst->syslog_severity, -1);
	if (num < 0) {
		cf_log_err_cs(conf, "Invalid syslog severity \"%s\"", inst->syslog_severity);
		return -1;
	}
	inst->syslog_priority |= num;
#endif

	if (!inst->line && !inst->reference) {
		cf_log_err_cs(conf, "Must specify a log format, or reference");
		return -1;
	}

	inst->ef = exfile_init(inst, 256, 30, true);
	if (!inst->ef) {
		cf_log_err_cs(conf, "Failed creating log file context");
		return -1;
	}

	inst->cs = conf;
	return 0;
}


/*
 *	Escape unprintable characters.
 */
static size_t linelog_escape_func(UNUSED REQUEST *request,
		char *out, size_t outlen, char const *in,
		UNUSED void *arg)
{
	if (outlen == 0) return 0;

	if (outlen == 1) {
		*out = '\0';
		return 0;
	}

	return fr_prints(out, outlen, in, -1, 0);
}

static rlm_rcode_t CC_HINT(nonnull) mod_do_linelog(void *instance, REQUEST *request)
{
	int fd = -1;
	rlm_linelog_t *inst = (rlm_linelog_t*) instance;
	char const *value = inst->line;

#ifdef HAVE_GRP_H
	gid_t gid;
	char *endptr;
#endif
	char path[2048];
	char line[4096];

	line[0] = '\0';

	if (inst->reference) {
		CONF_ITEM *ci;
		CONF_PAIR *cp;

		if (radius_xlat(line + 1, sizeof(line) - 1, request, inst->reference, linelog_escape_func, NULL) < 0) {
			return RLM_MODULE_FAIL;
		}

		line[0] = '.';	/* force to be in current section */

		/*
		 *	Don't allow it to go back up
		 */
		if (line[1] == '.') goto do_log;

		ci = cf_reference_item(NULL, inst->cs, line);
		if (!ci) {
			RDEBUG2("No such entry \"%s\"", line);
			return RLM_MODULE_NOOP;
		}

		if (!cf_item_is_pair(ci)) {
			RDEBUG2("Entry \"%s\" is not a variable assignment ", line);
			goto do_log;
		}

		cp = cf_item_to_pair(ci);
		value = cf_pair_value(cp);
		if (!value) {
			RWDEBUG2("Entry \"%s\" has no value", line);
			return RLM_MODULE_OK;
		}

		/*
		 *	Value exists, but is empty.  Don't log anything.
		 */
		if (!*value) return RLM_MODULE_OK;
	}

 do_log:
	/*
	 *	FIXME: Check length.
	 */
	if (radius_xlat(line, sizeof(line) - 1, request, value, linelog_escape_func, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

#ifdef HAVE_SYSLOG_H
	if (strcmp(inst->filename, "syslog") == 0) {
		syslog(inst->syslog_priority, "%s", line);
		return RLM_MODULE_OK;
	}
#endif

	/*
	 *	We're using a real filename now.
	 */
	if (radius_xlat(path, sizeof(path), request, inst->filename, inst->escape_func, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	fd = exfile_open(inst->ef, path, inst->permissions);
	if (fd < 0) {
		ERROR("rlm_linelog: Failed to open %s: %s", path, fr_syserror(errno));
		return RLM_MODULE_FAIL;
	}

	if (inst->group != NULL) {
		gid = strtol(inst->group, &endptr, 10);
		if (*endptr != '\0') {
			if (rad_getgid(request, &gid, inst->group) < 0) {
				RDEBUG2("Unable to find system group \"%s\"", inst->group);
				goto skip_group;
			}
		}

		if (chown(path, -1, gid) == -1) {
			RDEBUG2("Unable to change system group of \"%s\"", path);
		}
	}

 skip_group:
	strcat(line, "\n");

	if (write(fd, line, strlen(line)) < 0) {
		exfile_close(inst->ef, fd);
		ERROR("rlm_linelog: Failed writing: %s", fr_syserror(errno));
		return RLM_MODULE_FAIL;
	}

	exfile_close(inst->ef, fd);
	return RLM_MODULE_OK;
}


/*
 *	Externally visible module definition.
 */
extern module_t rlm_linelog;
module_t rlm_linelog = {
	.magic		= RLM_MODULE_INIT,
	.name		= "linelog",
	.type		= RLM_TYPE_HUP_SAFE,
	.inst_size	= sizeof(rlm_linelog_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_do_linelog,
		[MOD_AUTHORIZE]		= mod_do_linelog,
		[MOD_PREACCT]		= mod_do_linelog,
		[MOD_ACCOUNTING]	= mod_do_linelog,
		[MOD_PRE_PROXY]		= mod_do_linelog,
		[MOD_POST_PROXY]	= mod_do_linelog,
		[MOD_POST_AUTH]		= mod_do_linelog,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_do_linelog,
		[MOD_SEND_COA]		= mod_do_linelog
#endif
	},
};
