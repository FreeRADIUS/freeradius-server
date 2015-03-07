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
#  include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef HAVE_GRP_H
#  include <grp.h>
#endif

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#  ifndef LOG_INFO
#    define LOG_INFO (0)
#  endif
#endif

#include <sys/uio.h>

typedef enum {
	LINELOG_DST_FILE = 0,	//!< Log to a file.
	LINELOG_DST_SYSLOG,	//!< Log to syslog.
} linelog_dst_t;

/** linelog module instance
 */
typedef struct rlm_linelog_t {
	linelog_dst_t		log_dst;		//!< Logging destination.

	char const		*syslog_facility;	//!< Syslog facility string.
	char const		*syslog_severity;	//!< Syslog severity string.
	int			syslog_priority;	//!< Bitwise | of severity and facility.

	char const		*filename;		//!< File to write to.
	uint32_t		permissions;		//!< Permissions to use when creating new files.
	char const		*group_str;		//!< Group to set on new files.
	gid_t			group;			//!< Resolved gid.
	exfile_t		*ef;			//!< Exclusive file access handle.

	value_pair_tmpl_t	*log_src;		//!< Source of log messages.

	value_pair_tmpl_t	*log_ref;		//!< Path to a #CONF_PAIR (to use as the source of
							///< log messages).
	CONF_SECTION		*cs;			//!< #CONF_SECTION to use as the root for #log_ref lookups.
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
	{ "syslog_facility", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_linelog_t, syslog_facility), NULL },
	{ "syslog_severity", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_linelog_t, syslog_severity), "info" },
	{ "permissions", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_linelog_t, permissions), "0600" },
	{ "group", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_linelog_t, group_str), NULL },
	{ "format", FR_CONF_OFFSET(PW_TYPE_TMPL, rlm_linelog_t, log_src), NULL },
	{ "reference", FR_CONF_OFFSET(PW_TYPE_TMPL, rlm_linelog_t, log_ref), NULL },
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
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

	if (strcmp(inst->filename, "syslog") == 0) {
#ifndef HAVE_SYSLOG_H
		cf_log_err_cs(conf, "Syslog output is not supported on this system");
		return -1;
#else
		inst->log_dst = LINELOG_DST_SYSLOG;

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
	} else {
		inst->log_dst = LINELOG_DST_FILE;

		inst->ef = exfile_init(inst, 64, 30);
		if (!inst->ef) {
			cf_log_err_cs(conf, "Failed creating log file context");
			return -1;
		}

		if (inst->group_str) {
			char *endptr;

			inst->group = strtol(inst->group_str, &endptr, 10);
			if (*endptr != '\0') {
				if (rad_getgid(inst, &(inst->group), inst->group_str) < 0) {
					cf_log_err_cs(conf, "Unable to find system group \"%s\"", inst->group_str);
					return -1;
				}
			}
		}
	}

	if (!inst->log_src && !inst->log_ref) {
		cf_log_err_cs(conf, "Must specify a log format, or reference");
		return -1;
	}

	inst->cs = conf;
	return 0;
}


/** Escape unprintable characters
 *
 * ``\n``, ``\r`` are escaped as ``\r`` and ``\n``, all other unprintables are escaped as
 * ``\<oct><oct><oct>``.
 *
 * @param request The current request.
 * @param out Where to write the escaped string.
 * @param outlen Length of the output buffer.
 * @param in String to escape.
 * @param arg unused.
 */
static size_t linelog_escape_func(UNUSED REQUEST *request, char *out, size_t outlen,
				  char const *in, UNUSED void *arg)
{
	int len = 0;

	if (outlen == 0) return 0;
	if (outlen == 1) {
		*out = '\0';
		return 0;
	}

	while (in[0]) {
		if (in[0] >= ' ') {
			if (in[0] == '\\') {
				if (outlen <= 2) break;
				outlen--;
				*out++ = '\\';
				len++;
			}

			outlen--;
			if (outlen == 1) break;
			*out++ = *in++;
			len++;
			continue;
		}

		switch (in[0]) {
		case '\n':
			if (outlen <= 2) break;
			*out++ = '\\';
			*out++ = 'n';
			in++;
			len += 2;
			break;

		case '\r':
			if (outlen <= 2) break;
			*out++ = '\\';
			*out++ = 'r';
			in++;
			len += 2;
			break;

		default:
			if (outlen <= 4) break;
			snprintf(out, outlen,  "\\%03o", (uint8_t) *in);
			in++;
			out += 4;
			outlen -= 4;
			len += 4;
			break;
		}
	}

	*out = '\0';
	return len;
}

/** Write a linelog message
 *
 * Write a log message to syslog or a flat file.
 *
 * @param instance of rlm_linelog.
 * @param request The current request.
 * @return #RLM_MODULE_NOOP if no message to log, #RLM_MODULE_FAIL if we failed writing the
 *	message, #RLM_MODULE_OK on success.
 */
static rlm_rcode_t mod_do_linelog(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_do_linelog(void *instance, REQUEST *request)
{
	int			fd = -1;
	char			buff[4096], path[2048];
	char			*p = buff;
	rlm_linelog_t		*inst = instance;
	char const		*value;
	value_pair_tmpl_t	empty, *vpt = NULL, *vpt_p = NULL;
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	ssize_t			slen;

	buff[0] = '.';	/* force to be in current section */
	buff[1] = '\0';
	buff[2] = '\0';

	/*
	 *	Expand log_ref to a config path, using the module
	 *	configuration section as the root.
	 */
	if (inst->log_ref) {
		CONF_ITEM	*ci;
		CONF_PAIR	*cp;
		char const	*tmpl_str;

		if (tmpl_expand(NULL, buff + 1, sizeof(buff) - 1,
				request, inst->log_ref, linelog_escape_func, NULL) < 0) {
			return RLM_MODULE_FAIL;
		}

		if (buff[1] == '.') p++;

		/*
		 *	Don't go back up.
		 */
		if (buff[2] == '.') {
			REDEBUG("Invalid path \"%s\"", p);
			return RLM_MODULE_FAIL;
		}

		ci = cf_reference_item(NULL, inst->cs, p);
		if (!ci) {
			RDEBUG2("Path \"%s\" doesn't exist", p);
			goto default_msg;
		}

		if (!cf_item_is_pair(ci)) {
			REDEBUG("Path \"%s\" resolves to a section (should be a pair)", p);
			return RLM_MODULE_FAIL;
		}

		cp = cf_item_to_pair(ci);
		tmpl_str = cf_pair_value(cp);
		if (!tmpl_str || (tmpl_str[0] == '\0')) {
			RDEBUG2("Path \"%s\" resolves to an empty config pair", p);
			vpt_p = tmpl_init(&empty, TMPL_TYPE_LITERAL, "", 0);
			goto open_log;
		}

		/*
		 *	Alloc a template from the value of the CONF_PAIR
		 *	using request as the context (which will hopefully avoid a malloc).
		 */
		slen = tmpl_afrom_str(request, &vpt, tmpl_str, talloc_array_length(tmpl_str) - 1,
				      cf_pair_value_type(cp), REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
		if (slen <= 0) {
			REMARKER(tmpl_str, -slen, fr_strerror());
			return RLM_MODULE_FAIL;
		}
		vpt_p = vpt;

		goto open_log;
	}

default_msg:
	if (!inst->log_src) {
		RDEBUG2("No default message configured");
		return RLM_MODULE_NOOP;
	}
	/*
	 *	Use the pre-parsed format template
	 */
	RDEBUG2("Using default message");
	vpt_p = inst->log_src;


open_log:
	if (inst->log_dst == LINELOG_DST_FILE) {
		if (radius_xlat(path, sizeof(path), request, inst->filename, rad_filename_escape, NULL) < 0) {
			return RLM_MODULE_FAIL;
		}

		/* check path and eventually create subdirs */
		p = strrchr(path, '/');
		if (p) {
			*p = '\0';
			if (rad_mkdir(path, 0700, -1, -1) < 0) {
				RERROR("Failed to create directory %s: %s", path, fr_syserror(errno));
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
			*p = '/';
		}

		fd = exfile_open(inst->ef, path, inst->permissions, true);
		if (fd < 0) {
			RERROR("Failed to open %s: %s", path, fr_syserror(errno));
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		if (inst->group_str && (chown(path, -1, inst->group) == -1)) {
			RWARN("Unable to change system group of \"%s\": %s", path, fr_strerror());
		}
	}

	/*
	 *	Get the data we're going to log
	 */
	slen = tmpl_expand(&value, buff, sizeof(buff), request, vpt_p, linelog_escape_func, NULL);
	if (slen < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	/*
	 *	Write out the log entry
	 */
	if (inst->log_dst == LINELOG_DST_FILE) {
		static char const *nl = "\n";
		struct iovec vector[] = {{NULL, slen}, {NULL, 1}};

		/* iov_base is not declared as const *sigh* */
		memcpy(&vector[0].iov_base, &value, sizeof(vector[0].iov_base));
		memcpy(&vector[1].iov_base, &nl, sizeof(vector[1].iov_base));

		if (writev(fd, vector, sizeof(vector) / sizeof(*vector)) < 0) {
			RERROR("Failed writing to \"%s\": %s", path, fr_syserror(errno));
			exfile_close(inst->ef, fd);
			return RLM_MODULE_FAIL;
		}

		exfile_close(inst->ef, fd);

#ifdef HAVE_SYSLOG_H
	} else {
		syslog(inst->syslog_priority, "%s", buff);
#endif
	}

finish:
	if (fd >= 0) exfile_close(inst->ef, fd);
	talloc_free(vpt);

	return rcode;
}


/*
 *	Externally visible module definition.
 */
extern module_t rlm_linelog;
module_t rlm_linelog = {
	RLM_MODULE_INIT,
	"linelog",
	RLM_TYPE_HUP_SAFE,   	/* type */
	sizeof(rlm_linelog_t),
	module_config,
	mod_instantiate,		/* instantiation */
	NULL,				/* detach */
	{
		mod_do_linelog,		/* authentication */
		mod_do_linelog,		/* authorization */
		mod_do_linelog,		/* preaccounting */
		mod_do_linelog,		/* accounting */
		NULL,			/* checksimul */
		mod_do_linelog, 	/* pre-proxy */
		mod_do_linelog,		/* post-proxy */
		mod_do_linelog		/* post-auth */
#ifdef WITH_COA
		, mod_do_linelog,	/* recv-coa */
		mod_do_linelog		/* send-coa */
#endif
	},
};
