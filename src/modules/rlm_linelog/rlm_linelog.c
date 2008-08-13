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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>

#ifndef LOG_AUTHPRIV
#define LOG_AUTHPRIV LOG_USER
#endif

#ifndef LOG_PID
#define LOG_PID (0)
#endif

#ifndef LOG_INFO
#define LOG_INFO (0)
#endif
#endif

/*
 *	Define a structure for our module configuration.
 */
typedef struct rlm_linelog_t {
	CONF_SECTION	*cs;
	char		*filename;
	char		*line;
	char		*reference;
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
	{ "filename",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_linelog_t,filename), NULL,  NULL},
	{ "format",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_linelog_t,line), NULL,  NULL},
	{ "reference",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_linelog_t,reference), NULL,  NULL},
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


static int linelog_detach(void *instance)
{
	rlm_linelog_t *inst = instance;

	free(inst);
	return 0;
}

/*
 *	Instantiate the module.
 */
static int linelog_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_linelog_t *inst;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(*inst));
	memset(inst, 0, sizeof(*inst));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		linelog_detach(inst);
		return -1;
	}

	if (!inst->filename) {
		radlog(L_ERR, "rlm_linelog: Must specify an output filename");
		linelog_detach(inst);
		return -1;
	}

#ifndef HAVE_SYSLOG_H
	if (strcmp(inst->filename, "syslog") == 0) {
		radlog(L_ERR, "rlm_linelog: Syslog output is not supported");
		linelog_detach(inst);
		return -1;
	}
#endif

	if (!inst->line) {
		radlog(L_ERR, "rlm_linelog: Must specify a log format");
		linelog_detach(inst);
		return -1;
	}

	inst->cs = conf;
	*instance = inst;

	return 0;
}


/*
 *	Escape unprintable characters.
 */
static size_t linelog_escape_func(char *out, size_t outlen, const char *in)
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
			snprintf(out, outlen,  "\\%03o", *in);
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

static int do_linelog(void *instance, REQUEST *request)
{
	int fd = -1;
	char buffer[4096];
	char line[1024];
	rlm_linelog_t *inst = (rlm_linelog_t*) instance;
	const char *value = inst->line;

	/*
	 *	FIXME: Check length.
	 */
	if (strcmp(inst->filename, "syslog") != 0) {
		radius_xlat(buffer, sizeof(buffer), inst->filename, request,
			    NULL);
		
		fd = open(buffer, O_WRONLY | O_APPEND | O_CREAT, 0600);
		if (fd == -1) {
			radlog(L_ERR, "rlm_linelog: Failed to open %s: %s",
			       buffer, strerror(errno));
			return RLM_MODULE_FAIL;
		}
	}

	if (inst->reference) {
		CONF_ITEM *ci;
		CONF_PAIR *cp;

		radius_xlat(line + 1, sizeof(line) - 2, inst->reference,
			    request, linelog_escape_func);
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

		cp = cf_itemtopair(ci);
		value = cf_pair_value(cp);
		if (!value) {
			RDEBUG2("Entry \"%s\" has no value", line);
			goto do_log;
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
	radius_xlat(line, sizeof(line) - 1, value, request,
		    linelog_escape_func);

	if (fd >= 0) {
		strcat(line, "\n");
		
		write(fd, line, strlen(line));
		close(fd);

#ifdef HAVE_SYSLOG_H
	} else {
		syslog(LOG_AUTHPRIV | LOG_PID | LOG_INFO, "%s", line);
#endif
	}

	return RLM_MODULE_OK;
}


/*
 *	Externally visible module definition.
 */
module_t rlm_linelog = {
	RLM_MODULE_INIT,
	"linelog",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	linelog_instantiate,		/* instantiation */
	linelog_detach,			/* detach */
	{
		do_linelog,	/* authentication */
		do_linelog,	/* authorization */
		do_linelog,	/* preaccounting */
		do_linelog,	/* accounting */
		NULL,		/* checksimul */
		do_linelog, 	/* pre-proxy */
		do_linelog,	/* post-proxy */
		do_linelog	/* post-auth */
	},
};
