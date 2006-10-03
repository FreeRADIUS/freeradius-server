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
 * Copyright 2004  The FreeRADIUS server project
 * Copyright 2004  Alan DeKok <aland@freeradius.org>
 */

#include <freeradius-devel/autoconf.h>

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>


static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_linelog_t {
	char		*filename;
	char		*line;
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
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


static int linelog_detach(void *instance)
{
	rlm_linelog_t *inst = instance;

	free(inst->filename);
	free(inst->line);
	
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

	*instance = inst;

	return 0;
}


/*
 *	Escape unprintable characters.
 */
static int linelog_escape_func(char *out, int outlen, const char *in)
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
	int fd;
	char buffer[4096];
	char line[1024];
	rlm_linelog_t *inst;

	inst = (rlm_linelog_t*) instance;

	/*
	 *	FIXME: Check length.
	 */
	radius_xlat(buffer, sizeof(buffer), inst->filename, request, NULL);

	fd = open(buffer, O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (fd == -1) {
		radlog(L_ERR, "rlm_linelog: Failed to open %s: %s",
		       buffer, strerror(errno));
		return RLM_MODULE_FAIL;
	}

	/*
	 *	FIXME: Check length.
	 */
	radius_xlat(line, sizeof(line) - 1, inst->line, request,
		    linelog_escape_func);
	strcat(line, "\n");
	
	write(fd, line, strlen(line));
	close(fd);

	return RLM_MODULE_OK;
}


/*
 *	Externally visible module definition.
 */
module_t rlm_linelog = {
	RLM_MODULE_INIT,
	"linelog",
	RLM_TYPE_THREAD_SAFE,		/* type */
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
