/*
 * rlm_detail.c	accounting:    Write the "detail" files.
 *
 * Version:	$Id$
 *
 *  This program is is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2 if the
 *  License as published by the Free Software Foundation.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright 2000  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<sys/stat.h>

#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>
#include	<fcntl.h>

#include	"radiusd.h"
#include	"modules.h"
#define 	DIRLEN	8192

struct detail_instance {
	/* detail file */
	char *detailfile;

	/* detail file permissions */
	int detailperm;

	/* directory permissions */
	int dirperm;

	/* last made directory */
	char *last_made_directory;
};

static CONF_PARSER module_config[] = {
	{ "detailfile",    PW_TYPE_STRING_PTR,
	  offsetof(struct detail_instance,detailfile), NULL, "%A/%{Client-IP-Address}/detail" },
	{ "detailperm",    PW_TYPE_INTEGER,
	  offsetof(struct detail_instance,detailperm), NULL, "0600" },
	{ "dirperm",       PW_TYPE_INTEGER,
	  offsetof(struct detail_instance,dirperm),    NULL, "0755" },
	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	(Re-)read radiusd.conf into memory.
 */
static int detail_instantiate(CONF_SECTION *conf, void **instance)
{
	struct detail_instance *inst;

	inst = rad_malloc(sizeof *inst);

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	inst->last_made_directory = NULL;

	*instance = inst;
	return 0;
}

/*
 *	Accounting - write the detail files.
 */
static int detail_accounting(void *instance, REQUEST *request)
{
	int		outfd;
	FILE		*outfp;
	char		buffer[DIRLEN];
	char		*p;
	VALUE_PAIR	*pair;
	int		ret = RLM_MODULE_OK;
	struct stat	st;

	struct detail_instance *inst = instance;

	/*
	 *	Create a directory for this nas.
	 *
	 *	Generate the path for the detail file.  Use the
	 *	same format, but truncate at the last /.  Then
	 *	feed it through radius_xlat2() to expand the
	 *	variables.
	 */
	radius_xlat2(buffer, sizeof(buffer), inst->detailfile, request);
	DEBUG2("rlm_detail: %s expands to %s", inst->detailfile, buffer);

	/*
	 *	Grab the last directory delimiter.
	 */
	p = strrchr(buffer,'/');

	/*
	 *	There WAS a directory delimiter there, and
	 *	the file doesn't exist, so
	 *	we prolly must create it the dir(s)
	 */
	if ((p) && (stat(buffer, &st) < 0)) {
		*p = '\0';	
		/*
		 *	NO previously cached directory name, so we've
		 *	got to create a new one.
		 *
		 *	OR the new directory name is different than the old,
		 *	so we've got to create a new one.
		 *
		 *	OR the cached directory has somehow gotten removed,
		 *	so we've got to create a new one.
		 */
		if ((inst->last_made_directory == NULL) ||
		    (strcmp(inst->last_made_directory, buffer) != 0)) { 
			
			/*
			 *	Free any previously cached name.
			 */
			if (inst->last_made_directory != NULL) {
				free((char *) inst->last_made_directory);
				inst->last_made_directory = NULL;
			}
			
			/*
			 *	Go create possibly multiple directories.
			 */
			if (rad_mkdir(buffer, inst->dirperm) < 0) {
				radlog(L_ERR, "rlm_detail: Failed to create directory %s: %s", buffer, strerror(errno));
				return RLM_MODULE_FAIL;
			}
			inst->last_made_directory = strdup(buffer);
		}
		
		*p = '/';	
	} /* else there was no directory delimiter. */

	/*
	 *	Open & create the file, with the given permissions.
	 */
	if ((outfd = open(buffer, O_WRONLY|O_APPEND|O_CREAT,
			  inst->detailperm)) < 0) {
		radlog(L_ERR, "rlm_detail: Couldn't open file %s: %s",
		       buffer, strerror(errno));
		ret = RLM_MODULE_FAIL;

	} else if ((outfp = fdopen(outfd, "a")) == NULL) {
		radlog(L_ERR, "rlm_detail: Couldn't open file %s: %s",
		       buffer, strerror(errno));
		ret = RLM_MODULE_FAIL;
		close(outfd);
	} else {
		/* Post a timestamp */
		fputs(ctime(&request->timestamp), outfp);

		/* Write each attribute/value to the log file */
		pair = request->packet->vps;
		while (pair) {
			if (pair->attribute != PW_PASSWORD) {
				fputs("\t", outfp);
				vp_print(outfp, pair);
				fputs("\n", outfp);
			}
			pair = pair->next;
		}

		/*
		 *	Add non-protocol attibutes.
		 */
		fprintf(outfp, "\tTimestamp = %ld\n", request->timestamp);
		if (request->packet->verified)
			fputs("\tRequest-Authenticator = Verified\n", outfp);
		else
			fputs("\tRequest-Authenticator = None\n", outfp);
		fputs("\n", outfp);
		fclose(outfp);
	}

	return ret;
}


/*
 *	Clean up.
 */
static int detail_detach(void *instance)
{
        struct detail_instance *inst = instance;
	free((char *) inst->detailfile);

	if (inst->last_made_directory)
		free((char*) inst->last_made_directory);
        free(inst);
	return 0;
}


/* globally exported name */
module_t rlm_detail = {
	"detail",
	0,				/* type: reserved */
	NULL,				/* initialization */
	detail_instantiate,		/* instantiation */
	{
		NULL,			/* authentication */
		NULL,		 	/* authorization */
		NULL,			/* preaccounting */
		detail_accounting,	/* accounting */
		NULL			/* checksimul */
	},
	detail_detach,			/* detach */
	NULL				/* destroy */
};

