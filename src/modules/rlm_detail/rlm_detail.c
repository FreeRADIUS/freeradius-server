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
#include	<sys/select.h>

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

	/* if we want file locking */
	int locking;
};

static CONF_PARSER module_config[] = {
	{ "detailfile",    PW_TYPE_STRING_PTR,
	  offsetof(struct detail_instance,detailfile), NULL, "%A/%{Client-IP-Address}/detail" },
	{ "detailperm",    PW_TYPE_INTEGER,
	  offsetof(struct detail_instance,detailperm), NULL, "0600" },
	{ "dirperm",       PW_TYPE_INTEGER,
	  offsetof(struct detail_instance,dirperm),    NULL, "0755" },
	{ "locking",       PW_TYPE_BOOLEAN,
	  offsetof(struct detail_instance,locking),    NULL, "no" },
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
	int		locked;
	int		lock_count;
	struct timeval	tv;
	REALM		*proxy_realm;
	char		proxy_buffer[16];

	struct detail_instance *inst = instance;

	/*
	 *	Create a directory for this nas.
	 *
	 *	Generate the path for the detail file.  Use the
	 *	same format, but truncate at the last /.  Then
	 *	feed it through radius_xlat() to expand the
	 *	variables.
	 */
	radius_xlat(buffer, sizeof(buffer), inst->detailfile, request, NULL);
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
	 *
	 *	If we're not using locking, we'll just pass straight though
	 *	the while loop.
	 *	If we fail to aquire the filelock in 80 tries (approximately
	 *	two seconds) we bail out.
	 */
	locked = 0;
	lock_count = 0;
	do {
		if ((outfd = open(buffer, O_WRONLY | O_APPEND | O_CREAT,
				  inst->detailperm)) < 0) {
			radlog(L_ERR, "rlm_detail: Couldn't open file %s: %s",
			       buffer, strerror(errno));
			ret = RLM_MODULE_FAIL;
			break;
		}
		if (inst->locking) {
			lseek(outfd, 0L, SEEK_SET);
			if (rad_lockfd_nonblock(outfd, 0) < 0) {
				close(outfd);
				tv.tv_sec = 0;
				tv.tv_usec = 25000;
				select(0, NULL, NULL, NULL, &tv);
				lock_count++;
			} else {
				DEBUG("rlm_detail: Aquired filelock, tried %d time(s)",
				      lock_count + 1);
				locked = 1;
			}
		}
	} while (!locked && inst->locking && lock_count < 80);

	if (!locked && inst->locking && lock_count >= 80) {
		radlog(L_ERR, "rlm_detail: Failed to aquire filelock for %s, giving up",
		       buffer);
		outfd = -1;
		ret = RLM_MODULE_FAIL;
	}

	outfp = NULL;
	if (outfd > -1) {
		if ((outfp = fdopen(outfd, "a")) == NULL) {
			radlog(L_ERR, "rlm_detail: Couldn't open file %s: %s",
			       buffer, strerror(errno));
			ret = RLM_MODULE_FAIL;
			if (inst->locking) {
				lseek(outfd, 0L, SEEK_SET);
				rad_unlockfd(outfd, 0);
				DEBUG("rlm_detail: Released filelock");
			}
			close(outfd);
		}
	}

	if (outfd > -1 && outfp) {
		/* Post a timestamp */
		fseek(outfp, 0L, SEEK_END);
		fputs(ctime_r(&request->timestamp, buffer), outfp);

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
		if ((pair = pairfind(request->config_items, PW_PROXY_TO_REALM))
		    != NULL) {
			proxy_realm = realm_find(pair->strvalue, TRUE);
			if (proxy_realm) {
				memset((char *) proxy_buffer, 0, 16);
				ip_ntoa(proxy_buffer, proxy_realm->acct_ipaddr);
				fprintf(outfp, "\tFreeradius-Proxied-To = %s\n",
				        proxy_buffer);
				DEBUG("rlm_detail: Freeradius-Proxied-To set to %s",
				      proxy_buffer);
			}
		}
		fprintf(outfp, "\tTimestamp = %ld\n", request->timestamp);
		if (request->packet->verified == 2)
			fputs("\tRequest-Authenticator = Verified\n", outfp);
		else if (request->packet->verified == 1)
			fputs("\tRequest-Authenticator = None\n", outfp);
		pair = NULL;

		fputs("\n", outfp);

		if (inst->locking) {
			fflush(outfp);
			lseek(outfd, 0L, SEEK_SET);
			rad_unlockfd(outfd, 0);
			DEBUG("rlm_detail: Released filelock");
		}
	
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

