/*
 * rlm_detail.c	accounting:    Write the "detail" files.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/stat.h>

#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>
#include	<fcntl.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

struct detail_instance {
	/* detail file */
	const char *detailfile;

        /* detail file permissions */
        int detailperm;

	/* directory permissions */
	int dirperm;

	/* last made directory */
	const char *last_made_directory;
};

/*
 *	A temporary holding area for config values to be extracted
 *	into, before they are copied into the instance data
 */
static struct detail_instance config;

static CONF_PARSER module_config[] = {
	{ "detailfile",    PW_TYPE_STRING_PTR, &config.detailfile, "%A/%n/detail" },
        { "detailperm",    PW_TYPE_INTEGER,    &config.detailperm, "0600" },
	{ "dirperm",       PW_TYPE_INTEGER,    &config.dirperm,    "0755" },
	{ NULL, -1, NULL, NULL }
};

/*
 *	(Re-)read radiusd.conf into memory.
 */
static int detail_instantiate(CONF_SECTION *conf, void **instance)
{
        struct detail_instance *inst;
	size_t p=0;

        inst = malloc(sizeof *inst);
        if (!inst) {
                radlog(L_ERR|L_CONS, "rlm_detail: Out of memory\n");
                return -1;
        }

        if (cf_section_parse(conf, module_config) < 0) {
                free(inst);
                return -1;
        }

	/*
	 *	Sanitize the name for security!  Only permit letters, numbers,
	 *	-, _, / and \.  Anything else will be rejected.
	 */

	p = strspn(config.detailfile, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/%.");

	if (p != strlen(config.detailfile)) {
		radlog(L_ERR|L_CONS, "rlm_detail: Illegal character in detail filename.");
		return -1;
	}
			
        inst->detailfile = config.detailfile;
        inst->detailperm = config.detailperm;
	inst->dirperm = config.dirperm;
	inst->last_made_directory = NULL;
	config.detailfile = NULL;

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
	char		buffer[8192];
	char		*p;
	size_t		l;
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
	radius_xlat2(buffer, sizeof(buffer), inst->detailfile, request,
		     request->reply->vps);

	/*
	 *	Sanitize the name for security!  Only permit letters, numbers,
	 *	-, _, / and \.  Anything else will be rejected.
	 */

	if (strstr(buffer, "..")) {
		radlog(L_ERR, "rlm_detail: Directory \"%s\" contains \"..\" which is not valid.",
			buffer);
		return RLM_MODULE_FAIL;
	}

	l = strspn(buffer, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/.");

	if (l != strlen(buffer)) {
		radlog(L_ERR, "rlm_detail: Directory \"%s\" contains an invalid character.",
		       buffer);
		return RLM_MODULE_FAIL;
	}
			
	/*
	 *	Grab the last directory delimiter.
	 */
	p = strrchr(buffer,'/');

	/*
	 *	There WAS a directory delimiter there, so let's
	 *	go create the relevant directories.
	 */
	if (p) {
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
		    (strcmp(inst->last_made_directory, buffer) != 0) ||
		    (stat(buffer, &st) == -1)) {
			
			/*
			 *	Free any previously cached name.
			 */
			if (inst->last_made_directory != NULL) {
				free((char *) inst->last_made_directory);
				inst->last_made_directory = NULL;
			}
			
			/*
			 *	Try to create the new directory.
			 */
			if ((mkdir(buffer, inst->dirperm) == -1) &&
			    (errno != EEXIST)) {
				radlog(L_ERR, "rlm_detail: Couldn't create %s: %s",
				       buffer, strerror(errno));
				
				return RLM_MODULE_FAIL;
			}
			
			/*
			 *	Save a copy of the directory name that
			 *	we just created.
			 */
			inst->last_made_directory = strdup(buffer);
		}
		
		/*
		 *	Re-create the file name, by replacing the
		 *	directory delimiter that we removed above.
		 */
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
	NULL,		 		/* authorization */
	NULL,				/* authentication */
	NULL,				/* preaccounting */
	detail_accounting,		/* accounting */
	NULL,				/* checksimul */
	detail_detach,			/* detach */
	NULL				/* destroy */
};

