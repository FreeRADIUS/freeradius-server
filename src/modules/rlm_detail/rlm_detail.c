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
	char *detailfile;

        /* detail file permissions */
        int detailperm;

	/* directory permissions */
	int dirperm;
};

static int detail_init(void)
{
	return 0;
}

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

        inst = malloc(sizeof *inst);
        if (!inst) {
                radlog(L_ERR|L_CONS, "Out of memory\n");
                return -1;
        }

        if (cf_section_parse(conf, module_config) < 0) {
                free(inst);
                return -1;
        }

        inst->detailfile = config.detailfile;
        inst->detailperm = config.detailperm;
	inst->dirperm = config.dirperm;
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
	char		nasname[128];
	char		buffer[512];
	char		filename[512];
	char		*p;
	VALUE_PAIR	*pair;
	uint32_t	nas;
	NAS		*cl;
	int		ret = RLM_MODULE_OK;

	struct detail_instance *inst = instance;

	/*
	 *	Find out the name of this terminal server. We try
	 *	to find the PW_NAS_IP_ADDRESS in the naslist file.
	 *	If that fails, we look for the originating address.
	 *	Only if that fails we resort to a name lookup.
	 */
	cl = NULL;
	nas = request->packet->src_ipaddr;
	if ((pair = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS)) != NULL)
		nas = pair->lvalue;
	if (request->proxy && request->proxy->src_ipaddr)
		nas = request->proxy->src_ipaddr;

	if ((cl = nas_find(nas)) != NULL) {
		if (cl->shortname[0])
			strcpy(nasname, cl->shortname);
		else
			strcpy(nasname, cl->longname);
	}

	if (cl == NULL) {
		ip_hostname(nasname, sizeof(nasname), nas);
	}

	/*
	 *	Create a directory for this nas.
	 *
	 *	Generate the path for the detail file.  Use the
	 *	same format, but truncate at the last /.  Then
	 *	feed it through radius_xlat2() to expand the
	 *	variables.
	 */
	strNcpy(filename, inst->detailfile, sizeof(filename));
	p = strrchr(filename,'/');

	if (p) *p = '\0';

	radius_xlat2(buffer, sizeof(buffer), filename, request,
		     request->reply->vps);
	if ((mkdir(buffer, inst->dirperm) == -1) && errno != EEXIST) {
		radlog(L_ERR, "Detail: Couldn't create %s: %s",
		       buffer, strerror(errno));
		return RLM_MODULE_FAIL;
	}
	
	/*
	 *	Write Detail file.
	 *
	 *	Generate the filename for the detail file.  Use the
	 *	radius_xlat2() function to allow for variable detail
	 *	filenames.
	 */
	radius_xlat2(buffer, sizeof(buffer), inst->detailfile,
		     request, request->reply->vps);

	/*
	 *	Open & create the file, with the given permissions.
	 */
	if ((outfd = open(buffer, O_WRONLY|O_APPEND|O_CREAT,
			  inst->detailperm)) < 0) {
		radlog(L_ERR, "Detail: Couldn't open file %s: %s",
		       buffer, strerror(errno));
		ret = RLM_MODULE_FAIL;

	} else if ((outfp = fdopen(outfd, "a")) == NULL) {
		radlog(L_ERR, "Detail: Couldn't open file %s: %s",
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
	free(inst->detailfile);
        free(inst);
	return 0;
}


/* globally exported name */
module_t rlm_detail = {
	"detail",
	0,				/* type: reserved */
	detail_init,			/* initialization */
	detail_instantiate,		/* instantiation */
	NULL,		 		/* authorization */
	NULL,				/* authentication */
	NULL,				/* preaccounting */
	detail_accounting,		/* accounting */
	detail_detach,			/* detach */
	NULL				/* destroy */
};

