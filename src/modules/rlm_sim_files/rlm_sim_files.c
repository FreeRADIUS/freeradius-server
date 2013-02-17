/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
 * @file rlm_sim_files.c
 * @brief Parses simtriplets files to provide a data src for eap_sim.
 *
 * This is an authorization-only module that walks the file every time.
 *
 * This is an example of getting data for rlm_eap_sim from an external
 * place.
 *
 * In a real system, this would be replaced with a lookup to the SS7
 * network, but those interfaces are distinctly non-standard, and might
 * even be totally proprietary.
 *
 * The triplets file contains records of the form:
@verbatim
IMSI            RAND                             SRES     Kc
232420100000015,30000000000000000000000000000000,30112233,445566778899AABB
@endverbatim
 *
 * There must be *three* entries for every IMSI for it to be considered valid.
 * Lines starting with # are ignored.
 *
 * Conveniently, this file format is produced by XXXX.
 *
 * @copyright 2004  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * @copyright 2006  The FreeRADIUS server project
 */
#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#include	<sys/stat.h>
#include	<ctype.h>
#include	<fcntl.h>
#include	<limits.h>

#include        "../rlm_eap/libeap/eap_sim.h"

struct sim_file_instance {
	/* autz */
	char *file;
};

static const CONF_PARSER module_config[] = {
	{ "simtriplets",	PW_TYPE_STRING_PTR,
	  offsetof(struct sim_file_instance, file),
	  NULL, "${raddbdir}/simtriplets.dat" },

	{ NULL, -1, 0, NULL, NULL }
};

/*
 *	(Re-)read the "users" file into memory.
 */
static int sim_file_instantiate(CONF_SECTION *conf, void **instance)
{
	struct sim_file_instance *inst;

	inst = rad_malloc(sizeof *inst);
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	*instance = inst;
	return 0;
}

/*
 *	Find the named user in the database.  Create the
 *	set of attribute-value pairs to check and reply with
 *	for this user from the database. The main code only
 *	needs to check the password, the rest is done here.
 */
static rlm_rcode_t sim_file_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*reply_tmp;
	const char	*name;
	struct sim_file_instance *inst = instance;
	VALUE_PAIR     **reply_pairs;
	VALUE_PAIR     **config_pairs;
	FILE            *triplets;
	char             tripbuf[sizeof("232420100000015,30000000000000000000000000000000,30112233,445566778899AABB")*2];
	char             imsi[128], chal[256], kc[128], sres[128];
	int              imsicount;
	int              fieldcount;
	int lineno;

	reply_pairs = &request->reply->vps;
	config_pairs = &request->config_items;

 	/*
	 *	Grab the canonical user name.
	 */
	namepair = request->username;
	name = namepair ? (char *) namepair->vp_strvalue : "NONE";

	triplets = fopen(inst->file, "r");

	if(triplets == NULL) {
		radlog(L_ERR, "can not open %s: %s",
		       inst->file, strerror(errno));
		return RLM_MODULE_NOTFOUND;
	}

	imsicount = 0;
	lineno = 0;

	while(fgets(tripbuf, sizeof(tripbuf), triplets) == tripbuf
	      && imsicount < 3)
	{
		char *f;
		char *l;
		VALUE_PAIR *r, *k, *s;

		lineno++;
		if(tripbuf[0]=='#') continue;

		l = tripbuf;
		fieldcount = 0;
		chal[0]='0'; chal[1]='x';
		kc[0]='0';   kc[1]='x';
		sres[0]='0'; sres[1]='x';

		f = strsep(&l, ",");
		if(f)
		{
			strlcpy(imsi, f, sizeof(imsi));
			fieldcount++;
		}

		if(strcmp(imsi, name) != 0)
		{
			continue;
		}

		/* we found one */
		f = strsep(&l, ",");
		if(f)
		{
			strlcpy(chal + 2, f, sizeof(chal) - 2);
			fieldcount++;
		}

		f = strsep(&l, ",");
		if(f)
		{
			strlcpy(sres + 2, f, sizeof(sres) - 2);
			fieldcount++;
		}

		f = strsep(&l, ",\n");
		if(f)
		{
			strlcpy(kc + 2, f, sizeof(kc) - 2);
			fieldcount++;
		}

		if(fieldcount != 4)
		{
			radlog(L_ERR, "invalid number of fields %d at line %d",
			       fieldcount, lineno);
			/* complain about malformed line */
			continue;
		}


		r = paircreate(ATTRIBUTE_EAP_SIM_RAND1 + imsicount, 0);
		pairparsevalue(r, chal);
		pairadd(reply_pairs, r);

		k = paircreate(ATTRIBUTE_EAP_SIM_KC1 + imsicount, 0);
		pairparsevalue(k, kc);
		rad_assert(k != NULL);
		pairadd(reply_pairs, k);

		s = paircreate(ATTRIBUTE_EAP_SIM_SRES1 + imsicount, 0);
		pairparsevalue(s, sres);
		pairadd(reply_pairs, s);

		imsicount++;
	}
	fclose(triplets);

	if (imsicount < 3)
	{
		DEBUG("rlm_sim_files: "
		      "insufficient number of challenges for imsi %s: %d\n",
		      name, imsicount);
		return RLM_MODULE_NOTFOUND;
	}

	DEBUG("rlm_sim_files: "
	      "authorized user/imsi %s\n", name);

	/*
	 * EAP module will also grab based upon presence of EAP packet
	 * and it will add the Autz-Type entry.
	 */

	if((reply_tmp = pairmake ("EAP-Type", "SIM", T_OP_EQ)))
	{
		radlog(L_INFO, "rlm_sim_files: Adding EAP-Type: eap-sim");
		pairadd (config_pairs, reply_tmp);
	}

#if 0
	DEBUG("rlm_sim_files: saw config");
	debug_pair_list(*config_pairs);

	DEBUG("rlm_sim_files: saw reply");
	debug_pair_list(*reply_pairs);
#endif

	return RLM_MODULE_OK;
}


/*
 *	Clean up.
 */
static int sim_file_detach(void *instance)
{
	struct sim_file_instance *inst = instance;

	free(inst);
	return 0;
}


/* globally exported name */
module_t rlm_sim_files = {
	RLM_MODULE_INIT,
	"sim_files",
	0,				/* type: reserved */
	sim_file_instantiate,		/* instantiation */
	sim_file_detach,		/* detach */
	{
		NULL,			/* authentication */
		sim_file_authorize, 	/* authorization */
		NULL,        		/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,          		/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};

