/*
 * rlm_perl.c	
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2002  The FreeRADIUS server project
 * Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#ifdef DEBUG
#undef DEBUG
#endif

#include <EXTERN.h>
#include <perl.h>

#ifndef DO_CLEAN
#define DO_CLEAN 0
#endif

static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct perl_config {
	char	*cmd;
	char	*persistent;
} PERL_CONFIG;

/*
 * Some other things will be added in future 
 */
typedef struct perl_inst {
	PerlInterpreter	 	*perl;
	HV			*env_hv;
	HV			*result_hv;
	PERL_CONFIG		*config;
} PERL_INST;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
  { "cmd",  PW_TYPE_STRING_PTR, offsetof(PERL_CONFIG,cmd), NULL,  NULL},
  { "persistent", PW_TYPE_STRING_PTR, offsetof(PERL_CONFIG,persistent), NULL, NULL},
  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 * man perlembed
 */ 
EXTERN_C void boot_DynaLoader(pTHX_ CV* cv);

/*
 *	Do any per-module initialization.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	Try to avoid putting too much stuff in here - it's better to
 *	do it in instantiate() where it is not global.
 */
static int perl_init(void)
{
	/*
	 *	Everything's OK, return without an error.
	 */
	return 0;	
}


/*
 * man perlembed
 */ 
static void xs_init(pTHX)
{
	const char *file = __FILE__;
	dXSUB_SYS; 

	/* DynaLoader is a special case */
	DEBUG("rlm_perl:: xs_init enter \n");
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file); 
	DEBUG("rlm_perl:: xs_init leave \n");
	
}



/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int perl_instantiate(CONF_SECTION *conf, void **instance)
{
	PERL_INST	*inst;	
	char *embed[1];
	int exitstatus = 0;
	
	/*
	 *	Set up a storage area for instance data
	 */
	
	inst = rad_malloc(sizeof(PERL_INST));
	memset(inst, 0, sizeof(PERL_INST));
		
	inst->config = rad_malloc(sizeof(PERL_CONFIG));
	memset(inst->config, 0, sizeof(PERL_CONFIG));
	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst->config, module_config) < 0) {
		free(inst->config);
		return -1;
	}
	
	
	/*
	 * Boyan
	 * Prepare perl instance 
	 * 
	 */ 
	if((inst->perl = perl_alloc()) == NULL) {
                radlog(L_INFO, "no memory!");
		return -1;
	}
	
	PERL_SET_CONTEXT(inst->perl);
        perl_construct(inst->perl);
	
	PERL_SET_CONTEXT(inst->perl);

	embed[0] = inst->config->persistent;
	
	exitstatus = perl_parse(inst->perl, xs_init, 1, embed, NULL);

	PERL_SET_CONTEXT(inst->perl);
	if(!exitstatus) {
		exitstatus = perl_run(inst->perl);
	} else {
		radlog(L_INFO,"perl_parse failed: %s not found or has syntax errors. \n", inst->config->persistent);
		return (-1);
	}

	inst->env_hv = perl_get_hv("ENV",0);
        inst->result_hv = perl_get_hv("main::result",1);
	
	*instance = inst;
	
	return 0;
}

/*
 *  Boyan get the request and put them in perl hash 
 *  which will be given to perl cmd
 */
static void perl_env(VALUE_PAIR *vp, PERL_INST *inst)
{
        char            buffer[256];

        hv_clear(inst->env_hv);
        hv_clear(inst->result_hv);

	for ( ; vp != NULL; vp = vp->next) {
		int len;

		len = vp_prints_value(buffer, sizeof(buffer), vp, FALSE);

		hv_store(inst->env_hv, vp->name, strlen(vp->name),
			 newSVpv(buffer, len),0);
	}
}

/*
 * return structs and status 0 OK 1 Not
 * Boyan
 */
static int rlmperl_call(void *instance, REQUEST *request)
{
		
	PERL_INST	*inst = (PERL_INST *) instance;
	SV		*res_sv;
	VALUE_PAIR	*vp;
	char		*key, *val, *ptr, *p;
	char		*args[] = {NULL, DO_CLEAN, NULL};
	char		answer[4096];
	I32		key_len,i;
	int		val_len;
	int		exitstatus = 0, comma = 0;
	STRLEN n_a;

	args[0] = inst->config->cmd;
	
	perl_env(request->packet->vps, inst);
	
	for (i = hv_iterinit(inst->env_hv); i > 0; i--) {
	        res_sv = hv_iternextsv(inst->env_hv, &key, &key_len);
		val = SvPV(res_sv,val_len);
		radlog(L_DBG, "ENV %s= %s", key, val); 
	}
	
	PERL_SET_CONTEXT(inst->perl);
	call_argv("Embed::Persistent::eval_file", G_DISCARD | G_EVAL, args);
	
	exitstatus = 0;

	if (SvTRUE(ERRSV)) {
		exitstatus = SvIV(perl_get_sv("!",FALSE));;
	        radlog(L_INFO, "exit status=%d, %s\n", exitstatus,
		       SvPV(ERRSV,n_a));
	}

	ptr = answer;
	PERL_SET_CONTEXT(inst->perl);
	
	for (i = hv_iterinit(inst->result_hv); i > 0; i--) {
	        res_sv = hv_iternextsv(inst->result_hv,&key,&key_len);
	        val = SvPV(res_sv,val_len);
	        sprintf(ptr, "%s=\"%s\"\n", key, val); /* FIXME: snprintf */
	        ptr += key_len + val_len + 4;
	}
        /* perl_free(inst->perl); */

	*ptr='\0';
	vp = NULL;
	
        for (p = answer; *p; p++) { 
		if (*p == '\n') {
		       	*p = comma ? ' ' : ',';
		       	p++; comma = 0;
	       	} 
		if (*p == ',') comma++; 
	}
	
	/*
	 * Replace any trailing comma by a NUL.  
	 */                                
	if (answer[strlen(answer) - 1] == ',') {
		answer[strlen(answer) - 1] = '\0';
	}
	radlog(L_INFO,"perl_embed :: value-pairs: %s", answer);

	if (userparse(answer, &vp) < 0) {
		radlog(L_ERR, "perl_embed :: %s: unparsable reply", args[0]); 
	} else {
		pairmove(&request->reply->vps, &vp);
		pairfree(&vp);
	} 
	return exitstatus;

}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int perl_authorize(void *instance, REQUEST *request)
{
	int status = 0;
	
	radlog(L_INFO,"perl_embed :: Enter Authorize");

	if ((status = rlmperl_call(instance, request)) == 0) {
		return RLM_MODULE_OK;
	}
	
	return RLM_MODULE_FAIL;
}

/*
 *	Authenticate the user with the given password.
 */
static int perl_authenticate(void *instance, REQUEST *request)
{
	int status = 0;

	radlog(L_INFO,"perl_embed :: Enter Auth");

	if ((status = rlmperl_call(instance, request)) == 0) {
		return RLM_MODULE_OK;
	}

	return RLM_MODULE_FAIL;
}


/*
 *	Massage the request before recording it or proxying it
 */
static int perl_preacct(void *instance, REQUEST *request)
{
	int status = 0;

	radlog(L_INFO,"mod_perl ::  Enter PreAccounting");
	
	if ((status = rlmperl_call(instance, request)) == 0) {
		return RLM_MODULE_OK;
	}

	return RLM_MODULE_FAIL;
}

/*
 *	Write accounting information to this modules database.
 */

static int perl_accounting(void *instance, REQUEST *request)
{
	int status = 0;

	radlog(L_INFO,"mod_perl ::  Enter Accounting");
	
	if ((status = (rlmperl_call(instance, request))) == 0) {
		return RLM_MODULE_OK;
	}

	return RLM_MODULE_FAIL;
}

/*
 * Detach a instance free all ..
 */
static int perl_detach(void *instance)
{
	PERL_INST *inst=instance;
	PERL_SET_CONTEXT(inst->perl);
	perl_destruct(inst->perl);
        PERL_SET_CONTEXT(inst->perl);
	perl_free(inst->perl);

	free(inst->config);	
	hv_clear(inst->env_hv);
	hv_clear(inst->result_hv);
	free(inst);
	free(instance);
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_perl = {
	"perl",				/* Name */
	RLM_TYPE_THREAD_UNSAFE,		/* type */
	perl_init,			/* initialization */
	perl_instantiate,		/* instantiation */
	{
		perl_authenticate,
		perl_authorize,
		perl_preacct,
		perl_accounting
	},
	perl_detach,			/* detach */
	NULL,				/* destroy */
};
