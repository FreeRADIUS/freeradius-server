/*
 * rlm_perl.c	
 *
 * Version:    $Id$
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
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#ifdef DEBUG
#undef DEBUG
#endif

#ifdef INADDR_ANY
#undef INADDR_ANY
#endif

#ifdef INADDR_NONE
#undef INADDR_NONE
#endif

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

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
typedef struct perl_inst {
	/* Name of the perl module */
	char	*module;
	
	/* Name of the functions for each module method */
	char	*func_authorize;
	char	*func_authenticate;
	char	*func_accounting;
	char	*func_preacct;
	char	*func_checksimul;
	char	*func_detach;
	char	*func_xlat;
	char	*xlat_name;
	
	HV	*rad_reply_hv;
	HV	*rad_check_hv;
	HV	*rad_request_hv;
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
	{ "module",  PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,module), NULL,  "module"},
	{ "func_authorize", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_authorize), NULL, "authorize"},
	{ "func_authenticate", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_authenticate), NULL, "authenticate"},
	{ "func_accounting", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_accounting), NULL, "accounting"},
	{ "func_preacct", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_preacct), NULL, "preacct"},
	{ "func_checksimul", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_checksimul), NULL, "checksimul"},
	{ "func_detach", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_detach), NULL, "detach"},
	{ "func_xlat", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_xlat), NULL, "xlat"},
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 * man perlembed
 */ 
EXTERN_C void boot_DynaLoader(pTHX_ CV* cv);

/*
 *	We share one perl interpreter among all of the instances
 *	of this module.
 */
static PerlInterpreter	*my_perl;


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
	if ((my_perl = perl_alloc()) == NULL) {
		radlog(L_INFO, "rlm_perl: No memory for allocating new perl !");
		return -1;
	}
	
	perl_construct(my_perl);
	
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
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file); 
	
}
/*
 *
 * This is wrapper for radlog
 * Now users can call radiusd::radlog(level,msg) wich is the same 
 * calling radlog from C code.
 * Boyan
 */
static XS(XS_radiusd_radlog) 
{
       dXSARGS;
       int     level;
       char    *msg;
       
       level = *(int *) SvIV(ST(0));
       msg   = (char *) SvPV(ST(1), PL_na);
       
       /*
	*	Because 'msg' is a 'char *', we don't want '%s', etc.
	*	in it to give us printf-style vulnerabilities.
	*/
       radlog(level, "rlm_perl: %s", msg);

       XSRETURN_NO;
}

/*
 * The xlat function
 */
static int perl_xlat(void *instance, REQUEST *request, char *fmt, char * out,
		     int freespace, RADIUS_ESCAPE_STRING func)
{
	PERL_INST	*inst= (PERL_INST *) instance;
	char		params[1024], *tmp_ptr, *ptr, *tmp;
	int		count, ret;
	STRLEN		n_a;

	dSP;
	ENTER;
	SAVETMPS;
	
	/*
         * Do an xlat on the provided string (nice recursive operation).
        */
        if (!radius_xlat(params, sizeof(params), fmt, request, func)) {
		radlog(L_ERR, "rlm_perl: xlat failed.");
		return 0;
        }
	
	PERL_SET_CONTEXT(my_perl);
	ptr = strtok(params, " ");

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(newSVpv(ptr,0)));

  	while ((tmp_ptr = strtok(NULL, " ")) != NULL) {
		XPUSHs(sv_2mortal(newSVpv(tmp_ptr,0)));
	} 

	PUTBACK;
	PERL_SET_CONTEXT(my_perl);
	
	count = call_pv(inst->func_xlat, G_SCALAR | G_EVAL);

	SPAGAIN;
	
	if (SvTRUE(ERRSV)) { 
		radlog(L_ERR, "rlm_perl: perl_xlat exit %s\n",
		       SvPV(ERRSV,n_a));
		return 0;
	} 

	if (count > 0) { 
		tmp = POPp;
		ret = strlen(tmp);
		strncpy(out,tmp,ret);

		radlog(L_DBG,"rlm_perl: Len is %d , out is %s freespace is %d",
		       ret, out,freespace);
	
		PUTBACK ;
	        FREETMPS ;
	        LEAVE ;
		
		if (ret <= freespace)
			return ret;
	}
	return 0;
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
 *
 *	Boyan: 
 *	Setup a hashes wich we will use later
 *	parse a module and give him a chance to live 
 *	
 */
static int perl_instantiate(CONF_SECTION *conf, void **instance)
{
	PERL_INST       *inst = (PERL_INST *) instance;
	char *embed[2], *xlat_name;
	int exitstatus = 0;
	
	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(PERL_INST));
	memset(inst, 0, sizeof(PERL_INST));
		
	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}
	
	PERL_SET_CONTEXT(my_perl);

	embed[0] = NULL;
	embed[1] = inst->module;
	
	exitstatus = perl_parse(my_perl, xs_init, 2, embed, NULL);

	PERL_SET_CONTEXT(my_perl);
	if(!exitstatus) {
		exitstatus = perl_run(my_perl);
	} else {
		radlog(L_INFO,"rlm_perl: perl_parse failed: %s not found or has syntax errors. \n", inst->module);
		return (-1);
	}

        newXS("radiusd::radlog",XS_radiusd_radlog, "rlm_perl.c");

	inst->rad_reply_hv = get_hv("RAD_REPLY",1);
        inst->rad_check_hv = get_hv("RAD_CHECK",1);
	inst->rad_request_hv = get_hv("RAD_REQUEST",1);
		
	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL)
		xlat_name = cf_section_name1(conf);
	if (xlat_name){ 
		inst->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, perl_xlat, inst); 
	} 
	*instance = inst;
	
	return 0;
}

/*
 *  	Boyan get the vps and put them in perl hash 
 */
static void perl_store_vps(VALUE_PAIR *vp, HV *rad_hv)
{
        char            buffer[256];

        hv_clear(rad_hv);

	for ( ; vp != NULL; vp = vp->next) {
		int len;

		len = vp_prints_value(buffer, sizeof(buffer), vp, FALSE);

		hv_store(rad_hv, vp->name, strlen(vp->name),
			 newSVpv(buffer, len),0);
	}
}
/*
 *	Boyan :
 *	Gets the content from hashes 
 * 
 */
static int get_hv_content(HV *my_hv, VALUE_PAIR **vp) 
{
	SV		*res_sv;
	char		*key, *val;
	I32		key_len,i;
	int		val_len;
	VALUE_PAIR	*vpp;
	
	for (i = hv_iterinit(my_hv); i > 0; i--) {
		res_sv = hv_iternextsv(my_hv,&key,&key_len);
	        val = SvPV(res_sv,val_len);
		vpp = pairmake(key, val, T_OP_EQ);
		if (vpp != NULL) {
			pairadd(vp, vpp);
		} else {
			radlog(L_DBG,"rlm_perl: ERROR: Failed to create pair %s = %s",
			       key, val);
		}
	}

	return 1;
}

/*
 * 	Call the function_name inside the module 
 * 	Store all vps in hashes %RAD_CHECK %RAD_REPLY %RAD_REQUEST
 * 	
 */	
static int rlmperl_call(void *instance, REQUEST *request, char *function_name)
{
	PERL_INST	*inst = instance;
	VALUE_PAIR	*vp;
	int		exitstatus, count;
	STRLEN		n_a;
	
	dSP;

	/*
	 *	Radius has told us to call this function, but none
	 *	is defined.
	 */
	if (!function_name) {
		return RLM_MODULE_FAIL;
	}

	ENTER;
	SAVETMPS;

	perl_store_vps(request->reply->vps, inst->rad_reply_hv);
	perl_store_vps(request->config_items, inst->rad_check_hv);
	perl_store_vps(request->packet->vps, inst->rad_request_hv);

	vp = NULL;
	
	PERL_SET_CONTEXT(my_perl);
	
	PUSHMARK(SP);	
	count = call_pv(function_name, G_SCALAR | G_EVAL);

	SPAGAIN;	
	
	if (count != 1) { 
		exitstatus = RLM_MODULE_REJECT;
	} else {
		exitstatus = POPi;
	}
	
	PUTBACK;

	if (SvTRUE(ERRSV)) {
		exitstatus = SvIV(perl_get_sv("!",FALSE));
	        radlog(L_DBG, "rlm_perl: perl_embed:: module = %s , func = %s exit status=%d, %s\n",
		       inst->module,
		       function_name,exitstatus, SvPV(ERRSV,n_a));
	}
	

	PERL_SET_CONTEXT(my_perl);
	if ((get_hv_content(inst->rad_reply_hv, &vp)) == 1) {
		pairmove(&request->reply->vps, &vp);
		pairfree(&vp);
	} 

	PERL_SET_CONTEXT(my_perl);
	if ((get_hv_content(inst->rad_check_hv, &vp)) == 1 ) {
		pairmove(&request->config_items, &vp);
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
	return rlmperl_call(instance, request,
			    ((PERL_INST *)instance)->func_authorize);
}

/*
 *	Authenticate the user with the given password.
 */
static int perl_authenticate(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			    ((PERL_INST *)instance)->func_authenticate);
}


/*
 *	Massage the request before recording it or proxying it
 */
static int perl_preacct(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			    ((PERL_INST *)instance)->func_preacct);
}

/*
 *	Write accounting information to this modules database.
 */

static int perl_accounting(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			    ((PERL_INST *)instance)->func_accounting);
}
/*
 *	Check for simultaneouse-use 
 */

static int perl_checksimul(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			    ((PERL_INST *)instance)->func_checksimul);
}

/*
 * Detach a instance give a chance to a module to make some internal setup ... 
 */
static int perl_detach(void *instance)
{	
	PERL_INST	*inst = (PERL_INST *) instance;
	int 		status,count=0;
		
	dSP;
	radlog(L_DBG,"Enter the detach function");

	
	PERL_SET_CONTEXT(my_perl);
	
	PUSHMARK(SP);	
	count = call_pv(inst->func_detach, G_SCALAR | G_EVAL);

	SPAGAIN;
	
	if (count != 1) {
		status = RLM_MODULE_REJECT;
	} else {
		status = POPi;
	}
	
	PUTBACK;

	xlat_unregister(inst->xlat_name, perl_xlat);
	free(inst->xlat_name);

	if (inst->func_authorize) free(inst->func_authorize);
	if (inst->func_authenticate) free(inst->func_authenticate);
	if (inst->func_accounting) free(inst->func_accounting);
	if (inst->func_preacct) free(inst->func_preacct);
	if (inst->func_checksimul) free(inst->func_checksimul);
	if (inst->func_detach) free(inst->func_detach);

	free(inst);
	return status;
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
		perl_accounting, 
		NULL,	      		/* check simul */
		NULL,                   /* pre-proxy */
		NULL,                   /* post-proxy */
		NULL                    /* post-auth */
	},
	perl_detach,			/* detach */
	NULL,				/* destroy */
};
