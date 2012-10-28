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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2002,2006  The FreeRADIUS server project
 * Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifdef DEBUG
#undef DEBUG
#endif

#ifdef INADDR_ANY
#undef INADDR_ANY
#endif

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <dlfcn.h>
#include <semaphore.h>

#ifdef __APPLE__
extern char **environ;
#endif

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
	char	*func_start_accounting;
	char	*func_stop_accounting;
	char	*func_preacct;
	char	*func_checksimul;
	char	*func_detach;
	char	*func_xlat;
#ifdef WITH_PROXY
	char	*func_pre_proxy;
	char	*func_post_proxy;
#endif
	char	*func_post_auth;
#ifdef WITH_COA
	char	*func_recv_coa;
	char	*func_send_coa;
#endif
	char	*xlat_name;
	char	*perl_flags;
	PerlInterpreter *perl;
	pthread_key_t	*thread_key;

	pthread_mutex_t clone_mutex;
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
static const CONF_PARSER module_config[] = {
	{ "module",  PW_TYPE_FILENAME,
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
#ifdef WITH_PROXY
	{ "func_pre_proxy", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_pre_proxy), NULL, "pre_proxy"},
	{ "func_post_proxy", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_post_proxy), NULL, "post_proxy"},
#endif
	{ "func_post_auth", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_post_auth), NULL, "post_auth"},
#ifdef WITH_COA
	{ "func_recv_coa", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_recv_coa), NULL, "recv_coa"},
	{ "func_send_coa", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_send_coa), NULL, "send_coa"},
#endif
	{ "perl_flags", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,perl_flags), NULL, NULL},
	{ "func_start_accounting", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_start_accounting), NULL, NULL},
	{ "func_stop_accounting", PW_TYPE_STRING_PTR,
	  offsetof(PERL_INST,func_stop_accounting), NULL, NULL},

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 * man perlembed
 */
EXTERN_C void boot_DynaLoader(pTHX_ CV* cv);

#ifdef USE_ITHREADS
#define dl_librefs "DynaLoader::dl_librefs"
#define dl_modules "DynaLoader::dl_modules"
static void rlm_perl_clear_handles(pTHX)
{
	AV *librefs = get_av(dl_librefs, FALSE);
	if (librefs) {
		av_clear(librefs);
	}
}

static void **rlm_perl_get_handles(pTHX)
{
	I32 i;
	AV *librefs = get_av(dl_librefs, FALSE);
	AV *modules = get_av(dl_modules, FALSE);
	void **handles;

	if (!librefs) {
		radlog(L_ERR,
		   "Could not get @%s for unloading.\n",
		   dl_librefs);
		return NULL;
	}

	if (!(AvFILL(librefs) >= 0)) {
		return NULL;
	}

	handles = (void **)rad_malloc(sizeof(void *) * (AvFILL(librefs)+2));

	for (i=0; i<=AvFILL(librefs); i++) {
		void *handle;
		SV *handle_sv = *av_fetch(librefs, i, FALSE);

		if(!handle_sv) {
		    radlog(L_ERR,
			       "Could not fetch $%s[%d]!\n",
			       dl_librefs, (int)i);
		    continue;
		}
		handle = (void *)SvIV(handle_sv);

		if (handle) {
		    handles[i] = handle;
		}
	}

	av_clear(modules);
	av_clear(librefs);

	handles[i] = (void *)0;

	return handles;
}

static void rlm_perl_close_handles(void **handles)
{
	int i;

	if (!handles) {
		return;
	}

	for (i=0; handles[i]; i++) {
		radlog(L_DBG, "close %p\n", handles[i]);
		dlclose(handles[i]);
	}

	free(handles);
}

static void rlm_perl_destruct(PerlInterpreter *perl)
{
	dTHXa(perl);

	PERL_SET_CONTEXT(perl);

	PL_perl_destruct_level = 2;

	PL_origenviron = environ;

	{
		dTHXa(perl);
	}
	/*
	 * FIXME: This shouldn't happen
	 *
	 */
	while (PL_scopestack_ix > 1 ){
		LEAVE;
	}

	perl_destruct(perl);
	perl_free(perl);
}

static void rlm_destroy_perl(PerlInterpreter *perl)
{
	void	**handles;

	dTHXa(perl);
	PERL_SET_CONTEXT(perl);

	handles = rlm_perl_get_handles(aTHX);
	rlm_perl_destruct(perl);
	rlm_perl_close_handles(handles);
}

/* Create Key */
static void rlm_perl_make_key(pthread_key_t *key)
{
	pthread_key_create(key, rlm_destroy_perl);
}

static PerlInterpreter *rlm_perl_clone(PerlInterpreter *perl, pthread_key_t *key)
{
	PerlInterpreter *interp;
	UV clone_flags = 0;

	PERL_SET_CONTEXT(perl);

	interp = pthread_getspecific(*key);
	if (interp) return interp;

	interp = perl_clone(perl, clone_flags);
	{
		dTHXa(interp);
	}
#if PERL_REVISION >= 5 && PERL_VERSION <8
	call_pv("CLONE",0);
#endif
	ptr_table_free(PL_ptr_table);
	PL_ptr_table = NULL;

	PERL_SET_CONTEXT(aTHX);
    	rlm_perl_clear_handles(aTHX);

	pthread_setspecific(*key, interp);

	return interp;
}
#endif

static void xs_init(pTHX)
{
	char *file = __FILE__;

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
       if (items !=2)
	       croak("Usage: radiusd::radlog(level, message)");
       {
	       int     level;
	       char    *msg;

	       level = (int) SvIV(ST(0));
	       msg   = (char *) SvPV(ST(1), PL_na);

	       /*
		*	Because 'msg' is a 'char *', we don't want '%s', etc.
		*	in it to give us printf-style vulnerabilities.
		*/
	       radlog(level, "rlm_perl: %s", msg);
	}
       XSRETURN_NO;
}

/*
 * The xlat function
 */
static size_t perl_xlat(void *instance, REQUEST *request, char *fmt, char *out,
			size_t freespace)
{

	PERL_INST	*inst= (PERL_INST *) instance;
	PerlInterpreter *perl;
	char		params[1024], *ptr, *tmp;
	int		count;
	size_t		ret = 0;
	STRLEN		n_a;

	/*
	 * Do an xlat on the provided string (nice recursive operation).
	*/
	if (!radius_xlat(params, sizeof(params), fmt, request, NULL, NULL)) {
		radlog(L_ERR, "rlm_perl: xlat failed.");
		return 0;
	}

#ifndef WITH_ITHREADS
	perl = inst->perl;
#else
	perl = rlm_perl_clone(inst->perl,inst->thread_key);
	{
	  dTHXa(perl);
	}
#endif
	PERL_SET_CONTEXT(perl);
	{
	dSP;
	ENTER;SAVETMPS;

	ptr = strtok(params, " ");

	PUSHMARK(SP);

	while (ptr != NULL) {
		XPUSHs(sv_2mortal(newSVpv(ptr,0)));
		ptr = strtok(NULL, " ");
	}

	PUTBACK;

	count = call_pv(inst->func_xlat, G_SCALAR | G_EVAL);

	SPAGAIN;
	if (SvTRUE(ERRSV)) {
		radlog(L_ERR, "rlm_perl: perl_xlat exit %s\n",
		       SvPV(ERRSV,n_a));
		POPs ;
	} else if (count > 0) {
		tmp = POPp;
		strlcpy(out, tmp, freespace);
		ret = strlen(out);

		radlog(L_DBG,"rlm_perl: Len is %d , out is %s freespace is %d",
		       ret, out,freespace);
	}

	PUTBACK ;
	FREETMPS ;
	LEAVE ;

	}
	return ret;
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
	HV		*rad_reply_hv;
	HV		*rad_check_hv;
	HV		*rad_config_hv;
	HV		*rad_request_hv;
#ifdef WITH_PROXY
	HV		*rad_request_proxy_hv;
	HV		*rad_request_proxy_reply_hv;
#endif
	AV		*end_AV;

	char **embed;
        char **envp = NULL;
	const char *xlat_name;
	int exitstatus = 0, argc=0;

        embed = rad_malloc(4 * sizeof(char *));
        memset(embed, 0, 4 *sizeof(char *));
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
		free(embed);
		free(inst);
		return -1;
	}
	
	/*
	 *	Create pthread key. This key will be stored in instance
	 */

#ifdef USE_ITHREADS
	pthread_mutex_init(&inst->clone_mutex, NULL);

	inst->thread_key = rad_malloc(sizeof(*inst->thread_key));
	memset(inst->thread_key,0,sizeof(*inst->thread_key));
	
	rlm_perl_make_key(inst->thread_key);
#endif
	embed[0] = NULL;
	if (inst->perl_flags) {
		embed[1] = inst->perl_flags;
		embed[2] = inst->module;
		embed[3] = "0";
		argc = 4;
	} else {
		embed[1] = inst->module;
		embed[2] = "0";
		argc = 3;
	}

        PERL_SYS_INIT3(&argc, &embed, &envp);
#ifdef USE_ITHREADS
	if ((inst->perl = perl_alloc()) == NULL) {
		radlog(L_DBG, "rlm_perl: No memory for allocating new perl !");
		free(embed);
		free(inst);
		return (-1);
	}

	perl_construct(inst->perl);
	PL_perl_destruct_level = 2;

	{
	dTHXa(inst->perl);
	}
	PERL_SET_CONTEXT(inst->perl);
#else
	if ((inst->perl = perl_alloc()) == NULL) {
		radlog(L_ERR, "rlm_perl: No memory for allocating new perl !");
		free(embed);
		free(inst);
		return -1;
	}

	perl_construct(inst->perl);
#endif

#if PERL_REVISION >= 5 && PERL_VERSION >=8
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

	exitstatus = perl_parse(inst->perl, xs_init, argc, embed, NULL);

	end_AV = PL_endav;
	PL_endav = Nullav;

	if(!exitstatus) {
		exitstatus = perl_run(inst->perl);
	} else {
		radlog(L_ERR,"rlm_perl: perl_parse failed: %s not found or has syntax errors. \n", inst->module);
		free(embed);
		free(inst);
		return (-1);
	}

	PL_endav = end_AV;

        newXS("radiusd::radlog",XS_radiusd_radlog, "rlm_perl.c");

	rad_reply_hv = newHV();
	rad_check_hv = newHV();
	rad_config_hv = newHV();
	rad_request_hv = newHV();
#ifdef WITH_PROXY
	rad_request_proxy_hv = newHV();
	rad_request_proxy_reply_hv = newHV();
#endif

	rad_reply_hv = get_hv("RAD_REPLY",1);
        rad_check_hv = get_hv("RAD_CHECK",1);
	rad_config_hv = get_hv("RAD_CONFIG",1);
        rad_request_hv = get_hv("RAD_REQUEST",1);
#ifdef WITH_PROXY
	rad_request_proxy_hv = get_hv("RAD_REQUEST_PROXY",1);
	rad_request_proxy_reply_hv = get_hv("RAD_REQUEST_PROXY_REPLY",1);
#endif

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
 *  	get the vps and put them in perl hash
 *  	If one VP have multiple values it is added as array_ref
 *  	Example for this is Cisco-AVPair that holds multiple values.
 *  	Which will be available as array_ref in $RAD_REQUEST{'Cisco-AVPair'}
 */
static void perl_store_vps(VALUE_PAIR *vp, HV *rad_hv)
{
        VALUE_PAIR	*nvp, *vpa, *vpn;
	AV		*av;
	char		namebuf[256], *name;
	char            buffer[1024];
	int		attr, vendor, len;

	hv_undef(rad_hv);
	nvp = paircopy(vp);

	while (nvp != NULL) {
		name = nvp->name;
		attr = nvp->attribute;
		vendor = nvp->vendor;
		vpa = paircopy2(nvp, attr, vendor, -1);

		if (vpa->next) {
			av = newAV();
			vpn = vpa;
			while (vpn) {
				len = vp_prints_value(buffer, sizeof(buffer),
						vpn, FALSE);
				av_push(av, newSVpv(buffer, len));
				vpn = vpn->next;
			}
			hv_store(rad_hv, nvp->name, strlen(nvp->name),
					newRV_noinc((SV *) av), 0);
		} else {
			if ((vpa->flags.has_tag) &&
			    (vpa->flags.tag != 0)) {
				snprintf(namebuf, sizeof(namebuf), "%s:%d",
					 nvp->name, nvp->flags.tag);
				name = namebuf;
			}

			len = vp_prints_value(buffer, sizeof(buffer),
					      vpa, FALSE);
			hv_store(rad_hv, name, strlen(name),
				 newSVpv(buffer, len), 0);
		}

		pairfree(&vpa);
		vpa = nvp; while ((vpa != NULL) && (vpa->attribute == attr) && (vpa->vendor == vendor))
			vpa = vpa->next;
		pairdelete(&nvp, attr, vendor, -1);
		nvp = vpa;
	}
}

/*
 *
 *     Verify that a Perl SV is a string and save it in FreeRadius
 *     Value Pair Format
 *
 */
static int pairadd_sv(VALUE_PAIR **vp, char *key, SV *sv, int operator) {
       char            *val;
       VALUE_PAIR      *vpp;

       if (SvOK(sv)) {
               val = SvPV_nolen(sv);
               vpp = pairmake(key, val, operator);
               if (vpp != NULL) {
                       pairadd(vp, vpp);
                       radlog(L_DBG,
                         "rlm_perl: Added pair %s = %s", key, val);
		       return 1;
               } else {
                       radlog(L_DBG,
                         "rlm_perl: ERROR: Failed to create pair %s = %s",
                         key, val);
               }
        }
       return 0;
}

/*
  *     Boyan :
  *     Gets the content from hashes
  */
static int get_hv_content(HV *my_hv, VALUE_PAIR **vp)
{
       SV		*res_sv, **av_sv;
       AV		*av;
       char		*key;
       I32		key_len, len, i, j;
       int		ret=0;

       *vp = NULL;
       for (i = hv_iterinit(my_hv); i > 0; i--) {
               res_sv = hv_iternextsv(my_hv,&key,&key_len);
               if (SvROK(res_sv) && (SvTYPE(SvRV(res_sv)) == SVt_PVAV)) {
                       av = (AV*)SvRV(res_sv);
                       len = av_len(av);
                       for (j = 0; j <= len; j++) {
                               av_sv = av_fetch(av, j, 0);
                               ret = pairadd_sv(vp, key, *av_sv, T_OP_ADD) + ret;
                       }
               } else ret = pairadd_sv(vp, key, res_sv, T_OP_EQ) + ret;
        }

        return ret;
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
	int		exitstatus=0, count;
	STRLEN		n_a;

	HV		*rad_reply_hv;
	HV		*rad_check_hv;
	HV		*rad_config_hv;
	HV		*rad_request_hv;
#ifdef WITH_PROXY
	HV		*rad_request_proxy_hv;
	HV		*rad_request_proxy_reply_hv;
#endif
	
#ifdef USE_ITHREADS
	pthread_mutex_lock(&inst->clone_mutex);

	PerlInterpreter *interp;

	interp = rlm_perl_clone(inst->perl,inst->thread_key);
	{
	  dTHXa(interp);
	  PERL_SET_CONTEXT(interp);
	}
	
	pthread_mutex_unlock(&inst->clone_mutex);
#else
	PERL_SET_CONTEXT(inst->perl);
#endif

	{
	dSP;

	ENTER;
	SAVETMPS;


	/*
	 *	Radius has told us to call this function, but none
	 *	is defined.
	 */
	if (!function_name) {
		return RLM_MODULE_FAIL;
	}

	rad_reply_hv = get_hv("RAD_REPLY",1);
	rad_check_hv = get_hv("RAD_CHECK",1);
	rad_config_hv = get_hv("RAD_CONFIG",1);
	rad_request_hv = get_hv("RAD_REQUEST",1);
#ifdef WITH_PROXY
	rad_request_proxy_hv = get_hv("RAD_REQUEST_PROXY",1);
	rad_request_proxy_reply_hv = get_hv("RAD_REQUEST_PROXY_REPLY",1);
#endif

	perl_store_vps(request->reply->vps, rad_reply_hv);
	perl_store_vps(request->config_items, rad_check_hv);
	perl_store_vps(request->packet->vps, rad_request_hv);
	perl_store_vps(request->config_items, rad_config_hv);

#ifdef WITH_PROXY
	if (request->proxy != NULL) {
		perl_store_vps(request->proxy->vps, rad_request_proxy_hv);
	} else {
		hv_undef(rad_request_proxy_hv);
	}

	if (request->proxy_reply !=NULL) {
		perl_store_vps(request->proxy_reply->vps, rad_request_proxy_reply_hv);
	} else {
		hv_undef(rad_request_proxy_reply_hv);
	}
#endif

	PUSHMARK(SP);
	/*
	* This way %RAD_xx can be pushed onto stack as sub parameters.
	* XPUSHs( newRV_noinc((SV *)rad_request_hv) );
	* XPUSHs( newRV_noinc((SV *)rad_reply_hv) );
	* XPUSHs( newRV_noinc((SV *)rad_check_hv) );
	* PUTBACK;
	*/

	count = call_pv(function_name, G_SCALAR | G_EVAL | G_NOARGS);

	SPAGAIN;

	if (SvTRUE(ERRSV)) {
		radlog(L_ERR, "rlm_perl: perl_embed:: module = %s , func = %s exit status= %s\n",
		       inst->module,
		       function_name, SvPV(ERRSV,n_a));
		POPs;
	}

	if (count == 1) {
		exitstatus = POPi;
		if (exitstatus >= 100 || exitstatus < 0) {
			exitstatus = RLM_MODULE_FAIL;
		}
	}


	PUTBACK;
	FREETMPS;
	LEAVE;

	vp = NULL;
	if ((get_hv_content(rad_request_hv, &vp)) > 0 ) {
		pairfree(&request->packet->vps);
		request->packet->vps = vp;
		vp = NULL;

		/*
		 *	Update cached copies
		 */
		request->username = pairfind(request->packet->vps,
					     PW_USER_NAME, 0);
		request->password = pairfind(request->packet->vps,
					     PW_USER_PASSWORD, 0);
		if (!request->password)
			request->password = pairfind(request->packet->vps,
						     PW_CHAP_PASSWORD, 0);
	}

	if ((get_hv_content(rad_reply_hv, &vp)) > 0 ) {
		pairfree(&request->reply->vps);
		request->reply->vps = vp;
		vp = NULL;
	}

	if ((get_hv_content(rad_check_hv, &vp)) > 0 ) {
		pairfree(&request->config_items);
		request->config_items = vp;
		vp = NULL;
	}

#ifdef WITH_PROXY
	if (request->proxy &&
	    (get_hv_content(rad_request_proxy_hv, &vp) > 0)) {
		pairfree(&request->proxy->vps);
		request->proxy->vps = vp;
		vp = NULL;
	}

	if (request->proxy_reply &&
	    (get_hv_content(rad_request_proxy_reply_hv, &vp) > 0)) {
		pairfree(&request->proxy_reply->vps);
		request->proxy_reply->vps = vp;
		vp = NULL;
	}
#endif

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
	VALUE_PAIR	*pair;
	int 		acctstatustype=0;

	if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0)) != NULL) {
		acctstatustype = pair->vp_integer;
        } else {
                radlog(L_ERR, "Invalid Accounting Packet");
                return RLM_MODULE_INVALID;
        }

	switch (acctstatustype) {

		case PW_STATUS_START:

			if (((PERL_INST *)instance)->func_start_accounting) {
				return rlmperl_call(instance, request,
					    ((PERL_INST *)instance)->func_start_accounting);
			} else {
				return rlmperl_call(instance, request,
					    ((PERL_INST *)instance)->func_accounting);
			}
			break;

		case PW_STATUS_STOP:

			if (((PERL_INST *)instance)->func_stop_accounting) {
				return rlmperl_call(instance, request,
					    ((PERL_INST *)instance)->func_stop_accounting);
			} else {
				return rlmperl_call(instance, request,
					    ((PERL_INST *)instance)->func_accounting);
			}
			break;
		default:
			return rlmperl_call(instance, request,
					    ((PERL_INST *)instance)->func_accounting);

	}
}
/*
 *	Check for simultaneouse-use
 */
static int perl_checksimul(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			((PERL_INST *)instance)->func_checksimul);
}

#ifdef WITH_PROXY
/*
 *	Pre-Proxy request
 */
static int perl_pre_proxy(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			((PERL_INST *)instance)->func_pre_proxy);
}
/*
 *	Post-Proxy request
 */
static int perl_post_proxy(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			((PERL_INST *)instance)->func_post_proxy);
}
#endif

/*
 *	Pre-Auth request
 */
static int perl_post_auth(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			((PERL_INST *)instance)->func_post_auth);
}
#ifdef WITH_COA
/*
 *	Recv CoA request
 */
static int perl_recv_coa(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			((PERL_INST *)instance)->func_recv_coa);
}
/*
 *	Send CoA request
 */
static int perl_send_coa(void *instance, REQUEST *request)
{
	return rlmperl_call(instance, request,
			((PERL_INST *)instance)->func_send_coa);
}
#endif
/*
 * Detach a instance give a chance to a module to make some internal setup ...
 */
static int perl_detach(void *instance)
{
	PERL_INST	*inst = (PERL_INST *) instance;
	int 		exitstatus = 0, count = 0;

#if 0
	/*
	 *	FIXME: Call this in the destruct function?
	 */
		{
		dTHXa(handle->clone);
		PERL_SET_CONTEXT(handle->clone);
		{
		dSP; ENTER; SAVETMPS; PUSHMARK(SP);
		count = call_pv(inst->func_detach, G_SCALAR | G_EVAL );
		SPAGAIN;

		if (count == 1) {
			exitstatus = POPi;
			/*
			 * FIXME: bug in perl
			 *
			 */
			if (exitstatus >= 100 || exitstatus < 0) {
				exitstatus = RLM_MODULE_FAIL;
			}
		}
		PUTBACK;
		FREETMPS;
		LEAVE;
		}
		}
#endif

		if (inst->func_detach) {
	dTHXa(inst->perl);
	PERL_SET_CONTEXT(inst->perl);
	{
	dSP; ENTER; SAVETMPS;
	PUSHMARK(SP);

	count = call_pv(inst->func_detach, G_SCALAR | G_EVAL );
	SPAGAIN;

	if (count == 1) {
		exitstatus = POPi;
		if (exitstatus >= 100 || exitstatus < 0) {
			exitstatus = RLM_MODULE_FAIL;
		}
	}
	PUTBACK;
	FREETMPS;
	LEAVE;
	}
	}

	xlat_unregister(inst->xlat_name, perl_xlat, instance);
	free(inst->xlat_name);

#ifdef USE_ITHREADS
	rlm_perl_destruct(inst->perl);
	pthread_mutex_destroy(&inst->clone_mutex);
#else
	perl_destruct(inst->perl);
	perl_free(inst->perl);
#endif

        PERL_SYS_TERM();
	free(inst);
	return exitstatus;
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
	RLM_MODULE_INIT,
	"perl",				/* Name */
#ifdef USE_ITHREADS
	RLM_TYPE_THREAD_SAFE,		/* type */
#else
	RLM_TYPE_THREAD_UNSAFE,
#endif
	perl_instantiate,		/* instantiation */
	perl_detach,			/* detach */
	{
		perl_authenticate,	/* authenticate */
		perl_authorize,		/* authorize */
		perl_preacct,		/* preacct */
		perl_accounting,	/* accounting */
		perl_checksimul,      	/* check simul */
#ifdef WITH_PROXY
		perl_pre_proxy,		/* pre-proxy */
		perl_post_proxy,	/* post-proxy */
#else
		NULL, NULL,
#endif
		perl_post_auth		/* post-auth */
#ifdef WITH_COA
		, perl_recv_coa,
		perl_send_coa
#endif
	},
};
