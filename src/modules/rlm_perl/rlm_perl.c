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
#include <dlfcn.h>
#include <semaphore.h>

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
	char	*func_start_accounting;
	char	*func_stop_accounting;
	char	*func_preacct;
	char	*func_checksimul;
	char	*func_detach;
	char	*func_xlat;
	char	*xlat_name;
	char	*perl_flags;
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

/*
 *	We share one perl interpreter among all of the instances
 *	of this module. And clone it for every thread if we have perl
 *	with -Duseithreads compiled in
 */
static PerlInterpreter	*interp;

#ifdef USE_ITHREADS

/*
 * Pool of Perl's clones (genetically cloned) ;)
 *
 */
typedef struct pool_handle {
	struct pool_handle	*next;
	struct pool_handle	*prev;
	enum {busy, idle} 	status;
	unsigned int		request_count;
	PerlInterpreter		*clone;
} POOL_HANDLE;

typedef struct PERL_POOL {
	POOL_HANDLE	*head;
	POOL_HANDLE	*tail;

	int		current_clones;
	int		active_clones;
	int		max_clones;
	int		start_clones;
	int		min_spare_clones;
	int		max_spare_clones;
	int		max_request_per_clone;
	int		cleanup_delay;
	perl_mutex 	mutex;
	time_t		time_when_last_added;	
} PERL_POOL;

static PERL_POOL perl_pool;

static const CONF_PARSER pool_conf[] = {
	{ "max_clones", PW_TYPE_INTEGER, 0, &perl_pool.max_clones,		"32"},
	{ "start_clones",PW_TYPE_INTEGER, 0, &perl_pool.start_clones,		"5"},
	{ "min_spare_clones",PW_TYPE_INTEGER, 0, &perl_pool.min_spare_clones,	"3"},
	{ "max_spare_clones",PW_TYPE_INTEGER, 0, &perl_pool.max_spare_clones,	"3"},
	{ "cleanup_delay",PW_TYPE_INTEGER, 0, &perl_pool.cleanup_delay,		"5"},
	{ "max_request_per_clone",PW_TYPE_INTEGER, 0, &perl_pool.max_request_per_clone,	"0"},
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


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
		radlog(L_DBG, "close 0x%lx\n", (unsigned long)handles[i]);
		dlclose(handles[i]);
	}

	free(handles);
}

static PerlInterpreter *rlm_perl_clone()
{
	PerlInterpreter *clone;
	UV	clone_flags = CLONEf_KEEP_PTR_TABLE;
	
	PERL_SET_CONTEXT(interp);
	
	clone = perl_clone(interp, clone_flags);
	{	
		dTHXa(clone);
	}
    	
	ptr_table_free(PL_ptr_table);
	PL_ptr_table = NULL;

	PERL_SET_CONTEXT(aTHX);
    	rlm_perl_clear_handles(aTHX);
	
	return clone;
}

static void rlm_perl_destruct(PerlInterpreter *perl)
{
	char **orig_environ = NULL;
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

	if (orig_environ) {
		environ = orig_environ;
	}
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

static void delete_pool_handle(POOL_HANDLE *handle)
{
        POOL_HANDLE *prev;
        POOL_HANDLE *next;

        prev = handle->prev;
        next = handle->next;
	
        if (prev == NULL) {
                perl_pool.head = next;
        } else {
                prev->next = next;
        }
  
        if (next == NULL) {
                perl_pool.tail = prev;
        } else {
                next->prev = prev;
        }
	perl_pool.current_clones--;
}

static void move2tail(POOL_HANDLE *handle)
{
	POOL_HANDLE *prev;
	POOL_HANDLE *next;

	if (perl_pool.head == NULL) {

		handle->prev = NULL;
		handle->next = NULL;
		perl_pool.head = handle;
		perl_pool.tail = handle;
		return;
	}

	if (perl_pool.tail == handle) {
		return;
	}

	prev = handle->prev;
	next = handle->next;
  
	if ((next != NULL) ||
			(prev != NULL)) {
		if (next == NULL) {
			return;
		}

		if (prev == NULL) {
			perl_pool.head = next;
			next->prev = NULL;
		
		} else {

			prev->next = next;
			next->prev = prev;
		}
	}

	handle->next = NULL;
	prev = perl_pool.tail;

	perl_pool.tail = handle;
	handle->prev = prev;
	prev->next = handle;
}


static POOL_HANDLE *pool_grow () {
	POOL_HANDLE *handle;
	time_t	now;

	if (perl_pool.max_clones == perl_pool.current_clones) {
		return NULL;
	}
	
	handle = (POOL_HANDLE *)rad_malloc(sizeof(POOL_HANDLE));
	
	if (!handle) {
		radlog(L_ERR,"Could not find free memory for pool. Aborting");
		return NULL;
	}	
	
	handle->prev = NULL;
	handle->next = NULL;
	handle->status = idle;
	handle->clone = rlm_perl_clone();
	handle->request_count = 0;	
	perl_pool.current_clones++;
	move2tail(handle);
	
	now = time(NULL);
	perl_pool.time_when_last_added = now;
	
	return handle;
}

static POOL_HANDLE *pool_pop() 
{
	POOL_HANDLE	*handle;
	POOL_HANDLE	*found;
	POOL_HANDLE	*tmp;
	/*
	 * Lock the pool and be fast other thread maybe 
	 * waiting for us to finish
	 */
	MUTEX_LOCK(&perl_pool.mutex);
	
	found = NULL;
	
	for (handle = perl_pool.head; handle ; handle = tmp) {
		tmp = handle->next;
		
		if (handle->status == idle){
			found = handle;
			break;
		}
	}
	
	if (found == NULL) {
		if (perl_pool.current_clones < perl_pool.max_clones ) {
			
			found = pool_grow();
			perl_pool.current_clones++;

			if (found == NULL) {
				radlog(L_ERR,"Cannot grow pool returning");
				MUTEX_UNLOCK(&perl_pool.mutex);
				return NULL;
			} 
		} else {
			radlog(L_ERR,"reached maximum clones %d cannot grow",
					perl_pool.current_clones);
			MUTEX_UNLOCK(&perl_pool.mutex);
			return NULL;
		}
	}

	move2tail(found);
	found->status = busy;	
	perl_pool.active_clones++;
	found->request_count++;
	/*
	 * Hurry Up
	 */
	MUTEX_UNLOCK(&perl_pool.mutex);
	radlog(L_DBG,"perl_pool: item 0x%lx asigned new request. Handled so far: %d", 
			(unsigned long) found->clone, found->request_count);
	return found;
}
static int pool_release(POOL_HANDLE *handle) {

	POOL_HANDLE *tmp, *tmp2;
	int spare, i, t;
	time_t	now;
	/*
	 * Lock it
	 */
	MUTEX_LOCK(&perl_pool.mutex);
	handle->status = idle;
	perl_pool.active_clones--;
	
	spare = perl_pool.current_clones - perl_pool.active_clones;

	radlog(L_DBG,"perl_pool total/active/spare [%d/%d/%d]"
			, perl_pool.current_clones, perl_pool.active_clones, spare);	

	if (spare < perl_pool.min_spare_clones) {
		t = perl_pool.min_spare_clones - spare;
		for (i=0;i<t; i++) {
			if ((tmp = pool_grow()) == NULL) {
				MUTEX_UNLOCK(&perl_pool.mutex);
				return -1;
			}
		}
		MUTEX_UNLOCK(&perl_pool.mutex);
		return 0;
	}
	now = time(NULL);
	if ((now - perl_pool.time_when_last_added) < perl_pool.cleanup_delay) {
		MUTEX_UNLOCK(&perl_pool.mutex);
		return 0;
	}
	if (spare > perl_pool.max_spare_clones) {
		spare -= perl_pool.max_spare_clones;
		for (tmp = perl_pool.head; (tmp !=NULL ) && (spare > 0) ; tmp = tmp2) {
			tmp2 = tmp->next;

			if(tmp->status == idle) {
				rlm_destroy_perl(tmp->clone);
				delete_pool_handle(tmp);
				perl_pool.current_clones--;
				spare--;
				break;
			}
		}
	}
	/*
	 * Hurry Up :)
	 */
	MUTEX_UNLOCK(&perl_pool.mutex);
	return 0;
}
static int init_pool (CONF_SECTION *conf) {
	POOL_HANDLE 	*handle;
	int t;	
	
	MUTEX_INIT(&perl_pool.mutex);
	
	/*
	 * Read The Config 
	 *
	 */
	
	cf_section_parse(conf,NULL,pool_conf);
	
	for(t = 0;t < perl_pool.start_clones ;t++){
		if ((handle = pool_grow()) == NULL) {
			return -1;
		}
		
	}
	
	return 1;
}
#endif
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
	if ((interp = perl_alloc()) == NULL) {
		radlog(L_INFO, "rlm_perl: No memory for allocating new perl !");
		return -1;
	}

	perl_construct(interp);
	PL_perl_destruct_level = 2;	
	
	return 0;
	
}

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
static int perl_xlat(void *instance, REQUEST *request, char *fmt, char * out,
		     int freespace, RADIUS_ESCAPE_STRING func)
{
	
	PERL_INST	*inst= (PERL_INST *) instance;
	PerlInterpreter *perl;
	char		params[1024], *tmp_ptr, *ptr, *tmp;
	int		count, ret;
	STRLEN		n_a;
		
	perl = interp;

#ifdef USE_ITHREADS
	POOL_HANDLE	*handle;
	
	if ((handle = pool_pop()) == NULL) {
		return 0;
	}
	
	perl = handle->clone;

	radlog(L_DBG,"Found a interpetator 0x%lx",(unsigned long) perl);
	{
	dTHXa(perl);
	}
#endif	
	{	
	dSP;
	ENTER;SAVETMPS;
	
	/*
	 * Do an xlat on the provided string (nice recursive operation).
	*/
	if (!radius_xlat(params, sizeof(params), fmt, request, func)) {
		radlog(L_ERR, "rlm_perl: xlat failed.");
		return 0;
	}
	ptr = strtok(params, " ");

	PUSHMARK(SP);

	XPUSHs(sv_2mortal(newSVpv(ptr,0)));

	while ((tmp_ptr = strtok(NULL, " ")) != NULL) {
		XPUSHs(sv_2mortal(newSVpv(tmp_ptr,0)));
	} 

	PUTBACK;
	
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
	}
#ifdef USE_ITHREADS
	pool_release(handle);
#endif
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
	HV		*rad_reply_hv = newHV();
	HV		*rad_check_hv = newHV();
	HV		*rad_request_hv = newHV();
	
	char *embed[4], *xlat_name;
	int exitstatus = 0, argc=0;
	
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
	
	exitstatus = perl_parse(interp, xs_init, argc, embed, NULL);
	
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;

	if(!exitstatus) {
		exitstatus = perl_run(interp);
	} else {
		radlog(L_INFO,"rlm_perl: perl_parse failed: %s not found or has syntax errors. \n", inst->module);
		return (-1);
	}

        newXS("radiusd::radlog",XS_radiusd_radlog, "rlm_perl.c");

	rad_reply_hv = get_hv("RAD_REPLY",1);
        rad_check_hv = get_hv("RAD_CHECK",1);
        rad_request_hv = get_hv("RAD_REQUEST",1);

	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL)
		xlat_name = cf_section_name1(conf);
	if (xlat_name){ 
		inst->xlat_name = strdup(xlat_name);
		xlat_register(xlat_name, perl_xlat, inst); 
	} 

#ifdef USE_ITHREADS	
	
	if ((init_pool(conf)) == -1) {
		radlog(L_ERR,"Couldn't init a pool of perl clones. Exiting");
		return -1;
	}
	
#endif
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
	char            buffer[1024];
	int		attr, len;

	hv_clear(rad_hv);
	nvp = paircopy(vp);
	
	while (nvp != NULL) {
		attr = nvp->attribute;
		vpa = paircopy2(nvp,attr);
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
					newRV((SV *) av), 0);
		} else {
			len = vp_prints_value(buffer, sizeof(buffer),
					vpa, FALSE);
			hv_store(rad_hv, vpa->name, strlen(vpa->name),
					newSVpv(buffer, len), 0);
		}

		pairfree(&vpa);
		vpa = nvp; while ((vpa != NULL) && (vpa->attribute == attr))
			vpa = vpa->next;
		pairdelete(&nvp, attr);
		nvp = vpa;
	}
}
		
/*
 *
 *     Verify that a Perl SV is a string and save it in FreeRadius 
 *     Value Pair Format
 *
 */
static int pairadd_sv(VALUE_PAIR **vp, char *key, SV *sv) {
       char            *val;
       int             val_len;
       VALUE_PAIR      *vpp;
 
       if ((sv != NULL) && (SvPOK(sv))) {
               val = SvPV(sv, val_len);
               vpp = pairmake(key, val, T_OP_EQ);
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
        
       for (i = hv_iterinit(my_hv); i > 0; i--) {
               res_sv = hv_iternextsv(my_hv,&key,&key_len);
               if (SvROK(res_sv) && (SvTYPE(SvRV(res_sv)) == SVt_PVAV)) {
                       av = (AV*)SvRV(res_sv);
                       len = av_len(av);
                       for (j = 0; j <= len; j++) {
                               av_sv = av_fetch(av, j, 0);
                               ret = pairadd_sv(vp, key, *av_sv) + ret;
                       }
               } else ret = pairadd_sv(vp, key, res_sv) + ret;
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
	HV		*rad_request_hv;

#ifdef USE_ITHREADS
	POOL_HANDLE	*handle;
	
	if ((handle = pool_pop()) == NULL) {
		return RLM_MODULE_FAIL;
	}
	
	radlog(L_DBG,"found interpetator at address 0x%lx",(unsigned long) handle->clone);
	{	
	dTHXa(handle->clone);
	PERL_SET_CONTEXT(handle->clone);
	}
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
	rad_request_hv = get_hv("RAD_REQUEST",1);

	
	
	perl_store_vps(request->reply->vps, rad_reply_hv);
	perl_store_vps(request->config_items, rad_check_hv);
	perl_store_vps(request->packet->vps, rad_request_hv);
	vp = NULL;
	
	
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
	
	if (count == 1) {
		exitstatus = POPi;
		if (exitstatus >= 100 || exitstatus < 0) {
			exitstatus = RLM_MODULE_FAIL;
		}
	}
		
	PUTBACK;	
	FREETMPS;
	LEAVE;
	
	if (SvTRUE(ERRSV)) {
		radlog(L_ERR, "rlm_perl: perl_embed:: module = %s , func = %s exit status= %s\n",
		       inst->module,
		       function_name, SvPV(ERRSV,n_a));
	}

	if ((get_hv_content(rad_reply_hv, &vp)) > 0 ) {
		pairmove(&request->reply->vps, &vp);
		pairfree(&vp);
	} 

	if ((get_hv_content(rad_check_hv, &vp)) > 0 ) {
		pairmove(&request->config_items, &vp);
		pairfree(&vp);
	} 
	}
#ifdef USE_ITHREADS
	pool_release(handle);
	radlog(L_DBG,"Unreserve perl at address 0x%lx", (unsigned long) handle->clone);
#endif

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

	if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) != NULL) {
                acctstatustype = pair->lvalue;
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

/*
 * Detach a instance give a chance to a module to make some internal setup ... 
 */
static int perl_detach(void *instance)
{	
	PERL_INST	*inst = (PERL_INST *) instance;
	int 		exitstatus=0,count=0;
	
#ifdef USE_ITHREADS	
	POOL_HANDLE	*handle;
	
	for (handle = perl_pool.head; handle; handle = handle->next) {
		
		radlog(L_INFO,"Detach perl 0x%lx", (unsigned long) handle->clone);
		/*
		 * Wait until clone becomes idle 
		 *
		 */
		while (handle->status == busy) {
		}
		
		/*
		 * Give a clones chance to run detach function
		 */
		{
		dTHXa(handle->clone);
		PERL_SET_CONTEXT(handle->clone);
		{
		dSP; PUSHMARK(SP);
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
		radlog(L_INFO,"detach at 0x%lx returned status %d",
				(unsigned long) handle->clone, exitstatus);
		}
		}

	}
	/*
	 *
	 * FIXME: For more efficienty we don't
	 * free entire pool. We only reread config flags thus way 
	 * we can extend pool_size.
	 * 
	 */
	{
	dTHXa(interp);
	PERL_SET_CONTEXT(interp);
#endif /* USE_ITHREADS */	
	{
	dSP;
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
	}
#ifdef USE_ITHREADS
	}
#endif

	xlat_unregister(inst->xlat_name, perl_xlat);
	free(inst->xlat_name);

	if (inst->func_authorize) free(inst->func_authorize);
	if (inst->func_authenticate) free(inst->func_authenticate);
	if (inst->func_accounting) free(inst->func_accounting);
	if (inst->func_preacct) free(inst->func_preacct);
	if (inst->func_checksimul) free(inst->func_checksimul);
	if (inst->func_detach) free(inst->func_detach);

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
	"perl",				/* Name */
#ifdef USE_ITHREADS
	RLM_TYPE_THREAD_SAFE,		/* type */
#else
	RLM_TYPE_THREAD_UNSAFE,
#endif	
	perl_init,			/* initialization */
	perl_instantiate,		/* instantiation */
	{
		perl_authenticate,
		perl_authorize,
		perl_preacct,
		perl_accounting, 
		perl_checksimul,      	/* check simul */
		NULL,                   /* pre-proxy */
		NULL,                   /* post-proxy */
		NULL                    /* post-auth */
	},
	perl_detach,			/* detach */
	NULL,				/* destroy */
};
