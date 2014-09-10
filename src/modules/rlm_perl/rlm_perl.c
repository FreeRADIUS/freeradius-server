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
 * @file rlm_perl.c
 * @brief Translates requests between the server an a perl interpreter.
 *
 * @copyright 2002,2006  The FreeRADIUS server project
 * @copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

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
typedef struct rlm_perl_t {
	/* Name of the perl module */
	char const	*module;

	/* Name of the functions for each module method */
	char const	*func_authorize;
	char const	*func_authenticate;
	char const	*func_accounting;
	char const	*func_start_accounting;
	char const	*func_stop_accounting;
	char const	*func_preacct;
	char const	*func_checksimul;
	char const	*func_detach;
	char const	*func_xlat;
#ifdef WITH_PROXY
	char const	*func_pre_proxy;
	char const	*func_post_proxy;
#endif
	char const	*func_post_auth;
#ifdef WITH_COA
	char const	*func_recv_coa;
	char const	*func_send_coa;
#endif
	char const	*xlat_name;
	char const	*perl_flags;
	PerlInterpreter	*perl;
	pthread_key_t	*thread_key;

#ifdef USE_ITHREADS
	pthread_mutex_t	clone_mutex;
#endif

	HV		*rad_perlconf_hv;	//!< holds "config" items (perl %RAD_PERLCONF hash).

} rlm_perl_t;
/*
 *	A mapping of configuration file names to internal variables.
 */
#define RLM_PERL_CONF(_x) { "func_" STRINGIFY(_x), PW_TYPE_STRING, \
			offsetof(rlm_perl_t,func_##_x), NULL, STRINGIFY(_x)}

static const CONF_PARSER module_config[] = {
	{ "module", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_DEPRECATED, rlm_perl_t, module), NULL },
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_REQUIRED, rlm_perl_t, module), NULL },

	RLM_PERL_CONF(authorize),
	RLM_PERL_CONF(authenticate),
	RLM_PERL_CONF(post_auth),
	RLM_PERL_CONF(accounting),
	RLM_PERL_CONF(preacct),
	RLM_PERL_CONF(checksimul),
	RLM_PERL_CONF(detach),
	RLM_PERL_CONF(xlat),

#ifdef WITH_PROXY
	RLM_PERL_CONF(pre_proxy),
	RLM_PERL_CONF(post_proxy),
#endif
#ifdef WITH_COA
	RLM_PERL_CONF(recv_coa),
	RLM_PERL_CONF(send_coa),
#endif
	{ "perl_flags", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_perl_t, perl_flags), NULL },

	{ "func_start_accounting", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_perl_t, func_start_accounting), NULL },

	{ "func_stop_accounting", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_perl_t, func_stop_accounting), NULL },

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
	AV *librefs = get_av(dl_librefs, false);
	if (librefs) {
		av_clear(librefs);
	}
}

static void **rlm_perl_get_handles(pTHX)
{
	I32 i;
	AV *librefs = get_av(dl_librefs, false);
	AV *modules = get_av(dl_modules, false);
	void **handles;

	if (!librefs) return NULL;

	if (!(AvFILL(librefs) >= 0)) {
		return NULL;
	}

	handles = (void **)rad_malloc(sizeof(void *) * (AvFILL(librefs)+2));

	for (i=0; i<=AvFILL(librefs); i++) {
		void *handle;
		SV *handle_sv = *av_fetch(librefs, i, false);

		if(!handle_sv) {
			ERROR("Could not fetch $%s[%d]!\n",
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
		DEBUG("close %p\n", handles[i]);
		dlclose(handles[i]);
	}

	free(handles);
}

DIAG_OFF(shadow)
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
DIAG_ON(shadow)

static void rlm_destroy_perl(PerlInterpreter *perl)
{
	void	**handles;

	dTHXa(perl);
	PERL_SET_CONTEXT(perl);

	handles = rlm_perl_get_handles(aTHX);
	if (handles) rlm_perl_close_handles(handles);
	rlm_perl_destruct(perl);
}

/* Create Key */
static void rlm_perl_make_key(pthread_key_t *key)
{
	pthread_key_create(key, (void*)rlm_destroy_perl);
}

static PerlInterpreter *rlm_perl_clone(PerlInterpreter *perl, pthread_key_t *key)
{
	int ret;

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

	ret = pthread_setspecific(*key, interp);
	if (ret != 0) {
		DEBUG("rlm_perl: Failed associating interpretor with thread %s", fr_syserror(ret));

		rlm_perl_destruct(interp);
		return NULL;
	}

	return interp;
}
#endif

/*
 * This is wrapper for radlog
 * Now users can call radiusd::radlog(level,msg) wich is the same
 * calling radlog from C code.
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

static void xs_init(pTHX)
{
	char const *file = __FILE__;

	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);

	newXS("radiusd::radlog",XS_radiusd_radlog, "rlm_perl");
}

/*
 * The xlat function
 */
static ssize_t perl_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{

	rlm_perl_t	*inst = (rlm_perl_t *) instance;
	char		*tmp;
	char const	*p, *q;
	int		count;
	size_t		ret = 0;
	STRLEN		n_a;

#ifdef USE_ITHREADS
	PerlInterpreter *interp;

	pthread_mutex_lock(&inst->clone_mutex);
	interp = rlm_perl_clone(inst->perl, inst->thread_key);
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
		ENTER;SAVETMPS;

		PUSHMARK(SP);

		p = q = fmt;
		while (*p == ' ') {
			p++;
			q++;
		}
		while (*q) {
			if (*q == ' ') {
				XPUSHs(sv_2mortal(newSVpvn(p, q - p)));
				p = q + 1;

				/*
				 *	Don't use an empty string
				 */
				while (*p == ' ') p++;
				q = p;
			}
			q++;
		}

		/*
		 *	And the last bit.
		 */
		if (*p) {
			XPUSHs(sv_2mortal(newSVpvn(p, strlen(p))));
		}

		PUTBACK;

		count = call_pv(inst->func_xlat, G_SCALAR | G_EVAL);

		SPAGAIN;
		if (SvTRUE(ERRSV)) {
			REDEBUG("Exit %s", SvPV(ERRSV,n_a));
			(void)POPs;
		} else if (count > 0) {
			tmp = POPp;
			strlcpy(out, tmp, freespace);
			ret = strlen(out);

			RDEBUG("Len is %zu , out is %s freespace is %zu", ret, out, freespace);
		}

		PUTBACK ;
		FREETMPS ;
		LEAVE ;

	}

	return ret;
}

/*
 *	Parse a configuration section, and populate a HV.
 *	This function is recursively called (allows to have nested hashes.)
 */
static void perl_parse_config(CONF_SECTION *cs, int lvl, HV *rad_hv)
{
	if (!cs || !rad_hv) return;

	int indent_section = (lvl + 1) * 4;
	int indent_item = (lvl + 2) * 4;

	DEBUG("%*s%s {", indent_section, " ", cf_section_name1(cs));

	CONF_ITEM *ci = NULL;

	while ((ci = cf_item_find_next(cs, ci))) {
		/*
		 *  This is a section.
		 *  Create a new HV, store it as a reference in current HV,
		 *  Then recursively call perl_parse_config with this section and the new HV.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION	*sub_cs = cf_itemtosection(ci);
			char const	*key = cf_section_name1(sub_cs); /* hash key */
			HV		*sub_hv;
			SV		*ref;

			if (!key) continue;

			if (hv_exists(rad_hv, key, strlen(key))) {
				WARN("rlm_perl: Ignoring duplicate config section '%s'", key);
				continue;
			}

			sub_hv = newHV();
			ref = newRV_inc((SV*) sub_hv);

			(void)hv_store(rad_hv, key, strlen(key), ref, 0);

			perl_parse_config(sub_cs, lvl + 1, sub_hv);
		} else if (cf_item_is_pair(ci)){
			CONF_PAIR	*cp = cf_itemtopair(ci);
			char const	*key = cf_pair_attr(cp);	/* hash key */
			char const	*value = cf_pair_value(cp);	/* hash value */

			if (!key || !value) continue;

			/*
			 *  This is an item.
			 *  Store item attr / value in current HV.
			 */
			if (hv_exists(rad_hv, key, strlen(key))) {
				WARN("rlm_perl: Ignoring duplicate config item '%s'", key);
				continue;
			}

			(void)hv_store(rad_hv, key, strlen(key), newSVpvn(value, strlen(value)), 0);

			DEBUG("%*s%s = %s", indent_item, " ", key, value);
		}
	}

	DEBUG("%*s}", indent_section, " ");
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
 *	Setup a hashes wich we will use later
 *	parse a module and give him a chance to live
 *
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_perl_t       *inst = instance;
	AV		*end_AV;

	char const **embed_c;	/* Stupid Perl and lack of const consistency */
	char **embed;
	char **envp = NULL;
	char const *xlat_name;
	int exitstatus = 0, argc=0;

	MEM(embed_c = talloc_zero_array(inst, char const *, 4));
	memcpy(&embed, &embed_c, sizeof(embed));
	/*
	 *	Create pthread key. This key will be stored in instance
	 */

#ifdef USE_ITHREADS
	pthread_mutex_init(&inst->clone_mutex, NULL);

	inst->thread_key = rad_malloc(sizeof(*inst->thread_key));
	memset(inst->thread_key,0,sizeof(*inst->thread_key));

	rlm_perl_make_key(inst->thread_key);
#endif

	char arg[] = "0";

	embed_c[0] = NULL;
	if (inst->perl_flags) {
		embed_c[1] = inst->perl_flags;
		embed_c[2] = inst->module;
		embed_c[3] = arg;
		argc = 4;
	} else {
		embed_c[1] = inst->module;
		embed_c[2] = arg;
		argc = 3;
	}

	PERL_SYS_INIT3(&argc, &embed, &envp);

	if ((inst->perl = perl_alloc()) == NULL) {
		ERROR("rlm_perl: No memory for allocating new perl !");
		return (-1);
	}

	perl_construct(inst->perl);

#ifdef USE_ITHREADS
	PL_perl_destruct_level = 2;

	{
		dTHXa(inst->perl);
	}
	PERL_SET_CONTEXT(inst->perl);
#endif

#if PERL_REVISION >= 5 && PERL_VERSION >=8
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

	exitstatus = perl_parse(inst->perl, xs_init, argc, embed, NULL);

	end_AV = PL_endav;
	PL_endav = (AV *)NULL;

	if(!exitstatus) {
		perl_run(inst->perl);
	} else {
		ERROR("rlm_perl: perl_parse failed: %s not found or has syntax errors. \n", inst->module);
		return (-1);
	}

	PL_endav = end_AV;

	xlat_name = cf_section_name2(conf);
	if (!xlat_name)
		xlat_name = cf_section_name1(conf);
	if (xlat_name) {
		xlat_register(xlat_name, perl_xlat, NULL, inst);
	}

	/* parse perl configuration sub-section */
	CONF_SECTION *cs;
	cs = cf_section_sub_find(conf, "config");
	if (cs) {
		DEBUG("rlm_perl (%s): parsing 'config' section...", xlat_name);

		inst->rad_perlconf_hv = get_hv("RAD_PERLCONF",1);
		perl_parse_config(cs, 0, inst->rad_perlconf_hv);

		DEBUG("rlm_perl (%s): done parsing 'config'.", xlat_name);
	}

	return 0;
}

static void perl_vp_to_svpvn_element(REQUEST *request, AV *av, VALUE_PAIR const *vp,
				     int *i, const char *hash_name, const char *list_name)
{
	size_t len;

	char buffer[1024];

	switch (vp->da->type) {
	case PW_TYPE_STRING:
		RDEBUG("$%s{'%s'}[%i] = &%s:%s -> '%s'", hash_name, vp->da->name, *i,
		       list_name, vp->da->name, vp->vp_strvalue);
		av_push(av, newSVpvn(vp->vp_strvalue, vp->length));
		break;

	default:
		len = vp_prints_value(buffer, sizeof(buffer), vp, 0);
		RDEBUG("$%s{'%s'}[%i] = &%s:%s -> '%s'", hash_name, vp->da->name, *i,
		       list_name, vp->da->name, buffer);
		av_push(av, newSVpvn(buffer, truncate_len(len, sizeof(buffer))));
		break;
	}
	(*i)++;
}

/*
 *  	get the vps and put them in perl hash
 *  	If one VP have multiple values it is added as array_ref
 *  	Example for this is Cisco-AVPair that holds multiple values.
 *  	Which will be available as array_ref in $RAD_REQUEST{'Cisco-AVPair'}
 */
static void perl_store_vps(UNUSED TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR *vps, HV *rad_hv,
			   const char *hash_name, const char *list_name)
{
	VALUE_PAIR *vp;

	hv_undef(rad_hv);

	vp_cursor_t cursor;

	RINDENT();
	pairsort(&vps, attrtagcmp);
	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
	     	VALUE_PAIR *next;

	     	char const *name;
		char namebuf[256];
		char buffer[1024];

		size_t len;

		/*
		 *	Tagged attributes are added to the hash with name
		 *	<attribute>:<tag>, others just use the normal attribute
		 *	name as the key.
		 */
		if (vp->da->flags.has_tag && (vp->tag != TAG_ANY)) {
			snprintf(namebuf, sizeof(namebuf), "%s:%d", vp->da->name, vp->tag);
			name = namebuf;
		} else {
			name = vp->da->name;
		}

		/*
		 *	We've sorted by type, then tag, so attributes of the
		 *	same type/tag should follow on from each other.
		 */
		if ((next = fr_cursor_next_peek(&cursor)) && ATTRIBUTE_EQ(vp, next)) {
			int i = 0;
			AV *av;

			av = newAV();

			perl_vp_to_svpvn_element(request, av, vp, &i, hash_name, list_name);
			do {
				perl_vp_to_svpvn_element(request, av, next, &i, hash_name, list_name);
				fr_cursor_next(&cursor);
			} while ((next = fr_cursor_next_peek(&cursor)) && ATTRIBUTE_EQ(vp, next));
			(void)hv_store(rad_hv, name, strlen(name), newRV_noinc((SV *)av), 0);

			continue;
		}

		/*
		 *	It's a normal single valued attribute
		 */
		switch (vp->da->type) {
		case PW_TYPE_STRING:
			RDEBUG("$%s{'%s'} = &%s:%s -> '%s'", hash_name, vp->da->name, list_name,
			       vp->da->name, vp->vp_strvalue);
			(void)hv_store(rad_hv, name, strlen(name), newSVpvn(vp->vp_strvalue, vp->length), 0);
			break;

		default:
			len = vp_prints_value(buffer, sizeof(buffer), vp, 0);
			RDEBUG("$%s{'%s'} = &%s:%s -> '%s'", hash_name, vp->da->name,
			       list_name, vp->da->name, buffer);
			(void)hv_store(rad_hv, name, strlen(name),
				       newSVpvn(buffer, truncate_len(len, sizeof(buffer))), 0);
			break;
		}
	}
	REXDENT();
}

/*
 *
 *     Verify that a Perl SV is a string and save it in FreeRadius
 *     Value Pair Format
 *
 */
static int pairadd_sv(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **vps, char *key, SV *sv, FR_TOKEN op,
		      const char *hash_name, const char *list_name)
{
	char	    *val;
	VALUE_PAIR      *vp;

	if (SvOK(sv)) {
		STRLEN len;
		val = SvPV(sv, len);
		vp = pairmake(ctx, vps, key, NULL, op);
		if (!vp) {
		fail:
			REDEBUG("Failed to create pair %s:%s %s %s", list_name, key,
				fr_int2str(fr_tokens, op, "<INVALID>"), val);
			return -1;
		}

		switch (vp->da->type) {
		case PW_TYPE_STRING:
			pairstrncpy(vp, val, len);
			break;

		default:
			if (pairparsevalue(vp, val, len) < 0) goto fail;
		}

		RDEBUG("&%s:%s %s $%s{'%s'} -> '%s'", list_name, key, fr_int2str(fr_tokens, op, "<INVALID>"),
		       hash_name, key, val);
		return 0;
	}
	return -1;
}

/*
 *     Gets the content from hashes
 */
static int get_hv_content(TALLOC_CTX *ctx, REQUEST *request, HV *my_hv, VALUE_PAIR **vps,
			  const char *hash_name, const char *list_name)
{
	SV		*res_sv, **av_sv;
	AV		*av;
	char		*key;
	I32		key_len, len, i, j;
	int		ret = 0;

	*vps = NULL;
	for (i = hv_iterinit(my_hv); i > 0; i--) {
		res_sv = hv_iternextsv(my_hv,&key,&key_len);
		if (SvROK(res_sv) && (SvTYPE(SvRV(res_sv)) == SVt_PVAV)) {
			av = (AV*)SvRV(res_sv);
			len = av_len(av);
			for (j = 0; j <= len; j++) {
				av_sv = av_fetch(av, j, 0);
				ret = pairadd_sv(ctx, request, vps, key, *av_sv, T_OP_ADD, hash_name, list_name) + ret;
			}
		} else ret = pairadd_sv(ctx, request, vps, key, res_sv, T_OP_EQ, hash_name, list_name) + ret;
	}

	return ret;
}

/*
 * 	Call the function_name inside the module
 * 	Store all vps in hashes %RAD_CHECK %RAD_REPLY %RAD_REQUEST
 *
 */
static int do_perl(void *instance, REQUEST *request, char const *function_name)
{

	rlm_perl_t	*inst = instance;
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

	/*
	 *	Radius has told us to call this function, but none
	 *	is defined.
	 */
	if (!function_name) return RLM_MODULE_FAIL;

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

		rad_reply_hv = get_hv("RAD_REPLY", 1);
		rad_check_hv = get_hv("RAD_CHECK", 1);
		rad_config_hv = get_hv("RAD_CONFIG", 1);
		rad_request_hv = get_hv("RAD_REQUEST", 1);

		perl_store_vps(request->packet, request, request->packet->vps, rad_request_hv, "RAD_REQUEST", "request");
		perl_store_vps(request->reply, request, request->reply->vps, rad_reply_hv, "RAD_REPLY", "reply");
		perl_store_vps(request, request, request->config_items, rad_check_hv, "RAD_CHECK", "control");
		perl_store_vps(request, request, request->config_items, rad_config_hv, "RAD_CONFIG", "control");

#ifdef WITH_PROXY
		rad_request_proxy_hv = get_hv("RAD_REQUEST_PROXY",1);
		rad_request_proxy_reply_hv = get_hv("RAD_REQUEST_PROXY_REPLY",1);

		if (request->proxy != NULL) {
			perl_store_vps(request->proxy, request, request->proxy->vps, rad_request_proxy_hv,
				       "RAD_REQUEST_PROXY", "proxy-request");
		} else {
			hv_undef(rad_request_proxy_hv);
		}

		if (request->proxy_reply != NULL) {
			perl_store_vps(request->proxy_reply, request, request->proxy_reply->vps,
				       rad_request_proxy_reply_hv, "RAD_REQUEST_PROXY_REPLY", "proxy-reply");
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
			ERROR("rlm_perl: perl_embed:: module = %s , func = %s exit status= %s\n",
			       inst->module,
			       function_name, SvPV(ERRSV,n_a));
			(void)POPs;
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
		if ((get_hv_content(request->packet, request, rad_request_hv, &vp, "RAD_REQUEST", "request")) == 0) {
			pairfree(&request->packet->vps);
			request->packet->vps = vp;
			vp = NULL;

			/*
			 *	Update cached copies
			 */
			request->username = pairfind(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
			request->password = pairfind(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);
			if (!request->password)
				request->password = pairfind(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY);
		}

		if ((get_hv_content(request->reply, request, rad_reply_hv, &vp, "RAD_REPLY", "reply")) == 0) {
			pairfree(&request->reply->vps);
			request->reply->vps = vp;
			vp = NULL;
		}

		if ((get_hv_content(request, request, rad_check_hv, &vp, "RAD_CHECK", "control")) == 0) {
			pairfree(&request->config_items);
			request->config_items = vp;
			vp = NULL;
		}

#ifdef WITH_PROXY
		if (request->proxy &&
		    (get_hv_content(request->proxy, request, rad_request_proxy_hv, &vp,
		    		    "RAD_REQUEST_PROXY", "proxy-request") == 0)) {
			pairfree(&request->proxy->vps);
			request->proxy->vps = vp;
			vp = NULL;
		}

		if (request->proxy_reply &&
		    (get_hv_content(request->proxy_reply, request, rad_request_proxy_reply_hv, &vp,
		    		    "RAD_REQUEST_PROXY_REPLY", "proxy-reply") == 0)) {
			pairfree(&request->proxy_reply->vps);
			request->proxy_reply->vps = vp;
			vp = NULL;
		}
#endif

	}
	return exitstatus;
}

#define RLM_PERL_FUNC(_x) static rlm_rcode_t CC_HINT(nonnull) mod_##_x(void *instance, REQUEST *request) \
	{								\
		return do_perl(instance, request,			\
			       ((rlm_perl_t *)instance)->func_##_x); \
	}

RLM_PERL_FUNC(authorize)
RLM_PERL_FUNC(authenticate)
RLM_PERL_FUNC(post_auth)

RLM_PERL_FUNC(checksimul)

#ifdef WITH_PROXY
RLM_PERL_FUNC(pre_proxy)
RLM_PERL_FUNC(post_proxy)
#endif

#ifdef WITH_COA
RLM_PERL_FUNC(recv_coa)
RLM_PERL_FUNC(send_coa)
#endif

RLM_PERL_FUNC(preacct)

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	VALUE_PAIR	*pair;
	int 		acctstatustype=0;

	if ((pair = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) != NULL) {
		acctstatustype = pair->vp_integer;
	} else {
		ERROR("Invalid Accounting Packet");
		return RLM_MODULE_INVALID;
	}

	switch (acctstatustype) {
	case PW_STATUS_START:

		if (((rlm_perl_t *)instance)->func_start_accounting) {
			return do_perl(instance, request,
				       ((rlm_perl_t *)instance)->func_start_accounting);
		} else {
			return do_perl(instance, request,
				       ((rlm_perl_t *)instance)->func_accounting);
		}
		break;

	case PW_STATUS_STOP:

		if (((rlm_perl_t *)instance)->func_stop_accounting) {
			return do_perl(instance, request,
				       ((rlm_perl_t *)instance)->func_stop_accounting);
		} else {
			return do_perl(instance, request,
				       ((rlm_perl_t *)instance)->func_accounting);
		}
		break;

	default:
		return do_perl(instance, request,
			       ((rlm_perl_t *)instance)->func_accounting);
	}
}


/*
 * Detach a instance give a chance to a module to make some internal setup ...
 */
DIAG_OFF(nested-externs)
static int mod_detach(void *instance)
{
	rlm_perl_t	*inst = (rlm_perl_t *) instance;
	int 		exitstatus = 0, count = 0;

	if (inst->rad_perlconf_hv != NULL) {
		hv_undef(inst->rad_perlconf_hv);
	}

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

#ifdef USE_ITHREADS
	rlm_perl_destruct(inst->perl);
	pthread_mutex_destroy(&inst->clone_mutex);
#else
	perl_destruct(inst->perl);
	perl_free(inst->perl);
#endif

	PERL_SYS_TERM();
	return exitstatus;
}
DIAG_ON(nested-externs)

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
	sizeof(rlm_perl_t),
	module_config,
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		mod_authenticate,	/* authenticate */
		mod_authorize,		/* authorize */
		mod_preacct,		/* preacct */
		mod_accounting,	/* accounting */
		mod_checksimul,      	/* check simul */
#ifdef WITH_PROXY
		mod_pre_proxy,		/* pre-proxy */
		mod_post_proxy,	/* post-proxy */
#else
		NULL, NULL,
#endif
		mod_post_auth		/* post-auth */
#ifdef WITH_COA
		, mod_recv_coa,
		mod_send_coa
#endif
	},
};
