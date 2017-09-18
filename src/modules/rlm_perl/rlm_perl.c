/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
#  undef INADDR_ANY
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
	bool		perl_parsed;
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
	CONF_PARSER_TERMINATOR
};

/*
 * man perlembed
 */
EXTERN_C void boot_DynaLoader(pTHX_ CV* cv);

static int perl_sys_init3_called = 0;

#ifdef USE_ITHREADS
#  define dl_librefs "DynaLoader::dl_librefs"
#  define dl_modules "DynaLoader::dl_modules"
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

	for (i = 0; i <= AvFILL(librefs); i++) {
		void *handle;
		SV *handle_sv = *av_fetch(librefs, i, false);
		if (!handle_sv) {
			ERROR("Could not fetch $%s[%d]!", dl_librefs, (int)i);
			continue;
		}
		handle = (void *)SvIV(handle_sv);

		if (handle) handles[i] = handle;
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

	for (i = 0; handles[i]; i++) {
		DEBUG("Close %p", handles[i]);
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
	while (PL_scopestack_ix > 1) {
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
	pthread_key_create(key, (void (*)(void *))rlm_destroy_perl);
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
#  if PERL_REVISION >= 5 && PERL_VERSION <8
	call_pv("CLONE",0);
#  endif
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
 *	This is wrapper for radlog
 *	Now users can call radiusd::radlog(level,msg) wich is the same
 *	as calling radlog from C code.
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
 *	This is a wraper for radius_axlat
 *	Now users are able to get data that is accessible only via xlat
 *	e.g. %{client:...}
 *	Call syntax is radiusd::xlat(string), string will be handled the
 *	same way it is described in EXPANSIONS section of man unlang
 */
static XS(XS_radiusd_xlat)
{
	dXSARGS;
	char *in_str;
	char *expanded;
	ssize_t slen;
	SV *rad_requestp_sv;
	REQUEST *request;

	if (items != 1) croak("Usage: radiusd::xlat(string)");

	rad_requestp_sv = get_sv("RAD___REQUESTP", 0);
	if (rad_requestp_sv == NULL) croak("Can not evalue xlat, RAD___REQUESTP is not set!");

	request = INT2PTR(REQUEST *, SvIV(rad_requestp_sv));

	in_str = (char *) SvPV(ST(0), PL_na);
	expanded = NULL;
	slen = radius_axlat(&expanded, request, in_str, NULL, NULL);

	if (slen < 0) {
		REDEBUG("Error parsing xlat '%s'", in_str);
		XSRETURN_UNDEF;
	}


	XST_mPV(0, expanded);
	talloc_free(expanded);
	XSRETURN(1);
}

static void xs_init(pTHX)
{
	char const *file = __FILE__;

	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);

	newXS("radiusd::radlog",XS_radiusd_radlog, "rlm_perl");
	newXS("radiusd::xlat",XS_radiusd_xlat, "rlm_perl");
}

/*
 *	The xlat function
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
			CONF_SECTION	*sub_cs = cf_item_to_section(ci);
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
			CONF_PAIR	*cp = cf_item_to_pair(ci);
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

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_perl_t	*inst = instance;

	char const	*xlat_name;

	xlat_name = cf_section_name2(conf);
	if (!xlat_name) xlat_name = cf_section_name1(conf);

	xlat_register(xlat_name, perl_xlat, NULL, inst);

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
 *	Setup a hashes wich we will use later
 *	parse a module and give him a chance to live
 *
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_perl_t	*inst = instance;
	AV		*end_AV;

	char const	**embed_c;	/* Stupid Perl and lack of const consistency */
	char		**embed;
	char		**envp = NULL;
	int		exitstatus = 0, argc=0;
	char		arg[] = "0";

	CONF_SECTION	*cs;

#ifdef USE_ITHREADS
	/*
	 *	Create pthread key. This key will be stored in instance
	 */
	pthread_mutex_init(&inst->clone_mutex, NULL);

	inst->thread_key = rad_malloc(sizeof(*inst->thread_key));
	memset(inst->thread_key,0,sizeof(*inst->thread_key));

	rlm_perl_make_key(inst->thread_key);
#endif

	/*
	 *	Setup the argument array we pass to the perl interpreter
	 */
	MEM(embed_c = talloc_zero_array(inst, char const *, 4));
	memcpy(&embed, &embed_c, sizeof(embed));
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

	/*
	 *	Create tweak the server's environment to support
	 *	perl. Docs say only call this once... Oops.
	 */
	if (!perl_sys_init3_called) {
		PERL_SYS_INIT3(&argc, &embed, &envp);
		perl_sys_init3_called = 1;
	}

	/*
	 *	Allocate a new perl interpreter to do the parsing
	 */
	if ((inst->perl = perl_alloc()) == NULL) {
		ERROR("rlm_perl: No memory for allocating new perl !");
		return -1;
	}
	perl_construct(inst->perl);	/* ...and initialise it */

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

	if (exitstatus) {
		ERROR("rlm_perl: perl_parse failed: %s not found or has syntax errors", inst->module);
		return -1;
	}

	/* parse perl configuration sub-section */
	cs = cf_section_sub_find(conf, "config");
	if (cs) {
		inst->rad_perlconf_hv = get_hv("RAD_PERLCONF", 1);
		perl_parse_config(cs, 0, inst->rad_perlconf_hv);
	}

	inst->perl_parsed = true;
	perl_run(inst->perl);

	PL_endav = end_AV;

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
		av_push(av, newSVpvn(vp->vp_strvalue, vp->vp_length));
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
static void perl_store_vps(UNUSED TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **vps, HV *rad_hv,
			   const char *hash_name, const char *list_name)
{
	VALUE_PAIR *vp;
	char *tbuff;
	size_t tbufflen = 1024;

	hv_undef(rad_hv);

	vp_cursor_t cursor;

	/*
	 *	Find out how much room to allocate.
	 */
	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (((vp->length * 2) + 3) > tbufflen) {
			tbufflen = (vp->vp_length * 2) + 3;
		}
	}
	tbuff = talloc_array(request, char, tbufflen);

	RINDENT();
	fr_pair_list_sort(vps, fr_pair_cmp_by_da_tag);
	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
	     	VALUE_PAIR *next;
	     	char const *name;
		size_t len;
		char namebuf[256];

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
			(void)hv_store(rad_hv, name, strlen(name), newSVpvn(vp->vp_strvalue, vp->vp_length), 0);
			break;

		default:
			len = vp_prints_value(tbuff, tbufflen, vp, 0);
			RDEBUG("$%s{'%s'} = &%s:%s -> '%s'", hash_name, vp->da->name,
			       list_name, vp->da->name, tbuff);
			(void)hv_store(rad_hv, name, strlen(name),
				       newSVpvn(tbuff, truncate_len(len, tbufflen)), 0);
			break;
		}
	}
	REXDENT();

	talloc_free(tbuff);
}

/*
 *
 *     Verify that a Perl SV is a string and save it in FreeRadius
 *     Value Pair Format
 *
 */
static void pairadd_sv(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **vps, char *key, SV *sv, FR_TOKEN op,
		      const char *hash_name, const char *list_name)
{
	char		*val = NULL;
	VALUE_PAIR      *vp;
	STRLEN len;

	if (!SvOK(sv)) {
		REDEBUG("Internal failure creating pair &%s:%s %s $%s{'%s'} -> '%s'", list_name, key,
			fr_int2str(fr_tokens, op, "<INVALID>"), hash_name, key, (val ? val : "undef"));
		return;
	}

	val = SvPV(sv, len);
	vp = fr_pair_make(ctx, vps, key, NULL, op);
	if (!vp) {
	fail:
		REDEBUG("Failed to create pair - %s", fr_strerror());
		REDEBUG("    &%s:%s %s $%s{'%s'} -> '%s'", list_name, key,
			fr_int2str(fr_tokens, op, "<INVALID>"), hash_name, key, (val ? val : "undef"));
		return;
	}

	switch (vp->da->type) {
	case PW_TYPE_STRING:
		fr_pair_value_bstrncpy(vp, val, len);
		break;

	default:
		VERIFY_VP(vp);

		if (fr_pair_value_from_str(vp, val, len) < 0) goto fail;
	}

	RDEBUG("&%s:%s %s $%s{'%s'} -> '%s'", list_name, key, fr_int2str(fr_tokens, op, "<INVALID>"),
	       hash_name, key, val);
}

/*
 *     Gets the content from hashes
 */
static void get_hv_content(TALLOC_CTX *ctx, REQUEST *request, HV *my_hv, VALUE_PAIR **vps,
			  const char *hash_name, const char *list_name)
{
	SV		*res_sv, **av_sv;
	AV		*av;
	char		*key;
	I32		key_len, len, i, j;

	*vps = NULL;
	for (i = hv_iterinit(my_hv); i > 0; i--) {
		res_sv = hv_iternextsv(my_hv,&key,&key_len);
		if (SvROK(res_sv) && (SvTYPE(SvRV(res_sv)) == SVt_PVAV)) {
			av = (AV*)SvRV(res_sv);
			len = av_len(av);
			for (j = 0; j <= len; j++) {
				av_sv = av_fetch(av, j, 0);
				pairadd_sv(ctx, request, vps, key, *av_sv, T_OP_ADD, hash_name, list_name);
			}
		} else {
			pairadd_sv(ctx, request, vps, key, res_sv, T_OP_EQ, hash_name, list_name);
		}
	}

	if (*vps) VERIFY_LIST(*vps);
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
	HV		*rad_state_hv;
#ifdef WITH_PROXY
	HV		*rad_request_proxy_hv;
	HV		*rad_request_proxy_reply_hv;
#endif
	SV		*rad_requestp_sv;

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
		rad_state_hv = get_hv("RAD_STATE", 1);
		rad_requestp_sv = get_sv("RAD___REQUESTP", 1);

		perl_store_vps(request->packet, request, &request->packet->vps, rad_request_hv, "RAD_REQUEST", "request");
		perl_store_vps(request->reply, request, &request->reply->vps, rad_reply_hv, "RAD_REPLY", "reply");
		perl_store_vps(request, request, &request->config, rad_check_hv, "RAD_CHECK", "control");
		perl_store_vps(request, request, &request->config, rad_config_hv, "RAD_CONFIG", "control");
		perl_store_vps(request->state_ctx, request, &request->state, rad_state_hv, "RAD_STATE", "session-state");

#ifdef WITH_PROXY
		rad_request_proxy_hv = get_hv("RAD_REQUEST_PROXY",1);
		rad_request_proxy_reply_hv = get_hv("RAD_REQUEST_PROXY_REPLY",1);

		if (request->proxy != NULL) {
			perl_store_vps(request->proxy, request, &request->proxy->vps, rad_request_proxy_hv,
				       "RAD_REQUEST_PROXY", "proxy-request");
		} else {
			hv_undef(rad_request_proxy_hv);
		}

		if (request->proxy_reply != NULL) {
			perl_store_vps(request->proxy_reply, request, &request->proxy_reply->vps,
				       rad_request_proxy_reply_hv, "RAD_REQUEST_PROXY_REPLY", "proxy-reply");
		} else {
			hv_undef(rad_request_proxy_reply_hv);
		}
#endif

		/*
		 * Store pointer to request structure globally so xlat works
		 * We mark it read-only for interpreter so end users will not be
		 * in posession to change it and crash radiusd with bogus pointer
		 */
		SvREADONLY_off(rad_requestp_sv);
		sv_setiv(rad_requestp_sv, PTR2IV(request));
		SvREADONLY_on(rad_requestp_sv);

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
			RDEBUG("perl_embed:: module = %s , func = %s exit status= %s\n",
			       inst->module, function_name, SvPV(ERRSV,n_a));
			(void)POPs;
			count = 0;
			exitstatus = RLM_MODULE_FAIL;
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
		get_hv_content(request->packet, request, rad_request_hv, &vp, "RAD_REQUEST", "request");
		if (vp) {
			fr_pair_list_free(&request->packet->vps);
			request->packet->vps = vp;
			vp = NULL;

			/*
			 *	Update cached copies
			 */
			request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
			request->password = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);
			if (!request->password)
				request->password = fr_pair_find_by_num(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY);
		}

		get_hv_content(request->reply, request, rad_reply_hv, &vp, "RAD_REPLY", "reply");
		if (vp) {
			fr_pair_list_free(&request->reply->vps);
			request->reply->vps = vp;
			vp = NULL;
		}

		get_hv_content(request, request, rad_check_hv, &vp, "RAD_CHECK", "control");
		if (vp) {
			fr_pair_list_free(&request->config);
			request->config = vp;
			vp = NULL;
		}

		get_hv_content(request->state_ctx, request, rad_state_hv, &vp, "RAD_STATE", "session-state");
		if (vp) {
			fr_pair_list_free(&request->state);
			request->state = vp;
			vp = NULL;
		}

#ifdef WITH_PROXY
		if (request->proxy) {
			get_hv_content(request->proxy, request, rad_request_proxy_hv, &vp,
			    "RAD_REQUEST_PROXY", "proxy-request");
			if (vp) {
				fr_pair_list_free(&request->proxy->vps);
				request->proxy->vps = vp;
				vp = NULL;
			}
		}

		if (request->proxy_reply) {
			get_hv_content(request->proxy_reply, request, rad_request_proxy_reply_hv, &vp,
			    "RAD_REQUEST_PROXY_REPLY", "proxy-reply");
			if (vp) {
				fr_pair_list_free(&request->proxy_reply->vps);
				request->proxy_reply->vps = vp;
				vp = NULL;
			}
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

	if ((pair = fr_pair_find_by_num(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) != NULL) {
		acctstatustype = pair->vp_integer;
	} else {
		RDEBUG("Invalid Accounting Packet");
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

	case PW_STATUS_STOP:
		if (((rlm_perl_t *)instance)->func_stop_accounting) {
			return do_perl(instance, request,
				       ((rlm_perl_t *)instance)->func_stop_accounting);
		} else {
			return do_perl(instance, request,
				       ((rlm_perl_t *)instance)->func_accounting);
		}

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


	if (inst->perl_parsed) {
		dTHXa(inst->perl);
		PERL_SET_CONTEXT(inst->perl);
		if (inst->rad_perlconf_hv != NULL) hv_undef(inst->rad_perlconf_hv);

		if (inst->func_detach) {
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

	/*
	 *	Hope this is not really needed.
	 *	Is only allowed to be called once just before exit().
	 *
	 PERL_SYS_TERM();
	*/
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
extern module_t rlm_perl;
module_t rlm_perl = {
	.magic		= RLM_MODULE_INIT,
	.name		= "perl",
#ifdef USE_ITHREADS
	.type		= RLM_TYPE_THREAD_SAFE,
#else
	.type		= RLM_TYPE_THREAD_UNSAFE,
#endif
	.inst_size	= sizeof(rlm_perl_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul,
#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
#endif
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa
#endif
	},
};
