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
 * @copyright 2002,2006 The FreeRADIUS server project
 * @copyright 2002 Boian Jordanov (bjordanov@orbitel.bg)
 */
RCSID("$Id$")

#define LOG_PREFIX "perl"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/radius/radius.h>

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(compound-token-split-by-macro) /* Perl does horrible things with macros */
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)

#ifdef INADDR_ANY
#  undef INADDR_ANY
#endif
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <dlfcn.h>
#include <semaphore.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
extern char **environ;
#endif

#ifndef USE_ITHREADS
#  error perl must be compiled with USE_ITHREADS
#endif

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	/* Name of the perl module */
	char const	*module;

	/* Name of the functions for each module method */
	char const	*func_authorize;
	char const	*func_authenticate;
	char const	*func_accounting;
	char const	*func_start_accounting;
	char const	*func_stop_accounting;
	char const	*func_preacct;
	char const	*func_detach;
	char const	*func_post_auth;
	char const	*perl_flags;
	PerlInterpreter	*perl;
	bool		perl_parsed;
	HV		*rad_perlconf_hv;	//!< holds "config" items (perl %RAD_PERLCONF hash).

} rlm_perl_t;

typedef struct {
	PerlInterpreter		*perl;	//!< Thread specific perl interpreter.
} rlm_perl_thread_t;

static void *perl_dlhandle;		//!< To allow us to load perl's symbols into the global symbol table.

/*
 *	A mapping of configuration file names to internal variables.
 */
#define RLM_PERL_CONF(_x) { FR_CONF_OFFSET("func_" STRINGIFY(_x), FR_TYPE_STRING, rlm_perl_t, func_##_x), \
			   .data = NULL, .dflt = STRINGIFY(_x), .quote = T_INVALID }

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_perl_t, module) },

	RLM_PERL_CONF(authorize),
	RLM_PERL_CONF(authenticate),
	RLM_PERL_CONF(post_auth),
	RLM_PERL_CONF(accounting),
	RLM_PERL_CONF(preacct),
	RLM_PERL_CONF(detach),

	{ FR_CONF_OFFSET("perl_flags", FR_TYPE_STRING, rlm_perl_t, perl_flags) },

	{ FR_CONF_OFFSET("func_start_accounting", FR_TYPE_STRING, rlm_perl_t, func_start_accounting) },

	{ FR_CONF_OFFSET("func_stop_accounting", FR_TYPE_STRING, rlm_perl_t, func_stop_accounting) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_perl_dict[];
fr_dict_autoload_t rlm_perl_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_acct_status_type;
static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_perl_dict_attr[];
fr_dict_attr_autoload_t rlm_perl_dict_attr[] = {
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

/*
 * man perlembed
 */
EXTERN_C void boot_DynaLoader(pTHX_ CV* cv);

static _Thread_local request_t *rlm_perl_request;

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

	MEM(handles = talloc_array(NULL, void *, AvFILL(librefs) + 2));
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

	talloc_free(handles);
}

/*
 *	This is wrapper for fr_log
 *	Now users can call radiusd::log(level,msg) wich is the same
 *	as calling fr_log from C code.
 */
static XS(XS_radiusd_log)
{
	dXSARGS;
	if (items !=2)
		croak("Usage: radiusd::log(level, message)");
	{
		int     level;
		char    *msg;

		level = (int) SvIV(ST(0));
		msg   = (char *) SvPV(ST(1), PL_na);

		/*
		 *	Because 'msg' is a 'char *', we don't want '%s', etc.
		 *	in it to give us printf-style vulnerabilities.
		 */
		fr_log(&default_log, level, __FILE__, __LINE__, "rlm_perl: %s", msg);
	}
	XSRETURN_NO;
}

/*
 *	This is a wraper for xlat_aeval
 *	Now users are able to get data that is accessible only via xlat
 *	e.g. %(client:...)
 *	Call syntax is radiusd::xlat(string), string will be handled the
 *	same way it is described in EXPANSIONS section of man unlang
 */
static XS(XS_radiusd_xlat)
{
	dXSARGS;
	char *in_str;
	char *expanded;
	ssize_t slen;
	request_t *request;

	if (items != 1) croak("Usage: radiusd::xlat(string)");

	request = rlm_perl_request;

	in_str = (char *) SvPV(ST(0), PL_na);

	slen = xlat_aeval(request, &expanded, request, in_str, NULL, NULL);
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

	newXS("radiusd::log",XS_radiusd_log, "rlm_perl");
	newXS("radiusd::xlat",XS_radiusd_xlat, "rlm_perl");
}

/** Convert a list of value boxes to a Perl array for passing to subroutines
 *
 * The Perl array object should be created before calling this
 * to populate it.
 *
 * @param[in,out] av	Perl array object to append values to.
 * @param[in] head	of VB list.
 * @return
 * 	- 0 on success
 * 	- -1 on failure
 */
static int perl_vblist_to_av(AV *av, fr_value_box_list_t *head) {
	fr_value_box_t	*vb = NULL;
	SV		*sv;

	while ((vb = fr_dlist_next(head, vb))) {
		switch (vb->type) {
		case FR_TYPE_STRING:
			sv = newSVpvn(vb->vb_strvalue, vb->length);
			break;

		case FR_TYPE_OCTETS:
			sv = newSVpvn((char const *)vb->vb_octets, vb->vb_length);
			break;

		case FR_TYPE_GROUP:
		{
			AV 	*sub_av;
			sub_av = newAV();
			perl_vblist_to_av(sub_av, &vb->vb_group);
			sv = newRV_inc((SV *)sub_av);
		}
			break;
		default:
		{
			char	buffer[1024];
			ssize_t	slen;

			slen = fr_value_box_print_quoted(&FR_SBUFF_OUT(buffer, sizeof(buffer)), vb, T_BARE_WORD);
			if (slen < 0) return -1;
			sv = newSVpvn(buffer, (size_t)slen);
		}
			break;
		}
		if (!sv) return -1;
		if (vb->tainted) SvTAINT(sv);
		av_push(av, sv);
	}
	return 0;
}

/** Parse a Perl SV and create value boxes, appending to a list
 *
 * For parsing values passed back from a Perl subroutine
 *
 * When hashes are returned, first the key is added as a value box then the value
 *
 * @param[in] ctx	to allocate boxes in.
 * @param[out] list	to append value boxes to.
 * @param[in] request	being handled - only used for debug messages
 * @param[in] sv	to parse
 * @return
 * 	- 0 on success
 * 	- -1 on failure
 */
static int perl_sv_to_vblist(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request, SV *sv) {
	fr_value_box_t	*vb = NULL;
	char		*tmp;
	STRLEN		len;
	AV		*av;
	HV		*hv;
	I32		sv_len, i;
	int		type;

	type = SvTYPE(sv);

	switch (type) {
	case SVt_IV:
	/*	Integer or Reference */
		if (SvROK(sv)) {
			DEBUG3("Reference returned");
			if (perl_sv_to_vblist(ctx, list, request, SvRV(sv)) < 0) return -1;
			break;
		}
		DEBUG3("Integer returned");
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_INT32, NULL, SvTAINTED(sv)));
		vb->vb_int32 = SvIV(sv);
		break;

	case SVt_NV:
	/*	Float */
		DEBUG3("Float returned");
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_FLOAT64, NULL, SvTAINTED(sv)));
		vb->vb_float64 = SvNV(sv);
		break;

	case SVt_PV:
	/*	String */
		DEBUG3("String returned");
		tmp = SvPVutf8(sv, len);
		MEM(vb = fr_value_box_alloc_null(ctx));
		if (fr_value_box_bstrndup(ctx, vb, NULL, tmp, len, SvTAINTED(sv)) < 0) {
			talloc_free(vb);
			RPEDEBUG("Failed to allocate %ld for output", len);
			return -1;
		}
		break;

	case SVt_PVAV:
	/*	Array */
	{
		SV	**av_sv;
		DEBUG3("Array returned");
		av = (AV*)sv;
		sv_len = av_len(av);
		for (i = 0; i <= sv_len; i++) {
			av_sv = av_fetch(av, i, 0);
			if (SvOK(*av_sv)) {
				if (perl_sv_to_vblist(ctx, list, request, *av_sv) < 0) return -1;
			}
		}
	}
		break;

	case SVt_PVHV:
	/*	Hash */
	{
		SV	*hv_sv;
		DEBUG3("Hash returned");
		hv = (HV*)sv;
		for (i = hv_iterinit(hv); i > 0; i--) {
			hv_sv = hv_iternextsv(hv, &tmp, &sv_len);
			/*
			 *	Add key first
			 */
			MEM(vb = fr_value_box_alloc_null(ctx));
			if (fr_value_box_bstrndup(ctx, vb, NULL, tmp, sv_len, SvTAINTED(hv_sv)) < 0) {
				talloc_free(vb);
				RPEDEBUG("Failed to allocate %d for output", sv_len);
				return -1;
			}
			fr_dlist_insert_tail(list, vb);

			/*
			 *	Now process value
			 */
			if (perl_sv_to_vblist(ctx, list, request, hv_sv) < 0) return -1;

		}
		/*
		 *	Box has already been added to list - return
		 */
		return 0;
	}

	case SVt_NULL:
		break;

	default:
		RPEDEBUG("Perl returned unsupported data type %d", type);
		return -1;

	}

	if (vb) fr_dlist_insert_tail(list, vb);

	return 0;
}

static xlat_arg_parser_t const perl_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	{ .variadic = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Call perl code using an xlat
 *
 * @ingroup xlat_functions
 */
static xlat_action_t perl_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
			       xlat_ctx_t const *xctx,
			       request_t *request, fr_value_box_list_t *in)
{
	rlm_perl_thread_t const		*t = talloc_get_type_abort_const(xctx->mctx->thread, rlm_perl_thread_t);
	int				count, i;
	xlat_action_t			ret = XLAT_ACTION_FAIL;
	STRLEN				n_a;
	fr_value_box_t			*func = fr_dlist_pop_head(in);
	fr_value_box_t			*arg = NULL, *child;
	SV				*sv;
	AV				*av;
	fr_value_box_list_t		list, sub_list;
	fr_value_box_t			*vb = NULL;

	fr_value_box_list_init(&list);
	fr_value_box_list_init(&sub_list);

	{
		dTHXa(t->perl);
		PERL_SET_CONTEXT(t->perl);
	}

	{
		dSP;
		ENTER;SAVETMPS;

		PUSHMARK(SP);

		while ((arg = fr_dlist_next(in, arg))) {
			fr_assert(arg->type == FR_TYPE_GROUP);
			if (fr_dlist_empty(&arg->vb_group)) continue;

			if (fr_dlist_num_elements(&arg->vb_group) == 1) {
				child = fr_dlist_head(&arg->vb_group);
				/*
				 *	Single child value - add as scalar
				 */
				if (child->length == 0) continue;
				DEBUG3("Passing single value %pV", child);
				sv = newSVpvn(child->vb_strvalue, child->length);
				if (child->tainted) SvTAINT(sv);
				XPUSHs(sv_2mortal(sv));
				continue;
			}

			/*
			 *	Multiple child values - create array and pass reference
			 */
			av = newAV();
			perl_vblist_to_av(av, &arg->vb_group);
			DEBUG3("Passing list as array %pM", &arg->vb_group);
			sv = newRV_inc((SV *)av);
			XPUSHs(sv_2mortal(sv));
		}

		PUTBACK;

		count = call_pv(func->vb_strvalue, G_ARRAY | G_EVAL);

		SPAGAIN;
		if (SvTRUE(ERRSV)) {
			REDEBUG("Exit %s", SvPV(ERRSV,n_a));
			(void)POPs;
			goto cleanup;
		}

		/*
		 *	As results are popped from a stack, they are in reverse
		 *	sequence.  Add to a temporary list and then prepend to
		 *	main list.
		 */
		for (i = 0; i < count; i++) {
			sv = POPs;
			if (perl_sv_to_vblist(ctx, &sub_list, request, sv) < 0) goto cleanup;
			fr_dlist_move_head(&list, &sub_list);
		}
		ret = XLAT_ACTION_DONE;

		/*
		 *	Move the assembled list of boxes to the output
		 */
		while ((vb = fr_dlist_pop_head(&list))) fr_dcursor_append(out, vb);

	cleanup:
		PUTBACK;
		FREETMPS;
		LEAVE;

	}

	return ret;
}

/*
 *	Parse a configuration section, and populate a HV.
 *	This function is recursively called (allows to have nested hashes.)
 */
static void perl_parse_config(CONF_SECTION *cs, int lvl, HV *rad_hv)
{
	int indent_section = (lvl + 1) * 4;
	int indent_item = (lvl + 2) * 4;

	if (!cs || !rad_hv) return;

	DEBUG("%*s%s {", indent_section, " ", cf_section_name1(cs));

	for (CONF_ITEM *ci = NULL; (ci = cf_item_next(cs, ci)); ) {
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
				WARN("Ignoring duplicate config section '%s'", key);
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
				WARN("Ignoring duplicate config item '%s'", key);
				continue;
			}

			(void)hv_store(rad_hv, key, strlen(key), newSVpvn(value, strlen(value)), 0);

			DEBUG("%*s%s = %s", indent_item, " ", key, value);
		}
	}

	DEBUG("%*s}", indent_section, " ");
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t		*xlat;

	xlat = xlat_register_module(NULL, mctx, mctx->inst->name, perl_xlat, NULL);
	xlat_func_args(xlat, perl_xlat_args);

	return 0;
}

static void perl_vp_to_svpvn_element(request_t *request, AV *av, fr_pair_t const *vp,
				     int *i, const char *hash_name, const char *list_name)
{

	SV *sv;

	switch (vp->vp_type) {
	case FR_TYPE_STRING:
		RDEBUG2("$%s{'%s'}[%i] = &%s.%s -> '%s'", hash_name, vp->da->name, *i,
		        list_name, vp->da->name, vp->vp_strvalue);
		sv = newSVpvn(vp->vp_strvalue, vp->vp_length);
		break;

	case FR_TYPE_OCTETS:
		RDEBUG2("$%s{'%s'}[%i] = &%s.%s -> 0x%pH", hash_name, vp->da->name, *i,
		        list_name, vp->da->name, &vp->data);
		sv = newSVpvn((char const *)vp->vp_octets, vp->vp_length);
		break;

	default:
	{
		char	buffer[1024];
		ssize_t	slen;

		slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(buffer, sizeof(buffer)), vp, T_BARE_WORD);
		if (slen < 0) return;

		RDEBUG2("$%s{'%s'}[%i] = &%s.%s -> '%pV'", hash_name, vp->da->name, *i,
		        list_name, vp->da->name, fr_box_strvalue_len(buffer, (size_t)slen));
		sv = newSVpvn(buffer, (size_t)slen);
	}
		break;
	}

	if (!sv) return;
	SvTAINT(sv);
	av_push(av, sv);
	(*i)++;
}

/*
 *  	get the vps and put them in perl hash
 *  	If one VP have multiple values it is added as array_ref
 *  	Example for this is Vendor-Specific.Cisco.AVPair that holds multiple values.
 *  	Which will be available as array_ref in $RAD_REQUEST{'Vendor-Specific.Cisco.AVPair'}
 */
static void perl_store_vps(UNUSED TALLOC_CTX *ctx, request_t *request, fr_pair_list_t *vps, HV *rad_hv,
			   const char *hash_name, const char *list_name)
{
	fr_pair_t *vp;
	fr_dcursor_t cursor;

	hv_undef(rad_hv);

	RINDENT();
	fr_pair_list_sort(vps, fr_pair_cmp_by_da);
	for (vp = fr_pair_dcursor_init(&cursor, vps);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		fr_pair_t *next;
		char const *name;
		name = vp->da->name;

		/*
		 *	We've sorted by type, then tag, so attributes of the
		 *	same type/tag should follow on from each other.
		 */
		if ((next = fr_dcursor_next_peek(&cursor)) && ATTRIBUTE_EQ(vp, next)) {
			int i = 0;
			AV *av;

			av = newAV();
			perl_vp_to_svpvn_element(request, av, vp, &i, hash_name, list_name);
			do {
				perl_vp_to_svpvn_element(request, av, next, &i, hash_name, list_name);
				fr_dcursor_next(&cursor);
			} while ((next = fr_dcursor_next_peek(&cursor)) && ATTRIBUTE_EQ(vp, next));
			(void)hv_store(rad_hv, name, strlen(name), newRV_noinc((SV *)av), 0);

			continue;
		}

		/*
		 *	It's a normal single valued attribute
		 */
		switch (vp->vp_type) {
		case FR_TYPE_STRING:
			RDEBUG2("$%s{'%s'} = &%s.%s -> '%pV'", hash_name, vp->da->name, list_name,
			       vp->da->name, &vp->data);
			(void)hv_store(rad_hv, name, strlen(name), newSVpvn(vp->vp_strvalue, vp->vp_length), 0);
			break;

		case FR_TYPE_OCTETS:
			RDEBUG2("$%s{'%s'} = &%s.%s -> %pV", hash_name, vp->da->name, list_name,
			       vp->da->name, &vp->data);
			(void)hv_store(rad_hv, name, strlen(name),
				       newSVpvn((char const *)vp->vp_octets, vp->vp_length), 0);
			break;

		default:
		{
			char buffer[1024];
			ssize_t slen;

			slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(buffer, sizeof(buffer)), vp, T_BARE_WORD);
			RDEBUG2("$%s{'%s'} = &%s.%s -> '%pV'", hash_name, vp->da->name,
			        list_name, vp->da->name, fr_box_strvalue_len(buffer, (size_t)slen));
			(void)hv_store(rad_hv, name, strlen(name),
				       newSVpvn(buffer, (size_t)(slen)), 0);
		}
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
static int pairadd_sv(TALLOC_CTX *ctx, request_t *request, fr_pair_list_t *vps, char *key, SV *sv,
		      const char *hash_name, const char *list_name)
{
	char		*val;
	fr_pair_t      *vp;
	STRLEN		len;
	fr_dict_attr_t const *da;

	if (!SvOK(sv)) return -1;

	val = SvPV(sv, len);

	da = fr_dict_attr_search_by_qualified_oid(NULL, request->dict, key, true, true);
	if (!da) {
		REDEBUG("Ignoring unknown attribute '%s'", key);
		return -1;
	}
	fr_assert(da != NULL);

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
	fail:
		talloc_free(vp);
		RPEDEBUG("Failed to create pair %s.%s = %s", list_name, key, val);
		return -1;
	}

	switch (vp->vp_type) {
	case FR_TYPE_STRING:
		fr_pair_value_bstrndup(vp, val, len, true);
		break;

	case FR_TYPE_OCTETS:
		fr_pair_value_memdup(vp, (uint8_t const *)val, len, true);
		break;

	default:
		if (fr_pair_value_from_str(vp, val, len, NULL, false) < 0) goto fail;
	}

	PAIR_VERIFY(vp);
	(void) fr_pair_append(vps, vp);

	RDEBUG2("&%s.%s = $%s{'%s'} -> '%s'", list_name, key, hash_name, key, val);
	return 0;
}

/*
 *     Gets the content from hashes
 */
static int get_hv_content(TALLOC_CTX *ctx, request_t *request, HV *my_hv, fr_pair_list_t *vps,
			  const char *hash_name, const char *list_name)
{
	SV		*res_sv, **av_sv;
	AV		*av;
	char		*key;
	I32		key_len, len, i, j;
	int		ret = 0;

	for (i = hv_iterinit(my_hv); i > 0; i--) {
		res_sv = hv_iternextsv(my_hv,&key,&key_len);
		if (SvROK(res_sv) && (SvTYPE(SvRV(res_sv)) == SVt_PVAV)) {
			av = (AV*)SvRV(res_sv);
			len = av_len(av);
			for (j = 0; j <= len; j++) {
				av_sv = av_fetch(av, j, 0);
				ret = pairadd_sv(ctx, request, vps, key, *av_sv, hash_name, list_name) + ret;
			}
		} else ret = pairadd_sv(ctx, request, vps, key, res_sv, hash_name, list_name) + ret;
	}

	if (!fr_pair_list_empty(vps)) PAIR_LIST_VERIFY(vps);

	return ret;
}

/*
 * 	Call the function_name inside the module
 * 	Store all vps in hashes %RAD_CONFIG %RAD_REPLY %RAD_REQUEST
 *
 */
static unlang_action_t do_perl(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request,
			       PerlInterpreter *interp, char const *function_name)
{

	rlm_perl_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_perl_t);
	fr_pair_list_t		vps;
	int			ret=0, count;
	STRLEN			n_a;

	HV			*rad_reply_hv;
	HV			*rad_config_hv;
	HV			*rad_request_hv;
	HV			*rad_state_hv;

	/*
	 *	Radius has told us to call this function, but none
	 *	is defined.
	 */
	if (!function_name) RETURN_MODULE_FAIL;

	{
		dTHXa(interp);
		PERL_SET_CONTEXT(interp);
	}

	{
		dSP;

		ENTER;
		SAVETMPS;

		rad_reply_hv = get_hv("RAD_REPLY", 1);
		rad_config_hv = get_hv("RAD_CONFIG", 1);
		rad_request_hv = get_hv("RAD_REQUEST", 1);
		rad_state_hv = get_hv("RAD_STATE", 1);

		perl_store_vps(request->request_ctx, request, &request->request_pairs, rad_request_hv, "RAD_REQUEST", "request");
		perl_store_vps(request->reply_ctx, request, &request->reply_pairs, rad_reply_hv, "RAD_REPLY", "reply");
		perl_store_vps(request->control_ctx, request, &request->control_pairs, rad_config_hv, "RAD_CONFIG", "control");
		perl_store_vps(request->session_state_ctx, request, &request->session_state_pairs, rad_state_hv, "RAD_STATE", "session-state");

		/*
		 * Store pointer to request structure globally so radiusd::xlat works
		 */
		rlm_perl_request = request;

		PUSHMARK(SP);
		/*
		 * This way %RAD_xx can be pushed onto stack as sub parameters.
		 * XPUSHs( newRV_noinc((SV *)rad_request_hv) );
		 * XPUSHs( newRV_noinc((SV *)rad_reply_hv) );
		 * XPUSHs( newRV_noinc((SV *)rad_config_hv) );
		 * PUTBACK;
		 */

		count = call_pv(function_name, G_SCALAR | G_EVAL | G_NOARGS);

		rlm_perl_request = NULL;

		SPAGAIN;

		if (SvTRUE(ERRSV)) {
			REDEBUG("perl_embed:: module = %s , func = %s exit status= %s\n",
			        inst->module, function_name, SvPV(ERRSV,n_a));
			(void)POPs;
			ret = RLM_MODULE_FAIL;
		} else if (count == 1) {
			ret = POPi;
			if (ret >= 100 || ret < 0) {
				ret = RLM_MODULE_FAIL;
			}
		}


		PUTBACK;
		FREETMPS;
		LEAVE;

		fr_pair_list_init(&vps);
		if ((get_hv_content(request->request_ctx, request, rad_request_hv, &vps, "RAD_REQUEST", "request")) == 0) {
			fr_pair_list_free(&request->request_pairs);
			fr_pair_list_append(&request->request_pairs, &vps);
			fr_pair_list_init(&vps);
		}

		if ((get_hv_content(request->reply_ctx, request, rad_reply_hv, &vps, "RAD_REPLY", "reply")) == 0) {
			fr_pair_list_free(&request->reply_pairs);
			fr_pair_list_append(&request->reply_pairs, &vps);
			fr_pair_list_init(&vps);
		}

		if ((get_hv_content(request->control_ctx, request, rad_config_hv, &vps, "RAD_CONFIG", "control")) == 0) {
			fr_pair_list_free(&request->control_pairs);
			fr_pair_list_append(&request->control_pairs, &vps);
			fr_pair_list_init(&vps);
		}

		if ((get_hv_content(request->session_state_ctx, request, rad_state_hv, &vps, "RAD_STATE", "session-state")) == 0) {
			fr_pair_list_free(&request->session_state_pairs);
			fr_pair_list_append(&request->session_state_pairs, &vps);
			fr_pair_list_init(&vps);
		}
	}
	RETURN_MODULE_RCODE(ret);
}

#define RLM_PERL_FUNC(_x) \
static unlang_action_t CC_HINT(nonnull) mod_##_x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) \
{ \
	rlm_perl_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_perl_t); \
	return do_perl(p_result, mctx, request, \
		       ((rlm_perl_thread_t *)talloc_get_type_abort(mctx->thread, rlm_perl_thread_t))->perl, \
		       inst->func_##_x); \
}

RLM_PERL_FUNC(authorize)
RLM_PERL_FUNC(authenticate)
RLM_PERL_FUNC(post_auth)
RLM_PERL_FUNC(preacct)

/*
 *	Write accounting information to this modules database.
 */
static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_perl_t	 	*inst = talloc_get_type_abort(mctx->inst->data, rlm_perl_t);
	fr_pair_t		*pair;
	int 			acct_status_type = 0;
	char const		*func;

	pair = fr_pair_find_by_da(&request->request_pairs, NULL, attr_acct_status_type);
	if (pair != NULL) {
		acct_status_type = pair->vp_uint32;
	} else {
		REDEBUG("Invalid Accounting Packet");
		RETURN_MODULE_INVALID;
	}

	switch (acct_status_type) {
	case FR_STATUS_START:
		if (inst->func_start_accounting) {
			func = inst->func_start_accounting;
		} else {
			func = inst->func_accounting;
		}
		break;

	case FR_STATUS_STOP:
		if (inst->func_stop_accounting) {
			func = inst->func_stop_accounting;
		} else {
			func = inst->func_accounting;
		}
		break;

	default:
		func = inst->func_accounting;
		break;
	}

	return do_perl(p_result, mctx, request,
		       ((rlm_perl_thread_t *)talloc_get_type_abort(mctx->thread, rlm_perl_thread_t))->perl, func);
}

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(shadow)
static void rlm_perl_interp_free(PerlInterpreter *perl)
{
	void	**handles;

	{
		dTHXa(perl);
		PERL_SET_CONTEXT(perl);
	}

	handles = rlm_perl_get_handles(aTHX);
	if (handles) rlm_perl_close_handles(handles);

	PL_perl_destruct_level = 2;

	PL_origenviron = environ;

	/*
	 * FIXME: This shouldn't happen
	 *
	 */
	while (PL_scopestack_ix > 1) LEAVE;

	perl_destruct(perl);
	perl_free(perl);
}
DIAG_ON(shadow)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_perl_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_perl_t);
	rlm_perl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_perl_thread_t);
	PerlInterpreter		*interp;
	UV			clone_flags = 0;

	PERL_SET_CONTEXT(inst->perl);

	interp = perl_clone(inst->perl, clone_flags);
	{
		dTHXa(interp);			/* Sets the current thread's interpreter */
	}
#  if PERL_REVISION >= 5 && PERL_VERSION <8
	call_pv("CLONE", 0);
#  endif
	ptr_table_free(PL_ptr_table);
	PL_ptr_table = NULL;

	PERL_SET_CONTEXT(aTHX);
	rlm_perl_clear_handles(aTHX);

	t->perl = interp;			/* Store perl interp for easy freeing later */

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_perl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_perl_thread_t);

	rlm_perl_interp_free(t->perl);

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
 *	parse a module and give it a chance to live
 *
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_perl_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_perl_t);
	CONF_SECTION	*conf = mctx->inst->conf;
	AV		*end_AV;

	char const	**embed_c;	/* Stupid Perl and lack of const consistency */
	char		**embed;
	int		ret = 0, argc = 0;
	char		arg[] = "0";

	CONF_SECTION	*cs;

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
	 *	Allocate a new perl interpreter to do the parsing
	 */
	if ((inst->perl = perl_alloc()) == NULL) {
		ERROR("No memory for allocating new perl interpretor!");
		return -1;
	}
	perl_construct(inst->perl);	/* ...and initialise it */

	PL_perl_destruct_level = 2;
	{
		dTHXa(inst->perl);
	}
	PERL_SET_CONTEXT(inst->perl);

#if PERL_REVISION >= 5 && PERL_VERSION >=8
	PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

	ret = perl_parse(inst->perl, xs_init, argc, embed, NULL);

	end_AV = PL_endav;
	PL_endav = (AV *)NULL;

	if (ret) {
		ERROR("Perl_parse failed: %s not found or has syntax errors", inst->module);
		return -1;
	}

	/* parse perl configuration sub-section */
	cs = cf_section_find(conf, "config", NULL);
	if (cs) {
		inst->rad_perlconf_hv = get_hv("RAD_PERLCONF", 1);
		perl_parse_config(cs, 0, inst->rad_perlconf_hv);
	}

	inst->perl_parsed = true;
	perl_run(inst->perl);

	PL_endav = end_AV;

	return 0;
}

/*
 * Detach a instance give a chance to a module to make some internal setup ...
 */
DIAG_OFF(nested-externs)
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_perl_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_perl_t);
	int 		ret = 0, count = 0;


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
				ret = POPi;
				if (ret >= 100 || ret < 0) {
					ret = RLM_MODULE_FAIL;
				}
			}
			PUTBACK;
			FREETMPS;
			LEAVE;
		}
	}

	rlm_perl_interp_free(inst->perl);

	return ret;
}
DIAG_ON(nested-externs)

static int mod_load(void)
{
	char const	**embed_c;	/* Stupid Perl and lack of const consistency */
	char		**embed;
	char		**envp = NULL;
	int		argc = 0;

#define LOAD_INFO(_fmt, ...) fr_log(LOG_DST, L_INFO, __FILE__, __LINE__, "rlm_perl - " _fmt,  ## __VA_ARGS__)
#define LOAD_WARN(_fmt, ...) fr_log_perror(LOG_DST, L_WARN, __FILE__, __LINE__, \
					   &(fr_log_perror_format_t){ \
					   	.first_prefix = "rlm_perl - ", \
					   	.subsq_prefix = "rlm_perl - ", \
					   }, \
					   _fmt,  ## __VA_ARGS__)

	LOAD_INFO("Perl version: %s", PERL_API_VERSION_STRING);
	dependency_version_number_add(NULL, "perl", PERL_API_VERSION_STRING);

	/*
	 *	Load perl using RTLD_GLOBAL and dlopen.
	 *	This fixes issues where Perl C extensions
	 *	can't find the symbols they need.
	 */
	perl_dlhandle = dl_open_by_sym("perl_construct", RTLD_NOW | RTLD_GLOBAL);
	if (!perl_dlhandle) LOAD_WARN("Failed loading libperl symbols into global symbol table");

	/*
	 *	Setup the argument array we pass to the perl interpreter
	 */
	MEM(embed_c = talloc_zero_array(NULL, char const *, 1));
	memcpy(&embed, &embed_c, sizeof(embed));
	embed_c[0] = NULL;
	argc = 1;

	PERL_SYS_INIT3(&argc, &embed, &envp);

	talloc_free(embed_c);

	return 0;
}

static void mod_unload(void)
{
	if (perl_dlhandle) dlclose(perl_dlhandle);
	PERL_SYS_TERM();
}


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_perl;
module_rlm_t rlm_perl = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "perl",
		.type			= MODULE_TYPE_THREAD_SAFE,
		.inst_size		= sizeof(rlm_perl_t),

		.config			= module_config,
		.onload			= mod_load,
		.unload			= mod_unload,
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate,
		.detach			= mod_detach,

		.thread_inst_size	= sizeof(rlm_perl_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.method_names = (module_method_name_t[]){
		/*
		 *	Hack to support old configurations
		 */
		{ .name1 = "authorize",		.name2 = CF_IDENT_ANY,		.method = mod_authorize		},

		{ .name1 = "recv",		.name2 = "accounting-request",	.method = mod_preacct		},
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize		},
		{ .name1 = "accounting",	.name2 = CF_IDENT_ANY,		.method = mod_accounting	},
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate	},
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_post_auth		},
		MODULE_NAME_TERMINATOR
	}
};
