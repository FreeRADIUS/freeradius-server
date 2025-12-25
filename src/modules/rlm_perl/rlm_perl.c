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
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/radius/radius.h>

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(compound-token-split-by-macro) /* Perl does horrible things with macros */
DIAG_OFF(unreachable-code-return)
DIAG_OFF(unreachable-code-break)
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

typedef struct {
	char const	*function_name;	//!< Name of the function being called
	char		*name1;		//!< Section name1 where this is called
	char		*name2;		//!< Section name2 where this is called
	fr_rb_node_t	node;		//!< Node in tree of function calls.
} perl_func_def_t;

typedef struct {
	perl_func_def_t	*func;
} perl_call_env_t;

typedef struct {
	pthread_mutex_t	mutex;
} rlm_perl_mutable_t;

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

	fr_rb_tree_t	funcs;			//!< Tree of function calls found by call_env parser.
	bool		funcs_init;		//!< Has the tree been initialised.
	char const	*func_detach;		//!< Function to run when mod_detach is run.
	char const	*perl_flags;
	PerlInterpreter	*perl;
	bool		perl_parsed;
	HV		*rad_perlconf_hv;	//!< holds "config" items (perl %RAD_PERLCONF hash).
	rlm_perl_mutable_t	*mutable;

} rlm_perl_t;

typedef struct {
	PerlInterpreter		*perl;	//!< Thread specific perl interpreter.
} rlm_perl_thread_t;

/*
 *	C structure associated with tied hashes and arrays
 */
typedef struct fr_perl_pair_s fr_perl_pair_t;
struct fr_perl_pair_s {
	fr_dict_attr_t const	*da;		//!< Dictionary attribute associated with hash / array.
	fr_pair_t		*vp;		//!< Real pair associated with the hash / array, if it exists.
	unsigned int		idx;		//!< Instance number.
	fr_perl_pair_t		*parent;	//!< Parent attribute data.
	fr_dcursor_t		cursor;		//!< Cursor used for iterating over the keys of a tied hash.
};

/*
 *	Dummy Magic Virtual Table used to ensure we retrieve the correct magic data
 */
static MGVTBL rlm_perl_vtbl = { 0, 0, 0, 0, 0, 0, 0, 0 };

static void *perl_dlhandle;		//!< To allow us to load perl's symbols into the global symbol table.

/*
 *	A mapping of configuration file names to internal variables.
 */
static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("filename", CONF_FLAG_FILE_READABLE | CONF_FLAG_REQUIRED, rlm_perl_t, module) },

	{ FR_CONF_OFFSET("func_detach", rlm_perl_t, func_detach), .data = NULL, .dflt = "detach", .quote = T_INVALID },

	{ FR_CONF_OFFSET("perl_flags", rlm_perl_t, perl_flags) },

	CONF_PARSER_TERMINATOR
};

/** How to compare two Perl function calls
 *
 */
static int8_t perl_func_def_cmp(void const *one, void const *two)
{
	perl_func_def_t const *a = one, *b = two;
	int ret;

	ret = strcmp(a->name1, b->name1);
	if (ret != 0) return CMP(ret, 0);
	if (!a->name2 && !b->name2) return 0;
	if (!a->name2 || !b->name2) return a->name2 ? 1 : -1;
	ret = strcmp(a->name2, b->name2);
	return CMP(ret, 0);
}

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
 *	Now users can call freeradius::log(level,msg) which is the same
 *	as calling fr_log from C code.
 */
static XS(XS_freeradius_log)
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
 *	This is a wrapper for xlat_aeval
 *	Now users are able to get data that is accessible only via xlat
 *	e.g. %request.client(...)
 *	Call syntax is freeradius::xlat(string), string will be handled as
 *	a double-quoted string in the configuration files.
 */
static XS(XS_freeradius_xlat)
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

/** Helper function for turning hash keys into dictionary attributes
 *
 */
static inline fr_dict_attr_t const *perl_attr_lookup(fr_perl_pair_t *pair_data, char const *attr)
{
	fr_dict_attr_t const *da = fr_dict_attr_by_name(NULL, pair_data->da, attr);

	/*
	 *	Allow fallback to internal attributes if the parent is a group or dictionary root.
	 */
	if (!da && (fr_type_is_group(pair_data->da->type) || pair_data->da->flags.is_root)) {
		da = fr_dict_attr_by_name(NULL, fr_dict_root(fr_dict_internal()), attr);
	}

	if (!da) croak("Unknown or invalid attribute name \"%s\"", attr);

	return da;
}

/** Convenience macro for fetching C data associated with tied hash / array and validating stack size
 *
 */
#define GET_PAIR_MAGIC(count) MAGIC *mg = mg_findext(ST(0), PERL_MAGIC_ext, &rlm_perl_vtbl); \
	fr_perl_pair_t *pair_data; \
	if (unlikely(items < count)) { \
		croak("Expected %d stack entries, got %d", count, items); \
		XSRETURN_UNDEF; \
	} \
	if (!mg) { \
		croak("Failed to find Perl magic value"); \
		XSRETURN_UNDEF; \
	} \
	pair_data = (fr_perl_pair_t *)mg->mg_ptr;

/** Functions to implement subroutines required for a tied hash
 *
 * All structural components of attributes are represented by tied hashes
 */

/** Called when fetching hash values
 *
 * The stack contains
 *  - the tied SV
 *  - the hash key being requested
 *
 * When a numeric key is requested, we treat that as in instruction to find
 * a specific instance of the key of the parent.
 *
 * Whilst this is a bit odd, the alternative would be for every attribute to
 * be returned as an array so you would end up with crazy syntax like
 *   p{'request'}{'Vendor-Specific'}[0]{'Cisco'}[0]{'AVPair}[0]
 */
static XS(XS_pairlist_FETCH)
{
	dXSARGS;
	char			*attr;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp = NULL;
	STRLEN			len, i = 0;
	int			idx = 0;

	GET_PAIR_MAGIC(2)

	attr = (char *) SvPV(ST(1), len);

	/*
	 *	Check if our key is entirely numeric.
	 */
	while (i < len) {
		if (!isdigit(attr[i])) break;
		i++;
	}
	if (i == len) {
		idx = SvIV(ST(1));
		da = pair_data->da;
		if (pair_data->parent->vp) vp = fr_pair_find_by_da_idx(&pair_data->parent->vp->vp_group, da, idx);
	} else {
		da = perl_attr_lookup(pair_data, attr);
		if (!da) XSRETURN_UNDEF;
		if (pair_data->vp) vp = fr_pair_find_by_da(&pair_data->vp->vp_group, NULL, da);
	}

	switch(da->type) {
	/*
	 *	Leaf attributes are returned as an array with magic
	 */
	case FR_TYPE_LEAF:
	{
		AV		*pair_av;
		SV		*pair_tie;
		HV		*frpair_stash;
		fr_perl_pair_t	child_pair_data;

		frpair_stash = gv_stashpv("freeradiuspairs", GV_ADD);
		pair_av = newAV();
		pair_tie = newRV_noinc((SV *)newAV());
		sv_bless(pair_tie, frpair_stash);
		sv_magic(MUTABLE_SV(pair_av), MUTABLE_SV((GV *)pair_tie), PERL_MAGIC_tied, NULL, 0);
		SvREFCNT_dec(pair_tie);

		child_pair_data = (fr_perl_pair_t) {
			.vp = vp,
			.da = da,
			.parent = pair_data
		};
		sv_magicext((SV *)pair_tie, 0, PERL_MAGIC_ext, &rlm_perl_vtbl, (char *)&child_pair_data, sizeof(child_pair_data));
		ST(0) = sv_2mortal(newRV((SV *)pair_av));
	}
		break;

	/*
	 *	Structural attributes are returned as a hash with magic
	 */
	case FR_TYPE_STRUCTURAL:
	{
		HV		*struct_hv;
		SV		*struct_tie;
		HV		*frpair_stash;
		fr_perl_pair_t	child_pair_data;

		frpair_stash = gv_stashpv("freeradiuspairlist", GV_ADD);
		struct_hv = newHV();
		struct_tie = newRV_noinc((SV *)newHV());
		sv_bless(struct_tie, frpair_stash);
		hv_magic(struct_hv, (GV *)struct_tie, PERL_MAGIC_tied);
		SvREFCNT_dec(struct_tie);

		child_pair_data = (fr_perl_pair_t) {
			.vp = vp,
			.da = da,
			.parent = pair_data,
			.idx = idx
		};
		sv_magicext((SV *)struct_tie, 0, PERL_MAGIC_ext, &rlm_perl_vtbl, (char *)&child_pair_data, sizeof(child_pair_data));
		ST(0) = sv_2mortal(newRV((SV *)struct_hv));
	}
		break;

	default:
		fr_assert(0);
	}

	XSRETURN(1);
}

/** Called when a hash value is set / updated
 *
 * This is not allowed - only leaf node arrays can have values set
 */
static XS(XS_pairlist_STORE)
{
	dXSARGS;
	char			*attr;
	fr_dict_attr_t const	*da;

	GET_PAIR_MAGIC(3)

	attr = (char *) SvPV(ST(1), PL_na);
	da = perl_attr_lookup(pair_data, attr);
	if (!da) XSRETURN(0);

	if (fr_type_is_leaf(da->type)) {
		croak("Cannot set value of array of \"%s\" values.  Use array index to set a specific instance.", da->name);
	} else {
		croak("Cannot set values of structural object %s", da->name);
	}
	XSRETURN(0);
}

/** Called to test the existence of a key in a tied hash
 *
 * The stack contains
 *  - the tied SV
 *  - the key to check for
 */
static XS(XS_pairlist_EXISTS)
{
	dXSARGS;
	char			*attr;
	fr_dict_attr_t const	*da;
	STRLEN			len, i = 0;

	GET_PAIR_MAGIC(2)

	attr = (char *) SvPV(ST(1), len);
	while (i < len) {
		if (!isdigit(attr[i])) break;
		i++;
	}

	/*
	 *	Numeric key - check for an instance of the attribute
	 */
	if (i == len) {
		unsigned int	idx = SvIV(ST(1));
		if (pair_data->parent->vp) {
			if (fr_pair_find_by_da_idx(&pair_data->parent->vp->vp_group, pair_data->da, idx)) XSRETURN_YES;
		}
		XSRETURN_NO;
	}

	if (!pair_data->vp) XSRETURN_NO;

	da = perl_attr_lookup(pair_data, attr);
	if (!da) XSRETURN_NO;

	if(fr_pair_find_by_da(&pair_data->vp->vp_group, NULL, da)) XSRETURN_YES;

	XSRETURN_NO;
}

/** Called when functions like keys() want the first key in a tied hash
 *
 * The stack contains just the tied SV
 */
static XS(XS_pairlist_FIRSTKEY)
{
	dXSARGS;
	fr_pair_t	*vp;

	GET_PAIR_MAGIC(1)
	if (!pair_data->vp) XSRETURN_EMPTY;

	vp = fr_pair_dcursor_init(&pair_data->cursor, &pair_data->vp->vp_group);
	ST(0) = sv_2mortal(newSVpv(vp->da->name, vp->da->name_len));
	XSRETURN(1);
}

/** Called by functions like keys() which iterate over the keys in a tied hash
 *
 * The stack contains
 *  - the tied SV
 *  - the previous key
 */
static XS(XS_pairlist_NEXTKEY)
{
	dXSARGS;
	fr_pair_t	*vp;

	GET_PAIR_MAGIC(2)
	if (!pair_data->vp) XSRETURN_EMPTY;

	vp = fr_dcursor_next(&pair_data->cursor);
	if (!vp) XSRETURN_EMPTY;

	ST(0) = sv_2mortal(newSVpv(vp->da->name, vp->da->name_len));
	XSRETURN(1);
}

/** Called to delete a key from a tied hash
 *
 * The stack contains
 *  - the tied SV
 *  - the key being deleted
 */
static XS(XS_pairlist_DELETE)
{
	dXSARGS;
	char			*attr;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;

	GET_PAIR_MAGIC(2)
	attr = SvPV(ST(1), PL_na);

	da = perl_attr_lookup(pair_data, attr);
	if (!da) XSRETURN(0);
	if (!pair_data->vp) XSRETURN(0);

	vp = fr_pair_find_by_da(&pair_data->vp->vp_group, NULL, da);

	if (vp) fr_pair_delete(&pair_data->vp->vp_group, vp);

	XSRETURN(0);
}

/** Functions to implement subroutines required for a tied array
 *
 * Leaf attributes are represented by tied arrays to allow multiple instances.
 */

static int perl_value_marshal(fr_pair_t *vp, SV **value)
{
	switch(vp->vp_type) {
	case FR_TYPE_STRING:
		*value = sv_2mortal(newSVpvn(vp->vp_strvalue, vp->vp_length));
		break;

	case FR_TYPE_OCTETS:
		*value = sv_2mortal(newSVpvn((char const *)vp->vp_octets, vp->vp_length));
		break;

#define PERLUINT(_size)	case FR_TYPE_UINT ## _size: \
		*value = sv_2mortal(newSVuv(vp->vp_uint ## _size)); \
		break;
	PERLUINT(8)
	PERLUINT(16)
	PERLUINT(32)
	PERLUINT(64)

#define PERLINT(_size)	case FR_TYPE_INT ## _size: \
		*value = sv_2mortal(newSViv(vp->vp_int ## _size)); \
		break;
	PERLINT(8)
	PERLINT(16)
	PERLINT(32)
	PERLINT(64)


	case FR_TYPE_SIZE:
		*value = sv_2mortal(newSVuv(vp->vp_size));
		break;

	case FR_TYPE_BOOL:
		*value = sv_2mortal(newSVuv(vp->vp_bool));
		break;

	case FR_TYPE_FLOAT32:
		*value = sv_2mortal(newSVnv(vp->vp_float32));
		break;

	case FR_TYPE_FLOAT64:
		*value = sv_2mortal(newSVnv(vp->vp_float64));
		break;

	case FR_TYPE_ETHERNET:
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
	case FR_TYPE_IPV4_PREFIX:
	case FR_TYPE_IPV6_PREFIX:
	case FR_TYPE_COMBO_IP_ADDR:
	case FR_TYPE_COMBO_IP_PREFIX:
	case FR_TYPE_IFID:
	case FR_TYPE_DATE:
	case FR_TYPE_TIME_DELTA:
	case FR_TYPE_ATTR:
	{
		char	buff[128];
		ssize_t	slen;

		slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(buff, sizeof(buff)), vp, T_BARE_WORD);
		if (slen < 0) {
			croak("Cannot convert %s to Perl type, insufficient buffer space",
				fr_type_to_str(vp->vp_type));
			return -1;
		}

		*value = sv_2mortal(newSVpv(buff, slen));
	}
		break;

	/* Only leaf nodes should be able to call this */
	case FR_TYPE_NON_LEAF:
		croak("Cannot convert %s to Perl type", fr_type_to_str(vp->vp_type));
		return -1;
	}

	return 0;
}

/** Called to retrieve the value of an array entry
 *
 * In our case, retrieve the value of a specific instance of a leaf attribute
 *
 * The stack contains
 *  - the tied SV
 *  - the index to retrieve
 *
 * The magic data will hold the DA of the attribute.
 */
static XS(XS_pairs_FETCH)
{
	dXSARGS;
	unsigned int		idx = SvUV(ST(1));
	fr_pair_t		*vp = NULL;
	fr_perl_pair_t		*parent;

	GET_PAIR_MAGIC(2)

	parent = pair_data->parent;
	if (!parent->vp) XSRETURN_UNDEF;

	if (idx == 0) vp = pair_data->vp;
	if (!vp) vp = fr_pair_find_by_da_idx(&parent->vp->vp_group, pair_data->da, idx);
	if (!vp) XSRETURN_UNDEF;

	if (perl_value_marshal(vp, &ST(0)) < 0) XSRETURN(0);
	XSRETURN(1);
}

/** Build parent structural pairs needed when a leaf node is set
 *
 */
static int fr_perl_pair_parent_build(fr_perl_pair_t *pair_data)
{
	fr_perl_pair_t	*parent = pair_data->parent;
	if (!parent->vp) {
		/*
		 *	When building parent with idx > 0, it's "parent" is the
		 *	first instance of the attribute - so if that's not there
		 *	we don't have any.
		 */
		if (pair_data->idx > 0) {
		none_exist:
			croak("Attempt to set instance %d when none exist", pair_data->idx);
			return -1;
		}
		if (fr_perl_pair_parent_build(parent) < 0) return -1;
	}

	if (pair_data->idx > 0) {
		unsigned int count;

		if (!parent->parent->vp) goto none_exist;
		count = fr_pair_count_by_da(&parent->parent->vp->vp_group, pair_data->da);
		if (count < pair_data->idx) {
			croak("Attempt to set instance %d when only %d exist", pair_data->idx, count);
			return -1;
		}
		parent = parent->parent;
	}

	if (fr_pair_append_by_da(parent->vp, &pair_data->vp, &parent->vp->vp_group, pair_data->da) < 0) return -1;
	return 0;
}

/** Convert a Perl SV to a pair value.
 *
 */
static int perl_value_unmarshal(fr_pair_t *vp, SV *value)
{
	fr_value_box_t	vb;

	switch (SvTYPE(value)) {
	case SVt_IV:
		fr_value_box_init(&vb, FR_TYPE_INT64, NULL, true);
		vb.vb_int64 = SvIV(value);
		break;

	case SVt_NV:
		fr_value_box_init(&vb, FR_TYPE_FLOAT64, NULL, true);
		vb.vb_float64 = SvNV(value);
		break;

	case SVt_PV:
	case SVt_PVLV:
	{
		char	*val;
		STRLEN	len;
		fr_value_box_init(&vb, FR_TYPE_STRING, NULL, true);
		val = SvPV(value, len);
		fr_value_box_bstrndup_shallow(&vb, NULL, val, len, true);
	}
		break;

	default:
		croak("Unsupported Perl data type");
		return -1;
	}

	fr_pair_value_clear(vp);
	if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, &vb) < 0) {
		croak("Failed casting Perl value to %s", fr_type_to_str(vp->vp_type));
		return -1;
	}

	return 0;
}

/** Called when an array value is set / updated
 *
 * The stack contains
 *  - the tied SV
 *  - the index being updated
 *  - the value being assigned
 */
static XS(XS_pairs_STORE)
{
	dXSARGS;
	unsigned int		idx = SvUV(ST(1));
	fr_pair_t		*vp;
	fr_perl_pair_t		*parent;

	GET_PAIR_MAGIC(3)

	fr_assert(fr_type_is_leaf(pair_data->da->type));

	parent = pair_data->parent;

	if (!parent->vp) {
		/*
		 *	Trying to set something other than the first instance when
		 *	the parent doesn't exist is invalid.
		 */
		if (idx > 0) {
			croak("Attempting to set instance %d when none exist", idx);
			XSRETURN(0);
		}

		if(fr_perl_pair_parent_build(parent) < 0) XSRETURN(0);
	}

	vp = fr_pair_find_by_da_idx(&parent->vp->vp_group, pair_data->da, idx);
	if (!vp) {
		if (idx > 0) {
			unsigned int count = fr_pair_count_by_da(&pair_data->parent->vp->vp_group, pair_data->da);
			if (count < idx) {
				croak("Attempt to set instance %d when only %d exist", idx, count);
				XSRETURN(0);
			}
		}
		fr_pair_append_by_da(parent->vp, &vp, &parent->vp->vp_group, pair_data->da);
	}

	perl_value_unmarshal(vp, ST(2));

	XSRETURN(0);
}

/** Called when an array entry's existence is tested
 *
 */
static XS(XS_pairs_EXISTS)
{
	dXSARGS;
	unsigned int	idx = SvUV(ST(1));
	fr_pair_t	*vp;
	fr_perl_pair_t	*parent;

	GET_PAIR_MAGIC(2)

	parent = pair_data->parent;
	if (!parent->vp) XSRETURN_NO;

	vp = fr_pair_find_by_da_idx(&parent->vp->vp_group, pair_data->da, idx);
	if (vp) XSRETURN_YES;
	XSRETURN_NO;
}

/** Called when an array entry is deleted
 *
 */
static XS(XS_pairs_DELETE)
{
	dXSARGS;
	unsigned int	idx = SvUV(ST(1));
	fr_pair_t	*vp;
	fr_perl_pair_t	*parent;

	GET_PAIR_MAGIC(2)

	parent = pair_data->parent;
	if (!parent->vp) XSRETURN(0);

	vp = fr_pair_find_by_da_idx(&parent->vp->vp_group, pair_data->da, idx);
	if (vp) fr_pair_delete(&parent->vp->vp_group, vp);
	XSRETURN(0);
}

/** Called when Perl wants the size of a tied array
 *
 * The stack contains just the tied SV
 */
static XS(XS_pairs_FETCHSIZE)
{
	dXSARGS;
	GET_PAIR_MAGIC(1)

	if (!pair_data->parent->vp) XSRETURN_UV(0);
	XSRETURN_UV(fr_pair_count_by_da(&pair_data->parent->vp->vp_group, pair_data->da));
}

/** Called when attempting to set the size of an array
 *
 * We don't allow expanding the array this way, but will allow deleting pairs
 *
 * The stack contains
 *  - the tied SV
 *  - the requested size of the array
 */
static XS(XS_pairs_STORESIZE)
{
	dXSARGS;
	unsigned int	count, req_size = SvUV(ST(1));
	fr_pair_t	*vp, *prev;
	fr_perl_pair_t	*parent;
	GET_PAIR_MAGIC(2)

	parent = pair_data->parent;
	if (!parent->vp) {
		if (req_size > 0) {
			croak("Unable to set attribute instance count");
		}
		XSRETURN(0);
	}

	count = fr_pair_count_by_da(&parent->vp->vp_group, pair_data->da);
	if (req_size > count) {
		croak("Increasing attribute instance count not supported");
		XSRETURN(0);
	}

	/*
	 *	As req_size is 1 based and the attribute instance count is
	 *	0 based, searching for instance `req_size` will give the first
	 *	pair to delete.
	 */
	vp = fr_pair_find_by_da_idx(&parent->vp->vp_group, pair_data->da, req_size);
	while (vp) {
		prev = fr_pair_list_prev(&parent->vp->vp_group, vp);
		fr_pair_delete(&parent->vp->vp_group, vp);
		vp = fr_pair_find_by_da(&parent->vp->vp_group, prev, pair_data->da);
	}
	XSRETURN(0);
}

/** Called when values are pushed on a tied array
 *
 * The stack contains
 *  - the tied SV
 *  - one or more values being pushed onto the array
 */
static XS(XS_pairs_PUSH)
{
	dXSARGS;
	int		i = 1;
	fr_pair_t	*vp;
	fr_perl_pair_t	*parent;

	GET_PAIR_MAGIC(2)

	fr_assert(fr_type_is_leaf(pair_data->da->type));

	parent = pair_data->parent;
	if (!parent->vp) {
		if (fr_perl_pair_parent_build(parent) < 0) XSRETURN(0);
	}

	while (i < items) {
		fr_pair_append_by_da(parent->vp, &vp, &parent->vp->vp_group, pair_data->da);
		if (perl_value_unmarshal(vp, ST(i++)) < 0) break;
	}

	XSRETURN(0);
}

/** Called when values are popped off a tied array
 *
 * The stack contains just the tied SV
 */
static XS(XS_pairs_POP)
{
	dXSARGS;
	fr_pair_t	*vp;
	fr_perl_pair_t	*parent;

	GET_PAIR_MAGIC(1)

	fr_assert(fr_type_is_leaf(pair_data->da->type));

	parent = pair_data->parent;
	if (!parent->vp) XSRETURN(0);

	vp = fr_pair_find_last_by_da(&parent->vp->vp_group, NULL, pair_data->da);
	if (!vp) XSRETURN(0);

	if (perl_value_marshal(vp, &ST(0)) < 0) XSRETURN(0);

	fr_pair_remove(&parent->vp->vp_group, vp);
	XSRETURN(1);
}

/** Called when values are "shifted" off a tied array
 *
 * The stack contains just the tied SV
 */
static XS(XS_pairs_SHIFT)
{
	dXSARGS;
	fr_pair_t	*vp;
	fr_perl_pair_t	*parent;

	GET_PAIR_MAGIC(1)

	fr_assert(fr_type_is_leaf(pair_data->da->type));

	parent = pair_data->parent;
	if (!parent->vp) XSRETURN(0);

	vp = fr_pair_find_by_da(&parent->vp->vp_group, NULL, pair_data->da);
	if (!vp) XSRETURN(0);

	if (perl_value_marshal(vp, &ST(0)) < 0) XSRETURN(0);

	fr_pair_remove(&parent->vp->vp_group, vp);
	XSRETURN(1);
}

/** Called when values are "unshifted" onto a tied array
 *
 * The stack contains
 *  - the tied SV
 *  - one or more values being shifted onto the array
 */
static XS(XS_pairs_UNSHIFT)
{
	dXSARGS;
	int		i = 1;
	fr_pair_t	*vp;
	fr_perl_pair_t	*parent;

	GET_PAIR_MAGIC(2)

	fr_assert(fr_type_is_leaf(pair_data->da->type));

	parent = pair_data->parent;
	if (!parent->vp) {
		if (fr_perl_pair_parent_build(parent) < 0) XSRETURN(0);
	}

	while (i < items) {
		if (unlikely(fr_pair_prepend_by_da(parent->vp, &vp, &parent->vp->vp_group, pair_data->da) < 0)) {
			croak("Failed adding attribute %s", pair_data->da->name);
			break;
		}
		if (perl_value_unmarshal(vp, ST(i++)) < 0) break;
	}

	XSRETURN(0);
}

static void xs_init(pTHX)
{
	char const *file = __FILE__;

	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);

	newXS("freeradius::log",XS_freeradius_log, "rlm_perl");
	newXS("freeradius::xlat",XS_freeradius_xlat, "rlm_perl");

	/*
	 *	The freeradiuspairlist package implements functions required
	 *	for a tied hash handling structural attributes.
	 */
	newXS("freeradiuspairlist::FETCH", XS_pairlist_FETCH, "rlm_perl");
	newXS("freeradiuspairlist::STORE", XS_pairlist_STORE, "rlm_perl");
	newXS("freeradiuspairlist::EXISTS", XS_pairlist_EXISTS, "rlm_perl");
	newXS("freeradiuspairlist::FIRSTKEY", XS_pairlist_FIRSTKEY, "rlm_perl");
	newXS("freeradiuspairlist::NEXTKEY", XS_pairlist_NEXTKEY, "rlm_perl");
	newXS("freeradiuspairlist::DELETE", XS_pairlist_DELETE, "rlm_perl");

	/*
	 *	The freeradiuspairs package implements functions required
	 *	for a tied array handling leaf attributes.
	 */
	newXS("freeradiuspairs::FETCH", XS_pairs_FETCH, "rlm_perl");
	newXS("freeradiuspairs::STORE", XS_pairs_STORE, "rlm_perl");
	newXS("freeradiuspairs::EXISTS", XS_pairs_EXISTS, "rlm_perl");
	newXS("freeradiuspairs::DELETE", XS_pairs_DELETE, "rlm_perl");
	newXS("freeradiuspairs::FETCHSIZE", XS_pairs_FETCHSIZE, "rlm_perl");
	newXS("freeradiuspairs::STORESIZE", XS_pairs_STORESIZE, "rlm_perl");
	newXS("freeradiuspairs::PUSH", XS_pairs_PUSH, "rlm_perl");
	newXS("freeradiuspairs::POP", XS_pairs_POP, "rlm_perl");
	newXS("freeradiuspairs::SHIFT", XS_pairs_SHIFT, "rlm_perl");
	newXS("freeradiuspairs::UNSHIFT", XS_pairs_UNSHIFT, "rlm_perl");
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

	while ((vb = fr_value_box_list_next(head, vb))) {
		switch (vb->type) {
		case FR_TYPE_STRING:
			sv = newSVpvn(vb->vb_strvalue, vb->vb_length);
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

			slen = fr_value_box_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), vb, NULL);
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
			RDEBUG3("Reference returned");
			if (perl_sv_to_vblist(ctx, list, request, SvRV(sv)) < 0) return -1;
			break;
		}
		RDEBUG3("Integer returned");
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_INT32, NULL));
		vb->vb_int32 = SvIV(sv);
		break;

	case SVt_NV:
	/*	Float */
		RDEBUG3("Float returned");
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_FLOAT64, NULL));
		vb->vb_float64 = SvNV(sv);
		break;

	case SVt_PV:
	/*	String */
		RDEBUG3("String returned");
		tmp = SvPVutf8(sv, len);
		MEM(vb = fr_value_box_alloc_null(ctx));
		if (fr_value_box_bstrndup(vb, vb, NULL, tmp, len, SvTAINTED(sv)) < 0) {
			talloc_free(vb);
			RPEDEBUG("Failed to allocate %ld for output", len);
			return -1;
		}
		break;

	case SVt_PVAV:
	/*	Array */
	{
		SV	**av_sv;
		RDEBUG3("Array returned");
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
		RDEBUG3("Hash returned");
		hv = (HV*)sv;
		for (i = hv_iterinit(hv); i > 0; i--) {
			hv_sv = hv_iternextsv(hv, &tmp, &sv_len);
			/*
			 *	Add key first
			 */
			MEM(vb = fr_value_box_alloc_null(ctx));
			if (fr_value_box_bstrndup(vb, vb, NULL, tmp, sv_len, SvTAINTED(hv_sv)) < 0) {
				talloc_free(vb);
				RPEDEBUG("Failed to allocate %d for output", sv_len);
				return -1;
			}
			fr_value_box_list_insert_tail(list, vb);

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

	if (vb) {
		vb->tainted = SvTAINTED(sv);
		fr_value_box_list_insert_tail(list, vb);
	}

	return 0;
}

static xlat_arg_parser_t const perl_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .type = FR_TYPE_VOID },
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
	fr_value_box_t			*func = fr_value_box_list_pop_head(in);
	fr_value_box_t			*child;
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
		ssize_t slen;
		fr_sbuff_t *sbuff;

		dSP;
		ENTER;SAVETMPS;

		PUSHMARK(SP);

		FR_SBUFF_TALLOC_THREAD_LOCAL(&sbuff, 256, 16384);

		fr_value_box_list_foreach(in, arg) {

			fr_assert(arg->type == FR_TYPE_GROUP);
			if (fr_value_box_list_empty(&arg->vb_group)) continue;

			if (fr_value_box_list_num_elements(&arg->vb_group) == 1) {
				child = fr_value_box_list_head(&arg->vb_group);

				switch (child->type) {
				case FR_TYPE_STRING:
					if (child->vb_length == 0) continue;

					RDEBUG3("Passing single value %pV", child);
					sv = newSVpvn(child->vb_strvalue, child->vb_length);
					break;

				case FR_TYPE_GROUP:
					RDEBUG3("Ignoring nested group");
					continue;

				default:
					/*
					 *	@todo - turn over integers as strings.
					 */
					slen = fr_value_box_print(sbuff, child, NULL);
					if (slen <= 0) {
						RPEDEBUG("Failed printing sbuff");
						continue;
					}

					RDEBUG3("Passing single value %pV", child);
					sv = newSVpvn(fr_sbuff_start(sbuff), fr_sbuff_used(sbuff));
					fr_sbuff_set_to_start(sbuff);
					break;
				}

				if (child->tainted) SvTAINT(sv);
				XPUSHs(sv_2mortal(sv));
				continue;
			}

			/*
			 *	Multiple child values - create array and pass reference
			 */
			av = newAV();
			perl_vblist_to_av(av, &arg->vb_group);
			RDEBUG3("Passing list as array %pM", &arg->vb_group);
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
			fr_value_box_list_move_head(&list, &sub_list);
		}
		ret = XLAT_ACTION_DONE;

		/*
		 *	Move the assembled list of boxes to the output
		 */
		while ((vb = fr_value_box_list_pop_head(&list))) fr_dcursor_append(out, vb);

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

/** Create a Perl tied hash representing a pair list
 *
 */
static void perl_pair_list_tie(HV *parent, HV *frpair_stash, char const *name, fr_pair_t *vp, fr_dict_attr_t const *da)
{
	HV		*list_hv;
	SV		*list_tie;
	fr_perl_pair_t	pair_data;

	list_hv = newHV();
	list_tie = newRV_noinc((SV *)newHV());
	sv_bless(list_tie, frpair_stash);
	hv_magic(list_hv, (GV *)list_tie, PERL_MAGIC_tied);
	SvREFCNT_dec(list_tie);

	pair_data = (fr_perl_pair_t) {
		.vp = vp,
		.da = da
	};

	sv_magicext((SV *)list_tie, 0, PERL_MAGIC_ext, &rlm_perl_vtbl, (char *)&pair_data, sizeof(pair_data));

	(void)hv_store(parent, name, strlen(name), newRV_inc((SV *)list_hv), 0);
}

/*
 * 	Call the function_name inside the module
 * 	Store all vps in hashes %RAD_CONFIG %RAD_REPLY %RAD_REQUEST
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_perl(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_perl_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_perl_t);
	perl_call_env_t		*func = talloc_get_type_abort(mctx->env_data, perl_call_env_t);
	PerlInterpreter		*interp = ((rlm_perl_thread_t *)talloc_get_type_abort(mctx->thread, rlm_perl_thread_t))->perl;
	int			ret=0, count;
	STRLEN			n_a;

	HV			*frpair_stash;
	HV			*fr_packet;

	/*
	 *	call_env parsing will have established the function name to call.
	 */
	fr_assert(func->func->function_name);

	{
		dTHXa(interp);
		PERL_SET_CONTEXT(interp);
	}

	{
		dSP;

		ENTER;
		SAVETMPS;

		/* Get the stash for the freeradiuspairlist package */
		frpair_stash = gv_stashpv("freeradiuspairlist", GV_ADD);

		/* New hash to hold the pair list roots and pass to the Perl subroutine */
		fr_packet = newHV();

		perl_pair_list_tie(fr_packet, frpair_stash, "request",
				   fr_pair_list_parent(&request->request_pairs), fr_dict_root(request->proto_dict));
		perl_pair_list_tie(fr_packet, frpair_stash, "reply",
				   fr_pair_list_parent(&request->reply_pairs), fr_dict_root(request->proto_dict));
		perl_pair_list_tie(fr_packet, frpair_stash, "control",
				   fr_pair_list_parent(&request->control_pairs), fr_dict_root(request->proto_dict));
		perl_pair_list_tie(fr_packet, frpair_stash, "session-state",
				   fr_pair_list_parent(&request->session_state_pairs), fr_dict_root(request->proto_dict));

		/*
		 * Store pointer to request structure globally so radiusd::xlat works
		 */
		rlm_perl_request = request;

		PUSHMARK(SP);
		XPUSHs( sv_2mortal(newRV((SV *)fr_packet)) );
		PUTBACK;

		count = call_pv(func->func->function_name, G_SCALAR | G_EVAL );

		rlm_perl_request = NULL;

		SPAGAIN;

		if (SvTRUE(ERRSV)) {
			REDEBUG("perl_embed:: module = %s , func = %s exit status= %s\n",
			        inst->module, func->func->function_name, SvPV(ERRSV,n_a));
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
	}

	RETURN_UNLANG_RCODE(ret);
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
	rlm_perl_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_perl_t);
	rlm_perl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_perl_thread_t);
	PerlInterpreter		*interp;
	UV			clone_flags = 0;

	PERL_SET_CONTEXT(inst->perl);

	/*
	 *	Ensure only one thread is cloning an interpreter at a time
	 *	Whilst the documentation of perl_clone() does not say anything
	 *	about this, seg faults have been seen if multiple threads clone
	 *	the same inst->perl at the same time.
	 */
	pthread_mutex_lock(&inst->mutable->mutex);
	interp = perl_clone(inst->perl, clone_flags);
	pthread_mutex_unlock(&inst->mutable->mutex);
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

/** Check if a given Perl subroutine exists
 *
 */
static bool perl_func_exists(char const *func)
{
	char	*eval_str;
	SV	*val;

	/*
	 *	Perl's "can" method checks if the object contains a subroutine of the given name.
	 *	We expect referenced subroutines to be in the "main" namespace.
	 */
	eval_str = talloc_asprintf(NULL, "(main->can('%s') ? 1 : 0)", func);
	val = eval_pv(eval_str, TRUE);
	talloc_free(eval_str);
	return SvIV(val) ? true : false;
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
 *	Setup a hashes which we will use later
 *	parse a module and give it a chance to live
 *
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_perl_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_perl_t);
	perl_func_def_t		*func = NULL;
	fr_rb_iter_inorder_t	iter;
	CONF_PAIR		*cp;
	char			*pair_name;

	CONF_SECTION	*conf = mctx->mi->conf;
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
		ERROR("No memory for allocating new perl interpreter!");
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

	/*
	 *	The call_env parser has found all the places the module is called
	 *	Check for config options which set the subroutine name, falling back to
	 *	automatic subroutine names based on section name.
	 */
	if (!inst->funcs_init) fr_rb_inline_init(&inst->funcs, perl_func_def_t, node, perl_func_def_cmp, NULL);
	func = fr_rb_iter_init_inorder(&iter, &inst->funcs);
	while (func) {
		/*
		 *	Check for func_<name1>_<name2> or func_<name1> config pairs.
		 */
		if (func->name2) {
			pair_name = talloc_asprintf(func, "func_%s_%s", func->name1, func->name2);
			cp = cf_pair_find(mctx->mi->conf, pair_name);
			talloc_free(pair_name);
			if (cp) goto found_func;
		}
		pair_name = talloc_asprintf(func, "func_%s", func->name1);
		cp = cf_pair_find(conf, pair_name);
		talloc_free(pair_name);
	found_func:
		if (cp){
			func->function_name = cf_pair_value(cp);
			if (!perl_func_exists(func->function_name)) {
				cf_log_err(cp, "Perl subroutine %s does not exist", func->function_name);
				return -1;
			}
		/*
		 *	If no pair was found, then use <name1>_<name2> or <name1> as the function to call.
		 */
		} else if (func->name2) {
			func->function_name = talloc_asprintf(func, "%s_%s", func->name1, func->name2);
			if (!perl_func_exists(func->function_name)) {
				talloc_const_free(func->function_name);
				goto name1_only;
			}
		} else {
		name1_only:
			func->function_name = func->name1;
			if (!perl_func_exists(func->function_name)) {
				cf_log_err(cp, "Perl subroutine %s does not exist", func->function_name);
				return -1;
			}
		}

		func = fr_rb_iter_next_inorder(&iter);
	}

	PL_endav = end_AV;

	inst->mutable = talloc(NULL, rlm_perl_mutable_t);
	pthread_mutex_init(&inst->mutable->mutex, NULL);

	return 0;
}

/*
 * Detach a instance give a chance to a module to make some internal setup ...
 */
DIAG_OFF(nested-externs)
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_perl_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_perl_t);
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
	talloc_free(inst->mutable);

	return ret;
}
DIAG_ON(nested-externs)

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t *xlat;

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, perl_xlat, FR_TYPE_VOID);
	xlat_func_args_set(xlat, perl_xlat_args);

	return 0;
}

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
 *	Restrict automatic Perl function names to lowercase characters, numbers and underscore
 *	meaning that a module call in `recv Access-Request` will look for `recv_access_request`
 */
static void perl_func_name_safe(char *name) {
	char	*p;
	size_t	i;

	p = name;
	for (i = 0; i < talloc_array_length(name); i++) {
		*p = tolower(*p);
		if (!strchr("abcdefghijklmnopqrstuvwxyz1234567890", *p)) *p = '_';
		p++;
	}
}

static int perl_func_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, UNUSED tmpl_rules_t const *t_rules,
			   UNUSED CONF_ITEM *ci, call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_perl_t		*inst = talloc_get_type_abort(cec->mi->data, rlm_perl_t);
	call_env_parsed_t	*parsed;
	perl_func_def_t		*func;
	void			*found;

	if (!inst->funcs_init) {
		fr_rb_inline_init(&inst->funcs, perl_func_def_t, node, perl_func_def_cmp, NULL);
		inst->funcs_init = true;
	}

	MEM(parsed = call_env_parsed_add(ctx, out,
					 &(call_env_parser_t){
						.name = "func",
						.flags = CALL_ENV_FLAG_PARSE_ONLY,
						.pair = {
							.parsed = {
								.offset = rule->pair.offset,
								.type = CALL_ENV_PARSE_TYPE_VOID
							}
						}
					}));

	MEM(func = talloc_zero(inst, perl_func_def_t));
	func->name1 = talloc_strdup(func, cec->asked->name1);
	perl_func_name_safe(func->name1);
	if (cec->asked->name2) {
		func->name2 = talloc_strdup(func, cec->asked->name2);
		perl_func_name_safe(func->name2);
	}
	if (fr_rb_find_or_insert(&found, &inst->funcs, func) < 0) {
		talloc_free(func);
		return -1;
	}

	/*
	*	If the function call is already in the tree, use that entry.
	*/
	if (found) {
		talloc_free(func);
		call_env_parsed_set_data(parsed, found);
	} else {
		call_env_parsed_set_data(parsed, func);
	}
	return 0;
}

static const call_env_method_t perl_method_env = {
	FR_CALL_ENV_METHOD_OUT(perl_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY, CALL_ENV_FLAG_PARSE_MISSING, perl_func_parse) },
		CALL_ENV_TERMINATOR
	}
};

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
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_perl, .method_env = &perl_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
