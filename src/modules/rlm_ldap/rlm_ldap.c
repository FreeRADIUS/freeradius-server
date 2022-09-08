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
 * @file rlm_ldap.c
 * @brief LDAP authorization and authentication module.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2012,2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013,2015 Network RADIUS SARL (legal@networkradius.com)
 * @copyright 2012 Alan DeKok (aland@freeradius.org)
 * @copyright 1999-2013 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/uri.h>

#include "rlm_ldap.h"
#include <freeradius-devel/ldap/conf.h>

#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module_rlm.h>

static CONF_PARSER sasl_mech_dynamic[] = {
	{ FR_CONF_OFFSET("mech", FR_TYPE_TMPL | FR_TYPE_NOT_EMPTY, fr_ldap_sasl_t_dynamic_t, mech) },
	{ FR_CONF_OFFSET("proxy", FR_TYPE_TMPL, fr_ldap_sasl_t_dynamic_t, proxy) },
	{ FR_CONF_OFFSET("realm", FR_TYPE_TMPL, fr_ldap_sasl_t_dynamic_t, realm) },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER profile_config[] = {
	{ FR_CONF_OFFSET("filter", FR_TYPE_TMPL, rlm_ldap_t, profile_filter), .dflt = "(&)", .quote = T_SINGLE_QUOTED_STRING },	//!< Correct filter for when the DN is known.
	{ FR_CONF_OFFSET("attribute", FR_TYPE_STRING, rlm_ldap_t, profile_attr) },
	{ FR_CONF_OFFSET("default", FR_TYPE_TMPL, rlm_ldap_t, default_profile) },
	CONF_PARSER_TERMINATOR
};

/*
 *	User configuration
 */
static CONF_PARSER user_config[] = {
	{ FR_CONF_OFFSET("filter", FR_TYPE_TMPL, rlm_ldap_t, userobj_filter) },
	{ FR_CONF_OFFSET("scope", FR_TYPE_STRING, rlm_ldap_t, userobj_scope_str), .dflt = "sub" },
	{ FR_CONF_OFFSET("base_dn", FR_TYPE_TMPL, rlm_ldap_t, userobj_base_dn), .dflt = "", .quote = T_SINGLE_QUOTED_STRING },
	{ FR_CONF_OFFSET("sort_by", FR_TYPE_STRING, rlm_ldap_t, userobj_sort_by) },

	{ FR_CONF_OFFSET("access_attribute", FR_TYPE_STRING, rlm_ldap_t, userobj_access_attr) },
	{ FR_CONF_OFFSET("access_positive", FR_TYPE_BOOL, rlm_ldap_t, access_positive), .dflt = "yes" },

	/* Should be deprecated */
	{ FR_CONF_OFFSET("sasl", FR_TYPE_SUBSECTION, rlm_ldap_t, user_sasl), .subcs = (void const *) sasl_mech_dynamic },
	CONF_PARSER_TERMINATOR
};

/*
 *	Group configuration
 */
static CONF_PARSER group_config[] = {
	{ FR_CONF_OFFSET("filter", FR_TYPE_STRING, rlm_ldap_t, groupobj_filter) },
	{ FR_CONF_OFFSET("scope", FR_TYPE_STRING, rlm_ldap_t, groupobj_scope_str), .dflt = "sub" },
	{ FR_CONF_OFFSET("base_dn", FR_TYPE_TMPL, rlm_ldap_t, groupobj_base_dn), .dflt = "", .quote = T_SINGLE_QUOTED_STRING },

	{ FR_CONF_OFFSET("name_attribute", FR_TYPE_STRING, rlm_ldap_t, groupobj_name_attr), .dflt = "cn" },
	{ FR_CONF_OFFSET("membership_attribute", FR_TYPE_STRING, rlm_ldap_t, userobj_membership_attr) },
	{ FR_CONF_OFFSET("membership_filter", FR_TYPE_STRING | FR_TYPE_XLAT, rlm_ldap_t, groupobj_membership_filter) },
	{ FR_CONF_OFFSET("cacheable_name", FR_TYPE_BOOL, rlm_ldap_t, cacheable_group_name), .dflt = "no" },
	{ FR_CONF_OFFSET("cacheable_dn", FR_TYPE_BOOL, rlm_ldap_t, cacheable_group_dn), .dflt = "no" },
	{ FR_CONF_OFFSET("cache_attribute", FR_TYPE_STRING, rlm_ldap_t, cache_attribute) },
	{ FR_CONF_OFFSET("group_attribute", FR_TYPE_STRING, rlm_ldap_t, group_attribute) },
	{ FR_CONF_OFFSET("allow_dangling_group_ref", FR_TYPE_BOOL, rlm_ldap_t, allow_dangling_group_refs), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Reference for accounting updates
 */
static const CONF_PARSER acct_section_config[] = {
	{ FR_CONF_OFFSET("reference", FR_TYPE_STRING | FR_TYPE_XLAT, ldap_acct_section_t, reference), .dflt = "." },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	/*
	 *	Pool config items
	 */
	{ FR_CONF_OFFSET("server", FR_TYPE_STRING | FR_TYPE_MULTI, rlm_ldap_t, handle_config.server_str) },	/* Do not set to required */

	/*
	 *	Common LDAP conf parsers
	 */
	FR_LDAP_COMMON_CONF(rlm_ldap_t),

	{ FR_CONF_OFFSET("valuepair_attribute", FR_TYPE_STRING, rlm_ldap_t, valuepair_attr) },

#ifdef LDAP_CONTROL_X_SESSION_TRACKING
	{ FR_CONF_OFFSET("session_tracking", FR_TYPE_BOOL, rlm_ldap_t, session_tracking), .dflt = "no" },
#endif

#ifdef WITH_EDIR
	/* support for eDirectory Universal Password */
	{ FR_CONF_OFFSET("edir", FR_TYPE_BOOL, rlm_ldap_t, edir) }, /* NULL defaults to "no" */

	/*
	 *	Attempt to bind with the cleartext password we got from eDirectory
	 *	Universal password for additional authorization checks.
	 */
	{ FR_CONF_OFFSET("edir_autz", FR_TYPE_BOOL, rlm_ldap_t, edir_autz) }, /* NULL defaults to "no" */
#endif

	{ FR_CONF_POINTER("user", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) user_config },

	{ FR_CONF_POINTER("group", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) group_config },

	{ FR_CONF_POINTER("profile", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) profile_config },

	{ FR_CONF_OFFSET("pool", FR_TYPE_SUBSECTION, rlm_ldap_t, trunk_conf), .subcs = (void const *) fr_trunk_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_ldap_dict[];
fr_dict_autoload_t rlm_ldap_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

fr_dict_attr_t const *attr_cleartext_password;
fr_dict_attr_t const *attr_crypt_password;
fr_dict_attr_t const *attr_ldap_userdn;
fr_dict_attr_t const *attr_nt_password;
fr_dict_attr_t const *attr_password_with_header;

fr_dict_attr_t const *attr_user_password;
fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_ldap_dict_attr[];
fr_dict_attr_autoload_t rlm_ldap_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_crypt_password, .name = "Password.Crypt", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ldap_userdn, .name = "LDAP-UserDN", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_nt_password, .name = "Password.NT", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_password_with_header, .name = "Password.With-Header", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

extern global_lib_autoinst_t const *rlm_ldap_lib[];
global_lib_autoinst_t const *rlm_ldap_lib[] = {
	&fr_libldap_global_config,
	GLOBAL_LIB_TERMINATOR
};


static xlat_arg_parser_t const ldap_escape_xlat_arg = { .required = true, .concat = true, .type = FR_TYPE_STRING };

/** Escape LDAP string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_escape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      UNUSED xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*vb, *in_vb = fr_dlist_head(in);
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	MEM(vb = fr_value_box_alloc_null(ctx));
	/*
	 *	Maximum space needed for output would be 3 times the input if every
	 *	char needed escaping
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, in_vb->length * 3, in_vb->length * 3)) {
		REDEBUG("Failed to allocate buffer for escaped string");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Call the escape function, including the space for the trailing NULL
	 */
	len = fr_ldap_escape_func(request, fr_sbuff_buff(&sbuff), in_vb->length * 3 + 1, in_vb->vb_strvalue, NULL);

	/*
	 *	Trim buffer to fit used space and assign to box
	 */
	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), in_vb->tainted);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

/** Unescape LDAP string
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_unescape_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*vb, *in_vb = fr_dlist_head(in);
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	MEM(vb = fr_value_box_alloc_null(ctx));
	/*
	 *	Maximum space needed for output will be the same as the input
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, in_vb->length, in_vb->length)) {
		REDEBUG("Failed to allocate buffer for unescaped string");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Call the unescape function, including the space for the trailing NULL
	 */
	len = fr_ldap_unescape_func(request, fr_sbuff_buff(&sbuff), in_vb->length + 1, in_vb->vb_strvalue, NULL);

	/*
	 *	Trim buffer to fit used space and assign to box
	 */
	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), in_vb->tainted);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Escape function for a part of an LDAP URI
 *
 */
static int uri_part_escape(fr_value_box_t *vb, UNUSED void *uctx)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	sbuff_ctx;
	size_t			len;

	/*
	 *	Maximum space needed for output would be 3 times the input if every
	 *	char needed escaping
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, vb->length * 3, vb->length * 3)) {
		fr_strerror_printf_push("Failed to allocate buffer for escaped argument");
		return -1;
	}

	/*
	 *	Call the escape function, including the space for the trailing NULL
	 */
	len = fr_ldap_escape_func(NULL, fr_sbuff_buff(&sbuff), vb->length * 3 + 1, vb->vb_strvalue, NULL);

	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_clear_value(vb);
	fr_value_box_strdup_shallow(vb, NULL, fr_sbuff_buff(&sbuff), vb->tainted);

	return 0;
}

/** Callback when LDAP query times out
 *
 */
static void ldap_query_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_trunk_request_t	*treq = talloc_get_type_abort(uctx, fr_trunk_request_t);
	fr_ldap_query_t		*query = talloc_get_type_abort(treq->preq, fr_ldap_query_t);
	request_t		*request = treq->request;

	ROPTIONAL(RERROR, ERROR, "Timeout waiting for LDAP query");
	if (query->msgid) {
		fr_trunk_request_signal_cancel(query->treq);
	}

	query->ret = LDAP_RESULT_TIMEOUT;
	unlang_interpret_mark_runnable(request);
}

/** Callback when resuming after async ldap query is completed
 *
 */
static xlat_action_t ldap_xlat_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
	 			      request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_ldap_query_t		*query = talloc_get_type_abort(xctx->rctx, fr_ldap_query_t);
	fr_ldap_connection_t	*ldap_conn = query->ldap_conn;
	fr_value_box_t		*vb = NULL;
	LDAPMessage		*msg;
	struct berval		**values;
	char const		**attr;
	int			count, i;

	if (query->ret != LDAP_RESULT_SUCCESS) return XLAT_ACTION_FAIL;

	/*
	 *	We only parse "entries"
	 */
	for (msg = ldap_first_entry(ldap_conn->handle, query->result); msg; msg = ldap_next_entry(ldap_conn->handle, msg)) {
		for (attr = query->search.attrs; *attr; attr++) {
			values = ldap_get_values_len(ldap_conn->handle, msg, *attr);
			if (!values) {
				RDEBUG2("No \"%s\" attributes found in specified object", *attr);
				continue;
			}

			count = ldap_count_values_len(values);
			for (i = 0; i < count; i++) {
				MEM(vb = fr_value_box_alloc_null(ctx));
				if (fr_value_box_bstrndup(ctx, vb, NULL, values[i]->bv_val, values[i]->bv_len, true) < 0) {
					talloc_free(vb);
					RPERROR("Failed creating value from LDAP response");
					break;
				}
				fr_dcursor_append(out, vb);
			}
			ldap_value_free_len(values);
		}
	}

	talloc_free(query);

	return XLAT_ACTION_DONE;
}

/** Callback for signalling async ldap query
 *
 */
static void ldap_xlat_signal(xlat_ctx_t const *xctx, request_t *request, fr_state_signal_t action)
{
	fr_ldap_query_t		*query = talloc_get_type_abort(xctx->rctx, fr_ldap_query_t);

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Forcefully cancelling pending LDAP query");

	fr_trunk_request_signal_cancel(query->treq);
}


static fr_uri_part_t const ldap_uri_parts[] = {
	{ .name = "scheme", .terminals = &FR_SBUFF_TERMS(L(":")), .part_adv = { [':'] = 1 },
	  .tainted_allowed = false, .extra_skip = 2 },
	{ .name = "host", .terminals = &FR_SBUFF_TERMS(L(":"), L("/")), .part_adv = { [':'] = 1, ['/'] = 2 },
	  .tainted_allowed = false },
	{ .name = "port", .terminals = &FR_SBUFF_TERMS(L("/")), .part_adv = { ['/'] = 1 },
	  .tainted_allowed = false },
	{ .name = "dn", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 },
	  .tainted_allowed = true, .func = uri_part_escape },
	{ .name = "attrs", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 },
	  .tainted_allowed = false },
	{ .name = "scope", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1 },
	  .tainted_allowed = true, .func = uri_part_escape },
	{ .name = "filter", .terminals = &FR_SBUFF_TERMS(L("?")), .part_adv = { ['?'] = 1},
	  .tainted_allowed = true, .func = uri_part_escape },
	{ .name = "exts", .tainted_allowed = true, .func = uri_part_escape },
	XLAT_URI_PART_TERMINATOR
};

static xlat_arg_parser_t const ldap_xlat_arg = { .required = true, .type = FR_TYPE_STRING };

/** Expand an LDAP URL into a query, and return a string result from that query.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t ldap_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
			       xlat_ctx_t const *xctx,
	 		       request_t *request, fr_value_box_list_t *in)
{
	fr_ldap_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, fr_ldap_thread_t);
	fr_value_box_t		*in_vb = NULL;
	char			*host_url;
	fr_ldap_config_t const	*handle_config = t->config;
	fr_ldap_thread_trunk_t	*ttrunk;
	fr_ldap_query_t		*query = NULL;

	LDAPURLDesc		*ldap_url;

	if (fr_uri_escape(in, ldap_uri_parts, NULL) < 0) return XLAT_ACTION_FAIL;

	in_vb = fr_dlist_head(in);
	if (fr_value_box_list_concat_in_place(in_vb, in_vb, in, FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE,
					     true, SIZE_MAX) < 0) {
		REDEBUG("Failed concattenating input");
		return XLAT_ACTION_FAIL;
	}

	if (!ldap_is_ldap_url(in_vb->vb_strvalue)) {
		REDEBUG("String passed does not look like an LDAP URL");
		return XLAT_ACTION_FAIL;
	}

	if (ldap_url_parse(in_vb->vb_strvalue, &ldap_url)){
		REDEBUG("Parsing LDAP URL failed");
	error:
		ldap_free_urldesc(ldap_url);
		talloc_free(query);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Nothing, empty string, "*" string, or got 2 things, die.
	 */
	if (!ldap_url->lud_attrs || !ldap_url->lud_attrs[0] || !*ldap_url->lud_attrs[0] ||
	    (strcmp(ldap_url->lud_attrs[0], "*") == 0) || ldap_url->lud_attrs[1]) {
		REDEBUG("Bad attributes list in LDAP URL. URL must specify exactly one attribute to retrieve");

		goto error;
	}

	query = fr_ldap_search_alloc(unlang_interpret_frame_talloc_ctx(request),
				     ldap_url->lud_dn, ldap_url->lud_scope, ldap_url->lud_filter,
				     (char const * const*)ldap_url->lud_attrs, NULL, NULL);
	if (ldap_url->lud_exts) {
		LDAPControl	*serverctrls[LDAP_MAX_CONTROLS];
		int		i;

		if (fr_ldap_parse_url_extensions(serverctrls, NUM_ELEMENTS(serverctrls),
						 query->ldap_url->lud_exts) < 0) {
			RPERROR("Parsing URL extensions failed");
			goto error;
		}

		for (i = 0; i < LDAP_MAX_CONTROLS; i++) {
			if (!serverctrls[i]) break;
			query->serverctrls[i].control = serverctrls[i];
			query->serverctrls[i].freeit = true;
		}
	}

	/*
	 *	If the URL is <scheme>:/// the parsed host will be NULL - use config default
	 */
	if (!ldap_url->lud_host) {
		host_url = handle_config->server;
	} else {
		host_url = talloc_asprintf(query, "%s://%s:%d", ldap_url->lud_scheme,
	                        	   ldap_url->lud_host, ldap_url->lud_port);
	}

	ttrunk = fr_thread_ldap_trunk_get(t, host_url, handle_config->admin_identity,
					  handle_config->admin_password, request, handle_config);
	if (!ttrunk) {
		REDEBUG("Unable to get LDAP query for xlat");
		goto error;
	}

	query->ldap_url = ldap_url;	/* query destructor will free URL */

	fr_trunk_request_enqueue(&query->treq, ttrunk->trunk, request, query, NULL);

	fr_event_timer_in(query, unlang_interpret_event_list(request), &query->ev, handle_config->res_timeout,
			  ldap_query_timeout, query->treq);

	return unlang_xlat_yield(request, ldap_xlat_resume, ldap_xlat_signal, query);
}

/*
 *	Verify the result of the map.
 */
static int ldap_map_verify(CONF_SECTION *cs, UNUSED void *mod_inst, UNUSED void *proc_inst,
			   tmpl_t const *src, UNUSED map_list_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing LDAP URI");

		return -1;
	}

	return 0;
}

/** Error reading from or writing to the file descriptor
 *
 * @param[in] el	the event occurred in.
 * @param[in] fd	the event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	The error that ocurred.
 * @param[in] uctx	LDAP thread the connection that faulted relates to.
 */
static void _ldap_bind_auth_io_error(UNUSED fr_event_list_t *el, UNUSED int fd,
				     UNUSED int flags, UNUSED int fd_errno, void *uctx)
{
	fr_ldap_thread_t	*thread = talloc_get_type_abort(uctx, fr_ldap_thread_t);
	fr_ldap_connection_t	*c = talloc_get_type_abort(thread->conn->h, fr_ldap_connection_t);

	fr_ldap_state_error(c);		/* Restart the connection state machine */
}

/** Callback used to process LDAP bind auth results
 *
 * @param[in] el	the read event occurred in.
 * @param[in] fd	the read event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] uctx	LDAP thread associated with the event.
 */
static void _ldap_bind_auth_io_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_ldap_thread_t	*thread = talloc_get_type_abort(uctx, fr_ldap_thread_t);
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(thread->conn->h, fr_ldap_connection_t);
	fr_ldap_bind_auth_ctx_t	find = { .msgid = -1 }, *bind_auth_ctx;
	LDAPMessage		*result = NULL;

	int			ret;

	do {
		/*
		 *	Fetch the next LDAP result which has been fully received
		 */
		ret = fr_ldap_result(&result, NULL, ldap_conn, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, fr_time_delta_wrap(10));

		/*
		 *	Timeout in this case really means no results to read - we've
		 *	handled everything that was available
		 */
		if (ret == LDAP_PROC_TIMEOUT) return;

		/*
		 *	If there is no result don't try to process one
		 */
		if (!result) return;

		find.msgid = ldap_msgid(result);
		bind_auth_ctx = fr_rb_find(thread->binds, &find);

		if (!bind_auth_ctx) {
			WARN("Ignoring bind result msgid %i - doesn't match any outstanidng binds", find.msgid);
			ldap_msgfree(result);
			continue;
		}

		/*
		 *	Remove from the list of pending bind requests
		 */
		fr_rb_remove(bind_auth_ctx->thread->binds, bind_auth_ctx);

		bind_auth_ctx->ret = ret;

		switch (ret) {
		/*
		 *	Accept or reject will be SUCCESS, NOT_PERMITTED or REJECT
		 */
		case LDAP_PROC_SUCCESS:
		case LDAP_PROC_NOT_PERMITTED:
		case LDAP_PROC_REJECT:
			break;

		default:
			ERROR("LDAP connection returned an error - restarting the connection");
			fr_ldap_state_error(bind_auth_ctx->bind_ctx->c);	/* Restart the connection state machine */
			break;
		}
		unlang_interpret_mark_runnable(bind_auth_ctx->request);

		/*
		 *	Clear up the libldap results
		 */
		ldap_msgfree(result);

	} while (1);
}

/** Watch callback to add fd read callback to LDAP connection
 *
 * To add "bind" specific callbacks to LDAP conneciton being used
 * for bind auths, when the connection becomes connected.
 *
 * @param[in] conn	to watch.
 * @param[in] prev	connection state.
 * @param[in] state	the connection is now in.
 * @param[in] uctx	LDAP thread this connection relates to.
 */
static void _ldap_async_bind_auth_watch(fr_connection_t *conn, UNUSED fr_connection_state_t prev,
					UNUSED fr_connection_state_t state, void *uctx)
{
	fr_ldap_thread_t	*thread = talloc_get_type_abort(uctx, fr_ldap_thread_t);
	fr_ldap_connection_t	*ldap_conn = talloc_get_type_abort(conn->h, fr_ldap_connection_t);

	if (ldap_conn->fd < 0) {
	connection_failed:
		fr_connection_signal_reconnect(conn, FR_CONNECTION_FAILED);
		return;
	}
	if (fr_event_fd_insert(conn, conn->el, ldap_conn->fd,
			       _ldap_bind_auth_io_read,
			       NULL,
			       _ldap_bind_auth_io_error,
			       thread) < 0) {
		goto connection_failed;
	};
}

/** Perform a search and map the result of the search to server attributes
 *
 * Unlike LDAP xlat, this can be used to process attributes from multiple entries.
 *
 * @todo For xlat expansions we need to parse the raw URL first, and then apply
 *	different escape functions to the different parts.
 *
 * @param[in] mod_inst #rlm_ldap_t
 * @param[in] proc_inst unused.
 * @param[in,out] request The current request.
 * @param[in] url LDAP url specifying base DN and filter.
 * @param[in] maps Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned.
 *	- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *	- #RLM_MODULE_FAIL if an error occurred.
 */
static rlm_rcode_t mod_map_proc(void *mod_inst, UNUSED void *proc_inst, request_t *request,
				fr_value_box_list_t *url, map_list_t const *maps)
{
	rlm_rcode_t		rcode = RLM_MODULE_UPDATED;
	rlm_ldap_t		*inst = talloc_get_type_abort(mod_inst, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);

	LDAPURLDesc		*ldap_url;

	LDAPMessage		*entry = NULL;
	map_t const		*map;
	char const 		*url_str;

	char			*host_url;
	fr_ldap_query_t		*query;
	fr_ldap_thread_trunk_t	*ttrunk;

	fr_ldap_map_exp_t	expanded; /* faster than allocing every time */
	fr_value_box_t		*url_head = fr_dlist_head(url);

	/*
	 *	FIXME - Maybe it can be NULL?
	 */
	if (!url_head) {
		REDEBUG("LDAP URL cannot be (null)");
		return RLM_MODULE_FAIL;
	}

	if (fr_value_box_list_concat_in_place(request,
					      url_head, url, FR_TYPE_STRING,
					      FR_VALUE_BOX_LIST_FREE, true,
					      SIZE_MAX) < 0) {
		REDEBUG("Failed concatenating input");
		return RLM_MODULE_FAIL;
	}
	url_str = url_head->vb_strvalue;

	if (!ldap_is_ldap_url(url_str)) {
		REDEBUG("Map query string does not look like a valid LDAP URI");
		return RLM_MODULE_FAIL;
	}

	if (ldap_url_parse(url_str, &ldap_url)){
		REDEBUG("Parsing LDAP URL failed");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Expand the RHS of the maps to get the name of the attributes.
	 */
	if (fr_ldap_map_expand(&expanded, request, maps) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto free_urldesc;
	}

	/*
	 *	If the URL is <scheme>:/// the parsed host will be NULL - use config default
	 */
	if (!ldap_url->lud_host) {
		host_url = inst->handle_config.server;
	} else {
		host_url = talloc_asprintf(unlang_interpret_frame_talloc_ctx(request), "%s://%s:%d",
					   ldap_url->lud_scheme, ldap_url->lud_host, ldap_url->lud_port);
	}

	ttrunk =  fr_thread_ldap_trunk_get(thread, host_url, inst->handle_config.admin_identity,
					   inst->handle_config.admin_password, request, &inst->handle_config);
	if (!ttrunk) goto free_expanded;

	if (fr_ldap_trunk_search(&rcode,
			    	 unlang_interpret_frame_talloc_ctx(request), &query, request, ttrunk, ldap_url->lud_dn,
				 ldap_url->lud_scope, ldap_url->lud_filter, expanded.attrs, NULL, NULL, false) < 0) {
		goto free_expanded;
	}
	switch (rcode) {
	case RLM_MODULE_OK:
		rcode = RLM_MODULE_UPDATED;
		break;

	case RLM_MODULE_NOTFOUND:
		goto free_expanded;

	default:
		rcode = RLM_MODULE_FAIL;
		goto free_expanded;
	}

	for (entry = ldap_first_entry(query->ldap_conn->handle, query->result);
	     entry;
	     entry = ldap_next_entry(query->ldap_conn->handle, entry)) {
		char	*dn = NULL;
		int	i;


		if (RDEBUG_ENABLED2) {
			dn = ldap_get_dn(query->ldap_conn->handle, entry);
			RDEBUG2("Processing \"%s\"", dn);
		}

		RINDENT();
		for (map = map_list_head(maps), i = 0;
		     map != NULL;
		     map = map_list_next(maps, map), i++) {
			int			ret;
			fr_ldap_result_t	attr;

			attr.values = ldap_get_values_len(query->ldap_conn->handle, entry, expanded.attrs[i]);
			if (!attr.values) {
				/*
				 *	Many LDAP directories don't expose the DN of
				 *	the object as an attribute, so we need this
				 *	hack, to allow the user to retrieve it.
				 */
				if (strcmp(LDAP_VIRTUAL_DN_ATTR, expanded.attrs[i]) == 0) {
					struct berval value;
					struct berval *values[2] = { &value, NULL };

					if (!dn) dn = ldap_get_dn(query->ldap_conn->handle, entry);
					value.bv_val = dn;
					value.bv_len = strlen(dn);

					attr.values = values;
					attr.count = 1;

					ret = map_to_request(request, map, fr_ldap_map_getvalue, &attr);
					if (ret == -1) {
						rcode = RLM_MODULE_FAIL;
						ldap_memfree(dn);
						goto free_expanded;
					}
					continue;
				}

				RDEBUG3("Attribute \"%s\" not found in LDAP object", expanded.attrs[i]);

				continue;
			}
			attr.count = ldap_count_values_len(attr.values);

			ret = map_to_request(request, map, fr_ldap_map_getvalue, &attr);
			ldap_value_free_len(attr.values);
			if (ret == -1) {
				rcode = RLM_MODULE_FAIL;
				ldap_memfree(dn);
				goto free_expanded;
			}
		}
		ldap_memfree(dn);
		REXDENT();
	}

free_expanded:
	talloc_free(expanded.ctx);
free_urldesc:
	ldap_free_urldesc(ldap_url);

	return rcode;
}

/** Perform LDAP-Group comparison checking
 *
 * Attempts to match users to groups using a variety of methods.
 *
 * @param instance of the rlm_ldap module.
 * @param request Current request.
 * @param check Which group to check for user membership.
 * @return
 *	- 1 on failure (or if the user is not a member).
 *	- 0 on success.
 */
static int rlm_ldap_groupcmp(void *instance, request_t *request, fr_pair_t const *check)
{
	rlm_ldap_t const	*inst = talloc_get_type_abort_const(instance, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);
	rlm_rcode_t		rcode;

	bool			found = false;
	bool			check_is_dn;

	fr_ldap_thread_trunk_t	*ttrunk = NULL;
	char const		*user_dn;
	fr_pair_t		*check_p = NULL;

	fr_assert(inst->groupobj_base_dn);

	RDEBUG2("Searching for user in group \"%pV\"", &check->data);

	if (check->vp_length == 0) {
		REDEBUG("Cannot do comparison (group name is empty)");
		return 1;
	}

	/*
	 *	Check if we can do cached membership verification
	 */
	check_is_dn = fr_ldap_util_is_dn(check->vp_strvalue, check->vp_length);
	if (check_is_dn) {
		char	*norm;
		size_t	len;

		check = check_p = fr_pair_copy(request, check); /* allocate a mutable version */

		MEM(norm = talloc_array(check_p, char, talloc_array_length(check_p->vp_strvalue)));
		len = fr_ldap_util_normalise_dn(norm, check->vp_strvalue);

		/*
		 *	Will clear existing buffer (i.e. check->vp_strvalue)
		 */
		fr_pair_value_bstrdup_buffer_shallow(check_p, norm, check->vp_tainted);

		/*
		 *	Trim buffer to match normalised DN
		 */
		fr_pair_value_bstr_realloc(check_p, NULL, len);
	}
	if ((check_is_dn && inst->cacheable_group_dn) || (!check_is_dn && inst->cacheable_group_name)) {
		rlm_rcode_t our_rcode;

		rlm_ldap_check_cached(&our_rcode, inst, request, check);
		switch (our_rcode) {
		case RLM_MODULE_NOTFOUND:
			found = false;
			goto finish;

		case RLM_MODULE_OK:
			found = true;
			goto finish;
		/*
		 *	Fallback to dynamic search on failure
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		default:
			break;
		}
	}

	ttrunk =  fr_thread_ldap_trunk_get(thread, inst->handle_config.server, inst->handle_config.admin_identity,
					   inst->handle_config.admin_password, request, &inst->handle_config);
	if (!ttrunk) goto cleanup;

	/*
	 *	This is used in the default membership filter.
	 */
	user_dn = rlm_ldap_find_user(inst, request, ttrunk, NULL, false, NULL, NULL, &rcode);
	if (!user_dn) goto cleanup;

	/*
	 *	Check groupobj user membership
	 */
	if (inst->groupobj_membership_filter) {
		rlm_rcode_t our_rcode;

		rlm_ldap_check_groupobj_dynamic(&our_rcode, inst, request, ttrunk, check);
		switch (our_rcode) {
		case RLM_MODULE_NOTFOUND:
			break;

		case RLM_MODULE_OK:
			found = true;
			FALL_THROUGH;

		default:
			goto finish;
		}
	}

	/*
	 *	Check userobj group membership
	 */
	if (inst->userobj_membership_attr) {
		rlm_rcode_t our_rcode;

		rlm_ldap_check_userobj_dynamic(&our_rcode, inst, request, ttrunk, user_dn, check);
		switch (our_rcode) {
		case RLM_MODULE_NOTFOUND:
			break;

		case RLM_MODULE_OK:
			found = true;
			FALL_THROUGH;

		default:
			goto finish;
		}
	}

finish:
	if (found) {
		talloc_free(check_p);
		return 0;
	}

	RDEBUG2("User is not a member of \"%pV\"", &check->data);

cleanup:
	talloc_free(check_p);
	return 1;
}

static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);
	rlm_rcode_t		rcode;
	char const		*dn;
	fr_ldap_thread_trunk_t	*ttrunk = NULL;

	char			sasl_mech_buff[LDAP_MAX_DN_STR_LEN];
	char			sasl_proxy_buff[LDAP_MAX_DN_STR_LEN];
	char			sasl_realm_buff[LDAP_MAX_DN_STR_LEN];
	fr_ldap_sasl_t		sasl;
	fr_pair_t *username, *password;

	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	password = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_password);

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	if (!password) {
		RWDEBUG("You have set \"Auth-Type := LDAP\" somewhere");
		RWDEBUG("without checking if User-Password is present");
		RWDEBUG("*********************************************");
		RWDEBUG("* THAT CONFIGURATION IS WRONG.  DELETE IT.   ");
		RWDEBUG("* YOU ARE PREVENTING THE SERVER FROM WORKING");
		RWDEBUG("*********************************************");

		REDEBUG("Attribute \"User-Password\" is required for authentication");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (password->vp_length == 0) {
		REDEBUG("User-Password must not be empty");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &password->data);
	} else {
		RDEBUG2("Login attempt with password");
	}

	ttrunk =  fr_thread_ldap_trunk_get(thread, inst->handle_config.server, inst->handle_config.admin_identity,
					   inst->handle_config.admin_password, request, &inst->handle_config);
	if (!ttrunk) RETURN_MODULE_FAIL;

	/*
	 *	Expand dynamic SASL fields
	 */
	if (inst->user_sasl.mech) {
		memset(&sasl, 0, sizeof(sasl));

		if (tmpl_expand(&sasl.mech, sasl_mech_buff, sizeof(sasl_mech_buff), request,
				inst->user_sasl.mech, fr_ldap_escape_func, inst) < 0) {
			RPEDEBUG("Failed expanding user.sasl.mech");
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		if (inst->user_sasl.proxy) {
			if (tmpl_expand(&sasl.proxy, sasl_proxy_buff, sizeof(sasl_proxy_buff), request,
					inst->user_sasl.proxy, fr_ldap_escape_func, inst) < 0) {
				RPEDEBUG("Failed expanding user.sasl.proxy");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		}

		if (inst->user_sasl.realm) {
			if (tmpl_expand(&sasl.realm, sasl_realm_buff, sizeof(sasl_realm_buff), request,
					inst->user_sasl.realm, fr_ldap_escape_func, inst) < 0) {
				RPEDEBUG("Failed expanding user.sasl.realm");
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		}
	}

	RDEBUG2("Login attempt by \"%pV\"", &username->data);

	/*
	 *	Get the DN by doing a search.
	 */
	dn = rlm_ldap_find_user(inst, request, ttrunk, NULL, false, NULL, NULL, &rcode);
	if (!dn) RETURN_MODULE_RCODE(rcode);

	/*
	 *	Attempt a bind using the thread specific connection for bind auths
	 */
	if (fr_ldap_bind_auth_async(request, thread, dn, password->vp_strvalue) < 0) RETURN_MODULE_FAIL;

	rcode = unlang_interpret_synchronous(unlang_interpret_event_list(request), request);

finish:

	RETURN_MODULE_RCODE(rcode);
}

/** Search for and apply an LDAP profile
 *
 * LDAP profiles are mapped using the same attribute map as user objects, they're used to add common
 * sets of attributes to the request.
 *
 * @param[out] p_result		the result of applying the profile.
 * @param[in] inst		rlm_ldap configuration.
 * @param[in] request		Current request.
 * @param[in] ttrunk		to use.
 * @param[in] dn		of profile object to apply.
 * @param[in] expanded		Structure containing a list of xlat
 *				expanded attribute names and mapping information.
 * @return One of the RLM_MODULE_* values.
 */
static unlang_action_t rlm_ldap_map_profile(rlm_rcode_t *p_result, rlm_ldap_t const *inst,
					    request_t *request, fr_ldap_thread_trunk_t *ttrunk,
					    char const *dn, fr_ldap_map_exp_t const *expanded)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	LDAPMessage	*entry = NULL;
	int		ldap_errno;
	LDAP		*handle;
	char const	*filter;
	char		filter_buff[LDAP_MAX_FILTER_STR_LEN];
	fr_ldap_query_t	*query;

	fr_assert(inst->profile_filter); 	/* We always have a default filter set */

	if (!dn || !*dn) RETURN_MODULE_OK;

	if (tmpl_expand(&filter, filter_buff, sizeof(filter_buff), request,
			inst->profile_filter, fr_ldap_escape_func, NULL) < 0) {
		REDEBUG("Failed creating profile filter");

		RETURN_MODULE_INVALID;
	}

	if (fr_ldap_trunk_search(&rcode,
				 unlang_interpret_frame_talloc_ctx(request), &query, request, ttrunk, dn,
				 LDAP_SCOPE_BASE, filter, expanded->attrs, NULL, NULL, false) < 0) RETURN_MODULE_FAIL;
	switch (rcode) {
	case RLM_MODULE_OK:
		break;

	case RLM_MODULE_NOTFOUND:
		RDEBUG2("Profile object \"%s\" not found", dn);
		RETURN_MODULE_NOTFOUND;

	default:
		RETURN_MODULE_FAIL;
	}

	fr_assert(query->result);
	handle = query->ldap_conn->handle;

	entry = ldap_first_entry(handle, query->result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		RETURN_MODULE_RCODE(RLM_MODULE_NOTFOUND);
	}

	RDEBUG2("Processing profile attributes");
	RINDENT();
	if (fr_ldap_map_do(request, inst->valuepair_attr, expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;
	REXDENT();

	RETURN_MODULE_RCODE(rcode);
}

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const 	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	int			ldap_errno;
	int			i;
	struct berval		**values;
	fr_ldap_thread_trunk_t	*ttrunk;
	LDAP			*handle;
	LDAPMessage		*result, *entry;
	char const 		*dn = NULL;
	fr_ldap_map_exp_t	expanded; /* faster than allocing every time */

	/*
	 *	Don't be tempted to add a check for User-Name or
	 *	User-Password here.  LDAP authorization can be used
	 *	for many things besides searching for users.
	 */

	if (fr_ldap_map_expand(&expanded, request, &inst->user_map) < 0) RETURN_MODULE_FAIL;

	ttrunk =  fr_thread_ldap_trunk_get(thread, inst->handle_config.server, inst->handle_config.admin_identity,
					   inst->handle_config.admin_password, request, &inst->handle_config);
	if (!ttrunk) RETURN_MODULE_FAIL;

	/*
	 *	Add any additional attributes we need for checking access, memberships, and profiles
	 */
	if (inst->userobj_access_attr) {
		expanded.attrs[expanded.count++] = inst->userobj_access_attr;
	}

	if (inst->userobj_membership_attr && (inst->cacheable_group_dn || inst->cacheable_group_name)) {
		expanded.attrs[expanded.count++] = inst->userobj_membership_attr;
	}

	if (inst->profile_attr) {
		expanded.attrs[expanded.count++] = inst->profile_attr;
	}

	if (inst->valuepair_attr) {
		expanded.attrs[expanded.count++] = inst->valuepair_attr;
	}

	expanded.attrs[expanded.count] = NULL;

	dn = rlm_ldap_find_user(inst, request, ttrunk, expanded.attrs, true, &result, &handle, &rcode);
	if (!dn) {
		goto finish;
	}

	entry = ldap_first_entry(handle, result);
	if (!entry) {
		ldap_get_option(handle, LDAP_OPT_RESULT_CODE, &ldap_errno);
		REDEBUG("Failed retrieving entry: %s", ldap_err2string(ldap_errno));

		goto finish;
	}

	/*
	 *	Check for access.
	 */
	if (inst->userobj_access_attr) {
		rcode = rlm_ldap_check_access(inst, request, entry);
		if (rcode != RLM_MODULE_OK) {
			goto finish;
		}
	}

	/*
	 *	Check if we need to cache group memberships
	 */
	if (inst->cacheable_group_dn || inst->cacheable_group_name) {
		if (inst->userobj_membership_attr) {
			rlm_ldap_cacheable_userobj(&rcode, inst, request, ttrunk, entry, inst->userobj_membership_attr);
			if (rcode != RLM_MODULE_OK) {
				goto finish;
			}
		}

		rlm_ldap_cacheable_groupobj(&rcode, inst, request, ttrunk);
		if (rcode != RLM_MODULE_OK) {
			goto finish;
		}
	}

#ifdef WITH_EDIR
	/*
	 *	We already have a Password.Cleartext.  Skip edir.
	 */
	if (fr_pair_find_by_da(&request->control_pairs, NULL, attr_cleartext_password)) goto skip_edir;

	/*
	 *      Retrieve Universal Password if we use eDirectory
	 */
	if (inst->edir) {
		fr_pair_t	*vp;
		int		res = 0;
		char		password[256];
		size_t		pass_size = sizeof(password);

		/*
		 *	Retrive universal password
		 */
		res = fr_ldap_edir_get_password(handle, dn, password, &pass_size);
		if (res != 0) {
			REDEBUG("Failed to retrieve eDirectory password: (%i) %s", res, fr_ldap_edir_errstr(res));
			rcode = RLM_MODULE_FAIL;

			goto finish;
		}

		/*
		 *	Add Password.Cleartext attribute to the request
		 */
		MEM(pair_update_control(&vp, attr_cleartext_password) >= 0);
		fr_pair_value_bstrndup(vp, password, pass_size, true);

		if (RDEBUG_ENABLED3) {
			RDEBUG3("Added eDirectory password.  control.%pP", vp);
		} else {
			RDEBUG2("Added eDirectory password");
		}

		if (inst->edir_autz) {
			RDEBUG2("Binding as user for eDirectory authorization checks");
			/*
			 *	Bind as the user
			 */
			if (fr_ldap_bind_auth_async(request, thread, dn, vp->vp_strvalue) < 0) {
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}

			rcode = unlang_interpret_synchronous(unlang_interpret_event_list(request), request);

			if (rcode != RLM_MODULE_OK) goto finish;
		}
	}

skip_edir:
#endif

	/*
	 *	Apply ONE user profile, or a default user profile.
	 */
	if (inst->default_profile) {
		char const	*profile;
		char		profile_buff[1024];
		rlm_rcode_t	ret;

		if (tmpl_expand(&profile, profile_buff, sizeof(profile_buff),
				request, inst->default_profile, NULL, NULL) < 0) {
			REDEBUG("Failed creating default profile string");

			rcode = RLM_MODULE_INVALID;
			goto finish;
		}

		rlm_ldap_map_profile(&ret, inst, request, ttrunk, profile, &expanded);
		switch (ret) {
		case RLM_MODULE_INVALID:
			rcode = RLM_MODULE_INVALID;
			goto finish;

		case RLM_MODULE_FAIL:
			rcode = RLM_MODULE_FAIL;
			goto finish;

		case RLM_MODULE_UPDATED:
			rcode = RLM_MODULE_UPDATED;
			FALL_THROUGH;
		default:
			break;
		}
	}

	/*
	 *	Apply a SET of user profiles.
	 */
	if (inst->profile_attr) {
		values = ldap_get_values_len(handle, entry, inst->profile_attr);
		if (values != NULL) {
			for (i = 0; values[i] != NULL; i++) {
				rlm_rcode_t ret;
				char *value;

				value = fr_ldap_berval_to_string(request, values[i]);
				rlm_ldap_map_profile(&ret, inst, request, ttrunk, value, &expanded);
				talloc_free(value);
				if (ret == RLM_MODULE_FAIL) {
					ldap_value_free_len(values);
					rcode = ret;
					goto finish;
				}

			}
			ldap_value_free_len(values);
		}
	}

	if (!map_list_empty(&inst->user_map) || inst->valuepair_attr) {
		RDEBUG2("Processing user attributes");
		RINDENT();
		if (fr_ldap_map_do(request, inst->valuepair_attr,
				   &expanded, entry) > 0) rcode = RLM_MODULE_UPDATED;
		REXDENT();
		rlm_ldap_check_reply(mctx, request, ttrunk);
	}

finish:
	talloc_free(expanded.ctx);

	RETURN_MODULE_RCODE(rcode);
}

/** Modify user's object in LDAP
 *
 * Process a modifcation map to update a user object in the LDAP directory.
 *
 * @param[out] p_result		the result of the modification.
 * @param[in] inst		rlm_ldap instance.
 * @param[in] request		Current request.
 * @param[in] section		that holds the map to process.
 * @return one of the RLM_MODULE_* values.
 */
static unlang_action_t user_modify(rlm_rcode_t *p_result, rlm_ldap_t const *inst,
				   request_t *request, ldap_acct_section_t *section)
{
	rlm_rcode_t	rcode = RLM_MODULE_OK;
	fr_ldap_thread_t	*thread = talloc_get_type_abort(module_rlm_thread_by_data(inst)->data, fr_ldap_thread_t);

	fr_ldap_thread_trunk_t	*ttrunk = NULL;
	fr_ldap_query_t		*query = NULL;

	LDAPMod		*mod_p[LDAP_MAX_ATTRMAP + 1], mod_s[LDAP_MAX_ATTRMAP];
	LDAPMod		**modify = mod_p;

	char		*passed[LDAP_MAX_ATTRMAP * 2];
	int		i, total = 0, last_pass = 0;

	char 		*expanded[LDAP_MAX_ATTRMAP];
	int		last_exp = 0;

	char const	*attr;
	char const	*value;

	char const	*dn;
	/*
	 *	Build our set of modifications using the update sections in
	 *	the config.
	 */
	CONF_ITEM  	*ci;
	CONF_PAIR	*cp;
	CONF_SECTION 	*cs;
	fr_token_t	op;
	char		path[FR_MAX_STRING_LEN];

	char		*p = path;

	fr_assert(section);

	/*
	 *	Locate the update section were going to be using
	 */
	if (section->reference[0] != '.') {
		*p++ = '.';
	}

	if (xlat_eval(p, (sizeof(path) - (p - path)) - 1, request, section->reference, NULL, NULL) < 0) {
		goto error;
	}

	ci = cf_reference_item(NULL, section->cs, path);
	if (!ci) {
		goto error;
	}

	if (!cf_item_is_section(ci)){
		REDEBUG("Reference must resolve to a section");

		goto error;
	}

	cs = cf_section_find(cf_item_to_section(ci), "update", NULL);
	if (!cs) {
		REDEBUG("Section must contain 'update' subsection");

		goto error;
	}

	/*
	 *	Iterate over all the pairs, building our mods array
	 */
	for (ci = cf_item_next(cs, NULL); ci != NULL; ci = cf_item_next(cs, ci)) {
		bool do_xlat = false;

		if (total == LDAP_MAX_ATTRMAP) {
			REDEBUG("Modify map size exceeded");

			goto error;
		}

		if (!cf_item_is_pair(ci)) {
			REDEBUG("Entry is not in \"ldap-attribute = value\" format");

			goto error;
		}

		/*
		 *	Retrieve all the information we need about the pair
		 */
		cp = cf_item_to_pair(ci);
		value = cf_pair_value(cp);
		attr = cf_pair_attr(cp);
		op = cf_pair_operator(cp);

		if (!value || (*value == '\0')) {
			RDEBUG2("Empty value string, skipping attribute \"%s\"", attr);

			continue;
		}

		switch (cf_pair_value_quote(cp)) {
		case T_BARE_WORD:
		case T_SINGLE_QUOTED_STRING:
			break;

		case T_BACK_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			do_xlat = true;
			break;

		default:
			fr_assert(0);
			goto error;
		}

		if (op == T_OP_CMP_FALSE) {
			passed[last_pass] = NULL;
		} else if (do_xlat) {
			char *exp = NULL;

			if (xlat_aeval(request, &exp, request, value, NULL, NULL) <= 0) {
				RDEBUG2("Skipping attribute \"%s\"", attr);

				talloc_free(exp);

				continue;
			}

			expanded[last_exp++] = exp;
			passed[last_pass] = exp;
		/*
		 *	Static strings
		 */
		} else {
			memcpy(&(passed[last_pass]), &value, sizeof(passed[last_pass]));
		}

		passed[last_pass + 1] = NULL;

		mod_s[total].mod_values = &(passed[last_pass]);

		last_pass += 2;

		switch (op) {
		/*
		 *  T_OP_EQ is *NOT* supported, it is impossible to
		 *  support because of the lack of transactions in LDAP
		 */
		case T_OP_ADD_EQ:
			mod_s[total].mod_op = LDAP_MOD_ADD;
			break;

		case T_OP_SET:
			mod_s[total].mod_op = LDAP_MOD_REPLACE;
			break;

		case T_OP_SUB_EQ:
		case T_OP_CMP_FALSE:
			mod_s[total].mod_op = LDAP_MOD_DELETE;
			break;

		case T_OP_INCRM:
			mod_s[total].mod_op = LDAP_MOD_INCREMENT;
			break;

		default:
			REDEBUG("Operator '%s' is not supported for LDAP modify operations",
				fr_table_str_by_value(fr_tokens_table, op, "<INVALID>"));

			goto error;
		}

		/*
		 *	Now we know the value is ok, copy the pointers into
		 *	the ldapmod struct.
		 */
		memcpy(&(mod_s[total].mod_type), &attr, sizeof(mod_s[total].mod_type));

		mod_p[total] = &(mod_s[total]);
		total++;
	}

	if (total == 0) {
		rcode = RLM_MODULE_NOOP;
		goto release;
	}

	mod_p[total] = NULL;

	MEM(ttrunk = fr_thread_ldap_trunk_get(thread, inst->handle_config.server, inst->handle_config.admin_identity,
					      inst->handle_config.admin_password, request, &inst->handle_config));


	dn = rlm_ldap_find_user(inst, request, ttrunk, NULL, false, NULL, NULL, &rcode);
	if (!dn || (rcode != RLM_MODULE_OK)) {
		goto error;
	}

	if (fr_ldap_trunk_modify(&rcode, unlang_interpret_frame_talloc_ctx(request),
				 &query, request, ttrunk,
				 dn, modify, NULL, NULL, false) < 0 ){
		rcode = RLM_MODULE_FAIL;
		goto error;
	}
	switch (rcode) {
	case RLM_MODULE_OK:
		break;

	case RLM_MODULE_NOTFOUND:
		rcode = RLM_MODULE_INVALID;
		break;

	default:
		rcode = RLM_MODULE_FAIL;
		break;
	};

release:
error:
	/*
	 *	Free up any buffers we allocated for xlat expansion
	 */
	for (i = 0; i < last_exp; i++) talloc_free(expanded[i]);

	RETURN_MODULE_RCODE(rcode);
}

static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);

	if (inst->accounting) return user_modify(p_result, inst, request, inst->accounting);

	RETURN_MODULE_NOOP;
}

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ldap_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_ldap_t);

	if (inst->postauth) return user_modify(p_result, inst, request, inst->postauth);

	RETURN_MODULE_NOOP;
}


/** Detach from the LDAP server and cleanup internal state.
 *
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_ldap_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);

	if (inst->userobj_sort_ctrl) ldap_control_free(inst->userobj_sort_ctrl);

	fr_pool_free(inst->pool);

	return 0;
}

/** Parse an accounting sub section.
 *
 * Allocate a new ldap_acct_section_t and write the config data into it.
 *
 * @param[in] mctx rlm_ldap configuration.
 * @param[in] parent of the config section.
 * @param[out] config to write the sub section parameters to.
 * @param[in] comp The section name were parsing the config for.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int parse_sub_section(module_inst_ctx_t const *mctx,
			     CONF_SECTION *parent, ldap_acct_section_t **config,
			     rlm_components_t comp)
{
	rlm_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	CONF_SECTION 	*cs;

	char const *name = section_type_value[comp];

	cs = cf_section_find(parent, name, NULL);
	if (!cs) {
		DEBUG2("rlm_ldap (%s) - Couldn't find configuration for %s, will return NOOP for calls "
		       "from this section", mctx->inst->name, name);

		return 0;
	}

	if (cf_section_rules_push(cs, acct_section_config) < 0) return -1;

	*config = talloc_zero(inst, ldap_acct_section_t);
	if (cf_section_parse(*config, *config, cs) < 0) {
		PERROR("rlm_ldap (%s) - Failed parsing configuration for section %s", mctx->inst->name, name);

		return -1;
	}

	(*config)->cs = cs;

	return 0;
}

/** Initialise thread specific data structure
 *
 */
static int mod_thread_instatiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_ldap_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	fr_ldap_thread_t	*t = talloc_get_type_abort(mctx->thread, fr_ldap_thread_t);
	fr_ldap_thread_trunk_t	*ttrunk;

	/*
	 *	Initialise tree for connection trunks used by this thread
	 */
	MEM(t->trunks = fr_rb_inline_talloc_alloc(t, fr_ldap_thread_trunk_t, node, fr_ldap_trunk_cmp, NULL));

	t->config = &inst->handle_config;
	t->trunk_conf = &inst->trunk_conf;
	t->el = mctx->el;

	/*
	 *	Launch trunk for module default connection
	 */
	ttrunk = fr_thread_ldap_trunk_get(t, inst->handle_config.server, inst->handle_config.admin_identity,
					  inst->handle_config.admin_password, NULL, &inst->handle_config);
	if (!ttrunk) {
		ERROR("Unable to launch LDAP trunk");
		return -1;
	}

	/*
	 *	Set up a per-thread LDAP connection to use for bind auths
	 */
	t->conn = fr_ldap_connection_state_alloc(t, mctx->el, t->config, mctx->inst->name);
	fr_connection_add_watch_post(t->conn, FR_CONNECTION_STATE_CONNECTED, _ldap_async_bind_auth_watch, false, t);
	fr_connection_signal_init(t->conn);

	MEM(t->binds = fr_rb_inline_talloc_alloc(t, fr_ldap_bind_auth_ctx_t, node, fr_ldap_bind_auth_cmp, NULL));

	return 0;
}

/** Clean up thread specific data structure
 *
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	fr_ldap_thread_t	*t = talloc_get_type_abort(mctx->thread, fr_ldap_thread_t);
	void			**trunks_to_free;
	int			i;

	if (fr_rb_flatten_inorder(NULL, &trunks_to_free, t->trunks) < 0) return -1;

	for (i = talloc_array_length(trunks_to_free) - 1; i >= 0; i--) talloc_free(trunks_to_free[i]);
	talloc_free(trunks_to_free);
	talloc_free(t->trunks);

	return 0;
}

/** Bootstrap the module
 *
 * Define attributes.
 *
 * @param[in] mctx configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	CONF_SECTION	*conf = mctx->inst->conf;
	char		buffer[256];
	char const	*group_attribute;
	xlat_t		*xlat;

	inst->handle_config.name = talloc_typed_asprintf(inst, "rlm_ldap (%s)", mctx->inst->name);

	if (inst->group_attribute) {
		group_attribute = inst->group_attribute;
	} else if (cf_section_name2(conf)) {
		snprintf(buffer, sizeof(buffer), "%s-LDAP-Group", mctx->inst->name);
		group_attribute = buffer;
	} else {
		group_attribute = "LDAP-Group";
	}

	if (paircmp_register_by_name(group_attribute, attr_user_name, false, rlm_ldap_groupcmp, inst) < 0) {
		PERROR("Error registering group comparison");
		goto error;
	}

	inst->group_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), group_attribute);

	/*
	 *	Setup the cache attribute
	 */
	if (inst->cache_attribute) {
		fr_dict_attr_flags_t	flags;

		memset(&flags, 0, sizeof(flags));
		if (fr_dict_attr_add(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
				     inst->cache_attribute, -1, FR_TYPE_STRING, &flags) < 0) {
			PERROR("Error creating cache attribute");
		error:
			return -1;

		}
		inst->cache_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), inst->cache_attribute);
	} else {
		inst->cache_da = inst->group_da;	/* Default to the group_da */
	}

	xlat = xlat_register_module(NULL, mctx, mctx->inst->name, ldap_xlat, NULL);
	xlat_func_mono(xlat, &ldap_xlat_arg);

	xlat = xlat_register_module(NULL, mctx, "ldap_escape", ldap_escape_xlat, XLAT_FLAG_PURE);
	if (xlat) xlat_func_mono(xlat, &ldap_escape_xlat_arg);
	xlat = xlat_register_module(NULL, mctx, "ldap_unescape", ldap_unescape_xlat, XLAT_FLAG_PURE);
	if (xlat) xlat_func_mono(xlat, &ldap_escape_xlat_arg);

	map_proc_register(inst, mctx->inst->name, mod_map_proc, ldap_map_verify, 0);

	return 0;
}

/** Instantiate the module
 *
 * Creates a new instance of the module reading parameters from a configuration section.
 *
 * @param [in] mctx configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	size_t		i;

	CONF_SECTION	*options, *update;
	rlm_ldap_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_ldap_t);
	CONF_SECTION	*conf = mctx->inst->conf;

	map_list_init(&inst->user_map);

	options = cf_section_find(conf, "options", NULL);
	if (!options || !cf_pair_find(options, "chase_referrals")) {
		inst->handle_config.chase_referrals_unset = true;	 /* use OpenLDAP defaults */
	}

	/*
	 *	If the configuration parameters can't be parsed, then fail.
	 */
	if ((parse_sub_section(mctx, conf, &inst->accounting, MOD_ACCOUNTING) < 0) ||
	    (parse_sub_section(mctx, conf, &inst->postauth, MOD_POST_AUTH) < 0)) {
		cf_log_err(conf, "Failed parsing configuration");

		goto error;
	}

	/*
	 *	Sanity checks for cacheable groups code.
	 */
	if (inst->cacheable_group_name && inst->groupobj_membership_filter) {
		if (!inst->groupobj_name_attr) {
			cf_log_err(conf, "Configuration item 'group.name_attribute' must be set if cacheable "
				      "group names are enabled");

			goto error;
		}
	}

	/*
	 *	If we have a *pair* as opposed to a *section*
	 *	then the module is referencing another ldap module's
	 *	connection pool.
	 */
	if (!cf_pair_find(conf, "pool")) {
		if (!inst->handle_config.server_str) {
			cf_log_err(conf, "Configuration item 'server' must have a value");
			goto error;
		}
	}

#ifndef WITH_SASL
	if (inst->user_sasl.mech) {
		cf_log_err(conf, "Configuration item 'user.sasl.mech' not supported.  "
			   "Linked libldap does not provide ldap_sasl_bind( function");
		goto error;
	}

	if (inst->handle_config.admin_sasl.mech) {
		cf_log_err(conf, "Configuration item 'sasl.mech' not supported.  "
			   "Linked libldap does not provide ldap_sasl_interactive_bind function");
		goto error;
	}
#endif

	/*
	 *	Initialise server with zero length string to
	 *	make code below simpler.
	 */
	inst->handle_config.server = talloc_strdup(inst, "");

	/*
	 *	Now iterate over all the 'server' config items
	 */
	for (i = 0; i < talloc_array_length(inst->handle_config.server_str); i++) {
		char const *value = inst->handle_config.server_str[i];
		size_t j;

		/*
		 *	Explicitly prevent multiple server definitions
		 *	being used in the same string.
		 */
		for (j = 0; j < talloc_array_length(value) - 1; j++) {
			switch (value[j]) {
			case ' ':
			case ',':
			case ';':
				cf_log_err(conf, "Invalid character '%c' found in 'server' configuration item",
					      value[j]);
				goto error;

			default:
				continue;
			}
		}

		/*
		 *	Split original server value out into URI, server and port
		 *	so whatever initialization function we use later will have
		 *	the server information in the format it needs.
		 */
		if (ldap_is_ldap_url(value)) {
			if (fr_ldap_server_url_check(&inst->handle_config, value, conf) < 0) return -1;
		} else
		/*
		 *	If it's not an URL, then just treat server as a hostname.
		 */
		{
			if (fr_ldap_server_config_check(&inst->handle_config, value, conf) < 0) return -1;
		}
	}

	/*
	 *	inst->handle_config.server be unset if connection pool sharing is used.
	 */
	if (inst->handle_config.server) {
		inst->handle_config.server[talloc_array_length(inst->handle_config.server) - 2] = '\0';
		DEBUG4("rlm_ldap (%s) - LDAP server string: %s", mctx->inst->name, inst->handle_config.server);
	}

	/*
	 *	Workaround for servers which support LDAPS but not START TLS
	 */
	if (inst->handle_config.port == LDAPS_PORT || inst->handle_config.tls_mode) {
		inst->handle_config.tls_mode = LDAP_OPT_X_TLS_HARD;
	} else {
		inst->handle_config.tls_mode = 0;
	}

	/*
	 *	Convert dereference strings to enumerated constants
	 */
	if (inst->handle_config.dereference_str) {
		inst->handle_config.dereference = fr_table_value_by_str(fr_ldap_dereference,
							     inst->handle_config.dereference_str, -1);
		if (inst->handle_config.dereference < 0) {
			cf_log_err(conf, "Invalid 'dereference' value \"%s\", expected 'never', 'searching', "
				      "'finding' or 'always'", inst->handle_config.dereference_str);
			goto error;
		}
	}

	/*
	 *	Convert scope strings to enumerated constants
	 */
	inst->userobj_scope = fr_table_value_by_str(fr_ldap_scope, inst->userobj_scope_str, -1);
	if (inst->userobj_scope < 0) {
		cf_log_err(conf, "Invalid 'user.scope' value \"%s\", expected 'sub', 'one', 'base' or 'children'",
			   inst->userobj_scope_str);
		goto error;
	}

	inst->groupobj_scope = fr_table_value_by_str(fr_ldap_scope, inst->groupobj_scope_str, -1);
	if (inst->groupobj_scope < 0) {
		cf_log_err(conf, "Invalid 'group.scope' value \"%s\", expected 'sub', 'one', 'base' or 'children'",
			   inst->groupobj_scope_str);
		goto error;
	}

	/*
	 *	Build the server side sort control for user objects
	 */
	if (inst->userobj_sort_by) {
		LDAPSortKey	**keys;
		int		ret;

		ret = ldap_create_sort_keylist(&keys, UNCONST(char *, inst->userobj_sort_by));
		if (ret != LDAP_SUCCESS) {
			cf_log_err(conf, "Invalid user.sort_by value \"%s\": %s",
				      inst->userobj_sort_by, ldap_err2string(ret));
			goto error;
		}

		/*
		 *	Always set the control as critical, if it's not needed
		 *	the user can comment it out...
		 */
		ret = ldap_create_sort_control(ldap_global_handle, keys, 1, &inst->userobj_sort_ctrl);
		ldap_free_sort_keylist(keys);
		if (ret != LDAP_SUCCESS) {
			ERROR("Failed creating server sort control: %s", ldap_err2string(ret));
			goto error;
		}
	}

	if (inst->handle_config.tls_require_cert_str) {
		/*
		 *	Convert cert strictness to enumerated constants
		 */
		inst->handle_config.tls_require_cert = fr_table_value_by_str(fr_ldap_tls_require_cert,
							      inst->handle_config.tls_require_cert_str, -1);
		if (inst->handle_config.tls_require_cert < 0) {
			cf_log_err(conf, "Invalid 'tls.require_cert' value \"%s\", expected 'never', "
				      "'demand', 'allow', 'try' or 'hard'", inst->handle_config.tls_require_cert_str);
			goto error;
		}
	}

	if (inst->handle_config.tls_min_version_str) {
		if (strcmp(inst->handle_config.tls_min_version_str, "1.2") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_2;

		} else if (strcmp(inst->handle_config.tls_min_version_str, "1.1") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_1;

		} else if (strcmp(inst->handle_config.tls_min_version_str, "1.0") == 0) {
			inst->handle_config.tls_min_version = LDAP_OPT_X_TLS_PROTOCOL_TLS1_0;

		} else {
			cf_log_err(conf, "Invalid 'tls.tls_min_version' value \"%s\"", inst->handle_config.tls_min_version_str);
			goto error;
		}
	}

	/*
	 *	Build the attribute map
	 */
	{
		tmpl_rules_t	parse_rules = {
			.attr = {
				.allow_foreign = true	/* Because we don't know where we'll be called */
			}
		};

		update = cf_section_find(conf, "update", NULL);
		if (update && (map_afrom_cs(inst, &inst->user_map, update,
					    &parse_rules, &parse_rules, fr_ldap_map_verify, NULL,
					    LDAP_MAX_ATTRMAP) < 0)) {
			return -1;
		}
	}

	return 0;

error:
	return -1;
}

/* globally exported name */
extern module_rlm_t rlm_ldap;
module_rlm_t rlm_ldap = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "ldap",
		.type		= 0,
		.inst_size	= sizeof(rlm_ldap_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,
		.thread_inst_size	= sizeof(fr_ldap_thread_t),
		.thread_inst_type	= "fr_ldap_thread_t",
		.thread_instantiate	= mod_thread_instatiate,
		.thread_detach		= mod_thread_detach,
	},
	.method_names = (module_method_name_t[]){
		/*
		 *	Hack to support old configurations
		 */
		{ .name1 = "authorize",		.name2 = CF_IDENT_ANY,		.method = mod_authorize		},

		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize		},
		{ .name1 = "accounting",	.name2 = CF_IDENT_ANY,		.method = mod_accounting	},
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate	},
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_post_auth		},
		MODULE_NAME_TERMINATOR
	}
};
