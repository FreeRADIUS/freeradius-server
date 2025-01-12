/*
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
 */

/**
 * $Id$
 * @file rlm_krb5.c
 * @brief Authenticate users, retrieving their TGT from a Kerberos V5 TDC.
 *
 * @copyright 2000,2006,2012-2013 The FreeRADIUS server project
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000 Nathan Neulinger (nneul@umr.edu)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/util/debug.h>
#include "krb5.h"

#ifdef KRB5_IS_THREAD_SAFE
static const conf_parser_t reuse_krb5_config[] = {
	FR_SLAB_CONFIG_CONF_PARSER
	CONF_PARSER_TERMINATOR
};
#endif

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("keytab", rlm_krb5_t, keytabname) },
	{ FR_CONF_OFFSET("service_principal", rlm_krb5_t, service_princ) },
#ifdef KRB5_IS_THREAD_SAFE
	{ FR_CONF_OFFSET_SUBSECTION("reuse", 0, rlm_krb5_t, reuse, reuse_krb5_config) },
#endif
	CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_value_box_t	username;
	fr_value_box_t	password;
} krb5_auth_call_env_t;

#ifdef KRB5_IS_THREAD_SAFE
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_krb5_t 		*inst = talloc_get_type_abort(mctx->mi->data, rlm_krb5_t);
	rlm_krb5_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_krb5_thread_t);

	t->inst = inst;
	if (!(t->slab = krb5_slab_list_alloc(t, mctx->el, &inst->reuse, krb5_handle_init, NULL, inst, false, true))) {
		ERROR("Handle pool instantiation failed");
		return -1;
	}

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_krb5_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_krb5_thread_t);
	talloc_free(t->slab);
	return 0;
}
#endif

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_krb5_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_krb5_t);

#ifndef HEIMDAL_KRB5
	talloc_free(inst->vic_options);

	if (inst->gic_options) krb5_get_init_creds_opt_free(inst->context, inst->gic_options);
	if (inst->server) krb5_free_principal(inst->context, inst->server);
#endif

	/* Don't free hostname, it's just a pointer into service_princ */
	talloc_free(inst->service);

	if (inst->context) krb5_free_context(inst->context);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_krb5_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_krb5_t);
	krb5_error_code ret;
#ifndef HEIMDAL_KRB5
	krb5_keytab keytab;
	char keytab_name[200];
	char *princ_name;
#endif

#ifdef HEIMDAL_KRB5
	DEBUG("Using Heimdal Kerberos library");
#else
	DEBUG("Using MIT Kerberos library");
#endif


	if (!krb5_is_thread_safe()) {
/*
 *	rlm_krb5 was built as threadsafe
 */
#ifdef KRB5_IS_THREAD_SAFE
		ERROR("Build time libkrb5 was threadsafe, but run time library claims not to be");
		ERROR("Modify runtime linker path (LD_LIBRARY_PATH on most systems), to prefer threadsafe libkrb5");
		return -1;
/*
 *	rlm_krb5 was not built as threadsafe
 */
#else
		fr_log(&default_log, L_WARN, __FILE__, __LINE__,
		       "libkrb5 is not threadsafe, recompile it with thread support enabled ("
#  ifdef HEIMDAL_KRB5
		       "--enable-pthread-support"
#  else
		       "--disable-thread-support=no"
#  endif
		       ")");
		WARN("rlm_krb5 will run in single threaded mode, performance may be degraded");
	} else {
		WARN("Build time libkrb5 was not threadsafe, but run time library claims to be");
		WARN("Reconfigure and recompile rlm_krb5 to enable thread support");
#endif
	}

	ret = krb5_init_context(&inst->context);
	if (ret) {
		ERROR("Context initialisation failed: %s", rlm_krb5_error(inst, NULL, ret));

		return -1;
	}

	/*
	 *	Split service principal into service and host components
	 *	they're needed to build the server principal in MIT,
	 *	and to set the validation service in Heimdal.
	 */
	if (inst->service_princ) {
		size_t len;
		/* Service principal appears to contain a host component */
		inst->hostname = strchr(inst->service_princ, '/');
		if (inst->hostname) {
			len = (inst->hostname - inst->service_princ);
			inst->hostname++;
		} else {
			len = strlen(inst->service_princ);
		}

		if (len) {
			inst->service = talloc_array(inst, char, (len + 1));
			strlcpy(inst->service, inst->service_princ, len + 1);
		}
	}

#ifdef HEIMDAL_KRB5
	if (inst->hostname) DEBUG("Ignoring hostname component of service principal \"%s\", not "
				  "needed/supported by Heimdal", inst->hostname);
#else

	/*
	 *	Convert the service principal string to a krb5 principal.
	 */
	ret = krb5_sname_to_principal(inst->context, inst->hostname, inst->service, KRB5_NT_SRV_HST, &(inst->server));
	if (ret) {
		ERROR("Failed parsing service principal: %s", rlm_krb5_error(inst, inst->context, ret));

		return -1;
	}

	ret = krb5_unparse_name(inst->context, inst->server, &princ_name);
	if (ret) {
		/* Uh? */
		ERROR("Failed constructing service principal string: %s", rlm_krb5_error(inst, inst->context, ret));

		return -1;
	}

	/*
	 *	Not necessarily the same as the config item
	 */
	DEBUG("Using service principal \"%s\"", princ_name);
	krb5_free_unparsed_name(inst->context, princ_name);

	/*
	 *	Setup options for getting credentials and verifying them
	 */
	ret = krb5_get_init_creds_opt_alloc(inst->context, &(inst->gic_options)); /* For some reason the 'init' version
										    of this function is deprecated */
	if (ret) {
		ERROR("Couldn't allocate initial credential options: %s", rlm_krb5_error(inst, inst->context, ret));

		return -1;
	}

	/*
	 *	Perform basic checks on the keytab
	 */
	ret = inst->keytabname ?
		krb5_kt_resolve(inst->context, inst->keytabname, &keytab) :
		krb5_kt_default(inst->context, &keytab);
	if (ret) {
		ERROR("Resolving keytab failed: %s", rlm_krb5_error(inst, inst->context, ret));

		return -1;
	}

	ret = krb5_kt_get_name(inst->context, keytab, keytab_name, sizeof(keytab_name));
	krb5_kt_close(inst->context, keytab);
	if (ret) {
		ERROR("Can't retrieve keytab name: %s", rlm_krb5_error(inst, inst->context, ret));

		return -1;
	}

	DEBUG("Using keytab \"%s\"", keytab_name);

	MEM(inst->vic_options = talloc_zero(inst, krb5_verify_init_creds_opt));
	krb5_verify_init_creds_opt_init(inst->vic_options);
	krb5_verify_init_creds_opt_set_ap_req_nofail(inst->vic_options, true);
#endif

#ifndef KRB5_IS_THREAD_SAFE
	inst->conn = krb5_mod_conn_create(inst, inst, fr_time_delta_wrap(0));
	if (!inst->conn) return -1;
#endif
	return 0;
}

/** Common function for transforming a User-Name string into a principal.
 *
 * @param[out] client Where to write the client principal.
 * @param[in] inst of rlm_krb5.
 * @param[in] request Current request.
 * @param[in] context Kerberos context.
 * @param[in] env call env data containing username.
 */
static rlm_rcode_t krb5_parse_user(krb5_principal *client, KRB5_UNUSED rlm_krb5_t const *inst, request_t *request,
				   krb5_context context, krb5_auth_call_env_t *env)
{
	krb5_error_code ret;
	char *princ_name;

	ret = krb5_parse_name(context, env->username.vb_strvalue, client);
	if (ret) {
		REDEBUG("Failed parsing username as principal: %s", rlm_krb5_error(inst, context, ret));

		return RLM_MODULE_FAIL;
	}

	krb5_unparse_name(context, *client, &princ_name);
	RDEBUG2("Using client principal \"%s\"", princ_name);
#ifdef HEIMDAL_KRB5
	free(princ_name);
#else
	krb5_free_unparsed_name(context, princ_name);
#endif
	return RLM_MODULE_OK;
}

/** Log error message and return appropriate rcode
 *
 * Translate kerberos error codes into return codes.
 * @param inst of rlm_krb5.
 * @param request Current request.
 * @param ret code from kerberos.
 * @param conn used in the last operation.
 */
static rlm_rcode_t krb5_process_error(rlm_krb5_t const *inst, request_t *request, rlm_krb5_handle_t *conn, int ret)
{
	fr_assert(ret != 0);

	if (!fr_cond_assert(inst)) return RLM_MODULE_FAIL;
	if (!fr_cond_assert(conn)) return RLM_MODULE_FAIL;	/* Silences warnings */

	switch (ret) {
	case KRB5_LIBOS_BADPWDMATCH:
	case KRB5KRB_AP_ERR_BAD_INTEGRITY:
		REDEBUG("Provided password was incorrect (%i): %s", ret, rlm_krb5_error(inst, conn->context, ret));
		return RLM_MODULE_REJECT;

	case KRB5KDC_ERR_KEY_EXP:
	case KRB5KDC_ERR_CLIENT_REVOKED:
	case KRB5KDC_ERR_SERVICE_REVOKED:
		REDEBUG("Account has been locked out (%i): %s", ret, rlm_krb5_error(inst, conn->context, ret));
		return RLM_MODULE_DISALLOW;

	case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
		RDEBUG2("User not found (%i): %s", ret, rlm_krb5_error(inst, conn->context, ret));
		return RLM_MODULE_NOTFOUND;

	default:
		REDEBUG("Error verifying credentials (%i): %s", ret, rlm_krb5_error(inst, conn->context, ret));
		return RLM_MODULE_FAIL;
	}
}

#ifdef HEIMDAL_KRB5

/*
 *	Validate user/pass (Heimdal)
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	krb5_auth_call_env_t	*env = talloc_get_type_abort(mctx->env_data, krb5_auth_call_env_t);
	rlm_krb5_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_krb5_t);
#  ifdef KRB5_IS_THREAD_SAFE
	rlm_krb5_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_krb5_thread_t);
#  endif
	rlm_rcode_t		rcode;
	krb5_error_code		ret;
	rlm_krb5_handle_t	*conn;
	krb5_principal		client = NULL;

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (env->password.vb_length == 0) {
		REDEBUG("User-Password must not be empty");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &env->password);
	} else {
		RDEBUG2("Login attempt with password");
	}

#  ifdef KRB5_IS_THREAD_SAFE
	conn = krb5_slab_reserve(t->slab);
	if (!conn) RETURN_MODULE_FAIL;
#  else
	conn = inst->conn;
#  endif

	rcode = krb5_parse_user(&client, inst, request, conn->context, env);
	if (rcode != RLM_MODULE_OK) goto cleanup;

	/*
	 *	Verify the user, using the options we set in instantiate
	 */
	ret = krb5_verify_user_opt(conn->context, client, env->password.vb_strvalue, &conn->options);
	if (ret) {
		rcode = krb5_process_error(inst, request, conn, ret);
		goto cleanup;
	}

	/*
	 *	krb5_verify_user_opt adds the credentials to the ccache
	 *	we specified with krb5_verify_opt_set_ccache.
	 *
	 *	To make sure we don't accumulate thousands of sets of
	 *	credentials, remove them again here.
	 *
	 * @todo This should definitely be optional, which means writing code for the MIT
	 *	 variant as well.
	 */
	{
		krb5_cc_cursor cursor;
		krb5_creds cred;

		krb5_cc_start_seq_get(conn->context, conn->ccache, &cursor);
		for (ret = krb5_cc_next_cred(conn->context, conn->ccache, &cursor, &cred);
		     ret == 0;
		     ret = krb5_cc_next_cred(conn->context, conn->ccache, &cursor, &cred)) {
		     krb5_cc_remove_cred(conn->context, conn->ccache, 0, &cred);
		}
		krb5_cc_end_seq_get(conn->context, conn->ccache, &cursor);
	}

cleanup:
	if (client) {
		krb5_free_principal(conn->context, client);
	}

#  ifdef KRB5_IS_THREAD_SAFE
	krb5_slab_release(conn);
#  endif
	RETURN_MODULE_RCODE(rcode);
}

#else  /* HEIMDAL_KRB5 */

/*
 *  Validate userid/passwd (MIT)
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	krb5_auth_call_env_t	*env = talloc_get_type_abort(mctx->env_data, krb5_auth_call_env_t);
	rlm_krb5_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_krb5_t);
#  ifdef KRB5_IS_THREAD_SAFE
	rlm_krb5_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_krb5_thread_t);
#  endif
	rlm_rcode_t		rcode;
	krb5_error_code		ret;

	rlm_krb5_handle_t	*conn;

	krb5_principal		client = NULL;	/* actually a pointer value */
	krb5_creds		init_creds;

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (env->password.vb_length == 0) {
		REDEBUG("User-Password must not be empty");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &env->password);
	} else {
		RDEBUG2("Login attempt with password");
	}

#  ifdef KRB5_IS_THREAD_SAFE
	conn = krb5_slab_reserve(t->slab);
	if (!conn) RETURN_MODULE_FAIL;
#  else
	conn = inst->conn;
#  endif

	/*
	 *	Zero out local storage
	 */
	memset(&init_creds, 0, sizeof(init_creds));

	/*
	 *	Check we have all the required VPs, and convert the username
	 *	into a principal.
	 */
	rcode = krb5_parse_user(&client, inst, request, conn->context, env);
	if (rcode != RLM_MODULE_OK) goto cleanup;

	/*
	 * 	Retrieve the TGT from the TGS/KDC and check we can decrypt it.
	 */
	RDEBUG2("Retrieving and decrypting TGT");
	ret = krb5_get_init_creds_password(conn->context, &init_creds, client, UNCONST(char *, env->password.vb_strvalue),
					   NULL, NULL, 0, NULL, inst->gic_options);
	if (ret) {
		rcode = krb5_process_error(inst, request, conn, ret);
		goto cleanup;
	}

	RDEBUG2("Attempting to authenticate against service principal");
	ret = krb5_verify_init_creds(conn->context, &init_creds, inst->server, conn->keytab, NULL, inst->vic_options);
	if (ret) rcode = krb5_process_error(inst, request, conn, ret);

cleanup:
	if (client) krb5_free_principal(conn->context, client);
	krb5_free_cred_contents(conn->context, &init_creds);

#  ifdef KRB5_IS_THREAD_SAFE
	krb5_slab_release(conn);
#  endif
	RETURN_MODULE_RCODE(rcode);
}

#endif /* MIT_KRB5 */

static const call_env_method_t krb5_auth_call_env = {
	FR_CALL_ENV_METHOD_OUT(krb5_auth_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED, krb5_auth_call_env_t, username),
			.pair.dflt = "&User-Name", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("password", FR_TYPE_STRING, CALL_ENV_FLAG_SECRET | CALL_ENV_FLAG_REQUIRED, krb5_auth_call_env_t, password),
			.pair.dflt = "&User-Password", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

extern module_rlm_t rlm_krb5;
module_rlm_t rlm_krb5 = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "krb5",
		/*
		 *	FIXME - Probably want a global mutex created on mod_load
		 */
#ifndef KRB5_IS_THREAD_SAFE
		.flags		= MODULE_TYPE_THREAD_UNSAFE,
#else
		.thread_inst_size	= sizeof(rlm_krb5_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
#endif
		.inst_size	= sizeof(rlm_krb5_t),
		.config		= module_config,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate, .method_env = &krb5_auth_call_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
