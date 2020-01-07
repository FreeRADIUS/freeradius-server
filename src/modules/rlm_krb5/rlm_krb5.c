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

#define LOG_PREFIX "rlm_krb5 (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>
#include "krb5.h"

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("keytab", FR_TYPE_STRING, rlm_krb5_t, keytabname) },
	{ FR_CONF_OFFSET("service_principal", FR_TYPE_STRING, rlm_krb5_t, service_princ) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_krb5_dict[];
fr_dict_autoload_t rlm_krb5_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_krb5_dict_attr[];
fr_dict_attr_autoload_t rlm_krb5_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static int mod_detach(void *instance)
{
	rlm_krb5_t *inst = instance;

#ifndef HEIMDAL_KRB5
	talloc_free(inst->vic_options);

	if (inst->gic_options) krb5_get_init_creds_opt_free(inst->context, inst->gic_options);
	if (inst->server) krb5_free_principal(inst->context, inst->server);
#endif

	/* Don't free hostname, it's just a pointer into service_princ */
	talloc_free(inst->service);

	if (inst->context) krb5_free_context(inst->context);
#ifdef KRB5_IS_THREAD_SAFE
	fr_pool_free(inst->pool);
#endif

	return 0;
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_krb5_t *inst = instance;
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

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

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
#endif

#ifdef KRB5_IS_THREAD_SAFE
	/*
	 *	Initialize the socket pool.
	 */
	inst->pool = module_connection_pool_init(conf, inst, krb5_mod_conn_create, NULL, NULL, NULL, NULL);
	if (!inst->pool) return -1;
#else
	inst->conn = krb5_mod_conn_create(inst, inst, 0);
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
 */
static rlm_rcode_t krb5_parse_user(krb5_principal *client, KRB5_UNUSED rlm_krb5_t const *inst, REQUEST *request,
				   krb5_context context)
{
	krb5_error_code ret;
	char *princ_name;
	VALUE_PAIR *username;

	username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	ret = krb5_parse_name(context, username->vp_strvalue, client);
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
static rlm_rcode_t krb5_process_error(rlm_krb5_t const *inst, REQUEST *request, rlm_krb5_handle_t *conn, int ret)
{
	rad_assert(ret != 0);

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
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_krb5_t const	*inst = instance;
	rlm_rcode_t		rcode;
	krb5_error_code		ret;
	rlm_krb5_handle_t	*conn;
	krb5_principal		client = NULL;
	VALUE_PAIR		*password;

	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);

	if (!password) {
		REDEBUG("Attribute \"User-Password\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (password->vp_length == 0) {
		REDEBUG("User-Password must not be empty");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &password->data);
	} else {
		RDEBUG2("Login attempt with password");
	}

#  ifdef KRB5_IS_THREAD_SAFE
	conn = fr_pool_connection_get(inst->pool, request);
	if (!conn) return RLM_MODULE_FAIL;
#  else
	conn = inst->conn;
#  endif

	rcode = krb5_parse_user(&client, inst, request, conn->context);
	if (rcode != RLM_MODULE_OK) goto cleanup;

	/*
	 *	Verify the user, using the options we set in instantiate
	 */
	ret = krb5_verify_user_opt(conn->context, client, password->vp_strvalue, &conn->options);
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
	fr_pool_connection_release(inst->pool, request, conn);
#  endif
	return rcode;
}

#else  /* HEIMDAL_KRB5 */

/*
 *  Validate userid/passwd (MIT)
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_krb5_t const	*inst = instance;
	rlm_rcode_t		rcode;
	krb5_error_code		ret;

	rlm_krb5_handle_t	*conn;

	krb5_principal		client = NULL;	/* actually a pointer value */
	krb5_creds		init_creds;
	char			*nonconst_password;		/* compiler warnings */
	VALUE_PAIR		*password;

	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);

	if (!password) {
		REDEBUG("Attribute \"User-Password\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (password->vp_length == 0) {
		REDEBUG("User-Password must not be empty");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &password->data);
	} else {
		RDEBUG2("Login attempt with password");
	}

#  ifdef KRB5_IS_THREAD_SAFE
	conn = fr_pool_connection_get(inst->pool, request);
	if (!conn) return RLM_MODULE_FAIL;
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
	rcode = krb5_parse_user(&client, inst, request, conn->context);
	if (rcode != RLM_MODULE_OK) goto cleanup;

	/*
	 * 	Retrieve the TGT from the TGS/KDC and check we can decrypt it.
	 */
	memcpy(&nonconst_password, &password->vp_strvalue, sizeof(nonconst_password));
	RDEBUG2("Retrieving and decrypting TGT");
	ret = krb5_get_init_creds_password(conn->context, &init_creds, client, nonconst_password,
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
	fr_pool_connection_release(inst->pool, request, conn);
#  endif
	return rcode;
}

#endif /* MIT_KRB5 */

extern module_t rlm_krb5;
module_t rlm_krb5 = {
	.magic		= RLM_MODULE_INIT,
	.name		= "krb5",
#ifdef KRB5_IS_THREAD_SAFE
	.type		= RLM_TYPE_THREAD_SAFE,
#endif
	.inst_size	= sizeof(rlm_krb5_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate
	},
};
