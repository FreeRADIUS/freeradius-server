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
 * @copyright 2000,2006,2012-2013  The FreeRADIUS server project
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000  Nathan Neulinger <nneul@umr.edu>
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */
#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

/* krb5 includes */
#include <krb5.h>
#include <com_err.h>

#define SERVICE_NAME_LEN 64	    //!< Maximum length of a service name.

/** Instance configuration for rlm_krb5
 *
 * Holds the configuration and preparsed data for a instance of rlm_krb5.
 */
typedef struct rlm_krb5_t {
	const char *xlat_name;	    //!< This module's instance name.
	const char *keytabname;	    //!< The keytab to resolve the service in.
	const char *service_princ;  //!< The service name provided by the 
				    //!< config parser.
	
	char *hostname;		    //!< The hostname component of 
				    //!< service_princ, or NULL.
	char *service;		    //!< The service component of 
				    //!< service_princ, or NULL.
	
	krb5_context *context;	    //!< The kerberos context (cloned once per
				    //!< request).
	
#ifndef HEIMDAL_KRB5
	krb5_get_init_creds_opt	*gic_options;	 //!< Options to pass to the
						 //!< get_initial_credentials.
						 //!< function.
	krb5_verify_init_creds_opt *vic_options; //!< Options to pass to the 
						 //!< validate_initial_creds
						 //!< function.

	krb5_principal server;	    //!< A structure representing the parsed
				    //!< service_princ.
#endif
	
} rlm_krb5_t;

static const CONF_PARSER module_config[] = {
	{ "keytab", PW_TYPE_STRING_PTR,
	  offsetof(rlm_krb5_t,keytabname), NULL, NULL },
	{ "service_principal", PW_TYPE_STRING_PTR,
	  offsetof(rlm_krb5_t,service_princ), NULL, NULL },
	{ NULL, -1, 0, NULL, NULL }
};

static int krb5_detach(void *instance)
{
	rlm_krb5_t *inst = instance;
		
#ifndef HEIMDAL_KRB5
	free(inst->vic_options);

	if (inst->gic_options) {
		krb5_get_init_creds_opt_free(*(inst->context),
					     inst->gic_options);
	}
#endif

	/* Don't free hostname, it's just a pointer into service_princ */
	free(inst->service);
		
	if (inst->context) {
		krb5_free_context(*(inst->context));
	}
	
	free(instance);

	return 0;
}

static int krb5_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_krb5_t *inst;
	krb5_error_code ret;
	
	krb5_context *context;
	char *princ_name;
	
#ifndef HEIMDAL_KRB5
	radlog(L_ERR, "rlm_krb5 (*): Using MIT Kerberos library");
#else
	radlog(L_ERR, "rlm_krb5 (*): Using Heimdal Kerberos library");
#endif
	/*
 	 *	@todo Update configure script to call krb5_is_thread_safe,
 	 *	this should really be a warning.
 	 */
	if (!krb5_is_thread_safe()) {
		radlog(L_ERR, "rlm_krb5 (*): krb5 library is not threadsafe, "
		       "please recompile it with thread support enabled");
		       
		return -1;
	}

	inst = rad_calloc(sizeof(*inst));
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}
	
	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	rad_assert(inst->xlat_name);
	
	context = inst->context = rad_calloc(sizeof(*context));
	ret = krb5_init_context(context);
	if (ret) {
		radlog(L_ERR, "rlm_krb5 (%s): Context initialisation "
		       "failed: %s", inst->xlat_name, error_message(ret));
  
		goto error;
	} else {
		radlog(L_DBG, "rlm_krb5 (%s): Context initialised "
		       "successfully", inst->xlat_name);
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
			len = SERVICE_NAME_LEN;
		}
		
		if (len) {
			inst->service = rad_malloc(len + 1);
			strlcpy(inst->service, inst->service_princ, len);
		}
	}
	
#ifndef HEIMDAL_KRB5
	/*
	 *	Convert the service principal string to a krb5 principal.
	 */
	ret = krb5_sname_to_principal(*context, inst->hostname,
				      inst->service, KRB5_NT_SRV_HST,
				      &(inst->server));
	if (ret) {
		radlog(L_ERR, "rlm_krb5 (%s): Failed parsing service "
		       "principal: %s", inst->xlat_name, error_message(ret));

		goto error;
	}
	
	ret = krb5_unparse_name(*context, inst->server, &princ_name);
	if (ret) {
		/* Uh? */
		radlog(L_ERR, "rlm_krb5 (%s): Failed constructing service "
		       "principal string: %s", inst->xlat_name,
		       error_message(ret));

		goto error;
	}
	
	/*
	 *	Not necessarily the same as the config item
	 */
	radlog(L_DBG, "rlm_krb5 (%s): Using service principal \"%s\"",
	       inst->xlat_name, princ_name);
	       
	krb5_free_unparsed_name(*context, princ_name);
	
	/*
	 *	Setup options for getting credentials and verifying them
	 */
	 
	/* For some reason the 'init' version of this function is deprecated */
	ret = krb5_get_init_creds_opt_alloc(*context, &(inst->gic_options));
	if (ret) {
		radlog(L_ERR, "rlm_krb5 (%s): Couldn't allocated inital "
		       "credential options: %s", inst->xlat_name,
		       error_message(ret));
		
		goto error;
	}
	
	inst->vic_options = rad_calloc(sizeof(*(inst->vic_options)));
	if (!inst->vic_options) goto error;
	
	krb5_verify_init_creds_opt_init(inst->vic_options);
	krb5_verify_init_creds_opt_set_ap_req_nofail(inst->vic_options,
						     TRUE);
	
#else
	if (inst->hostname) {
		radlog(L_DBG, "rlm_krb5 (%s): Ignoring hostname component of "
		       "service principal \"%s\", not needed/supported by "
		       "Heimdal", inst->xlat_name, hostname);
	}
#endif
	 
	*instance = inst;
	return 0;
	
	error:
	krb5_detach(inst);
	return -1;
}

static rlm_rcode_t krb5_parse_user(rlm_krb5_t *inst, REQUEST *request,
			   	   krb5_principal *client)
{
	krb5_error_code ret;
	char *princ_name;
	
	/*
	 * 	We can only authenticate user requests which HAVE
	 * 	a User-Name attribute.
	 */
	if (!request->username) {
		RDEBUG("Attribute \"User-Name\" is required for "
		       "authentication");
		
		return RLM_MODULE_INVALID;
	}

	/*
	 * 	We can only authenticate user requests which HAVE
	 * 	a User-Password attribute.
	 */
	if (!request->password) {
		RDEBUG("Attribute \"User-Password\" is required for "
		       "authentication");
		
		return RLM_MODULE_INVALID;
	}

	/*
	 * 	Ensure that we're being passed a plain-text password,
	 * 	and not anything else.
	 */
	if (request->password->da->attr != PW_USER_PASSWORD) {
		RDEBUG("Attribute \"User-Password\" is required for "
		       "authentication.  Cannot use \"%s\".",
		       request->password->da->name);
		
		return RLM_MODULE_INVALID;
	}
	
	ret = krb5_parse_name(*(inst->context), request->username->vp_strvalue,
			      client);
	if (ret) {
		RDEBUG("Failed parsing username as principal: %s",
		       error_message(ret));
		       
		return RLM_MODULE_FAIL;
	}

	krb5_unparse_name(*(inst->context), *client, &princ_name);
	RDEBUG("Using client principal \"%s\"", princ_name);
	krb5_free_unparsed_name(*(inst->context), princ_name);

	return RLM_MODULE_OK;
}

#ifndef HEIMDAL_KRB5

/* 
 *  Validate userid/passwd (MIT)
 */
static rlm_rcode_t krb5_auth(void *instance, REQUEST *request)
{
	rlm_krb5_t *inst = instance;
	rlm_rcode_t rcode;	
	krb5_error_code ret;

	krb5_principal client;
	krb5_creds init_creds;
	krb5_keytab keytab;
	krb5_context *context = NULL;
	
	/*
	 *	All the snippets on threadsafety say that individual threads
	 *	must each use their own copy of context.
	 *
	 *	As we don't have any per thread instantiation, we either have
	 *	to clone inst->context on every request, or use the connection
	 *	API.
	 *
	 *	@todo Use the connection API (3.0 only).
	 */
	ret = krb5_copy_context(*(inst->context), context);
	if (ret) {
		radlog(L_ERR, "rlm_krb5 (%s): Error cloning krb5 context: %s",
		       inst->xlat_name, error_message(ret));
		
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Check we have all the required VPs, and convert the username
	 *	into a principal.
	 */
	rcode = krb5_parse_user(inst, request, &client);
	if (rcode != RLM_MODULE_OK) goto cleanup;

	/*
	 * 	Retrieve the TGT from the TGS/KDC and check we can decrypt it.
	 */
	memset(&init_creds, 0, sizeof(init_creds));
	ret = krb5_get_init_creds_password(*context, &init_creds, client,
					   request->password->vp_strvalue,
					   NULL, NULL, 0, NULL,
					   inst->gic_options);
	if (ret) {
		error:
		switch (ret) {
		case KRB5_LIBOS_BADPWDMATCH:
		case KRB5KRB_AP_ERR_BAD_INTEGRITY:
			RDEBUG("Provided password was incorrect: %s",
			       error_message(ret));
			rcode = RLM_MODULE_REJECT;
			break;
			
		case KRB5KDC_ERR_KEY_EXP:
		case KRB5KDC_ERR_CLIENT_REVOKED:
		case KRB5KDC_ERR_SERVICE_REVOKED:
			RDEBUG("Account has been locked out: %s",
			       error_message(ret));
			rcode = RLM_MODULE_USERLOCK;
			break;
			
		case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
			RDEBUG("User not found: %s", error_message(ret));
			rcode = RLM_MODULE_NOTFOUND;
			break;
			
		default:
			radlog(L_ERR, "rlm_krb5 (%s): Failed getting/verifying "
			       "credentials: %s", inst->xlat_name,
			       error_message(ret));
			rcode = RLM_MODULE_FAIL;
			break;
		}

		goto cleanup;
	}
	
	RDEBUG("Successfully retrieved and decrypted TGT");
	
	memset(&keytab, 0, sizeof(keytab));
	ret = inst->keytabname ? 
		krb5_kt_resolve(*context, inst->keytabname, &keytab) :
		krb5_kt_default(*context, &keytab);
	if (ret) {
		radlog(L_ERR, "rlm_krb5 (%s): Resolving keytab failed: %s",
		       inst->xlat_name, error_message(ret));
		
		goto cleanup;
	}
	
	ret = krb5_verify_init_creds(*context, &init_creds, inst->server,
				     keytab, NULL, inst->vic_options);
	if (ret) goto error;
 
	cleanup:

	krb5_free_cred_contents(*context, &init_creds);
	krb5_free_context(*context);
	krb5_kt_close(*context, keytab);
	
	return rcode;
}

#else

/*
 *	Validate user/pass (Heimdal)
 */
static rlm_rcode_t krb5_auth(void *instance, REQUEST *request)
{
	rlm_krb5_t *inst = instance;
	rlm_rcode_t rcode;
	
	krb5_error_code ret;
	
	krb5_principal client;
	krb5_ccache ccache;
	krb5_keytab keytab;
	krb5_verify_opt options;
	krb5_context *context = NULL;
	
	/*
	 *	See above in MIT krb5_auth
	 */
	ret = krb5_copy_context(*(inst->context), context);
	if (ret) {
		radlog(L_ERR, "rlm_krb5 (%s): Error cloning krb5 context: %s",
		       inst->xlat_name, error_message(ret));
		
		return RLM_MODULE_FAIL;
	}
	
	/*
	 *	Setup krb5_verify_user options
	 *
	 *	Not entirely sure this is necessary, but as we use context 
	 *	to get the cache handle, we probably do have to do this with
	 *	the cloned context.
	 */
	krb5_cc_default(*context, &ccache);
	
	krb5_verify_opt_init(&options);
	krb5_verify_opt_set_ccache(&options, ccache);
	
	memset(&keytab, 0, sizeof(keytab));
	ret = inst->keytabname ? 
		krb5_kt_resolve(*context, inst->keytabname, &keytab) :
		krb5_kt_default(*context, &keytab);
	if (ret) {
		radlog(L_ERR, "rlm_krb5 (%s): Resolving keytab failed: %s",
		       inst->xlat_name, error_message(ret));
		
		goto cleanup;
	}
	
	krb5_verify_opt_set_keytab(&options, keytab);
	krb5_verify_opt_set_secure(&options, TRUE);

	if (inst->service) {
		krb5_verify_opt_set_service(&options, inst->service);
	}
	
	rcode = krb5_parse_user(inst, request, &client);
	if (rcode != RLM_MODULE_OK) goto cleanup;

	/* 
	 *	Verify the user, using the options we set in instantiate
	 */
	ret = krb5_verify_user_opt(*context, client,
				   request->password->vp_strvalue,
				   &options);
	if (ret) {
		switch (ret) {
		case KRB5_LIBOS_BADPWDMATCH:
		case KRB5KRB_AP_ERR_BAD_INTEGRITY:
			RDEBUG("Provided password was incorrect: %s",
			       error_message(ret));
			rcode = RLM_MODULE_REJECT;
		
			break;
		case KRB5KDC_ERR_KEY_EXP:
		case KRB5KDC_ERR_CLIENT_REVOKED:
		case KRB5KDC_ERR_SERVICE_REVOKED:
			RDEBUG("Account has been locked out: %s",
			       error_message(ret));
			rcode = RLM_MODULE_USERLOCK;
		
			break;
		case KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN:
			RDEBUG("User not found: %s", error_message(ret));
			rcode = RLM_MODULE_NOTFOUND;
					
		default:
			radlog(L_ERR, "rlm_krb5 (%s): Verifying user failed: "
			       "%s", inst->xlat_name, error_message(ret));
			rcode = RLM_MODULE_FAIL;
		
			break;
		}

		goto cleanup;
	}
	
	cleanup:
	
	krb5_free_context(*context);
	krb5_kt_close(*context, keytab);
	
	return rcode;
}

#endif /* HEIMDAL_KRB5 */

module_t rlm_krb5 = {
	RLM_MODULE_INIT,
	"Kerberos",
	RLM_TYPE_THREAD_SAFE | RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,
	krb5_instantiate,   		/* instantiation */
	krb5_detach,			/* detach */
	{
		krb5_auth,		/* authenticate */
		NULL,			/* authorize */
		NULL,			/* pre-accounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
