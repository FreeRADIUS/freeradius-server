/*
 * rlm_krb5.c	module to authenticate against krb5
 *
 * Version:	$Id$
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
 * Copyright 2000,2006,2012  The FreeRADIUS server project
 * Copyright 2000  Nathan Neulinger <nneul@umr.edu>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include	<freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>

/* krb5 includes */
#include <krb5.h>
#include <com_err.h>

 /* Arbitrary 64char limit on service names */
#define SERVICE_NAME_LEN 64

typedef struct rlm_krb5_t {
	const char *keytab;
	const char *service_princ;
	const char *cache;
	krb5_context *context;
} rlm_krb5_t;

static const CONF_PARSER module_config[] = {
	{ "keytab", PW_TYPE_STRING_PTR,
	  offsetof(rlm_krb5_t,keytab), NULL, NULL },
	{ "service_principal", PW_TYPE_STRING_PTR,
	  offsetof(rlm_krb5_t,service_princ), NULL, NULL },
	{ "cache", PW_TYPE_BOOLEAN,
	  offsetof(rlm_krb5_t,cache), NULL, "yes" },
	{ NULL, -1, 0, NULL, NULL }
};

#ifndef HEIMDAL_KRB5

static int krb5_build_auth_context(rlm_krb5_t *inst,
				   krb5_context context,
				   krb5_auth_context *auth_context)
{
	int ret;
	krb5_int32 flags;
	
	ret = krb5_auth_con_init(context, auth_context);
	if (ret)
		return ret;
	
	ret = krb5_auth_con_getflags(context, *auth_context, &flags);
	if (ret)
		return ret;
		
	if (!inst->cache && (flags & KRB5_AUTH_CONTEXT_DO_TIME)) {
		ret = krb5_auth_con_setflags(context, *auth_context, flags & ~KRB5_AUTH_CONTEXT_DO_TIME);

		if (ret)
			return ret;
	}
	
	return 0;
}

static rlm_rcode_t verify_krb5_tgt(krb5_context context, rlm_krb5_t *inst,
			   	   const char *user, krb5_ccache ccache)
{
	int rcode;
	int ret;
	char phost[BUFSIZ];
	krb5_principal princ;
	krb5_keyblock *keyblock = 0;
	krb5_data packet, *server;
	krb5_auth_context auth_context = NULL;
	krb5_keytab keytab;

	char service[SERVICE_NAME_LEN] = "host";
	char *server_name = NULL;
	char *keytab_name;
	
	/* krb5_kt_read_service_key lacks const qualifier */
	memcpy(&keytab_name, &inst->keytab, sizeof(keytab_name));

	if (inst->service_princ != NULL) {
		server_name = strchr(inst->service_princ, '/');
		if (server_name != NULL) {
			*server_name = '\0';
		}

		strlcpy(service, inst->service_princ, sizeof(service));

		if (server_name != NULL) {
			*server_name = '/';
			server_name++;
		}
	}

	memset(&packet, 0, sizeof packet);
	ret = krb5_sname_to_principal(context, server_name, service,
				      KRB5_NT_SRV_HST, &princ);
	if (ret) {
		radlog(L_DBG, "rlm_krb5: [%s] krb5_sname_to_principal failed: %s",
			user, error_message(ret));

		return RLM_MODULE_REJECT;
	}

	server = krb5_princ_component(c, princ, 1);
	if (!server) {
		radlog(L_DBG, "rlm_krb5: [%s] krb5_princ_component failed.",
		       user);

		return RLM_MODULE_REJECT;
	}
	
	strlcpy(phost, server->data, sizeof(phost));

	/*
	 *  Do we have host/<host> keys?
	 *  (use default/configured keytab, kvno IGNORE_VNO to get the
	 *  first match, and enctype is currently ignored anyhow.)
	 */
	ret = krb5_kt_read_service_key(context, keytab_name, princ, 0,
				       ENCTYPE_DES_CBC_MD5, &keyblock);
	if (ret) {
		/* Keytab or service key does not exist */
		radlog(L_DBG, "rlm_krb5: verify_krb_v5_tgt: host key not found : %s",
		       error_message(ret));
		       
		return RLM_MODULE_OK;
	}
	
	if (keyblock)
		krb5_free_keyblock(context, keyblock);

	/*
	 *  Talk to the kdc and construct the ticket.
	 */
	ret = krb5_build_auth_context(inst, context, &auth_context);
	if (ret) {
		radlog(L_DBG, "rlm_krb5: [%s] krb5_build_auth_context() failed: %s",
		       user, error_message(ret));
		       
		rcode = RLM_MODULE_REJECT;
		goto cleanup;
	}
	
	ret = krb5_mk_req(context, &auth_context, 0, service, phost, NULL,
			  ccache, &packet);
	if (auth_context) {
		krb5_auth_con_free(context, auth_context);
		auth_context = NULL; /* setup for rd_req */
	}

	if (ret) {
		radlog(L_DBG, "rlm_krb5: [%s] krb5_mk_req() failed: %s",
		       user, error_message(ret));

		rcode = RLM_MODULE_REJECT;
		goto cleanup;
	}

	if (keytab_name != NULL) {
		ret = krb5_kt_resolve(context, keytab_name, &keytab);
	}

	if (keytab_name == NULL || ret) {
		ret = krb5_kt_default(context, &keytab);
	}

	/* Hmm?  The keytab was just fine a second ago! */
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_kt_resolve failed: %s",
			user, error_message(ret));
			
		rcode = RLM_MODULE_REJECT;
		goto cleanup;
	}

	/* Try to use the ticket. */
	ret = krb5_build_auth_context(inst, context, &auth_context);
	if (ret) {
		radlog(L_DBG, "rlm_krb5: [%s] krb5_build_auth_context() failed: %s",
		       user, error_message(ret));

		rcode = RLM_MODULE_REJECT;
		goto cleanup;
	}
	
	ret = krb5_rd_req(context, &auth_context, &packet, princ,
			  keytab, NULL, NULL);
	if (auth_context)
		krb5_auth_con_free(context, auth_context);

	krb5_kt_close(context, keytab);

	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_rd_req() failed: %s",
		       user, error_message(ret));

		rcode = RLM_MODULE_REJECT;
	} else {
		rcode = RLM_MODULE_OK;
	}
	
cleanup:
	if (packet.data) {
		krb5_free_data_contents(context, &packet);
	}
	
	return rcode;
}
#endif

static int krb5_instantiate(CONF_SECTION *conf, void **instance)
{
	int ret;
	rlm_krb5_t *data;
	krb5_context *context;

	data = rad_malloc(sizeof(*data));

	memset(data, 0, sizeof(*data));

	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}
	
	context = data->context = rad_malloc(sizeof(*context));

	ret = krb5_init_context(context);
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: krb5_init failed: %s",
		       error_message(ret));
  
		free(data);
		return -1;
	} else {
		radlog(L_AUTH, "rlm_krb5: krb5_init ok");
	}
	
	*instance = data;
	
	return 0;
}

static int krb5_detach(void *instance)
{
	free(((rlm_krb5_t *)instance)->context);
	free(instance);
	
	return 0;
}

/* 
 *  Validate userid/passwd (MIT)
 */
#ifndef HEIMDAL_KRB5
static rlm_rcode_t krb5_auth(void *instance, REQUEST *request)
{
	rlm_krb5_t *inst = instance;
	int ret;
	
	static char tgs_name[] = KRB5_TGS_NAME;
	krb5_data tgtname = {
		0,
		KRB5_TGS_NAME_SIZE,
		tgs_name
	};
	
	krb5_creds kcreds;
	krb5_ccache ccache;
	
	/* MEMORY: + unsigned int (20) + NULL */
	char cache_name[28];

	krb5_context context = *(inst->context); /* copy data */
	const char *user, *pass;

	/*
	 *  We can only authenticate user requests which HAVE
	 *  a User-Name attribute.
	 */
	if (!request->username) {
		radlog(L_AUTH, "rlm_krb5: Attribute \"User-Name\" is required for authentication.");
		
		return RLM_MODULE_INVALID;
	}

	/*
	 *  We can only authenticate user requests which HAVE
	 *  a User-Password attribute.
	 */
	if (!request->password) {
		radlog(L_AUTH, "rlm_krb5: Attribute \"User-Password\" is required for authentication.");
		
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_USER_PASSWORD) {
		radlog(L_AUTH, "rlm_krb5: Attribute \"User-Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		
		return RLM_MODULE_INVALID;
	}

	user = request->username->vp_strvalue;
	pass = request->password->vp_strvalue;

	/*
	 *  Generate a unique cache_name.
	 */
	snprintf(cache_name, sizeof(cache_name), "MEMORY:%u", request->number);

	ret = krb5_cc_resolve(context, cache_name, &ccache);
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_cc_resolve(): %s",
		       user, error_message(ret));
		       
		return RLM_MODULE_REJECT;
	}

	/*
	 *  Actually perform the authentication.
	 */
	memset((char *)&kcreds, 0, sizeof(kcreds));

	ret = krb5_parse_name(context, user, &kcreds.client);
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_parse_name failed: %s",
		       user, error_message(ret));
		       
		return RLM_MODULE_REJECT;
	}

	ret = krb5_cc_initialize(context, ccache, kcreds.client);
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_cc_initialize(): %s",
		       user, error_message(ret));
		       
		return RLM_MODULE_REJECT;
	}

	/*
	 *  MIT krb5 verification.
	 */
	ret = krb5_build_principal_ext(context, &kcreds.server,
			krb5_princ_realm(context, kcreds.client)->length,
			krb5_princ_realm(context, kcreds.client)->data,
			tgtname.length,
			tgtname.data,
			krb5_princ_realm(context, kcreds.client)->length,
			krb5_princ_realm(context, kcreds.client)->data,
			0);
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_build_principal_ext failed: %s",
			user, error_message(ret));
		krb5_cc_destroy(context, ccache);
		
		return RLM_MODULE_REJECT;
	}

	ret = krb5_get_in_tkt_with_password(context, 0, NULL, NULL, NULL, pass,
					    ccache, &kcreds, 0);
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_g_i_t_w_p failed: %s",
		       user, error_message(ret));
		krb5_free_cred_contents(context, &kcreds);
		krb5_cc_destroy(context, ccache);
		
		return RLM_MODULE_REJECT;
	}

	/*
	 *  Now verify the KDC's identity.
	 */
	ret = verify_krb5_tgt(context, inst, user, ccache);
	krb5_free_cred_contents(context, &kcreds);
	krb5_cc_destroy(context, ccache);
	
	return ret;
}

#else /* HEIMDAL_KRB5 */

/*
 *  validate user/pass (Heimdal)
 */
static rlm_rcode_t krb5_auth(void *instance, REQUEST *request)
{
	rlm_krb5_t *inst = instance;

	krb5_error_code ret;
	krb5_ccache id;
	krb5_principal userP;

	krb5_context context = *(inst->context); /* copy data */
	const char *user, *pass;

	char service[SERVICE_NAME_LEN] = "host";
	char *server_name = NULL;
	char *princ_name;

	krb5_verify_opt krb_verify_options;
	krb5_keytab keytab;

	if (inst->service_princ != NULL) {
		server_name = strchr(inst->service_princ, '/');
		if (server_name != NULL) {
			*server_name = '\0';
		}

		strlcpy(service, inst->service_princ, sizeof(service));
		if (server_name != NULL) {
			*server_name = '/';
			server_name++;
		}
	}

	/*
	 *  We can only authenticate user requests which HAVE
	 *  a User-Name attribute.
	 */
	if (!request->username) {
		radlog(L_AUTH, "rlm_krb5: Attribute \"User-Name\" is required for authentication.");
		
		return RLM_MODULE_INVALID;
	}

	/*
	 *  We can only authenticate user requests which HAVE
	 *  a User-Password attribute.
	 */
	if (!request->password) {
		radlog(L_AUTH, "rlm_krb5: Attribute \"User-Password\" is required for authentication.");
		
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_USER_PASSWORD) {
		radlog(L_AUTH, "rlm_krb5: Attribute \"User-Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		
		return RLM_MODULE_INVALID;
	}

	user = request->username->vp_strvalue;
	pass = request->password->vp_strvalue;

	ret = krb5_parse_name(context, user, &userP);
	if (ret) {
		radlog(L_AUTH, "rlm_krb5: [%s] krb5_parse_name failed: %s",
		       user, error_message(ret));
		       
		return RLM_MODULE_REJECT;
	}

	/*
	 *  Heimdal krb5 verification.
	 */
	 
	/*
	 *  The following bit allows us to also log user/instance@REALM if someone
	 *  logs in using an instance.
	 */
	ret = krb5_unparse_name(context, userP, &princ_name);
	if (ret != 0) {
		radlog(L_AUTH, "rlm_krb5: Unparsable name");
	} else {
		radlog(L_AUTH, "rlm_krb5: Parsed name is: %s", princ_name);
		free(princ_name);
	}

	krb5_cc_default(context, &id);

	/*
	 *  Set up krb5_verify_user options.
	 */
	krb5_verify_opt_init(&krb_verify_options);
	krb5_verify_opt_set_ccache(&krb_verify_options, id);

	/*
	 *  Resolve keytab name. This allows us to use something other than
	 *  the default system keytab
	 */
	if (inst->keytab != NULL) {
		ret = krb5_kt_resolve(context, inst->keytab, &keytab);
		if (ret) {
			radlog(L_AUTH, "rlm_krb5: unable to resolve keytab %s: %s",
			       inst->keytab, error_message(ret));
			krb5_kt_close(context, keytab);
			
			return RLM_MODULE_REJECT;
		}
		
		krb5_verify_opt_set_keytab(&krb_verify_options, keytab);
	}

	/*
	 *  Verify aquired credentials against the keytab.
	 */
	krb5_verify_opt_set_secure(&krb_verify_options, 1);

	/*
	 *  Allow us to use an arbitrary service name.
	 */
	krb5_verify_opt_set_service(&krb_verify_options, service);

	/* 
	 *  Verify the user, using the above set options.
	 */
	ret = krb5_verify_user_opt(context, userP, pass, &krb_verify_options);

	/*
	 *  We are done with the keytab, close it.
	 */
	krb5_kt_close(context, keytab);

	if (ret == 0)
		return RLM_MODULE_OK;

	radlog(L_AUTH, "rlm_krb5: failed verify_user: %s (%s@%s)",
	       error_message(ret),
	       *userP->name.name_string.val,
	       userP->realm);

	return RLM_MODULE_REJECT;
}

#endif /* HEIMDAL_KRB5 */

module_t rlm_krb5 = {
	RLM_MODULE_INIT,
	"Kerberos",
	RLM_TYPE_THREAD_UNSAFE,	/* type: not thread safe */
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
