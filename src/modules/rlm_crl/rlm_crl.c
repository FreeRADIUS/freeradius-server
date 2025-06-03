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
 * @file rlm_crl.c
 * @brief Check a certificate's serial number against a CRL
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/timer.h>

#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/signal.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/log.h>

#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>

#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/tls/utils.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>

/** Global tree of CRLs
 *
 * Separate from the instance data because that's protected.
 */
typedef struct {
	fr_rb_tree_t			*crls;				//!< A tree of CRLs organised by CDP URL.
	fr_timer_list_t			*timer_list;			//!< The timer list to use for CRL expiry.
									///< This gets serviced by the main loop.
	pthread_mutex_t			mutex;
} rlm_crl_mutable_t;

typedef struct {
	CONF_SECTION    		*virtual_server;		//!< Virtual server to use when retrieving CRLs
	fr_time_delta_t			force_expiry;			//!< Force expiry of CRLs after this time
	bool				force_expiry_is_set;
	fr_time_delta_t			early_refresh;			//!< Time interval before nextUpdate to refresh
	char const			*ca_file;			//!< File containing certs for verifying CRL signatures.
	char const			*ca_path;			//!< Directory containing certs for verifying CRL signatures.
	X509_STORE			*verify_store;			//!< Store of certificates to verify CRL signatures.
	rlm_crl_mutable_t		*mutable;			//!< Mutable data that's shared between all threads.
} rlm_crl_t;

/** A single CRL in the global list of CRLs */
typedef struct {
	X509_CRL			*crl;				//!< The CRL.
	char const 			*cdp_url;			//!< The URL of the CRL.
	ASN1_INTEGER			*crl_num;			//!< The CRL number.
	fr_timer_t 			*ev;				//!< When to expire the CRL
	fr_rb_node_t			node;				//!< The node in the tree
	fr_value_box_list_t		delta_urls;			//!< URLs from which a delta CRL can be retrieved.
	rlm_crl_t const			*inst;				//!< The instance of the CRL module.
} crl_entry_t;

typedef struct {
	fr_value_box_t			*cdp_url;			//!< The URL we're currently attempting to load.
	fr_value_box_list_t		crl_data;			//!< Data from CRL expansion.
	fr_value_box_list_t		missing_crls;			//!< CRLs missing from the tree
} rlm_crl_rctx_t;

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_IS_SET("force_expiry", FR_TYPE_TIME_DELTA, 0, rlm_crl_t, force_expiry) },
	{ FR_CONF_OFFSET("early_refresh", rlm_crl_t, early_refresh) },
	{ FR_CONF_OFFSET("ca_file", rlm_crl_t, ca_file) },
	{ FR_CONF_OFFSET("ca_path", rlm_crl_t, ca_path) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_crl_dict[];
fr_dict_autoload_t rlm_crl_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_crl_data;
static fr_dict_attr_t const *attr_crl_cdp_url;

extern fr_dict_attr_autoload_t rlm_crl_dict_attr[];
fr_dict_attr_autoload_t rlm_crl_dict_attr[] = {
	{ .out = &attr_crl_data, .name = "CRL.Data", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_crl_cdp_url, .name = "CRL.CDP-URL", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL }
};

typedef struct {
	tmpl_t				*http_exp;			//!< The xlat expansion used to retrieve the CRL via http://
	tmpl_t				*ldap_exp;			//!< The xlat expansion used to retrieve the CRL via ldap://
	fr_value_box_t			serial;				//!< The serial to check
	fr_value_box_list_head_t	*cdp; 				//!< The CRL distribution points
} rlm_crl_env_t;

typedef enum {
	CRL_ERROR = -1,							//!< Unspecified error ocurred.
	CRL_ENTRY_NOT_FOUND = 0,					//!< Serial not found in this CRL.
	CRL_ENTRY_FOUND = 1,						//!< Serial was found in this CRL.
	CRL_ENTRY_REMOVED = 2,						//!< Serial was "un-revoked" in this delta CRL.
	CRL_NOT_FOUND = 3,						//!< No CRL found, need to load it from the CDP URL
} crl_ret_t;

static const call_env_method_t crl_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_crl_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_SUBSECTION("source", NULL, CALL_ENV_FLAG_SUBSECTION | CALL_ENV_FLAG_PARSE_MISSING,
			((call_env_parser_t[]) {
				{ FR_CALL_ENV_SUBSECTION("dynamic", NULL, CALL_ENV_FLAG_SUBSECTION | CALL_ENV_FLAG_PARSE_MISSING,
				((call_env_parser_t[]) {
					{ FR_CALL_ENV_PARSE_ONLY_OFFSET("http", FR_TYPE_OCTETS, CALL_ENV_FLAG_REQUIRED, rlm_crl_env_t, http_exp )},
					{ FR_CALL_ENV_PARSE_ONLY_OFFSET("ldap", FR_TYPE_OCTETS, CALL_ENV_FLAG_NONE, rlm_crl_env_t, ldap_exp )},
					CALL_ENV_TERMINATOR
				}))},
				CALL_ENV_TERMINATOR
			}))},
		{ FR_CALL_ENV_OFFSET("serial", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_SINGLE, rlm_crl_env_t, serial),
					 .pair.dflt = "session-state.TLS-Certificate.Serial", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("cdp", FR_TYPE_STRING, CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE| CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_MULTI, rlm_crl_env_t, cdp),
					 .pair.dflt = "session-state.TLS-Certificate.X509v3-CRL-Distribution-Points[*]", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	},
};

static int8_t crl_cmp(void const *a, void const *b)
{
	crl_entry_t	const	*crl_a = (crl_entry_t const *)a;
	crl_entry_t	const	*crl_b = (crl_entry_t const *)b;

	return CMP(strcmp(crl_a->cdp_url,  crl_b->cdp_url), 0);
}

static void crl_free(void *data)
{
	talloc_free(data);
}

static void crl_expire(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, UNUSED void *uctx)
{
	crl_entry_t	*crl = talloc_get_type_abort(uctx, crl_entry_t);

	DEBUG2("CRL associated with CDP %s expired", crl->cdp_url);
	pthread_mutex_lock(&crl->inst->mutable->mutex);
	fr_rb_remove(crl->inst->mutable->crls, crl);
	pthread_mutex_unlock(&crl->inst->mutable->mutex);
	talloc_free(crl);
}

/** Make sure we don't lock up the server if a request is cancelled
 */
static void crl_signal(module_ctx_t const *mctx, UNUSED request_t *request, fr_signal_t action)
{
	rlm_crl_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_crl_t);

	if (action == FR_SIGNAL_CANCEL) {
		pthread_mutex_unlock(&inst->mutable->mutex);
		pair_delete_request(attr_crl_cdp_url);
	}
}

/** See if a particular serial is present in a CRL list
 *
 */
static crl_ret_t crl_check_entry(crl_entry_t *crl_entry, request_t *request, uint8_t const *serial)
{
	X509_REVOKED	*revoked;
	ASN1_INTEGER	*asn1_serial = NULL;
	int ret;

	asn1_serial = d2i_ASN1_INTEGER(NULL, (unsigned char const **)&serial, talloc_array_length(serial));
	ret = X509_CRL_get0_by_serial(crl_entry->crl, &revoked, asn1_serial);
	ASN1_INTEGER_free(asn1_serial);
	switch (ret) {
	/* The docs describe 0 as "failure" - but that means "failed to find"*/
	case 0:
		RDEBUG3("Certificate not in CRL");
		return CRL_ENTRY_NOT_FOUND;

	case 1:
		RDEBUG2("Certificate revoked by %s", crl_entry->cdp_url);
		return CRL_ENTRY_FOUND;

	case 2:
		RDEBUG3("Certificate un-revoked by %s", crl_entry->cdp_url);
		return CRL_ENTRY_REMOVED;
	}

	return CRL_ERROR;
}

/** Resolve a cdp_url to a CRL entry, and check serial against it, if it exists
 *
 */
static crl_ret_t crl_check_serial(fr_rb_tree_t *crls, request_t *request, char const *cdp_url, uint8_t const *serial)
{
	crl_entry_t	*found, find = { .cdp_url = cdp_url};

	found = fr_rb_find(crls, &find);
	if (found == NULL) return CRL_NOT_FOUND;

	return crl_check_entry(found, request, serial);
}

static int _crl_entry_free(crl_entry_t *crl_entry)
{
	X509_CRL_free(crl_entry->crl);
	if (crl_entry->crl_num) ASN1_INTEGER_free(crl_entry->crl_num);
	return 0;
}

/** Add an entry to the cdp_url -> crl tree
 *
 * @note Must be called with the mutex held.
 */
static crl_entry_t *crl_entry_create(rlm_crl_t const *inst, fr_timer_list_t *tl, char const *url, uint8_t const *data)
{
	uint8_t const	*our_data = data;
	crl_entry_t	*crl;
	time_t		next_update;
	fr_time_t	now = fr_time();
	fr_time_delta_t	expiry_time;
	int		i;
	STACK_OF(DIST_POINT)	*dps;
	X509_STORE_CTX	*verify_ctx = NULL;
	X509_OBJECT	*xobj;
	EVP_PKEY	*pkey;

	MEM(crl = talloc_zero(inst->mutable->crls, crl_entry_t));
	crl->cdp_url = talloc_bstrdup(crl, url);
	crl->crl = d2i_X509_CRL(NULL, (const unsigned char **)&our_data, talloc_array_length(our_data));
	if (crl->crl == NULL) {
		fr_tls_strerror_printf("Failed to parse CRL from %s", url);
	error:
		talloc_free(crl);
		if (verify_ctx) X509_STORE_CTX_free(verify_ctx);
		return NULL;
	}
	talloc_set_destructor(crl, _crl_entry_free);

	verify_ctx = X509_STORE_CTX_new();
        if (!verify_ctx || !X509_STORE_CTX_init(verify_ctx, inst->verify_store, NULL, NULL)) {
		fr_tls_strerror_printf("Error initialising X509 store");
            	goto error;
        }

        xobj = X509_STORE_CTX_get_obj_by_subject(verify_ctx, X509_LU_X509,
                                                 X509_CRL_get_issuer(crl->crl));
        if (!xobj) {
		fr_tls_strerror_printf("CRL issuer certificate not in trusted store");
		goto error;
        }
        pkey = X509_get_pubkey(X509_OBJECT_get0_X509(xobj));
        X509_OBJECT_free(xobj);
        if (!pkey) {
		fr_tls_strerror_printf("Error getting CRL issuer public key");
		goto error;
        }
        i = X509_CRL_verify(crl->crl, pkey);
        EVP_PKEY_free(pkey);

	if (i < 0) {
		fr_tls_strerror_printf("Could not verify CRL signature");
		goto error;
	}
        if (i == 0) {
		fr_tls_strerror_printf("CRL certificate signature failed");
		goto error;
	}

	crl->crl_num = X509_CRL_get_ext_d2i(crl->crl, NID_crl_number, &i, NULL);

	if (fr_tls_utils_asn1time_to_epoch(&next_update, X509_CRL_get0_nextUpdate(crl->crl)) < 0) {
		fr_tls_strerror_printf("Failed to parse nextUpdate from CRL");
		goto error;
	}

	if (!fr_rb_insert(inst->mutable->crls, crl)) {
		ERROR("Failed to insert CRL into tree of CRLs");
		goto error;
	}
	crl->inst = inst;

	/*
	 *	Check if this CRL has a Freshest CRL extension - the list of URIs to get deltas from
	 */
	fr_value_box_list_init(&crl->delta_urls);
	if ((dps = X509_CRL_get_ext_d2i(crl->crl, NID_freshest_crl, NULL, NULL))) {
		DIST_POINT		*dp;
		STACK_OF(GENERAL_NAME)	*names;
		GENERAL_NAME		*name;
		int			j;
		fr_value_box_t		*vb;

		for (i = 0; i < sk_DIST_POINT_num(dps); i++) {
			dp = sk_DIST_POINT_value(dps, i);
			names = dp->distpoint->name.fullname;
			for (j = 0; j < sk_GENERAL_NAME_num(names); j++) {
				name = sk_GENERAL_NAME_value(names, j);
				if (name->type != GEN_URI) continue;
				MEM(vb = fr_value_box_alloc_null(crl));
				fr_value_box_bstrndup(vb, vb, NULL,
						      (char const *)ASN1_STRING_get0_data(name->d.uniformResourceIdentifier),
						      ASN1_STRING_length(name->d.uniformResourceIdentifier), true);
				DEBUG3("CRL references delta URI %pV", vb);
				fr_value_box_list_insert_tail(&crl->delta_urls, vb);
			}
		}
		CRL_DIST_POINTS_free(dps);
	}

	expiry_time = fr_time_delta_sub(fr_time_sub(fr_time_from_sec(next_update), now), inst->early_refresh);
	if (inst->force_expiry_is_set &&
	    (fr_time_delta_cmp(expiry_time, inst->force_expiry) > 0)) expiry_time = inst->force_expiry;

	DEBUG3("CRL from %s will expire in %pVs", url, fr_box_time_delta(expiry_time));
	fr_timer_in(crl, tl, &crl->ev, expiry_time, false, crl_expire, crl);

	X509_STORE_CTX_free(verify_ctx);
	return crl;
}

static unlang_action_t crl_process_cdp_data(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request);

/** Yield to a tmpl to retrieve CRL data
 *
 */
static unlang_action_t crl_tmpl_yield(rlm_rcode_t *p_result, request_t *request, rlm_crl_env_t *env, rlm_crl_rctx_t *rctx)
{
	fr_pair_t	*vp;
	tmpl_t		*vpt;

	MEM(pair_update_request(&vp, attr_crl_cdp_url) >= 0);
	MEM(fr_value_box_copy(vp, &vp->data, rctx->cdp_url) == 0);

	if (strncmp(rctx->cdp_url->vb_strvalue, "http", 4) == 0) {
		vpt = env->http_exp;
	} else if (strncmp(rctx->cdp_url->vb_strvalue, "ldap", 4) == 0) {
		if (!env->ldap_exp) {
			RERROR("CRL URI requires LDAP, but the crl module ldap expansion is not configured");
			RETURN_MODULE_INVALID;
		}
		vpt = env->ldap_exp;
	} else {
		RERROR("Unsupported URI scheme in CRL URI %pV", rctx->cdp_url);
		RETURN_MODULE_FAIL;
	}

	return unlang_module_yield_to_tmpl(rctx, &rctx->crl_data, request, vpt,
					   NULL, crl_process_cdp_data, crl_signal, 0, rctx);
}

static unlang_action_t crl_by_url(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request);

/** Process the response from evaluating the cdp_url -> crl_data expansion
 *
 * This is the resumption function when we yield to get CRL data associated with a URL
 */
static unlang_action_t crl_process_cdp_data(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_crl_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_crl_t);
	rlm_crl_env_t *env = talloc_get_type_abort(mctx->env_data, rlm_crl_env_t);
	rlm_crl_rctx_t *rctx = talloc_get_type_abort(mctx->rctx, rlm_crl_rctx_t);

	switch (fr_value_box_list_num_elements(&rctx->crl_data)) {
	case 0:
		REDEBUG("No CRL data returned from %pV, failing", rctx->cdp_url);
	again:
		talloc_free(rctx->cdp_url);

		/*
		 *	If there are more URIs to try, push a new tmpl to expand.
		 */
		rctx->cdp_url = fr_value_box_list_pop_head(&rctx->missing_crls);
		if (rctx->cdp_url) return crl_tmpl_yield(p_result, request, env, rctx);
	fail:
		pthread_mutex_unlock(&inst->mutable->mutex);
		fr_value_box_list_talloc_free(&rctx->crl_data);
		pair_delete_request(attr_crl_cdp_url);
		RETURN_MODULE_FAIL;

	case 1:
	{
		crl_entry_t *crl_entry;

		crl_entry = crl_entry_create(inst, unlang_interpret_event_list(request)->tl,
				       rctx->cdp_url->vb_strvalue,
				       fr_value_box_list_head(&rctx->crl_data)->vb_octets);
		if (!crl_entry) {
			RPERROR("Failed to process returned CRL data");
			goto again;
		}

		switch (crl_check_entry(crl_entry, request, env->serial.vb_octets)) {
		case CRL_ENTRY_FOUND:
			pthread_mutex_unlock(&inst->mutable->mutex);
			RETURN_MODULE_REJECT;

		case CRL_ENTRY_NOT_FOUND:
			/*
			 *	We have a CRL, but the serial is not in it.
			 */

		case CRL_ENTRY_REMOVED:
			pthread_mutex_unlock(&inst->mutable->mutex);
			fr_value_box_list_talloc_free(&rctx->crl_data);	/* Free the raw CRL data */
			pair_delete_request(attr_crl_cdp_url);
			RETURN_MODULE_OK;

		case CRL_ERROR:
			goto fail;

		/*
		 *	This should be return by crl_check_entry because we provided the entry!
		 */
		case CRL_NOT_FOUND:
			fr_assert(0);
			goto fail;
		}

	}
		break;

	default:
		REDEBUG("Too many CRL values returned, failing");
		break;
	}

	goto fail;
}

static unlang_action_t crl_by_url(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_crl_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_crl_t);
	rlm_crl_env_t *env = talloc_get_type_abort(mctx->env_data, rlm_crl_env_t);
	rlm_crl_rctx_t *rctx = mctx->rctx;
	rlm_rcode_t	rcode = RLM_MODULE_NOOP;

	if (!rctx) rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), rlm_crl_rctx_t);
	fr_value_box_list_init(&rctx->missing_crls);

	pthread_mutex_lock(&inst->mutable->mutex);

	/*
	 *	Fast path when we have a CRL.
	 *	All distribution points are considered equivalent, so check if
	 *	if we have any of them before attempting to fetch missing ones.
	 */
	while ((rctx->cdp_url = fr_value_box_list_pop_head(env->cdp))) {
		switch (crl_check_serial(inst->mutable->crls, request,
				 rctx->cdp_url->vb_strvalue, env->serial.vb_octets)) {
		case CRL_ENTRY_FOUND:
			rcode = RLM_MODULE_REJECT;
			break;

		case CRL_ENTRY_NOT_FOUND:
		case CRL_ENTRY_REMOVED:
			rcode = RLM_MODULE_OK;
			break;

		case CRL_ERROR:
			continue;

		case CRL_NOT_FOUND:
			fr_value_box_list_insert_tail(&rctx->missing_crls, rctx->cdp_url);
			rcode = RLM_MODULE_NOTFOUND;
			continue;
		}
	}

	if (rcode != RLM_MODULE_NOTFOUND) {
		pthread_mutex_unlock(&inst->mutable->mutex);
		RETURN_MODULE_RCODE(rcode);
	}

	/*
	 *	Need to convert a missing cdp_url to a CRL entry
	 *
	 *	We yield to an expansion to allow this to happen, then parse the CRL data
	 *	and check if the serial has an entry in the CRL.
	 */
	fr_value_box_list_init(&rctx->crl_data);

	rctx->cdp_url = fr_value_box_list_pop_head(&rctx->missing_crls);

	return crl_tmpl_yield(p_result, request, env, rctx);
}

static int mod_mutable_free(rlm_crl_mutable_t *mutable)
{
	pthread_mutex_destroy(&mutable->mutex);
	return 0;
}

/**	Instantiate the module
 *
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_crl_t);

	MEM(inst->mutable = talloc_zero(NULL, rlm_crl_mutable_t));
	MEM(inst->mutable->crls = fr_rb_inline_talloc_alloc(inst->mutable, crl_entry_t, node, crl_cmp, crl_free));
	pthread_mutex_init(&inst->mutable->mutex, NULL);
	talloc_set_destructor(inst->mutable, mod_mutable_free);

	if (!inst->ca_file && !inst->ca_path) {
		cf_log_err(mctx->mi->conf, "Missing ca_file / ca_path option.  One or other (or both) must be specified.");
		return -1;
	}

	inst->verify_store = X509_STORE_new();
	if (!X509_STORE_load_locations(inst->verify_store, inst->ca_file, inst->ca_path)) {
		cf_log_err(mctx->mi->conf, "Failed reading Trusted root CA file \"%s\" and path \"%s\"",
			   inst->ca_file, inst->ca_path);
		return -1;
	}

	X509_STORE_set_purpose(inst->verify_store, X509_PURPOSE_SSL_CLIENT);

	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_crl_t);

	if (inst->verify_store) X509_STORE_free(inst->verify_store);
	talloc_free(inst->mutable);
	return 0;
}

extern module_rlm_t rlm_crl;
module_rlm_t rlm_crl = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.inst_size	= sizeof(rlm_crl_t),
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,
		.name		= "crl",
		.config		= module_config,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = crl_by_url, .method_env = &crl_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
