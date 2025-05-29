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
	rlm_crl_mutable_t		*mutable;			//!< Mutable data that's shared between all threads.
} rlm_crl_t;

/** A single CRL in the global list of CRLs */
typedef struct {
	X509_CRL			*crl;				//!< The CRL.
	char const 			*cdp_url;			//!< The URL of the CRL.
	fr_timer_t 			*ev;				//!< When to expire the CRL
	fr_rb_node_t			node;				//!< The node in the tree
	rlm_crl_t const			*inst;				//!< The instance of the CRL module.
} crl_entry_t;

typedef struct {
	fr_value_box_t			*cdp_url;			//!< The URL we're currently attempting to load.
	fr_value_box_list_t		crl_data;			//!< Data from CRL expansion.
} rlm_crl_rctx_t;

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
	tmpl_t				*exp;				//!< The xlat expansion use to retrieve the CRL.
	fr_value_box_t			serial;				//!< The serial to check
	fr_value_box_list_head_t	*cdp; 				//!< The CRL distribution points
} rlm_crl_env_t;

typedef enum {
	CRL_ERROR = -1,							//!< Unspecified error ocurred.
	CRL_ENTRY_NOT_FOUND = 0,					//!< Serial not found in this CRL.
	CRL_ENTRY_FOUND = 1,						//!< Serial was found in this CRL.
	CRL_NOT_FOUND = 2,						//!< No CRL found, need to load it from the CDP URL
} crl_ret_t;

static const call_env_method_t crl_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_crl_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("crl", FR_TYPE_OCTETS, CALL_ENV_FLAG_REQUIRED, rlm_crl_env_t, exp )},
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
	fr_rb_remove(crl->inst->mutable->crls, &crl->node);
	pthread_mutex_unlock(&crl->inst->mutable->mutex);
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
	case 0:
		fr_tls_strerror_printf("Failed checking serial number against CRL %s", crl_entry->cdp_url);
		RPERROR("Returning fail");
		return CRL_ERROR;

	case 1:
		RDEBUG2("Certificate revoked by %s", crl_entry->cdp_url);
		return CRL_ENTRY_FOUND;

	case 2:
		RDEBUG2("Remove from CRL?");
		return CRL_ENTRY_NOT_FOUND;
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

	MEM(crl = talloc_zero(inst->mutable->crls, crl_entry_t));
	crl->cdp_url = talloc_bstrdup(crl, url);
	crl->crl = d2i_X509_CRL(NULL, (const unsigned char **)&our_data, talloc_array_length(our_data));
	if (crl->crl == NULL) {
		fr_tls_strerror_printf("Failed to parse CRL from %s", url);
	error:
		talloc_free(crl);
		return NULL;
	}
	talloc_set_destructor(crl, _crl_entry_free);

	if (!fr_rb_insert(inst->mutable->crls, crl)) {
		ERROR("Failed to insert CRL into tree of CRLs");
		goto error;
	}
	fr_timer_in(crl, tl, &crl->ev, inst->force_expiry, false, crl_expire, crl);
	crl->ev = NULL;

	return crl;
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
		REDEBUG("No CRL data returned, failing");
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
		if (!crl_entry) goto fail;

		switch (crl_check_entry(crl_entry, request, env->serial.vb_octets)) {
		case CRL_ENTRY_FOUND:
			pthread_mutex_unlock(&inst->mutable->mutex);
			RETURN_MODULE_REJECT;

		case CRL_ENTRY_NOT_FOUND:
			/*
			 *	We have a CRL, but the serial is not in it.
			 *	check the rest of the CDPs, then return OK.
			 */
			pthread_mutex_unlock(&inst->mutable->mutex);
			fr_value_box_list_talloc_free(&rctx->crl_data);	/* Free the raw CRL data */
			pair_delete_request(attr_crl_cdp_url);
			return crl_by_url(p_result, mctx, request);

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

	if (!rctx) rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), rlm_crl_rctx_t);

	pthread_mutex_lock(&inst->mutable->mutex);

	/*
	 *	Fast path when we have all the CRLs
	 */
	while ((rctx->cdp_url = fr_value_box_list_next(env->cdp, rctx->cdp_url))) {
		switch (crl_check_serial(inst->mutable->crls, request,
				 rctx->cdp_url->vb_strvalue, env->serial.vb_octets)) {
		case CRL_ENTRY_FOUND:
			pthread_mutex_unlock(&inst->mutable->mutex);
			RETURN_MODULE_REJECT;

		case CRL_ENTRY_NOT_FOUND:
		case CRL_ERROR:
			continue;

		/*
		 *	Need to convert the cdp_url to a CRL entry
		 *
		 *	We yield to an expansion to allow this to happen, then parse the CRL data
		 *	and check if the serial has an entry in the CRL.
		 */
		case CRL_NOT_FOUND:
		{
			fr_pair_t *vp;

			fr_value_box_list_init(&rctx->crl_data);

			MEM(pair_update_request(&vp, attr_crl_cdp_url) >= 0);
			MEM(fr_value_box_copy(vp, &vp->data, rctx->cdp_url) == 0);

			return unlang_module_yield_to_tmpl(rctx, &rctx->crl_data, request, env->exp,
							   NULL, crl_process_cdp_data, crl_signal, 0, rctx);
		}
		}
	}

	pthread_mutex_unlock(&inst->mutable->mutex);

	RETURN_MODULE_OK;
}

static int mod_mutable_free(rlm_crl_mutable_t *mutable)
{
	pthread_mutex_destroy(&mutable->mutex);
	return 0;
}

/*
 *	(Re-)read radiusd.conf into memory.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_crl_t);

	MEM(inst->mutable = talloc_zero(NULL, rlm_crl_mutable_t));
	MEM(inst->mutable->crls = fr_rb_inline_talloc_alloc(inst->mutable, crl_entry_t, node, crl_cmp, crl_free));
	pthread_mutex_init(&inst->mutable->mutex, NULL);
	talloc_set_destructor(inst->mutable, mod_mutable_free);

	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_crl_t);

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
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = crl_by_url, .method_env = &crl_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
