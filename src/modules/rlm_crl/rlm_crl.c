/*
 *   This program is free software; you can redistribute it and/or modify
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

#include <freeradius-devel/crl/crl.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/io/coord_pair.h>

#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/tls/utils.h>

#include <freeradius-devel/unlang/xlat_func.h>

#include <openssl/x509v3.h>

/** Thread specific structure to hold requests awaiting CRL fetching */
typedef struct {
	fr_rb_tree_t			pending;			//!< Requests yielded while the CRL is being fetched.
	fr_coord_worker_t		*cw;				//!< Worker side of coordinator communication.
	fr_rb_tree_t			crls;				//!< CRLs fetched from the coordinator.
	fr_rb_tree_t			fails;				//!< Recent CRLs which have failed to fetch.
} rlm_crl_thread_t;

typedef struct {
	fr_time_delta_t			retry_delay;			//!< Time to hold off between CRL fetching failures.
	char const			**urls;				//!< Initial list of URLs to fetch.
	fr_coord_pair_reg_t		*coord_pair_reg;		//!< coord_pair registration for fetching CRLs.
	fr_coord_reg_t			*coord_reg;			//!< coord registration for fetching CRLs.
} rlm_crl_t;

/** A single CRL in the thread specific list of CRLs */
typedef struct {
	X509_CRL			*crl;				//!< The CRL.
	char const 			*cdp_url;			//!< The URL of the CRL.
	fr_rb_node_t			node;				//!< The node in the tree
	fr_value_box_list_t		delta_urls;			//!< URLs from which a delta CRL can be retrieved.
} crl_entry_t;

/** Structure to record recent fetch failures
 */
typedef struct {
	char const			*cdp_url;			//!< The URL which failed to fetch.
	fr_rb_node_t			node;				//!< Node in the tree of failures.
	fr_time_t			fail_time;			//!< When did the failure occur.
} crl_fail_t;

/** Structure to record a request which is waiting for CRL fetching to complete */
typedef struct {
	request_t			*request;
	fr_rb_node_t			node;
} crl_pending_t;

/** A status used to track which CRL is being checked */
typedef enum {
	CRL_CHECK_BASE = 0,						//!< The base CRL is being checked
	CRL_CHECK_FETCH_DELTA,						//!< The delta CRL is being fetched
	CRL_CHECK_DELTA							//!< The delta CRL exists and is being checked
} crl_check_status_t;

typedef struct {
	fr_value_box_t			*cdp_url;			//!< The URL we're currently attempting to load.
	crl_entry_t			*base_crl;			//!< The base CRL relating to the delta currently being fetched.
	fr_value_box_list_t		crl_data;			//!< Data from CRL expansion.
	fr_value_box_list_t		missing_crls;			//!< CRLs missing from the tree
	crl_check_status_t		status;				//!< Status of the current CRL check.
} rlm_crl_rctx_t;

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("retry_delay", rlm_crl_t, retry_delay), .dflt = "30s" },
	{ FR_CONF_OFFSET_FLAGS("url", CONF_FLAG_MULTI, rlm_crl_t, urls) },
	CONF_PARSER_TERMINATOR
};

/** Callback IDs used by CRL coordinator calls
 */
typedef enum {
	CRL_COORD_PAIR_CALLBACK_ID = 0,
} rlm_crl_coord_callback_t;

static fr_dict_t const *dict_crl;

extern fr_dict_autoload_t rlm_crl_dict[];
fr_dict_autoload_t rlm_crl_dict[] = {
	{ .out = &dict_crl, .proto = "crl" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_crl_data;
static fr_dict_attr_t const *attr_crl_cdp_url;
static fr_dict_attr_t const *attr_base_crl;
static fr_dict_attr_t const *attr_delta_crl;
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t rlm_crl_dict_attr[];
fr_dict_attr_autoload_t rlm_crl_dict_attr[] = {
	{ .out = &attr_crl_data, .name = "CRL-Data", .type = FR_TYPE_OCTETS, .dict = &dict_crl },
	{ .out = &attr_crl_cdp_url, .name = "CDP-URL", .type = FR_TYPE_STRING, .dict = &dict_crl },
	{ .out = &attr_base_crl, .name = "Base-CRL", .type = FR_TYPE_STRING, .dict = &dict_crl },
	{ .out = &attr_delta_crl, .name = "Delta-CRL", .type = FR_TYPE_STRING, .dict = &dict_crl },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_crl },
	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	fr_value_box_t			serial;				//!< The serial to check
	fr_value_box_list_head_t	*cdp; 				//!< The CRL distribution points
} rlm_crl_env_t;

typedef enum {
	CRL_ERROR = -1,							//!< Unspecified error occurred.
	CRL_ENTRY_NOT_FOUND = 0,					//!< Serial not found in this CRL.
	CRL_ENTRY_FOUND = 1,						//!< Serial was found in this CRL.
	CRL_ENTRY_REMOVED = 2,						//!< Serial was "un-revoked" in this delta CRL.
	CRL_NOT_FOUND = 3,						//!< No CRL found, need to load it from the CDP URL
	CRL_MISSING_DELTA = 4,						//!< Need to load a delta CRL to supplement this CRL.
} crl_ret_t;

#ifdef WITH_TLS
static const call_env_method_t crl_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_crl_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_OFFSET("serial", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_SINGLE, rlm_crl_env_t, serial),
					 .pair.dflt = "session-state.TLS-Certificate.Serial", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("cdp", FR_TYPE_STRING, CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE| CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_MULTI | CALL_ENV_FLAG_NULLABLE, rlm_crl_env_t, cdp),
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

static int8_t crl_pending_cmp(void const *a, void const *b)
{
	crl_pending_t	const *pending_a = (crl_pending_t const *)a;
	crl_pending_t	const *pending_b = (crl_pending_t const *)b;

	return CMP(pending_a->request, pending_b->request);
}

static int8_t crl_fail_cmp(void const *a, void const *b)
{
	crl_fail_t	const *fail_a = (crl_fail_t const *)a;
	crl_fail_t	const *fail_b = (crl_fail_t const *)b;

	return CMP(strcmp(fail_a->cdp_url, fail_b->cdp_url), 0);
}

static xlat_arg_parser_t const crl_refresh_xlat_arg[] = {
	{ .required=true, .concat = true, .type = FR_TYPE_STRING },
	{ .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Forcibly trigger refresh of a CRL
 *
 * Example:
 @verbatim
 %crl.refresh('http://example.com/ca.crl')
 @endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t crl_refresh_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
				      UNUSED request_t *request, fr_value_box_list_t *args)
{
	rlm_crl_t const		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_crl_t);
	rlm_crl_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_crl_thread_t);
	fr_value_box_t		*vb, *url, *base_crl;
	fr_pair_list_t		list;
	fr_pair_t		*vp;
	TALLOC_CTX		*local = talloc_new(NULL);
	int			ret;
	crl_entry_t		find, *found;
	XLAT_ARGS(args, &url, &base_crl);

	fr_pair_list_init(&list);
	fr_pair_list_append_by_da(local, vp, &list, attr_packet_type, (uint32_t)FR_CRL_CRL_REFRESH, false);
	if (!vp) {
	error:
		talloc_free(local);
		return XLAT_ACTION_FAIL;
	}

	if (fr_pair_append_by_da(local, &vp, &list, attr_crl_cdp_url) < 0) goto error;
	if (fr_value_box_copy(vp, &vp->data, url) < 0) goto error;

	if (base_crl) {
		if (fr_pair_append_by_da(local, &vp, &list, attr_base_crl) < 0) goto error;
		if (fr_value_box_copy(vp, &vp->data, base_crl) < 0) goto error;
	}

	ret = fr_worker_to_coord_pair_send(t->cw, inst->coord_pair_reg, &list);

	talloc_free(local);

	if (ret < 0) return XLAT_ACTION_FAIL;

	find = (crl_entry_t) {
		.cdp_url = url->vb_strvalue
	};
	found = fr_rb_find(&t->crls, &find);
	if (found) {
		fr_rb_remove(&t->crls, found);
		talloc_free(found);
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	vb->vb_bool = true;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
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
		REDEBUG2("Certificate revoked by %s", crl_entry->cdp_url);
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
static crl_ret_t crl_check_serial(fr_rb_tree_t *crls, request_t *request, char const *cdp_url, uint8_t const *serial,
				  crl_entry_t **found)
{
	crl_entry_t	*delta, find = { .cdp_url = cdp_url};
	fr_value_box_t	*vb = NULL;
	crl_ret_t	ret = CRL_NOT_FOUND;

	*found = fr_rb_find(crls, &find);
	if (*found == NULL) return CRL_NOT_FOUND;

	/*
	 *	First check the delta if it should exist
	 */
	while ((vb = fr_value_box_list_next(&(*found)->delta_urls, vb))) {
		find.cdp_url = vb->vb_strvalue;
		delta = fr_rb_find(crls, &find);
		if (delta) {
			ret = crl_check_entry(delta, request, serial);

			/*
			 *	An entry found in a delta overrides the base CRL
			 */
			if (ret != CRL_ENTRY_NOT_FOUND) return ret;
			break;
		} else {
			ret = CRL_MISSING_DELTA;
		}
	}

	if (ret == CRL_MISSING_DELTA) return ret;

	return crl_check_entry(*found, request, serial);
}

static int _crl_entry_free(crl_entry_t *crl_entry)
{
	X509_CRL_free(crl_entry->crl);
	return 0;
}

/** Request a CRL from the coordinator
 *
 * @param inst		Module instance
 * @param t		Thread data
 * @param cdp_urls	List of URLs to fetch the CRL from
 * @param base_crl	URL of the base CRL if a delta is being requested.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int crl_fetch_start(rlm_crl_t const *inst, rlm_crl_thread_t *t, fr_value_box_list_t *cdp_urls, char const *base_crl) {
	fr_pair_list_t		list;
	fr_pair_t		*vp;
	TALLOC_CTX		*local = talloc_new(NULL);
	int			ret;

	fr_pair_list_init(&list);
	fr_pair_list_append_by_da(local, vp, &list, attr_packet_type, (uint32_t)FR_CRL_CRL_FETCH, false);
	if (!vp) {
	error:
		talloc_free(local);
		return -1;
	}

	fr_value_box_list_foreach(cdp_urls, cdp) {
		if (fr_pair_append_by_da(local, &vp, &list, attr_crl_cdp_url) < 0) goto error;
		if (fr_value_box_copy(vp, &vp->data, cdp) < 0) goto error;
	}

	if (base_crl) {
		if (fr_pair_append_by_da(local, &vp, &list, attr_base_crl) < 0) goto error;
		fr_value_box_strdup(vp, &vp->data, NULL, base_crl, false);
	}

	ret = fr_worker_to_coord_pair_send(t->cw, inst->coord_pair_reg, &list);

	talloc_free(local);

	return ret;
}

static void crl_by_url_cancel(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	rlm_crl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);
	crl_pending_t		find, *found;

	find = (crl_pending_t) {
		.request = request
	};

	found = fr_rb_find(&t->pending, &find);
	if (!found) return;

	fr_rb_remove(&t->pending, found);
	talloc_free(found);
}

static unlang_action_t CC_HINT(nonnull) mod_crl_by_url(unlang_result_t *p_result, module_ctx_t const *mctx,
						       request_t *request)
{
	rlm_crl_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_crl_t);
	rlm_crl_env_t		*env = talloc_get_type_abort(mctx->env_data, rlm_crl_env_t);
	rlm_crl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);
	fr_value_box_t		*cdp = NULL;
	crl_entry_t		*found;
	fr_value_box_list_t	missing;
	fr_value_box_t		*uri;
	char const		*base_url = NULL;
	int			ret;
	crl_pending_t		*pending;
	crl_fail_t		find, *fail;

	fr_value_box_list_init(&missing);

	while ((cdp = fr_value_box_list_next(env->cdp, cdp))) {
		switch (crl_check_serial(&t->crls, request, cdp->vb_strvalue, env->serial.vb_octets, &found)) {
		case CRL_ENTRY_FOUND:
			RETURN_UNLANG_REJECT;

		case CRL_ENTRY_NOT_FOUND:
		case CRL_ENTRY_REMOVED:
			RETURN_UNLANG_OK;

		case CRL_ERROR:
			continue;

		case CRL_NOT_FOUND:
			uri = fr_value_box_acopy(NULL, cdp);
			fr_value_box_list_insert_tail(&missing, uri);
			continue;

		case CRL_MISSING_DELTA:
			fr_value_box_t	*vb = NULL;
			fr_value_box_list_talloc_free(&missing);
			while ((vb = fr_value_box_list_next(&found->delta_urls, vb))) {
				uri = fr_value_box_acopy(NULL, vb);
				fr_value_box_list_insert_tail(&missing, uri);
			}
			base_url = cdp->vb_strvalue;
			break;
		}
	}

	if (fr_value_box_list_num_elements(&missing) == 0) RETURN_UNLANG_FAIL;

	find = (crl_fail_t) {
		.cdp_url = fr_value_box_list_head(&missing)->vb_strvalue
	};

	/*
	 *	Check to see if the missing CRL has failed to be fetched
	 *	recently.  If it has, within the retry delay time, then
	 *	fail this request.
	 */
	fail = fr_rb_find(&t->fails, &find);
	if (fail) {
		if (fr_time_gt(fr_time_add(fail->fail_time, inst->retry_delay), fr_time())) {
			fr_value_box_list_talloc_free(&missing);
			RETURN_UNLANG_FAIL;
		}

		fr_rb_delete(&t->fails, fail);
	}

	ret = crl_fetch_start(inst, t, &missing, base_url);

	fr_value_box_list_talloc_free(&missing);

	if (ret < 0) RETURN_UNLANG_FAIL;

	if (unlang_module_yield(request, mod_crl_by_url, crl_by_url_cancel,
				~FR_SIGNAL_CANCEL, mctx->rctx) != UNLANG_ACTION_YIELD) RETURN_UNLANG_FAIL;

	MEM(pending = talloc_zero(t, crl_pending_t));
	pending->request = request;

	if (!fr_rb_insert(&t->pending, pending)) {
		talloc_free(pending);
		RETURN_UNLANG_FAIL;
	}

	RDEBUG3("Yielding request until CRL fetching completed");

	return UNLANG_ACTION_YIELD;
}

/** Resume requests waiting for a CRL fetch.
 */
static void crl_pending_resume(rlm_crl_thread_t *thread)
{
	crl_pending_t		*pending;
	fr_rb_iter_inorder_t	iter;

	for (pending = fr_rb_iter_init_inorder(&thread->pending, &iter);
	     pending;
	     pending = fr_rb_iter_next_inorder(&thread->pending, &iter)) {
		fr_rb_iter_delete_inorder(&thread->pending, &iter);
		unlang_interpret_mark_runnable(pending->request);
		talloc_free(pending);
	}
}

/** Callback for worker receiving Fetch-OK packet from coordinator
 */
static void recv_crl_ok(UNUSED fr_coord_worker_t *cw, UNUSED fr_coord_pair_reg_t *coord_pair_reg,
			  fr_pair_list_t const *list, UNUSED fr_time_t now,
			  module_ctx_t *mctx, UNUSED void *uctx)
{
	fr_pair_t               *url, *crl, *delta = NULL;
	crl_entry_t		*crl_entry, find;
	rlm_crl_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);
	uint8_t const		*data;

	url = fr_pair_find_by_da(list, NULL, attr_crl_cdp_url);
	if (!url) {
		ERROR("Missing URL");
		return;
	}

	find = (crl_entry_t) {
		.cdp_url = url->vp_strvalue
	};

	crl_entry = fr_rb_find(&thread->crls, &find);

	crl = fr_pair_find_by_da(list, NULL, attr_crl_data);
	if (!crl) {
		ERROR("No CRL data");
		return;
	}

	/*
	 *	If this CRL didn't previously exist, create the entry
	 */
	if (!crl_entry) {
		MEM(crl_entry = talloc_zero(thread, crl_entry_t));
		crl_entry->cdp_url = talloc_strdup(crl_entry, url->vp_strvalue);
		fr_value_box_list_init(&crl_entry->delta_urls);
		if (!fr_rb_insert(&thread->crls, crl_entry)) {
			talloc_free(crl_entry);
			return;
		}
		talloc_set_destructor(crl_entry, _crl_entry_free);
	} else {
		X509_CRL_free(crl_entry->crl);
		fr_value_box_list_talloc_free(&crl_entry->delta_urls);
	}

	data = crl->vp_octets;
	crl_entry->crl = d2i_X509_CRL(NULL, (const unsigned char **)&data, crl->vp_size);
	if (unlikely(!crl_entry->crl)) {
		ERROR("Failed to parse CRL");
	error:
		fr_rb_remove(&thread->crls, crl_entry);
		talloc_free(crl_entry);
	}

	DEBUG3("CRL %pP refreshed", crl);

	while ((delta = fr_pair_find_by_da(list, delta, attr_delta_crl))) {
		fr_value_box_t	*vb;
		MEM(vb = fr_value_box_alloc_null(crl_entry));
		if (unlikely(fr_value_box_copy(vb, vb, &delta->data) < 0)) goto error;
		fr_value_box_list_insert_tail(&crl_entry->delta_urls, vb);
	}

	crl_pending_resume(thread);
}

/** Callback for worker receiving Fetch-Fail packet from coordinator
 */
static void recv_crl_fail(UNUSED fr_coord_worker_t *cw, UNUSED fr_coord_pair_reg_t *coord_pair_reg,
			  fr_pair_list_t const *list, fr_time_t now, module_ctx_t *mctx, UNUSED void *uctx)
{
	fr_pair_t               *vp;
	rlm_crl_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);

	/*
	 *	Record the URL of the fetch that failed.
	 */
	vp = fr_pair_find_by_da(list, NULL, attr_crl_cdp_url);
	if (vp) {
		crl_fail_t *fail;

		MEM(fail = talloc_zero(thread, crl_fail_t));
		fail->cdp_url = talloc_strdup(fail, vp->vp_strvalue);
		fail->fail_time = now;

		if (unlikely(!fr_rb_insert(&thread->fails, fail))) {
			talloc_free(fail);
		}
	}

	crl_pending_resume(thread);
}

/** Callback for worker receiving CRL-Expire packet from coordinator
 */
static void recv_crl_expire(UNUSED fr_coord_worker_t *cw, UNUSED fr_coord_pair_reg_t *coord_pair_reg,
			    fr_pair_list_t const *list, UNUSED fr_time_t now, module_ctx_t *mctx, UNUSED void *uctx)
{
	fr_pair_t		*vp;
	rlm_crl_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);
	crl_entry_t		*crl_entry, find;

	vp = fr_pair_find_by_da(list, NULL, attr_crl_cdp_url);
	if (!vp) return;

	find = (crl_entry_t) {
		.cdp_url = vp->vp_strvalue
	};

	crl_entry = fr_rb_find(&thread->crls, &find);

	if (!crl_entry) return;

	/*
	 *	If the expired CRL has any deltas, remove them as well.
	 */
	fr_value_box_list_foreach(&crl_entry->delta_urls, delta) {
		crl_entry_t	*delta_entry;

		find.cdp_url = delta->vb_strvalue;
		delta_entry = fr_rb_find(&thread->crls, &find);
		if (!delta_entry) continue;

		WARN("Delta CRL %s expired", delta_entry->cdp_url);
		fr_rb_remove(&thread->crls, delta_entry);
		talloc_free(delta_entry);
	}

	WARN("CRL %s expired", crl_entry->cdp_url);
	fr_rb_remove(&thread->crls, crl_entry);
	talloc_free(crl_entry);
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_crl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);

	fr_rb_inline_init(&t->pending, crl_pending_t, node, crl_pending_cmp, NULL);
	fr_rb_inline_init(&t->crls, crl_entry_t, node, crl_cmp, NULL);
	fr_rb_inline_init(&t->fails, crl_fail_t, node, crl_fail_cmp, NULL);

	return 0;
}

static int mod_coord_attach(module_thread_inst_ctx_t const *mctx)
{
	rlm_crl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);
	rlm_crl_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_crl_t);
	size_t			i;

	t->cw = fr_coord_attach(t, mctx->el, inst->coord_reg);

	if (!t->cw) {
		ERROR("Failed to attach to coordinator");
		return -1;
	}

	if (fr_schedule_worker_id() != 0) return 0;

	/*
	 *	If any urls have been configured to pre-load, trigger those from
	 *	worker ID 0.
	 */
	if (!inst->urls) return 0;

	for (i = 0; i < talloc_array_length(inst->urls); i++) {
		fr_value_box_list_t	list;
		fr_value_box_t		vb;

		DEBUG2("Pre-fetching CRL from %s", inst->urls[i]);
		fr_value_box_list_init(&list);
		fr_value_box_init(&vb, FR_TYPE_STRING, NULL, false);
		fr_value_box_strdup_shallow(&vb, NULL, inst->urls[i], false);
		fr_value_box_list_insert_head(&list, &vb);
		if (crl_fetch_start(inst, t, &list, NULL) < 0) {
			ERROR("Failed to initiate fetch for %s", inst->urls[i]);
			return -1;
		}
	}

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_crl_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_crl_thread_t);

	if (!t->cw) return 0;

	fr_coord_detach(t->cw, true);
	t->cw = NULL;
	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t			*xlat;

	if (unlikely(!(xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "refresh", crl_refresh_xlat,
						       FR_TYPE_BOOL)))) return -1;
	xlat_func_args_set(xlat, crl_refresh_xlat_arg);

	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_crl_t);

	fr_coord_deregister(inst->coord_reg);
	talloc_free(inst->coord_pair_reg);
	return 0;
}

static fr_coord_cb_reg_t coord_callbacks[] = {
	FR_COORD_PAIR_CALLBACK(CRL_COORD_PAIR_CALLBACK_ID),
	FR_COORD_CALLBACK_TERMINATOR
};

static fr_coord_worker_cb_reg_t worker_callbacks[] = {
	FR_COORD_WORKER_PAIR_CALLBACK(CRL_COORD_PAIR_CALLBACK_ID),
	FR_COORD_CALLBACK_TERMINATOR
};

static fr_coord_worker_pair_cb_reg_t worker_pair_callbacks[] = {
	{ .packet_type = FR_CRL_FETCH_OK, .callback = recv_crl_ok },
	{ .packet_type = FR_CRL_FETCH_FAIL, .callback = recv_crl_fail },
	{ .packet_type = FR_CRL_CRL_EXPIRE, .callback = recv_crl_expire },
	FR_COORD_CALLBACK_TERMINATOR
};
#endif

/**	Instantiate the module
 *
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
#ifdef WITH_TLS
	rlm_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_crl_t);

	inst->coord_pair_reg = fr_coord_pair_register(&(fr_coord_pair_reg_ctx_t) {
			.name = mctx->mi->name,
			.worker_cb = worker_pair_callbacks,
			.cb_id = CRL_COORD_PAIR_CALLBACK_ID,
			.root = fr_dict_root(dict_crl),
			.cs = mctx->mi->conf,
		}
	);
	if (!inst->coord_pair_reg) return -1;

	FR_COORD_PAIR_CB_CTX_SET(coord_callbacks, worker_callbacks, inst->coord_pair_reg);

	inst->coord_reg = fr_coord_register(&(fr_coord_reg_ctx_t) {
			.name = mctx->mi->name,
			.coord_cb = coord_callbacks,
			.worker_cb = worker_callbacks,
			.mi = mctx->mi
		});

	if (!inst->coord_reg) return -1;

	return 0;
#else
	cf_log_err(mctx->mi->conf, "rlm_crl requires OpenSSL");
	return -1;
#endif
}

extern module_rlm_t rlm_crl;
module_rlm_t rlm_crl = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.inst_size	= sizeof(rlm_crl_t),
		.instantiate	= mod_instantiate,
		.name		= "crl",
		.config		= module_config,
		MODULE_THREAD_INST(rlm_crl_thread_t),
#ifdef WITH_TLS
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
		.coord_attach		= mod_coord_attach,
		.bootstrap	= mod_bootstrap,
		.detach		= mod_detach,
#endif
	},
#ifdef WITH_TLS
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_crl_by_url, .method_env = &crl_env },
			MODULE_BINDING_TERMINATOR
		}
	}
#endif
};
