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
 * @file src/process/crl/base.c
 * @brief State machine for CRL coordinator thread
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef WITH_TLS
#include <freeradius-devel/crl/crl.h>
#include <freeradius-devel/io/coord_pair.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/tls/utils.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/debug.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>

static fr_dict_t const *dict_crl;
static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t process_crl_dict[];
fr_dict_autoload_t process_crl_dict[] = {
	{ .out = &dict_crl, .proto = "crl" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_crl_cdp_url;
static fr_dict_attr_t const *attr_base_crl;
static fr_dict_attr_t const *attr_crl_data;
static fr_dict_attr_t const *attr_crl_num;
static fr_dict_attr_t const *attr_delta_crl;
static fr_dict_attr_t const *attr_last_update;
static fr_dict_attr_t const *attr_next_update;
static fr_dict_attr_t const *attr_worker_id;

extern fr_dict_attr_autoload_t process_crl_dict_attr[];
fr_dict_attr_autoload_t process_crl_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_crl },
	{ .out = &attr_crl_cdp_url, .name = "CDP-URL", .type = FR_TYPE_STRING, .dict = &dict_crl },
	{ .out = &attr_base_crl, .name = "Base-CRL", .type = FR_TYPE_STRING, .dict = &dict_crl },
	{ .out = &attr_crl_data, .name = "CRL-Data", .type = FR_TYPE_OCTETS, .dict = &dict_crl },
	{ .out = &attr_crl_num, .name = "CRL-Num", .type = FR_TYPE_UINT64, .dict = &dict_crl },
	{ .out = &attr_delta_crl, .name = "Delta-CRL", .type = FR_TYPE_STRING, .dict = &dict_crl },
	{ .out = &attr_last_update, .name = "Last-Update", .type = FR_TYPE_DATE, .dict = &dict_crl },
	{ .out = &attr_next_update, .name = "Next-Update", .type = FR_TYPE_DATE, .dict = &dict_crl },
	{ .out = &attr_worker_id, .name = "Worker-Id", .type = FR_TYPE_INT32, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*crl_fetch;
	CONF_SECTION	*fetch_ok;
	CONF_SECTION	*fetch_fail;
	CONF_SECTION	*do_not_respond;
} process_crl_sections_t;

typedef struct {
	fr_rb_tree_t			crls;		//!< Fetched CRL data.
	fr_dlist_head_t			fetching;	//!< List of CRLs currently being fetched.
} process_crl_mutable_t;

typedef struct {
	process_crl_sections_t		sections;	//!< Pointers to various config sections
							///< we need to execute

	fr_time_delta_t			force_refresh;			//!< Force refresh of CRLs after this time
	bool				force_refresh_is_set;
	fr_time_delta_t			force_delta_refresh;		//!< Force refresh of delta CRLs after this time
	bool				force_delta_refresh_is_set;
	fr_time_delta_t			early_refresh;			//!< Time interval before nextUpdate to refresh
	fr_time_delta_t			retry_delay;			//!< Delay between retries of failed refreshes.
	char const			*ca_file;			//!< File containing certs for verifying CRL signatures.
	char const			*ca_path;			//!< Directory containing certs for verifying CRL signatures.

	bool				allow_expired;			//!< Will CRLs be accepted after nextUpdate
	bool				allow_not_yet_valid;		//!< Will CRLs be accepted before lastUpdate

	X509_STORE			*verify_store;	//!< Store of certificates to verify CRL signatures;

	process_crl_mutable_t		*mutable;	//!< Mutable data
} process_crl_t;

typedef struct {
	fr_event_list_t			*el;		//!< Event list for CRL refresh events.
} process_thread_crl_t;

static const conf_parser_t config[] = {
	{ FR_CONF_OFFSET_IS_SET("force_refresh", FR_TYPE_TIME_DELTA, 0, process_crl_t, force_refresh) },
	{ FR_CONF_OFFSET_IS_SET("force_delta_refresh", FR_TYPE_TIME_DELTA, 0, process_crl_t, force_delta_refresh) },
	{ FR_CONF_OFFSET("early_refresh", process_crl_t, early_refresh) },
	{ FR_CONF_OFFSET("retry_delay", process_crl_t, retry_delay), .dflt = "30s" },
	{ FR_CONF_OFFSET("ca_file", process_crl_t, ca_file) },
	{ FR_CONF_OFFSET("ca_path", process_crl_t, ca_path) },
	{ FR_CONF_OFFSET("allow_expired", process_crl_t, allow_expired) },
	{ FR_CONF_OFFSET("allow_not_yet_valid", process_crl_t, allow_not_yet_valid) },
	CONF_PARSER_TERMINATOR
};

typedef enum {
	CRL_TYPE_BASE,
	CRL_TYPE_DELTA
} crl_type_t;

/** A single CRL in the list of CRLs
 */
typedef struct {
	char const 			*cdp_url;		//!< The URL of the CRL.
	crl_type_t			type;			//!< What type of CRL is this.
	uint8_t				*crl_data;		//!< The CRL data.
	time_t				last_update;		//!< Last update value extracted from the CRL.
	time_t				next_update;		//!< Next update value extracted from the CRL.
	ASN1_INTEGER			*crl_num;		//!< The CRL number.
	fr_rb_node_t			node;			//!< The node in the tree of CRLs;
	fr_time_t			refresh;		//!< Refresh time of the CRL.
	union {
		fr_value_box_list_t	delta_urls;		//!< URLs from which a delta CRL can be retrieved
		char const		*base_url;		//!< Base URL if this is a delta
	};
	process_crl_t			*inst;			//!< Module instance this entry is associated with.
	fr_coord_pair_t			*coord_pair;		//!< The coord_pair which requested this CRL.
	fr_timer_t			*ev;			//!< Timer event for renewal.
} crl_entry_t;

/** An entry in the list of CRLs currently being fetched.
 */
typedef struct {
	char const			*cdp_url;		//!< URL being fetched.
	bool				*workers;		//!< True for each worker waiting for a response.
	fr_dlist_t			entry;			//!< Entry in list of CRLs being fetched.
} crl_fetch_t;

/** An entry in the list of CRL requests pending a currently running fetch
 */
typedef struct {
	request_t			*request;
	int32_t				worker_id;
	fr_dlist_t			entry;
} crl_pending_request_t;

/** Compare two CRLs in the list of entries by URL
 */
static int8_t crl_cmp(void const *a, void const *b)
{
	crl_entry_t	const	*crl_a = (crl_entry_t const *)a;
	crl_entry_t	const	*crl_b = (crl_entry_t const *)b;

	return CMP(strcmp(crl_a->cdp_url,  crl_b->cdp_url), 0);
}

/** Resume context for CRL requests */
typedef struct {
	unlang_result_t		result;			//!< Where process section results are written to
	int32_t			worker_id;		//!< The worker which sent the data leading to this request.
	char const		*cdp_url;		//!< The URL of the CRL being requested.
	crl_entry_t		*crl_entry;		//!< The existing instance a CRL, if previously fetched.
	crl_entry_t		*base_crl;		//!< The base CRL a delta CRL is related to.
	bool			cached;			//!< This is a cached response.
	bool			refresh;		//!< Is this a refresh request.
} process_crl_rctx_t;

#define FR_CRL_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) < FR_CRL_CODE_MAX))
#define FR_CRL_PROCESS_CODE_VALID(_code) (FR_CRL_PACKET_CODE_VALID(_code) || (_code == FR_CRL_DO_NOT_RESPOND))

#define PROCESS_PACKET_TYPE		fr_crl_packet_code_t
#define PROCESS_CODE_MAX		FR_CRL_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_CRL_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_CRL_PROCESS_CODE_VALID
#define PROCESS_INST			process_crl_t
#define PROCESS_RCTX			process_crl_rctx_t

#include <freeradius-devel/server/process.h>

RECV(crl_fetch);
RECV(crl_refresh);

/** Common setup used by both CRL-Fetch and CRL-Refresh
 */
static unlang_action_t fetch_setup_common(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request,
					  fr_pair_t *vp, process_crl_rctx_t *rctx)
{
	process_crl_t		*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);
	crl_fetch_t		*fetch;

	/*
	 *	Check to see if we're already fetching this URL.  If so, record
	 *	that this worker wants the reply, and just Do Not Respond.
	 */
	fr_dlist_foreach(&inst->mutable->fetching, crl_fetch_t, fetching) {
		if (strcmp(fetching->cdp_url, vp->vp_strvalue) == 0) {
			if (rctx->worker_id >= 0) fetching->workers[rctx->worker_id] = true;
			RDEBUG2("CRL already being fetched");
			return CALL_SEND_TYPE(FR_CRL_DO_NOT_RESPOND);
		}
	}

	/*
	 *	Cache the URI / Base CRL incase the pair gets altered / deleted in the process section.
	 */
	rctx->cdp_url = talloc_bstrdup(rctx, vp->vp_strvalue);

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_base_crl);
	if (vp) {
		crl_entry_t		find;
		find.cdp_url = vp->vp_strvalue;
		rctx->base_crl = fr_rb_find(&inst->mutable->crls, &find);
	}

	/*
	 *	Record what CRL we're fetching in the list.
	 */
	MEM(fetch = talloc(inst->mutable, crl_fetch_t));
	fetch->cdp_url = rctx->cdp_url;
	fetch->workers = talloc_zero_array(fetch, bool, main_config->max_workers);
	fr_dlist_insert_tail(&inst->mutable->fetching, fetch);

	return CALL_RECV(generic);
}

/** Build reply pairs from a CRL
 *
 * Pairs are marked as immutable to prevent changes when run through send Fetch-OK
 */
static int crl_build_reply(request_t *request, crl_entry_t *crl_entry)
{
	fr_pair_t	*vp;

	if (pair_update_reply(&vp, attr_crl_cdp_url) < 0) return -1;;
	fr_value_box_clear_value(&vp->data);
	fr_value_box_strdup(vp, &vp->data, NULL, crl_entry->cdp_url, false);
	fr_pair_immutable(vp);

	if (fr_pair_append_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_crl_num)< 0) return -1;
	ASN1_INTEGER_get_uint64(&vp->vp_uint64, crl_entry->crl_num);
	fr_pair_immutable(vp);

	if (crl_entry->type == CRL_TYPE_BASE) {
		fr_value_box_list_foreach(&crl_entry->delta_urls, delta_url) {
			if (fr_pair_append_by_da(request->reply_ctx, &vp, &request->reply_pairs,
						 attr_delta_crl) < 0) return -1;
			if (unlikely(fr_value_box_copy(vp, &vp->data, delta_url) < 0)) {
				fr_pair_remove(&request->reply_pairs, vp);
				talloc_free(vp);
			}
			fr_pair_immutable(vp);
		}
	}

	if (fr_pair_append_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_last_update) < 0) return -1;
	vp->vp_date = fr_unix_time_from_sec(crl_entry->last_update);
	fr_pair_immutable(vp);

	if (fr_pair_append_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_next_update) < 0) return -1;
	vp->vp_date = fr_unix_time_from_sec(crl_entry->next_update);
	fr_pair_immutable(vp);

	return 0;
}

/** CRL-Fetch packets are sent from workers to the coordinator.
 *
 * They can reply with cached data if it exists, otherwise a fetch will
 * be initiated.
 *
 * Replies will always be sent back.
 */
RECV(crl_fetch)
{
	process_crl_t		*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);
	process_crl_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_crl_rctx_t);
	fr_pair_t		*vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_worker_id);
	crl_entry_t		find, *crl_entry;

	if (!vp) return UNLANG_ACTION_FAIL;
	rctx->worker_id = vp->vp_int32;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_crl_cdp_url);
	if (!vp) return UNLANG_ACTION_FAIL;

	find.cdp_url = vp->vp_strvalue;
	rctx->crl_entry = crl_entry = fr_rb_find(&inst->mutable->crls, &find);

	/*
	 *	If we found the data, send it back without running the process section as long as it's not expired.
	 */
	if (crl_entry && (inst->allow_expired || fr_time_gt(fr_time_from_sec(crl_entry->next_update),
							    fr_time_from_sec(time(NULL))))) {
		if (fr_pair_append_by_da(request->reply_ctx, &vp, &request->reply_pairs,
					 attr_crl_data) < 0) return CALL_SEND_TYPE(FR_CRL_FETCH_FAIL);
		fr_value_box_memdup_buffer(vp, &vp->data, NULL, crl_entry->crl_data, false);
		fr_pair_set_immutable(vp);

		if (crl_build_reply(request, crl_entry) < 0) return CALL_SEND_TYPE(FR_CRL_FETCH_FAIL);

		rctx->cached = true;
		return CALL_SEND_TYPE(FR_CRL_FETCH_OK);
	}

	return fetch_setup_common(p_result, mctx, request, vp, rctx);
}

/** CRL-Refresh packets are generated within the coordinator by refresh timer events
 *
 * Fetching of CRL data is run through the recv Fetch-CRL process section.
 * Data will only be sent to workers if the refresh fetched a newer CRL.
 */
RECV(crl_refresh) {
	process_crl_t		*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);
	process_crl_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_crl_rctx_t);
	fr_pair_t		*vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_crl_cdp_url);
	crl_entry_t		find;

	if (!vp) return UNLANG_ACTION_FAIL;

	find.cdp_url = vp->vp_strvalue;
	rctx->crl_entry = fr_rb_find(&inst->mutable->crls, &find);
	if (rctx->crl_entry) rctx->refresh = true;

	return fetch_setup_common(p_result, mctx, request, vp, rctx);
}

/** Tidy up CRL entries when freeing.
 */
static int _crl_entry_free(crl_entry_t *to_free)
{
	if (to_free->crl_num) ASN1_INTEGER_free(to_free->crl_num);

	/*
	 *	Ensure the entry is no-longer in the tree.
	 */
	if (fr_rb_node_inline_in_tree(&to_free->node)) fr_rb_remove(&to_free->inst->mutable->crls, to_free);

	/*
	 *	If the entry referenced deltas, those must be removed as well.
	 */
	if ((to_free->type == CRL_TYPE_BASE) && fr_value_box_list_initialised(&to_free->delta_urls)) {
		fr_value_box_list_foreach(&to_free->delta_urls, delta) {
			crl_entry_t	find, *delta_crl;

			find.cdp_url = delta->vb_strvalue;
			delta_crl = fr_rb_find(&to_free->inst->mutable->crls, &find);
			if (!delta_crl) continue;

			fr_rb_remove(&to_free->inst->mutable->crls, delta_crl);
			talloc_free(delta_crl);
		}
	}

	return 0;
}

/** Event callback to trigger the refresh of a CRL
 */
static void crl_refresh_event(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	crl_entry_t	*crl_entry = talloc_get_type_abort(uctx, crl_entry_t);
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	TALLOC_CTX	*local = talloc_new(NULL);

	DEBUG2("Refreshing CRL from CDP %s", crl_entry->cdp_url);

	fr_pair_list_init(&list);
	fr_pair_list_append_by_da(local, vp, &list, attr_packet_type, (uint32_t)FR_CRL_CRL_REFRESH, false);
	if (!vp) {
	fail:
		talloc_free(local);
		return;
	}

	if (fr_pair_append_by_da(local, &vp, &list, attr_crl_cdp_url) < 0) goto fail;
	fr_value_box_strdup(vp, &vp->data, NULL, crl_entry->cdp_url, false);

	if (crl_entry->type == CRL_TYPE_DELTA) {
		if (fr_pair_append_by_da(local, &vp, &list, attr_base_crl) < 0) goto fail;
		fr_value_box_strdup(vp, &vp->data, NULL, crl_entry->cdp_url, false);
	}

	if (fr_coord_pair_coord_request_start(crl_entry->coord_pair, &list, now) < 0) {
		ERROR("Failed to initialise CRL refresh request");
		if (fr_timer_in(crl_entry, tl, &crl_entry->ev, crl_entry->inst->retry_delay, false,
				crl_refresh_event, crl_entry) <0) {
			ERROR("Failed to set timer to retry CRL refresh");
		}
	}

	talloc_free(local);
}

static inline void crl_fetching_entry_remove(fr_dlist_head_t *fetching, char const *cdp_url) {
	fr_dlist_foreach(fetching, crl_fetch_t, fetch) {
		if (strcmp(fetch->cdp_url, cdp_url) == 0) {
			fr_dlist_remove(fetching, fetch);
			talloc_free(fetch);
			return;
		}
	}
}

RESUME(crl_fetch)
{
	process_crl_t		*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);
	process_thread_crl_t	*thread = talloc_get_type_abort(mctx->thread, process_thread_crl_t);
	process_crl_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_crl_rctx_t);
	crl_entry_t		*crl_entry = NULL;
	fr_pair_t		*crl_data;
	uint8_t const		*data;
	X509_CRL		*crl;
	X509_STORE_CTX		*verify_ctx = NULL;
	X509_OBJECT		*xobj;
	EVP_PKEY		*pkey;
	STACK_OF(DIST_POINT)	*dps;
	int			i;
	fr_time_t		now = fr_time();
	fr_time_delta_t		refresh_delta;

	switch (RESULT_RCODE) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return CALL_RESUME(recv_generic);
	default:
		break;
	}

	/*
	 *	If no CRL data was returned, that's a failure
	 */
	crl_data = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_crl_data);
	if (!crl_data) {
		RERROR("No %s found", attr_crl_data->name);
		return CALL_SEND_TYPE(FR_CRL_FETCH_FAIL);
	}
	fr_pair_immutable(crl_data);

	/*
	 *	Parse the CRL data and verify it is correctly signed
	 */
	data = crl_data->vp_octets;
	crl = d2i_X509_CRL(NULL, (const unsigned char **)&data, crl_data->vp_size);
	if (!crl) {
		fr_tls_strerror_printf("Failed to parse CRL from %s", rctx->cdp_url);
		return CALL_SEND_TYPE(FR_CRL_FETCH_FAIL);
	}

	verify_ctx = X509_STORE_CTX_new();
        if (!verify_ctx || !X509_STORE_CTX_init(verify_ctx, inst->verify_store, NULL, NULL)) {
		fr_tls_strerror_printf("Error initialising X509 store");
	error:
		if (verify_ctx) X509_STORE_CTX_free(verify_ctx);
		RPERROR("Error verifying CRL");
		X509_CRL_free(crl);
		talloc_free(crl_entry);
		return CALL_SEND_TYPE(FR_CRL_FETCH_FAIL);
        }

        xobj = X509_STORE_CTX_get_obj_by_subject(verify_ctx, X509_LU_X509, X509_CRL_get_issuer(crl));
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
        i = X509_CRL_verify(crl, pkey);
        EVP_PKEY_free(pkey);

	if (i < 0) {
		fr_tls_strerror_printf("Could not verify CRL signature");
		goto error;
	}
        if (i == 0) {
		fr_tls_strerror_printf("CRL certificate signature failed");
		goto error;
	}

	/*
	 *	Now we have a verified CRL, start building the entry for the global list
	 */
	MEM(crl_entry = talloc_zero(inst->mutable, crl_entry_t));
	crl_entry->inst = inst;

	/*
	 *	If we're passed a base_crl, then this is a delta.
	 */
	crl_entry->type = rctx->base_crl ? CRL_TYPE_DELTA : CRL_TYPE_BASE;
	talloc_set_destructor(crl_entry, _crl_entry_free);

	if (fr_tls_utils_asn1time_to_epoch(&crl_entry->next_update, X509_CRL_get0_nextUpdate(crl)) < 0) {
		RPERROR("Failed to parse nextUpdate from CRL");
		goto error;
	}

	if (!inst->allow_expired && fr_time_lt(fr_time_from_sec(crl_entry->next_update),
					       fr_time_from_sec(time(NULL)))) {
		RPERROR("Fetched CRL expired at %pV", fr_box_time(fr_time_from_sec(crl_entry->next_update)));
		goto error;
	}

	crl_entry->crl_num = X509_CRL_get_ext_d2i(crl, NID_crl_number, &i, NULL);
	if (!crl_entry->crl_num) {
		fr_tls_strerror_printf("Missing CRL number");
		goto error;
	}

	/*
	 *	If there is existing data for this CRL, the it should only be updated if the number has increased.
	 */
	if (rctx->crl_entry) {
		if (ASN1_INTEGER_cmp(crl_entry->crl_num, rctx->crl_entry->crl_num) == 0) {
			uint64_t new_num;
			ASN1_INTEGER_get_uint64(&new_num, crl_entry->crl_num);
			RDEBUG3("Refresh returned the same CRL number (%"PRIu64") as the existing entry", new_num);
			goto use_old;
		}
		if (ASN1_INTEGER_cmp(crl_entry->crl_num, rctx->crl_entry->crl_num) < 0) {
			uint64_t old_num, new_num;
			ASN1_INTEGER_get_uint64(&old_num, rctx->crl_entry->crl_num);
			ASN1_INTEGER_get_uint64(&new_num, crl_entry->crl_num);
			RERROR("Got CRL number %"PRIu64" which is less than current number %"PRIu64,
			       new_num, old_num);
		use_old:
			crl_fetching_entry_remove(&inst->mutable->fetching, rctx->cdp_url);
			talloc_free(crl_entry);
			crl_entry = rctx->crl_entry;

			if (rctx->refresh) {
				/*
				 *	A refresh which didn't produce updated data means noop.
				 */
				rctx->result.rcode = RLM_MODULE_NOOP;
			} else {
				/*
				 *	CRL-Fetch requests expect a response.
				 */
				if (crl_build_reply(request, crl_entry) < 0) goto error;
			}
			goto timer;
		}

		/*
		 *	The fetched entry data is newer, free the old entry.
		 *	This will also remove it from the tree and clear any
		 *	related deltas.
		 */
		TALLOC_FREE(rctx->crl_entry);
	}

	/*
	 *	The fetched CRL is now validated and newer than the old
	 *	entry, complete building the entry.
	 */
	crl_entry->cdp_url = talloc_bstrdup(crl_entry, rctx->cdp_url);
	crl_entry->crl_data = talloc_typed_memdup(crl_entry, crl_data->vp_octets, crl_data->vp_length);
	crl_entry->coord_pair = fr_coord_pair_request_coord_pair(request);

	/*
	 *	If this is a delta check it relates to the correct base.
	 */
	if (crl_entry->type == CRL_TYPE_DELTA) {
		ASN1_INTEGER *base_num = X509_CRL_get_ext_d2i(crl, NID_delta_crl, &i, NULL);

#ifdef __clang_analyzer__
		/*
		 *	type is set to CRL_TYPE_DELTA by the presence of a base_crl
		 *	but the analysers don't detect this.
		 */
		if (unlikely(!rctx->base_crl)) goto error;
#endif
		fr_assert(rctx->base_crl);
		if (!base_num) {
			RERROR("Delta CRL missing Delta CRL Indicator extension");
			goto error;
		}
		if (ASN1_INTEGER_cmp(base_num, rctx->base_crl->crl_num) > 0) {
			uint64_t delta_base, crl_num;
			ASN1_INTEGER_get_uint64(&delta_base, base_num);
			ASN1_INTEGER_get_uint64(&crl_num, rctx->base_crl->crl_num);
			RERROR("Delta CRL refers to base CRL number %"PRIu64", current base is %"PRIu64,
			       delta_base, crl_num);
			ASN1_INTEGER_free(base_num);
			goto error;
		}
		ASN1_INTEGER_free(base_num);
		if (ASN1_INTEGER_cmp(crl_entry->crl_num, rctx->base_crl->crl_num) < 0) {
			uint64_t delta_num, crl_num;
			ASN1_INTEGER_get_uint64(&delta_num, crl_entry->crl_num);
			ASN1_INTEGER_get_uint64(&crl_num, rctx->base_crl->crl_num);
			RERROR("Delta CRL number %"PRIu64" is less than base CRL number %"PRIu64, delta_num, crl_num);
			goto error;
		}
		crl_entry->base_url = talloc_strdup(crl_entry, rctx->base_crl->cdp_url);
	}

	if (fr_tls_utils_asn1time_to_epoch(&crl_entry->last_update, X509_CRL_get0_lastUpdate(crl)) < 0) {
		RPERROR("Failed to parse lastUpdate from CRL");
		goto error;
	}

	if (!inst->allow_not_yet_valid && fr_time_gt(fr_time_from_sec(crl_entry->last_update),
						     fr_time_from_sec(time(NULL)))) {
		RPERROR("Fetched CRL is not valid until %pV", fr_box_time(fr_time_from_sec(crl_entry->last_update)));
		goto error;
	}

	/*
	 *	Check if this CRL has a Freshest CRL extension - the list of URIs to get deltas from
	 */
	if ((crl_entry->type == CRL_TYPE_BASE) && (dps = X509_CRL_get_ext_d2i(crl, NID_freshest_crl, NULL, NULL))) {
		DIST_POINT		*dp;
		STACK_OF(GENERAL_NAME)	*names;
		GENERAL_NAME		*name;
		int			j;
		fr_value_box_t		*vb;

		fr_value_box_list_init(&crl_entry->delta_urls);
		for (i = 0; i < sk_DIST_POINT_num(dps); i++) {
			dp = sk_DIST_POINT_value(dps, i);
			names = dp->distpoint->name.fullname;
			for (j = 0; j < sk_GENERAL_NAME_num(names); j++) {
				name = sk_GENERAL_NAME_value(names, j);
				if (name->type != GEN_URI) continue;
				MEM(vb = fr_value_box_alloc_null(crl_entry));
				fr_value_box_bstrndup(vb, vb, NULL,
						      (char const *)ASN1_STRING_get0_data(name->d.uniformResourceIdentifier),
						      ASN1_STRING_length(name->d.uniformResourceIdentifier), true);
				RDEBUG3("CRL references delta URI %pV", vb);
				fr_value_box_list_insert_tail(&crl_entry->delta_urls, vb);
			}
		}
		CRL_DIST_POINTS_free(dps);

		/*
		 *	If the CRL has a delta then fetch it.  An updated CRL means the
		 *	delta must be updated or it's invalid as it will point to the wrong
		 *	version of the base CRL.
		 */
		if (fr_value_box_list_num_elements(&crl_entry->delta_urls) > 0) {
			fr_pair_list_t	list;
			fr_pair_t	*vp;
			TALLOC_CTX	*local = talloc_new(NULL);

			fr_pair_list_init(&list);
			fr_pair_list_append_by_da(local, vp, &list, attr_packet_type, (uint32_t)FR_CRL_CRL_REFRESH, false);
			if (!vp) goto free_local;

			fr_value_box_list_foreach(&crl_entry->delta_urls, delta) {
				if (fr_pair_append_by_da(local, &vp, &list, attr_crl_cdp_url) < 0) goto free_local;
				if (unlikely(fr_value_box_copy(vp, &vp->data, delta) < 0)) goto free_local;
			}

			if (fr_pair_append_by_da(local, &vp, &list, attr_base_crl) < 0) goto free_local;
			if (unlikely(fr_value_box_strdup(vp, &vp->data, NULL, rctx->cdp_url,
							 false) < 0)) goto free_local;

			if (fr_coord_pair_coord_request_start(crl_entry->coord_pair, &list, now) < 0) {
				RERROR("Failed to start fetch of delta CRL");
			}

		free_local:
			talloc_free(local);
		}
	}

	if (!fr_rb_insert(&inst->mutable->crls, crl_entry)) {
		RERROR("Failed storing CRL");
		goto error;
	}

	if (crl_build_reply(request, crl_entry) < 0) goto error;

timer:
	/*
	 *	Setup a timer to refresh the CRL
	 */
	crl_entry->refresh = fr_time_from_sec(crl_entry->next_update);
	refresh_delta = fr_time_delta_sub(fr_time_sub(crl_entry->refresh, now), inst->early_refresh);
	if (rctx->base_crl && inst->force_delta_refresh_is_set) {
		if (fr_time_delta_cmp(refresh_delta, inst->force_delta_refresh)) refresh_delta = inst->force_delta_refresh;
	} else {
		if (inst->force_refresh_is_set &&
		    (fr_time_delta_cmp(refresh_delta, inst->force_refresh) > 0)) refresh_delta = inst->force_refresh;
	}

	/*
	 *	A negative expiry time will occur if a refresh fails to fetch a newer CRL
	 *	or the CRL has already expired. In that case use retry_delay to rate limit retries.
	 */
	if (fr_time_delta_isneg(refresh_delta)) refresh_delta = inst->retry_delay;

	RDEBUG2("CRL from %s will refresh in %pVs", rctx->cdp_url, fr_box_time_delta(refresh_delta));

	if (fr_timer_in(crl_entry, thread->el->tl, &crl_entry->ev, refresh_delta, false, crl_refresh_event, crl_entry) <0) {
		RERROR("Failed to set timer to refresh CRL");
	}

	X509_STORE_CTX_free(verify_ctx);
	X509_CRL_free(crl);

	return CALL_RESUME(recv_generic);
}

RESUME_FLAG(send_crl_ok, UNUSED,)
{
	process_crl_t		*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);
	process_crl_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_crl_rctx_t);

	/*
	 *	Remove the fetching entry.  We use broadcast for the reply after
	 *	a fetch so no need to individually send to workers.
 	 */
	crl_fetching_entry_remove(&inst->mutable->fetching, rctx->cdp_url);

	if (rctx->cached) {
		/*
		 *	Cached replies are only sent to the worker which requested the data.
		 */
		RDEBUG3("Sending cached CRL to worker %d", rctx->worker_id);
		fr_coord_to_worker_reply_send(request, rctx->worker_id);
	} else {
		/*
		 *	Successful update of a CRL is broadcast to all clients.
		 */
		RDEBUG3("Sending updated CRL to all workers");
		fr_coord_to_worker_reply_broadcast(request);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

RESUME_FLAG(send_crl_fail, UNUSED,)
{
	process_crl_t		*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);
	process_thread_crl_t	*thread = talloc_get_type_abort(mctx->thread, process_thread_crl_t);
	process_crl_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_crl_rctx_t);
	fr_pair_t		*vp;

	if (rctx->refresh) {
		crl_fetching_entry_remove(&inst->mutable->fetching, rctx->cdp_url);

		/*
		 *	Set up retry of failed refresh.
		 */
		RDEBUG2("Refresh of CRL from %s will retry in %pVs", rctx->cdp_url, fr_box_time_delta(inst->retry_delay));

		if (fr_timer_in(rctx->crl_entry, thread->el->tl, &rctx->crl_entry->ev, inst->retry_delay,
				false, crl_refresh_event, rctx->crl_entry) <0) {
			RERROR("Failed to set timer to retry CRL fetch");
		}

		/*
		 *	Refresh requests are local to the coordinator, so there
		 *	is nothing to send back on a failure, unless the CRL has
		 *	expired and expired CRLs are not allowed.
		 */
		if (inst->allow_expired || fr_time_gt(fr_time_from_sec(rctx->crl_entry->next_update),
						      fr_time_from_sec(time(NULL)))) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	A refresh failed on an expired CRL, notify all workers with a CRL-Expire reply.
		 */
		fr_pair_list_free(&request->reply_pairs);
		if (fr_pair_append_by_da(request->reply_ctx, &vp, &request->reply_pairs,
					 attr_packet_type) < 0) RETURN_UNLANG_FAIL;
		vp->vp_uint32 = FR_CRL_CRL_EXPIRE;

		if (fr_pair_append_by_da(request->reply_ctx, &vp, &request->reply_pairs,
					 attr_crl_cdp_url) < 0) RETURN_UNLANG_FAIL;
		fr_value_box_strdup(vp, &vp->data, NULL, rctx->cdp_url, false);

		fr_coord_to_worker_reply_broadcast(request);

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	The fetch failed, ensure we don't send CRL data back
	 */
	fr_pair_delete_by_da(&request->reply_pairs, attr_crl_data);

	if (pair_update_reply(&vp, attr_crl_cdp_url) < 0) RETURN_UNLANG_FAIL;
	fr_value_box_strdup(vp, &vp->data, NULL, rctx->cdp_url, false);

	RDEBUG3("Sending fail to worker %d", rctx->worker_id);
	fr_coord_to_worker_reply_send(request, rctx->worker_id);

	/*
	 *	If any other workers were waiting for this CRL, send them
	 *	the failure as well.
 	 */
	fr_dlist_foreach(&inst->mutable->fetching, crl_fetch_t, fetch) {
		if (strcmp(fetch->cdp_url, rctx->cdp_url) == 0) {
			uint32_t	i;
			fr_dlist_remove(&inst->mutable->fetching, fetch);
			for (i = 0; i < main_config->max_workers; i++) {
				if (fetch->workers[i]) {
					fr_coord_to_worker_reply_send(request, i);
					RDEBUG3("Sending fail to worker %d", i);
				}
			}
			talloc_free(fetch);
			break;
		}
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_crl_t);
	fr_assert(FR_CRL_PACKET_CODE_VALID(request->packet->code));

	request->component = "crl";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_crl);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->request_pairs, NULL);

	return state->recv(p_result, mctx, request);
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	process_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);

	MEM(inst->mutable = talloc_zero(NULL, process_crl_mutable_t));

	fr_rb_inline_init(&inst->mutable->crls, crl_entry_t, node, crl_cmp, NULL);
	fr_dlist_init(&inst->mutable->fetching, crl_fetch_t, entry);

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
	process_crl_t	*inst = talloc_get_type_abort(mctx->mi->data, process_crl_t);

	if (inst->verify_store) X509_STORE_free(inst->verify_store);
	talloc_free(inst->mutable);

	return 0;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	process_thread_crl_t	*t = talloc_get_type_abort(mctx->thread, process_thread_crl_t);

	t->el = mctx->el;
	return 0;
}

static fr_process_state_t const process_state[] = {
	/*
	 *	Fetch a CRL
	 */
	[ FR_CRL_CRL_FETCH ] = {
		.packet_type = {
			[RLM_MODULE_OK]		= FR_CRL_FETCH_OK,
			[RLM_MODULE_UPDATED]	= FR_CRL_FETCH_OK,
			[RLM_MODULE_FAIL]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_INVALID]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_REJECT]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_NOOP]	= FR_CRL_FETCH_OK,
			[RLM_MODULE_TIMEOUT]	= FR_CRL_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_crl_fetch,
		.resume = resume_crl_fetch,
		.section_offset = offsetof(process_crl_sections_t, crl_fetch),
	},
	[ FR_CRL_CRL_REFRESH ] = {
		.packet_type = {
			[RLM_MODULE_OK]		= FR_CRL_FETCH_OK,
			[RLM_MODULE_UPDATED]	= FR_CRL_FETCH_OK,
			[RLM_MODULE_FAIL]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_INVALID]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_REJECT]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_NOOP]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_CRL_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_crl_refresh,
		.resume = resume_crl_fetch,
		.section_offset = offsetof(process_crl_sections_t, crl_fetch),
	},
	[ FR_CRL_FETCH_OK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_INVALID]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_REJECT]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_CRL_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_crl_ok,
		.section_offset = offsetof(process_crl_sections_t, fetch_ok),
	},
	[ FR_CRL_FETCH_FAIL ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_INVALID]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_REJECT]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_CRL_FETCH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_CRL_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
		.send = send_generic,
		.resume = resume_send_crl_fail,
		.section_offset = offsetof(process_crl_sections_t, fetch_fail),
	},
	[ FR_CRL_DO_NOT_RESPOND ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_HANDLED]	= FR_CRL_DO_NOT_RESPOND,

			[RLM_MODULE_NOTFOUND]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_CRL_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_CRL_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_HANDLED,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_crl_sections_t, do_not_respond),
	}
};

static virtual_server_compile_t compile_list[] = {
	{
		.section = SECTION_NAME("recv", "CRL-Fetch"),
		.actions = &mod_actions_authenticate,
		.offset = PROCESS_CONF_OFFSET(crl_fetch),
	},
	{
		.section = SECTION_NAME("send", "Fetch-OK"),
		.actions = &mod_actions_authenticate,
		.offset = PROCESS_CONF_OFFSET(fetch_ok),
	},
	{
		.section = SECTION_NAME("send", "Fetch-Fail"),
		.actions = &mod_actions_authenticate,
		.offset = PROCESS_CONF_OFFSET(fetch_fail),
	},
	{
		.section = SECTION_NAME("send", "Do-Not-Respond"),
		.actions = &mod_actions_authenticate,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},

	COMPILE_TERMINATOR
};

extern fr_process_module_t process_crl;
fr_process_module_t process_crl = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "crl",
		.config			= config,
		MODULE_INST(process_crl_t),
		MODULE_RCTX(process_crl_rctx_t),
		.instantiate		= mod_instantiate,
		.detach			= mod_detach,
		MODULE_THREAD_INST(process_thread_crl_t),
		.thread_instantiate	= mod_thread_instantiate
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_crl,
	.packet_type	= &attr_packet_type
};
#endif
