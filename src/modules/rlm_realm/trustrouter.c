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
 * @file trustrouter.c
 * @brief Integration with external trust router code
 *
 * @copyright 2014 Network RADIUS SARL
 */
#include <trust_router/tid.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/realms.h>

#ifdef HAVE_TRUST_ROUTER_TR_DH_H
#include "trustrouter.h"

#include <trust_router/tr_dh.h>

/* This instance is supposed to be thread-safe as it is always used read-only (except in the initiation) */
static TIDC_INSTANCE *global_tidc = NULL;

struct resp_opaque {
	REALM *orig_realm;
	REALM *output_realm;
	TID_RC result;
	char err_msg[1024];
	char *fr_realm_name;
};

/*
 * This structure represents a rekey context. It is created once a new REALM is added to the REALM rbtree and it
 * contains the values required to recreate the TIDC request that originated that REALM.
 */
struct rekey_ctx {
	REALM *realm;
	char const *realm_name;
	char const *community;
	char const *rprealm;
	char const *trustrouter;
	unsigned int port;
	unsigned int times;
	unsigned int failed;
	fr_event_t *ev;
};

/* Thread, event list, and mutexes to protect access to the event list */
static pthread_t rekeyer_thread_id;
static fr_event_list_t *rekey_evl = NULL;
static pthread_mutex_t evl_mutex;
static pthread_mutexattr_t evl_mutex_attr;

/* Simultaneous TIDC connections do not work well. We use this mutext to serialize them */
static pthread_mutex_t tidc_mutex;

/* Constant declarations */
static uint MAX_FAILED_REKEYS	= 5;	// Max number of tolerable consecutive rekey errors
static uint REKEY_ERROR_DELAY	= 10;	// Number of seconds we wait until we start a new rekey after a failure
static uint REKEY_THRESHOLD	= 120;	// Number of seconds before the REALM expires to start a rekey

/* Configuration parameters */
static uint32_t realm_lifetime	= 0;		// Number of seconds the REALM can be used
static bool rekey_enabled	= false;	// Is the rekey functionality enabled?

/* Forward declarations */
static void tr_response_func(TIDC_INSTANCE*, TID_REQ*, TID_RESP*, void*);
static void _tr_do_rekey(void *);

/*
 * Builds a rekey_ctx context using the given parameters.
 * Memory context is attached to the REALM object, whereas all the char* fields are copied.
 */
static struct rekey_ctx *build_rekey_ctx(REALM *realm, char const *realm_name, char const *community,
					 char const *rprealm, const char *trustrouter, int port)
{
	struct rekey_ctx *ctx = talloc_zero(realm, struct rekey_ctx);
	ctx->realm = realm;
	ctx->realm_name = talloc_strdup(ctx, realm_name);
	ctx->community = talloc_strdup(ctx, community);
	ctx->rprealm = talloc_strdup(ctx, rprealm);
	ctx->trustrouter = talloc_strdup(ctx, trustrouter);
	ctx->port = port;
	ctx->times = 0;
	ctx->ev = NULL;
	return ctx;
}

/*
 * Main function for the rekeyer thread, which implements the rekey event loop.
 * A recursive lock is used to protect access to the event list, which might receive insertions from
 * other threads (i.e. REQUESTS).
 * If there are no rekey events to be executed, it sleeps for 1 second.
 */
void *rekeyer_thread(UNUSED void* args)
{
	struct timeval when;
	int rv = 0;
	while (true) {
		gettimeofday(&when, NULL);
		pthread_mutex_lock(&evl_mutex);
		rv = fr_event_run(rekey_evl, &when);
		// DEBUG2("REALMs to be rekeyed: %d. Next rekey event in %lu seconds",
		// 	fr_event_list_num_elements(rekey_evl), when.tv_sec - time(NULL));
		pthread_mutex_unlock(&evl_mutex);
		if (!rv) sleep(1);
	}
	return NULL;
}

/*
 * Sends a TIDC request and fills up the provided cookie with the response.
 * Returns FALSE if a response cannot be obtained for some reason (e.g. cannot connect to the TR)
 */
static bool tidc_send_recv(const char *trustrouter, int port, const char *rprealm, const char *realm_name,
			   const char *community, struct resp_opaque *cookie)
{
	gss_ctx_id_t gssctx;
	int conn = 0;
	int rcode;

	/* Open TIDC connection */
	DEBUG2("Opening TIDC connection to %s:%u", trustrouter, port);
	conn = tidc_open_connection(global_tidc, (char *) trustrouter, port, &gssctx);
	if (conn < 0) {
		DEBUG2("Error in tidc_open_connection.");
		return false;
	}

	/* Send TIDC request */
	rcode = tidc_send_request(global_tidc, conn, gssctx, (char *) rprealm, (char *) realm_name,
				  (char *) community, &tr_response_func, cookie);
	if (rcode > 0) {
		DEBUG2("Error in tidc_send_request, rc = %d.", rcode);
		return false;
	}

	return true;
}

/*
 * Gets the maximum expiration time of the realm's auth pool.
 */
static time_t get_realm_expiration(REALM const *realm)
{
	time_t expiration = 0;
	for (int i = 0; i < realm->auth_pool->num_home_servers; i++) {
		home_server_t *server = realm->auth_pool->servers[i];
		if (server->expiration > expiration)
			expiration = server->expiration;
	}
	return expiration;
}

/*
 * Schedules a rekey event with the indicated context by inserting a new event in the list.
 * It uses the evl_mutex to make no other thread accesses the event list at the same time.
 */
static int schedule_rekey(struct rekey_ctx *rekey_ctx)
{
	int rv = 0;
	struct timeval when;
	gettimeofday(&when, NULL);
	pthread_mutex_lock(&evl_mutex);
	/* If last attempt was a failure, schedule a rekey in REKEY_ERROR_DELAY seconds.
	 * Else, schedule the rekey for REKEY_THRESHOLD seconds before the actual REALM expiration.
	 */
	if (rekey_ctx->failed)
		when.tv_sec += REKEY_ERROR_DELAY;
	else
		when.tv_sec = get_realm_expiration(rekey_ctx->realm) - REKEY_THRESHOLD;

	rv = fr_event_insert(rekey_evl, _tr_do_rekey, rekey_ctx, &when, &rekey_ctx->ev);
	pthread_mutex_unlock(&evl_mutex);
	DEBUG2("Scheduled a rekey for realm %s in %lu seconds", rekey_ctx->realm_name, when.tv_sec - time(NULL));
	return rv;
}

/*
 * Callback that performs the actual rekey of a REALM. It receives a rekey_ctx which is used to replicate the
 * original TIDC query. If the request is sucessful, a new rekey is scheduled based on the expiration lifetime and
 * the configured threshold (REKEY_THRESHOLD).
 * When a failure is found, a new rekey is scheduled in a shorter period of time (REKEY_ERROR_DELAY).
 */
static void _tr_do_rekey(void *ctx){
	struct rekey_ctx *rekey_ctx = (struct rekey_ctx *) ctx;
	bool result;
	struct resp_opaque cookie;

	/* clear the cookie structure and copy values from the rekey context */
	memset (&cookie, 0, sizeof(cookie));
	cookie.fr_realm_name = (char*) rekey_ctx->realm->name;
	cookie.orig_realm = rekey_ctx->realm;

	DEBUG2("Rekeying realm %s for the %dth time", rekey_ctx->realm_name, ++rekey_ctx->times);

	/* send the TIDC request and get the response. Use GLOBAL mutext to protect global_tidc and the realm */
	pthread_mutex_lock(&tidc_mutex);
	result = tidc_send_recv(rekey_ctx->trustrouter, rekey_ctx->port, rekey_ctx->rprealm,
			        rekey_ctx->realm_name, rekey_ctx->community, &cookie);
	pthread_mutex_unlock(&tidc_mutex);

	/* If the rekey failed, schedule a new rekey in REKEY_ERROR_DELAY seconds, unless we have failed more
	   than MAX_FAILED_REKEYS times in a row. In that case, return without scheduling a rekey */
	if (!result || cookie.result != TID_SUCCESS) {
		if (++rekey_ctx->failed >= MAX_FAILED_REKEYS) {
			DEBUG2("Reached the maximum number of failed rekeys (%d) for realm %s. Giving up.",
				MAX_FAILED_REKEYS, rekey_ctx->realm_name);
			talloc_free(rekey_ctx);
			return;
		}
		DEBUG2("Rekey for realm %s failed for the %dth time.", rekey_ctx->realm_name, rekey_ctx->failed);
	}
	/* if rekey is successful, reset the failed counter */
	else {
		rekey_ctx->failed = 0;
	}

	/* schedule the new rekey */
	if (!schedule_rekey(rekey_ctx)){
		DEBUG2("Error scheduling rekey event for realm %s!", rekey_ctx->realm_name);
		talloc_free(rekey_ctx);
	}
}

bool tr_init(bool cnf_rekey_enabled, uint32_t cnf_realm_lifetime)
{
	if (global_tidc) return true;

	global_tidc = tidc_create();
	if (!global_tidc) {
		DEBUG2( "tr_init: Error creating global TIDC instance.\n");
		return false;
	}

	if (!tidc_set_dh(global_tidc, tr_create_dh_params(NULL, 0))) {
		DEBUG2( "tr_init: Error creating client DH params.\n");
		return false;
	}

	realm_lifetime = cnf_realm_lifetime;
	rekey_enabled = cnf_rekey_enabled;

	/* create the TIDC mutex */
	pthread_mutex_init(&tidc_mutex, NULL);

	/* If rekey is enabled, set up and create the rekeyer thread, event list and event mutex (recursive) */
	if (rekey_enabled) {
		rekey_evl = fr_event_list_create(NULL, NULL);
		pthread_mutexattr_init(&evl_mutex_attr);
		pthread_mutexattr_settype(&evl_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
		pthread_mutex_init(&evl_mutex, &evl_mutex_attr);
		pthread_create(&rekeyer_thread_id, NULL, rekeyer_thread, NULL);
	}

	return true;
}

static fr_tls_server_conf_t *construct_tls(TIDC_INSTANCE *inst,
					   home_server_t *hs,
					   TID_SRVR_BLK *server)
{
	fr_tls_server_conf_t *tls;
	unsigned char *key_buf = NULL;
	ssize_t keylen;
	char *hexbuf = NULL;
	DH *aaa_server_dh;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	const BIGNUM *dh_pubkey = NULL;
#endif

	tls = tls_server_conf_alloc(hs);
	if (!tls) return NULL;

	aaa_server_dh = tid_srvr_get_dh(server);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	DH_get0_key(aaa_server_dh, &dh_pubkey, NULL);
	if (NULL == dh_pubkey) {
		DEBUG2("DH error");
		goto error;
	}

	keylen = tr_compute_dh_key(&key_buf, BN_dup(dh_pubkey),
				   tidc_get_dh(inst));
#else
	keylen = tr_compute_dh_key(&key_buf, aaa_server_dh->pub_key,
				   tidc_get_dh(inst));
#endif
	if (keylen <= 0) {
		DEBUG2("DH error");
		goto error;
	}

	hexbuf = talloc_size(tls, keylen*2 + 1);
	if (!hexbuf) goto error;

	tr_bin_to_hex(key_buf, keylen, hexbuf, 2*keylen + 1);

	tls->psk_password = hexbuf;
	tls->psk_identity = talloc_strdup(tls, tid_srvr_get_key_name(server)->buf);

	tls->cipher_list = talloc_strdup(tls, "PSK");
	tls->fragment_size = 4200;
	tls->ctx = tls_init_ctx(tls, 1);
	if (!tls->ctx) goto error;

	memset(key_buf, 0, keylen);
	tr_dh_free(key_buf);
	return tls;

error:
	if (key_buf) {
		memset(key_buf, 0, keylen);
		tr_dh_free(key_buf);
	}
	if (hexbuf) memset(hexbuf, 0, keylen*2);

	if (tls) talloc_free(tls);
	return NULL;
}

static char *build_pool_name(TALLOC_CTX *ctx, TID_RESP *resp)
{
	size_t index, sa_len, sl;
	TID_SRVR_BLK *server;
	char *pool_name = NULL;
	char addr_buf[256];
	const struct sockaddr *sa;
	pool_name = talloc_strdup(ctx, "hp-");

	tid_resp_servers_foreach(resp, server, index) {
		tid_srvr_get_address(server, &sa, &sa_len);
		if (0 != getnameinfo(sa, sa_len,
				     addr_buf, sizeof(addr_buf)-1,
				     NULL, 0, NI_NUMERICHOST)) {
			DEBUG2("getnameinfo failed");
			return NULL;
		}

		sl = strlen(addr_buf);
		rad_assert(sl+2 <= sizeof(addr_buf));

		addr_buf[sl] = '-';
		addr_buf[sl+1] = '\0';

		pool_name = talloc_strdup_append(pool_name, addr_buf);
	}

	return pool_name;
}

static home_server_t *srvr_blk_to_home_server(TALLOC_CTX *ctx,
					      TIDC_INSTANCE *inst,
					      TID_SRVR_BLK *blk,
					      char const *realm_name)
{
	home_server_t *hs = NULL;
	const struct sockaddr *sa = NULL;
	size_t sa_len = 0;
	fr_ipaddr_t home_server_ip;
	uint16_t port;
	char nametemp[256];
	time_t now = time(NULL);
	struct timeval key_expiration;

	rad_assert(blk != NULL);
	tid_srvr_get_address(blk, &sa, &sa_len);

	fr_sockaddr2ipaddr((struct sockaddr_storage *) sa, sa_len, &home_server_ip, &port);

	if (0 != getnameinfo(sa, sa_len,
			     nametemp,
			     sizeof nametemp,
			     NULL, 0,
			     NI_NUMERICHOST)) {
		DEBUG2("getnameinfo failed");
		return NULL;
	}

	hs = talloc_zero(ctx, home_server_t);
	if (!hs) return NULL;

	/*
	 *	All dynamic home servers are for authentication.
	 */
	hs->type = HOME_TYPE_AUTH;
	hs->ipaddr = home_server_ip;
	hs->src_ipaddr.af = home_server_ip.af;
	hs->log_name = talloc_asprintf(hs, "%s-for-%s", nametemp, realm_name);
	hs->name = talloc_strdup(hs, nametemp);
	hs->port = port;
	hs->proto = IPPROTO_TCP;
	hs->secret = talloc_strdup(hs, "radsec");
	hs->response_window.tv_sec = 30;
	hs->last_packet_recv = now;
	/*
	 *  We want sockets using these servers to close as soon as possible,
	 *  to make sure that whenever a pool is replaced, sockets using old ones
	 *  will not last long (hopefully less than 300s).
	 */
	hs->limit.idle_timeout = 5;
	/*
	 *  Set the expiration of the server.
	 *  If a realm_lifetime configuration parameter is provided (i.e. >0), use: now + realm_lifetime
	 *  Else use the value from the TIDC response (if the accessor function is available) or now + 600
	 */
#ifdef HAVE_TRUST_ROUTER_GET_KEY_EXP
	tid_srvr_get_key_expiration(blk, &key_expiration);
#else
	key_expiration.tv_sec = now + 600;
#endif
	hs->expiration = realm_lifetime > 0 ? (now + realm_lifetime) : key_expiration.tv_sec;
	hs->tls = construct_tls(inst, hs, blk);
	if (!hs->tls) goto error;

	realm_home_server_sanitize(hs, NULL);

	return hs;
error:
	talloc_free(hs);
	return NULL;
}

static home_pool_t *servers_to_pool(TALLOC_CTX *ctx,
				    TIDC_INSTANCE *inst,
				    TID_RESP *resp,
				    const char *realm_name)
{
	home_pool_t *pool = NULL;
	size_t num_servers = 0, index;
	TID_SRVR_BLK *server = NULL;

	num_servers = tid_resp_get_num_servers(resp);

	pool = talloc_zero_size(ctx, sizeof(*pool) + num_servers *sizeof(home_server_t *));
	if (!pool) goto error;

	pool->type = HOME_POOL_CLIENT_PORT_BALANCE;
	pool->server_type = HOME_TYPE_AUTH;

	pool->name = build_pool_name(pool, resp);
	if (!pool->name) goto error;

	pool->num_home_servers = num_servers;

	tid_resp_servers_foreach(resp, server, index) {
		home_server_t *hs;

		hs = srvr_blk_to_home_server(pool, inst, server, realm_name);
		if (!hs) goto error;
		pool->servers[index] = hs;
	}

	return pool;

error:
	if (pool) talloc_free(pool);

	return NULL;
}

static void tr_response_func( TIDC_INSTANCE *inst,
			      UNUSED TID_REQ *req, TID_RESP *resp,
			      void *cookie)
{
	struct resp_opaque  *opaque = (struct resp_opaque *) cookie;
	REALM *nr = opaque->orig_realm;

	if (tid_resp_get_result(resp) != TID_SUCCESS) {

		size_t err_msg_len;
		opaque->result = tid_resp_get_result(resp);
		memset(opaque->err_msg, 0, sizeof(opaque->err_msg));

		if (tid_resp_get_err_msg(resp)) {
			TR_NAME *err_msg = tid_resp_get_err_msg(resp);
			err_msg_len = err_msg->len+1;
			if (err_msg_len > sizeof(opaque->err_msg))
				err_msg_len = sizeof(opaque->err_msg);
			strlcpy(opaque->err_msg, err_msg->buf, err_msg_len);
		}
		return;
	}

	if (!nr) {
		nr = talloc_zero(NULL, REALM);
		if (!nr) goto error;
		nr->name = talloc_move(nr, &opaque->fr_realm_name);
		nr->auth_pool = servers_to_pool(nr, inst, resp, opaque->fr_realm_name);
		if (!realm_realm_add(nr, NULL)) goto error;

	} else {
		home_pool_t *old_pool = nr->auth_pool;
		home_pool_t *new_pool;

		new_pool = servers_to_pool(nr, inst, resp, opaque->fr_realm_name);
		if (!new_pool) {
			ERROR("Unable to recreate pool for %s", opaque->fr_realm_name);
			goto error;
		}
		nr->auth_pool = new_pool;

		/*
		 *	Mark the old pool as "to be freed"
		 */
		realm_pool_free(old_pool);
	}

	opaque->output_realm = nr;
	return;

error:
	if (nr && !opaque->orig_realm) {
		talloc_free(nr);
	}

	return;
}

static bool update_required(REALM const *r)
{
	const home_pool_t *pool;
	int i;
	const home_server_t *server;
	time_t now = time(NULL);

	/*
	 *	No pool.  Not our realm.
	 */
	if (!r->auth_pool) return false;

	pool = r->auth_pool;

	for (i = 0; i < pool->num_home_servers; i++) {
		server = pool->servers[i];

		/*
		 *	The realm was loaded from the configuration
		 *	files.
		 */
		if (server->cs) return false;

		/*
		 *	These values don't make sense.
		 */
		if ((server->last_packet_recv > (now + 5)) ||
		    (server->last_failed_open > (now + 5))) {
			continue;
		}

		/*
		 *  If home server is expired, update
		 */
		if (now > server->expiration)
			continue;
		/*
		 *	If we've opened in the last 10 minutes, then
		 *	open rather than update.
		 */
		if ((now - server->last_failed_open) > 600) {
			return false;
		}
	}

	return true;
}

REALM *tr_query_realm(REQUEST *request, char const *realm,
		      char const  *community,
		      char const *rprealm,
		      char const *trustrouter,
		      unsigned int port)
{
	VALUE_PAIR *vp;
	struct resp_opaque cookie;
	bool rv = false;

	if (!realm) return NULL;

	if (!trustrouter || (strcmp(trustrouter, "none") == 0)) return NULL;

	/* clear the cookie structure */
	memset (&cookie, 0, sizeof(cookie));

	/* See if the request overrides the community*/
	vp = fr_pair_find_by_num(request->packet->vps, PW_UKERNA_TR_COI, VENDORPEC_UKERNA, TAG_ANY);
	if (vp)
		community = vp->vp_strvalue;
	else pair_make_request("Trust-Router-COI", community, T_OP_SET);

	/* Check if we already have a valid REALM and return it */
	cookie.fr_realm_name = talloc_asprintf(NULL,
					       "%s%%%s",
					       community, realm);
	cookie.orig_realm = cookie.output_realm = realm_find(cookie.fr_realm_name);
	if (cookie.orig_realm && !update_required(cookie.orig_realm))
		goto cleanup;

	/*  We use this lock for serializing TIDC requests and protect access to the TIDC calls */
	pthread_mutex_lock(&tidc_mutex);

	/* Check again that the realm was not created while we were waiting to acquire the lock. */
	cookie.orig_realm = cookie.output_realm = realm_find(cookie.fr_realm_name);
	if (cookie.orig_realm && !update_required(cookie.orig_realm)){
		pthread_mutex_unlock(&tidc_mutex);
		goto cleanup;
	}

	/* Perform the request/response exchange with the trust router server */
	rv = tidc_send_recv(trustrouter, port, (char *) rprealm, (char *) realm, (char *)community, &cookie);
	pthread_mutex_unlock(&tidc_mutex);

	/* If we weren't able to get a response from the trust router server, goto cleanup (hence return NULL realm) */
	if (!rv) goto cleanup;

	/* If we got a response but it is an error one, include a Reply-Message and Error-Cause attributes */
	if (cookie.result != TID_SUCCESS) {
		DEBUG2("TID response is error, rc = %d: %s.\n", cookie.result,
		       cookie.err_msg?cookie.err_msg:"(NO ERROR TEXT)");
		if (cookie.err_msg)
			pair_make_reply("Reply-Message", cookie.err_msg, T_OP_SET);
		pair_make_reply("Error-Cause", "502", T_OP_SET); /*proxy unroutable*/
	}
	/* TIDC request was successful. If rekey is enabled, create a rekey event */
	else if (rekey_enabled) {
		struct rekey_ctx *rctx = build_rekey_ctx(cookie.output_realm, realm, community,
							 rprealm, trustrouter, port);
		if (!schedule_rekey(rctx)){
			talloc_free(rctx);
			DEBUG2("Error scheduling rekey event for realm %s!", realm);
		}
	}

cleanup:
	if (cookie.fr_realm_name)
		talloc_free(cookie.fr_realm_name);

	return cookie.output_realm;
}
#endif	/* HAVE_TRUST_ROUTER_TR_DH_H */
