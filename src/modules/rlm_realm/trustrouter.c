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
static TIDC_INSTANCE *global_tidc = NULL;

struct resp_opaque {
	REALM *orig_realm;
	REALM *output_realm;
	TID_RC result;
	char err_msg[1024];
	char *fr_realm_name;
};


bool tr_init(void) 
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

	tls = talloc_zero( hs, fr_tls_server_conf_t);
	if (!tls) return NULL;

	aaa_server_dh = tid_srvr_get_dh(server);
	keylen = tr_compute_dh_key(&key_buf, aaa_server_dh->pub_key,
				   tidc_get_dh(inst));
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
	hs->last_packet_recv = time(NULL);

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
		 *	This server has received a packet in the last
		 *	5 minutes.  It doesn't need an update.
		 */
		if ((now - server->last_packet_recv) < 300) {
			return false;
		}

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
	int conn = 0;
	int rcode;
	VALUE_PAIR *vp;
	gss_ctx_id_t gssctx;
	struct resp_opaque cookie;

	if (!realm) return NULL;

	if (!trustrouter || (strcmp(trustrouter, "none") == 0)) return NULL;

	/* clear the cookie structure */
	memset (&cookie, 0, sizeof(cookie));

	/* See if the request overrides the community*/
	vp = fr_pair_find_by_num(request->packet->vps, PW_UKERNA_TR_COI, VENDORPEC_UKERNA, TAG_ANY);
	if (vp)
		community = vp->vp_strvalue;
	else pair_make_request("Trust-Router-COI", community, T_OP_SET);

	cookie.fr_realm_name = talloc_asprintf(NULL,
					       "%s%%%s",
					       community, realm);

	cookie.orig_realm = cookie.output_realm = realm_find(cookie.fr_realm_name);

	if (cookie.orig_realm && !update_required(cookie.orig_realm)) {
		talloc_free(cookie.fr_realm_name);
		return cookie.orig_realm;
	}
    
	/* Set-up TID connection */
	DEBUG2("Opening TIDC connection to %s:%u", trustrouter, port);

	conn = tidc_open_connection(global_tidc, (char *)trustrouter, port, &gssctx);
	if (conn < 0) {
		/* Handle error */
		DEBUG2("Error in tidc_open_connection.\n");
		goto cleanup;
	}

	/* Send a TID request */
	rcode = tidc_send_request(global_tidc, conn, gssctx, (char *)rprealm, 
				  (char *) realm, (char *)community, 
				  &tr_response_func, &cookie);
	if (rcode < 0) {
		/* Handle error */
		DEBUG2("Error in tidc_send_request, rc = %d.\n", rcode);
		goto cleanup;
	}
	if (cookie.result != TID_SUCCESS) {
		DEBUG2("TID response is error, rc = %d: %s.\n", cookie.result,
		       cookie.err_msg?cookie.err_msg:"(NO ERROR TEXT)");
		if (cookie.err_msg) 
			pair_make_reply("Reply-Message", cookie.err_msg, T_OP_SET);
		pair_make_reply("Error-Cause", "502", T_OP_SET); /*proxy unroutable*/
	}

cleanup:
	if (cookie.fr_realm_name)
		talloc_free(cookie.fr_realm_name);

	return cookie.output_realm;
}
#endif	/* HAVE_TRUST_ROUTER_TR_DH_H */
