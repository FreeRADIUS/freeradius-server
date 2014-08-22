/*
 * Copyright (c) 2012-2014, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <trust_router/tid.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>
#include "trustrouter_integ.h"
#include <trust_router/tr_dh.h>
#include <freeradius-devel/realms.h>

static TIDC_INSTANCE *global_tidc = NULL;


struct resp_opaque {
	REALM *orig_realm;
	REALM *output_realm;
	TID_RC result;
	char err_msg[1024];
	char *fr_realm_name;
};


int tr_init(void)
{
	if (NULL == (global_tidc = tidc_create())) {
		DEBUG2( "tr_init: Error creating global TIDC instance.\n");
		return -1;
	}
	if (NULL == (tidc_set_dh(global_tidc, tr_create_dh_params(NULL, 0)))) {
		DEBUG2( "tr_init: Error creating client DH params.\n");
		return 1;
	}
	return 0;
}

static fr_tls_server_conf_t *construct_tls( TIDC_INSTANCE *inst,
					    home_server_t *hs,
					    TID_SRVR_BLK *server)
{
	fr_tls_server_conf_t *tls = talloc_zero( hs, fr_tls_server_conf_t);
	unsigned char *key_buf = NULL;
	ssize_t keylen;
	char *hexbuf = NULL;
	DH *aaa_server_dh;

	if (tls == NULL)
		goto error;
	aaa_server_dh = tid_srvr_get_dh(server);
	keylen = tr_compute_dh_key(&key_buf, aaa_server_dh->pub_key,
				   tidc_get_dh(inst));
	if (keylen <= 0) {
		DEBUG2("DH error");
		goto error;
	}
	hexbuf = talloc_size(tls, keylen*2 + 1);
	if (hexbuf == NULL)
		goto error;
	tr_bin_to_hex(key_buf, keylen, hexbuf,
		      2*keylen + 1);
	tls->psk_password = hexbuf;
	tls->psk_identity = talloc_strdup(tls, tid_srvr_get_key_name(server)->buf);


	tls->cipher_list = talloc_strdup(tls, "PSK");
	tls->fragment_size = 4200;
	tls->ctx = tls_init_ctx(tls, 1);
	if (tls->ctx == NULL)
		goto error;
	memset(key_buf, 0, keylen);
	tr_dh_free(key_buf);
	return tls;
 error:
	if (key_buf) {
		memset(key_buf, 0, keylen);
		tr_dh_free(key_buf);
	}
	if (hexbuf) {
		memset(hexbuf, 0, keylen*2);
		talloc_free(hexbuf);
	}
	if (tls)
		talloc_free(tls);
	return NULL;
}

static char *build_pool_name(void *talloc_ctx, TID_RESP *resp)
{
	size_t index, sa_len, sl;
	TID_SRVR_BLK *server;
	char *pool_name = NULL;
	char addr_buf[256];
	const struct sockaddr *sa;
	pool_name = talloc_strdup(talloc_ctx, "hp-");
	tid_resp_servers_foreach(resp, server, index) {
		tid_srvr_get_address(server, &sa, &sa_len);
		if (0 != getnameinfo(sa, sa_len,
				     addr_buf, sizeof(addr_buf)-1,
				     NULL, 0, NI_NUMERICHOST)) {
			DEBUG2("getnameinfo failed");
			return NULL;
		}
		sl = strlen(addr_buf);
		rad_assert(sl+2 <= sizeof addr_buf);
		addr_buf[sl] = '-';
		addr_buf[sl+1] = '\0';
		pool_name = talloc_strdup_append(pool_name, addr_buf);
	}
	return pool_name;
}

static home_server_t *srvr_blk_to_home_server(
					      void *talloc_ctx,
					      TIDC_INSTANCE *inst,
					      TID_SRVR_BLK *blk,
					      const char *realm_name)
{
	home_server_t *hs = NULL;
	const struct sockaddr *sa = NULL;
	size_t sa_len = 0;
	fr_ipaddr_t home_server_ip;
	uint16_t port;
	char nametemp[256];

	rad_assert(blk != NULL);
	tid_srvr_get_address(blk, &sa, &sa_len);
	switch(sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
		home_server_ip.af = AF_INET;
		home_server_ip.scope = 0;
		home_server_ip.ipaddr.ip4addr = sin->sin_addr;
		port = ntohs(sin->sin_port);
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;
		home_server_ip.af = AF_INET6;
		home_server_ip.scope = sin6->sin6_scope_id;
		home_server_ip.ipaddr.ip6addr = sin6->sin6_addr;
		break;
	}
	default:
		DEBUG2("Unknown address family in tid srvr block");
		return NULL;
	}

	if (0 != getnameinfo(sa, sa_len,
			     nametemp,
			     sizeof nametemp,
			     NULL, 0,
			     NI_NUMERICHOST)) {
		DEBUG2("getnameinfo failed");
		return NULL;
	}
	hs = talloc_zero(talloc_ctx, home_server_t);
	if (!hs) return NULL;
	hs->type = HOME_TYPE_AUTH;
	hs->ipaddr = home_server_ip;
	hs->src_ipaddr.af = home_server_ip.af;
	hs->name = talloc_asprintf(hs, "%s for %s", nametemp, realm_name);
	hs->hostname = talloc_strdup(hs, nametemp);
	hs->port = port;
	hs->proto = IPPROTO_TCP;
	hs->secret = talloc_strdup(hs, "radsec");
	hs->tls = construct_tls(inst, hs, blk);
	hs->response_window.tv_sec = 30;
	hs->last_packet_recv = time(0);
	if (hs->tls == NULL) goto error;
	realm_home_server_sanitize(hs, NULL);

	return hs;
 error:
	talloc_free(hs);
	return NULL;
}

static home_pool_t *servers_to_pool(void *talloc_ctx,
				    TIDC_INSTANCE *inst,
				    TID_RESP *resp,
				    const char *realm_name)
{
	char *pool_name;
	home_pool_t *pool = NULL;
	size_t num_servers = 0, index;
	TID_SRVR_BLK *server = NULL;
	pool_name = build_pool_name( resp, resp);
	num_servers = tid_resp_get_num_servers(resp);
	pool = talloc_zero_size(talloc_ctx, sizeof(*pool) + num_servers *sizeof(home_server_t *));
	if (pool == NULL) goto error;
	pool->type = HOME_POOL_CLIENT_PORT_BALANCE;
	pool->server_type = HOME_TYPE_AUTH;
	pool->name = talloc_steal(pool, pool_name);
	if (pool->name == NULL) goto error;
	pool->num_home_servers = num_servers;
	tid_resp_servers_foreach(resp, server, index) {
		home_server_t *hs = srvr_blk_to_home_server(pool, inst, server, realm_name);
		if (NULL == hs)
			goto error;
		pool->servers[index] = hs;
	}

	return pool;
 error:
	if (pool)
		talloc_free(pool);
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

	if (nr == NULL) {
		nr = talloc_zero(NULL, REALM);
		if (nr == NULL) goto error;
		nr->name = talloc_move(nr, &opaque->fr_realm_name);
		nr->auth_pool = servers_to_pool(nr, inst, resp, opaque->fr_realm_name);
		if (!realm_realm_add(nr, NULL)) goto error;
	} else {
		home_pool_t *old_pool = nr->auth_pool;
		home_pool_t *new_pool = servers_to_pool(nr, inst, resp, opaque->fr_realm_name);
		if (new_pool == NULL) {
			ERROR("Unable to recreate pool for %s", opaque->fr_realm_name);
			goto error;
		}
		nr->auth_pool = new_pool;
		/*xxx Really we want to free this a few seconds from now, so that anyone who is load balancing in the new pool has gotten this update to avoid  the race or at least make it basically unlikely to ever happen.
		 */
		talloc_free(old_pool);
	}

	opaque->output_realm = nr;
	return;

 error:
	if (nr && !opaque->orig_realm)
		talloc_free(nr);
	return;
}

static bool update_required(const REALM 		 *r)
{
	const home_pool_t *pool;
	int i;
	const home_server_t *server;
	time_t now = time(0);
	if (!r->auth_pool)
		return 0; /*not ours*/
	pool = r->auth_pool;
	for (i = 0; i < pool->num_home_servers; i++) {
		server = pool->servers[i];
		if (server->cs)
			return 0; /*we didn't allocate this*/
		if ((server->last_packet_recv > now+5)
		    ||(server->last_failed_open > now+5))
			continue; /*nonsensical values*/
		/*If any server has received a packet in the last 5 minutes then we don't need an update*/
		if (now - server->last_packet_recv < 300)
			return 0;
		/*If we haven't had a failed open to this server in the last 10 minutes, then try an open rather than an update*/
		if (now - server->last_failed_open > 600)
			return 0;
	}
	return 1;
}



REALM *tr_query_realm(const char *q_realm,
		      const char  *q_community,
		      const char *q_rprealm,
		      const char *q_trustrouter,
		      unsigned int q_trport)
{
	int conn = 0;
	int rc;
	gss_ctx_id_t gssctx;
	struct resp_opaque cookie;

	/* clear the cookie structure */
	memset (&cookie, 0, sizeof(struct resp_opaque));
	if (NULL == q_realm)
		return NULL;

	cookie.fr_realm_name = talloc_asprintf(NULL,
					       "%s%%%s",
					       q_community, q_realm);
	cookie.orig_realm = cookie.output_realm = realm_find(cookie.fr_realm_name);
	if (cookie.orig_realm && (!update_required(cookie.orig_realm))) {
		talloc_free(cookie.fr_realm_name);
		return cookie.output_realm;
	}

	/* Set-up TID connection */
	DEBUG2("Openning TIDC connection to %s:%u", q_trustrouter, q_trport);
	if (-1 == (conn = tidc_open_connection(global_tidc, (char *)q_trustrouter, q_trport, &gssctx))) {
		/* Handle error */
		DEBUG2("Error in tidc_open_connection.\n");
		goto cleanup;
	}

	/* Send a TID request */
	if (0 > (rc = tidc_send_request(global_tidc, conn, gssctx, (char *)q_rprealm,
					(char *) q_realm, (char *)q_community,
					&tr_response_func, &cookie))) {
		/* Handle error */
		DEBUG2("Error in tidc_send_request, rc = %d.\n", rc);
		goto cleanup;
	}

 cleanup:
	if (cookie.fr_realm_name)
		talloc_free(cookie.fr_realm_name);
	return cookie.output_realm;
}
