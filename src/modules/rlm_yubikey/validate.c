/**
 * $Id$
 * @file rlm_yubikey/validate.c
 * @brief Authentication for yubikey OTP tokens using the ykclient library.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@networkradius.com)
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Network RADIUS (legal@networkradius.com)
 */
#define LOG_PREFIX "rlm_yubikey (%s) - "
#define LOG_PREFIX_ARGS inst->name

#include "rlm_yubikey.h"

#ifdef HAVE_YKCLIENT
#include <freeradius-devel/server/pool.h>

/** Frees a ykclient handle
 *
 * @param[in] yandle rlm_yubikey_handle_t to close and free.
 * @return returns 0.
 */
static int _mod_conn_free(ykclient_handle_t **yandle)
{
	ykclient_handle_done(yandle);

	return 0;
}

/** Creates a new connection handle for use by the FR connection API.
 *
 * Matches the fr_pool_connection_create_t function prototype, is passed to
 * fr_pool_init, and called when a new connection is required by the
 * connection pool API.
 *
 * @see fr_pool_init
 * @see fr_pool_connection_create_t
 * @see connection.c
 */
static void *mod_conn_create(TALLOC_CTX *ctx, void *instance, UNUSED fr_time_delta_t timeout)
{
	rlm_yubikey_t const *inst = talloc_get_type_abort_const(instance, rlm_yubikey_t);
	ykclient_rc status;
	ykclient_handle_t *yandle, **marker;

	status = ykclient_handle_init(inst->ykc, &yandle);
	if (status != YKCLIENT_OK) {
		ERROR("%s", ykclient_strerror(status));

		return NULL;
	}
	marker = talloc(ctx, ykclient_handle_t *);
	talloc_set_destructor(marker, _mod_conn_free);
	*marker = yandle;

	return yandle;
}

int rlm_yubikey_ykclient_init(CONF_SECTION *conf, rlm_yubikey_t *inst)
{
	ykclient_rc status;
	CONF_SECTION *servers;

	int count = 0;

	if (!inst->client_id) {
		ERROR("validation.client_id must be set (to a valid id) when validation is enabled");

		return -1;
	}

	if (!inst->api_key || !*inst->api_key || is_zero(inst->api_key)) {
		ERROR("validation.api_key must be set (to a valid key) when validation is enabled");

		return -1;
	}

	DEBUG("Initialising ykclient");

	status = ykclient_global_init();
	if (status != YKCLIENT_OK) {
yk_error:
		ERROR("%s", ykclient_strerror(status));

		return -1;
	}

	status = ykclient_init(&inst->ykc);
	if (status != YKCLIENT_OK) goto yk_error;

	servers = cf_section_find(conf, "servers", CF_IDENT_ANY);
	if (servers) {
		CONF_PAIR *uri, *first;
		/*
		 *	If there were no uris configured we just use the default
		 *	ykclient uris which point to the yubico servers.
		 */
		first = uri = cf_pair_find(servers, "uri");
		if (!uri) {
			goto init;
		}

		while (uri) {
			count++;
			uri = cf_pair_find_next(servers, uri, "uri");
		}
		inst->uris = talloc_zero_array(inst, char const *, count);

		uri = first;
		count = 0;
		while (uri) {
			inst->uris[count++] = cf_pair_value(uri);
			uri = cf_pair_find_next(servers, uri, "uri");
		}
		if (count) {
			status = ykclient_set_url_templates(inst->ykc, count, inst->uris);
			if (status != YKCLIENT_OK) {
				goto yk_error;
			}
		}
	}

init:
	status = ykclient_set_client_b64(inst->ykc, inst->client_id, inst->api_key);
	if (status != YKCLIENT_OK) {
		ERROR("%s", ykclient_strerror(status));

		return -1;
	}

	inst->pool = module_connection_pool_init(conf, inst, mod_conn_create, NULL, inst->name, NULL, NULL);
	if (!inst->pool) {
		ykclient_done(&inst->ykc);

		return -1;
	}

	return 0;
}

int rlm_yubikey_ykclient_detach(rlm_yubikey_t *inst)
{
	fr_pool_free(inst->pool);
	ykclient_done(&inst->ykc);
	ykclient_global_done();

	return 0;
}

rlm_rcode_t rlm_yubikey_validate(rlm_yubikey_t const *inst, REQUEST *request, char const *passcode)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;
	ykclient_rc status;
	ykclient_handle_t *yandle;

	yandle = fr_pool_connection_get(inst->pool, request);
	if (!yandle) return RLM_MODULE_FAIL;

	/*
	 *	The libcurl multi-handle interface will tear down the TCP sockets for any partially completed
	 *	requests when their easy handle is removed from the multistack.
	 *
	 *	For performance reasons ykclient will stop processing the request immediately after receiving
	 *	a response from one of the servers. If we then immediately call ykclient_handle_cleanup
	 *	the connections are destroyed and will need to be re-established the next time the handle
	 *	is used.
	 *
	 *	To try and prevent this from happening, we leave cleanup until the *next* time
	 *	the handle is used, by which time the requests will of hopefully completed and the connections
	 *	can be re-used.
	 *
	 */
	ykclient_handle_cleanup(yandle);

	status = ykclient_request_process(inst->ykc, yandle, passcode);
	if (status != YKCLIENT_OK) {
		REDEBUG("%s", ykclient_strerror(status));
		switch (status) {
		case YKCLIENT_BAD_OTP:
		case YKCLIENT_REPLAYED_OTP:
			rcode = RLM_MODULE_REJECT;
			break;

		case YKCLIENT_NO_SUCH_CLIENT:
			rcode = RLM_MODULE_NOTFOUND;
			break;

		default:
			rcode = RLM_MODULE_FAIL;
		}
	}

	fr_pool_connection_release(inst->pool, request, yandle);

	return rcode;
}
#endif
