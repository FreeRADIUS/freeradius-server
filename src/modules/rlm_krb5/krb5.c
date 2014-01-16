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
 * @file krb5.h
 * @brief Context management functions for rlm_krb5
 *
 * @copyright 2013  The FreeRADIUS server project
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include "krb5.h"

#ifdef HEIMDAL_KRB5
#  define KRB5_STRERROR_BUFSIZE (2048)

fr_thread_local_setup(char *, krb5_error_buffer)	/* macro */

/*
 *	Explicitly cleanup the memory allocated to the error buffer.
 */
static void _krb5_logging_free(void *arg)
{
	free(arg);
}

char const *rlm_krb5_error(krb5_context context, krb5_error_code code)
{
	char const *msg;
	char *buffer;

	buffer = fr_thread_local_init(krb5_error_buffer, _krb5_logging_free);
	if (!buffer) {
		int ret;

		/*
		 *	malloc is thread safe, talloc is not
		 */
		buffer = malloc(sizeof(char) * KRB5_STRERROR_BUFSIZE);
		if (!buffer) {
			ERROR("Failed allocating memory for krb5 error buffer");
			return NULL;
		}

		ret = fr_thread_local_set(krb5_error_buffer, buffer);
		if (ret != 0) {
			ERROR("Failed setting up TLS for krb5 error buffer: %s", fr_syserror(ret));
			free(buffer);
			return NULL;
		}
	}

	msg = krb5_get_error_message(context, code);
	if (msg) {
		strlcpy(buffer, msg, KRB5_STRERROR_BUFSIZE);
		krb5_free_error_message(context, msg);
	} else {
		strlcpy(buffer, "Unknown error", KRB5_STRERROR_BUFSIZE);
	}

	return buffer;
}
#endif

/** Frees a krb5 context
 *
 * @param instance rlm_krb5 instance.
 * @param handle to destroy.
 * @return 0 (always indicates success).
 */
int mod_conn_delete(UNUSED void *instance, void *handle)
{
	return talloc_free((krb5_context *) handle);
}

/** Frees libkrb5 resources associated with the handle
 *
 * Must not be called directly.
 *
 * @param conn to free.
 * @return 0 (always indicates success).
 */
static int _free_handle(rlm_krb5_handle_t *conn) {
	krb5_free_context(conn->context);

	if (conn->keytab) {
		krb5_kt_close(conn->context, conn->keytab);
	}
	return 0;
}

/** Create and return a new connection
 *
 * libkrb5(s) can talk to the KDC over TCP. Were assuming something sane is implemented
 * by libkrb5 and that it does connection caching associated with contexts, so it's
 * worth using a connection pool to preserve connections when workers die.
 *
 * @param instance rlm_krb5 instance instance.
 * @return A new context or NULL on error.
 */
void *mod_conn_create(void *instance)
{
	rlm_krb5_t *inst = instance;
	rlm_krb5_handle_t *conn;
	krb5_error_code ret;

	MEM(conn = talloc_zero(instance, rlm_krb5_handle_t));
	ret = krb5_init_context(&conn->context);
	if (ret) {
		EDEBUG("rlm_krb5 (%s): Context initialisation failed: %s", inst->xlat_name,
		       rlm_krb5_error(NULL, ret));

		return NULL;
	}
	talloc_set_destructor(conn, _free_handle);

	ret = inst->keytabname ?
		krb5_kt_resolve(conn->context, inst->keytabname, &conn->keytab) :
		krb5_kt_default(conn->context, &conn->keytab);
	if (ret) {
		ERROR("Resolving keytab failed: %s", rlm_krb5_error(conn->context, ret));

		goto cleanup;
	}

#ifdef HEIMDAL_KRB5
	/*
	 *	Setup krb5_verify_user options
	 *
	 *	Not entirely sure this is necessary, but as we use context
	 *	to get the cache handle, we probably do have to do this with
	 *	the cloned context.
	 */
	krb5_cc_default(conn->context, &conn->ccache);

	krb5_verify_opt_init(&conn->options);
	krb5_verify_opt_set_ccache(&conn->options, conn->ccache);

	krb5_verify_opt_set_keytab(&conn->options, conn->keytab);
	krb5_verify_opt_set_secure(&conn->options, true);

	if (inst->service) {
		krb5_verify_opt_set_service(&conn->options, inst->service);
	}
#else
	krb5_verify_init_creds_opt_set_ap_req_nofail(inst->vic_options, true);
#endif
	return conn;

cleanup:
	talloc_free(conn);
	return NULL;
}
