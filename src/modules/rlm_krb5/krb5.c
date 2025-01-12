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
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX inst->name

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/base.h>
#include "krb5.h"

#ifdef HAVE_KRB5_GET_ERROR_MESSAGE
#  define KRB5_STRERROR_BUFSIZE (2048)

static _Thread_local char *krb5_error_buffer;

/*
 *	Explicitly cleanup the memory allocated to the error buffer.
 */
static int _krb5_logging_free(void *arg)
{
	return talloc_free(arg);
}

char const *rlm_krb5_error(rlm_krb5_t const *inst, krb5_context context, krb5_error_code code)
{
	char const *msg;
	char *buffer;

	if (!fr_cond_assert(inst)) return NULL;

	buffer = krb5_error_buffer;
	if (!buffer) {
		buffer = talloc_array(NULL, char, KRB5_STRERROR_BUFSIZE);
		if (!buffer) {
			ERROR("Failed allocating memory for krb5 error buffer");
			return NULL;
		}

		fr_atexit_thread_local(krb5_error_buffer, _krb5_logging_free, buffer);
	}

	msg = krb5_get_error_message(context, code);
	if (msg) {
		strlcpy(buffer, msg, KRB5_STRERROR_BUFSIZE);
#  ifdef HAVE_KRB5_FREE_ERROR_MESSAGE
		krb5_free_error_message(context, msg);
#  elif defined(HAVE_KRB5_FREE_ERROR_STRING)
		krb5_free_error_string(context, UNCONST(char *, msg));
#  else
#    error "No way to free error strings, missing krb5_free_error_message() and krb5_free_error_string()"
#  endif
	} else {
		strlcpy(buffer, "Unknown error", KRB5_STRERROR_BUFSIZE);
	}

	return buffer;
}
#endif

/** Frees libkrb5 resources associated with the handle
 *
 * Must not be called directly.
 *
 * @param conn to free.
 * @return 0 (always indicates success).
 */
static int _mod_conn_free(rlm_krb5_handle_t *conn) {
	krb5_free_context(conn->context);

	if (conn->keytab) krb5_kt_close(conn->context, conn->keytab);

#ifdef HEIMDAL_KRB5
	if (conn->ccache) krb5_cc_destroy(conn->context, conn->ccache);
#endif

	return 0;
}

int krb5_handle_init(rlm_krb5_handle_t *conn, void *uctx)
{
	rlm_krb5_t const *inst = talloc_get_type_abort_const(uctx, rlm_krb5_t);
	krb5_error_code ret;

	ret = krb5_init_context(&conn->context);
	if (ret) {
		ERROR("Context initialisation failed: %s", rlm_krb5_error(inst, NULL, ret));
		return -1;
	}
	talloc_set_destructor(conn, _mod_conn_free);

	ret = inst->keytabname ?
		krb5_kt_resolve(conn->context, inst->keytabname, &conn->keytab) :
		krb5_kt_default(conn->context, &conn->keytab);
	if (ret) {
		ERROR("Resolving keytab failed: %s", rlm_krb5_error(inst, conn->context, ret));
		return -1;
	}

#ifdef HEIMDAL_KRB5
	ret = krb5_cc_new_unique(conn->context, "MEMORY", NULL, &conn->ccache);
	if (ret) {
		ERROR("Credential cache creation failed: %s", rlm_krb5_error(inst, conn->context, ret));
		return -1;
	}

	krb5_verify_opt_init(&conn->options);
	krb5_verify_opt_set_ccache(&conn->options, conn->ccache);

	krb5_verify_opt_set_keytab(&conn->options, conn->keytab);
	krb5_verify_opt_set_secure(&conn->options, true);

	if (inst->service) krb5_verify_opt_set_service(&conn->options, inst->service);
#endif
	return 0;
}

/** Create and return a new connection
 *
 * libkrb5(s) can talk to the KDC over TCP. Were assuming something sane is implemented
 * by libkrb5 and that it does connection caching associated with contexts, so it's
 * worth using a connection pool to preserve connections when workers die.
 */
void *krb5_mod_conn_create(TALLOC_CTX *ctx, void *instance, UNUSED fr_time_delta_t timeout)
{
	rlm_krb5_t *inst = talloc_get_type_abort(instance, rlm_krb5_t);
	rlm_krb5_handle_t *conn;

	MEM(conn = talloc_zero(ctx, rlm_krb5_handle_t));

	if (krb5_handle_init(conn, inst) < 0) {
		talloc_free(conn);
		return NULL;
	}

	return conn;
}
